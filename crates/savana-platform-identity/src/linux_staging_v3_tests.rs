use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

fn fixture() -> (tempfile::TempDir, DeploymentApplySelectorV2) {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let selector = populate(root.path());
    (root, selector)
}
fn populate(root: &Path) -> DeploymentApplySelectorV2 {
    let selector = DeploymentApplySelectorV2::parse_arguments(
        [
            "savana-deploy".into(),
            "apply".into(),
            "ab".repeat(32).into(),
        ]
        .into_iter(),
    )
    .unwrap();
    let staged = root.join(selector.leaf());
    fs::create_dir(&staged).unwrap();
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(staged.join(PAYLOAD)).unwrap();
    fs::set_permissions(staged.join(PAYLOAD), fs::Permissions::from_mode(0o700)).unwrap();
    for (name, mode) in PLANS
        .iter()
        .map(|p| (*p, 0o600))
        .chain([(TRANSACTION_DESCRIPTOR_LEAF_V2, 0o400)])
    {
        fs::write(staged.join(name), b"synthetic plan").unwrap();
        fs::set_permissions(staged.join(name), fs::Permissions::from_mode(mode)).unwrap();
    }
    for tag in [10, 13, 44] {
        let path = staged.join(PAYLOAD).join(tag.to_string());
        fs::write(&path, b"synthetic artifact").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    selector
}

#[test]
#[ignore = "requires explicitly marked disposable root tmpfs container"]
fn staging_disposable_root_fixed_spool_contract() {
    assert_eq!(rustix::process::geteuid().as_raw(), 0);
    assert!(Path::new("/.dockerenv").is_file());
    assert!(Path::new("/run/savana-deployment-disk-test-only").is_file());
    assert!(!Path::new("/dev/tpm0").exists() && !Path::new("/dev/tpmrm0").exists());
    let base = Path::new("/var/lib/savana-deploy");
    let mounts = fs::read_to_string("/proc/mounts").unwrap();
    assert!(mounts.lines().any(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        fields.get(1) == Some(&"/var/lib/savana-deploy") && fields.get(2) == Some(&"tmpfs")
    }));
    assert_eq!(fs::read_dir(base).unwrap().count(), 0);
    fs::set_permissions(base, fs::Permissions::from_mode(0o700)).unwrap();
    for path in [base.join("spool"), base.join("spool/ready")] {
        fs::create_dir(&path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let ready = base.join("spool/ready");
    let selector = populate(&ready);
    let spool = FixedDeploymentSpoolV2::open_fixed_linux().unwrap();
    let mut measured = spool.measure_staging_v3(selector).unwrap();
    measured.revalidate().unwrap();
    let artifact = ready.join(selector.leaf()).join(PAYLOAD).join("13");
    fs::set_permissions(artifact, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(measured.revalidate().is_err());
    assert!(spool.measure_staging_v3(selector).is_err());
}

#[test]
fn staging_measures_exact_closed_inventory_and_original_plan_bytes() {
    let (root, selector) = fixture();
    let spool = FixedDeploymentSpoolV2::open_for_test(root.path()).unwrap();
    let mut tree = spool.measure_staging_v3(selector).unwrap();
    assert_eq!(
        tree.entries().iter().map(|e| e.tag()).collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 6, 7, 10, 13, 44]
    );
    assert_eq!(
        tree.entries()[7].sha256(),
        <[u8; 32]>::from(Sha256::digest(b"synthetic artifact"))
    );
    assert_eq!(tree.entries()[6].sha256(), [0; 32]);
    assert_eq!(tree.entries()[6].mode(), 0o700);
    assert_eq!(tree.plan_bytes(1).unwrap(), b"synthetic plan");
    assert!(tree.plan_bytes(0).is_err());
    assert!(tree.plan_bytes(7).is_err());
    assert_ne!(
        tree.entries()[0].acl_digest(),
        tree.entries()[0].xattr_digest()
    );
    tree.revalidate().unwrap();
}

#[test]
fn staging_rejects_unknown_missing_duplicate_alias_and_special_files() {
    for case in 0..9 {
        let (root, selector) = fixture();
        let staged = root.path().join(selector.leaf());
        let artifact = staged.join(PAYLOAD).join("10");
        match case {
            0 => {
                fs::write(staged.join(".DS_Store"), b"x").unwrap();
            }
            1 => {
                fs::remove_file(staged.join(PLANS[0])).unwrap();
            }
            2 => {
                fs::rename(&artifact, staged.join(PAYLOAD).join("010")).unwrap();
            }
            3 => {
                fs::rename(&artifact, staged.join(PAYLOAD).join("45")).unwrap();
            }
            4 => {
                fs::remove_file(&artifact).unwrap();
                symlink("/etc/passwd", &artifact).unwrap();
            }
            5 => {
                fs::hard_link(&artifact, staged.join(PAYLOAD).join("11")).unwrap();
            }
            6 => {
                fs::remove_file(&artifact).unwrap();
                rustix::fs::mkfifoat(&rustix::fs::CWD, &artifact, Mode::RUSR | Mode::WUSR).unwrap();
            }
            7 => {
                fs::remove_file(&artifact).unwrap();
                fs::create_dir(&artifact).unwrap();
            }
            8 => {
                fs::set_permissions(&artifact, fs::Permissions::from_mode(0o640)).unwrap();
            }
            _ => unreachable!(),
        }
        let spool = FixedDeploymentSpoolV2::open_for_test(root.path()).unwrap();
        assert!(spool.measure_staging_v3(selector).is_err(), "case {case}");
    }
}

#[test]
fn staging_rejects_mutation_and_poisons_even_after_inventory_is_restored() {
    for case in 0..5 {
        let (root, selector) = fixture();
        let staged = root.path().join(selector.leaf());
        let spool = FixedDeploymentSpoolV2::open_for_test(root.path()).unwrap();
        let mut tree = spool.measure_staging_v3(selector).unwrap();
        match case {
            0 => fs::write(staged.join(PAYLOAD).join("10"), b"different artifact").unwrap(),
            1 => fs::write(staged.join(PLANS[0]), b"different plan").unwrap(),
            2 => {
                let p = staged.join(TRANSACTION_DESCRIPTOR_LEAF_V2);
                fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
                fs::write(&p, b"other descriptor").unwrap();
                fs::set_permissions(p, fs::Permissions::from_mode(0o400)).unwrap();
            }
            3 => fs::write(staged.join("extra"), b"x").unwrap(),
            4 => fs::rename(&staged, root.path().join("moved")).unwrap(),
            _ => unreachable!(),
        }
        assert!(tree.revalidate().is_err());
        if case == 3 {
            fs::remove_file(staged.join("extra")).unwrap();
        }
        assert!(tree.revalidate().is_err());
    }
}

#[test]
fn staging_rejects_extended_attributes_and_oversized_sparse_plan() {
    for case in 0..4 {
        let (root, selector) = fixture();
        let staged = root.path().join(selector.leaf());
        let path = match case {
            0 => staged.join(PAYLOAD),
            1 => staged.join(PAYLOAD).join("10"),
            2 => staged.join(TRANSACTION_DESCRIPTOR_LEAF_V2),
            _ => staged.join(PLANS[0]),
        };
        if case == 3 {
            fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(PLAN_LIMIT + 1)
                .unwrap();
        } else {
            if case == 2 {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            let f = File::open(path).unwrap();
            rustix::fs::fsetxattr(
                &f,
                "user.savana-test",
                b"synthetic",
                rustix::fs::XattrFlags::empty(),
            )
            .unwrap();
            if case == 2 {
                f.set_permissions(fs::Permissions::from_mode(0o400))
                    .unwrap();
            }
        }
        let spool = FixedDeploymentSpoolV2::open_for_test(root.path()).unwrap();
        assert!(spool.measure_staging_v3(selector).is_err());
    }
}
