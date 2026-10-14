//! Separate Linux operator API. Not part of Client/Session or an Agent tool.
//! Signatures must be created by the independently provisioned administrator.
use savana_policy_core::v2::{ManagedAdminCommandV04, ManagedAdminResultV04};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Private offline signing preparation. It neither signs nor submits anything.
/// The operator reviews the canonical bytes and signs exactly signing_digest
/// using its independently provisioned, purpose-appropriate key.
pub struct PreparedPrivateArtifact {
    canonical: Zeroizing<Vec<u8>>,
    digest: [u8; 32],
}
impl std::fmt::Debug for PreparedPrivateArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedPrivateArtifact(<private unsigned artifact>)")
    }
}
impl PreparedPrivateArtifact {
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn signing_digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Parse and validate in Rust, including duplicate/unknown field rejection.
/// `kind` is a closed discriminator, never a policy or executable expression.
/// Does not validate a live root or nested signatures: the owner still must.
pub fn prepare_artifact(
    kind: &str,
    json: &[u8],
) -> Result<PreparedPrivateArtifact, ManagedAdminError> {
    if json.is_empty() || json.len() > MAX_COMMAND {
        return Err(ManagedAdminError::InvalidCommand);
    }
    use savana_policy_core::v2::{
        ContinuationDispatchPolicyV04, ContinuationStorageProfileV04, FusedPlanningProfileV04,
        FusedRecipeApprovalV04, ManagedSourcePolicyV04,
    };
    macro_rules! prepare {
        ($ty:ty) => {{
            let value: $ty =
                serde_json::from_slice(json).map_err(|_| ManagedAdminError::InvalidCommand)?;
            let digest = value
                .signing_digest()
                .map_err(|_| ManagedAdminError::InvalidCommand)?;
            let canonical =
                serde_json::to_vec(&value).map_err(|_| ManagedAdminError::InvalidCommand)?;
            PreparedPrivateArtifact {
                canonical: Zeroizing::new(canonical),
                digest,
            }
        }};
    }
    Ok(match kind {
        "command" => prepare!(ManagedAdminCommandV04),
        "planning_profile" => prepare!(FusedPlanningProfileV04),
        "planning_draft" => prepare!(savana_policy_core::v2::FusedTaskDraftV04),
        "recipe_approval" => prepare!(FusedRecipeApprovalV04),
        "storage_profile" => prepare!(ContinuationStorageProfileV04),
        "dispatch_policy" => prepare!(ContinuationDispatchPolicyV04),
        "source_policy" => prepare!(ManagedSourcePolicyV04),
        _ => return Err(ManagedAdminError::InvalidCommand),
    })
}

const MAX_COMMAND: usize = 256 * 1024;
#[cfg(any(target_os = "linux", test))]
const MAX_REPLY: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedAdminError {
    UnsupportedPlatform,
    AdministratorRequired,
    InvalidCommand,
    /// No assertion about whether the mutation committed. Retry EXACT bytes and
    /// signature, never generate a new request ID to resolve this error.
    NotConfirmed,
}
impl std::fmt::Display for ManagedAdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnsupportedPlatform => "managed administration requires Linux",
            Self::AdministratorRequired => "managed administration requires a local root operator",
            Self::InvalidCommand => "invalid signed management command",
            Self::NotConfirmed => "management result not confirmed; retry the exact signed command",
        })
    }
}
impl std::error::Error for ManagedAdminError {}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    schema: u16,
    status: String,
    request: [u8; 32],
    command_digest: [u8; 32],
    result: ManagedAdminResultV04,
}

/// Private historical result; it is not a live permission/approval token.
pub struct ManagedAdminReceipt {
    reply: Reply,
}
impl std::fmt::Debug for ManagedAdminReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ManagedAdminReceipt(<private historical result>)")
    }
}
impl ManagedAdminReceipt {
    /// Explicit private export for an operator UI. Never put it in Agent output.
    pub fn private_json(&self) -> Result<String, ManagedAdminError> {
        serde_json::to_string(&self.reply).map_err(|_| ManagedAdminError::NotConfirmed)
    }
}

fn parse_command(bytes: &[u8]) -> Result<ManagedAdminCommandV04, ManagedAdminError> {
    if bytes.is_empty() || bytes.len() > MAX_COMMAND {
        return Err(ManagedAdminError::InvalidCommand);
    }
    let cmd: ManagedAdminCommandV04 =
        serde_json::from_slice(bytes).map_err(|_| ManagedAdminError::InvalidCommand)?;
    if cmd
        .canonical_bytes()
        .map_err(|_| ManagedAdminError::InvalidCommand)?
        != bytes
    {
        return Err(ManagedAdminError::InvalidCommand);
    }
    Ok(cmd)
}

#[cfg(any(target_os = "linux", test))]
fn parse_reply(
    bytes: &[u8],
    cmd: &ManagedAdminCommandV04,
) -> Result<ManagedAdminReceipt, ManagedAdminError> {
    if bytes.len() > MAX_REPLY {
        return Err(ManagedAdminError::NotConfirmed);
    }
    let reply: Reply =
        serde_json::from_slice(bytes).map_err(|_| ManagedAdminError::NotConfirmed)?;
    if reply.schema != 1
        || reply.status != "committed"
        || reply.request != cmd.request
        || reply.command_digest
            != cmd
                .signing_digest()
                .map_err(|_| ManagedAdminError::InvalidCommand)?
    {
        return Err(ManagedAdminError::NotConfirmed);
    }
    use savana_policy_core::v2::ManagedAdminOperationV04 as Op;
    use ManagedAdminResultV04 as Result;
    let matching = match (&cmd.operation, &reply.result) {
        (
            Op::PreparePlanningExecution { task, root },
            Result::PlanningExecutionPrepared {
                task: actual,
                run,
                approval,
            },
        ) => {
            task == actual
                && task == &approval.task
                && root == &approval.root
                && *run != [0; 32]
                && approval.installation == cmd.installation
                && approval.signing_digest().is_ok()
        }
        (Op::RegisterSource { policy, .. }, Result::SourceRegistered { source, namespace }) => {
            source == &policy.source && namespace == &policy.namespace
        }
        (
            Op::CreateResource {
                source, namespace, ..
            },
            Result::ResourceCreated { resource },
        ) => {
            source == &resource.source
                && namespace == &resource.namespace
                && resource.object != [0; 32]
                && resource.incarnation == 0
        }
        (
            Op::UpdateResource {
                resource,
                expected_revision,
                ..
            },
            Result::ResourceUpdated {
                resource: actual,
                revision,
            },
        ) => {
            resource == actual
                && (*expected_revision == *revision
                    || expected_revision.checked_add(1) == Some(*revision))
        }
        (
            Op::EnrollTask { profile, .. },
            Result::TaskEnrolled {
                task,
                profile: digest,
            },
        ) => task == &profile.task && profile.signing_digest().ok().as_ref() == Some(digest),
        (
            Op::CompilePlanning { task, .. },
            Result::PlanningEnrolled {
                task: actual,
                profile,
            },
        ) => task == actual && profile != &[0; 32],
        (
            Op::EnrollPlanning { profile, .. },
            Result::PlanningEnrolled {
                task,
                profile: digest,
            },
        ) => task == &profile.task && profile.signing_digest().ok().as_ref() == Some(digest),
        (
            Op::ApprovePlanningRecipes { approval, .. },
            Result::PlanningRecipesApproved {
                task,
                approval: digest,
            },
        ) => task == &approval.task && approval.signing_digest().ok().as_ref() == Some(digest),
        _ => false,
    };
    if !matching {
        return Err(ManagedAdminError::NotConfirmed);
    }
    Ok(ManagedAdminReceipt { reply })
}

/// Submit to a fixed, root-only local socket. No HTTP, configurable remote URL,
/// private key, policy bypass, or automatic retry. All parsing stays in Rust.
pub fn submit_signed(
    command: &[u8],
    signature: &[u8; 64],
) -> Result<ManagedAdminReceipt, ManagedAdminError> {
    let cmd = parse_command(command)?;
    #[cfg(target_os = "linux")]
    {
        let reply = linux::exchange(command, signature)?;
        parse_reply(&reply, &cmd)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (cmd, signature);
        Err(ManagedAdminError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use nix::sys::socket::{self, sockopt, AddressFamily, SockFlag, SockType, UnixAddr};
    use std::io::{Read, Write};
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};
    const PATH: &str = "/run/savana/kerneld/admin/managed-v04.sock";

    fn remaining(deadline: Instant) -> Result<Duration, ManagedAdminError> {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(ManagedAdminError::NotConfirmed)
    }
    fn connect(deadline: Instant) -> Result<UnixStream, ManagedAdminError> {
        let fd = socket::socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            None,
        )
        .map_err(|_| ManagedAdminError::NotConfirmed)?;
        let address = UnixAddr::new(PATH).map_err(|_| ManagedAdminError::NotConfirmed)?;
        match socket::connect(fd.as_raw_fd(), &address) {
            Ok(()) => {}
            Err(nix::errno::Errno::EINPROGRESS) => {
                loop {
                    let ms = remaining(deadline)?.as_millis().min(u16::MAX as u128) as u16;
                    let mut polls = [nix::poll::PollFd::new(
                        fd.as_fd(),
                        nix::poll::PollFlags::POLLOUT,
                    )];
                    match nix::poll::poll(&mut polls, ms) {
                        Ok(n) if n > 0 => break,
                        Err(nix::errno::Errno::EINTR) => continue,
                        _ => return Err(ManagedAdminError::NotConfirmed),
                    }
                }
                if socket::getsockopt(&fd, sockopt::SocketError)
                    .map_err(|_| ManagedAdminError::NotConfirmed)?
                    != 0
                {
                    return Err(ManagedAdminError::NotConfirmed);
                }
            }
            _ => return Err(ManagedAdminError::NotConfirmed),
        }
        let stream = UnixStream::from(fd);
        stream
            .set_nonblocking(false)
            .map_err(|_| ManagedAdminError::NotConfirmed)?;
        Ok(stream)
    }

    pub(super) fn exchange(
        command: &[u8],
        signature: &[u8; 64],
    ) -> Result<Zeroizing<Vec<u8>>, ManagedAdminError> {
        if !nix::unistd::geteuid().is_root() || nix::unistd::getegid().as_raw() != 0 {
            return Err(ManagedAdminError::AdministratorRequired);
        }
        let path = std::path::Path::new(PATH);
        let meta = std::fs::symlink_metadata(path).map_err(|_| ManagedAdminError::NotConfirmed)?;
        let parent =
            std::fs::symlink_metadata(path.parent().ok_or(ManagedAdminError::NotConfirmed)?)
                .map_err(|_| ManagedAdminError::NotConfirmed)?;
        if !meta.file_type().is_socket()
            || meta.uid() != 0
            || meta.gid() != 0
            || meta.mode() & 0o7777 != 0o600
            || !parent.is_dir()
            || parent.file_type().is_symlink()
            || parent.uid() != 0
            || parent.gid() != 0
            || parent.mode() & 0o7777 != 0o711
        {
            return Err(ManagedAdminError::NotConfirmed);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = connect(deadline)?;
        // A systemd-inherited listening socket reports the socket creator (root),
        // not the accepting daemon. Filesystem + root peer authenticate this local
        // endpoint; user-controlled sockets cannot satisfy both checks.
        let peer = socket::getsockopt(&stream, sockopt::PeerCredentials)
            .map_err(|_| ManagedAdminError::NotConfirmed)?;
        if peer.uid() != 0 || peer.gid() != 0 || peer.pid() <= 0 {
            return Err(ManagedAdminError::NotConfirmed);
        }
        let mut frame = Zeroizing::new((command.len() as u32).to_be_bytes().to_vec());
        frame.extend_from_slice(command);
        frame.extend_from_slice(signature);
        let mut sent = 0;
        while sent < frame.len() {
            stream
                .set_write_timeout(Some(remaining(deadline)?))
                .map_err(|_| ManagedAdminError::NotConfirmed)?;
            let n = stream
                .write(&frame[sent..])
                .map_err(|_| ManagedAdminError::NotConfirmed)?;
            if n == 0 {
                return Err(ManagedAdminError::NotConfirmed);
            }
            sent += n;
        }
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|_| ManagedAdminError::NotConfirmed)?;
        fn read_exact(
            stream: &mut UnixStream,
            buf: &mut [u8],
            deadline: Instant,
        ) -> Result<(), ManagedAdminError> {
            let mut read = 0;
            while read < buf.len() {
                stream
                    .set_read_timeout(Some(remaining(deadline)?))
                    .map_err(|_| ManagedAdminError::NotConfirmed)?;
                let n = stream
                    .read(&mut buf[read..])
                    .map_err(|_| ManagedAdminError::NotConfirmed)?;
                if n == 0 {
                    return Err(ManagedAdminError::NotConfirmed);
                }
                read += n;
            }
            Ok(())
        }
        let mut size = [0; 4];
        read_exact(&mut stream, &mut size, deadline)?;
        let size = u32::from_be_bytes(size) as usize;
        if size == 0 || size > MAX_REPLY {
            return Err(ManagedAdminError::NotConfirmed);
        }
        let mut out = Zeroizing::new(vec![0; size]);
        read_exact(&mut stream, &mut out, deadline)?;
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| ManagedAdminError::NotConfirmed)?;
        if stream
            .read(&mut [0])
            .map_err(|_| ManagedAdminError::NotConfirmed)?
            != 0
        {
            return Err(ManagedAdminError::NotConfirmed);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use savana_policy_core::v2::ManagedAdminOperationV04;
    fn command() -> ManagedAdminCommandV04 {
        ManagedAdminCommandV04 {
            schema: 1,
            installation: [1; 32],
            store: [2; 32],
            request: [3; 32],
            not_before: 1,
            expires_at: 10,
            operation: ManagedAdminOperationV04::CreateResource {
                source: [4; 32],
                namespace: [5; 32],
                label: "private".into(),
                content: vec![6],
            },
        }
    }
    #[test]
    fn managed_admin_recipe_preparation_and_receipt_are_separately_bound() {
        use savana_policy_core::v2::{FusedRecipeApprovalV04, FusedRecipeBindingV04};
        let a = FusedRecipeApprovalV04 {
            inputs_digest: None,
            schema: 1,
            recipe_schema: 1,
            installation: [1; 32],
            manifest: [2; 32],
            task: [3; 32],
            root: [4; 32],
            profile: [5; 32],
            deployment_generation: 7,
            not_before: 1,
            expires_at: 10,
            bindings: vec![FusedRecipeBindingV04 {
                operation: 1,
                recipe: [6; 32],
            }],
        };
        let draft =
            prepare_artifact("recipe_approval", &serde_json::to_vec_pretty(&a).unwrap()).unwrap();
        assert_eq!(draft.canonical_bytes(), serde_json::to_vec(&a).unwrap());
        assert_eq!(draft.signing_digest(), a.signing_digest().unwrap());
        assert!(prepare_artifact("planning_profile", draft.canonical_bytes()).is_err());
        let mut cmd = command();
        cmd.operation = ManagedAdminOperationV04::ApprovePlanningRecipes {
            approval: Box::new(a.clone()),
            approval_signature: vec![1; 64],
        };
        let mut reply = Reply {
            schema: 1,
            status: "committed".into(),
            request: cmd.request,
            command_digest: cmd.signing_digest().unwrap(),
            result: ManagedAdminResultV04::PlanningRecipesApproved {
                task: a.task,
                approval: a.signing_digest().unwrap(),
            },
        };
        assert!(parse_reply(&serde_json::to_vec(&reply).unwrap(), &cmd).is_ok());
        reply.result = ManagedAdminResultV04::PlanningRecipesApproved {
            task: a.task,
            approval: [99; 32],
        };
        assert!(parse_reply(&serde_json::to_vec(&reply).unwrap(), &cmd).is_err());
        reply.result = ManagedAdminResultV04::PlanningEnrolled {
            task: a.task,
            profile: a.signing_digest().unwrap(),
        };
        assert!(parse_reply(&serde_json::to_vec(&reply).unwrap(), &cmd).is_err());
    }
    #[test]
    fn managed_admin_preparation_uses_rust_canonicalization_and_exact_digest() {
        let command = command();
        let draft = serde_json::to_vec_pretty(&command).unwrap();
        let prepared = prepare_artifact("command", &draft).unwrap();
        assert_eq!(
            prepared.canonical_bytes(),
            command.canonical_bytes().unwrap()
        );
        assert_eq!(prepared.signing_digest(), command.signing_digest().unwrap());
        assert_eq!(
            format!("{prepared:?}"),
            "PreparedPrivateArtifact(<private unsigned artifact>)"
        );
        let mut changed = command.clone();
        changed.request = [8; 32];
        assert_ne!(prepared.signing_digest(), changed.signing_digest().unwrap());
    }
    #[test]
    fn managed_admin_preparation_refuses_ambiguous_unknown_and_oversized_input() {
        let bytes = command().canonical_bytes().unwrap();
        assert!(prepare_artifact("tool", &bytes).is_err());
        assert!(prepare_artifact("planning_profile", &bytes).is_err());
        assert!(prepare_artifact("command", &vec![b' '; MAX_COMMAND + 1]).is_err());
        let json = String::from_utf8(bytes).unwrap();
        let duplicate = json.replacen("{", "{\"schema\":1,", 1);
        assert!(prepare_artifact("command", duplicate.as_bytes()).is_err());
        let unknown = json.replacen("{", "{\"ignore_rules\":true,", 1);
        assert!(prepare_artifact("command", unknown.as_bytes()).is_err());
    }
    #[test]
    fn managed_admin_client_rejects_malformed_noncanonical_and_oversized_commands() {
        let cmd = command();
        let mut bytes = cmd.canonical_bytes().unwrap();
        assert!(parse_command(&bytes).is_ok());
        bytes.push(b' ');
        assert!(parse_command(&bytes).is_err());
        assert!(parse_command(&vec![0; MAX_COMMAND + 1]).is_err());
        assert!(parse_command(b"{}").is_err());
    }
    #[test]
    fn managed_admin_compilation_receipt_is_bound_to_signed_command_and_task() {
        let draft: savana_policy_core::v2::FusedTaskDraftV04 = serde_json::from_value(serde_json::json!({
            "schema":1,"root":vec![4;32],"observer_scope":vec![5;32],"not_before":1,"expires_at":10,
            "operations":[{"id":1,"clause":1,"descriptor":vec![6;32],"tool":"mail.send","bindings":[],"after":[]}],
            "templates":[],"rounds":[],"delivery_schedule":[],"release_model_views":false,"max_replacements":0
        })).unwrap();
        let prepared =
            prepare_artifact("planning_draft", &serde_json::to_vec(&draft).unwrap()).unwrap();
        assert_eq!(prepared.signing_digest(), draft.signing_digest().unwrap());
        // Preparation is offline syntax/bounds only: empty templates here would
        // fail real compilation. It must not manufacture a live authorization.
        let mut cmd = command();
        cmd.operation = ManagedAdminOperationV04::CompilePlanning {
            task: [7; 32],
            draft: Box::new(draft),
        };
        let mut reply = Reply {
            schema: 1,
            status: "committed".into(),
            request: cmd.request,
            command_digest: cmd.signing_digest().unwrap(),
            result: ManagedAdminResultV04::PlanningEnrolled {
                task: [7; 32],
                profile: [8; 32],
            },
        };
        assert!(parse_reply(&serde_json::to_vec(&reply).unwrap(), &cmd).is_ok());
        for (task, profile) in [([9; 32], [8; 32]), ([7; 32], [0; 32])] {
            reply.result = ManagedAdminResultV04::PlanningEnrolled { task, profile };
            assert!(parse_reply(&serde_json::to_vec(&reply).unwrap(), &cmd).is_err());
        }
        reply.result = ManagedAdminResultV04::PlanningEnrolled {
            task: [7; 32],
            profile: [8; 32],
        };
        reply.command_digest = [9; 32];
        assert!(parse_reply(&serde_json::to_vec(&reply).unwrap(), &cmd).is_err());
    }
    #[test]
    fn managed_admin_client_binds_private_receipt_to_exact_command() {
        let cmd = command();
        let mut reply = Reply { schema:1,status:"committed".into(),request:cmd.request,command_digest:cmd.signing_digest().unwrap(),
            result:ManagedAdminResultV04::ResourceCreated { resource: serde_json::from_value(serde_json::json!({
                "source": vec![4;32], "namespace": vec![5;32], "object": vec![6;32], "incarnation": 0
            })).unwrap() } };
        let result = parse_reply(&serde_json::to_vec(&reply).unwrap(), &cmd).unwrap();
        assert_eq!(
            format!("{result:?}"),
            "ManagedAdminReceipt(<private historical result>)"
        );
        reply.request = [8; 32];
        assert!(parse_reply(&serde_json::to_vec(&reply).unwrap(), &cmd).is_err());
        reply.request = cmd.request;
        reply.command_digest = [9; 32];
        assert!(parse_reply(&serde_json::to_vec(&reply).unwrap(), &cmd).is_err());
        assert!(parse_reply(br#"{"schema":1,"status":"not_confirmed"}"#, &cmd).is_err());
    }
}
