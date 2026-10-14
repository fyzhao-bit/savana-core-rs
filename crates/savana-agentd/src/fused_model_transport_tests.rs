use super::*;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{RootCertStore, ServerConfig, ServerConnection};
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::thread;

fn fixture(name: &str) -> Vec<u8> {
    let prefix = format!("{name}=");
    let line = include_str!("../../savana-execd/tests/fixtures/provider-tls-v2.hex")
        .lines()
        .find_map(|v| v.strip_prefix(&prefix))
        .unwrap();
    (0..line.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
        .collect()
}
fn pin() -> Digest32V2 {
    Digest32V2::new(Sha256::digest(certificate_spki_der(&fixture("server_cert")).unwrap()).into())
}
fn config(alpn: &[u8]) -> Arc<ServerConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(fixture("ca_cert"))).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    let mut c = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from(fixture("server_cert"))],
            PrivateKeyDer::try_from(fixture("server_key")).unwrap(),
        )
        .unwrap();
    c.alpn_protocols = vec![alpn.to_vec()];
    Arc::new(c)
}
fn client(path: &Path, host: &str, pin: Digest32V2) -> UnixMtlsFusedModelTransportV04 {
    UnixMtlsFusedModelTransportV04::from_verified_deployment(
        host.into(),
        path.into(),
        pin,
        fixture("ca_cert"),
        fixture("client_cert"),
        Zeroizing::new(fixture("client_key")),
    )
    .unwrap()
}
fn deadline(ms: u64) -> UnixMillisV2 {
    UnixMillisV2::new(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + ms,
    )
}
fn request(tls: &mut StreamOwned<ServerConnection, UnixStream>) -> Vec<u8> {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let mut b = [0];
        tls.read_exact(&mut b).unwrap();
        header.push(b[0]);
        assert!(header.len() < 4096);
    }
    let h = String::from_utf8(header).unwrap();
    assert!(h.starts_with("POST /savana.fused.v04/exchange HTTP/1.1\r\n"));
    let size = h
        .lines()
        .find_map(|s| s.strip_prefix("Content-Length: "))
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let mut body = vec![0; size];
    tls.read_exact(&mut body).unwrap();
    minicbor::Decoder::new(&body).bytes().unwrap().to_vec()
}
fn serve(listener: UnixListener, response: Vec<u8>, clean: bool) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut tls = StreamOwned::new(ServerConnection::new(config(b"http/1.1")).unwrap(), s);
        let body = request(&mut tls);
        tls.write_all(&response).unwrap();
        tls.flush().unwrap();
        if clean {
            tls.conn.send_close_notify();
            let _ = tls.conn.complete_io(&mut tls.sock);
            // Keep the Unix endpoint alive until the client consumes close_notify;
            // dropping it with unread peer bytes can reset the transport on macOS.
            let mut end = [0];
            let _ = tls.read(&mut end);
        }
        body
    })
}
fn response(body: &[u8]) -> Vec<u8> {
    let mut r=format!("HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).into_bytes();
    r.extend_from_slice(body);
    r
}

#[test]
fn fused_unix_mtls_exact_bytes_and_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("model.sock");
    let server = serve(
        UnixListener::bind(&path).unwrap(),
        response(&encode_bytes(b"{\"schema\":1}").unwrap()),
        true,
    );
    let mut worker = client(&path, "provider.example", pin());
    assert_eq!(
        worker.recipient_identity(),
        fused_model_recipient_v04("provider.example", pin()).unwrap()
    );
    let result = worker.exchange(b"approved frozen view", deadline(2000), 1024);
    assert_eq!(server.join().unwrap(), b"approved frozen view");
    assert_eq!(result.unwrap(), b"{\"schema\":1}");
    assert!(!format!("{worker:?}").contains("provider.example"));
}

#[test]
fn fused_unix_mtls_rejects_pin_hostname_and_alpn_before_application_bytes() {
    for (host, pinned, alpn) in [
        (
            "provider.example",
            Digest32V2::new([7; 32]),
            b"http/1.1".as_slice(),
        ),
        ("wrong.example", pin(), b"http/1.1".as_slice()),
        ("provider.example", pin(), b"h2".as_slice()),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.sock");
        let l = UnixListener::bind(&path).unwrap();
        let cfg = config(alpn);
        let server = thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut tls = StreamOwned::new(ServerConnection::new(cfg).unwrap(), s);
            let mut b = [0];
            tls.read(&mut b).is_ok_and(|n| n > 0)
        });
        assert!(client(&path, host, pinned)
            .exchange(b"must not leak", deadline(2000), 1024)
            .is_err());
        assert!(!server.join().unwrap());
    }
}

#[test]
fn fused_unix_mtls_rejects_redirect_truncation_trailing_and_noncanonical_cbor() {
    let good = encode_bytes(b"ok").unwrap();
    let mut trailing = response(&good);
    trailing.push(0);
    for (wire, clean) in [
        (
            b"HTTP/1.1 302 Found\r\nLocation: https://evil.invalid\r\n\r\n".to_vec(),
            true,
        ),
        (response(&good), false),
        (trailing, true),
        (response(&[0x58, 2, b'o', b'k']), true),
        (response(&[0x42, b'o', b'k', 0]), true),
        (response(&vec![0; 2000]), true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.sock");
        let server = serve(UnixListener::bind(&path).unwrap(), wire, clean);
        assert!(client(&path, "provider.example", pin())
            .exchange(b"view", deadline(2000), 1024)
            .is_err());
        assert_eq!(server.join().unwrap(), b"view");
    }
}

#[test]
fn fused_unix_mtls_limits_fail_before_connect_and_no_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("absent.sock");
    let mut worker = client(&path, "provider.example", pin());
    for (body, at, limit) in [
        (vec![1], UnixMillisV2::new(1), 10),
        (vec![1; MAX_REQUEST + 1], deadline(1000), 10),
        (vec![], deadline(1000), 10),
        (vec![1], deadline(1000), 0),
        (vec![1], deadline(1000), MAX_FUSED_MODEL_REPLY_BYTES_V04 + 1),
    ] {
        assert!(worker.exchange(&body, at, limit).is_err());
    }
    assert!(worker.exchange(b"view", deadline(1000), 10).is_err());
    assert!(fused_model_recipient_v04("evil\r\nheader", pin()).is_err());
    assert!(fused_model_recipient_v04("Provider.example", pin()).is_err());
    assert!(fused_model_recipient_v04("provider.example", Digest32V2::new([0; 32])).is_err());
}

#[test]
fn fused_unix_mtls_handshake_has_absolute_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("m.sock");
    let l = UnixListener::bind(&path).unwrap();
    let server = thread::spawn(move || {
        let (_s, _) = l.accept().unwrap();
        thread::sleep(Duration::from_millis(250));
    });
    let start = Instant::now();
    assert!(client(&path, "provider.example", pin())
        .exchange(b"view", deadline(60), 100)
        .is_err());
    assert!(start.elapsed() < Duration::from_millis(500));
    server.join().unwrap();
}

#[test]
#[ignore = "requires explicit SAVANA_FUSED_TEST_PYTHON interpreter and local Unix sockets"]
fn fused_unix_mtls_python_worker_returns_native_bound_proposal() {
    use savana_continuation_core::planning::{Mode, ModelView, PlanChoice, PlanProposal, Role};
    use std::io::BufRead;
    use std::process::{Command, Stdio};
    let python = std::env::var_os("SAVANA_FUSED_TEST_PYTHON").expect("explicit Python interpreter");
    let dir = tempfile::tempdir().unwrap();
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../savana-core-py/tests/fused_worker_probe.py");
    let mut child = Command::new(python)
        .arg(script)
        .arg(dir.path())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready, "READY\n");
    let view = ModelView {
        schema: 1,
        job: [1; 16],
        role: Role::Planner,
        model_profile: 1,
        deadline: deadline(3000).get(),
        mode: Mode::RegisteredTemplateV04,
        public_view: b"synthetic public task".to_vec(),
        template_ids: vec![1],
        question_codes: vec![],
        suggested_templates: vec![],
        suggested_questions: vec![],
    };
    let result = client(&dir.path().join("python.sock"), "provider.example", pin()).exchange(
        &view.canonical_bytes().unwrap(),
        deadline(2000),
        16384,
    );
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().unwrap();
    let bytes = result.unwrap();
    assert!(status.success());
    let proposal: PlanProposal = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(serde_json::to_vec(&proposal).unwrap(), bytes);
    assert_eq!(proposal.job, view.job);
    assert_eq!(proposal.view, view.commitment());
    assert_eq!(
        proposal.choice,
        PlanChoice::RegisteredTemplate { template: 1 }
    );
}
