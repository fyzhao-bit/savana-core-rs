use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use savana_agentd::planner_privacy::{
    encode_mapped_workflow_v2, encode_ordered_structural_plan_v2,
    encode_structural_planner_request_v2, IntentTrustBoundaryV2, IntentTrustDeploymentCeilingV2,
    MappedEdgeV2, MappedNodeV2, MappedWorkflowV2, MapperCatalogToolV2, MapperIntentRequestV2,
    OrderedStructuralPlanV2, StructuralNodeIdIssuerV2, StructuralRoleV2,
};
use savana_agentd::{
    execute_private_planning_pipeline_v2, test_certificate_spki_sha256_v2,
    AgentBrowserAuthorityErrorV2, BoundedPlannerSemanticTextV2, MapperEndpointDeploymentV2,
    PinnedMtlsAgentMapperClientV2, PinnedMtlsAgentPlannerClientV2, PlannerCatalogEntryV2,
};
use savana_kernel_protocol::v2::{
    ActionTemplateIdV2, ActiveToolViewV2, CommitPlannerValueResponseV2, Digest32V2, Nonce32V2,
    PlanRevisionDigestV2, PlanStepHandleV2, PlannerEnvelopeV2, PlannerIntentKindV2,
    PlannerLimitsV2, PlannerRouteIdV2, PlannerTicketHandleV2, PreparePlannerCallResponseV2,
    RunHandleV2, StaticTemplateIdV2, ToolClassIdV2, ToolHandleV2, UnixMillisV2, ValueHandleV2,
};
use savana_policy_core::v2::{ConnectorStructuralRoleV2, EffectSetV2};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

fn tls_fixture(name: &str) -> Vec<u8> {
    let prefix = format!("{name}=");
    let encoded = include_str!("../../savana-execd/tests/fixtures/provider-tls-v2.hex")
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap();
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("non-hex TLS fixture"),
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

fn server_config() -> ServerConfig {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(tls_fixture("ca_cert")))
        .unwrap();
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![CertificateDer::from(tls_fixture("server_cert"))],
                PrivateKeyDer::try_from(tls_fixture("server_key")).unwrap(),
            )
            .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

fn read_body(tls: &mut StreamOwned<ServerConnection, std::net::TcpStream>) -> (String, Vec<u8>) {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let mut byte = [0_u8; 1];
        tls.read_exact(&mut byte).unwrap();
        header.push(byte[0]);
    }
    let header = String::from_utf8(header).unwrap();
    let length = header
        .split("\r\n")
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let mut body = vec![0_u8; length];
    tls.read_exact(&mut body).unwrap();
    (header, body)
}

fn spawn_tls_model_server<F>(
    listener: TcpListener,
    path: &'static str,
    calls: usize,
    handler: F,
) -> thread::JoinHandle<()>
where
    F: Fn(Vec<u8>) -> Vec<u8> + Send + Sync + 'static,
{
    thread::spawn(move || {
        let config = Arc::new(server_config());
        for _ in 0..calls {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut tls =
                StreamOwned::new(ServerConnection::new(Arc::clone(&config)).unwrap(), socket);
            let (header, body) = read_body(&mut tls);
            assert!(header.starts_with(&format!("POST {path} HTTP/1.1\r\n")));
            assert!(tls
                .conn
                .peer_certificates()
                .is_some_and(|chain| !chain.is_empty()));
            let response = handler(body);
            write!(
                tls,
                "HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .unwrap();
            tls.write_all(&response).unwrap();
            tls.flush().unwrap();
            tls.conn.send_close_notify();
            let _ = tls.conn.complete_io(&mut tls.sock);
        }
    })
}

fn deadline() -> UnixMillisV2 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    UnixMillisV2::new(u64::try_from((now + Duration::from_secs(5)).as_millis()).unwrap())
}

fn active_tool(byte: u8, class: u32, action: u32) -> ActiveToolViewV2 {
    ActiveToolViewV2::new(
        ToolHandleV2::from_authority_entropy([byte; 32]).unwrap(),
        ActionTemplateIdV2::new(action),
        ToolClassIdV2::new(class),
        StaticTemplateIdV2::new(class + action),
    )
    .unwrap()
}

fn catalog_entry(name: &str, description: &str) -> PlannerCatalogEntryV2 {
    catalog_entry_for(
        100,
        10,
        ConnectorStructuralRoleV2::Source,
        EffectSetV2::READ,
        name,
        description,
    )
}

fn catalog_entry_for(
    class: u32,
    action: u32,
    role: ConnectorStructuralRoleV2,
    effects: EffectSetV2,
    name: &str,
    description: &str,
) -> PlannerCatalogEntryV2 {
    PlannerCatalogEntryV2::new(
        ToolClassIdV2::new(class),
        ActionTemplateIdV2::new(action),
        role,
        effects,
        BoundedPlannerSemanticTextV2::new(name).unwrap(),
        BoundedPlannerSemanticTextV2::new(description).unwrap(),
    )
    .unwrap()
}

fn envelope(nonce: u8) -> PlannerEnvelopeV2 {
    PlannerEnvelopeV2::new(
        PlannerRouteIdV2::new(9),
        StaticTemplateIdV2::new(7),
        PlannerIntentKindV2::Search,
        vec![ActionTemplateIdV2::new(10)],
        vec![],
        vec![],
        PlannerLimitsV2::new(2, 1, 1, 4096).unwrap(),
        Nonce32V2::new([nonce; 32]),
        deadline(),
    )
    .unwrap()
}

fn prepared(nonce: u8, ticket: u8) -> PreparePlannerCallResponseV2 {
    prepared_from(envelope(nonce), ticket)
}

fn prepared_from(envelope: PlannerEnvelopeV2, ticket: u8) -> PreparePlannerCallResponseV2 {
    let digest = Digest32V2::new(Sha256::digest(minicbor::to_vec(&envelope).unwrap()).into());
    PreparePlannerCallResponseV2::new(
        PlannerTicketHandleV2::from_authority_entropy([ticket; 32]).unwrap(),
        envelope.clone(),
        digest,
        Digest32V2::new([ticket.wrapping_add(1); 32]),
        envelope.expires_at(),
    )
    .unwrap()
}

fn invalid_inactive_mapper_response() -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(3).unwrap().u16(2).unwrap().array(1).unwrap();
    encoder
        .array(6)
        .unwrap()
        .u16(1)
        .unwrap()
        .u32(999)
        .unwrap()
        .u32(10)
        .unwrap()
        .array(0)
        .unwrap()
        .u16(StructuralRoleV2::Source as u16)
        .unwrap()
        .u16(EffectSetV2::READ.bits())
        .unwrap();
    encoder.array(0).unwrap();
    encoder.into_writer()
}

fn mapped_response(request: &MapperIntentRequestV2) -> Vec<u8> {
    let node = MappedNodeV2::new(
        1,
        ToolClassIdV2::new(100),
        ActionTemplateIdV2::new(10),
        vec![],
        StructuralRoleV2::Source,
        EffectSetV2::READ,
    )
    .unwrap();
    encode_mapped_workflow_v2(&MappedWorkflowV2::new(request, vec![node], vec![]).unwrap()).unwrap()
}

fn clients(
    mapper_address: std::net::SocketAddr,
    planner_address: std::net::SocketAddr,
) -> (
    PinnedMtlsAgentMapperClientV2,
    PinnedMtlsAgentPlannerClientV2,
) {
    let pin = test_certificate_spki_sha256_v2(&tls_fixture("server_cert")).unwrap();
    let mapper_endpoint = MapperEndpointDeploymentV2::new(
        "provider.example".to_owned(),
        mapper_address.port(),
        vec![mapper_address],
        pin,
    )
    .unwrap();
    let mapper = PinnedMtlsAgentMapperClientV2::from_verified_deployment(
        IntentTrustDeploymentCeilingV2::PrivateOnly,
        mapper_endpoint,
        None,
        tls_fixture("ca_cert"),
        tls_fixture("client_cert"),
        Zeroizing::new(tls_fixture("client_key")),
    )
    .unwrap();
    let planner = PinnedMtlsAgentPlannerClientV2::from_verified_deployment(
        "provider.example".to_owned(),
        planner_address.port(),
        vec![planner_address],
        pin,
        tls_fixture("ca_cert"),
        tls_fixture("client_cert"),
        Zeroizing::new(tls_fixture("client_key")),
    )
    .unwrap();
    (mapper, planner)
}

struct Guard {
    held: Arc<AtomicBool>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.held.store(false, Ordering::SeqCst);
        self.events.lock().unwrap().push("guard_drop");
    }
}

#[test]
fn real_mtls_pipeline_is_one_way_private_and_reuses_one_lifetime_issuer() {
    let active = vec![active_tool(0x41, 100, 10)];
    let first_entry = catalog_entry("customer_lookup", "query private customer records");
    let first_request = MapperIntentRequestV2::new(
        &envelope(0x51),
        &active,
        vec![MapperCatalogToolV2::from_catalog_entry(&first_entry).unwrap()],
    )
    .unwrap();
    let mapper_response = mapped_response(&first_request);
    let mapper_calls = Arc::new(AtomicUsize::new(0));
    let mapper_bodies = Arc::new(Mutex::new(Vec::new()));
    let mapper_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mapper_address = mapper_listener.local_addr().unwrap();
    let mapper_server = spawn_tls_model_server(mapper_listener, "/savana.mapper.v2/map", 2, {
        let calls = Arc::clone(&mapper_calls);
        let bodies = Arc::clone(&mapper_bodies);
        move |body| {
            calls.fetch_add(1, Ordering::SeqCst);
            bodies.lock().unwrap().push(body);
            mapper_response.clone()
        }
    });
    let planner_calls = Arc::new(AtomicUsize::new(0));
    let planner_bodies = Arc::new(Mutex::new(Vec::new()));
    let planner_ids = Arc::new(Mutex::new(Vec::new()));
    let planner_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let planner_address = planner_listener.local_addr().unwrap();
    let planner_server = spawn_tls_model_server(planner_listener, "/savana.planner.v2/plan", 2, {
        let calls = Arc::clone(&planner_calls);
        let bodies = Arc::clone(&planner_bodies);
        let ids = Arc::clone(&planner_ids);
        move |body| {
            calls.fetch_add(1, Ordering::SeqCst);
            let request =
                savana_agentd::planner_privacy::decode_structural_planner_request_v2(&body)
                    .unwrap();
            let ordered = request
                .graph()
                .nodes()
                .iter()
                .map(|node| node.id())
                .collect::<Vec<_>>();
            ids.lock().unwrap().push(ordered.clone());
            bodies.lock().unwrap().push(body);
            encode_ordered_structural_plan_v2(&OrderedStructuralPlanV2::new(ordered).unwrap())
                .unwrap()
        }
    });
    let (mapper, planner) = clients(mapper_address, planner_address);
    let issuer = Mutex::new(StructuralNodeIdIssuerV2::new().unwrap());
    let events = Arc::new(Mutex::new(Vec::new()));
    let commits = Arc::new(AtomicUsize::new(0));

    for (index, (nonce, name, description)) in [
        (0x51, "customer_lookup", "query private customer records"),
        (0x61, "account_lookup", "query private account records"),
    ]
    .into_iter()
    .enumerate()
    {
        events.lock().unwrap().push("guard_acquire");
        let held = Arc::new(AtomicBool::new(true));
        let result = execute_private_planning_pipeline_v2(
            Guard {
                held: Arc::clone(&held),
                events: Arc::clone(&events),
            },
            RunHandleV2::from_authority_entropy([0x71 + index as u8; 32]).unwrap(),
            &active,
            &issuer,
            IntentTrustBoundaryV2::Private,
            {
                let events = Arc::clone(&events);
                move || {
                    events.lock().unwrap().push("prepare");
                    Ok(prepared(nonce, 0x73 + index as u8))
                }
            },
            {
                let events = Arc::clone(&events);
                move |_| {
                    events.lock().unwrap().push("catalog");
                    Ok(vec![catalog_entry(name, description)])
                }
            },
            {
                let events = Arc::clone(&events);
                let mapper = &mapper;
                move |request, boundary| {
                    events.lock().unwrap().push("mapper");
                    mapper
                        .map(request, boundary, deadline())
                        .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)
                }
            },
            {
                let events = Arc::clone(&events);
                let planner = &planner;
                move |request| {
                    events.lock().unwrap().push("planner");
                    planner
                        .plan(request, deadline())
                        .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)
                }
            },
            {
                let events = Arc::clone(&events);
                let held = Arc::clone(&held);
                let commits = Arc::clone(&commits);
                move |request| {
                    events.lock().unwrap().push("commit");
                    assert!(held.load(Ordering::SeqCst));
                    assert_eq!(request.plan().envelope_nonce(), Nonce32V2::new([nonce; 32]));
                    commits.fetch_add(1, Ordering::SeqCst);
                    CommitPlannerValueResponseV2::new(
                        ValueHandleV2::from_authority_entropy([0x81 + index as u8; 32]).unwrap(),
                        Digest32V2::new([0x82 + index as u8; 32]),
                        PlanRevisionDigestV2::new([0x83 + index as u8; 32]),
                        vec![
                            PlanStepHandleV2::from_authority_entropy([0x84 + index as u8; 32])
                                .unwrap(),
                        ],
                    )
                    .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)
                }
            },
        )
        .unwrap();
        assert_eq!(result.plan().steps().len(), 1);
        assert!(!held.load(Ordering::SeqCst));
    }

    mapper_server.join().unwrap();
    planner_server.join().unwrap();
    assert_eq!(mapper_calls.load(Ordering::SeqCst), 2);
    assert_eq!(planner_calls.load(Ordering::SeqCst), 2);
    assert_eq!(commits.load(Ordering::SeqCst), 2);
    let mapper_bodies = mapper_bodies.lock().unwrap();
    assert!(mapper_bodies[0]
        .windows(b"customer_lookup".len())
        .any(|w| w == b"customer_lookup"));
    assert!(mapper_bodies[1]
        .windows(b"account_lookup".len())
        .any(|w| w == b"account_lookup"));
    assert!(!mapper_bodies[0].windows(32).any(|w| w == [0x51; 32]));
    assert!(!mapper_bodies[1].windows(32).any(|w| w == [0x61; 32]));
    let planner_bodies = planner_bodies.lock().unwrap();
    for body in planner_bodies.iter() {
        assert!(!body
            .windows(b"customer_lookup".len())
            .any(|w| w == b"customer_lookup"));
        assert!(!body
            .windows(b"account_lookup".len())
            .any(|w| w == b"account_lookup"));
        assert!(!body.windows(32).any(|w| w == [0x51; 32] || w == [0x61; 32]));
    }
    let ids = planner_ids.lock().unwrap();
    assert_ne!(ids[0][0], ids[1][0]);
    assert_eq!(
        events.lock().unwrap().as_slice(),
        [
            "guard_acquire",
            "prepare",
            "catalog",
            "mapper",
            "planner",
            "commit",
            "guard_drop",
            "guard_acquire",
            "prepare",
            "catalog",
            "mapper",
            "planner",
            "commit",
            "guard_drop"
        ]
    );
}

#[test]
fn inactive_mapper_selection_is_rejected_before_planner_or_commit() {
    let active = vec![active_tool(0x11, 100, 10)];
    let mapper_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mapper_address = mapper_listener.local_addr().unwrap();
    let mapper_calls = Arc::new(AtomicUsize::new(0));
    let mapper_server = spawn_tls_model_server(mapper_listener, "/savana.mapper.v2/map", 1, {
        let mapper_calls = Arc::clone(&mapper_calls);
        move |_| {
            mapper_calls.fetch_add(1, Ordering::SeqCst);
            invalid_inactive_mapper_response()
        }
    });
    let unused_planner = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mapper, planner) = clients(mapper_address, unused_planner.local_addr().unwrap());
    let issuer = Mutex::new(StructuralNodeIdIssuerV2::new().unwrap());
    let planner_calls = AtomicUsize::new(0);
    let commits = AtomicUsize::new(0);
    let held = Arc::new(AtomicBool::new(true));
    let events = Arc::new(Mutex::new(vec!["guard_acquire"]));

    let result = execute_private_planning_pipeline_v2(
        Guard {
            held: Arc::clone(&held),
            events: Arc::clone(&events),
        },
        RunHandleV2::from_authority_entropy([0x12; 32]).unwrap(),
        &active,
        &issuer,
        IntentTrustBoundaryV2::Private,
        || {
            events.lock().unwrap().push("prepare");
            Ok(prepared(0x13, 0x14))
        },
        |_| {
            events.lock().unwrap().push("catalog");
            Ok(vec![catalog_entry("active_tool", "the only active tool")])
        },
        |request, boundary| {
            events.lock().unwrap().push("mapper");
            mapper
                .map(request, boundary, deadline())
                .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)
        },
        |request| {
            planner_calls.fetch_add(1, Ordering::SeqCst);
            planner
                .plan(request, deadline())
                .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)
        },
        |_| {
            commits.fetch_add(1, Ordering::SeqCst);
            Err(AgentBrowserAuthorityErrorV2::Unavailable)
        },
    );

    assert_eq!(
        result.err(),
        Some(AgentBrowserAuthorityErrorV2::InvalidReference)
    );
    mapper_server.join().unwrap();
    assert_eq!(mapper_calls.load(Ordering::SeqCst), 1);
    assert_eq!(planner_calls.load(Ordering::SeqCst), 0);
    assert_eq!(commits.load(Ordering::SeqCst), 0);
    assert!(!held.load(Ordering::SeqCst));
    assert_eq!(
        events.lock().unwrap().as_slice(),
        [
            "guard_acquire",
            "prepare",
            "catalog",
            "mapper",
            "guard_drop"
        ]
    );
}

#[test]
fn non_topological_planner_order_is_rejected_before_commit() {
    let active = vec![active_tool(0x21, 100, 10), active_tool(0x22, 200, 20)];
    let two_node_envelope = PlannerEnvelopeV2::new(
        PlannerRouteIdV2::new(9),
        StaticTemplateIdV2::new(7),
        PlannerIntentKindV2::Search,
        vec![ActionTemplateIdV2::new(10), ActionTemplateIdV2::new(20)],
        vec![],
        vec![],
        PlannerLimitsV2::new(2, 1, 1, 4096).unwrap(),
        Nonce32V2::new([0x23; 32]),
        deadline(),
    )
    .unwrap();
    let entries = vec![
        catalog_entry_for(
            100,
            10,
            ConnectorStructuralRoleV2::Source,
            EffectSetV2::READ,
            "source",
            "read source records",
        ),
        catalog_entry_for(
            200,
            20,
            ConnectorStructuralRoleV2::Sink,
            EffectSetV2::SEND,
            "sink",
            "send records to destination",
        ),
    ];
    let mapper_request = MapperIntentRequestV2::new(
        &two_node_envelope,
        &active,
        entries
            .iter()
            .map(MapperCatalogToolV2::from_catalog_entry)
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
    )
    .unwrap();
    let mapped = MappedWorkflowV2::new(
        &mapper_request,
        vec![
            MappedNodeV2::new(
                1,
                ToolClassIdV2::new(100),
                ActionTemplateIdV2::new(10),
                vec![],
                StructuralRoleV2::Source,
                EffectSetV2::READ,
            )
            .unwrap(),
            MappedNodeV2::new(
                2,
                ToolClassIdV2::new(200),
                ActionTemplateIdV2::new(20),
                vec![],
                StructuralRoleV2::Sink,
                EffectSetV2::SEND,
            )
            .unwrap(),
        ],
        vec![MappedEdgeV2::new(1, 2).unwrap()],
    )
    .unwrap();
    let mapper_response = encode_mapped_workflow_v2(&mapped).unwrap();
    let mapper_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mapper_address = mapper_listener.local_addr().unwrap();
    let mapper_server =
        spawn_tls_model_server(mapper_listener, "/savana.mapper.v2/map", 1, move |_| {
            mapper_response.clone()
        });
    let planner_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let planner_address = planner_listener.local_addr().unwrap();
    let planner_calls = Arc::new(AtomicUsize::new(0));
    let planner_server = spawn_tls_model_server(planner_listener, "/savana.planner.v2/plan", 1, {
        let planner_calls = Arc::clone(&planner_calls);
        move |body| {
            planner_calls.fetch_add(1, Ordering::SeqCst);
            let request =
                savana_agentd::planner_privacy::decode_structural_planner_request_v2(&body)
                    .unwrap();
            let edge = request.graph().edges()[0];
            encode_ordered_structural_plan_v2(
                &OrderedStructuralPlanV2::new(vec![edge.to(), edge.from()]).unwrap(),
            )
            .unwrap()
        }
    });
    let (mapper, planner) = clients(mapper_address, planner_address);
    let issuer = Mutex::new(StructuralNodeIdIssuerV2::new().unwrap());
    let commits = AtomicUsize::new(0);
    let held = Arc::new(AtomicBool::new(true));
    let events = Arc::new(Mutex::new(vec!["guard_acquire"]));

    let result = execute_private_planning_pipeline_v2(
        Guard {
            held: Arc::clone(&held),
            events: Arc::clone(&events),
        },
        RunHandleV2::from_authority_entropy([0x24; 32]).unwrap(),
        &active,
        &issuer,
        IntentTrustBoundaryV2::Private,
        || {
            events.lock().unwrap().push("prepare");
            Ok(prepared_from(two_node_envelope, 0x25))
        },
        |_| {
            events.lock().unwrap().push("catalog");
            Ok(entries)
        },
        |request, boundary| {
            events.lock().unwrap().push("mapper");
            mapper
                .map(request, boundary, deadline())
                .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)
        },
        |request| {
            events.lock().unwrap().push("planner");
            planner
                .plan(request, deadline())
                .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)
        },
        |_| {
            commits.fetch_add(1, Ordering::SeqCst);
            Err(AgentBrowserAuthorityErrorV2::Unavailable)
        },
    );

    assert_eq!(
        result.err(),
        Some(AgentBrowserAuthorityErrorV2::InvalidReference)
    );
    mapper_server.join().unwrap();
    planner_server.join().unwrap();
    assert_eq!(planner_calls.load(Ordering::SeqCst), 1);
    assert_eq!(commits.load(Ordering::SeqCst), 0);
    assert!(!held.load(Ordering::SeqCst));
    assert_eq!(
        events.lock().unwrap().as_slice(),
        [
            "guard_acquire",
            "prepare",
            "catalog",
            "mapper",
            "planner",
            "guard_drop"
        ]
    );
}

#[test]
fn different_envelope_and_semantics_produce_identical_planner_bytes_for_the_same_graph() {
    let active = vec![active_tool(0x31, 100, 10)];
    let planner_bodies = Arc::new(Mutex::new(Vec::new()));
    let inputs = [
        (
            PlannerEnvelopeV2::new(
                PlannerRouteIdV2::new(91),
                StaticTemplateIdV2::new(71),
                PlannerIntentKindV2::Search,
                vec![ActionTemplateIdV2::new(10)],
                vec![],
                vec![],
                PlannerLimitsV2::new(2, 1, 1, 4096).unwrap(),
                Nonce32V2::new([0x91; 32]),
                deadline(),
            )
            .unwrap(),
            catalog_entry("customer_lookup", "query customer records"),
        ),
        (
            PlannerEnvelopeV2::new(
                PlannerRouteIdV2::new(92),
                StaticTemplateIdV2::new(72),
                PlannerIntentKindV2::SendMessage,
                vec![ActionTemplateIdV2::new(10)],
                vec![],
                vec![],
                PlannerLimitsV2::new(2, 1, 1, 4096).unwrap(),
                Nonce32V2::new([0x92; 32]),
                deadline(),
            )
            .unwrap(),
            catalog_entry("dataroom_lookup", "query acquisition records"),
        ),
    ];

    for (index, (envelope, entry)) in inputs.into_iter().enumerate() {
        let issuer =
            Mutex::new(StructuralNodeIdIssuerV2::for_test([0xa1; 32], [0xb2; 16]).unwrap());
        let bodies = Arc::clone(&planner_bodies);
        let nonce = envelope.envelope_nonce();
        execute_private_planning_pipeline_v2(
            (),
            RunHandleV2::from_authority_entropy([0xa3 + index as u8; 32]).unwrap(),
            &active,
            &issuer,
            IntentTrustBoundaryV2::Private,
            || Ok(prepared_from(envelope, 0xa5 + index as u8)),
            |_| Ok(vec![entry]),
            |request, _| {
                Ok(MappedWorkflowV2::new(
                    request,
                    vec![MappedNodeV2::new(
                        1,
                        ToolClassIdV2::new(100),
                        ActionTemplateIdV2::new(10),
                        vec![],
                        StructuralRoleV2::Source,
                        EffectSetV2::READ,
                    )
                    .unwrap()],
                    vec![],
                )
                .unwrap())
            },
            |request| {
                bodies
                    .lock()
                    .unwrap()
                    .push(encode_structural_planner_request_v2(request).unwrap());
                Ok(OrderedStructuralPlanV2::new(vec![request.graph().nodes()[0].id()]).unwrap())
            },
            |request| {
                assert_eq!(request.plan().envelope_nonce(), nonce);
                CommitPlannerValueResponseV2::new(
                    ValueHandleV2::from_authority_entropy([0xa7 + index as u8; 32]).unwrap(),
                    Digest32V2::new([0xa9 + index as u8; 32]),
                    PlanRevisionDigestV2::new([0xab + index as u8; 32]),
                    vec![
                        PlanStepHandleV2::from_authority_entropy([0xad + index as u8; 32]).unwrap(),
                    ],
                )
                .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)
            },
        )
        .unwrap();
    }

    let bodies = planner_bodies.lock().unwrap();
    assert_eq!(bodies.len(), 2);
    assert_eq!(bodies[0], bodies[1]);
}
