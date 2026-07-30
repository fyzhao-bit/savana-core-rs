use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::Instant;

use savana_kernel_protocol::v2::{EndpointRoleV2, UnixMillisV2};

use crate::deployment_trust::DeploymentTrustErrorV2;
use crate::policy_runtime::V2GenerationRuntime;
use crate::v2_connection::serve_one_suite_one_v2_connection;
use crate::v2_dispatch::{KernelServiceDispatchErrorV2, KernelServiceDispatcherV2};
use crate::v2_edge::{VerifiedAcceptedPeerV2, VerifiedServiceEdgeV2};
use crate::v2_transport_owner::KernelV2HandshakeOwner;

pub(crate) trait NativeUnixPeerVerifierV2: Send + Sync {
    fn verify(
        &self,
        stream: &UnixStream,
        edge: &VerifiedServiceEdgeV2,
    ) -> Result<VerifiedAcceptedPeerV2, DeploymentTrustErrorV2>;
}

#[cfg(target_os = "linux")]
pub(crate) struct LinuxNativeUnixPeerVerifierV2;

#[cfg(target_os = "linux")]
impl NativeUnixPeerVerifierV2 for LinuxNativeUnixPeerVerifierV2 {
    fn verify(
        &self,
        stream: &UnixStream,
        edge: &VerifiedServiceEdgeV2,
    ) -> Result<VerifiedAcceptedPeerV2, DeploymentTrustErrorV2> {
        let pinned = savana_platform_identity::measure_linux_peer_v2(stream)
            .map_err(|_| DeploymentTrustErrorV2::EdgeLockMismatch)?;
        edge.verify_native_peer(pinned.measurement())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum V2ListenerError {
    EndpointRole,
    NativeIdentity,
    DeadlineExceeded,
    Idle,
    Accept,
    Connection(KernelServiceDispatchErrorV2),
}

pub(crate) struct KerneldV2EndpointListener {
    listener: UnixListener,
    edge: Arc<VerifiedServiceEdgeV2>,
    runtime: Arc<V2GenerationRuntime>,
    peer_verifier: Arc<dyn NativeUnixPeerVerifierV2>,
    handshake_owner: Arc<KernelV2HandshakeOwner>,
    dispatcher: Arc<KernelServiceDispatcherV2>,
}

impl std::fmt::Debug for KerneldV2EndpointListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KerneldV2EndpointListener")
            .field("role", &self.edge.role())
            .finish_non_exhaustive()
    }
}

impl KerneldV2EndpointListener {
    pub(crate) fn new_agent(
        listener: UnixListener,
        edge: Arc<VerifiedServiceEdgeV2>,
        runtime: Arc<V2GenerationRuntime>,
        peer_verifier: Arc<dyn NativeUnixPeerVerifierV2>,
        handshake_owner: Arc<KernelV2HandshakeOwner>,
        dispatcher: Arc<KernelServiceDispatcherV2>,
    ) -> Result<Self, V2ListenerError> {
        Self::new_fixed(
            EndpointRoleV2::AgentKernel,
            listener,
            edge,
            runtime,
            peer_verifier,
            handshake_owner,
            dispatcher,
        )
    }

    pub(crate) fn new_ingress(
        listener: UnixListener,
        edge: Arc<VerifiedServiceEdgeV2>,
        runtime: Arc<V2GenerationRuntime>,
        peer_verifier: Arc<dyn NativeUnixPeerVerifierV2>,
        handshake_owner: Arc<KernelV2HandshakeOwner>,
        dispatcher: Arc<KernelServiceDispatcherV2>,
    ) -> Result<Self, V2ListenerError> {
        Self::new_fixed(
            EndpointRoleV2::IngressKernel,
            listener,
            edge,
            runtime,
            peer_verifier,
            handshake_owner,
            dispatcher,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_fixed(
        required_role: EndpointRoleV2,
        listener: UnixListener,
        edge: Arc<VerifiedServiceEdgeV2>,
        runtime: Arc<V2GenerationRuntime>,
        peer_verifier: Arc<dyn NativeUnixPeerVerifierV2>,
        handshake_owner: Arc<KernelV2HandshakeOwner>,
        dispatcher: Arc<KernelServiceDispatcherV2>,
    ) -> Result<Self, V2ListenerError> {
        if edge.role() != required_role
            || !matches!(
                required_role,
                EndpointRoleV2::AgentKernel | EndpointRoleV2::IngressKernel
            )
        {
            return Err(V2ListenerError::EndpointRole);
        }
        Ok(Self {
            listener,
            edge,
            runtime,
            peer_verifier,
            handshake_owner,
            dispatcher,
        })
    }

    pub(crate) fn serve_one(
        &self,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), V2ListenerError> {
        if Instant::now() >= deadline {
            return Err(V2ListenerError::DeadlineExceeded);
        }
        let (stream, _) = match self.listener.accept() {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(V2ListenerError::Idle)
            }
            Err(_) => return Err(V2ListenerError::Accept),
        };
        self.serve_stream(stream, now, deadline)
    }

    pub(crate) fn set_nonblocking(&self) -> Result<(), V2ListenerError> {
        self.listener
            .set_nonblocking(true)
            .map_err(|_| V2ListenerError::Accept)
    }

    pub(crate) fn try_clone(&self) -> Result<Self, V2ListenerError> {
        Ok(Self {
            listener: self
                .listener
                .try_clone()
                .map_err(|_| V2ListenerError::Accept)?,
            edge: Arc::clone(&self.edge),
            runtime: Arc::clone(&self.runtime),
            peer_verifier: Arc::clone(&self.peer_verifier),
            handshake_owner: Arc::clone(&self.handshake_owner),
            dispatcher: Arc::clone(&self.dispatcher),
        })
    }

    fn serve_stream(
        &self,
        stream: UnixStream,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), V2ListenerError> {
        let lease = self
            .runtime
            .acquire(&self.edge, deadline)
            .map_err(|error| {
                if error == savana_kernel_protocol::StableCode::DeadlineExceeded {
                    V2ListenerError::DeadlineExceeded
                } else {
                    V2ListenerError::NativeIdentity
                }
            })?;
        let accepted = self
            .peer_verifier
            .verify(&stream, &self.edge)
            .map_err(|_| V2ListenerError::NativeIdentity)?;
        if accepted.role() != self.edge.role()
            || accepted.client_identity() != self.edge.client_identity()
            || accepted.edge_digest() != lease.edge_digest()
        {
            return Err(V2ListenerError::NativeIdentity);
        }
        let result = serve_one_suite_one_v2_connection(
            stream,
            accepted.into_peer_binding(),
            lease,
            self.handshake_owner.as_ref(),
            self.dispatcher.as_ref(),
            now,
            deadline,
        )
        .map_err(V2ListenerError::Connection);
        result
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use ed25519_dalek::SigningKey;
    use savana_kernel_protocol::v2::{
        derive_ed25519_key_id_v2, BootIdV2, Digest32V2, Ed25519KeyIdV2,
        KernelServiceHandshakeEdgeV2, UnixMillisV2,
    };
    use savana_platform_identity::NativePeerMeasurementV2;

    use super::{KerneldV2EndpointListener, NativeUnixPeerVerifierV2, V2ListenerError};
    use crate::deployment_trust::{ClosedServiceEdgeIdV2, DeploymentTrustErrorV2};
    use crate::policy_runtime::V2GenerationRuntime;
    use crate::v2_dispatch::{
        KernelServiceDeploymentV2, KernelServiceDispatcherV2, KernelServiceResponseBodyV2,
    };
    use crate::v2_edge::{
        V2ActiveGenerationSnapshot, VerifiedAcceptedPeerV2, VerifiedServiceEdgeV2,
    };
    use crate::v2_kernel_owner::KernelRuntimeOwnerV2;
    use crate::v2_transport_owner::KernelV2HandshakeOwner;

    struct FixedPeerVerifierV2 {
        measurement: NativePeerMeasurementV2,
    }

    impl NativeUnixPeerVerifierV2 for FixedPeerVerifierV2 {
        fn verify(
            &self,
            _stream: &UnixStream,
            edge: &VerifiedServiceEdgeV2,
        ) -> Result<VerifiedAcceptedPeerV2, DeploymentTrustErrorV2> {
            edge.verify_native_peer(&self.measurement)
        }
    }

    struct ListenerDependencies {
        edge: Arc<VerifiedServiceEdgeV2>,
        runtime: Arc<V2GenerationRuntime>,
        verifier: Arc<dyn NativeUnixPeerVerifierV2>,
        handshake: Arc<KernelV2HandshakeOwner>,
        dispatcher: Arc<KernelServiceDispatcherV2>,
        calls: Arc<AtomicUsize>,
    }

    fn dependencies(edge_id: ClosedServiceEdgeIdV2) -> ListenerDependencies {
        let edge = Arc::new(VerifiedServiceEdgeV2::for_generation_test(
            edge_id, 7, 8, 0x91,
        ));
        let runtime = Arc::new(V2GenerationRuntime::new());
        runtime
            .activate_for_test(V2ActiveGenerationSnapshot::for_generation_test(&edge))
            .unwrap();
        let client_key = SigningKey::from_bytes(&[0x31; 32]);
        let server_key = SigningKey::from_bytes(&[0x32; 32]);
        let protocol_edge = KernelServiceHandshakeEdgeV2::from_verified_deployment(
            edge.role(),
            Digest32V2::new([1; 32]),
            edge.client_identity(),
            edge.server_identity(),
            derive_ed25519_key_id_v2(client_key.verifying_key().to_bytes()),
            derive_ed25519_key_id_v2(server_key.verifying_key().to_bytes()),
            BootIdV2::new([4; 32]),
            5,
            edge.active_state_manifest_digest(),
            edge.deployment_generation(),
            edge.effect_fence_epoch(),
            Digest32V2::new([9; 32]),
            Digest32V2::new([10; 32]),
            Digest32V2::new([11; 32]),
            Digest32V2::new([12; 32]),
            Digest32V2::new([13; 32]),
            Digest32V2::new([14; 32]),
        )
        .unwrap();
        let handshake = Arc::new(
            KernelV2HandshakeOwner::spawn(
                protocol_edge,
                client_key.verifying_key().to_bytes(),
                server_key,
                4,
            )
            .unwrap(),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let handled = Arc::clone(&calls);
        let owner = KernelRuntimeOwnerV2::spawn_for_test(4, move |_| {
            handled.fetch_add(1, Ordering::SeqCst);
            Ok(KernelServiceResponseBodyV2::from_typed_handler(vec![0x80]).unwrap())
        })
        .unwrap();
        let dispatcher = Arc::new(
            KernelServiceDispatcherV2::spawn(
                KernelServiceDeploymentV2::from_verified_startup(
                    BootIdV2::new([4; 32]),
                    edge.server_identity(),
                    edge.active_state_manifest_digest(),
                    edge.deployment_generation(),
                )
                .unwrap(),
                Ed25519KeyIdV2::new([16; 32]),
                SigningKey::from_bytes(&[17; 32]),
                owner,
            )
            .unwrap(),
        );
        let verifier = Arc::new(FixedPeerVerifierV2 {
            measurement: NativePeerMeasurementV2::linux(501, 20, 42, 99, [0x96; 32]).unwrap(),
        });
        ListenerDependencies {
            edge,
            runtime,
            verifier,
            handshake,
            dispatcher,
            calls,
        }
    }

    fn listener() -> (tempfile::TempDir, UnixListener, std::path::PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("v2.sock");
        let listener = UnixListener::bind(&path).unwrap();
        (directory, listener, path)
    }

    #[test]
    fn endpoint_constructors_accept_only_their_fixed_role() {
        let agent = dependencies(ClosedServiceEdgeIdV2::AgentKernel);
        let ingress = dependencies(ClosedServiceEdgeIdV2::IngressKernel);
        let executor = dependencies(ClosedServiceEdgeIdV2::KernelExecutor);

        let (_dir, socket, _) = listener();
        assert!(KerneldV2EndpointListener::new_agent(
            socket,
            Arc::clone(&agent.edge),
            Arc::clone(&agent.runtime),
            Arc::clone(&agent.verifier),
            Arc::clone(&agent.handshake),
            Arc::clone(&agent.dispatcher),
        )
        .is_ok());
        let (_dir, socket, _) = listener();
        assert!(matches!(
            KerneldV2EndpointListener::new_agent(
                socket,
                Arc::clone(&ingress.edge),
                Arc::clone(&ingress.runtime),
                Arc::clone(&ingress.verifier),
                Arc::clone(&ingress.handshake),
                Arc::clone(&ingress.dispatcher),
            ),
            Err(V2ListenerError::EndpointRole)
        ));
        let (_dir, socket, _) = listener();
        assert!(KerneldV2EndpointListener::new_ingress(
            socket,
            Arc::clone(&ingress.edge),
            Arc::clone(&ingress.runtime),
            Arc::clone(&ingress.verifier),
            Arc::clone(&ingress.handshake),
            Arc::clone(&ingress.dispatcher),
        )
        .is_ok());
        let (_dir, socket, _) = listener();
        assert!(matches!(
            KerneldV2EndpointListener::new_ingress(
                socket,
                Arc::clone(&executor.edge),
                Arc::clone(&executor.runtime),
                Arc::clone(&executor.verifier),
                Arc::clone(&executor.handshake),
                Arc::clone(&executor.dispatcher),
            ),
            Err(V2ListenerError::EndpointRole)
        ));
    }

    #[test]
    fn v1_prefix_gets_no_response_and_never_reaches_dispatch() {
        let dependencies = dependencies(ClosedServiceEdgeIdV2::AgentKernel);
        let (_directory, socket, path) = listener();
        let endpoint = KerneldV2EndpointListener::new_agent(
            socket,
            Arc::clone(&dependencies.edge),
            Arc::clone(&dependencies.runtime),
            Arc::clone(&dependencies.verifier),
            Arc::clone(&dependencies.handshake),
            Arc::clone(&dependencies.dispatcher),
        )
        .unwrap();
        let server = thread::spawn(move || {
            endpoint.serve_one(
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(2),
            )
        });
        let mut client = UnixStream::connect(path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(b"SAVANA1\0").unwrap();
        client.write_all(&[0_u8; 12]).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut byte = [0_u8; 1];
        assert_eq!(client.read(&mut byte).unwrap(), 0);
        assert!(matches!(
            server.join().unwrap(),
            Err(V2ListenerError::Connection(
                crate::v2_dispatch::KernelServiceDispatchErrorV2::Malformed
            ))
        ));
        assert_eq!(dependencies.calls.load(Ordering::SeqCst), 0);
    }
}
