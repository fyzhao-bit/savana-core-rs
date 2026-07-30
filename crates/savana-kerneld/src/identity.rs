use savana_kernel_protocol::{
    BootId, ProtocolVersion, ServerIdentityV1, StableCode, PROTOCOL_MAJOR, PROTOCOL_MINOR,
};

use crate::{DaemonConfig, DaemonError, DaemonSigningIdentity};

impl DaemonConfig {
    pub(crate) fn server_identity(
        &self,
        signing_identity: &DaemonSigningIdentity,
        boot_id: BootId,
        protocol: ProtocolVersion,
    ) -> Result<ServerIdentityV1, DaemonError> {
        if signing_identity.public_key() != *self.daemon_identity().public_key() {
            return Err(DaemonError::stable(StableCode::IdentityKeyPermissions));
        }
        if protocol != ProtocolVersion::new(PROTOCOL_MAJOR, PROTOCOL_MINOR)
            || protocol.major != self.protocol_major()
            || protocol.minor < self.minimum_minor()
            || protocol.minor > self.maximum_minor()
        {
            return Err(DaemonError::stable(StableCode::ProtocolUnsupportedVersion));
        }
        Ok(ServerIdentityV1 {
            daemon_key_id: self.daemon_identity().key_id().clone(),
            boot_id,
            protocol,
            release_digest: self.release_digest(),
            policy_digest: self.policy_digest(),
            policy_version: self.policy_version(),
            model_manifest_digest: self.model_manifest_digest(),
            approval_key_set_digest: self.approval_key_set_digest(),
            resource_profile_digest: self.resource_profile_digest(),
        })
    }
}
