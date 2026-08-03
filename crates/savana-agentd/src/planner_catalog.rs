use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};
use hmac::{Hmac, Mac as _};
use rustix::fs::{
    fchmod, open as rustix_open, openat, renameat, statat, unlinkat, AtFlags, FileType, Mode,
    OFlags,
};
use rustix::io::Errno;
use savana_kernel_protocol::v2::{ActionTemplateIdV2, ActiveToolViewV2, Digest32V2, ToolClassIdV2};
use savana_policy_core::v2::{ConnectorDescriptorV2, ConnectorStructuralRoleV2, EffectSetV2};
use sha2::{Digest as _, Sha256};
use unicode_normalization::UnicodeNormalization as _;
use zeroize::Zeroizing;

const STATE_FILE_NAME_V2: &str = "planner-catalog-state-v2.cbor";
const SCHEMA_VERSION_V2: u16 = 2;
const KEY_DOMAIN_V2: &[u8] = b"SAVANA_AGENTD_PLANNER_CATALOG_KEY_V2\0";
const STATE_DOMAIN_V2: &[u8] = b"SAVANA_AGENTD_PLANNER_CATALOG_STATE_V2\0";
const HEAD_DOMAIN_V2: &[u8] = b"SAVANA_AGENTD_PLANNER_CATALOG_HEAD_V2\0";
const NONCE_BYTES_V2: usize = 12;
const MAX_STATE_BYTES_V2: u64 = 16 * 1024 * 1024;
const MAX_CATALOG_ENTRIES_V2: usize = 4096;
const MAX_SEMANTIC_TEXT_BYTES_V2: usize = 1024;
const TEMP_ATTEMPTS_V2: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PlannerCatalogErrorV2 {
    #[error("planner catalog input is invalid")]
    Invalid,
    #[error("planner catalog durable state is unavailable")]
    DurableState,
    #[error("planner catalog authentication failed")]
    Authentication,
    #[error("planner catalog rollback was detected")]
    RollbackDetected,
    #[error("planner catalog commit outcome is uncertain")]
    CommitUncertain,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoundedPlannerSemanticTextV2(String);

impl core::fmt::Debug for BoundedPlannerSemanticTextV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BoundedPlannerSemanticTextV2(<redacted>)")
    }
}

impl BoundedPlannerSemanticTextV2 {
    pub fn new(value: impl Into<String>) -> Result<Self, PlannerCatalogErrorV2> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_SEMANTIC_TEXT_BYTES_V2
            || value.chars().any(unsafe_semantic_char)
            || !value.chars().nfc().eq(value.chars())
        {
            return Err(PlannerCatalogErrorV2::Invalid);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn unsafe_semantic_char(value: char) -> bool {
    value.is_control()
        || matches!(
            value,
            '\u{00ad}'
                | '\u{034f}'
                | '\u{061c}'
                | '\u{115f}'
                | '\u{1160}'
                | '\u{17b4}'
                | '\u{17b5}'
                | '\u{180b}'..='\u{180f}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
        )
}

#[derive(Clone, PartialEq, Eq)]
pub struct PlannerCatalogEntryV2 {
    tool_class: ToolClassIdV2,
    action_template: ActionTemplateIdV2,
    structural_role: ConnectorStructuralRoleV2,
    effects: EffectSetV2,
    semantic_name: BoundedPlannerSemanticTextV2,
    semantic_description: BoundedPlannerSemanticTextV2,
}

impl core::fmt::Debug for PlannerCatalogEntryV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PlannerCatalogEntryV2")
            .field("tool_class", &self.tool_class)
            .field("action_template", &self.action_template)
            .field("structural_role", &self.structural_role)
            .field("effects", &self.effects)
            .field("semantic_name", &"<redacted>")
            .field("semantic_description", &"<redacted>")
            .finish()
    }
}

impl PlannerCatalogEntryV2 {
    pub fn new(
        tool_class: ToolClassIdV2,
        action_template: ActionTemplateIdV2,
        structural_role: ConnectorStructuralRoleV2,
        effects: EffectSetV2,
        semantic_name: BoundedPlannerSemanticTextV2,
        semantic_description: BoundedPlannerSemanticTextV2,
    ) -> Result<Self, PlannerCatalogErrorV2> {
        if tool_class.get() == 0 || action_template.get() == 0 || effects.bits() == 0 {
            return Err(PlannerCatalogErrorV2::Invalid);
        }
        Ok(Self {
            tool_class,
            action_template,
            structural_role,
            effects,
            semantic_name,
            semantic_description,
        })
    }

    pub const fn tool_class(&self) -> ToolClassIdV2 {
        self.tool_class
    }

    pub const fn action_template(&self) -> ActionTemplateIdV2 {
        self.action_template
    }

    pub const fn structural_role(&self) -> ConnectorStructuralRoleV2 {
        self.structural_role
    }

    pub const fn effects(&self) -> EffectSetV2 {
        self.effects
    }

    pub const fn semantic_name(&self) -> &BoundedPlannerSemanticTextV2 {
        &self.semantic_name
    }

    pub const fn semantic_description(&self) -> &BoundedPlannerSemanticTextV2 {
        &self.semantic_description
    }
}

pub fn project_connector_descriptor_v2(
    descriptor: &ConnectorDescriptorV2,
) -> Result<Vec<PlannerCatalogEntryV2>, PlannerCatalogErrorV2> {
    let display_name = descriptor.display_name().as_str();
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(descriptor.tool_descriptors().len())
        .map_err(|_| PlannerCatalogErrorV2::DurableState)?;
    for tool in descriptor.tool_descriptors() {
        let provider_tool_id = tool.provider_tool_id().as_str();
        entries.push(PlannerCatalogEntryV2::new(
            tool.tool_class(),
            tool.action_template(),
            descriptor.structural_role(),
            tool.effects(),
            BoundedPlannerSemanticTextV2::new(format!("{display_name}/{provider_tool_id}"))?,
            BoundedPlannerSemanticTextV2::new(format!(
                "connector {display_name}; tool {provider_tool_id}"
            ))?,
        )?);
    }
    entries.sort_by_key(entry_key);
    validate_entries(&entries)?;
    Ok(entries)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DurablePlannerCatalogNamespaceV2 {
    installation_id: Digest32V2,
    store_id: Digest32V2,
}

impl DurablePlannerCatalogNamespaceV2 {
    pub fn from_verified_installation(
        installation_id: Digest32V2,
        store_id: Digest32V2,
    ) -> Result<Self, PlannerCatalogErrorV2> {
        if is_zero(installation_id.as_bytes()) || is_zero(store_id.as_bytes()) {
            return Err(PlannerCatalogErrorV2::Invalid);
        }
        Ok(Self {
            installation_id,
            store_id,
        })
    }

    pub const fn installation_id(self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn store_id(self) -> Digest32V2 {
        self.store_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannerCatalogStateHeadV2 {
    sequence: u64,
    state_digest: Digest32V2,
}

impl Default for PlannerCatalogStateHeadV2 {
    fn default() -> Self {
        Self::GENESIS
    }
}

impl PlannerCatalogStateHeadV2 {
    const GENESIS: Self = Self {
        sequence: 0,
        state_digest: Digest32V2::new([0; 32]),
    };

    pub fn new(sequence: u64, state_digest: Digest32V2) -> Result<Self, PlannerCatalogErrorV2> {
        if (sequence == 0) != is_zero(state_digest.as_bytes()) {
            return Err(PlannerCatalogErrorV2::Invalid);
        }
        Ok(Self {
            sequence,
            state_digest,
        })
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    pub const fn state_digest(self) -> Digest32V2 {
        self.state_digest
    }
}

pub trait PlannerCatalogRollbackAnchorV2: Send {
    fn current_head(&self) -> Result<PlannerCatalogStateHeadV2, PlannerCatalogErrorV2>;

    fn compare_and_advance(
        &mut self,
        expected: PlannerCatalogStateHeadV2,
        next: PlannerCatalogStateHeadV2,
    ) -> Result<(), PlannerCatalogErrorV2>;
}

pub struct DurablePlannerCatalogV2 {
    path: SecureCatalogPathV2,
    namespace: DurablePlannerCatalogNamespaceV2,
    encryption_key: Zeroizing<[u8; 32]>,
    sequence: u64,
    current_head: PlannerCatalogStateHeadV2,
    rollback_anchor: Box<dyn PlannerCatalogRollbackAnchorV2>,
    entries: Vec<PlannerCatalogEntryV2>,
    poisoned: bool,
    #[cfg(test)]
    fail_next_connector_insert_for_test: bool,
}

impl core::fmt::Debug for DurablePlannerCatalogV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DurablePlannerCatalogV2")
            .field("path", &self.path.path)
            .field("sequence", &self.sequence)
            .field("entry_count", &self.entries.len())
            .field("poisoned", &self.poisoned)
            .finish()
    }
}

impl DurablePlannerCatalogV2 {
    pub fn open(
        path: &Path,
        master_key: [u8; 32],
        namespace: DurablePlannerCatalogNamespaceV2,
        mut rollback_anchor: Box<dyn PlannerCatalogRollbackAnchorV2>,
        shipped_entries: Vec<PlannerCatalogEntryV2>,
    ) -> Result<Self, PlannerCatalogErrorV2> {
        if master_key == [0; 32] {
            return Err(PlannerCatalogErrorV2::Invalid);
        }
        validate_entries(&shipped_entries)?;
        let path = SecureCatalogPathV2::open(path)?;
        let encryption_key = derive_key(&master_key, namespace)?;
        let anchored_head = rollback_anchor.current_head()?;
        let existing = path.read_existing()?;
        if let Some(bytes) = existing {
            let (sequence, previous, entries) =
                decode_encrypted_snapshot(&bytes, &encryption_key, namespace)?;
            if shipped_entries.iter().any(|shipped| {
                entries
                    .binary_search_by_key(&entry_key(shipped), entry_key)
                    .map_or(true, |index| entries[index] != *shipped)
            }) {
                return Err(PlannerCatalogErrorV2::Invalid);
            }
            let snapshot_head = PlannerCatalogStateHeadV2 {
                sequence,
                state_digest: state_head_digest(namespace, &bytes),
            };
            if snapshot_head != anchored_head {
                if sequence
                    == anchored_head
                        .sequence
                        .checked_add(1)
                        .ok_or(PlannerCatalogErrorV2::RollbackDetected)?
                    && previous == anchored_head.state_digest
                {
                    rollback_anchor.compare_and_advance(anchored_head, snapshot_head)?;
                } else {
                    return Err(PlannerCatalogErrorV2::RollbackDetected);
                }
            }
            return Ok(Self {
                path,
                namespace,
                encryption_key,
                sequence,
                current_head: snapshot_head,
                rollback_anchor,
                entries,
                poisoned: false,
                #[cfg(test)]
                fail_next_connector_insert_for_test: false,
            });
        }
        if anchored_head != PlannerCatalogStateHeadV2::GENESIS {
            return Err(PlannerCatalogErrorV2::RollbackDetected);
        }
        let mut value = Self {
            path,
            namespace,
            encryption_key,
            sequence: 0,
            current_head: PlannerCatalogStateHeadV2::GENESIS,
            rollback_anchor,
            entries: Vec::new(),
            poisoned: false,
            #[cfg(test)]
            fail_next_connector_insert_for_test: false,
        };
        value.commit(shipped_entries)?;
        Ok(value)
    }

    pub fn entries(&self) -> &[PlannerCatalogEntryV2] {
        &self.entries
    }

    pub fn insert_entries(
        &mut self,
        new_entries: Vec<PlannerCatalogEntryV2>,
    ) -> Result<(), PlannerCatalogErrorV2> {
        self.ensure_usable()?;
        validate_entries(&new_entries)?;
        let mut next = self.entries.clone();
        for entry in new_entries {
            match next.binary_search_by_key(&entry_key(&entry), entry_key) {
                Ok(index) if next[index] == entry => continue,
                Ok(_) => return Err(PlannerCatalogErrorV2::Invalid),
                Err(index) => next.insert(index, entry),
            }
        }
        if next == self.entries {
            return Ok(());
        }
        self.commit(next)
    }

    /// Persists the local semantic projection of a connector that kerneld has
    /// already authorized from an approved user settlement. Agentd commits
    /// this projection durably before asking kerneld to apply/activate the
    /// approved connector; `project_active` remains the runtime activation
    /// intersection.
    pub fn insert_connector_descriptor(
        &mut self,
        canonical_descriptor: &[u8],
    ) -> Result<(), PlannerCatalogErrorV2> {
        #[cfg(test)]
        if core::mem::take(&mut self.fail_next_connector_insert_for_test) {
            return Err(PlannerCatalogErrorV2::DurableState);
        }
        let descriptor =
            ConnectorDescriptorV2::from_canonical_bytes_for_local_projection(canonical_descriptor)
                .map_err(|_| PlannerCatalogErrorV2::Invalid)?;
        self.insert_entries(project_connector_descriptor_v2(&descriptor)?)
    }

    #[cfg(test)]
    pub(crate) fn fail_next_connector_insert_for_test(&mut self) {
        self.fail_next_connector_insert_for_test = true;
    }

    pub fn project_active(
        &self,
        active_tools: &[ActiveToolViewV2],
    ) -> Result<Vec<PlannerCatalogEntryV2>, PlannerCatalogErrorV2> {
        self.ensure_usable()?;
        let pairs = active_tools
            .iter()
            .map(|tool| (tool.tool_class().get(), tool.action_template().get()))
            .collect::<HashSet<_>>();
        Ok(self
            .entries
            .iter()
            .filter(|entry| pairs.contains(&entry_key(entry)))
            .cloned()
            .collect())
    }

    fn ensure_usable(&self) -> Result<(), PlannerCatalogErrorV2> {
        if self.poisoned {
            Err(PlannerCatalogErrorV2::CommitUncertain)
        } else {
            Ok(())
        }
    }

    fn commit(&mut self, entries: Vec<PlannerCatalogEntryV2>) -> Result<(), PlannerCatalogErrorV2> {
        validate_entries(&entries)?;
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(PlannerCatalogErrorV2::DurableState)?;
        let previous = self.current_head.state_digest;
        let bytes = encode_encrypted_snapshot(
            sequence,
            previous,
            &entries,
            &self.encryption_key,
            self.namespace,
        )?;
        let next_head = PlannerCatalogStateHeadV2 {
            sequence,
            state_digest: state_head_digest(self.namespace, &bytes),
        };
        if let Err(error) = self.path.replace(&bytes) {
            if error == PlannerCatalogErrorV2::CommitUncertain {
                self.poisoned = true;
            }
            return Err(error);
        }
        if self
            .rollback_anchor
            .compare_and_advance(self.current_head, next_head)
            .is_err()
        {
            self.poisoned = true;
            return Err(PlannerCatalogErrorV2::CommitUncertain);
        }
        self.sequence = sequence;
        self.current_head = next_head;
        self.entries = entries;
        Ok(())
    }
}

fn entry_key(entry: &PlannerCatalogEntryV2) -> (u32, u32) {
    (entry.tool_class.get(), entry.action_template.get())
}

fn validate_entries(entries: &[PlannerCatalogEntryV2]) -> Result<(), PlannerCatalogErrorV2> {
    if entries.len() > MAX_CATALOG_ENTRIES_V2
        || entries
            .windows(2)
            .any(|pair| entry_key(&pair[0]) >= entry_key(&pair[1]))
    {
        return Err(PlannerCatalogErrorV2::Invalid);
    }
    Ok(())
}

fn derive_key(
    master: &[u8; 32],
    namespace: DurablePlannerCatalogNamespaceV2,
) -> Result<Zeroizing<[u8; 32]>, PlannerCatalogErrorV2> {
    let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(master)
        .map_err(|_| PlannerCatalogErrorV2::Authentication)?;
    mac.update(KEY_DOMAIN_V2);
    mac.update(namespace.installation_id.as_bytes());
    mac.update(namespace.store_id.as_bytes());
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

fn encryption_aad(
    namespace: DurablePlannerCatalogNamespaceV2,
    sequence: u64,
    previous: Digest32V2,
    nonce: &[u8; NONCE_BYTES_V2],
) -> Vec<u8> {
    let mut aad = Vec::from(STATE_DOMAIN_V2);
    aad.extend_from_slice(namespace.installation_id.as_bytes());
    aad.extend_from_slice(namespace.store_id.as_bytes());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.extend_from_slice(previous.as_bytes());
    aad.extend_from_slice(nonce);
    aad
}

fn encode_encrypted_snapshot(
    sequence: u64,
    previous: Digest32V2,
    entries: &[PlannerCatalogEntryV2],
    key: &[u8; 32],
    namespace: DurablePlannerCatalogNamespaceV2,
) -> Result<Vec<u8>, PlannerCatalogErrorV2> {
    let plaintext = Zeroizing::new(encode_payload(sequence, previous, namespace, entries)?);
    let mut nonce = [0; NONCE_BYTES_V2];
    getrandom::getrandom(&mut nonce).map_err(|_| PlannerCatalogErrorV2::DurableState)?;
    if nonce == [0; NONCE_BYTES_V2] {
        return Err(PlannerCatalogErrorV2::DurableState);
    }
    let aad = encryption_aad(namespace, sequence, previous, &nonce);
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| PlannerCatalogErrorV2::Authentication)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| PlannerCatalogErrorV2::Authentication)?;
    encode_envelope(sequence, previous, &nonce, &ciphertext)
}

fn decode_encrypted_snapshot(
    bytes: &[u8],
    key: &[u8; 32],
    namespace: DurablePlannerCatalogNamespaceV2,
) -> Result<(u64, Digest32V2, Vec<PlannerCatalogEntryV2>), PlannerCatalogErrorV2> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES_V2 {
        return Err(PlannerCatalogErrorV2::DurableState);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 5)?;
    if decoder.u16().map_err(decode_state)? != SCHEMA_VERSION_V2 {
        return Err(PlannerCatalogErrorV2::DurableState);
    }
    let sequence = decoder.u64().map_err(decode_state)?;
    let previous = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let nonce = decode_fixed::<NONCE_BYTES_V2>(&mut decoder)?;
    let ciphertext = decoder.bytes().map_err(decode_state)?;
    if decoder.position() != bytes.len()
        || encode_envelope(sequence, previous, &nonce, ciphertext)? != bytes
    {
        return Err(PlannerCatalogErrorV2::DurableState);
    }
    let aad = encryption_aad(namespace, sequence, previous, &nonce);
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| PlannerCatalogErrorV2::Authentication)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| PlannerCatalogErrorV2::Authentication)?,
    );
    let entries = decode_payload(&plaintext, sequence, previous, namespace)?;
    if encode_payload(sequence, previous, namespace, &entries)?.as_slice() != plaintext.as_slice() {
        return Err(PlannerCatalogErrorV2::DurableState);
    }
    Ok((sequence, previous, entries))
}

fn encode_envelope(
    sequence: u64,
    previous: Digest32V2,
    nonce: &[u8; NONCE_BYTES_V2],
    ciphertext: &[u8],
) -> Result<Vec<u8>, PlannerCatalogErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(5)
        .and_then(|encoder| encoder.u16(SCHEMA_VERSION_V2))
        .and_then(|encoder| encoder.u64(sequence))
        .and_then(|encoder| encoder.bytes(previous.as_bytes()))
        .and_then(|encoder| encoder.bytes(nonce))
        .and_then(|encoder| encoder.bytes(ciphertext))
        .map_err(|_| PlannerCatalogErrorV2::DurableState)?;
    let bytes = encoder.into_writer();
    if bytes.len() as u64 > MAX_STATE_BYTES_V2 {
        return Err(PlannerCatalogErrorV2::DurableState);
    }
    Ok(bytes)
}

fn encode_payload(
    sequence: u64,
    previous: Digest32V2,
    namespace: DurablePlannerCatalogNamespaceV2,
    entries: &[PlannerCatalogEntryV2],
) -> Result<Vec<u8>, PlannerCatalogErrorV2> {
    validate_entries(entries)?;
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(7)
        .and_then(|encoder| encoder.u16(SCHEMA_VERSION_V2))
        .and_then(|encoder| encoder.u64(sequence))
        .and_then(|encoder| encoder.bytes(previous.as_bytes()))
        .and_then(|encoder| encoder.bytes(namespace.installation_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(namespace.store_id.as_bytes()))
        .and_then(|encoder| encoder.array(entries.len() as u64))
        .map_err(|_| PlannerCatalogErrorV2::DurableState)?;
    for entry in entries {
        encoder
            .array(6)
            .and_then(|encoder| encoder.u32(entry.tool_class.get()))
            .and_then(|encoder| encoder.u32(entry.action_template.get()))
            .and_then(|encoder| encoder.u16(entry.structural_role.tag()))
            .and_then(|encoder| encoder.u16(entry.effects.bits()))
            .and_then(|encoder| encoder.str(entry.semantic_name.as_str()))
            .and_then(|encoder| encoder.str(entry.semantic_description.as_str()))
            .map_err(|_| PlannerCatalogErrorV2::DurableState)?;
    }
    encoder
        .u16(SCHEMA_VERSION_V2)
        .map_err(|_| PlannerCatalogErrorV2::DurableState)?;
    Ok(encoder.into_writer())
}

fn decode_payload(
    bytes: &[u8],
    expected_sequence: u64,
    expected_previous: Digest32V2,
    namespace: DurablePlannerCatalogNamespaceV2,
) -> Result<Vec<PlannerCatalogEntryV2>, PlannerCatalogErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 7)?;
    if decoder.u16().map_err(decode_state)? != SCHEMA_VERSION_V2
        || decoder.u64().map_err(decode_state)? != expected_sequence
        || Digest32V2::new(decode_fixed::<32>(&mut decoder)?) != expected_previous
        || Digest32V2::new(decode_fixed::<32>(&mut decoder)?) != namespace.installation_id
        || Digest32V2::new(decode_fixed::<32>(&mut decoder)?) != namespace.store_id
    {
        return Err(PlannerCatalogErrorV2::Authentication);
    }
    let count = decoder
        .array()
        .map_err(decode_state)?
        .ok_or(PlannerCatalogErrorV2::DurableState)?;
    let count = usize::try_from(count).map_err(|_| PlannerCatalogErrorV2::DurableState)?;
    if count > MAX_CATALOG_ENTRIES_V2 {
        return Err(PlannerCatalogErrorV2::Invalid);
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| PlannerCatalogErrorV2::DurableState)?;
    for _ in 0..count {
        require_array(&mut decoder, 6)?;
        let class = decoder.u32().map_err(decode_state)?;
        let action = decoder.u32().map_err(decode_state)?;
        let role = match decoder.u16().map_err(decode_state)? {
            1 => ConnectorStructuralRoleV2::Source,
            2 => ConnectorStructuralRoleV2::Transform,
            3 => ConnectorStructuralRoleV2::Sink,
            _ => return Err(PlannerCatalogErrorV2::Invalid),
        };
        let effects = EffectSetV2::from_bits(decoder.u16().map_err(decode_state)?)
            .ok_or(PlannerCatalogErrorV2::Invalid)?;
        let name =
            BoundedPlannerSemanticTextV2::new(decoder.str().map_err(decode_state)?.to_owned())?;
        let description =
            BoundedPlannerSemanticTextV2::new(decoder.str().map_err(decode_state)?.to_owned())?;
        entries.push(PlannerCatalogEntryV2::new(
            ToolClassIdV2::new(class),
            ActionTemplateIdV2::new(action),
            role,
            effects,
            name,
            description,
        )?);
    }
    if decoder.u16().map_err(decode_state)? != SCHEMA_VERSION_V2
        || decoder.position() != bytes.len()
    {
        return Err(PlannerCatalogErrorV2::DurableState);
    }
    validate_entries(&entries)?;
    Ok(entries)
}

fn state_head_digest(namespace: DurablePlannerCatalogNamespaceV2, bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(HEAD_DOMAIN_V2);
    hasher.update(namespace.installation_id.as_bytes());
    hasher.update(namespace.store_id.as_bytes());
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

fn require_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), PlannerCatalogErrorV2> {
    match decoder.array().map_err(decode_state)? {
        Some(actual) if actual == expected => Ok(()),
        _ => Err(PlannerCatalogErrorV2::DurableState),
    }
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], PlannerCatalogErrorV2> {
    decoder
        .bytes()
        .map_err(decode_state)?
        .try_into()
        .map_err(|_| PlannerCatalogErrorV2::DurableState)
}

fn decode_state<T>(_error: T) -> PlannerCatalogErrorV2 {
    PlannerCatalogErrorV2::DurableState
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

struct SecureCatalogPathV2 {
    path: PathBuf,
    parent: File,
    parent_path: PathBuf,
    parent_dev: u64,
    parent_ino: u64,
    leaf: OsString,
    owner_uid: u32,
    owner_gid: u32,
}

impl SecureCatalogPathV2 {
    fn open(path: &Path) -> Result<Self, PlannerCatalogErrorV2> {
        if !path.is_absolute()
            || path.file_name().and_then(|name| name.to_str()) != Some(STATE_FILE_NAME_V2)
        {
            return Err(PlannerCatalogErrorV2::DurableState);
        }
        let parent_path = path.parent().ok_or(PlannerCatalogErrorV2::DurableState)?;
        let leaf = path
            .file_name()
            .ok_or(PlannerCatalogErrorV2::DurableState)?
            .to_os_string();
        let before =
            fs::symlink_metadata(parent_path).map_err(|_| PlannerCatalogErrorV2::DurableState)?;
        if before.file_type().is_symlink() {
            return Err(PlannerCatalogErrorV2::DurableState);
        }
        let descriptor = rustix_open(
            parent_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| PlannerCatalogErrorV2::DurableState)?;
        let parent = File::from(descriptor);
        let opened = parent
            .metadata()
            .map_err(|_| PlannerCatalogErrorV2::DurableState)?;
        if !opened.is_dir()
            || opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.uid() != before.uid()
            || opened.gid() != before.gid()
            || opened.mode() & 0o7777 != 0o700
        {
            return Err(PlannerCatalogErrorV2::DurableState);
        }
        let value = Self {
            path: path.to_owned(),
            parent,
            parent_path: parent_path.to_owned(),
            parent_dev: opened.dev(),
            parent_ino: opened.ino(),
            leaf,
            owner_uid: opened.uid(),
            owner_gid: opened.gid(),
        };
        value.recheck_parent()?;
        Ok(value)
    }

    fn recheck_parent(&self) -> Result<(), PlannerCatalogErrorV2> {
        let opened = self
            .parent
            .metadata()
            .map_err(|_| PlannerCatalogErrorV2::DurableState)?;
        let linked = fs::symlink_metadata(&self.parent_path)
            .map_err(|_| PlannerCatalogErrorV2::DurableState)?;
        if linked.file_type().is_symlink()
            || !linked.is_dir()
            || opened.dev() != self.parent_dev
            || opened.ino() != self.parent_ino
            || linked.dev() != self.parent_dev
            || linked.ino() != self.parent_ino
            || linked.uid() != self.owner_uid
            || linked.gid() != self.owner_gid
            || linked.mode() & 0o7777 != 0o700
        {
            return Err(PlannerCatalogErrorV2::DurableState);
        }
        Ok(())
    }

    fn read_existing(&self) -> Result<Option<Vec<u8>>, PlannerCatalogErrorV2> {
        self.read_existing_after_stat(|| {}, || {})
    }

    #[cfg(test)]
    fn read_existing_with_race_hook(
        &self,
        hook: impl FnOnce(),
    ) -> Result<Option<Vec<u8>>, PlannerCatalogErrorV2> {
        self.read_existing_after_stat(hook, || {})
    }

    #[cfg(test)]
    fn read_existing_with_post_read_race_hook(
        &self,
        hook: impl FnOnce(),
    ) -> Result<Option<Vec<u8>>, PlannerCatalogErrorV2> {
        self.read_existing_after_stat(|| {}, hook)
    }

    fn read_existing_after_stat(
        &self,
        before_open: impl FnOnce(),
        after_read: impl FnOnce(),
    ) -> Result<Option<Vec<u8>>, PlannerCatalogErrorV2> {
        self.recheck_parent()?;
        let before = match statat(&self.parent, &self.leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Ok(None),
            Err(_) => return Err(PlannerCatalogErrorV2::DurableState),
        };
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile {
            return Err(PlannerCatalogErrorV2::DurableState);
        }
        before_open();
        let descriptor = openat(
            &self.parent,
            &self.leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| PlannerCatalogErrorV2::DurableState)?;
        let mut file = File::from(descriptor);
        let opened = file
            .metadata()
            .map_err(|_| PlannerCatalogErrorV2::DurableState)?;
        if !opened.is_file()
            || i128::from(before.st_dev) != i128::from(opened.dev())
            || before.st_ino != opened.ino()
            || before.st_uid != self.owner_uid
            || before.st_gid != self.owner_gid
            || opened.uid() != self.owner_uid
            || opened.gid() != self.owner_gid
            || opened.mode() & 0o7777 != 0o600
            || opened.nlink() != 1
            || opened.len() == 0
            || opened.len() > MAX_STATE_BYTES_V2
        {
            return Err(PlannerCatalogErrorV2::DurableState);
        }
        let capacity =
            usize::try_from(opened.len()).map_err(|_| PlannerCatalogErrorV2::DurableState)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| PlannerCatalogErrorV2::DurableState)?;
        file.read_to_end(&mut bytes)
            .map_err(|_| PlannerCatalogErrorV2::DurableState)?;
        after_read();
        if bytes.len() != capacity {
            return Err(PlannerCatalogErrorV2::DurableState);
        }
        validate_catalog_file_at(
            &self.parent,
            &self.leaf,
            &file,
            self.owner_uid,
            self.owner_gid,
            opened.len(),
        )?;
        self.recheck_parent()?;
        Ok(Some(bytes))
    }

    fn replace(&self, bytes: &[u8]) -> Result<(), PlannerCatalogErrorV2> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES_V2 {
            return Err(PlannerCatalogErrorV2::DurableState);
        }
        self.recheck_parent()?;
        let (temporary_leaf, mut temporary) =
            create_catalog_temporary(&self.parent, &self.leaf, self.owner_uid, self.owner_gid)?;
        let before_rename = (|| {
            temporary
                .write_all(bytes)
                .map_err(|_| PlannerCatalogErrorV2::DurableState)?;
            temporary
                .sync_all()
                .map_err(|_| PlannerCatalogErrorV2::DurableState)?;
            validate_catalog_file_at(
                &self.parent,
                &temporary_leaf,
                &temporary,
                self.owner_uid,
                self.owner_gid,
                u64::try_from(bytes.len()).map_err(|_| PlannerCatalogErrorV2::DurableState)?,
            )?;
            self.recheck_parent()
        })();
        if before_rename.is_err() {
            let _ = unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
            return Err(PlannerCatalogErrorV2::DurableState);
        }
        if renameat(&self.parent, &temporary_leaf, &self.parent, &self.leaf).is_err() {
            let _ = unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
            return Err(PlannerCatalogErrorV2::DurableState);
        }
        validate_catalog_file_at(
            &self.parent,
            &self.leaf,
            &temporary,
            self.owner_uid,
            self.owner_gid,
            u64::try_from(bytes.len()).map_err(|_| PlannerCatalogErrorV2::CommitUncertain)?,
        )
        .map_err(|_| PlannerCatalogErrorV2::CommitUncertain)?;
        self.parent
            .sync_all()
            .map_err(|_| PlannerCatalogErrorV2::CommitUncertain)?;
        self.recheck_parent()
            .map_err(|_| PlannerCatalogErrorV2::CommitUncertain)
    }
}

fn create_catalog_temporary(
    parent: &File,
    final_leaf: &OsStr,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(OsString, File), PlannerCatalogErrorV2> {
    for _ in 0..TEMP_ATTEMPTS_V2 {
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).map_err(|_| PlannerCatalogErrorV2::DurableState)?;
        let mut temporary_leaf = OsString::from(".");
        temporary_leaf.push(final_leaf);
        temporary_leaf.push(format!(".tmp-{:032x}", u128::from_be_bytes(random)));
        match openat(
            parent,
            &temporary_leaf,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        ) {
            Ok(descriptor) => {
                let file = File::from(descriptor);
                fchmod(&file, Mode::from_bits_truncate(0o600))
                    .map_err(|_| PlannerCatalogErrorV2::DurableState)?;
                validate_catalog_file_at(parent, &temporary_leaf, &file, owner_uid, owner_gid, 0)?;
                return Ok((temporary_leaf, file));
            }
            Err(Errno::EXIST) => {}
            Err(_) => return Err(PlannerCatalogErrorV2::DurableState),
        }
    }
    Err(PlannerCatalogErrorV2::DurableState)
}

fn validate_catalog_file_at(
    parent: &File,
    leaf: &OsStr,
    file: &File,
    owner_uid: u32,
    owner_gid: u32,
    expected_length: u64,
) -> Result<(), PlannerCatalogErrorV2> {
    let opened = file
        .metadata()
        .map_err(|_| PlannerCatalogErrorV2::DurableState)?;
    let linked = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| PlannerCatalogErrorV2::DurableState)?;
    if !opened.is_file()
        || opened.uid() != owner_uid
        || opened.gid() != owner_gid
        || opened.mode() & 0o7777 != 0o600
        || opened.nlink() != 1
        || opened.len() != expected_length
        || FileType::from_raw_mode(linked.st_mode) != FileType::RegularFile
        || i128::from(linked.st_dev) != i128::from(opened.dev())
        || linked.st_ino != opened.ino()
        || linked.st_uid != owner_uid
        || linked.st_gid != owner_gid
        || linked.st_mode & 0o7777 != 0o600
        || linked.st_nlink != 1
        || u64::try_from(linked.st_size).ok() != Some(expected_length)
    {
        return Err(PlannerCatalogErrorV2::DurableState);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt as _};
    use std::sync::{Arc, Mutex};

    use savana_kernel_protocol::v2::{
        ActionTemplateIdV2, ActiveToolViewV2, Digest32V2, DisplayProjectionIdV2,
        ExecutorIdentityV2, ImplementationIdV2, ProjectionIdV2, RoleIdV2, StaticTemplateIdV2,
        ToolClassIdV2, ToolHandleV2, UnixMillisV2, VersionV2,
    };
    use savana_policy_core::v2::{
        AttemptKindV2, BoundedConnectorRetryPolicyV2, ConnectorDescriptorV2,
        ConnectorStructuralRoleV2, ConnectorTierV2, EffectSetV2, ExecutorIdempotencyContractV2,
        IdentifierV2, InternalValidatorDeclarationV2, UnsignedToolDescriptorV2,
    };
    use sha2::{Digest as _, Sha256};

    use super::{
        project_connector_descriptor_v2, BoundedPlannerSemanticTextV2,
        DurablePlannerCatalogNamespaceV2, DurablePlannerCatalogV2, PlannerCatalogEntryV2,
        PlannerCatalogErrorV2, PlannerCatalogRollbackAnchorV2, PlannerCatalogStateHeadV2,
        SecureCatalogPathV2,
    };

    #[derive(Clone, Default)]
    struct TestAnchor(Arc<Mutex<PlannerCatalogStateHeadV2>>);

    impl TestAnchor {
        fn head(&self) -> PlannerCatalogStateHeadV2 {
            *self.0.lock().unwrap()
        }
    }

    impl PlannerCatalogRollbackAnchorV2 for TestAnchor {
        fn current_head(&self) -> Result<PlannerCatalogStateHeadV2, PlannerCatalogErrorV2> {
            Ok(self.head())
        }

        fn compare_and_advance(
            &mut self,
            expected: PlannerCatalogStateHeadV2,
            next: PlannerCatalogStateHeadV2,
        ) -> Result<(), PlannerCatalogErrorV2> {
            let mut head = self.0.lock().unwrap();
            if *head != expected || next.sequence() != expected.sequence() + 1 {
                return Err(PlannerCatalogErrorV2::RollbackDetected);
            }
            *head = next;
            Ok(())
        }
    }

    fn digest(byte: u8) -> Digest32V2 {
        Digest32V2::new([byte; 32])
    }

    fn namespace(installation: u8, store: u8) -> DurablePlannerCatalogNamespaceV2 {
        DurablePlannerCatalogNamespaceV2::from_verified_installation(
            digest(installation),
            digest(store),
        )
        .unwrap()
    }

    fn private_path() -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("planner-catalog-state-v2.cbor");
        (directory, path)
    }

    fn entry(class: u32, action: u32, name: &str) -> PlannerCatalogEntryV2 {
        PlannerCatalogEntryV2::new(
            ToolClassIdV2::new(class),
            ActionTemplateIdV2::new(action),
            ConnectorStructuralRoleV2::Sink,
            EffectSetV2::SEND,
            BoundedPlannerSemanticTextV2::new(name).unwrap(),
            BoundedPlannerSemanticTextV2::new(format!("description {name}")).unwrap(),
        )
        .unwrap()
    }

    fn connector_tool(seed: u8, name: &str) -> UnsignedToolDescriptorV2 {
        let contract = ExecutorIdempotencyContractV2::ConnectorIdempotentByExecutionNonce;
        UnsignedToolDescriptorV2::from_verified_manifest(
            2,
            VersionV2::new(1, 0, 0),
            digest(seed),
            IdentifierV2::new(name).unwrap(),
            ActionTemplateIdV2::new(u32::from(seed) + 100),
            ToolClassIdV2::new(u32::from(seed) + 200),
            digest(seed.wrapping_add(1)),
            digest(seed.wrapping_add(2)),
            vec![RoleIdV2::new(1)],
            EffectSetV2::SEND,
            AttemptKindV2::ToolWrite,
            BoundedConnectorRetryPolicyV2::new(contract, 2, 1000).unwrap(),
            vec![InternalValidatorDeclarationV2::new(
                ImplementationIdV2::new(u32::from(seed) + 300),
                VersionV2::new(1, 0, 0),
                digest(seed.wrapping_add(3)),
            )],
            ExecutorIdentityV2::new([seed.wrapping_add(4); 32]),
            ProjectionIdV2::new(u32::from(seed) + 400),
            digest(seed.wrapping_add(5)),
            DisplayProjectionIdV2::new(u32::from(seed) + 500),
            digest(seed.wrapping_add(6)),
            contract,
            UnixMillisV2::new(1),
            UnixMillisV2::new(10_000),
        )
        .unwrap()
    }

    fn connector_descriptor() -> ConnectorDescriptorV2 {
        const NAME: &str = "mail-connector";
        let package = digest(0x61);
        let mut identity = minicbor::Encoder::new(Vec::new());
        identity
            .array(2)
            .unwrap()
            .str(NAME)
            .unwrap()
            .array(2)
            .unwrap()
            .u16(1)
            .unwrap()
            .bytes(package.as_bytes())
            .unwrap();
        let mut hasher = Sha256::new();
        hasher.update(b"savana.connector.user.v2\0");
        hasher.update(identity.into_writer());
        let connector_id = Digest32V2::new(hasher.finalize().into());
        let tools = [
            connector_tool(0x62, "mail.read"),
            connector_tool(0x63, "mail.send"),
        ];
        let mut descriptor = minicbor::Encoder::new(Vec::new());
        descriptor
            .array(8)
            .unwrap()
            .bytes(connector_id.as_bytes())
            .unwrap()
            .str(NAME)
            .unwrap()
            .u16(ConnectorTierV2::UserRegistered.tag())
            .unwrap()
            .array(2)
            .unwrap()
            .u16(1)
            .unwrap()
            .bytes(package.as_bytes())
            .unwrap()
            .array(2)
            .unwrap();
        for tool in &tools {
            descriptor
                .writer_mut()
                .extend_from_slice(&minicbor::to_vec(tool).unwrap());
        }
        descriptor
            .u16(EffectSetV2::SEND.bits())
            .unwrap()
            .u16(ConnectorStructuralRoleV2::Sink.tag())
            .unwrap()
            .u64(1)
            .unwrap();
        ConnectorDescriptorV2::from_canonical_bytes(&descriptor.into_writer(), &[]).unwrap()
    }

    #[test]
    fn connector_projection_derives_every_nested_tool_and_keeps_semantics_local() {
        let descriptor = connector_descriptor();
        let projected = project_connector_descriptor_v2(&descriptor).unwrap();
        assert_eq!(projected.len(), 2);
        for (entry, tool) in projected.iter().zip(descriptor.tool_descriptors()) {
            assert_eq!(entry.tool_class(), tool.tool_class());
            assert_eq!(entry.action_template(), tool.action_template());
            assert_eq!(entry.structural_role(), ConnectorStructuralRoleV2::Sink);
            assert_eq!(entry.effects(), EffectSetV2::SEND);
            assert_eq!(
                entry.semantic_name().as_str(),
                format!("mail-connector/{}", tool.provider_tool_id().as_str())
            );
            assert_eq!(
                entry.semantic_description().as_str(),
                format!(
                    "connector mail-connector; tool {}",
                    tool.provider_tool_id().as_str()
                )
            );
            assert!(!descriptor
                .canonical_bytes()
                .windows(entry.semantic_name().as_str().len())
                .any(|window| window == entry.semantic_name().as_str().as_bytes()));
        }
    }

    #[test]
    fn approved_registration_projection_is_durable_but_requires_an_active_kernel_pair() {
        let (_directory, path) = private_path();
        let anchor = TestAnchor::default();
        let descriptor = connector_descriptor();
        let expected = project_connector_descriptor_v2(&descriptor).unwrap();
        let mut catalog = DurablePlannerCatalogV2::open(
            &path,
            [0x71; 32],
            namespace(0x72, 0x73),
            Box::new(anchor.clone()),
            vec![],
        )
        .unwrap();

        // Production calls this only after kerneld has authorized the exact
        // approved descriptor and before kerneld applies it.
        catalog
            .insert_connector_descriptor(descriptor.canonical_bytes())
            .unwrap();
        assert_eq!(catalog.entries(), expected);
        assert!(catalog.project_active(&[]).unwrap().is_empty());
        drop(catalog);

        let reopened = DurablePlannerCatalogV2::open(
            &path,
            [0x71; 32],
            namespace(0x72, 0x73),
            Box::new(anchor),
            vec![],
        )
        .unwrap();
        assert_eq!(reopened.entries(), expected);
        assert!(reopened.project_active(&[]).unwrap().is_empty());
    }

    #[test]
    fn encrypted_catalog_round_trips_without_semantic_plaintext_and_binds_key_namespace_and_anchor()
    {
        let (_directory, path) = private_path();
        let anchor = TestAnchor::default();
        let shipped = entry(202, 102, "development.draft_due_diligence_report");
        let catalog = DurablePlannerCatalogV2::open(
            &path,
            [0x31; 32],
            namespace(0x32, 0x33),
            Box::new(anchor.clone()),
            vec![shipped.clone()],
        )
        .unwrap();
        assert_eq!(catalog.entries(), std::slice::from_ref(&shipped));
        let bytes = fs::read(&path).unwrap();
        assert!(!bytes
            .windows(shipped.semantic_name().as_str().len())
            .any(|window| { window == shipped.semantic_name().as_str().as_bytes() }));
        drop(catalog);

        assert_eq!(
            DurablePlannerCatalogV2::open(
                &path,
                [0x32; 32],
                namespace(0x32, 0x33),
                Box::new(anchor.clone()),
                vec![shipped.clone()],
            )
            .unwrap_err(),
            PlannerCatalogErrorV2::Authentication,
        );
        for wrong in [namespace(0x34, 0x33), namespace(0x32, 0x35)] {
            assert!(matches!(
                DurablePlannerCatalogV2::open(
                    &path,
                    [0x31; 32],
                    wrong,
                    Box::new(anchor.clone()),
                    vec![shipped.clone()],
                ),
                Err(PlannerCatalogErrorV2::Authentication | PlannerCatalogErrorV2::RollbackDetected)
            ));
        }
        fs::remove_file(&path).unwrap();
        assert_eq!(
            DurablePlannerCatalogV2::open(
                &path,
                [0x31; 32],
                namespace(0x32, 0x33),
                Box::new(anchor),
                vec![shipped],
            )
            .unwrap_err(),
            PlannerCatalogErrorV2::RollbackDetected,
        );
    }

    #[test]
    fn catalog_rejects_unsafe_text_duplicates_and_stale_entries_are_not_projected() {
        for invalid in ["", "not\nallowed", "e\u{301}"] {
            assert_eq!(
                BoundedPlannerSemanticTextV2::new(invalid).unwrap_err(),
                PlannerCatalogErrorV2::Invalid,
            );
        }
        let (_directory, path) = private_path();
        let duplicate = entry(11, 12, "duplicate");
        assert_eq!(
            DurablePlannerCatalogV2::open(
                &path,
                [0x41; 32],
                namespace(0x42, 0x43),
                Box::new(TestAnchor::default()),
                vec![duplicate.clone(), duplicate],
            )
            .unwrap_err(),
            PlannerCatalogErrorV2::Invalid,
        );
        let (_directory, path) = private_path();
        assert_eq!(
            DurablePlannerCatalogV2::open(
                &path,
                [0x42; 32],
                namespace(0x43, 0x44),
                Box::new(TestAnchor::default()),
                vec![entry(2, 2, "later"), entry(1, 1, "earlier")],
            )
            .unwrap_err(),
            PlannerCatalogErrorV2::Invalid,
        );

        let (_directory, path) = private_path();
        let active = entry(21, 22, "active");
        let stale = entry(23, 24, "stale");
        let catalog = DurablePlannerCatalogV2::open(
            &path,
            [0x44; 32],
            namespace(0x45, 0x46),
            Box::new(TestAnchor::default()),
            vec![active.clone(), stale],
        )
        .unwrap();
        let active_view = ActiveToolViewV2::new(
            ToolHandleV2::from_authority_entropy([1; 32]).unwrap(),
            active.action_template(),
            active.tool_class(),
            StaticTemplateIdV2::new(1),
        )
        .unwrap();
        assert_eq!(
            catalog.project_active(&[active_view]).unwrap(),
            vec![active]
        );
    }

    #[test]
    fn corruption_and_rollback_are_fail_closed() {
        let (_directory, path) = private_path();
        let anchor = TestAnchor::default();
        let mut catalog = DurablePlannerCatalogV2::open(
            &path,
            [0x51; 32],
            namespace(0x52, 0x53),
            Box::new(anchor.clone()),
            vec![entry(31, 32, "first")],
        )
        .unwrap();
        let first = fs::read(&path).unwrap();
        catalog
            .insert_entries(vec![entry(33, 34, "second")])
            .unwrap();
        fs::write(&path, first).unwrap();
        assert_eq!(
            DurablePlannerCatalogV2::open(
                &path,
                [0x51; 32],
                namespace(0x52, 0x53),
                Box::new(anchor.clone()),
                vec![entry(31, 32, "first")],
            )
            .unwrap_err(),
            PlannerCatalogErrorV2::RollbackDetected,
        );
        let mut corrupt = fs::read(&path).unwrap();
        *corrupt.last_mut().unwrap() ^= 1;
        fs::write(&path, corrupt).unwrap();
        assert!(DurablePlannerCatalogV2::open(
            &path,
            [0x51; 32],
            namespace(0x52, 0x53),
            Box::new(anchor),
            vec![entry(31, 32, "first")],
        )
        .is_err());
    }

    #[test]
    fn catalog_entry_limit_is_exactly_4096() {
        let exact = (1..=4096)
            .map(|value| entry(value, value, &format!("tool-{value}")))
            .collect::<Vec<_>>();
        let (_directory, path) = private_path();
        let catalog = DurablePlannerCatalogV2::open(
            &path,
            [0x61; 32],
            namespace(0x62, 0x63),
            Box::new(TestAnchor::default()),
            exact.clone(),
        )
        .unwrap();
        assert_eq!(catalog.entries().len(), 4096);

        let mut overflow = exact;
        overflow.push(entry(4097, 4097, "tool-4097"));
        let (_directory, path) = private_path();
        assert_eq!(
            DurablePlannerCatalogV2::open(
                &path,
                [0x64; 32],
                namespace(0x65, 0x66),
                Box::new(TestAnchor::default()),
                overflow,
            )
            .unwrap_err(),
            PlannerCatalogErrorV2::Invalid,
        );
    }

    #[test]
    fn unsafe_state_file_metadata_is_rejected() {
        let (_directory, path) = private_path();
        let anchor = TestAnchor::default();
        let catalog = DurablePlannerCatalogV2::open(
            &path,
            [0x81; 32],
            namespace(0x82, 0x83),
            Box::new(anchor.clone()),
            vec![],
        )
        .unwrap();
        drop(catalog);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            DurablePlannerCatalogV2::open(
                &path,
                [0x81; 32],
                namespace(0x82, 0x83),
                Box::new(anchor),
                vec![],
            )
            .unwrap_err(),
            PlannerCatalogErrorV2::DurableState,
        );

        let (directory, path) = private_path();
        let anchor = TestAnchor::default();
        let catalog = DurablePlannerCatalogV2::open(
            &path,
            [0x84; 32],
            namespace(0x85, 0x86),
            Box::new(anchor.clone()),
            vec![],
        )
        .unwrap();
        drop(catalog);
        fs::hard_link(&path, directory.path().join("catalog-hardlink")).unwrap();
        assert_eq!(
            DurablePlannerCatalogV2::open(
                &path,
                [0x84; 32],
                namespace(0x85, 0x86),
                Box::new(anchor),
                vec![],
            )
            .unwrap_err(),
            PlannerCatalogErrorV2::DurableState,
        );

        let (directory, path) = private_path();
        let anchor = TestAnchor::default();
        let catalog = DurablePlannerCatalogV2::open(
            &path,
            [0x87; 32],
            namespace(0x88, 0x89),
            Box::new(anchor.clone()),
            vec![],
        )
        .unwrap();
        drop(catalog);
        let target = directory.path().join("catalog-target");
        fs::rename(&path, &target).unwrap();
        symlink(&target, &path).unwrap();
        assert_eq!(
            DurablePlannerCatalogV2::open(
                &path,
                [0x87; 32],
                namespace(0x88, 0x89),
                Box::new(anchor),
                vec![],
            )
            .unwrap_err(),
            PlannerCatalogErrorV2::DurableState,
        );
    }

    #[test]
    fn leaf_swap_race_and_parent_rebind_are_detected_by_dirfd_identity() {
        let (_directory, path) = private_path();
        let catalog = DurablePlannerCatalogV2::open(
            &path,
            [0x91; 32],
            namespace(0x92, 0x93),
            Box::new(TestAnchor::default()),
            vec![],
        )
        .unwrap();
        drop(catalog);
        let anchored = SecureCatalogPathV2::open(&path).unwrap();
        let displaced = path.with_extension("displaced");
        assert_eq!(
            anchored
                .read_existing_with_race_hook(|| {
                    fs::rename(&path, &displaced).unwrap();
                    fs::write(&path, b"replacement").unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                })
                .unwrap_err(),
            PlannerCatalogErrorV2::DurableState,
        );

        let (_directory, path) = private_path();
        let catalog = DurablePlannerCatalogV2::open(
            &path,
            [0x97; 32],
            namespace(0x98, 0x99),
            Box::new(TestAnchor::default()),
            vec![],
        )
        .unwrap();
        drop(catalog);
        let anchored = SecureCatalogPathV2::open(&path).unwrap();
        let second_link = path.with_extension("second-link");
        assert_eq!(
            anchored
                .read_existing_with_post_read_race_hook(|| {
                    fs::hard_link(&path, &second_link).unwrap();
                })
                .unwrap_err(),
            PlannerCatalogErrorV2::DurableState,
        );

        let root = tempfile::tempdir().unwrap();
        let original_parent = root.path().join("catalog-parent");
        fs::create_dir(&original_parent).unwrap();
        fs::set_permissions(&original_parent, fs::Permissions::from_mode(0o700)).unwrap();
        let rebound_path = original_parent.join("planner-catalog-state-v2.cbor");
        let mut catalog = DurablePlannerCatalogV2::open(
            &rebound_path,
            [0x94; 32],
            namespace(0x95, 0x96),
            Box::new(TestAnchor::default()),
            vec![],
        )
        .unwrap();
        let displaced_parent = root.path().join("catalog-parent-displaced");
        fs::rename(&original_parent, &displaced_parent).unwrap();
        fs::create_dir(&original_parent).unwrap();
        fs::set_permissions(&original_parent, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            catalog
                .insert_entries(vec![entry(501, 502, "rebound")])
                .unwrap_err(),
            PlannerCatalogErrorV2::DurableState,
        );
        assert!(!rebound_path.exists());
    }
}
