use crate::domain::{verify_directory, verify_orders, verify_root};
use crate::{
    codec, decode, hash, json, opaque, Context, Digest, Error, PlannerPort, PlannerView, RootRule,
    SignedMessage, SlotStatus, StateStore, TrustPins, ViewSlot,
};
use savana_kernel_protocol::v2::{
    ActionAlternativeV2, BusinessRequestV2, BusinessResponseDispositionV2, Digest32V2,
    MAX_BUSINESS_JSON_BYTES_V2,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryQuery {
    pub root: Digest,
    pub nonce: String,
    pub account: String,
    pub year_month: u32,
    pub started_at: u64,
}

/// Private transport material, deliberately not Serialize and not a dispatch
/// capability for the production executor. Never expose this through PlannerPort.
pub struct DispatchRequest {
    business: BusinessRequestV2,
    root: Digest,
    evidence: Digest,
    descriptor: Digest,
}
impl DispatchRequest {
    pub fn business(&self) -> &BusinessRequestV2 {
        &self.business
    }
    pub fn root_digest(&self) -> Digest {
        self.root
    }
    pub fn evidence_digest(&self) -> Digest {
        self.evidence
    }
    pub fn alternative(&self) -> Result<ActionAlternativeV2, Error> {
        self.business
            .action_alternative(Digest32V2::new(self.descriptor))
            .map_err(|_| Error::Malformed)
    }
}

/// TRUSTED host transport: pins identify its actual endpoint and credential.
/// The implementation must have exclusive monitored effect access and return
/// the authenticated provider's bytes, not a worker-authored success assertion.
/// No concrete network transport is installed by this research crate.
pub trait ProviderTransport {
    fn target_identity(&self) -> Digest;
    fn credential_identity(&self) -> Digest;
    fn exchange(&mut self, request: &DispatchRequest) -> Result<Vec<u8>, Error>;
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Phase {
    Ready,
    Reserved,
    Attempted,
    Retained,
    Done,
    Unknown,
    Unavailable,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Entry {
    pub(crate) order: String,
    pub(crate) version: u64,
    pub(crate) merchant: String,
    pub(crate) contact: String,
    pub(crate) evidence: Digest,
    pub(crate) valid_until: u64,
    pub(crate) handle: String,
    pub(crate) execution: String,
    phase: Phase,
    response: Option<Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: u8,
    signed_root: SignedMessage,
    root_digest: Digest,
    pins: Digest,
    salt: Digest,
    last_now: u64,
    discoveries: u16,
    source_version: u64,
    source_semantics: Option<Digest>,
    directory_semantics: Option<Digest>,
    pending: Option<DiscoveryQuery>,
    accepted_query: Option<String>,
    accepted_evidence: Option<Digest>,
    entries: Vec<Entry>,
    revoked: bool,
    disclosures: u16,
    disclosure_closed: bool,
    view: PlannerView,
}

/// Exclusive trusted state owner. Mutation is committed before any public view
/// or transport attempt. A storage error poisons the owner until authenticated reopen.
pub struct Workflow<S: StateStore> {
    store: S,
    root: RootRule,
    pins: TrustPins,
    state: Snapshot,
    poisoned: bool,
}
impl<S: StateStore> Workflow<S> {
    pub fn create(
        mut store: S,
        pins: TrustPins,
        context: Context,
        signed_root: SignedMessage,
        now: u64,
    ) -> Result<Self, Error> {
        if store.load()?.is_some() {
            return Err(Error::Conflict);
        }
        let root = verify_root(&signed_root, &pins, context)?;
        root.live(now)?;
        let mut salt = [0; 32];
        getrandom::getrandom(&mut salt).map_err(|_| Error::Storage)?;
        let state = Snapshot {
            schema: 1,
            root_digest: root.digest()?,
            signed_root,
            pins: pins.digest(),
            salt,
            last_now: now,
            discoveries: 0,
            source_version: 0,
            source_semantics: None,
            directory_semantics: None,
            pending: None,
            accepted_query: None,
            accepted_evidence: None,
            entries: Vec::new(),
            revoked: false,
            disclosures: 1,
            disclosure_closed: false,
            view: PlannerView {
                schema: 1,
                epoch: 1,
                discovering: false,
                can_discover: true,
                slots: Vec::new(),
            },
        };
        store.commit(&json(&state)?)?;
        Ok(Self {
            store,
            root,
            pins,
            state,
            poisoned: false,
        })
    }

    pub fn reopen(store: S, pins: TrustPins, context: Context) -> Result<Self, Error> {
        let state: Snapshot = decode(&store.load()?.ok_or(Error::Storage)?, 8 * 1024 * 1024)?;
        let root = verify_root(&state.signed_root, &pins, context)?;
        if state.schema != 1
            || state.root_digest != root.digest()?
            || state.pins != pins.digest()
            || state.salt == [0; 32]
            || state.entries.len() > usize::from(root.max_orders)
            || state.discoveries > root.max_discoveries
            || state.disclosures > root.max_disclosures
            || state.disclosures == 0
            || state.view.epoch != u64::from(state.disclosures)
            || state.last_now < root.not_before
            || state.source_semantics.is_some() != (state.source_version > 0)
            || state.directory_semantics.is_some() != state.source_semantics.is_some()
            || state.accepted_query.is_some() != state.accepted_evidence.is_some()
            || (!state.disclosure_closed && project(&state, &root) != state.view)
        {
            return Err(Error::Storage);
        }
        for (i, entry) in state.entries.iter().enumerate() {
            if entry.handle != opaque(&state.salt, b"slot", i as u64)
                || entry.execution != opaque(&state.salt, b"execution", i as u64)
                || state.entries[..i].iter().any(|e| e.order == entry.order)
                || entry.evidence == [0; 32]
                || entry.valid_until == 0
                || entry.valid_until > root.expires_at
                || (matches!(
                    entry.phase,
                    Phase::Ready | Phase::Reserved | Phase::Attempted | Phase::Unavailable
                ) && entry.response.is_some())
                || (matches!(entry.phase, Phase::Retained | Phase::Done)
                    && entry.response.is_none())
                || entry
                    .response
                    .as_ref()
                    .is_some_and(|b| b.len() > MAX_BUSINESS_JSON_BYTES_V2)
            {
                return Err(Error::Storage);
            }
            codec::request(&root, entry)?;
        }
        if let Some(query) = &state.pending {
            if query.root != state.root_digest
                || query.account != root.account
                || query.year_month != root.year_month
                || query.started_at > state.last_now
                || query.nonce != opaque(&state.salt, b"query", u64::from(state.discoveries))
            {
                return Err(Error::Storage);
            }
        }
        let mut this = Self {
            store,
            root,
            pins,
            state,
            poisoned: false,
        };
        // The fence is durable: if no response was durably retained, never retry.
        // A retained response can be classified after restart without transport.
        let mut next = this.state.clone();
        let mut changed = false;
        for entry in &mut next.entries {
            match entry.phase {
                Phase::Attempted => {
                    entry.phase = Phase::Unknown;
                    changed = true;
                }
                Phase::Retained => {
                    settle(&this.root, entry);
                    changed = true;
                }
                _ => {}
            }
        }
        if changed {
            this.commit(next)?;
        }
        Ok(this)
    }

    pub fn planner(&mut self) -> PlannerPort<'_, S> {
        PlannerPort { workflow: self }
    }
    pub fn root(&self) -> &RootRule {
        &self.root
    }
    pub fn into_store(self) -> S {
        self.store
    }
    /// Trusted source adapter only. This query never belongs in the planner view.
    pub fn pending_discovery(&self) -> Option<&DiscoveryQuery> {
        if self.poisoned {
            None
        } else {
            self.state.pending.as_ref()
        }
    }
    /// Owner-only audit counter, not another model query surface.
    pub fn attempts(&self) -> usize {
        self.state
            .entries
            .iter()
            .filter(|e| {
                matches!(
                    e.phase,
                    Phase::Reserved
                        | Phase::Attempted
                        | Phase::Retained
                        | Phase::Done
                        | Phase::Unknown
                )
            })
            .count()
    }
    pub fn disclosures(&self) -> u16 {
        self.state.disclosures
    }

    fn live(&self, now: u64) -> Result<(), Error> {
        if self.poisoned || self.state.revoked || now < self.state.last_now {
            return Err(Error::Unavailable);
        }
        self.root.live(now)
    }
    fn mutable_view(&self, epoch: u64, now: u64) -> Result<(), Error> {
        self.live(now)?;
        if self.state.disclosure_closed || epoch != self.state.view.epoch {
            return Err(Error::Unavailable);
        }
        if self.state.disclosures >= self.root.max_disclosures {
            return Err(Error::Limit);
        }
        Ok(())
    }
    pub(crate) fn visible(&mut self, now: u64) -> Result<PlannerView, Error> {
        self.live(now)?;
        if self.state.disclosure_closed {
            return Err(Error::Unavailable);
        }
        let mut next = self.state.clone();
        let mut changed = false;
        for entry in &mut next.entries {
            if entry.phase == Phase::Ready && now >= entry.valid_until {
                entry.phase = Phase::Unavailable;
                changed = true;
            }
        }
        if changed {
            next.last_now = now;
            self.commit(next)?;
        }
        if self.state.disclosure_closed {
            return Err(Error::Unavailable);
        }
        Ok(self.state.view.clone())
    }
    pub(crate) fn discover(&mut self, epoch: u64, now: u64) -> Result<(), Error> {
        self.mutable_view(epoch, now)?;
        if self.state.pending.is_some() {
            return Ok(());
        }
        if self.state.discoveries >= self.root.max_discoveries
            || self.state.entries.len() >= usize::from(self.root.max_orders)
        {
            return Err(Error::Limit);
        }
        let mut next = self.state.clone();
        next.discoveries += 1;
        next.last_now = now;
        next.pending = Some(DiscoveryQuery {
            root: next.root_digest,
            nonce: opaque(&next.salt, b"query", u64::from(next.discoveries)),
            account: self.root.account.clone(),
            year_month: self.root.year_month,
            started_at: now,
        });
        self.commit(next)
    }

    /// Only authenticated closed metadata may instantiate the fixed root rule.
    /// Text/amount fields are parsed, bounded and ignored; they are not authority.
    pub fn accept_discovery(
        &mut self,
        orders: &SignedMessage,
        directory: &SignedMessage,
        now: u64,
    ) -> Result<(), Error> {
        self.live(now)?;
        let orders_facts = verify_orders(orders, &self.pins)?;
        let directory_facts = verify_directory(directory, &self.pins)?;
        let evidence = hash(
            b"SAVANA_PRIVATE_CONTINUATION_EVIDENCE_V1\0",
            &[
                &orders.canonical,
                &orders.signature,
                &directory.canonical,
                &directory.signature,
            ],
        );
        if self.state.accepted_query.as_deref() == Some(&orders_facts.binding.query)
            && self.state.accepted_evidence == Some(evidence)
        {
            return Ok(());
        } // Exact replay changes neither views nor budgets.
        let query = self.state.pending.as_ref().ok_or(Error::Conflict)?;
        orders_facts
            .binding
            .check(&self.root, &query.nonce, self.root.orders_source, now)?;
        directory_facts
            .binding
            .check(&self.root, &query.nonce, self.root.directory_source, now)?;
        if orders_facts.binding.observed_at < query.started_at
            || directory_facts.binding.observed_at < query.started_at
            || directory_facts.version != self.root.directory_version
            || orders_facts.snapshot_version < self.state.source_version
        {
            return Err(Error::Conflict);
        }
        // Ignore non-authoritative fields even for consistency checks: hashing
        // notes/amounts here would make later rejection an equality oracle for
        // a field the planner was never permitted to inspect.
        let authority_fields: Vec<_> = orders_facts
            .orders
            .iter()
            .map(|o| {
                (
                    &o.id,
                    o.version,
                    &o.account,
                    o.year_month,
                    &o.merchant,
                    o.invoice_missing,
                )
            })
            .collect();
        let source_semantics = hash(
            b"SAVANA_PRIVATE_ORDER_SNAPSHOT_V1\0",
            &[&json(&authority_fields)?],
        );
        let directory_semantics = hash(
            b"SAVANA_PRIVATE_DIRECTORY_SNAPSHOT_V1\0",
            &[&json(&directory_facts.merchants)?],
        );
        if (orders_facts.snapshot_version == self.state.source_version
            && self.state.source_semantics != Some(source_semantics))
            || self
                .state
                .directory_semantics
                .is_some_and(|d| d != directory_semantics)
        {
            return Err(Error::Conflict);
        }
        let mut next = self.state.clone();
        for order in &orders_facts.orders {
            if order.account != self.root.account
                || order.year_month != self.root.year_month
                || !order.invoice_missing
            {
                continue;
            }
            let merchant = directory_facts
                .merchants
                .iter()
                .find(|m| m.id == order.merchant)
                .ok_or(Error::Authentication)?;
            if let Some(old) = next.entries.iter().find(|e| e.order == order.id) {
                // Later observations cannot replace the tuple or refresh a spent
                // identity. Even legitimate version changes require a new task.
                if old.version != order.version
                    || old.merchant != merchant.id
                    || old.contact != merchant.contact
                {
                    return Err(Error::Conflict);
                }
                continue;
            }
            if next.entries.len() >= usize::from(self.root.max_orders) {
                return Err(Error::Limit);
            }
            let valid_until = [
                orders_facts.binding.expires_at,
                directory_facts.binding.expires_at,
                orders_facts
                    .binding
                    .observed_at
                    .saturating_add(self.root.max_fact_age_ms)
                    .saturating_add(1),
                directory_facts
                    .binding
                    .observed_at
                    .saturating_add(self.root.max_fact_age_ms)
                    .saturating_add(1),
                self.root.expires_at,
            ]
            .into_iter()
            .min()
            .expect("nonempty bounds");
            let index = next.entries.len() as u64;
            next.entries.push(Entry {
                order: order.id.clone(),
                version: order.version,
                merchant: merchant.id.clone(),
                contact: merchant.contact.clone(),
                evidence,
                valid_until,
                handle: opaque(&next.salt, b"slot", index),
                execution: opaque(&next.salt, b"execution", index),
                phase: Phase::Ready,
                response: None,
            });
        }
        next.source_version = orders_facts.snapshot_version;
        next.source_semantics = Some(source_semantics);
        next.directory_semantics = Some(directory_semantics);
        next.accepted_query = Some(query.nonce.clone());
        next.accepted_evidence = Some(evidence);
        next.pending = None;
        next.last_now = now;
        self.commit(next)
    }

    pub(crate) fn reserve(&mut self, epoch: u64, handle: &str, now: u64) -> Result<(), Error> {
        self.mutable_view(epoch, now)?;
        let i = self
            .state
            .entries
            .iter()
            .position(|e| e.handle == handle)
            .ok_or(Error::Unavailable)?;
        let entry = &self.state.entries[i];
        if entry.phase != Phase::Ready || now >= entry.valid_until {
            return Err(Error::Unavailable);
        }
        let mut next = self.state.clone();
        next.entries[i].phase = Phase::Reserved;
        next.last_now = now;
        self.commit(next)
    }

    pub fn pending_request(&self, handle: &str, now: u64) -> Result<DispatchRequest, Error> {
        self.live(now)?;
        let entry = self
            .state
            .entries
            .iter()
            .find(|e| e.handle == handle)
            .ok_or(Error::Unavailable)?;
        if entry.phase != Phase::Reserved || now >= entry.valid_until {
            return Err(Error::Unavailable);
        }
        Ok(DispatchRequest {
            business: codec::request(&self.root, entry)?,
            root: self.state.root_digest,
            evidence: entry.evidence,
            descriptor: self.root.tool_descriptor,
        })
    }

    /// Rechecks the actual worker request before the durable attempt fence.
    /// This research API never accepts a worker-supplied terminal status.
    pub fn execute<T: ProviderTransport>(
        &mut self,
        handle: &str,
        worker_request: &[u8],
        transport: &mut T,
        now: u64,
    ) -> Result<(), Error> {
        let request = self.pending_request(handle, now)?;
        if transport.target_identity() != self.root.executor_target
            || transport.credential_identity() != self.root.executor_credential
        {
            return Err(Error::Authentication);
        }
        request
            .business
            .verify_equivalent(worker_request)
            .map_err(|_| Error::Authentication)?;
        let i = self
            .state
            .entries
            .iter()
            .position(|e| e.handle == handle)
            .ok_or(Error::Unavailable)?;
        let mut next = self.state.clone();
        next.entries[i].phase = Phase::Attempted;
        next.last_now = now;
        self.commit(next)?; // No transport before durable fence.
        let response = transport.exchange(&request);
        let mut next = self.state.clone();
        match response {
            Ok(bytes) if bytes.len() <= MAX_BUSINESS_JSON_BYTES_V2 => {
                next.entries[i].response = Some(bytes);
                next.entries[i].phase = Phase::Retained;
                self.commit(next)?; // Preserve authenticated bytes before outcome.
                next = self.state.clone();
                settle(&self.root, &mut next.entries[i]);
            }
            _ => next.entries[i].phase = Phase::Unknown,
        }
        self.commit(next)
    }

    /// Authenticated host cancellation only. No new reservation or attempt after
    /// this commit; an already attempted external effect is not rolled back.
    pub fn revoke(&mut self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Storage);
        }
        if self.state.revoked {
            return Ok(());
        }
        let mut next = self.state.clone();
        next.revoked = true;
        self.commit(next)
    }

    fn commit(&mut self, mut next: Snapshot) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Storage);
        }
        let proposed = project(&next, &self.root);
        if proposed != next.view && !next.disclosure_closed {
            if next.disclosures >= self.root.max_disclosures {
                next.disclosure_closed = true;
            } else {
                next.disclosures += 1;
                next.view = PlannerView {
                    epoch: u64::from(next.disclosures),
                    ..proposed
                };
            }
        }
        if let Err(e) = self.store.commit(&json(&next)?) {
            self.poisoned = true;
            return Err(e);
        }
        self.state = next;
        Ok(())
    }
}

fn project(s: &Snapshot, root: &RootRule) -> PlannerView {
    PlannerView {
        schema: 1,
        epoch: s.view.epoch,
        discovering: s.pending.is_some(),
        can_discover: !s.revoked
            && s.pending.is_none()
            && s.discoveries < root.max_discoveries
            && s.entries.len() < usize::from(root.max_orders),
        slots: s
            .entries
            .iter()
            .map(|e| ViewSlot {
                handle: e.handle.clone(),
                status: match e.phase {
                    Phase::Ready => SlotStatus::Ready,
                    Phase::Reserved | Phase::Attempted | Phase::Retained => SlotStatus::Pending,
                    Phase::Done => SlotStatus::Done,
                    Phase::Unknown => SlotStatus::Unknown,
                    Phase::Unavailable => SlotStatus::Unavailable,
                },
            })
            .collect(),
    }
}
fn settle(root: &RootRule, entry: &mut Entry) {
    let success = codec::request(root, entry).ok().and_then(|r| {
        entry
            .response
            .as_ref()
            .and_then(|bytes| r.classify_response(bytes).ok())
    });
    entry.phase = if success == Some(BusinessResponseDispositionV2::Succeeded) {
        Phase::Done
    } else {
        Phase::Unknown
    };
    // Failure is not evidence of no effect. No refund, new execution ID or retry.
}
