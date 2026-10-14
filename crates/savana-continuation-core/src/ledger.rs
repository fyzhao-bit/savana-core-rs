//! Pure multi-domain ledger transitions for integration INTO a durable owner.
//!
//! No filesystem, anchor, authenticated evidence, approval or transport exists
//! here. Apply is an in-memory atomic transition, NOT a durable reservation and
//! MUST NOT be treated as permission to dispatch. The real owner must persist
//! these values together with exact approval/request bindings before any effect.
use crate::finite::strict_order;
use crate::{digest, Digest, Error};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskKey {
    pub installation_lineage: Digest,
    pub task_lineage: Digest,
}

/// No path, version, handle, current key, connector session or plan revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceKey {
    pub source: Digest,
    pub namespace: Digest,
    pub object: Digest,
    pub incarnation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainLimit {
    pub domain: u16,
    pub total: u64,
    pub per_resource: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Charge {
    pub domain: u16,
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub execution: Digest,
    /// Digest of the actual exact request and its gate/approval/lease bindings.
    /// Caller must establish those bindings; this module does not verify them.
    pub request_binding: Digest,
    pub resource: ResourceKey,
    pub charges: Vec<Charge>,
}

#[derive(Debug, Clone)]
struct Counter {
    limit: DomainLimit,
    used: u64,
    members: BTreeMap<ResourceKey, u64>,
}

#[derive(Debug, Clone)]
pub struct Ledger {
    task: TaskKey,
    root: Digest,
    revision: u64,
    max_executions: usize,
    domains: BTreeMap<u16, Counter>,
    reservations: BTreeMap<Digest, Reservation>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: u16,
    task: TaskKey,
    root: Digest,
    max_executions: usize,
    limits: Vec<DomainLimit>,
    reservations: Vec<Reservation>,
}

/// Not Clone or Deserialize; bound to the entire prior ledger, not just a counter.
#[derive(Debug)]
pub struct PreparedUpdate {
    before: Digest,
    reservation: Reservation,
    replay: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    New,
    OriginalReplay,
}

impl Ledger {
    /// Private owner payload; encrypt and authenticate it before storage.
    pub fn snapshot(&self) -> Result<Vec<u8>, Error> {
        let bytes = serde_json::to_vec(&Snapshot {
            schema: 1,
            task: self.task,
            root: self.root,
            max_executions: self.max_executions,
            limits: self.domains.values().map(|c| c.limit.clone()).collect(),
            reservations: self.reservations.values().cloned().collect(),
        })
        .map_err(|_| Error::Invalid)?;
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(Error::Limit);
        }
        Ok(bytes)
    }

    /// Rebuild counters from original reservations, never trust serialized totals.
    /// Bounds/configuration are supplied independently by the authenticated owner.
    /// This does not authenticate freshness or supply rollback protection itself.
    pub fn restore(
        bytes: &[u8],
        task: TaskKey,
        root: Digest,
        limits: &[DomainLimit],
        max_executions: usize,
    ) -> Result<Self, Error> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(Error::Limit);
        }
        let snapshot: Snapshot = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        if snapshot.schema != 1
            || snapshot.task != task
            || snapshot.root != root
            || snapshot.limits != limits
            || snapshot.max_executions != max_executions
            || snapshot.reservations.len() > max_executions
            || !snapshot
                .reservations
                .windows(2)
                .all(|w| w[0].execution < w[1].execution)
            || serde_json::to_vec(&snapshot).map_err(|_| Error::Invalid)? != bytes
        {
            return Err(Error::Binding);
        }
        let mut ledger = Self::new(task, root, limits.to_vec(), max_executions)?;
        for reservation in snapshot.reservations {
            let prepared = ledger.prepare(reservation)?;
            ledger.apply(prepared)?;
        }
        Ok(ledger)
    }

    pub fn new(
        task: TaskKey,
        root: Digest,
        limits: Vec<DomainLimit>,
        max_executions: usize,
    ) -> Result<Self, Error> {
        if [task.installation_lineage, task.task_lineage, root].contains(&[0; 32])
            || limits.is_empty()
            || limits.len() > 64
            || max_executions == 0
            || max_executions > 65_536
            || !strict_order(&limits.iter().map(|d| d.domain).collect::<Vec<_>>())
            || limits
                .iter()
                .any(|l| l.total == 0 || l.per_resource == 0 || l.per_resource > l.total)
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            task,
            root,
            revision: 0,
            max_executions,
            domains: limits
                .into_iter()
                .map(|limit| {
                    (
                        limit.domain,
                        Counter {
                            limit,
                            used: 0,
                            members: BTreeMap::new(),
                        },
                    )
                })
                .collect(),
            reservations: BTreeMap::new(),
        })
    }

    /// Host-private diagnostic. Must not be forwarded as a model status field.
    pub fn usage(&self, domain: u16) -> Option<u64> {
        self.domains.get(&domain).map(|c| c.used)
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn reservation(&self, id: &Digest) -> Option<&Reservation> {
        self.reservations.get(id)
    }

    fn state_digest(&self) -> Digest {
        let domains: Vec<_> = self
            .domains
            .values()
            .map(|c| (&c.limit, c.used, c.members.iter().collect::<Vec<_>>()))
            .collect();
        let reservations: Vec<_> = self.reservations.values().collect();
        digest(
            b"SAVANA_STABLE_LEDGER_V04\0",
            &(
                self.task,
                self.root,
                self.revision,
                self.max_executions,
                domains,
                reservations,
            ),
        )
    }

    /// This first profile requires every registered domain on each reservation.
    /// Action-specific domain sets need a separately root-checked cost profile;
    /// caller omission must never silently skip a global or per-resource limit.
    pub fn prepare(&self, reservation: Reservation) -> Result<PreparedUpdate, Error> {
        if [
            reservation.execution,
            reservation.request_binding,
            reservation.resource.source,
            reservation.resource.namespace,
            reservation.resource.object,
        ]
        .contains(&[0; 32])
            || reservation.charges.is_empty()
            || reservation.charges.len() > 64
            || reservation.charges.iter().any(|c| c.amount == 0)
            || !strict_order(
                &reservation
                    .charges
                    .iter()
                    .map(|c| c.domain)
                    .collect::<Vec<_>>(),
            )
        {
            return Err(Error::Invalid);
        }
        if reservation
            .charges
            .iter()
            .map(|c| c.domain)
            .ne(self.domains.keys().copied())
        {
            return Err(Error::Binding);
        }
        if let Some(original) = self.reservations.get(&reservation.execution) {
            if original != &reservation {
                return Err(Error::History);
            }
            return Ok(PreparedUpdate {
                before: self.state_digest(),
                reservation,
                replay: true,
            });
        }
        if self.reservations.len() >= self.max_executions || self.revision == u64::MAX {
            return Err(Error::Limit);
        }
        for charge in &reservation.charges {
            let counter = self.domains.get(&charge.domain).ok_or(Error::Binding)?;
            let total = counter
                .used
                .checked_add(charge.amount)
                .ok_or(Error::Limit)?;
            let member = counter
                .members
                .get(&reservation.resource)
                .copied()
                .unwrap_or(0)
                .checked_add(charge.amount)
                .ok_or(Error::Limit)?;
            if total > counter.limit.total || member > counter.limit.per_resource {
                return Err(Error::Limit);
            }
        }
        Ok(PreparedUpdate {
            before: self.state_digest(),
            reservation,
            replay: false,
        })
    }

    /// All-or-none in-memory apply; a durable owner still must commit/anchor it.
    /// There is deliberately no refund, reset, rename or replan method.
    pub fn apply(&mut self, update: PreparedUpdate) -> Result<Applied, Error> {
        if update.before != self.state_digest() {
            return Err(Error::Binding);
        }
        if update.replay {
            return Ok(Applied::OriginalReplay);
        }
        // prepare checked every arithmetic update against this exact digest.
        for charge in &update.reservation.charges {
            let counter = self.domains.get_mut(&charge.domain).ok_or(Error::Binding)?;
            counter.used += charge.amount;
            *counter
                .members
                .entry(update.reservation.resource)
                .or_default() += charge.amount;
        }
        self.reservations
            .insert(update.reservation.execution, update.reservation);
        self.revision += 1;
        Ok(Applied::New)
    }
}
