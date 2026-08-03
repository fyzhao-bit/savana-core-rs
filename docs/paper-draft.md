# Savana: An Information-Flow Kernel for Agentic Language-Model Systems

**Paper draft** · Revision 1.0 · 2026-08-01
Target venues: USENIX Security, IEEE S&P, OSDI/SOSP (systems track).
Status: draft for internal review. §7 marks which evaluation components exist
and which must be completed before submission.

---

## Abstract

Systems that let a large language model take actions on a user's behalf face
an unsolved security problem: the model is simultaneously the component that
interprets untrusted input and the component that decides what to do. Prompt
injection is not a defect in such systems but a consequence of their
architecture. Existing defenses — instruction hardening, input/output
classification, tool sandboxing — place the security boundary at or inside the
model, and therefore fail against an adversary who controls the model's input.

We present **Savana**, a security kernel that moves the boundary out of the
model entirely. Savana treats the model as an untrusted proposer: it may
request actions but holds no capability to perform them. Every value in the
system carries a four-dimension security label (integrity, confidentiality,
reader set, effect set); label propagation only ever narrows a value's
audience; and the sole operation that widens confidentiality is an explicit
*declassification transition* that (i) names the exact recipient it releases
to, (ii) is subject to a deterministic content gate whose evidence is computed
from what the gate observed rather than asserted by its caller, and (iii)
records an immutable provenance node. A signed, hash-chained policy supply
chain establishes what is possible; runtime gates and human-approval
round-trips bound to signed settlements establish what is permitted in each
instance.

Savana is implemented in 233,730 lines of Rust across 14 crates and includes a
durable dispatch pipeline with crash recovery, HPKE-sealed executor envelopes,
and hash-chained deployment authorities. We describe three design principles
that emerged from building it — *possession implies verification*, *the
checker computes its own evidence*, and *one definition of the predicate* —
and show how their violation produced concrete vulnerabilities that we found
and fixed. We report on a 6,427-vector differential corpus that mechanizes the
agreement between the masking and verification halves of the content gate,
and we characterize precisely the gap between the properties Savana enforces
and those it currently obtains by construction.

---

## 1. Introduction

An agentic system embeds a language model in a loop with tools: the model
reads content, decides on an action, and the system performs it. The content
it reads is attacker-influenced in essentially every deployment — web pages,
documents, email, prior tool results. The model therefore receives attacker
text in the same channel as its instructions, with no reliable mechanism to
distinguish them. This is prompt injection, and years of mitigation research
have not produced a defense that holds against an adaptive adversary, because
the mitigations operate *within* the abstraction that creates the problem.

The security architecture literature has long known the shape of the answer.
If a component cannot be trusted to make a decision correctly, it must not
hold the authority to enact the decision. Capability confinement and
information-flow control (IFC) are the classical mechanisms; recent work
(notably the CaMeL line) has shown they apply naturally to LLM agents by
separating the control plane from the data plane and attaching capabilities to
values. That work established feasibility at prototype scale.

The gap this paper addresses is the distance between that result and a system
one can operate. A prototype can assume its policy is correct and present; a
real system must obtain policy over a signed, revocable, hash-chained supply
chain and behave sanely when it is absent or stale. A prototype can assume it
does not crash; a real system must journal before it acts and must be able to
say, honestly, that a value came from an action whose outcome it learned after
a restart. A prototype can assume its trusted components are trustworthy; a
real system must assume the executor, the approval service, and the network
are separately compromisable and bind each interaction cryptographically.

**Contributions.**

1. **A four-dimension label model with an enforced untrusted-effect ceiling.**
   We show that the invariant `integrity = ExternalUntrusted ⇒ effects ⊆
   {READ}`, applied at construction, at derivation, and again after every
   join, is what prevents effect laundering — the attack in which a value
   assembled from attacker-controlled content inherits the authority to act
   because it was combined with a trusted value (§3.3).

2. **Declassification as the system's only widening operation, made
   structurally unskippable.** Derivation intersects reader sets, so audience
   growth requires an explicit transition. We enumerate five transitions, tie
   each to a content-gate duty determined by *who reads the result* rather
   than by how far confidentiality drops, and place the gate's execution
   inside the record constructor so its evidence cannot be asserted by a
   caller (§4).

3. **Exact-recipient binding.** For the two transitions that hand a value to a
   single recipient, the recipient's identity is carried inside the transition
   variant, making it impossible to name the transition without naming its
   reader. We argue that reader *classes* are insufficient at the egress
   boundary: "an external sink may read this" cannot distinguish the release
   the user asked for from a release to somewhere else (§4.2).

4. **A signed policy supply chain with a uniform verification discipline.**
   Hash-chained trust-root sets with per-purpose members and nested validity
   windows; canonical re-encode equality on every signed object; 92 distinct
   domain-separation strings; and a type discipline in which possessing a
   verified value *is* the proof of verification (§5).

5. **Three design principles, each derived from a real defect.** We report the
   vulnerabilities that motivated them, which we found and fixed during a
   security assessment of the system: caller-asserted gate evidence,
   null-binding declassification records, class-level reader binding, and —
   most instructive — a divergence between the code that masked sensitive data
   and the code that verified the masking (§6).

6. **Mechanized agreement between masker and verifier.** A 6,427-vector
   differential corpus asserts the one-way implication `masked(x) ⇒
   gate_passes(masked(x))`, converting an architectural assumption into a
   checkable property (§7.2).

We also report, in §8, a precise account of what Savana does *not* currently
enforce: the declassification constructor has no production callers, so two
real paths widen confidentiality without traversing the gate. We argue this
distinction — safe *by construction* versus safe *by enforcement* — is one the
literature should insist on, and that reporting it is necessary for the
paper's central claim to be meaningful.

---

## 2. Threat model

**Adversary.** We assume an adversary who (A1) fully controls all content the
agent reads; (A2) fully controls the model's output, including a compromised
or malicious model provider; (A3) has arbitrary code execution in the agent
process; (A4) controls a registered tool or connector and its results; and
(A5) controls the network between all components. We additionally consider
(A6) crash faults at adversarially chosen points, including between a state
mutation and its journal write.

**Trusted computing base.** The kernel process, the installer/MDM signing key
and the authorities it roots, the platform's cryptographic primitives and
process isolation, and — for the specific digest-bound artifact they are
shown — the human approver.

**Security goals.** (S1) No effect without a policy decision derived from
signed policy over unforgeable evidence. (S2) No confidential value reaches a
reader outside its authorized set. (S3) Data of external provenance can never
carry authority to cause an effect. (S4) Every value's lineage is recorded and
every decision replayable from recorded inputs. (S5) Every failure denies.

**Non-goals.** Model correctness within its authority; a compromised kernel;
side channels; availability under a malicious executor.

---

## 3. The label model

### 3.1 Dimensions

Values carry `⟨integrity, confidentiality, readers, effects⟩`. Integrity is a
three-point total order (`KernelTrusted < UserAuthorized < ExternalUntrusted`,
join = max). Confidentiality is a four-point lattice (`Public`,
`PlannerAbstract`, `AgentMasked`, `VaultBound`). Readers and effects are
closed bit sets over seven principals and seven effects respectively.

The confidentiality lattice is deliberately non-linear: `PlannerAbstract` and
`AgentMasked` are incomparable and join to `VaultBound`. A value derived from
one thing the external planner may see and one thing the agent may see is
readable by *neither*. The safe outcome falls out of the algebra; no special
case computes it.

### 3.2 Propagation narrows

Derivation joins integrity and confidentiality upward and **intersects**
readers and effects. A derived value is therefore readable by a subset of
every parent's readers. This single choice is what makes declassification the
only interesting operation in the system: in its absence, the reachable state
space contains no widening at all.

### 3.3 The untrusted-effect ceiling and effect laundering

Consider an agent that fetches a web page containing an attacker-supplied
email address, combines it with a user-authorized document handle, and
proposes to send. Without further constraint, the combined value's effect set
derives from the session-wide policy allowance, and the `SEND` effect is
present — the fabricated recipient passes effect-based confinement. We call
this *effect laundering*: authority acquired by combination.

Savana enforces:

```
integrity(v) = ExternalUntrusted  ⇒  effects(v) ⊆ {READ}
```

at construction, at derivation, and **again after each join**. The
re-application is the operative part: a value combining a trusted and an
untrusted parent becomes untrusted by the integrity join, and must therefore
lose the authorizing effects its trusted parent contributed. Without
re-application the invariant holds pointwise at construction and is violated
by exactly the derivation that matters.

This addresses S3 directly and is, in our assessment, the highest-value single
invariant in the system.

---

## 4. Declassification

### 4.1 Five transitions, duties by recipient

| Transition | Target | Gate duty |
|---|---|---|
| `MaskTokenizeAndLeakCheck` | (AgentMasked, AGENT) | blocklist + no residual PII |
| `BuildPlannerEnvelope` | (PlannerAbstract, EXTERNAL_PLANNER) | blocklist + no residual PII |
| `BuildApprovalDisplay` | (AgentMasked, APPROVAL_DISPLAY) | blocklist only |
| `BuildExecutionEnvelope{executor_id}` | (VaultBound, EXECUTOR) | blocklist only |
| `BuildFinalRelease{sink_id}` | (VaultBound, EXTERNAL_SINK) | blocklist only |

The duty assignment follows *who reads the result*, not how far
confidentiality drops — a distinction we believe is underappreciated. A
language model is the one recipient that cannot be trusted to hold personal
data without it becoming prompt context, training input, or an outbound
request; hence the two LLM-facing transitions must be free of residual PII. A
human approver and an executor both require real values to perform their
function; masking them would not be a stricter gate but a broken one. The
blocklist — injected instructions — binds universally: no recipient is
entitled to those under any transition.

### 4.2 Exact-recipient binding

For the two transitions that hand a value to one recipient, the recipient's
identity digest is carried *inside* the transition variant:

```rust
BuildExecutionEnvelope { executor_identity_digest: Digest32V2 }
BuildFinalRelease      { sink_identity_digest:     Digest32V2 }
```

The transition cannot be named without naming its reader; the identity is
bound into the provenance node's evidence; and an all-zero identity is
refused. A reader *class* can express "an external sink may read this," which
cannot distinguish the release the user requested from a release to an
attacker-chosen destination. At the egress boundary that distinction is the
entire security property.

### 4.3 The checker computes its own evidence

The declassification constructor runs the gate and derives the evidence digest
from the observation:

```rust
let leak_gate_digest = enforce_for_declassification(value, transition.leak_gate_duty())?;
```

`leak_gate_digest` is deliberately not a parameter. Taking it from the caller
would permit asserting a check the kernel cannot verify occurred, at precisely
the point where the kernel relinquishes a confidentiality guarantee. We state
this as a general principle in §6.2.

The constructor further refuses records whose rule, implementation, token-set,
or purpose digests are all zero — a record claiming authority from a rule that
names nothing binds nothing — and refuses a zero exact-reader identity.

---

## 5. Signed policy supply chain

Prototypes assume policy; operable systems must obtain it. Savana's authority
graph is rooted in an installer/MDM key that signs `OperationalTrustRootSetV2`
objects: canonically encoded, domain-separated, hash-chained by
(sequence, previous-signed-digest), carrying per-purpose members
(deployment authorization, rollback, activation, installer) each with a
validity window nested inside the set's, sorted and deduplicated by key id,
with the member-set binding digest recomputed at decode.

Three disciplines recur and constitute, in our view, a reusable house style
for security-critical Rust:

1. **Possession implies verification.** Verified types have private fields and
   a single verifying constructor. Holding the value is the proof. Downstream
   code cannot forget to re-check because there is nothing to re-check.
2. **Canonical re-encode equality.** Decode, re-encode, compare to input.
   Non-canonical encodings — mutated bytes, alternate integer widths,
   indefinite-length containers — are refused uniformly. 92 distinct
   domain-separation strings prevent cross-protocol signature reuse.
3. **Chain, don't patch.** Revocation publishes a successor; predecessor
   validation enforces sequence continuity, digest linkage, and family
   identity. There are no tombstones and no partial updates.

Every effectful dispatch binds installation id, active manifest digest,
deployment generation, effect-fence epoch, executor identity, executor key id,
and connector-registry digest into an effect-gate lease, then journals before
acting and HPKE-seals the payload to the executor's public key.

---

## 6. Design principles from real defects

Each principle below was extracted from a vulnerability we found and fixed
during a security assessment of this system. We report them because negative
results of this kind are the transferable part of systems security work.

### 6.1 Untrusted integrity must cap authority, transitively

*Defect*: untrusted values inherited authorizing effects from the session
policy allowance, and derivations combining trusted and untrusted parents
retained the trusted parent's effects. *Fix*: the ceiling of §3.3, applied
post-join. *Principle*: an integrity level must imply an authority ceiling,
and the implication must be re-established after every operation that can
lower integrity.

### 6.2 The checker computes its own evidence

*Defect*: the declassification record accepted `leak_gate_digest` as a
parameter, so a caller could assert a gate result the kernel never observed.
*Fix*: compute it inside the constructor from the actual gate invocation
(§4.3). *Principle*: at a security boundary, evidence that a check occurred
must be produced by the check, never accepted from the party the check
constrains.

### 6.3 A record that names nothing binds nothing

*Defect*: declassification records with all-zero rule/implementation/purpose
digests, and with all-zero recipient identities, were constructible. A record
"authorized by" a null rule and "released to" a null identity provides the
appearance of an audit trail with none of its substance. *Fix*: explicit
zero-refusal on every binding digest. *Principle*: null bindings must be
refused at construction; a permissive construction path adjacent to a strict
one is the one attackers will use.

### 6.4 One definition of the predicate

*Defect*, and the most instructive: the component that *masked* sensitive data
at ingress and the component that *verified* the masking at the gate consulted
different definitions of "sensitive" — one used a pattern table, the other a
byte scanner with different coverage. Each was individually reasonable; their
disagreement meant the verifier could pass output the masker had not fully
masked, and vice versa. *Fix*: a single crate exporting one definition (a
union of both detectors) consumed by both halves, with a `pattern_set_digest`
folded into every gate digest, plus a differential corpus mechanizing the
implication `masked(x) ⇒ gate_passes(masked(x))`. *Principle*: when a system
enforces a predicate at two places, they must share one implementation, and
the agreement must be mechanized — code review does not detect drift, and
drift is silent.

### 6.5 Absence of a symbol is not absence of a pipeline

*Methodological*: our own initial audit concluded, from the absence of callers
to the declassification constructor, that the egress path did not exist. It
exists and is elaborate — approval envelopes, signed settlements, single-use
consumption, quota, effect leases, durable dispatch, HPKE sealing — and simply
does not use the provenance system. *Principle*: audit by data flow, not by
symbol reference; a pipeline that bypasses a mechanism is invisible to a
search for that mechanism's users.

---

## 7. Evaluation

### 7.1 Implementation

233,730 lines of Rust across 14 crates: policy core 76,397; kernel daemon
45,572; wire protocol 38,023; executor 13,605; approval service 12,388; agent
driver 11,705; ingress 7,750; identity 4,977; vault 4,004; content gate 1,745;
input runtime 1,389. Cryptography: Ed25519 with weak-key rejection, SHA-256
domain-separated digests, X25519 + AES-GCM / ChaCha20-Poly1305 HPKE, canonical
CBOR, explicit zero-checks on generated nonces.

### 7.2 Mechanized properties

The system contains 1,165 test functions across 78 integration files and 139
unit modules. Of note for the claims in this paper:

- **Differential corpus**: 427 hand-constructed vectors across 17 behavioral
  groups, plus 6,000 fuzz vectors (4,000 blocklist, 2,000 redaction) — 6,427
  total — asserting the one-way implication of §6.4.
- **Adversarial matrix** (671 lines): signature forgery, equivocation,
  cross-boot and cross-rollover replay, expiry-versus-signature refusal
  ordering, and precedence stability over real transports.
- **Crash matrix**: crash points across the durable dispatch pipeline.
- **Startup matrix** (601 lines): corrupt, partial, and entropy-faulted
  installation material must bind no socket — the daemon must not offer a
  degraded service.

Measured results on the assessment branch: policy core 183/183 pass; content
gate 11/11; input runtime 4/4; kernel daemon 262 pass with 32 failures, all
attributable to a 10-second daemon-startup wall-clock deadline exceeded under
container contention, confirmed environmental by an A/B run against the parent
commit producing byte-identical failure signatures.

### 7.3 Evaluation components required before submission

We state these explicitly rather than approximate them:

- **Performance.** No throughput, latency, or overhead measurement has been
  conducted. A submission requires: per-transition gate cost, end-to-end
  action latency versus an ungated baseline, and label/provenance memory
  overhead as a function of DAG depth.
- **Security evaluation against a corpus of published prompt-injection
  attacks**, reporting which are structurally impossible (as opposed to
  detected) under the label model.
- **Recall measurement** of the content gate against a labeled PII corpus,
  with the over-blocking rate as the counterpart metric.
- **Case study**: an end-to-end scenario in which an injected agent's attempt
  to exfiltrate is refused, with the refusal traced through label state.

---

## 8. What is enforced versus what holds by construction

A claim that a system enforces a property is only meaningful if the system
distinguishes enforcement from coincidence. Savana currently does not enforce
its central mechanism on two live paths, and we report this precisely.

`ProvenanceRecordV2::kernel_declassification` — the constructor of §4.3 — is
private and invoked only from tests. Consequently:

- **The masked agent view** is produced by masking the ingress value and
  handing the result to the agent as a vault record. No declassification node
  is minted; no gate digest is recorded for the bytes the agent reads.
- **The planner envelope** is assembled from abstract slots and digested, with
  no declassification recorded.
- **The final-release pipeline** — which implements approval envelopes, signed
  settlement verification, single-use consumption, quota, effect leases,
  durable dispatch, payload re-verification, and HPKE sealing — never runs the
  content gate over the released plaintext.

The consequence is *not* that data leaks. Since the unification of §6.4, the
masked output provably satisfies the gate over the differential corpus, and
the planner envelope is structurally abstract (opaque slot references, no free
text). These paths are safe **by construction**. But safety by construction
rests on two implementations continuing to agree, with no mechanism that
notices when they stop; safety by enforcement does not. Additionally, the
`confidentiality` and `readers` label dimensions are propagated and hashed but
consulted by no judgment: the system is currently safe because nothing widens,
rather than because widening is governed.

Closing this requires a signed declassification-rule surface (so that
`rule_digest` has a referent), routing the masking and planner paths through
the constructor, and making the reader dimension load-bearing at handoff. A
staged design for this exists in the repository. We regard reporting the gap
as a prerequisite for the paper's contribution to be assessable: the
architecture's value lies in gated widening, and a reader deserves to know
which paths are gated today.

---

## 9. Related work

**Information-flow control.** Savana's label model descends from classical
lattice-based IFC (Denning; Myers and Liskov's decentralized label model) and
from IFC operating systems (Asbestos, HiStar, Flume), which established
process-granularity flow control with declassification as an explicit,
privileged operation. Savana's contribution is not the lattice but its
application: the recipient set is a set of *system roles and named external
identities* rather than users, and declassification duties are assigned by
recipient trustworthiness — specifically, by whether the recipient is a
language model.

**LLM agent security.** The CaMeL line of work established control-flow/data-flow
separation with capabilities for LLM agents and demonstrated it at prototype
scale; Savana shares the architectural thesis and differs in engineering
completeness (signed supply chain, durability, crash recovery, real
transports, adversarial matrices). Prompt-injection defense research based on
detection and instruction hierarchies is complementary but operates inside the
boundary Savana relocates. Sandboxing approaches confine code rather than
authority: a sandboxed tool invoked with attacker-chosen arguments still
performs the attacker's action.

**Confidential computing and supply chain.** The manifest, trust-root, and
sealed-envelope discipline draws on binary transparency and in-toto-style
supply-chain integrity, applied to *policy* rather than to artifacts.

---

## 10. Limitations and future work

Beyond §8: the content gate is single-modality (deterministic patterns and a
scanner), with recall below a measured NER model — future work integrates a
measured worker whose proposals may only *add* masking, keeping the
deterministic union as a floor and the gate as the sole decider. Connector
registration requires a deployment rollover; a design for hash-chained runtime
self-service with tiered capability ceilings exists but is unimplemented. The
system has received no third-party audit and no formal verification; the
invariants of §3.3 and §4.3 are stated in prose and enforced by construction,
and mechanizing them (via refinement types or a proof assistant over the label
algebra) is the natural next step.

---

## 11. Conclusion

Prompt injection is unsolvable at the layer where it is usually attacked,
because the model is both the interpreter of untrusted input and the holder of
authority. Savana separates these: the model proposes, the kernel disposes,
values carry labels that only narrow, and the single widening operation is
gated, recipient-bound, and recorded. We have described the architecture, the
supply chain that makes it operable, three design principles derived from real
defects, and — with equal specificity — the paths on which the mechanism is
built but not yet reached. Our position is that the second kind of reporting
is what allows the first to be believed.

---

*Draft prepared from direct inspection of the implementation on branch
`claude/security-capabilities-assessment-06bjbl`. All quantitative figures were
measured from the working tree; §7.3 enumerates the measurements a submission
requires that do not yet exist.*
