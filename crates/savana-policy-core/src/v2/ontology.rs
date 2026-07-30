use minicbor::Encode as _;
use savana_kernel_protocol::v2::{
    Digest32V2, DurableTaskIdV2, EntityIdV2, NamespaceIdV2, OntologySetIdV2, PrincipalIdV2,
    RoleIdV2, ToolClassIdV2,
};

use super::{value::KernelScalarRefV2, ArgumentNameV2, FieldNameV2, KernelValueV2};

const MAX_ONTOLOGY_TEXT_BYTES: usize = 1_024;
const MAX_FIELD_PATH_ITEMS: usize = 16;
const MAX_BOOLEAN_CHILDREN: usize = 32;
const MAX_ONTOLOGY_DEPTH: usize = 8;
const MAX_ONTOLOGY_NODES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum G4Error {
    #[error("G4 text is not bounded NFC text")]
    InvalidText,
    #[error("G4 field path exceeds 16 items")]
    PathLimitExceeded,
    #[error("G4 All/Any must contain 1 through 32 children")]
    BooleanChildCount,
    #[error("G4 ontology expression exceeds depth 8")]
    OntologyDepthExceeded,
    #[error("G4 ontology expression exceeds 256 nodes")]
    OntologyNodeLimitExceeded,
    #[error("G4 canonical ordering is invalid")]
    NonCanonicalOrder,
    #[error("G4 ontology evaluation failed closed")]
    EvaluationError,
    #[error("G4 verified evaluation inputs are not strictly sorted and unique")]
    EvaluationInputOrder,
    #[error("G4 connector retry policy is incompatible with its idempotency contract")]
    InvalidRetryPolicy,
    #[error("G4 tool descriptor exceeds a compiled collection or byte limit")]
    DescriptorLimitExceeded,
    #[error("G4 tool descriptor is not exact canonical CBOR")]
    NonCanonicalDescriptor,
    #[error("G4 tool descriptor has an invalid schema or field binding")]
    InvalidDescriptor,
    #[error("G4 tool descriptor signature is invalid")]
    InvalidDescriptorSignature,
    #[error("G4 tool descriptor is outside its verified activity window")]
    DescriptorNotActive,
    #[error("G4 tool descriptor registry version does not match the verified registry")]
    RegistryVersionMismatch,
    #[error("G4 tool descriptor projection binding is invalid")]
    InvalidProjectionBinding,
    #[error("G4 tool descriptor repeats an internal validator implementation")]
    DuplicateValidatorImplementation,
    #[error("G4 verified registry publisher authority is invalid")]
    InvalidRegistryPublisher,
    #[error("G4 fallible allocation failed")]
    AllocationFailure,
    #[error("G4 stored value or provenance record is missing")]
    MissingStoredValue,
    #[error("G4 stored value, provenance, or internal-slot binding does not match")]
    StoredValueMismatch,
    #[error("G4 stored binding belongs to another run or active manifest")]
    StaleStoredBinding,
    #[error("G4 argument binding repeats an internal value identity")]
    DuplicateStoredValueIdentity,
    #[error("G4 required vault token slot is unknown")]
    UnknownVaultTokenSlot,
    #[error("G4 vault credential or executor binding does not match")]
    CredentialBindingMismatch,
    #[error("G4 stored binding digest computation failed closed")]
    BindingDigestFailure,
    #[error("G4 request identity was reused with different canonical proposal bytes")]
    IdempotencyConflict,
    #[error("G4 immutable plan step was rebound to different semantics")]
    StateConflict,
    #[error("G4 action-intent or replay index exceeds its compiled limit")]
    IntentLimitExceeded,
    #[error("G4 action-intent record does not exist")]
    IntentNotFound,
    #[error("G4 action-intent semantic binding contains an invalid identity or digest")]
    InvalidIntentBinding,
    #[error("G4 resolved planner internal-slot material is invalid")]
    InvalidInternalSlotBinding,
    #[error("G4 quota counter branch does not exist")]
    QuotaCounterNotFound,
    #[error("G4 quota admission exceeds its effective limit")]
    QuotaExceeded,
    #[error("G4 quota limit is not bound to a verified policy capability")]
    InvalidQuotaLimit,
    #[error("G4 quota transition is invalid for the current reservation state")]
    InvalidQuotaTransition,
    #[error("G4 durable state I/O failed")]
    DurableStateIo,
    #[error("G4 durable state authentication failed")]
    DurableStateAuthentication,
    #[error("G4 durable state was rolled back behind its protected high-water")]
    DurableStateRollback,
    #[error("G4 durable state is malformed or violates an invariant")]
    DurableStateCorrupt,
    #[error("G4 durable state commit is uncertain and the store is fail-stopped")]
    DurableCommitUncertain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttemptKindV2 {
    ToolRead,
    ToolWrite,
    ToolIrreversible,
}

impl AttemptKindV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::ToolRead => 1,
            Self::ToolWrite => 2,
            Self::ToolIrreversible => 3,
        }
    }
}

impl<C> minicbor::Encode<C> for AttemptKindV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(1)?.u16(self.tag())?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OntologyScalarV2(OntologyScalarKindV2);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum OntologyScalarKindV2 {
    Null,
    Bool(bool),
    I64(i64),
    Text(String),
    Digest(Digest32V2),
}

impl OntologyScalarV2 {
    pub const fn null() -> Self {
        Self(OntologyScalarKindV2::Null)
    }

    pub const fn boolean(value: bool) -> Self {
        Self(OntologyScalarKindV2::Bool(value))
    }

    pub const fn integer(value: i64) -> Self {
        Self(OntologyScalarKindV2::I64(value))
    }

    pub fn text(value: impl Into<String>) -> Result<Self, G4Error> {
        let value = value.into();
        if value.len() > MAX_ONTOLOGY_TEXT_BYTES || !unicode_normalization::is_nfc(&value) {
            return Err(G4Error::InvalidText);
        }
        Ok(Self(OntologyScalarKindV2::Text(value)))
    }

    pub const fn digest(value: Digest32V2) -> Self {
        Self(OntologyScalarKindV2::Digest(value))
    }
}

impl<C> minicbor::Encode<C> for OntologyScalarV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match &self.0 {
            OntologyScalarKindV2::Null => {
                encoder.array(1)?.u16(0)?;
            }
            OntologyScalarKindV2::Bool(value) => {
                encoder.array(2)?.u16(1)?.bool(*value)?;
            }
            OntologyScalarKindV2::I64(value) => {
                encoder.array(2)?.u16(2)?.i64(*value)?;
            }
            OntologyScalarKindV2::Text(value) => {
                encoder.array(2)?.u16(3)?.str(value)?;
            }
            OntologyScalarKindV2::Digest(value) => {
                encoder.array(2)?.u16(4)?;
                value.encode(encoder, context)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FieldPathV2(Vec<FieldNameV2>);

impl FieldPathV2 {
    pub fn new(fields: Vec<FieldNameV2>) -> Result<Self, G4Error> {
        if fields.len() > MAX_FIELD_PATH_ITEMS {
            return Err(G4Error::PathLimitExceeded);
        }
        Ok(Self(fields))
    }

    pub fn as_slice(&self) -> &[FieldNameV2] {
        &self.0
    }
}

impl<C> minicbor::Encode<C> for FieldPathV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(self.0.len() as u64)?;
        for field in &self.0 {
            field.encode(encoder, context)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContextFieldV2 {
    Role,
    Tool,
    AttemptKind,
    PrincipalDigest,
    TaskDigest,
}

impl ContextFieldV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::Role => 1,
            Self::Tool => 2,
            Self::AttemptKind => 3,
            Self::PrincipalDigest => 4,
            Self::TaskDigest => 5,
        }
    }
}

impl<C> minicbor::Encode<C> for ContextFieldV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(1)?.u16(self.tag())?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OntologyOperandV2 {
    Argument {
        name: ArgumentNameV2,
        path: FieldPathV2,
    },
    Ontology {
        namespace: NamespaceIdV2,
        entity: EntityIdV2,
        path: FieldPathV2,
    },
    Context(ContextFieldV2),
    Literal(OntologyScalarV2),
}

impl OntologyOperandV2 {
    pub const fn argument(name: ArgumentNameV2, path: FieldPathV2) -> Self {
        Self::Argument { name, path }
    }

    pub const fn ontology(namespace: NamespaceIdV2, entity: EntityIdV2, path: FieldPathV2) -> Self {
        Self::Ontology {
            namespace,
            entity,
            path,
        }
    }

    pub const fn context(field: ContextFieldV2) -> Self {
        Self::Context(field)
    }

    pub const fn literal(value: OntologyScalarV2) -> Self {
        Self::Literal(value)
    }
}

impl<C> minicbor::Encode<C> for OntologyOperandV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::Argument { name, path } => {
                encoder.array(3)?.u16(1)?;
                name.encode(encoder, context)?;
                path.encode(encoder, context)?;
            }
            Self::Ontology {
                namespace,
                entity,
                path,
            } => {
                encoder.array(4)?.u16(2)?;
                namespace.encode(encoder, context)?;
                entity.encode(encoder, context)?;
                path.encode(encoder, context)?;
            }
            Self::Context(field) => {
                encoder.array(2)?.u16(3)?;
                field.encode(encoder, context)?;
            }
            Self::Literal(value) => {
                encoder.array(2)?.u16(4)?;
                value.encode(encoder, context)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ManifestOntologySetRefV2 {
    namespace: NamespaceIdV2,
    set: OntologySetIdV2,
    set_digest: Digest32V2,
}

impl ManifestOntologySetRefV2 {
    pub(crate) const fn new(
        namespace: NamespaceIdV2,
        set: OntologySetIdV2,
        set_digest: Digest32V2,
    ) -> Self {
        Self {
            namespace,
            set,
            set_digest,
        }
    }
}

impl<C> minicbor::Encode<C> for ManifestOntologySetRefV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(3)?;
        self.namespace.encode(encoder, context)?;
        self.set.encode(encoder, context)?;
        self.set_digest.encode(encoder, context)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OntologyExprV2 {
    kind: OntologyExprKindV2,
    depth: u16,
    nodes: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum OntologyExprKindV2 {
    Eq(OntologyOperandV2, OntologyOperandV2),
    Ne(OntologyOperandV2, OntologyOperandV2),
    In(OntologyOperandV2, ManifestOntologySetRefV2),
    NotIn(OntologyOperandV2, ManifestOntologySetRefV2),
    All(Vec<OntologyExprV2>),
    Any(Vec<OntologyExprV2>),
}

impl OntologyExprV2 {
    pub const fn eq(left: OntologyOperandV2, right: OntologyOperandV2) -> Self {
        Self::leaf(OntologyExprKindV2::Eq(left, right))
    }

    pub const fn ne(left: OntologyOperandV2, right: OntologyOperandV2) -> Self {
        Self::leaf(OntologyExprKindV2::Ne(left, right))
    }

    pub(crate) const fn in_set(operand: OntologyOperandV2, set: ManifestOntologySetRefV2) -> Self {
        Self::leaf(OntologyExprKindV2::In(operand, set))
    }

    pub(crate) const fn not_in_set(
        operand: OntologyOperandV2,
        set: ManifestOntologySetRefV2,
    ) -> Self {
        Self::leaf(OntologyExprKindV2::NotIn(operand, set))
    }

    pub fn all(children: Vec<Self>) -> Result<Self, G4Error> {
        Self::boolean(children, true)
    }

    pub fn any(children: Vec<Self>) -> Result<Self, G4Error> {
        Self::boolean(children, false)
    }

    const fn leaf(kind: OntologyExprKindV2) -> Self {
        Self {
            kind,
            depth: 1,
            nodes: 1,
        }
    }

    fn boolean(children: Vec<Self>, all: bool) -> Result<Self, G4Error> {
        if children.is_empty() || children.len() > MAX_BOOLEAN_CHILDREN {
            return Err(G4Error::BooleanChildCount);
        }
        let depth = children
            .iter()
            .map(|child| child.depth)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(G4Error::OntologyDepthExceeded)?;
        if usize::from(depth) > MAX_ONTOLOGY_DEPTH {
            return Err(G4Error::OntologyDepthExceeded);
        }
        let nodes = children.iter().try_fold(1_u16, |nodes, child| {
            nodes
                .checked_add(child.nodes)
                .ok_or(G4Error::OntologyNodeLimitExceeded)
        })?;
        if usize::from(nodes) > MAX_ONTOLOGY_NODES {
            return Err(G4Error::OntologyNodeLimitExceeded);
        }
        Ok(Self {
            kind: if all {
                OntologyExprKindV2::All(children)
            } else {
                OntologyExprKindV2::Any(children)
            },
            depth,
            nodes,
        })
    }
}

impl<C> minicbor::Encode<C> for OntologyExprV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match &self.kind {
            OntologyExprKindV2::Eq(left, right) => {
                encoder.array(3)?.u16(1)?;
                left.encode(encoder, context)?;
                right.encode(encoder, context)?;
            }
            OntologyExprKindV2::Ne(left, right) => {
                encoder.array(3)?.u16(2)?;
                left.encode(encoder, context)?;
                right.encode(encoder, context)?;
            }
            OntologyExprKindV2::In(operand, set) => {
                encoder.array(3)?.u16(3)?;
                operand.encode(encoder, context)?;
                set.encode(encoder, context)?;
            }
            OntologyExprKindV2::NotIn(operand, set) => {
                encoder.array(3)?.u16(4)?;
                operand.encode(encoder, context)?;
                set.encode(encoder, context)?;
            }
            OntologyExprKindV2::All(children) => {
                encode_children(5, children, encoder, context)?;
            }
            OntologyExprKindV2::Any(children) => {
                encode_children(6, children, encoder, context)?;
            }
        }
        Ok(())
    }
}

fn encode_children<C, W: minicbor::encode::Write>(
    tag: u16,
    children: &[OntologyExprV2],
    encoder: &mut minicbor::Encoder<W>,
    context: &mut C,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    encoder.array(2)?.u16(tag)?.array(children.len() as u64)?;
    for child in children {
        child.encode(encoder, context)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OntologyEvaluationV2 {
    Match,
    NoMatch,
    EvaluationError,
}

impl OntologyEvaluationV2 {
    pub(crate) const fn permits(self) -> bool {
        matches!(self, Self::Match)
    }
}

pub struct VerifiedOntologySetV2 {
    namespace: NamespaceIdV2,
    set: OntologySetIdV2,
    digest: Digest32V2,
    members: Vec<OntologyScalarV2>,
}

impl VerifiedOntologySetV2 {
    pub(crate) fn new(
        namespace: NamespaceIdV2,
        set: OntologySetIdV2,
        digest: Digest32V2,
        members: Vec<OntologyScalarV2>,
    ) -> Result<Self, G4Error> {
        if members.len() > 65_536
            || members
                .windows(2)
                .any(|pair| scalar_order(&pair[0], &pair[1]) != std::cmp::Ordering::Less)
        {
            return Err(G4Error::NonCanonicalOrder);
        }
        Ok(Self {
            namespace,
            set,
            digest,
            members,
        })
    }
}

pub(crate) struct OntologyEvaluationContextV2<'value> {
    arguments: Vec<(ArgumentNameV2, &'value KernelValueV2)>,
    ontology: Vec<((NamespaceIdV2, EntityIdV2), &'value KernelValueV2)>,
    sets: Vec<VerifiedOntologySetV2>,
    role: RoleIdV2,
    tool: ToolClassIdV2,
    attempt_kind: AttemptKindV2,
    principal: PrincipalIdV2,
    task: DurableTaskIdV2,
}

impl<'value> OntologyEvaluationContextV2<'value> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        arguments: Vec<(ArgumentNameV2, &'value KernelValueV2)>,
        ontology: Vec<((NamespaceIdV2, EntityIdV2), &'value KernelValueV2)>,
        sets: Vec<VerifiedOntologySetV2>,
        role: RoleIdV2,
        tool: ToolClassIdV2,
        attempt_kind: AttemptKindV2,
        principal: PrincipalIdV2,
        task: DurableTaskIdV2,
    ) -> Result<Self, G4Error> {
        if arguments
            .windows(2)
            .any(|pair| pair[0].0.as_str().as_bytes() >= pair[1].0.as_str().as_bytes())
            || ontology.windows(2).any(|pair| pair[0].0 >= pair[1].0)
            || sets
                .windows(2)
                .any(|pair| (pair[0].namespace, pair[0].set) >= (pair[1].namespace, pair[1].set))
        {
            return Err(G4Error::EvaluationInputOrder);
        }
        Ok(Self {
            arguments,
            ontology,
            sets,
            role,
            tool,
            attempt_kind,
            principal,
            task,
        })
    }

    fn resolve<'context>(
        &'context self,
        operand: &'context OntologyOperandV2,
    ) -> Result<RuntimeScalarV2<'context>, G4Error> {
        match operand {
            OntologyOperandV2::Argument { name, path } => {
                let value = self
                    .arguments
                    .iter()
                    .find_map(|(candidate, value)| (candidate == name).then_some(*value))
                    .ok_or(G4Error::EvaluationError)?;
                runtime_from_value(value, path)
            }
            OntologyOperandV2::Ontology {
                namespace,
                entity,
                path,
            } => {
                let value = self
                    .ontology
                    .iter()
                    .find_map(|(candidate, value)| {
                        (*candidate == (*namespace, *entity)).then_some(*value)
                    })
                    .ok_or(G4Error::EvaluationError)?;
                runtime_from_value(value, path)
            }
            OntologyOperandV2::Context(field) => Ok(match field {
                ContextFieldV2::Role => RuntimeScalarV2::I64(i64::from(self.role.get())),
                ContextFieldV2::Tool => RuntimeScalarV2::I64(i64::from(self.tool.get())),
                ContextFieldV2::AttemptKind => {
                    RuntimeScalarV2::I64(i64::from(self.attempt_kind.tag()))
                }
                ContextFieldV2::PrincipalDigest => {
                    RuntimeScalarV2::Digest(Digest32V2::new(*self.principal.as_bytes()))
                }
                ContextFieldV2::TaskDigest => {
                    RuntimeScalarV2::Digest(Digest32V2::new(*self.task.as_bytes()))
                }
            }),
            OntologyOperandV2::Literal(value) => Ok(RuntimeScalarV2::from_scalar(value)),
        }
    }

    fn resolve_set(
        &self,
        reference: &ManifestOntologySetRefV2,
    ) -> Result<&VerifiedOntologySetV2, G4Error> {
        self.sets
            .iter()
            .find(|set| {
                set.namespace == reference.namespace
                    && set.set == reference.set
                    && set.digest == reference.set_digest
            })
            .ok_or(G4Error::EvaluationError)
    }
}

impl OntologyExprV2 {
    pub(crate) fn evaluate(
        &self,
        context: &OntologyEvaluationContextV2<'_>,
    ) -> OntologyEvaluationV2 {
        self.evaluate_inner(context)
            .unwrap_or(OntologyEvaluationV2::EvaluationError)
    }

    fn evaluate_inner<'context>(
        &'context self,
        context: &'context OntologyEvaluationContextV2<'_>,
    ) -> Result<OntologyEvaluationV2, G4Error> {
        match &self.kind {
            OntologyExprKindV2::Eq(left, right) => {
                compare_operands(context.resolve(left)?, context.resolve(right)?)
            }
            OntologyExprKindV2::Ne(left, right) => Ok(invert(compare_operands(
                context.resolve(left)?,
                context.resolve(right)?,
            )?)),
            OntologyExprKindV2::In(operand, reference) => {
                evaluate_membership(context.resolve(operand)?, context.resolve_set(reference)?)
            }
            OntologyExprKindV2::NotIn(operand, reference) => Ok(invert(evaluate_membership(
                context.resolve(operand)?,
                context.resolve_set(reference)?,
            )?)),
            OntologyExprKindV2::All(children) => evaluate_all(children, context),
            OntologyExprKindV2::Any(children) => evaluate_any(children, context),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeScalarV2<'value> {
    Null,
    Bool(bool),
    I64(i64),
    Text(&'value str),
    Digest(Digest32V2),
}

impl<'value> RuntimeScalarV2<'value> {
    fn from_scalar(value: &'value OntologyScalarV2) -> Self {
        match &value.0 {
            OntologyScalarKindV2::Null => Self::Null,
            OntologyScalarKindV2::Bool(value) => Self::Bool(*value),
            OntologyScalarKindV2::I64(value) => Self::I64(*value),
            OntologyScalarKindV2::Text(value) => Self::Text(value),
            OntologyScalarKindV2::Digest(value) => Self::Digest(*value),
        }
    }
}

fn runtime_from_value<'value>(
    value: &'value KernelValueV2,
    path: &FieldPathV2,
) -> Result<RuntimeScalarV2<'value>, G4Error> {
    let scalar = value
        .select_path(path.as_slice())
        .and_then(KernelValueV2::scalar_ref)
        .ok_or(G4Error::EvaluationError)?;
    Ok(match scalar {
        KernelScalarRefV2::Null => RuntimeScalarV2::Null,
        KernelScalarRefV2::Bool(value) => RuntimeScalarV2::Bool(value),
        KernelScalarRefV2::I64(value) => RuntimeScalarV2::I64(value),
        KernelScalarRefV2::Text(value) => RuntimeScalarV2::Text(value),
        KernelScalarRefV2::Digest(value) => RuntimeScalarV2::Digest(value),
    })
}

fn compare_operands(
    left: RuntimeScalarV2<'_>,
    right: RuntimeScalarV2<'_>,
) -> Result<OntologyEvaluationV2, G4Error> {
    let equal = match (left, right) {
        (RuntimeScalarV2::Null, RuntimeScalarV2::Null) => true,
        (RuntimeScalarV2::Bool(left), RuntimeScalarV2::Bool(right)) => left == right,
        (RuntimeScalarV2::I64(left), RuntimeScalarV2::I64(right)) => left == right,
        (RuntimeScalarV2::Text(left), RuntimeScalarV2::Text(right)) => left == right,
        (RuntimeScalarV2::Digest(left), RuntimeScalarV2::Digest(right)) => left == right,
        _ => return Err(G4Error::EvaluationError),
    };
    Ok(if equal {
        OntologyEvaluationV2::Match
    } else {
        OntologyEvaluationV2::NoMatch
    })
}

fn evaluate_membership(
    value: RuntimeScalarV2<'_>,
    set: &VerifiedOntologySetV2,
) -> Result<OntologyEvaluationV2, G4Error> {
    let contains = set
        .members
        .iter()
        .any(|member| RuntimeScalarV2::from_scalar(member) == value);
    Ok(if contains {
        OntologyEvaluationV2::Match
    } else {
        OntologyEvaluationV2::NoMatch
    })
}

fn evaluate_all(
    children: &[OntologyExprV2],
    context: &OntologyEvaluationContextV2<'_>,
) -> Result<OntologyEvaluationV2, G4Error> {
    let mut all_match = true;
    for child in children {
        match child.evaluate_inner(context)? {
            OntologyEvaluationV2::Match => {}
            OntologyEvaluationV2::NoMatch => all_match = false,
            OntologyEvaluationV2::EvaluationError => return Err(G4Error::EvaluationError),
        }
    }
    Ok(if all_match {
        OntologyEvaluationV2::Match
    } else {
        OntologyEvaluationV2::NoMatch
    })
}

fn evaluate_any(
    children: &[OntologyExprV2],
    context: &OntologyEvaluationContextV2<'_>,
) -> Result<OntologyEvaluationV2, G4Error> {
    let mut any_match = false;
    for child in children {
        match child.evaluate_inner(context)? {
            OntologyEvaluationV2::Match => any_match = true,
            OntologyEvaluationV2::NoMatch => {}
            OntologyEvaluationV2::EvaluationError => return Err(G4Error::EvaluationError),
        }
    }
    Ok(if any_match {
        OntologyEvaluationV2::Match
    } else {
        OntologyEvaluationV2::NoMatch
    })
}

const fn invert(value: OntologyEvaluationV2) -> OntologyEvaluationV2 {
    match value {
        OntologyEvaluationV2::Match => OntologyEvaluationV2::NoMatch,
        OntologyEvaluationV2::NoMatch => OntologyEvaluationV2::Match,
        OntologyEvaluationV2::EvaluationError => OntologyEvaluationV2::EvaluationError,
    }
}

fn scalar_order(left: &OntologyScalarV2, right: &OntologyScalarV2) -> std::cmp::Ordering {
    scalar_tag(left)
        .cmp(&scalar_tag(right))
        .then_with(|| match (&left.0, &right.0) {
            (OntologyScalarKindV2::Null, OntologyScalarKindV2::Null) => std::cmp::Ordering::Equal,
            (OntologyScalarKindV2::Bool(left), OntologyScalarKindV2::Bool(right)) => {
                left.cmp(right)
            }
            (OntologyScalarKindV2::I64(left), OntologyScalarKindV2::I64(right)) => left.cmp(right),
            (OntologyScalarKindV2::Text(left), OntologyScalarKindV2::Text(right)) => {
                left.as_bytes().cmp(right.as_bytes())
            }
            (OntologyScalarKindV2::Digest(left), OntologyScalarKindV2::Digest(right)) => {
                left.as_bytes().cmp(right.as_bytes())
            }
            _ => std::cmp::Ordering::Equal,
        })
}

const fn scalar_tag(value: &OntologyScalarV2) -> u16 {
    match value.0 {
        OntologyScalarKindV2::Null => 0,
        OntologyScalarKindV2::Bool(_) => 1,
        OntologyScalarKindV2::I64(_) => 2,
        OntologyScalarKindV2::Text(_) => 3,
        OntologyScalarKindV2::Digest(_) => 4,
    }
}

#[cfg(test)]
#[path = "ontology_tests.rs"]
mod tests;
