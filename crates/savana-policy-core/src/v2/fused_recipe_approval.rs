//! Signed private recipe allowlist. Not a task root, G6 approval or G7 grant.
use super::{FusedPlanningProfileV04, G4Error};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

const MAX_BYTES: usize = 256 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FusedRecipeBindingV04 {
    pub operation: u16,
    pub recipe: [u8; 32],
}

/// Immutable operator approval of a finite recipe set for an existing profile.
/// A recipe digest is produced locally; models must never prepare this artifact.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FusedRecipeApprovalV04 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs_digest: Option<[u8; 32]>,
    pub schema: u16,
    pub recipe_schema: u16,
    pub installation: [u8; 32],
    pub manifest: [u8; 32],
    pub task: [u8; 32],
    pub root: [u8; 32],
    pub profile: [u8; 32],
    pub deployment_generation: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub bindings: Vec<FusedRecipeBindingV04>,
}

impl FusedRecipeApprovalV04 {
    pub fn signing_digest(&self) -> Result<[u8; 32], G4Error> {
        if self.schema != 1
            || !matches!(self.recipe_schema, 1 | 2)
            || (self.recipe_schema == 1 && self.inputs_digest.is_some())
            || (self.recipe_schema == 2 && self.inputs_digest.is_none_or(|d| d == [0; 32]))
            || [
                self.installation,
                self.manifest,
                self.task,
                self.root,
                self.profile,
            ]
            .contains(&[0; 32])
            || self.deployment_generation == 0
            || self.not_before >= self.expires_at
            || self.bindings.is_empty()
            || self.bindings.len() > 64
            || self
                .bindings
                .iter()
                .any(|b| b.operation == 0 || b.recipe == [0; 32])
            || self
                .bindings
                .windows(2)
                .any(|p| p[0].operation >= p[1].operation)
        {
            return Err(G4Error::StateConflict);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| G4Error::StateConflict)?;
        if bytes.len() > MAX_BYTES {
            return Err(G4Error::StateConflict);
        }
        Ok(*super::task_authorization::hash_parts(
            b"SAVANA_FUSED_RECIPE_APPROVAL_V04_SCHEMA1\0",
            &[&bytes],
        )
        .as_bytes())
    }

    pub(super) fn matches_profile(&self, profile: &FusedPlanningProfileV04) -> Result<(), G4Error> {
        self.signing_digest()?;
        if self.installation != profile.installation
            || self.task != profile.task
            || self.root != profile.policy.root
            || self.profile != profile.signing_digest()?
            || self.not_before < profile.not_before
            || self.expires_at > profile.expires_at
            || !profile.execution_bindings.is_empty()
            || self.bindings.len() != profile.policy.operations.len()
            || self
                .bindings
                .iter()
                .zip(&profile.policy.operations)
                .any(|(b, op)| b.operation != op.id)
        {
            return Err(G4Error::StateConflict);
        }
        for op in &profile.policy.operations {
            if op.bindings.iter().any(|b| b.result_of.is_some())
                && (self.recipe_schema != 2
                    || !self.bindings.iter().any(|b| {
                        b.operation == op.id
                            && Self::result_recipe(
                                self.profile,
                                self.inputs_digest.unwrap_or([0; 32]),
                                op,
                            )
                            .ok()
                                == Some(b.recipe)
                    }))
            {
                return Err(G4Error::StateConflict);
            }
        }
        Ok(())
    }

    /// Explicit schema-2 authorization for a signed result-data edge. It does
    /// not approve the future effect: exact G4, G5/G6 and G7 still run at use.
    pub fn result_recipe(
        profile: [u8; 32],
        inputs: [u8; 32],
        operation: &savana_continuation_core::planning::Operation,
    ) -> Result<[u8; 32], G4Error> {
        if profile == [0; 32]
            || inputs == [0; 32]
            || !operation.bindings.iter().any(|b| b.result_of.is_some())
        {
            return Err(G4Error::StateConflict);
        }
        let bytes = serde_json::to_vec(operation).map_err(|_| G4Error::StateConflict)?;
        Ok(*super::task_authorization::hash_parts(
            b"SAVANA_FUSED_RESULT_RECIPE_SCHEMA2\0",
            &[&profile, &inputs, &bytes],
        )
        .as_bytes())
    }

    pub(super) fn permits_recipe(
        &self,
        profile: [u8; 32],
        operation: &savana_continuation_core::planning::Operation,
        exact: [u8; 32],
    ) -> bool {
        let expected = if operation.bindings.iter().any(|b| b.result_of.is_some()) {
            if self.recipe_schema != 2 {
                return false;
            }
            match Self::result_recipe(profile, self.inputs_digest.unwrap_or([0; 32]), operation) {
                Ok(d) => d,
                Err(_) => return false,
            }
        } else {
            exact
        };
        self.bindings
            .iter()
            .any(|b| b.operation == operation.id && b.recipe == expected)
    }
}

// Only the authenticated admin owner path selects this verifier's issuer. Time,
// current root/profile, no prior effects and immutable installation are checked
// again inside the prospective durable transaction.
pub(super) struct VerifiedFusedRecipeApprovalV04(pub(super) FusedRecipeApprovalV04);
impl VerifiedFusedRecipeApprovalV04 {
    pub(super) fn verify(
        bytes: &[u8],
        signature: &[u8; 64],
        issuer: &VerifyingKey,
    ) -> Result<Self, G4Error> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES || issuer.is_weak() {
            return Err(G4Error::StateConflict);
        }
        let approval: FusedRecipeApprovalV04 =
            serde_json::from_slice(bytes).map_err(|_| G4Error::StateConflict)?;
        if serde_json::to_vec(&approval).map_err(|_| G4Error::StateConflict)? != bytes {
            return Err(G4Error::StateConflict);
        }
        issuer
            .verify_strict(
                &approval.signing_digest()?,
                &Signature::from_bytes(signature),
            )
            .map_err(|_| G4Error::StateConflict)?;
        Ok(Self(approval))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn approval() -> FusedRecipeApprovalV04 {
        FusedRecipeApprovalV04 {
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
        }
    }
    #[test]
    fn result_recipe_binds_profile_initial_inputs_and_exact_source_edge() {
        use savana_continuation_core::planning::{Operation, SlotBinding};
        let op = Operation {
            id: 2,
            tool_class: 31,
            action_template: 21,
            after: vec![1],
            bindings: vec![SlotBinding {
                argument: "body".into(),
                slot: [7; 16],
                result_of: Some(1),
                result_path: None,
                result_max_bytes: None,
                result_source_clause: None,
            }],
        };
        let mut a = approval();
        a.recipe_schema = 2;
        a.inputs_digest = Some([8; 32]);
        let digest = FusedRecipeApprovalV04::result_recipe(a.profile, [8; 32], &op).unwrap();
        a.bindings = vec![FusedRecipeBindingV04 {
            operation: 2,
            recipe: digest,
        }];
        assert!(a.permits_recipe(a.profile, &op, [99; 32]));
        let key = SigningKey::from_bytes(&[10; 32]);
        let signature = key.sign(&a.signing_digest().unwrap()).to_bytes();
        a.inputs_digest = Some([9; 32]);
        assert!(!a.permits_recipe(a.profile, &op, [99; 32]));
        assert!(VerifiedFusedRecipeApprovalV04::verify(
            &serde_json::to_vec(&a).unwrap(),
            &signature,
            &key.verifying_key()
        )
        .is_err());
        a.inputs_digest = Some([8; 32]);
        let mut wrong_source = op.clone();
        wrong_source.bindings[0].result_of = Some(3);
        assert!(!a.permits_recipe(a.profile, &wrong_source, [99; 32]));
        assert!(!a.permits_recipe([9; 32], &op, [99; 32]));
        a.recipe_schema = 1;
        a.inputs_digest = None;
        assert!(!a.permits_recipe(a.profile, &op, digest));
    }

    #[test]
    fn recipe_approval_closed_bounds_and_schema() {
        for n in 0..9 {
            let mut a = approval();
            match n {
                0 => a.schema = 2,
                1 => a.recipe_schema = 2,
                2 => a.deployment_generation = 0,
                3 => a.root = [0; 32],
                4 => a.expires_at = a.not_before,
                5 => a.bindings.clear(),
                6 => a.bindings[0].recipe = [0; 32],
                7 => a.bindings.push(a.bindings[0].clone()),
                _ => {
                    a.bindings = (1..=65)
                        .map(|operation| FusedRecipeBindingV04 {
                            operation,
                            recipe: [6; 32],
                        })
                        .collect()
                }
            }
            assert!(a.signing_digest().is_err(), "invalid {n}");
        }
    }
    #[test]
    fn recipe_approval_signature_is_canonical_key_and_purpose_bound() {
        let key = SigningKey::from_bytes(&[10; 32]);
        let a = approval();
        let bytes = serde_json::to_vec(&a).unwrap();
        let signature = key.sign(&a.signing_digest().unwrap()).to_bytes();
        assert!(
            VerifiedFusedRecipeApprovalV04::verify(&bytes, &signature, &key.verifying_key())
                .is_ok()
        );
        assert!(VerifiedFusedRecipeApprovalV04::verify(
            &bytes,
            &signature,
            &SigningKey::from_bytes(&[11; 32]).verifying_key()
        )
        .is_err());
        let wrong_purpose = crate::v2::task_authorization::hash_parts(
            b"SAVANA_FUSED_PLANNING_PROFILE_V04\0",
            &[&bytes],
        );
        assert!(VerifiedFusedRecipeApprovalV04::verify(
            &bytes,
            &key.sign(wrong_purpose.as_bytes()).to_bytes(),
            &key.verifying_key()
        )
        .is_err());
        for json in [
            serde_json::to_vec_pretty(&a).unwrap(),
            b"{}".to_vec(),
            vec![0; MAX_BYTES + 1],
            String::from_utf8(bytes.clone())
                .unwrap()
                .replacen("{", "{\"schema\":1,", 1)
                .into_bytes(),
            String::from_utf8(bytes.clone())
                .unwrap()
                .replacen("{", "{\"bypass_g6\":true,", 1)
                .into_bytes(),
        ] {
            assert!(VerifiedFusedRecipeApprovalV04::verify(
                &json,
                &signature,
                &key.verifying_key()
            )
            .is_err());
        }
    }
}
