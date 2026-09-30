"""Reviewed blockers, not attestation. There is deliberately no --force flag.

Removing a row is NOT evidence of readiness: native startup must still provide
the real measured authority. This inventory only prevents premature experiments.
"""
BLOCKERS = (
    ("cross_uid_native_deployment_acceptance", "docs/verification/linux-identity-broker-v2.md"),
    ("native_signer_and_monotonic_anchor", "docs/verification/tpm-authority-v3.md"),
    ("authenticated_private_intake_and_recovery", "docs/research/v04-product-implementation.md"),
    # Tool/FinalRelease transport and the private native release owner exist;
    # deployed consumer acceptance and freshly authenticated reconnect do not
    # follow from synthetic native/component tests.
    # Owner-only Python publication receipts and the byte-matching observer now
    # exist; they do not supply the missing deployed result receiver/reconnect.
    ("consumer_approval_handoff_delivery", "docs/verification/private-release-approval-v04.md"),
    ("exclusive_publication_and_reconnect", "docs/verification/fused-final-result-v04.md"),
    # Finite signed-root/tool compilation, result-to-payload chains and bounded
    # signed observation projections are implemented. Official task adapters and
    # general dynamic discovery/branching are not implied by component tests.
    ("general_private_loop_compiler", "docs/verification/task-compilation-and-observation-v04.md"),
)


def report():
    return {
        "schema": "savana-experiment-readiness-v1", "full_product_ready": False,
        "component_regressions_allowed": True, "model_evaluation_started": False,
        "blockers": [{"id": key, "evidence": path} for key, path in BLOCKERS],
        "notice": "Source audit inventory, NOT runtime attestation or completed acceptance.",
    }


def require_full_product():
    raise RuntimeError("full_v04_product_experiment_blocked_by_architecture")
