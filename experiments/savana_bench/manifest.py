"""Reproducibility metadata and exact predeclared trial-set binding."""
import hashlib
import json

from .metrics import Trial, validate_unique
from .readiness import require_full_product


def digest(document):
    return hashlib.sha256(json.dumps(
        document, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()).hexdigest()


def bind_results(manifest, trials):
    if not isinstance(manifest, dict):
        raise ValueError("invalid_manifest")
    if manifest.get("schema") != "savana-benchmark-manifest-v1":
        raise ValueError("unsupported_manifest")
    if manifest.get("scope") == "full_product":
        require_full_product()
    if manifest.get("scope") not in ("sdk_v2_component", "isolated_model", "private_workflow_component"):
        raise ValueError("invalid_experiment_scope")
    # These are researcher-supplied provenance, not trusted hardware evidence.
    for key in ("benchmark_revision", "dataset_sha256", "oracle_revision", "adapter_revision",
                "source_tree_sha256", "model_id", "model_revision", "model_role",
                "runtime_revision", "quantization", "template_sha256", "hardware"):
        value = manifest.get(key)
        if not isinstance(value, str) or not value.strip() or value.lower() in ("pending", "unknown", "latest", "main", "placeholder"):
            raise ValueError("unresolved_provenance_" + key)
    for key in ("dataset_sha256", "source_tree_sha256", "template_sha256"):
        value = manifest[key]
        if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("invalid_digest_" + key)
    if manifest["model_role"] not in ("reviewer", "planner", "agent"):
        raise ValueError("invalid_model_role")
    sampling = manifest.get("sampling", {})
    if not isinstance(sampling, dict):
        raise ValueError("invalid_sampling")
    for key in ("context_tokens", "max_output_tokens", "max_tool_calls", "timeout_seconds"):
        if type(sampling.get(key)) is not int or sampling[key] <= 0:
            raise ValueError("missing_sampling_limit_" + key)
    temperature = sampling.get("temperature")
    if type(temperature) not in (int, float) or not 0 <= temperature <= 2:
        raise ValueError("invalid_temperature")
    scheduled = manifest.get("scheduled_trials")
    if not isinstance(scheduled, list) or not scheduled:
        raise ValueError("empty_schedule")
    binding = digest(manifest)
    expected = []
    for item in scheduled:
        # Validate exactly the same identity domain as actual records. No
        # outcomes or extra keys may be smuggled into the predeclared schedule.
        if not isinstance(item, dict) or set(item) != {"task_id", "attack_id", "seed", "defense", "condition"}:
            raise ValueError("invalid_schedule")
        expected.append(Trial(binding, status="error", utility=None,
                              safety="unknown", effects_complete=False, **item))
    validate_unique(expected)
    trials = list(trials)
    validate_unique(trials)
    key = lambda t: (t.manifest_sha256, t.defense, t.condition, *t.pair_key)
    if {key(t) for t in expected} != {key(t) for t in trials}:
        raise ValueError("scheduled_trials_missing_extra_or_wrong_manifest")
    return trials
