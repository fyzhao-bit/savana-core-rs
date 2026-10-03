"""Catalog is the single source of truth for the full-dojo read pipeline.

These checks need no agentdojo install: they pin the committed deployment
artifact and the descriptor generator's expectations to the authoring catalog,
so the provider (agentdojo_calendar), the Rust profile generator (which reads
the committed JSON) and the task contracts can never silently drift apart.
"""
import json
import unittest
from pathlib import Path

from savana_bench.agentdojo_provider import canonical
from savana_bench.agentdojo_tasks import (
    MODEL_CATALOG, TOOL_CATALOG, WRITE_CATALOG, WRITE_VALIDATORS, _TASKS, catalog_json, upstream_for)

# The artifact assemble.py copies verbatim into etc/savana/read-tool-catalog-v04.json.
COMMITTED = (Path(__file__).resolve().parents[2]
             / "deploy/linux/integration/read-tool-catalog-v04.json")


class ReadToolCatalogTests(unittest.TestCase):
    def test_committed_artifact_equals_authoring_catalog(self):
        # The deployment generator reads this file; it must be byte-identical to
        # canonical(catalog_json()). If this fails, regenerate the committed file.
        self.assertEqual(COMMITTED.read_bytes(), canonical(catalog_json()))
        # One committed catalog per suite; a host is staged with exactly one.
        from savana_bench.dojo_catalog import SUITES
        for suite in SUITES:
            path = COMMITTED.with_name(f"read-tool-catalog-v04-{suite}.json")
            self.assertEqual(path.read_bytes(), canonical(catalog_json(suite)), suite)

    def test_catalog_json_structure_is_closed(self):
        doc = catalog_json()
        self.assertEqual(doc["schema"], 2)
        # The original workspace reads come first, in their original order.
        self.assertEqual([t["operation"] for t in doc["read_tools"]][:len(TOOL_CATALOG)],
                         [name for name, _, _ in TOOL_CATALOG])
        for tool in doc["read_tools"]:
            self.assertEqual(set(tool), {"operation", "effect", "fixed_magnitude", "fields"})
            self.assertEqual(tool["effect"], "read")
            self.assertEqual(tool["fixed_magnitude"], 1)
            self._check_fields(tool["fields"])
            roles = {f["name"]: f["role"] for f in tool["fields"]}
            self.assertEqual(roles["calendar"], "resource")

    def test_write_tools_declare_roles_and_the_confinement_validator(self):
        doc = catalog_json()
        operations = [t["operation"] for t in doc["write_tools"]]
        self.assertEqual(operations[:len(WRITE_CATALOG)], [name for name, _, _, _ in WRITE_CATALOG])
        self.assertEqual(operations[-len(MODEL_CATALOG):], [name for name, _, _, _ in MODEL_CATALOG])
        for tool in doc["write_tools"]:
            self.assertEqual(set(tool),
                             {"operation", "effect", "fixed_magnitude", "validators", "fields"})
            # A write tool is authorizing (never "read") and must require the
            # intent-flow-confinement validator so an untrusted-derived argument
            # escalates to owner approval at G5.
            self.assertNotEqual(tool["effect"], "read")
            self.assertEqual(tool["validators"], list(WRITE_VALIDATORS))
            self.assertIn("intent_flow_confinement", tool["validators"])
            self._check_fields(tool["fields"], synthetic=False)
            # Exactly one of each structural role (business-profile invariant).
            roles = [f["role"] for f in tool["fields"]]
            for required in ("payload", "resource", "destination"):
                self.assertEqual(roles.count(required), 1, (tool["operation"], required))

    def _check_fields(self, fields, synthetic=True):
        names = [f["name"] for f in fields]
        self.assertEqual(names, sorted(names))
        roles = {f["name"]: f["role"] for f in fields}
        if synthetic:
            self.assertEqual(roles["body"], "payload")
            self.assertEqual(roles["to"], "destination")
        for field in fields:
            self.assertEqual(set(field), {"name", "role", "type"})
            # A text list only where the reviewed kind is a list.
            self.assertIn(field["type"], {"text", "text_list"})
            if field["type"] == "text_list":
                self.assertIn(field["role"], {"destination", "parameter"})
            self.assertIn(field["role"], {"payload", "resource", "destination", "parameter"})

    def test_every_contract_argument_set_matches_its_tool_catalog_params(self):
        params = {name: set(p) for name, _, p in TOOL_CATALOG}
        for contract in _TASKS:
            self.assertIn(contract.tool, params, contract.task_id)
            self.assertEqual({k for k, _ in contract.arguments}, params[contract.tool],
                             contract.task_id)
            self.assertEqual(contract.upstream_tool, upstream_for(contract.tool),
                             contract.task_id)

    def test_the_generator_is_a_confined_send_tool_with_fixed_controls(self):
        # Sending an earlier result to a model provider is an outbound effect:
        # it ships as SEND with confinement, never as a silent read.
        (name, upstream, effect, fields), (xname, xupstream, xeffect, xfields) = MODEL_CATALOG
        self.assertEqual((name, upstream, effect), ("dojo.model.generate", "quarantined_generate", "send"))
        self.assertEqual(dict(fields), {"body": "payload", "instruction": "parameter",
                                        "model": "resource", "to": "destination"})
        self.assertEqual(upstream_for(name), "quarantined_generate")
        # The extractor for planner-drafted programs: same model, one more
        # inert label naming the value it must produce, and the payload's step.
        self.assertEqual((xname, xupstream, xeffect), ("dojo.model.extract", "quarantined_extract", "send"))
        self.assertEqual(dict(xfields), dict(fields, target="parameter", context="parameter", context2="parameter",
                                             context3="parameter", context4="parameter", context5="parameter",
                                             source="parameter"))

    def test_upstream_functions_are_the_reviewed_read_set(self):
        # Exactly the official AgentDojo workspace read functions we serve.
        self.assertEqual({u for _, u, _ in TOOL_CATALOG}, {
            "search_calendar_events", "get_day_calendar_events", "search_emails",
            "get_unread_emails", "list_files", "search_files_by_filename", "search_files"})


if __name__ == "__main__":
    unittest.main()
