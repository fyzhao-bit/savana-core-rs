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
from savana_bench.agentdojo_tasks import TOOL_CATALOG, _TASKS, catalog_json, upstream_for

# The artifact assemble.py copies verbatim into etc/savana/read-tool-catalog-v04.json.
COMMITTED = (Path(__file__).resolve().parents[2]
             / "deploy/linux/integration/read-tool-catalog-v04.json")


class ReadToolCatalogTests(unittest.TestCase):
    def test_committed_artifact_equals_authoring_catalog(self):
        # The deployment generator reads this file; it must be byte-identical to
        # canonical(catalog_json()). If this fails, regenerate the committed file.
        self.assertEqual(COMMITTED.read_bytes(), canonical(catalog_json()))

    def test_catalog_json_structure_is_closed(self):
        doc = catalog_json()
        self.assertEqual(doc["schema"], 1)
        self.assertEqual([t["operation"] for t in doc["read_tools"]],
                         [name for name, _, _ in TOOL_CATALOG])
        for tool in doc["read_tools"]:
            self.assertEqual(set(tool), {"operation", "effect", "fixed_magnitude", "fields"})
            self.assertEqual(tool["effect"], "read")
            self.assertEqual(tool["fixed_magnitude"], 1)
            names = [f["name"] for f in tool["fields"]]
            self.assertEqual(names, sorted(names))
            roles = {f["name"]: f["role"] for f in tool["fields"]}
            self.assertEqual(roles["body"], "payload")
            self.assertEqual(roles["calendar"], "resource")
            self.assertEqual(roles["to"], "destination")
            for field in tool["fields"]:
                self.assertEqual(set(field), {"name", "role", "type"})
                self.assertEqual(field["type"], "text")
                self.assertIn(field["role"], {"payload", "resource", "destination", "parameter"})

    def test_every_contract_argument_set_matches_its_tool_catalog_params(self):
        params = {name: set(p) for name, _, p in TOOL_CATALOG}
        for contract in _TASKS:
            self.assertIn(contract.tool, params, contract.task_id)
            self.assertEqual({k for k, _ in contract.arguments}, params[contract.tool],
                             contract.task_id)
            self.assertEqual(contract.upstream_tool, upstream_for(contract.tool),
                             contract.task_id)

    def test_upstream_functions_are_the_reviewed_read_set(self):
        # Exactly the official AgentDojo workspace read functions we serve.
        self.assertEqual({u for _, u, _ in TOOL_CATALOG}, {
            "search_calendar_events", "get_day_calendar_events", "search_emails",
            "get_unread_emails", "list_files", "search_files_by_filename", "search_files"})


if __name__ == "__main__":
    unittest.main()
