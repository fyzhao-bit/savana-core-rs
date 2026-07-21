"""Emit byte-exact GBNF grammar reference vectors from LIVE Python.

Oracle: server.runtime.gbnf_generator.generate_grammar. Each vector carries the
exact injected input (tool name + input_schema + allow_no_tool) and the grammar
string Python produced, so the Rust port can rebuild the input and assert its
emitted grammar is byte-identical.

Run from the jarvis checkout:
    PYTHONPATH=. /tmp/civenv/bin/python vectors/gen/gen_gbnf_vectors.py
Writes: crates/libsavana-ner/src/gbnf_vectors.json
"""
import json
import os

from server.runtime.tool_registry import ToolSpec
from server.runtime.gbnf_generator import generate_grammar

OUT = os.path.join(
    os.path.dirname(__file__), "..", "..",
    "crates", "libsavana-ner", "src", "gbnf_vectors.json",
)


def spec(name, properties=None, required=None, extra_schema=None):
    schema = {"type": "object", "properties": properties or {}}
    if required is not None:
        schema["required"] = required
    if extra_schema:
        schema.update(extra_schema)
    return ToolSpec(
        name=name, description="", input_schema=schema,
        roles=frozenset(), attempt="x",
    )


# Representative sets covering every grammar branch.
SETS = {
    "empty_args": ([spec("ping", {})], False),
    "all_optional": ([spec("search", {"query": {"type": "string"},
                                       "limit": {"type": "integer"},
                                       "lang": {"type": "string"}})], False),
    "required_middle": ([spec("send_email",
                              {"cc": {"type": "string"},
                               "to": {"type": "string"},
                               "subject": {"type": "string"},
                               "body": {"type": "string"}},
                              required=["to", "body"])], False),
    "required_first": ([spec("read_doc",
                             {"path": {"type": "string"},
                              "encoding": {"type": "string"}},
                             required=["path"])], False),
    "additional_props_false": ([spec("t", {"a": {"type": "string"}},
                                     required=["a"],
                                     extra_schema={"additionalProperties": False})], False),
    "multi_allow_no_tool": ([
        spec("ping", {}),
        spec("search", {"query": {"type": "string"}}, required=["query"]),
        spec("send_email", {"to": {"type": "string"}, "body": {"type": "string"}},
             required=["to", "body"]),
    ], True),
    "unicode_names": ([spec("发送邮件", {"收件人": {"type": "string"}}, required=["收件人"])], False),
}

vectors = []
for key, (tools, allow_no_tool) in SETS.items():
    vectors.append({
        "id": key,
        "allow_no_tool": allow_no_tool,
        "tools": [{"name": t.name, "input_schema": t.input_schema} for t in tools],
        "grammar": generate_grammar(tools, allow_no_tool=allow_no_tool),
    })

with open(os.path.abspath(OUT), "w", encoding="utf-8") as f:
    json.dump({"vectors": vectors}, f, ensure_ascii=False, indent=2)
    f.write("\n")
print(f"wrote {len(vectors)} vectors -> {os.path.abspath(OUT)}")
