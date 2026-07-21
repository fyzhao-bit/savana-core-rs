//! GBNF generator — Rust port of `server/runtime/gbnf_generator.py`. Turns an
//! injected ACTIVE ToolSpec set into the constrained-decoding grammar that locks
//! the CONTROL structure of a single tool call
//! (`{"tool": <name>, "args": {...}, "body_span": "..."?}`). Deterministic, zero
//! regex, pure string/JSON — so **byte-exact vs. Python is the whole contract**
//! (a diverging grammar changes the model's decodable output space).
//!
//! Ported faithfully:
//!   - `_gbnf_string_literal` (gbnf_generator.py:59-68): the double `json.dumps`
//!     of a name into a GBNF terminal (see [`gbnf_string_literal`]);
//!   - `_validated_object_schema` (gbnf_generator.py:75-108): the fail-closed
//!     JSON-Schema-root validation and its exact `ValueError` messages;
//!   - `_argument_rules` (gbnf_generator.py:111-151): the fixed-order argument
//!     object — the empty / required-present / all-optional-suffix-chain branches;
//!   - `generate_grammar` (gbnf_generator.py:154-200): the root/invocation rules,
//!     per-tool invocation rule, and the fixed JSON value grammar tail.
//!
//! Deliberately NOT ported (same seam-lifting as the sibling ports):
//!   - MCP discovery / pack loading / role filtering / the full `ToolSpec`
//!     (tool_registry.py) — the caller resolves the ACTIVE set and injects each
//!     tool as a plain [`ToolSpec`] (`name` + `input_schema` JSON object), exactly
//!     as Python passes a pre-resolved `list[ToolSpec]`. The grammar only reads
//!     `tool.name` and `tool.input_schema`.
//!   - `tool_name_alternatives` (gbnf_generator.py:54-56): a trivial `[t.name …]`
//!     projection the grammar builder itself never calls.
//!
//! ## JSON encoding equivalence
//! Python builds terminals with `json.dumps(..., ensure_ascii=False)`; this port
//! uses [`serde_json::to_string`]. For the strings that appear here (tool /
//! property names, fixed JSON keys) the two are byte-identical: both wrap in
//! quotes, escape only `"` `\` and control chars `< 0x20` (with the same short
//! `\b\t\n\f\r` forms), leave `/` and all non-ASCII as raw UTF-8, and add no
//! separators. `input_schema` must be parsed with serde_json's `preserve_order`
//! feature (declared in Cargo.toml) so `properties` iterate in declaration order,
//! matching Python dict insertion order — the fixed-order argument grammar
//! depends on it. The committed differential (`gbnf_vectors.json`, emitted by
//! live Python) freezes this equivalence.

use std::collections::HashSet;

use serde_json::{Map, Value};

/// Root-schema constructs the grammar cannot honour — `_UNSUPPORTED_ROOT_CONSTRUCTS`
/// (gbnf_generator.py:28-51). Presence of any (as a schema key) is a hard error.
const UNSUPPORTED_ROOT_CONSTRUCTS: &[&str] = &[
    "$ref",
    "$dynamicRef",
    "allOf",
    "anyOf",
    "oneOf",
    "not",
    "if",
    "then",
    "else",
    "dependentRequired",
    "dependentSchemas",
    "dependencies",
    "patternProperties",
    "propertyNames",
    "minProperties",
    "maxProperties",
    "unevaluatedProperties",
    "prefixItems",
    "items",
    "contains",
    "enum",
    "const",
];

/// The fixed JSON value grammar tail appended verbatim to every grammar
/// (gbnf_generator.py:189-200). A raw string literal so its GBNF backslash
/// escapes (`\"`, `\\`, `\x00`, and the literal `\t`/`\n` in `ws`) stay literal;
/// there is **no trailing newline** (Python's last fragment `'ws ::= [ \\t\\n]*'`
/// carries none).
const VALUE_GRAMMAR_TAIL: &str = r#"obj ::= "{" ws ( member ( ws "," ws member )* )? ws "}"
member ::= str ws ":" ws value
value ::= str | obj | array | number | boolean | "null"
array ::= "[" ws ( value ( ws "," ws value )* )? ws "]"
number ::= "-"? ( "0" | [1-9] [0-9]* ) ( "." [0-9]+ )? ( [eE] [+-]? [0-9]+ )?
boolean ::= "true" | "false"
str ::= "\"" char* "\""
char ::= [^"\\\x00-\x1F] | "\\" escape
escape ::= ["\\/bfnrt] | "u" hex hex hex hex
hex ::= [0-9a-fA-F]
ws ::= [ \t\n]*"#;

/// One resolved, injected tool. Only the two fields the grammar reads are
/// modeled (see module docs); `input_schema` is expected to be a JSON object.
#[derive(Debug, Clone)]
pub struct ToolSpec {
    pub name: String,
    pub input_schema: Value,
}

impl ToolSpec {
    /// Convenience: build from a name and a JSON-schema string (parsed with
    /// order preserved). Panics on invalid JSON — intended for tests/callers
    /// that inline a literal schema.
    pub fn new(name: &str, input_schema_json: &str) -> Self {
        ToolSpec {
            name: name.to_string(),
            input_schema: serde_json::from_str(input_schema_json)
                .expect("input_schema must be valid JSON"),
        }
    }
}

/// A validation failure — mirrors Python `ValueError`, carrying the identical
/// message so callers/tests can assert on it.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0}")]
pub struct GbnfError(pub &'static str);

/// `json.dumps(s, ensure_ascii=False)` — the single-quote JSON encoding used for
/// fixed keys. Never fails for a `&str`.
fn j(s: &str) -> String {
    serde_json::to_string(s).expect("&str always serializes to JSON")
}

/// `_gbnf_string_literal` (gbnf_generator.py:59-68): encode one JSON string token
/// as a GBNF terminal via a **double** `json.dumps`. Rust `&str` is always a
/// valid string and valid Unicode, so the two Python `isinstance`/encode guards
/// cannot trip here.
fn gbnf_string_literal(s: &str) -> String {
    j(&j(s))
}

/// `_argument_member` (gbnf_generator.py:71-72).
fn argument_member(name: &str) -> String {
    format!("{} ws {} ws value", gbnf_string_literal(name), j(":"))
}

/// `_validated_object_schema` (gbnf_generator.py:75-108). Returns the property
/// names (declaration order) and the required set, or the first failing check's
/// `ValueError` message. Check order matches Python exactly.
fn validated_object_schema(tool: &ToolSpec) -> Result<(Vec<String>, HashSet<String>), GbnfError> {
    let schema = tool
        .input_schema
        .as_object()
        .ok_or(GbnfError("tool input schema must be an object"))?;

    // root type must be "object" or absent
    match schema.get("type") {
        None => {}
        Some(Value::String(t)) if t == "object" => {}
        _ => {
            return Err(GbnfError(
                "tool input schema root type must be object or absent",
            ))
        }
    }

    if UNSUPPORTED_ROOT_CONSTRUCTS
        .iter()
        .any(|k| schema.contains_key(*k))
    {
        return Err(GbnfError("unsupported tool input schema root construct"));
    }

    if let Some(ap) = schema.get("additionalProperties") {
        // Python: `is not False` — only the boolean literal false is accepted.
        if ap != &Value::Bool(false) {
            return Err(GbnfError(
                "additionalProperties must be false when explicitly declared",
            ));
        }
    }

    let empty = Map::new();
    let properties = match schema.get("properties") {
        None => &empty,
        Some(Value::Object(m)) => m,
        Some(_) => return Err(GbnfError("tool input schema properties must be an object")),
    };
    let names: Vec<String> = properties.keys().cloned().collect();
    for (_name, property_schema) in properties {
        // Python also re-validates the name is a string/encodable via
        // `_gbnf_string_literal(name)`; JSON object keys are always valid Rust
        // `&str`, so that check cannot fail here.
        if !property_schema.is_object() {
            return Err(GbnfError(
                "tool input schema property definitions must be objects",
            ));
        }
    }

    let required_list: Vec<String> = match schema.get("required") {
        None => Vec::new(),
        Some(Value::Array(arr)) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                match item.as_str() {
                    Some(s) => out.push(s.to_string()),
                    None => return Err(GbnfError("required tool argument names must be strings")),
                }
            }
            out
        }
        Some(_) => return Err(GbnfError("tool input schema required must be an array")),
    };
    let required: HashSet<String> = required_list.iter().cloned().collect();
    if required.len() != required_list.len() {
        return Err(GbnfError("required tool argument names must be unique"));
    }
    if !required.iter().all(|n| properties.contains_key(n)) {
        return Err(GbnfError(
            "required tool argument is missing from properties",
        ));
    }
    Ok((names, required))
}

/// `_argument_rules` (gbnf_generator.py:111-151): one fixed-order argument object.
fn argument_rules(index: usize, tool: &ToolSpec) -> Result<Vec<String>, GbnfError> {
    let (names, required) = validated_object_schema(tool)?;
    let args_rule = format!("args-{index}");

    if names.is_empty() {
        return Ok(vec![format!("{args_rule} ::= {} ws {}", j("{"), j("}"))]);
    }

    let required_positions: Vec<usize> = names
        .iter()
        .enumerate()
        .filter(|(_, name)| required.contains(*name))
        .map(|(pos, _)| pos)
        .collect();

    if let Some(&first_required) = required_positions.first() {
        let mut parts: Vec<String> = vec![format!("{args_rule} ::= {} ws", j("{"))];
        for name in &names[..first_required] {
            parts.push(format!("( {} ws {} ws )?", argument_member(name), j(",")));
        }
        parts.push(argument_member(&names[first_required]));
        for name in &names[first_required + 1..] {
            let member = argument_member(name);
            if required.contains(name) {
                parts.push(format!("ws {} ws {member}", j(",")));
            } else {
                parts.push(format!("( ws {} ws {member} )?", j(",")));
            }
        }
        parts.push(format!("ws {}", j("}")));
        return Ok(vec![parts.join(" ")]);
    }

    // No required properties: an outer optional permits `{}`, and this suffix
    // chain represents every non-empty fixed-order subset without 2^N blowup.
    let mut option_rules: Vec<String> = Vec::with_capacity(names.len());
    for (pos, name) in names.iter().enumerate() {
        let option = format!("{args_rule}-options-{pos}");
        let member = argument_member(name);
        let rhs = if pos + 1 == names.len() {
            member
        } else {
            let following = format!("{args_rule}-options-{}", pos + 1);
            format!("{member} ( ws {} ws {following} )? | {following}", j(","))
        };
        option_rules.push(format!("{option} ::= {rhs}"));
    }
    let mut rules = vec![format!(
        "{args_rule} ::= {} ws ( {args_rule}-options-0 )? ws {}",
        j("{"),
        j("}")
    )];
    rules.extend(option_rules);
    Ok(rules)
}

/// `generate_grammar` (gbnf_generator.py:154-200). Produces the GBNF grammar
/// constraining decoding to one tool call over `tools`. Fail-closed on an empty
/// active set, empty/duplicate tool names.
pub fn generate_grammar(tools: &[ToolSpec], allow_no_tool: bool) -> Result<String, GbnfError> {
    if tools.is_empty() {
        return Err(GbnfError(
            "cannot build a tool-call grammar from an empty active set",
        ));
    }

    let mut seen: HashSet<&str> = HashSet::with_capacity(tools.len());
    for tool in tools {
        if tool.name.is_empty() {
            return Err(GbnfError("tool names must be nonempty strings"));
        }
        // Python also calls `_gbnf_string_literal(name)` here — always valid for
        // a Rust `&str`.
        if !seen.insert(tool.name.as_str()) {
            return Err(GbnfError("tool names must be unique"));
        }
    }

    let invocation_names: Vec<String> = (0..tools.len())
        .map(|i| format!("invocation-{i}"))
        .collect();
    let root_rule = if allow_no_tool {
        "root ::= \"NO_TOOL\" | invocation\n"
    } else {
        "root ::= invocation\n"
    };
    let invocation_rule = format!("invocation ::= {}\n", invocation_names.join(" | "));

    let mut tool_rules: Vec<String> = Vec::new();
    for (index, tool) in tools.iter().enumerate() {
        tool_rules.push(format!(
            "invocation-{index} ::= {lb} ws {tool_key} ws {name_lit} ws {comma} ws \
             {args_key} ws args-{index} ( ws {comma} ws {body_key} ws str )? ws {rb}",
            lb = j("{"),
            tool_key = j("\"tool\":"),
            name_lit = gbnf_string_literal(&tool.name),
            comma = j(","),
            args_key = j("\"args\":"),
            body_key = j("\"body_span\":"),
            rb = j("}"),
        ));
        tool_rules.extend(argument_rules(index, tool)?);
    }

    let mut out = String::new();
    out.push_str(root_rule);
    out.push_str(&invocation_rule);
    out.push_str(&tool_rules.join("\n"));
    out.push('\n');
    out.push_str(VALUE_GRAMMAR_TAIL);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Vector {
        id: String,
        allow_no_tool: bool,
        tools: Vec<VectorTool>,
        grammar: String,
    }

    #[derive(serde::Deserialize)]
    struct VectorTool {
        name: String,
        input_schema: Value,
    }

    #[derive(serde::Deserialize)]
    struct VectorFile {
        vectors: Vec<Vector>,
    }

    /// Golden grammars emitted by LIVE Python (server.runtime.gbnf_generator),
    /// frozen by `vectors/gen/gen_gbnf_vectors.py`. serde_json parses this with
    /// `preserve_order`, so `input_schema.properties` iterate in the same
    /// declaration order Python used.
    const VECTORS_JSON: &str = include_str!("gbnf_vectors.json");

    #[test]
    fn grammars_are_byte_identical_to_python() {
        let file: VectorFile = serde_json::from_str(VECTORS_JSON).expect("parse vectors");
        assert_eq!(file.vectors.len(), 7, "expected 7 differential vectors");
        for v in &file.vectors {
            let tools: Vec<ToolSpec> = v
                .tools
                .iter()
                .map(|t| ToolSpec {
                    name: t.name.clone(),
                    input_schema: t.input_schema.clone(),
                })
                .collect();
            let got = generate_grammar(&tools, v.allow_no_tool)
                .unwrap_or_else(|e| panic!("vector {} failed: {e}", v.id));
            assert_eq!(got, v.grammar, "grammar mismatch for vector {}", v.id);
        }
    }

    // ── Unit coverage of the fail-closed validation branches (Python ValueError
    //    messages, byte-exact). ──

    fn err(tools: &[ToolSpec], allow_no_tool: bool) -> String {
        generate_grammar(tools, allow_no_tool)
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn empty_active_set_is_rejected() {
        assert_eq!(
            err(&[], false),
            "cannot build a tool-call grammar from an empty active set"
        );
    }

    #[test]
    fn empty_and_duplicate_names_rejected() {
        assert_eq!(
            err(&[ToolSpec::new("", "{}")], false),
            "tool names must be nonempty strings"
        );
        assert_eq!(
            err(
                &[ToolSpec::new("dup", "{}"), ToolSpec::new("dup", "{}")],
                false
            ),
            "tool names must be unique"
        );
    }

    #[test]
    fn schema_root_validation_messages() {
        assert_eq!(
            err(&[ToolSpec::new("t", "[]")], false),
            "tool input schema must be an object"
        );
        assert_eq!(
            err(&[ToolSpec::new("t", r#"{"type":"array"}"#)], false),
            "tool input schema root type must be object or absent"
        );
        assert_eq!(
            err(&[ToolSpec::new("t", r#"{"enum":[1,2]}"#)], false),
            "unsupported tool input schema root construct"
        );
        assert_eq!(
            err(
                &[ToolSpec::new("t", r#"{"additionalProperties":true}"#)],
                false
            ),
            "additionalProperties must be false when explicitly declared"
        );
        assert_eq!(
            err(&[ToolSpec::new("t", r#"{"properties":[]}"#)], false),
            "tool input schema properties must be an object"
        );
        assert_eq!(
            err(&[ToolSpec::new("t", r#"{"properties":{"a":"x"}}"#)], false),
            "tool input schema property definitions must be objects"
        );
        assert_eq!(
            err(&[ToolSpec::new("t", r#"{"required":"a"}"#)], false),
            "tool input schema required must be an array"
        );
        assert_eq!(
            err(&[ToolSpec::new("t", r#"{"required":[1]}"#)], false),
            "required tool argument names must be strings"
        );
        assert_eq!(
            err(&[ToolSpec::new("t", r#"{"required":["a","a"]}"#)], false),
            "required tool argument names must be unique"
        );
        assert_eq!(
            err(
                &[ToolSpec::new(
                    "t",
                    r#"{"properties":{"a":{}},"required":["b"]}"#
                )],
                false
            ),
            "required tool argument is missing from properties"
        );
    }

    #[test]
    fn absent_type_is_treated_as_object() {
        // Python `schema.get("type", "object")` — absent type is valid.
        let g = generate_grammar(&[ToolSpec::new("t", r#"{"properties":{}}"#)], false).unwrap();
        assert!(g.contains(r#"args-0 ::= "{" ws "}""#));
    }

    #[test]
    fn additional_properties_false_is_accepted() {
        assert!(generate_grammar(
            &[ToolSpec::new(
                "t",
                r#"{"properties":{"a":{}},"required":["a"],"additionalProperties":false}"#
            )],
            false
        )
        .is_ok());
    }
}
