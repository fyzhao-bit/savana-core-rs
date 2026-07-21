//! CaMeL capability / taint-tracking algebra — Rust port of the PURE core of
//! `server/security/capabilities.py`: the `Capability` dataclass, `combine_caps`,
//! and the `is_public`/`is_trusted` predicates.
//!
//! Deliberately NOT ported here: `CaMeLValue` (wraps an arbitrary `Any` raw
//! payload plus a dependency tree), its constructors (`user_value`,
//! `tool_value`, `qllm_value`, ...), `derive`, `all_dependencies`, and
//! `wrap_tool_tree`/`unwrap_tool_tree`. Those are generic tree-recursion /
//! value-wrapping scaffolding over a dynamically-typed payload, not the pure
//! set algebra this slice targets — porting them means picking a concrete
//! Rust payload type (e.g. `serde_json::Value`), which is an
//! interpreter-level design decision out of scope here.
//!
//! Trust model (mirrors the Python docstring, capabilities.py:14-16):
//!   - User / Constant / Planner  -> trusted (control-flow & literals)
//!   - Tool / Qllm                -> untrusted (anything that came from the world)

use std::collections::BTreeSet;

/// Provenance tag for a value. Mirrors `class Source(str, Enum)`
/// (capabilities.py:25-30); `as_str`/`from_wire` round-trip the exact wire
/// strings the Python `str, Enum` members serialize to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    User,
    Constant,
    Planner,
    Tool,
    Qllm,
}

impl Source {
    /// The exact string value of the corresponding Python `Source` member.
    pub fn as_str(self) -> &'static str {
        match self {
            Source::User => "user",
            Source::Constant => "constant",
            Source::Planner => "planner",
            Source::Tool => "tool",
            Source::Qllm => "qllm",
        }
    }

    /// Inverse of [`Source::as_str`]; `None` for anything the Python enum
    /// would reject with a `ValueError`. Named `from_wire` (not `from_str`)
    /// to avoid `clippy::should_implement_trait` — this isn't `FromStr`.
    pub fn from_wire(s: &str) -> Option<Source> {
        match s {
            "user" => Some(Source::User),
            "constant" => Some(Source::Constant),
            "planner" => Some(Source::Planner),
            "tool" => Some(Source::Tool),
            "qllm" => Some(Source::Qllm),
            _ => None,
        }
    }

    /// Membership test against `TRUSTED_SOURCES` (capabilities.py:33):
    /// `frozenset({USER, CONSTANT, PLANNER})`.
    pub fn is_trusted(self) -> bool {
        matches!(self, Source::User | Source::Constant | Source::Planner)
    }
}

/// Readers who may read a value. `None` == public (anyone); mirrors Python's
/// `readers: frozenset[str] | None` with the `PUBLIC: None = None` sentinel
/// (capabilities.py:39,46).
pub type Readers = Option<BTreeSet<String>>;

/// Provenance + readership tags carried by every value. Mirrors the frozen
/// `Capability` dataclass (capabilities.py:42-55).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub sources: BTreeSet<Source>,
    pub readers: Readers,
}

impl Capability {
    pub fn new(sources: BTreeSet<Source>, readers: Readers) -> Self {
        Capability { sources, readers }
    }

    /// `readers is None` (capabilities.py:49-50). NOTE: an empty-but-`Some`
    /// reader set is NOT public — only the `None` sentinel is.
    pub fn is_public(&self) -> bool {
        self.readers.is_none()
    }

    /// Trusted iff EVERY contributing source is trusted — `sources <=
    /// TRUSTED_SOURCES` (capabilities.py:52-55). Vacuously true for an empty
    /// source set, matching Python's `frozenset() <= TRUSTED_SOURCES`.
    pub fn is_trusted(&self) -> bool {
        self.sources.iter().all(|s| s.is_trusted())
    }
}

/// Module-level predicates (capabilities.py:186-191). The Python versions
/// take a `CaMeLValue` and immediately delegate to `v.cap.{is_public,
/// is_trusted}`; since this slice ports only the `Capability` algebra (see
/// module docs) these operate directly on a `Capability`.
pub fn is_public(cap: &Capability) -> bool {
    cap.is_public()
}

pub fn is_trusted(cap: &Capability) -> bool {
    cap.is_trusted()
}

/// Union of sources (taint spreads), intersection of readers (most
/// restrictive wins; any private input keeps the result private). Faithful
/// port of `combine_caps` (capabilities.py:162-174), including its
/// empty-input special case (`Capability({CONSTANT}, PUBLIC)`).
///
/// The reader accumulation mirrors Python exactly: `readers` starts at
/// `PUBLIC` (`None`), which acts as the identity element for intersection
/// ("public ∩ X = X" — a public cap never narrows the result); the first
/// non-public cap encountered is adopted outright, and every subsequent
/// non-public cap intersects into the running total. Because set
/// intersection is commutative and associative, the result does not depend
/// on input order despite the left-fold implementation.
pub fn combine_caps(caps: &[Capability]) -> Capability {
    if caps.is_empty() {
        let mut sources = BTreeSet::new();
        sources.insert(Source::Constant);
        return Capability::new(sources, None);
    }
    let mut sources: BTreeSet<Source> = BTreeSet::new();
    let mut readers: Readers = None; // PUBLIC — the identity element for ∩
    for c in caps {
        sources.extend(c.sources.iter().copied());
        match &c.readers {
            None => continue, // public ∩ X = X
            Some(r) => {
                readers = Some(match &readers {
                    None => r.clone(),
                    Some(acc) => acc.intersection(r).cloned().collect(),
                });
            }
        }
    }
    Capability::new(sources, readers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[Source]) -> BTreeSet<Source> {
        items.iter().copied().collect()
    }
    fn rset(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn source_string_round_trip() {
        for s in [
            Source::User,
            Source::Constant,
            Source::Planner,
            Source::Tool,
            Source::Qllm,
        ] {
            assert_eq!(Source::from_wire(s.as_str()), Some(s));
        }
        assert_eq!(Source::from_wire("bogus"), None);
    }

    #[test]
    fn trusted_sources_membership() {
        assert!(Source::User.is_trusted());
        assert!(Source::Constant.is_trusted());
        assert!(Source::Planner.is_trusted());
        assert!(!Source::Tool.is_trusted());
        assert!(!Source::Qllm.is_trusted());
    }

    #[test]
    fn capability_is_public_iff_readers_none() {
        let pub_cap = Capability::new(set(&[Source::User]), None);
        assert!(pub_cap.is_public());

        let priv_cap = Capability::new(set(&[Source::User]), Some(rset(&["user"])));
        assert!(!priv_cap.is_public());

        // An empty-but-Some reader set is NOT public — only `None` is.
        let empty_readers = Capability::new(set(&[Source::User]), Some(BTreeSet::new()));
        assert!(!empty_readers.is_public());
    }

    #[test]
    fn capability_is_trusted_iff_all_sources_trusted() {
        let trusted = Capability::new(
            set(&[Source::User, Source::Constant, Source::Planner]),
            None,
        );
        assert!(trusted.is_trusted());

        let mixed = Capability::new(set(&[Source::User, Source::Tool]), None);
        assert!(!mixed.is_trusted());

        let untrusted = Capability::new(set(&[Source::Qllm]), None);
        assert!(!untrusted.is_trusted());

        // Vacuous truth: an empty source set is trusted, matching Python's
        // `frozenset() <= TRUSTED_SOURCES`.
        let empty = Capability::new(BTreeSet::new(), None);
        assert!(empty.is_trusted());
    }

    #[test]
    fn free_function_predicates_match_methods() {
        let cap = Capability::new(set(&[Source::Tool]), Some(rset(&["a"])));
        assert_eq!(is_public(&cap), cap.is_public());
        assert_eq!(is_trusted(&cap), cap.is_trusted());
    }

    #[test]
    fn combine_caps_empty_yields_public_constant() {
        let c = combine_caps(&[]);
        assert_eq!(c.sources, set(&[Source::Constant]));
        assert!(c.is_public());
    }

    #[test]
    fn combine_caps_unions_sources() {
        let a = Capability::new(set(&[Source::User]), None);
        let b = Capability::new(set(&[Source::Tool]), None);
        let c = combine_caps(&[a, b]);
        assert_eq!(c.sources, set(&[Source::User, Source::Tool]));
    }

    #[test]
    fn combine_caps_all_public_stays_public() {
        let a = Capability::new(set(&[Source::User]), None);
        let b = Capability::new(set(&[Source::Constant]), None);
        let c = combine_caps(&[a, b]);
        assert!(c.is_public());
    }

    #[test]
    fn combine_caps_any_private_input_makes_result_private() {
        // "public ∩ X = X": a public cap must never dilute a private one.
        let pub_cap = Capability::new(set(&[Source::User]), None);
        let priv_cap = Capability::new(set(&[Source::Tool]), Some(rset(&["tool:x"])));
        let c = combine_caps(&[pub_cap, priv_cap]);
        assert!(!c.is_public());
        assert_eq!(c.readers, Some(rset(&["tool:x"])));
    }

    #[test]
    fn combine_caps_intersects_overlapping_readers() {
        let a = Capability::new(set(&[Source::Tool]), Some(rset(&["a", "b"])));
        let b = Capability::new(set(&[Source::Tool]), Some(rset(&["b", "c"])));
        let c = combine_caps(&[a, b]);
        assert_eq!(c.readers, Some(rset(&["b"])));
    }

    #[test]
    fn combine_caps_disjoint_readers_yields_empty_set_not_public() {
        let a = Capability::new(set(&[Source::Tool]), Some(rset(&["a"])));
        let b = Capability::new(set(&[Source::Tool]), Some(rset(&["b"])));
        let c = combine_caps(&[a, b]);
        assert!(!c.is_public()); // Some(empty), NOT None
        assert_eq!(c.readers, Some(BTreeSet::new()));
    }

    #[test]
    fn combine_caps_order_independent() {
        let a = Capability::new(set(&[Source::Tool]), Some(rset(&["a", "b"])));
        let b = Capability::new(set(&[Source::Qllm]), Some(rset(&["b", "c"])));
        let pub_cap = Capability::new(set(&[Source::User]), None);
        let forward = combine_caps(&[a.clone(), b.clone(), pub_cap.clone()]);
        let backward = combine_caps(&[pub_cap, b, a]);
        assert_eq!(forward, backward);
    }

    #[test]
    fn combine_caps_self_merge_is_idempotent() {
        let a = Capability::new(set(&[Source::User]), Some(rset(&["user"])));
        let once = combine_caps(&[a.clone()]);
        let twice = combine_caps(&[a.clone(), a]);
        assert_eq!(once, twice);
    }

    #[test]
    fn combine_caps_associative() {
        let a = Capability::new(set(&[Source::User]), Some(rset(&["a", "b"])));
        let b = Capability::new(set(&[Source::Tool]), Some(rset(&["b", "c"])));
        let c = Capability::new(set(&[Source::Qllm]), None);
        let flat = combine_caps(&[a.clone(), b.clone(), c.clone()]);
        let left_grouped = combine_caps(&[combine_caps(&[a.clone(), b.clone()]), c.clone()]);
        let right_grouped = combine_caps(&[a, combine_caps(&[b, c])]);
        assert_eq!(flat, left_grouped);
        assert_eq!(flat, right_grouped);
    }
}
