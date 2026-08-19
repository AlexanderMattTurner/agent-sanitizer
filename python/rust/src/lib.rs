//! The narrowing traversal: which lines of a payload can possibly hold a match.
//!
//! This is the execution half of `agent_sanitizer.secrets.prefilter`. The
//! ANALYSIS half stays in Python because `re._parser` is the authoritative
//! reading of a pattern — Python derives each pattern's required literals and
//! hands them here already case-folded, paired with opaque pattern ids it will
//! map back itself. Nothing here parses a regex or decides what counts as a
//! secret: a literal is a necessary condition, and over-claiming a line only
//! sends more text to Python's confirm pass.

use std::collections::{HashMap, HashSet};

use aho_corasick::{AhoCorasick, MatchKind};
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Every line index of `folded` that holds one of `literals`, mapped to the
/// pattern ids that literal was indexed to.
///
/// `folded` must be the case-folded view Python produced, and each literal
/// folded the same way, so one search serves a case-sensitive and a
/// case-insensitive pattern alike.
///
/// Line indices need no byte-to-code-point translation: `\n` is a single byte
/// that cannot occur inside a multi-byte UTF-8 sequence, so counting newline
/// BYTES counts exactly the newline characters Python's `str.split("\n")` would.
#[pyfunction]
fn literal_lines(
    py: Python<'_>,
    folded: &str,
    literals: Vec<(String, Vec<u32>)>,
) -> PyResult<Py<PyDict>> {
    let patterns: Vec<&str> = literals.iter().map(|(lit, _)| lit.as_str()).collect();
    // MatchKind::Standard with an OVERLAPPING iterator is what keeps this a
    // sound necessary condition: leftmost-first semantics would report `apikey`
    // and swallow the `key` inside it, dropping that literal's patterns from a
    // line that really can match them.
    let automaton = AhoCorasick::builder()
        .match_kind(MatchKind::Standard)
        .build(&patterns)
        .map_err(|err| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "could not build the literal automaton: {err}"
            ))
        })?;

    let bytes = folded.as_bytes();
    let mut claims: HashMap<usize, HashSet<u32>> = HashMap::new();

    // Matches arrive in ascending start order, so the line number advances
    // monotonically and each gap between consecutive starts is counted once —
    // one pass over the payload rather than one count per hit.
    let mut line = 0usize;
    let mut counted_to = 0usize;
    // A literal's second occurrence on a line claims exactly what its first did
    // (a fixed literal spans the same number of lines wherever it starts), so
    // the repeat is dropped before it costs a set update. One long line of
    // `key key key ...` is attacker-shaped input against a shared daemon.
    let mut seen_on_line: HashSet<u32> = HashSet::new();

    for hit in automaton.find_overlapping_iter(folded) {
        let start = hit.start();
        if start > counted_to {
            let advanced = memchr::memchr_iter(b'\n', &bytes[counted_to..start]).count();
            if advanced > 0 {
                line += advanced;
                seen_on_line.clear();
            }
            counted_to = start;
        }
        let literal_id = hit.pattern().as_u32();
        if !seen_on_line.insert(literal_id) {
            continue;
        }
        let ids = &literals[hit.pattern().as_usize()].1;
        claims.entry(line).or_default().extend(ids.iter().copied());
        // A literal carrying a newline reaches past its own line, and every line
        // it touches can hold the match, so each one is claimed.
        let interior = memchr::memchr_iter(b'\n', &bytes[start..hit.end()]).count();
        for offset in 1..=interior {
            claims
                .entry(line + offset)
                .or_default()
                .extend(ids.iter().copied());
        }
    }

    let out = PyDict::new(py);
    for (index, ids) in claims {
        let mut sorted: Vec<u32> = ids.into_iter().collect();
        sorted.sort_unstable();
        out.set_item(index, sorted)?;
    }
    Ok(out.into())
}

#[pymodule]
fn _narrow(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(literal_lines, module)?)?;
    Ok(())
}
