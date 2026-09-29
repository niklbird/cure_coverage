use std::collections::HashMap;
use std::fs;
use std::process::Command;

use serde::Serialize;

/// A single source line annotated with coverage data.
#[derive(Debug, Clone)]
pub struct CovLine {
    pub line_no: u32,
    pub content: String,
    /// Total hits across all guards that map to this line.
    pub hit_count: u64,
    /// Whether this line was a guard point (instrumented basic block entry).
    pub instrumented: bool,
}

/// Per-file coverage report.
#[derive(Debug, Clone)]
pub struct FileCoverage {
    pub path: String,
    pub lines: Vec<CovLine>,
    pub total_instrumented: usize,
    pub total_hit: usize,
}

/// A branch/edge that was instrumented and mapped to source but whose
/// coverage counter stayed at 0 — i.e. reached but never taken.
#[derive(Debug, Clone, Serialize)]
pub struct UncoveredBranch {
    /// Index into the AFL coverage bitmap (`guard_index + first_loc`).
    pub slot: usize,
    /// Guard index from the `__sancov_guards` section.
    pub guard_index: usize,
    /// Source file (path as recorded in debug info).
    pub file: String,
    /// 1-based source line the guard maps to (the body of the untaken branch).
    pub line: u32,
    /// 1-based line of the controlling `if` (an `else` is resolved back to its
    /// `if`). Falls back to `line` when no enclosing `if` can be identified.
    pub condition_line: u32,
    /// The controlling condition text, e.g. `if (x == 43)`.
    pub condition: String,
    /// Polarity of the untaken branch relative to `condition`:
    /// `Some(false)` → the `if`/then side (the condition was never true),
    /// `Some(true)`  → the `else` side (the condition was never false),
    /// `None`        → not an `if`-guarded branch, or the polarity is ambiguous.
    pub negated: Option<bool>,
    /// Signature of the function enclosing the branch, e.g. `void branch2(int x)`.
    pub function_signature: String,
}

/// Static analysis result: maps guard index → source location.
#[derive(Debug)]
pub struct GuardMap {
    /// guard_index → (canonical_file_path, line_number)
    pub guard_to_src: HashMap<usize, (String, u32)>,
    /// guard_index → virtual address of the instruction that increments it.
    /// Branch-select guards share the address of their (single) indexed load.
    pub guard_to_addr: HashMap<usize, u64>,
    pub guards_start_va: u64,
    pub guards_end_va: u64,
}

impl GuardMap {
    pub fn num_guards(&self) -> usize {
        ((self.guards_end_va - self.guards_start_va) / 4) as usize
    }

    /// Translate a complete coverage map (slot → hit_count) into per-file coverage.
    /// `first_loc` is the AFL guard base: slot = guard_index + first_loc.
    /// `source_roots` is a list of directories to search when addr2line paths don't exist.
    pub fn apply(&self, coverage: &[u16], first_loc: usize, source_roots: &[&str]) -> Vec<FileCoverage> {
        // file → line → hit_count
        let mut file_hits: HashMap<String, HashMap<u32, u64>> = HashMap::new();

        for (slot, &count) in coverage.iter().enumerate() {
            if slot < first_loc {
                continue;
            }
            let guard_idx = slot - first_loc;
            if let Some((file, line)) = self.guard_to_src.get(&guard_idx) {
                *file_hits
                    .entry(file.clone())
                    .or_default()
                    .entry(*line)
                    .or_insert(0) += count as u64;
            }
        }

        let mut result = Vec::with_capacity(file_hits.len());
        for (file_path, line_hits) in file_hits {
            let resolved = resolve_source_path(&file_path, source_roots);

            let source = fs::read_to_string(&resolved).unwrap_or_default();
            let src_lines: Vec<&str> = source.lines().collect();

            let mut total_instrumented = 0usize;
            let mut total_hit = 0usize;
            // Use max of actual source lines and highest hit line so coverage
            // is visible even when the source file is not accessible.
            let max_hit_line = line_hits.keys().copied().max().unwrap_or(0);
            let num_lines = (src_lines.len() as u32).max(max_hit_line);

            let lines: Vec<CovLine> = (1..=num_lines)
                .map(|ln| {
                    let hit_count = *line_hits.get(&ln).unwrap_or(&0);
                    let instrumented = line_hits.contains_key(&ln);
                    if instrumented {
                        total_instrumented += 1;
                        if hit_count > 0 {
                            total_hit += 1;
                        }
                    }
                    CovLine {
                        line_no: ln,
                        content: src_lines
                            .get((ln - 1) as usize)
                            .copied()
                            .unwrap_or("")
                            .to_string(),
                        hit_count,
                        instrumented,
                    }
                })
                .collect();

            result.push(FileCoverage {
                path: file_path,
                lines,
                total_instrumented,
                total_hit,
            });
        }
        result
    }

    /// Build the counter-index map: AFL coverage-map slot → source location.
    ///
    /// Whereas [`GuardMap::guard_to_src`] is keyed by guard index (the value
    /// emitted into `__sancov_guards`), this is keyed by the index into the AFL
    /// coverage bitmap that the running target actually increments. The two are
    /// related by `slot = guard_index + first_loc`, so this method simply shifts
    /// every guard entry by `first_loc`.
    ///
    /// Use [`GuardMap::detect_first_loc`] to recover `first_loc` from a coverage
    /// sample when it isn't known up front.
    pub fn counter_to_src(&self, first_loc: usize) -> HashMap<usize, (String, u32)> {
        self.guard_to_src
            .iter()
            .map(|(&guard_idx, src)| (guard_idx + first_loc, src.clone()))
            .collect()
    }

    /// Auto-detect `first_loc` (AFL guard base offset) from coverage data.
    ///
    /// For each active slot `s` and each known guard index `g`, the candidate
    /// `first_loc = s - g` gets a vote. The offset that makes the most active
    /// slots coincide with known guards wins.
    ///
    /// Ties are broken deterministically by the total aligned hit-count: the
    /// correct offset lines the heavily-executed edges up with real guards, so
    /// when two offsets explain the same number of coincidences we prefer the
    /// one that accounts for more coverage mass (and finally the smaller offset).
    /// This matters because raw coincidence counts can tie on small binaries,
    /// where an arbitrary winner produces a completely wrong source mapping.
    /// Falls back to `default` when no active slots exist.
    pub fn detect_first_loc(&self, coverage: &[u16], default: usize) -> usize {
        let mut guard_indices: Vec<usize> = self.guard_to_src.keys().copied().collect();
        guard_indices.sort_unstable();

        // candidate offset -> (coincidences, total aligned hit count)
        let mut votes: HashMap<usize, (usize, u64)> = HashMap::new();
        for (slot, &count) in coverage.iter().enumerate() {
            if count == 0 {
                continue;
            }
            for &g in &guard_indices {
                if slot >= g {
                    let entry = votes.entry(slot - g).or_insert((0, 0));
                    entry.0 += 1;
                    entry.1 += count as u64;
                }
            }
        }

        votes
            .into_iter()
            .max_by(|(ak, av), (bk, bv)| {
                av.0
                    .cmp(&bv.0) // most coincidences
                    .then(av.1.cmp(&bv.1)) // then most aligned hit-count
                    .then(bk.cmp(ak)) // then smallest offset
            })
            .map(|(k, _)| k)
            .unwrap_or(default)
    }

    /// Return every instrumented branch that was *reached but not taken*:
    /// guards that map to a source location but whose coverage counter is 0.
    ///
    /// For each such branch the result carries its bitmap index plus textual
    /// context — the concrete source line of the branch (the condition) and the
    /// signature of the enclosing function. `source_roots` is searched by
    /// basename when the debug-info path no longer exists locally.
    ///
    /// Results are sorted by guard index for deterministic output.
    pub fn uncovered_branches(
        &self,
        coverage: &[u16],
        first_loc: usize,
        source_roots: &[&str],
    ) -> Vec<UncoveredBranch> {
        // Cache parsed source per resolved path: (lines, brace-depth-at-line-start).
        let mut cache: HashMap<String, (Vec<String>, Vec<i32>)> = HashMap::new();

        let mut guards: Vec<(&usize, &(String, u32))> = self.guard_to_src.iter().collect();
        guards.sort_by_key(|(idx, _)| **idx);

        let mut out = Vec::new();
        for (&guard_idx, (file, line)) in guards {
            let slot = guard_idx + first_loc;
            // A non-zero counter means the branch was taken at least once.
            if coverage.get(slot).copied().unwrap_or(0) != 0 {
                continue;
            }

            let resolved = resolve_source_path(file, source_roots);
            let (lines, depths) = cache.entry(resolved.clone()).or_insert_with(|| {
                let src = fs::read_to_string(&resolved).unwrap_or_default();
                let lines: Vec<String> = src.lines().map(str::to_string).collect();
                let depths = line_depths(&lines);
                (lines, depths)
            });

            // The guard maps to the branch body; resolve the controlling `if`
            // condition and which side (then/else) was never taken.
            let branch_idx = (*line as usize).checked_sub(1);
            let (condition_line, condition, negated) = branch_idx
                .map(|i| branch_condition(lines, i))
                .unwrap_or((*line, String::new(), None));
            let function_signature = branch_idx
                .and_then(|i| enclosing_signature(lines, depths, i))
                .unwrap_or_default();

            out.push(UncoveredBranch {
                slot,
                guard_index: guard_idx,
                file: file.clone(),
                line: *line,
                condition_line,
                condition,
                negated,
                function_signature,
            });
        }
        out
    }
}

/// Resolve a debug-info source path to an existing file, falling back to a
/// basename lookup under each of `source_roots` when the original path is gone.
fn resolve_source_path(file_path: &str, source_roots: &[&str]) -> String {
    if std::path::Path::new(file_path).exists() {
        return file_path.to_string();
    }
    let basename = std::path::Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    source_roots
        .iter()
        .filter_map(|root| {
            let candidate = std::path::Path::new(root).join(basename);
            candidate
                .exists()
                .then(|| candidate.to_string_lossy().into_owned())
        })
        .next()
        .unwrap_or_else(|| file_path.to_string())
}

/// Strip a trailing `//` line comment so it doesn't perturb brace counting.
fn strip_line_comment(line: &str) -> &str {
    match line.find("//") {
        Some(pos) => &line[..pos],
        None => line,
    }
}

/// Brace depth at the *start* of each line. Naive: tracks only `{`/`}` and
/// ignores `//` comments; good enough to locate enclosing C-style functions.
fn line_depths(lines: &[String]) -> Vec<i32> {
    let mut depths = Vec::with_capacity(lines.len());
    let mut depth = 0i32;
    for line in lines {
        depths.push(depth);
        for c in strip_line_comment(line).chars() {
            match c {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
        }
    }
    depths
}

/// Find the signature of the function enclosing `branch_idx` (0-based line).
///
/// Walks up to the top-level (depth-0) header that opens the enclosing block,
/// gathers the contiguous header lines up to the previous statement boundary,
/// and trims everything from the opening brace onward.
fn enclosing_signature(lines: &[String], depths: &[i32], branch_idx: usize) -> Option<String> {
    if branch_idx >= lines.len() {
        return None;
    }

    // Rise out of nested blocks to the depth-0 line that opens this function.
    let mut header = branch_idx as isize;
    while header >= 0 && depths[header as usize] > 0 {
        header -= 1;
    }
    if header < 0 {
        return None;
    }

    // Extend upward across multi-line headers, stopping at the previous
    // construct's boundary (a `;`, a closing `}`, or a blank line).
    let mut start = header;
    while start > 0 && depths[(start - 1) as usize] == 0 {
        let prev = lines[(start - 1) as usize].trim_end();
        if prev.is_empty() || prev.ends_with(';') || prev.ends_with('}') {
            break;
        }
        start -= 1;
    }

    let sig = (start..=header)
        .map(|k| lines[k as usize].trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let sig = sig.split('{').next().unwrap_or(&sig).trim().to_string();
    (!sig.is_empty()).then_some(sig)
}

/// Control-flow head that opens a block.
enum HeadKind {
    If,
    ElseIf,
    Else,
}

/// Does `s` begin with the whole word `kw` (next char is not part of an identifier)?
fn starts_with_word(s: &str, kw: &str) -> bool {
    s.strip_prefix(kw)
        .is_some_and(|rest| !rest.starts_with(|c: char| c.is_alphanumeric() || c == '_'))
}

/// Classify the text preceding a block-opening `{` as `if` / `else if` / `else`.
fn classify_head(head: &str) -> Option<HeadKind> {
    let t = head.trim_start_matches(|c: char| c == '}' || c.is_whitespace());
    if starts_with_word(t, "else") {
        let after = t["else".len()..].trim_start();
        return Some(if starts_with_word(after, "if") {
            HeadKind::ElseIf
        } else {
            HeadKind::Else
        });
    }
    starts_with_word(t, "if").then_some(HeadKind::If)
}

/// Text controlling the block opened on `opener_line` — everything before the
/// last `{`, trimmed; if that is empty (brace on its own line) the nearest
/// non-empty line above is used. Leading `}`/whitespace is stripped.
fn construct_head(lines: &[String], opener_line: usize) -> String {
    let line = strip_line_comment(&lines[opener_line]);
    let brace = line.rfind('{').unwrap_or(line.len());
    let mut head = line[..brace].trim().to_string();
    if head.is_empty() {
        for j in (0..opener_line).rev() {
            let p = strip_line_comment(&lines[j]).trim();
            if !p.is_empty() {
                head = p.to_string();
                break;
            }
        }
    }
    head.trim_start_matches(|c: char| c == '}' || c.is_whitespace())
        .trim()
        .to_string()
}

/// Find the `{` matching the `}` at `(close_line, close_char)` by scanning
/// backward with brace balancing. Returns the opening brace's `(line, char)`.
fn matching_open(lines: &[String], close_line: usize, close_char: usize) -> Option<(usize, usize)> {
    let mut bal = 1i32; // the closing `}` itself
    let mut li = close_line as isize;
    while li >= 0 {
        let line = strip_line_comment(&lines[li as usize]);
        let upper = if li as usize == close_line {
            close_char.min(line.len())
        } else {
            line.len()
        };
        for (ci, ch) in line[..upper].char_indices().rev() {
            match ch {
                '}' => bal += 1,
                '{' => {
                    bal -= 1;
                    if bal == 0 {
                        return Some((li as usize, ci));
                    }
                }
                _ => {}
            }
        }
        li -= 1;
    }
    None
}

/// Given the line of an `else`, find the line of its matching `if` by closing
/// the preceding then-block (`} ... { ... }`) back to its opener.
fn matching_if_of_else(lines: &[String], else_line: usize) -> Option<usize> {
    let el = strip_line_comment(&lines[else_line]);
    let bound = el.find("else").unwrap_or(el.len());
    let mut close_line = else_line;
    let mut close_char = el[..bound].rfind('}');
    while close_char.is_none() && close_line > 0 {
        close_line -= 1;
        close_char = strip_line_comment(&lines[close_line]).rfind('}');
    }
    matching_open(lines, close_line, close_char?).map(|(l, _)| l)
}

/// Find the `{` opening the block directly enclosing `branch_idx` (backward
/// brace matching from the line above it).
fn enclosing_opener(lines: &[String], branch_idx: usize) -> Option<usize> {
    let mut bal = 0i32;
    let mut li = branch_idx as isize - 1;
    while li >= 0 {
        let line = strip_line_comment(&lines[li as usize]);
        for ch in line.chars().rev() {
            match ch {
                '}' => bal += 1,
                '{' => {
                    if bal == 0 {
                        return Some(li as usize);
                    }
                    bal -= 1;
                }
                _ => {}
            }
        }
        li -= 1;
    }
    None
}

/// Resolve the controlling `if` for the branch body at `branch_idx`.
///
/// Returns `(condition_line, condition_text, negated)`:
/// * `negated == Some(false)` — the body is the `if`/then side, so the
///   condition was never true.
/// * `negated == Some(true)`  — the body is the `else` side (resolved back to
///   the governing `if`), so the condition was never false.
/// * `negated == None`        — the guard maps to the control line itself (the
///   taken edge is ambiguous) or no `if` was found; the branch line is returned.
fn branch_condition(lines: &[String], branch_idx: usize) -> (u32, String, Option<bool>) {
    let fallback = || {
        let txt = lines
            .get(branch_idx)
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        (branch_idx as u32 + 1, txt, None)
    };

    let Some(self_line) = lines.get(branch_idx).map(|l| strip_line_comment(l)) else {
        return fallback();
    };

    // Guard maps directly to a control/opening line: report the condition but
    // leave polarity unknown — we can't tell which edge the guard counts.
    if self_line.contains('{') {
        let head = construct_head(lines, branch_idx);
        return match classify_head(&head) {
            Some(_) => (branch_idx as u32 + 1, head, None),
            None => fallback(),
        };
    }

    // Guard maps to a statement inside a block: infer polarity from the block.
    let Some(opener) = enclosing_opener(lines, branch_idx) else {
        return fallback();
    };
    let head = construct_head(lines, opener);
    match classify_head(&head) {
        Some(HeadKind::If) | Some(HeadKind::ElseIf) => (opener as u32 + 1, head, Some(false)),
        Some(HeadKind::Else) => match matching_if_of_else(lines, opener) {
            Some(if_line) => (if_line as u32 + 1, construct_head(lines, if_line), Some(true)),
            None => (opener as u32 + 1, head, Some(true)),
        },
        None => fallback(),
    }
}

/// Get the virtual address bounds of `__sancov_guards` using `nm`.
fn sancov_bounds(binary: &str) -> Option<(u64, u64)> {
    let out = Command::new("nm").arg(binary).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut start = None;
    let mut stop = None;

    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(addr_str) = parts.next() else { continue };
        let Some(_ty) = parts.next() else { continue };
        let Some(sym) = parts.next() else { continue };
        let Ok(addr) = u64::from_str_radix(addr_str, 16) else {
            continue;
        };
        match sym {
            "__start___sancov_guards" => start = Some(addr),
            "__stop___sancov_guards" => stop = Some(addr),
            _ => {}
        }
    }

    Some((start?, stop?))
}

/// Scan the disassembly (via `objdump -d`) for the coverage-counter loads that
/// read a guard's VALUE (the AFL map index) out of the sancov_guards section.
///
/// The compiler emits these loads (`movslq` / `movsxd`) in two shapes:
///
/// * **RIP-relative** — `movslq 0x7daf(%rip),%rax` — objdump resolves the target
///   and annotates it `# HEXADDR <symbol>`. One guard per load. Used for
///   unconditional coverage points (e.g. function entry).
/// * **Register-indexed** — `movslq 0x4(%rdx,%rax,4),%rax` — the base register
///   was just loaded with the guard array's address via `lea …(%rip),%rdx`
///   (annotated `# HEXADDR`), and the index register selects a branch outcome
///   (`0` or `1`). objdump does NOT annotate the effective address here, so we
///   reconstruct it as `lea_target + disp + idx*4`. This is the branch-select
///   form; a single instruction covers the two successor edges of a conditional.
///
/// Only the value loads are of interest — `lea` refs to the same range load a
/// guard's ADDRESS (for CMPLOG) and are ignored except when they establish the
/// base register consumed by an indexed load, as described above.
///
/// Returns:
/// * `guard_index → instruction_address` (first occurrence per guard), and
/// * every instruction address seen, sorted ascending. Branch-select loads carry
///   no line info of their own, so callers walk this list backwards from a
///   guard's address to the nearest instruction that does resolve to a line.
fn find_guard_refs(
    binary: &str,
    guards_start: u64,
    guards_end: u64,
) -> (HashMap<usize, u64>, Vec<u64>) {
    let out = Command::new("objdump")
        .args(["-d", binary])
        .output()
        .expect("objdump not found — install binutils");

    let text = String::from_utf8_lossy(&out.stdout);
    let mut result: HashMap<usize, u64> = HashMap::new();
    let mut all_addrs: Vec<u64> = Vec::new();
    let mut cur_addr: u64 = 0;

    // Register name -> guard-array address most recently `lea`'d into it. Used to
    // resolve the base of register-indexed guard-value loads (branch selects).
    let mut lea_base: HashMap<String, u64> = HashMap::new();

    // Record every guard reachable from an effective guard address, then advance
    // by one slot for `count` slots (a 2-way branch select touches two edges).
    let record_range = |eff_addr: u64, count: usize, at: u64, out: &mut HashMap<usize, u64>| {
        for k in 0..count as u64 {
            let target = eff_addr + k * 4;
            if target >= guards_start && target < guards_end {
                let guard_idx = ((target - guards_start) / 4) as usize;
                out.entry(guard_idx).or_insert(at);
            }
        }
    };

    for line in text.lines() {
        let trimmed = line.trim_start();

        // Parse instruction address: lines start with "HEXADDR:\t..."
        if let Some(colon) = trimmed.find(':') {
            let addr_part = &trimmed[..colon];
            if !addr_part.is_empty() && addr_part.chars().all(|c| c.is_ascii_hexdigit()) {
                if let Ok(a) = u64::from_str_radix(addr_part, 16) {
                    cur_addr = a;
                    all_addrs.push(a);
                }
            }
        }

        // Instruction text is the last tab-separated field, e.g.
        // "movslq 0x4(%rdx,%rax,4),%rax" or "lea 0x7d56(%rip),%rdx    # a19c <..>".
        let insn = line.rsplit('\t').next().unwrap_or("");

        // The RIP-relative address objdump resolved for this instruction (if any):
        // "# HEXADDR <symbol>", address without a "0x" prefix.
        let annotated = line.find("# ").and_then(|hash| {
            let addr_str = line[hash + 2..].split_whitespace().next().unwrap_or("");
            u64::from_str_radix(addr_str, 16).ok()
        });

        // `lea …(%rip),%reg` whose target is the guard array: remember the base
        // register so a following indexed load can be resolved against it. A `lea`
        // of anything else into that register overwrites the guard base, so drop
        // any stale entry — otherwise a later indexed load (e.g. the AFL map read)
        // could be resolved against a base the register no longer holds.
        if insn.starts_with("lea ") {
            if let Some(dest) = insn.split('#').next().and_then(|s| s.rsplit(',').next()) {
                let dest = dest.trim().to_string();
                match annotated {
                    Some(t) if t >= guards_start && t < guards_end => {
                        lea_base.insert(dest, t);
                    }
                    _ => {
                        lea_base.remove(&dest);
                    }
                }
            }
            continue;
        }

        // Guard VALUE loads are a mov-family instruction reading the guard slot.
        // Optimized builds emit `movslq`/`movsxd`; `-O0`/`-Og` builds keep each
        // branch body as its own block and load the guard with a plain 32-bit
        // `mov 0x..(%rip),%ecx`. Gating on a guard-range target below keeps this
        // broad match from picking up unrelated movs.
        let mnem = insn.split_whitespace().next().unwrap_or("");
        if !mnem.starts_with("mov") {
            continue;
        }

        // Operand text without objdump's trailing "# ..." comment.
        let ops = insn.split('#').next().unwrap_or(insn);

        // RIP-relative form: objdump already resolved the guard address. Require
        // the guard operand to be the SOURCE (a load) rather than a store target,
        // so guard-initialisation writes in the AFL runtime aren't mistaken for
        // coverage points.
        if let Some(target) = annotated {
            if target >= guards_start && target < guards_end {
                match (ops.find("(%rip)"), ops.rfind(',')) {
                    (Some(rip), Some(comma)) if rip < comma => {
                        record_range(target, 1, cur_addr, &mut result);
                    }
                    _ => {}
                }
            }
            continue;
        }

        // Register-indexed branch-select form: `movslq disp(%base,%idx,4),%dst`.
        // Restricted to the sign-extending loads with scale 4 (guards are 4-byte
        // ints) — this is the only shape the branch-select instrumentation emits.
        // A plain `mov (%base,%idx,1),%al` is the AFL map read, not a guard load,
        // and must not be treated as one.
        if mnem == "movslq" || mnem == "movsxd" {
            if let Some((disp, base)) = parse_indexed_operand(insn) {
                if let Some(&lea_target) = lea_base.get(&base) {
                    let eff = lea_target.wrapping_add(disp as u64);
                    // A branch select indexes the two successor edges (idx 0 and 1).
                    record_range(eff, 2, cur_addr, &mut result);
                }
            }
        }
    }

    all_addrs.sort_unstable();
    all_addrs.dedup();
    (result, all_addrs)
}

/// Parse an AT&T register-indexed memory operand `disp(%base,%index,4)` from an
/// instruction's operand text, returning `(disp, base_register)`.
///
/// Only operands with an index register **and scale 4** are accepted: guard
/// array elements are 4-byte ints, so the branch-select load always scales the
/// index by 4. Plain `disp(%base)`, RIP-relative operands, and other scales
/// (e.g. the scale-1 AFL map read `(%base,%idx,1)`) return `None`.
fn parse_indexed_operand(insn: &str) -> Option<(i64, String)> {
    let open = insn.find('(')?;
    let close = insn[open..].find(')')? + open;

    let disp_str = insn[..open].rsplit_once(' ').map(|(_, d)| d).unwrap_or("");
    let inner = &insn[open + 1..close];

    // Require "%base,%index,scale" with scale == 4.
    let mut parts = inner.split(',');
    let base = parts.next()?.trim();
    let _index = parts.next()?;
    let scale = parts.next()?.trim();
    if base.is_empty() || base == "%rip" || scale != "4" {
        return None;
    }

    let disp = parse_signed_hex(disp_str.trim());
    Some((disp, base.to_string()))
}

/// Parse a possibly-signed hex displacement such as `0x4`, `-0x4`, or `""` (0).
fn parse_signed_hex(s: &str) -> i64 {
    let (neg, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let digits = digits.strip_prefix("0x").unwrap_or(digits);
    let val = i64::from_str_radix(digits, 16).unwrap_or(0);
    if neg {
        -val
    } else {
        val
    }
}

/// Batch-resolve addresses to source locations using `addr2line`.
/// Returns addr → (canonical_path, line_number).
fn resolve_addrs(binary: &str, addrs: &[u64]) -> HashMap<u64, (String, u32)> {
    if addrs.is_empty() {
        return HashMap::new();
    }

    let hex_addrs: Vec<String> = addrs.iter().map(|a| format!("0x{:x}", a)).collect();

    let out = Command::new("addr2line")
        .arg("-e")
        .arg(binary)
        .args(&hex_addrs)
        .output()
        .expect("addr2line not found — install binutils");

    let text = String::from_utf8_lossy(&out.stdout);
    let mut map = HashMap::new();

    for (addr, location) in addrs.iter().zip(text.lines()) {
        // addr2line output: "/absolute/path/file.c:42" or "??:0"
        if location.starts_with("??") {
            continue;
        }
        if let Some(colon) = location.rfind(':') {
            let file = location[..colon].to_string();
            let line_str = location[colon + 1..].trim();
            if let Ok(lineno) = line_str.parse::<u32>() {
                if lineno > 0 {
                    map.insert(*addr, (file, lineno));
                }
            }
        }
    }

    map
}

/// Look up the source location for a guard's instruction `addr`, falling back to
/// nearby preceding instructions when `addr` itself has no line info.
///
/// The branch-select coverage loads are tagged by the compiler with no source
/// line, so `addr_src` won't contain them. In that case we step backwards through
/// the sorted instruction addresses `all_addrs` — the immediately preceding real
/// code is the branch's condition — trying each until one resolves. The window is
/// bounded so a guard in a genuinely un-lined region is dropped rather than
/// mis-attributed to some distant earlier statement.
fn resolve_with_fallback(
    addr: u64,
    all_addrs: &[u64],
    addr_src: &HashMap<u64, (String, u32)>,
) -> Option<(String, u32)> {
    const WINDOW: usize = 16;

    if let Some(src) = addr_src.get(&addr) {
        return Some(src.clone());
    }

    let pos = all_addrs.binary_search(&addr).ok()?;
    all_addrs[..pos]
        .iter()
        .rev()
        .take(WINDOW)
        .find_map(|a| addr_src.get(a).cloned())
}

/// Build a [`GuardMap`] by statically analysing the binary.
///
/// Requires `nm`, `objdump`, and `addr2line` (binutils).
/// The binary must have been compiled with debug info (`-g`) and
/// AFL PC-guard instrumentation (`afl-clang-fast`).
pub fn build_guard_map(binary: &str) -> Option<GuardMap> {
    let (g_start, g_end) = sancov_bounds(binary)?;

    if g_end <= g_start {
        eprintln!("source_cov: empty __sancov_guards section");
        return None;
    }

    let num_guards = ((g_end - g_start) / 4) as usize;
    eprintln!(
        "source_cov: {} guards at 0x{:x}–0x{:x}",
        num_guards, g_start, g_end
    );

    let (refs, all_addrs) = find_guard_refs(binary, g_start, g_end);
    eprintln!("source_cov: {} coverage guard references found", refs.len());

    // Resolve every instruction address up front. Branch-select guard loads carry
    // no line info of their own (addr2line reports "file:?"), so for those we walk
    // back through `all_addrs` to the nearest preceding instruction that does
    // resolve — the branch's condition line — bounded to a small window.
    let addr_src = resolve_addrs(binary, &all_addrs);

    let guard_to_src: HashMap<usize, (String, u32)> = refs
        .iter()
        .filter_map(|(&idx, &addr)| {
            resolve_with_fallback(addr, &all_addrs, &addr_src).map(|src| (idx, src))
        })
        .collect();

    eprintln!(
        "source_cov: {} guards mapped to source locations",
        guard_to_src.len()
    );

    Some(GuardMap {
        guard_to_src,
        guard_to_addr: refs,
        guards_start_va: g_start,
        guards_end_va: g_end,
    })
}

/// Build a counter-index → source-location map straight from a binary.
///
/// This is the convenience entry point for "given a binary, tell me which
/// source `(file, line)` each coverage-map counter corresponds to". It runs the
/// same static analysis as [`build_guard_map`] and then shifts every guard
/// entry by `first_loc` (the AFL guard base offset) so the resulting keys are
/// indices into the live coverage bitmap.
///
/// `first_loc` is the base at which AFL placed this binary's guards in the map
/// (`slot = guard_index + first_loc`). When it isn't known, build the
/// [`GuardMap`] directly, sample coverage, and recover it with
/// [`GuardMap::detect_first_loc`] before calling [`GuardMap::counter_to_src`].
///
/// Returns `None` if the binary has no usable `__sancov_guards` section (see
/// [`build_guard_map`] for the instrumentation/debug-info requirements).
pub fn build_counter_map(binary: &str, first_loc: usize) -> Option<HashMap<usize, (String, u32)>> {
    Some(build_guard_map(binary)?.counter_to_src(first_loc))
}

/// Print a human-readable coverage report to stdout.
pub fn print_report(files: &[FileCoverage]) {
    for file in files {
        println!(
            "\n=== {} ({}/{} instrumented lines hit) ===\n",
            file.path, file.total_hit, file.total_instrumented
        );

        for line in &file.lines {
            if line.instrumented {
                if line.hit_count > 0 {
                    println!("{:5} | {:>8} | {}", line.line_no, line.hit_count, line.content);
                } else {
                    println!("{:5} |     MISS | {}", line.line_no, line.content);
                }
            } else {
                println!("{:5} |          | {}", line.line_no, line.content);
            }
        }
    }
}

/// Print a human-readable report of branches reached but not taken.
pub fn print_uncovered(branches: &[UncoveredBranch]) {
    if branches.is_empty() {
        println!("\nNo uncovered branches: every instrumented location was hit.");
        return;
    }

    println!(
        "\n=== {} uncovered branch(es) (reached but not taken) ===\n",
        branches.len()
    );
    for b in branches {
        println!(
            "slot {:5} (guard[{:3}])  {}:{}",
            b.slot, b.guard_index, b.file, b.condition_line
        );
        if !b.function_signature.is_empty() {
            println!("    in: {}", b.function_signature);
        }
        match b.negated {
            Some(false) => println!("    check: {}  → condition never true (then branch not taken)\n", b.condition),
            Some(true) => println!("    check: {}  → condition never false (else branch not taken)\n", b.condition),
            None => println!("    at: {}\n", b.condition),
        }
    }
}

/// Serialize uncovered branches to JSON.
pub fn uncovered_to_json(branches: &[UncoveredBranch]) -> String {
    serde_json::to_string_pretty(branches).unwrap_or_else(|_| "[]".to_string())
}

/// Serialize coverage results to a simple JSON structure.
pub fn to_json(files: &[FileCoverage]) -> String {
    let mut out = String::from("[\n");
    for (fi, file) in files.iter().enumerate() {
        out.push_str(&format!("  {{\"file\":\"{}\",\"lines\":[\n", file.path));
        let instrumented: Vec<&CovLine> = file.lines.iter().filter(|l| l.instrumented).collect();
        for (i, line) in instrumented.iter().enumerate() {
            let comma = if i + 1 < instrumented.len() { "," } else { "" };
            out.push_str(&format!(
                "    {{\"line\":{},\"hits\":{}}}{}\n",
                line.line_no, line.hit_count, comma
            ));
        }
        let comma = if fi + 1 < files.len() { "," } else { "" };
        out.push_str(&format!("  ]}}{}\n", comma));
    }
    out.push(']');
    out
}
