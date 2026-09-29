use cure_coverage::coverage::execute_with_coverage_once;
use cure_coverage::source_cov::{
    build_guard_map, print_report, print_uncovered, to_json, uncovered_to_json,
};

fn usage(prog: &str) {
    eprintln!(
        "Usage: {prog} <binary> <command> [OPTIONS]

  binary   Path to AFL-instrumented binary (must have debug info)
  command  Shell command to execute, e.g. './binary arg1 arg2'

Options:
  --map-size N      AFL coverage map size in bytes (default: 65536)
  --first-loc N     Guard base index override (default: auto-detect)
  --source-dir DIR  Directory to search when source paths from debug info don't exist
                    (can be repeated for multiple directories)
  --json            Output JSON instead of text
  --show-all        Show all source lines, not just instrumented ones
  --uncovered       Report branches reached but not taken (counter == 0),
                    with each branch's condition line and enclosing function
  --verbose         Print slot→guard→source mapping for debugging

Example:
  source_map ./target_binary './target_binary 42'
  source_map ./target_binary './target_binary 42' --source-dir ./src --json
"
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        usage(&args[0]);
        std::process::exit(1);
    }

    let binary = &args[1];
    let cmd = &args[2];

    let mut map_size: usize = 65536;
    let mut first_loc_override: Option<usize> = None;
    let mut source_dirs: Vec<String> = Vec::new();
    let mut json_output = false;
    let mut show_all = false;
    let mut uncovered_only = false;
    let mut verbose = false;

    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--map-size" => {
                i += 1;
                map_size = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| {
                        eprintln!("--map-size requires an integer argument");
                        std::process::exit(1);
                    });
            }
            "--first-loc" => {
                i += 1;
                first_loc_override = Some(
                    args.get(i)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or_else(|| {
                            eprintln!("--first-loc requires an integer argument");
                            std::process::exit(1);
                        }),
                );
            }
            "--source-dir" => {
                i += 1;
                match args.get(i) {
                    Some(d) => source_dirs.push(d.clone()),
                    None => {
                        eprintln!("--source-dir requires a path argument");
                        std::process::exit(1);
                    }
                }
            }
            "--json" => json_output = true,
            "--show-all" => show_all = true,
            "--uncovered" => uncovered_only = true,
            "--verbose" => verbose = true,
            other => {
                eprintln!("Unknown option: {}", other);
                usage(&args[0]);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // --- Static analysis: build guard → source map ---
    let guard_map = build_guard_map(binary).unwrap_or_else(|| {
        eprintln!(
            "Failed to build guard map for '{}'. \
             Ensure the binary has debug info (-g) and AFL PC-guard instrumentation.",
            binary
        );
        std::process::exit(1);
    });

    if verbose {
        eprintln!("Guard map:");
        let mut entries: Vec<_> = guard_map.guard_to_src.iter().collect();
        entries.sort_by_key(|(idx, _)| *idx);
        for (idx, (file, line)) in &entries {
            eprintln!("  guard[{:3}] → {}:{}", idx, file, line);
        }
    }

    // --- Dynamic: run binary and collect coverage ---
    eprintln!("Running: {}", cmd);
    let coverage = execute_with_coverage_once(cmd, map_size);

    // Active slots diagnostic
    let active: Vec<(usize, u16)> = coverage
        .iter()
        .enumerate()
        .filter(|(_, &c)| c > 0)
        .map(|(i, &c)| (i, c))
        .collect();
    eprintln!("source_cov: {} active coverage slots: {:?}", active.len(), active);

    // --- Determine first_loc ---
    let first_loc = first_loc_override
        .unwrap_or_else(|| guard_map.detect_first_loc(&coverage, 1));
    eprintln!("source_cov: using first_loc = {}", first_loc);

    if verbose {
        eprintln!("Slot → source mapping with first_loc={}:", first_loc);
        for (slot, count) in &active {
            if *slot < first_loc { continue; }
            let guard_idx = slot - first_loc;
            if let Some((file, line)) = guard_map.guard_to_src.get(&guard_idx) {
                eprintln!("  slot {:4} (guard[{:3}]) count={:4} → {}:{}", slot, guard_idx, count, file, line);
            } else {
                eprintln!("  slot {:4} (guard[{:3}]) count={:4} → (no mapping)", slot, guard_idx, count);
            }
        }
    }

    let source_root_refs: Vec<&str> = source_dirs.iter().map(String::as_str).collect();

    // --- Uncovered-branch report: branches reached but not taken ---
    if uncovered_only {
        let branches = guard_map.uncovered_branches(&coverage, first_loc, &source_root_refs);
        if json_output {
            println!("{}", uncovered_to_json(&branches));
        } else {
            print_uncovered(&branches);
        }
        return;
    }

    // --- Map coverage to source ---
    let mut files = guard_map.apply(&coverage, first_loc, &source_root_refs);

    if files.is_empty() {
        eprintln!(
            "No coverage data could be mapped to source.\n\
             Hint: try --first-loc <N> or --source-dir <path-to-source>"
        );
        std::process::exit(1);
    }

    // Sort for deterministic output
    files.sort_by(|a, b| a.path.cmp(&b.path));

    if !show_all {
        for file in &mut files {
            file.lines.retain(|l| l.instrumented);
        }
    }

    if json_output {
        println!("{}", to_json(&files));
    } else {
        print_report(&files);
    }
}
