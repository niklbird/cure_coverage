# cure_coverage

![Rust](https://img.shields.io/badge/language-Rust-orange.svg) 
![License](https://img.shields.io/badge/license-MIT-blue.svg)

`cure_coverage` is a Rust library designed to extract coverage information from a binary instrumented with [AFL++](https://github.com/AFLplusplus/AFLplusplus) through shared memory mapped counters. It enables users to efficiently obtain branch coverage, which can be utilized for fuzzing purposes.

Note: This library is part of the CURE RPKI Toolchain.

## Features
✅ Extract accurate branch coverage from AFL++ instrumented binaries (16 bit counters for accurate readings)

✅ Progressive coverage mapping for efficient tracking

✅ Simple interfaces for easy integration into fuzzing workflows

## Installation
Add `cure_coverage` to your `Cargo.toml`:

```toml
[dependencies]
cure_coverage = "0.1"
```

## Usage

To run a binary with coverage, use the `read_coverage` function. It returns the counter map with exact (16 bit) counter values

```rust
use cure_coverage::coverage;

let cmd = "./target_binary";
let map_size = 65536; // Set appropriate map size for AFL++
let coverage_info = coverage::execute_with_coverage(cmd, map_size);
```

### Progressive Coverage Mapping
The library supports progressive coverage tracking, allowing users to continuously monitor new coverage information while minimizing redundant data.

## Example
Here’s a complete example demonstrating how to use cure_coverage together with Identification Functions:

```rust
use cure_coverage::coverage;

fn main() {
    let batch_sizes = [11, 33, 55, 77];
    let cmd = "./target_binary";
    let map_size = 65536; // Set appropriate map size for AFL++
    let mut candidates = HashSet::new();

    for (i, batch_size) in batch_sizes.iter().enumerate() {
        setup(batch_size) // Your own setup code to create a batch of size i
        let potential_ifs = coverage::find_candidates(cmd, batch_size, map_size)
        
        if i == 0 {
            candidates = HashSet::from_iter(potential_ifs);
        } else {
            candidates = candidates
                .intersection(&HashSet::from_iter(potential_ifs))
                .cloned()
                .collect();
        }
    }

    setup(99);
    let (ifs, max_val) = coverage::reduce_candidates(cmd, candidates, map_size);

    //.... fuzzer code
    setup_fuzzing_testcase_batch();
    let zero_wrap = false; // For C and Rust
    let mut known_counters = HashSet::new();

    (coverage_result, new_known_counters, crashed) = coverage::track_coverage(cmd, &ifs, known_counters, max_val, map_size, zero_wrap);
    known_counters.extend(new_known_counters);

    // Coverage result is a Vec of (object index in batch, how many new edges it found), only listing objects that found new coverage, all others are not included
}
```

## Build & Test
To build the project:
```sh
cargo build --release
```

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributions
Contributions are welcome! Please open an issue or submit a pull request if you’d like to improve `cure_coverage`.

## Contact
For questions or discussions, feel free to open an issue on [GitHub](https://github.com/niklbird/cure_coverage).

