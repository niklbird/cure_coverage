# cure_coverage

![Rust](https://img.shields.io/badge/language-Rust-orange.svg) 
![License](https://img.shields.io/badge/license-MIT-blue.svg)

`cure_coverage` is a Rust library designed to extract coverage information from a binary instrumented with [AFL++](https://github.com/AFLplusplus/AFLplusplus) through shared memory mapped counters. It enables users to efficiently obtain branch coverage, which can be utilized for fuzzing purposes.

Note: This library is part of the CURE RPKI Toolchain.

## Features
✅ Extract branch coverage from AFL++ instrumented binaries

✅ Progressive coverage mapping for efficient tracking

✅ Simple API for easy integration into fuzzing workflows

## Installation
Add `cure_coverage` to your `Cargo.toml`:

```toml
[dependencies]
cure_coverage = "0.1"
```

## Usage

To extract coverage information, use the `read_coverage` function:

```rust
use cure_coverage::coverage;

let cmd = "./target_binary";
let map_size = 65536; // Set appropriate map size for AFL++
let coverage_info = coverage::read_coverage(cmd, map_size);
```

### Progressive Coverage Mapping
The library supports progressive coverage tracking, allowing users to continuously monitor new coverage information while minimizing redundant data.

## Example
Here’s a complete example demonstrating how to read coverage data:

```rust
use cure_coverage::coverage;

fn main() {
    let cmd = "./test_binary";
    let map_size = 65536;
    
    let coverage_info = coverage::read_coverage(cmd, map_size);
    println!("Coverage data: {:?}", coverage_info);
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
For questions or discussions, feel free to open an issue on [GitHub](https://github.com/yourusername/cure_coverage).

