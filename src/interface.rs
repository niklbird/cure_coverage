use std::{collections::HashMap, fs};

use crate::{
    prf_names::{self, FunctionInfo},
    profraw::{self, generate_continous_coverage_report, get_cov_filenames, CoverageType},
};

pub fn get_function_names(file_uri_binary: &str) -> HashMap<String, FunctionInfo> {
    let binary_data = fs::read(file_uri_binary);
    if binary_data.is_err() {
        println!("Failed to read file: {}", file_uri_binary);
        return HashMap::new();
    }
    let binary_data = binary_data.unwrap();
    prf_names::get_function_names(&binary_data)
}

pub fn get_executed_functions(
    file_uri_profraw: &str,
    function_names: &HashMap<String, FunctionInfo>,
    interesting_counters: Option<Vec<usize>>,
    covtyp: CoverageType,
) -> (f64, usize, Vec<String>, Vec<usize>, HashMap<String, u64>) {
    profraw::read_all_counters(file_uri_profraw, function_names, None, interesting_counters, &covtyp)
}

pub fn get_coverage(
    binary_location: &str,
    profraw_location: &str,
) -> (f64, usize, Vec<std::string::String>, Vec<usize>, HashMap<std::string::String, u64>) {
    let function_names = get_function_names(binary_location);
    profraw::read_all_counters(profraw_location, &function_names, None, None, &CoverageType::FUNCTIONS)
}

pub fn get_progressive_coverage(
    folder_uri: &str,
    function_names: &HashMap<String, FunctionInfo>,
    base_counters: Option<&Vec<usize>>,
    id_functions: Option<Vec<usize>>,
    covtyp: &CoverageType,
) -> (Vec<(usize, f64, f64, Vec<String>)>, Vec<usize>, Vec<Vec<u64>>) {
    // You can already supply the base counters to skip to speed up parsing

    let filenames = get_cov_filenames(folder_uri);
    if filenames.len() == 0 {
        return (Vec::new(), Vec::new(), Vec::new());
    }

    let ret = generate_continous_coverage_report(filenames, function_names, base_counters, id_functions, covtyp);
    ret
}
