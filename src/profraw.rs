use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use regex::Regex;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::{self, File};
use std::io::{Error, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::str::{self};
use std::time::Instant;

use crate::prf_names::FunctionInfo;

/*
Using the existing LLVM Tools is not suitable for extracting coverage information as they take > 1s to extract the info.
This profraw file parser brings down this time to ca. 1ms, allowing coverage info extracting after each iteration.
*/

#[derive(Debug)]
struct FunctionRecord {
    name_ref: u64,
    num_counters: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CoverageType {
    FUNCTIONS,
    COUNTERS,
}

fn read_header(file: &mut File) -> Result<(u64, u64, u64), Error> {
    let magic = file.read_u64::<LittleEndian>();
    if magic.is_err() {
        return Err(magic.err().unwrap());
    }

    let version = file.read_u64::<LittleEndian>().unwrap();
    let mut buffer;
    if version == 8 {
        buffer = vec![0; 8 * 13];
    } else if version == 9 {
        buffer = vec![0; 8 * 14];
    } else {
        // We currently only support profraw version 8 and 9, the most current versions. May need to update in the future
        panic!("Unsupported version");
    }
    file.read_exact(&mut buffer).unwrap();

    let data_size = as_u64_le(&buffer[8..16]);

    let counter_size = as_u64_le(&buffer[24..32]);

    return Ok((version, data_size, counter_size));
}

fn read_counters(file: &mut File, num_counters: u64) -> Result<Vec<u64>, Error> {
    let mut buffer = vec![0; 8 * num_counters as usize];
    file.read_exact(&mut buffer)?;

    let counters: Vec<u64> = buffer.chunks_exact(8).map(|chunk| LittleEndian::read_u64(chunk)).collect();

    Ok(counters)
}

fn as_u32_be(array: &[u8]) -> u32 {
    ((array[0] as u32) << 24) + ((array[1] as u32) << 16) + ((array[2] as u32) << 8) + ((array[3] as u32) << 0)
}

fn as_u64_be(array: &[u8]) -> u64 {
    ((array[0] as u64) << 56)
        + ((array[1] as u64) << 48)
        + ((array[2] as u64) << 40)
        + ((array[3] as u64) << 32)
        + ((array[4] as u64) << 24)
        + ((array[5] as u64) << 16)
        + ((array[6] as u64) << 8)
        + ((array[7] as u64) << 0)
}

fn as_u32_le(array: &[u8]) -> u32 {
    ((array[3] as u32) << 24) + ((array[2] as u32) << 16) + ((array[1] as u32) << 8) + ((array[0] as u32) << 0)
}

fn as_u64_le(array: &[u8]) -> u64 {
    ((array[7] as u64) << 56)
        + ((array[6] as u64) << 48)
        + ((array[5] as u64) << 40)
        + ((array[4] as u64) << 32)
        + ((array[3] as u64) << 24)
        + ((array[2] as u64) << 16)
        + ((array[1] as u64) << 8)
        + ((array[0] as u64) << 0)
}

fn read_function_records(file: &mut File, num_data: u64, version: u64) -> Result<Vec<FunctionRecord>, Error> {
    let mut function_records = Vec::with_capacity(num_data.try_into().unwrap());

    let record_size = if version == 9 { 64 } else { 48 };
    let total_size = record_size * num_data;
    let mut buffer = vec![0u8; total_size.try_into().unwrap()];
    file.read_exact(&mut buffer)?;

    let counter_offset = if version == 9 { 48 } else { 40 };
    for i in 0..num_data {
        let fr = FunctionRecord {
            name_ref: as_u64_le(&buffer[(i * record_size) as usize..(i * record_size + 8) as usize]),
            // func_hash: as_u64_le(
            //     &buffer[(i * record_size + 8) as usize..(i * record_size + 16) as usize],
            // ),
            // counter_ref: as_u64_le(
            //     &buffer[(i * record_size + 16) as usize..(i * record_size + 24) as usize],
            // ),
            // func_ref: as_u64_le(
            //     &buffer[(i * record_size + 24) as usize..(i * record_size + 32) as usize],
            // ),
            // value_exp: as_u64_le(
            //     &buffer[(i * record_size + 32) as usize..(i * record_size + 40) as usize],
            // ),
            num_counters: as_u32_le(&buffer[(i * record_size + counter_offset) as usize..(i * record_size + counter_offset + 4) as usize]),
            // init_arr: as_u32_le(
            //     &buffer[(i * record_size + counter_offset + 4) as usize
            //         ..(i * record_size + counter_offset + 8) as usize],
            // ),
        };

        function_records.push(fr);
    }

    Ok(function_records)
}

fn get_indic_function_value(filename: &str, ids: &Option<Vec<usize>>) -> Vec<u64> {
    if ids.is_some() {
        let ids = ids.clone().unwrap();
        return get_counters_value(filename, ids);
    }
    return vec![];
}

/*
Base Counters: The counters that have already been read and should be skipped

*/
pub fn generate_continous_coverage_report(
    filenames: Vec<String>,
    function_names: &HashMap<String, FunctionInfo>,
    base_counters: Option<&Vec<usize>>,
    function_id_ids: Option<Vec<usize>>,
    covtyp: &CoverageType,
) -> (Vec<(usize, f64, f64, Vec<String>)>, Vec<usize>, Vec<Vec<u64>>) {
    if filenames.is_empty() {
        return (vec![], vec![], vec![]);
    }

    let mut ret = Vec::with_capacity(filenames.len());

    let mut ret_counters = vec![];

    let mut newer_counters = base_counters.unwrap_or(&vec![]).clone();

    let file1 = filenames.get(0).unwrap();
    let refsize = fs::metadata(file1).unwrap().size();
    let mut ind_func_values = Vec::with_capacity(filenames.len());

    for i in 0..filenames.len() {
        let counters = match newer_counters.len() > 0 {
            true => Some(&newer_counters),
            false => None,
        };

        let fname = &filenames[i];
        let size = fs::metadata(fname).unwrap().size();

        // This can happen if writing of the file was not finished in the last iteration -> To prevent reading incomplete files, we skip these
        if size != refsize {
            ind_func_values.push(vec![0]);

            continue;
        }
        let (cov_ex, ex_counter_len, names, new_counters, _) = read_all_counters(&filenames[i], function_names, counters, None, &covtyp);

        // This indicates a non-complete file.
        let ind_f_val = get_indic_function_value(&filenames[i], &function_id_ids);
        if ind_f_val.len() > 0 && ind_f_val[0] > 100000 {
            ind_func_values.push(vec![0]);
            continue;
        }
        ind_func_values.push(ind_f_val);

        // Check if anything new was discovered, if not -> continue
        if ex_counter_len == 0 {
            continue;
        }
        ret_counters.extend(new_counters.clone());
        newer_counters.extend(new_counters);

        newer_counters.sort();

        ret.push((i, cov_ex, ex_counter_len as f64, names));
    }

    (ret, ret_counters, ind_func_values)
}

pub fn print_cov_evolution(folder_uri: &str, function_names: &HashMap<String, FunctionInfo>) {
    let filenames = get_cov_filenames(folder_uri);
    let ret = generate_continous_coverage_report(filenames, function_names, None, None, &CoverageType::FUNCTIONS);
    let mut i = 0;
    let mut next_v = 0;

    loop {
        if i == ret.0[next_v].0 {
            next_v += 1;
            if next_v == ret.0.len() {
                break;
            }
        }
        i += 1;
    }
}

pub fn get_cov_filenames(folder_uri: &str) -> Vec<String> {
    let mut filenames: Vec<_> = fs::read_dir(folder_uri)
        .expect("Directory not found.")
        .filter_map(|entry| entry.ok())
        .filter_map(|e| {
            e.path()
                .file_name()
                .and_then(|n| n.to_str()) // Convert OsStr to &str
                .map(|s| s.to_string())
        }) // Convert &str to String
        .collect();

    // Sort filenames based on their numeric value
    filenames.sort_by(|a, b| {
        let a_num: i32 = a.split('.').next().unwrap().parse().unwrap();
        let b_num: i32 = b.split('.').next().unwrap().parse().unwrap();
        a_num.cmp(&b_num)
    });

    let mut ret = Vec::with_capacity(filenames.len());
    for f in filenames {
        let mut s = folder_uri.to_string();
        s.push_str(&f);
        ret.push(s);
    }
    return ret;
}

pub fn read_function_counters_folder(
    folder_uri: &str,
    function_names: &HashMap<String, FunctionInfo>,
    covtyp: CoverageType,
) -> Option<(f64, usize, Vec<String>, Vec<usize>)> {
    let filenames = get_cov_filenames(folder_uri);
    let newest_safe_element = filenames[filenames.len() - 2].clone();
    let r = read_all_counters(
        &(folder_uri.to_string() + &newest_safe_element),
        function_names,
        None,
        None,
        &covtyp,
    );
    let r = match r {
        (a, b, c, d, _) => Some((a, b, c, d)),
    };
    return r;
}

pub fn remove_hashes(input: &str) -> String {
    // Define a regex pattern that matches [16-character hex hash]
    let re = Regex::new(r"\[[0-9a-fA-F]{16}\]").unwrap();
    re.replace_all(input, "").to_string()
}

pub fn get_counter_value(filename: &str, counter_index: usize) -> u64 {
    let mut file = File::open(filename).unwrap();

    let (version, data_size, counters_size) = read_header(&mut file).unwrap();

    read_function_records(&mut file, data_size, version).unwrap();
    let counters = read_counters(&mut file, counters_size).unwrap();
    return counters[counter_index];
}

pub fn get_counters_value(filename: &str, counter_indeces: Vec<usize>) -> Vec<u64> {
    let mut file = File::open(filename).unwrap();

    let (version, data_size, counters_size) = read_header(&mut file).unwrap();

    read_function_records(&mut file, data_size, version).unwrap();
    let counters = read_counters(&mut file, counters_size).unwrap();

    let mut ret = vec![];
    for v in counter_indeces {
        ret.push(counters[v]);
    }
    return ret;
}

pub fn find_counters_by_name(filename: &str, func_names: &HashMap<String, FunctionInfo>, names: Vec<String>) -> Vec<usize> {
    let mut file = File::open(filename).unwrap();

    let (version, data_size, counters_size) = read_header(&mut file).unwrap();

    let function_records = read_function_records(&mut file, data_size, version).unwrap();
    let counters = read_counters(&mut file, counters_size).unwrap();

    let mut current_counter_index: usize = 0;
    let mut ret = vec![];

    // Find which function was executed by checking each functions' counters
    for r in 0..function_records.len() {
        let counter_amount = function_records[r].num_counters;
        if counter_amount > 0 {
            let a = format!("{:016x?}", function_records[r].name_ref);
            match func_names.get(&a) {
                Some(func) => {
                    // Use a reference to avoid cloning the full name for the vector
                    let cleaned_name = remove_hashes(&func.full_name);
                    if names.contains(&cleaned_name) {
                        for c in 0..counter_amount {
                            // Ensure we do not go out of bounds
                            if current_counter_index >= counters.len() {
                                break;
                            }

                            let function_execution_count = counters[current_counter_index];
                            if function_execution_count > 0 {
                                ret.push(current_counter_index);
                                current_counter_index += (counter_amount - c) as usize;

                                break;
                            }
                            current_counter_index += 1;
                        }
                    } else {
                        current_counter_index += counter_amount as usize;
                        continue;
                    }
                }
                None => {
                    current_counter_index += counter_amount as usize;
                }
            }
        }
    }

    return ret;
}

pub fn find_names_by_counters(filename: &str, func_names: &HashMap<String, FunctionInfo>, searched_counters: &Vec<usize>) -> Vec<String> {
    let mut file = File::open(filename).unwrap();

    let (version, data_size, counters_size) = read_header(&mut file).unwrap();

    let function_records = read_function_records(&mut file, data_size, version).unwrap();
    read_counters(&mut file, counters_size).unwrap();

    let mut current_counter_index: usize = 0;
    let mut executed_fs = vec![];

    // Find which function was executed by checking each functions' counters
    for r in 0..function_records.len() {
        let counter_amount = function_records[r].num_counters;

        if counter_amount > 0 {
            for c in 0..counter_amount {
                if searched_counters.contains(&current_counter_index) {
                    executed_fs.push(format!("{:016x?}", function_records[r].name_ref));
                }
                current_counter_index += 1;
            }
        }
    }

    let mut ret = vec![];
    for v in executed_fs {
        match func_names.get(&v) {
            Some(func) => {
                // Use a reference to avoid cloning the full name for the vector
                let cleaned_name = remove_hashes(&func.full_name);
                ret.push(cleaned_name.clone());
            }
            None => {
                println!("NOT FOUND1");
            }
        }
    }

    return ret;
}

/*
Read function counter records from Profraw File.
@filename: The filename of the Profraw file
@func_names: A hashmap of function names and their corresponding FunctionInfo
@skip_counters: A vector of counters to skip (optional) -> Useful for skipping counters that have already been read to safe time
@counters_of_interest: Counters of interest give the indices of counters where the amount should be tracked. If you want to track all, provide Some(vec![])
*/
pub fn read_all_counters(
    filename: &str,
    func_names: &HashMap<String, FunctionInfo>,
    skip_counters: Option<&Vec<usize>>,
    counters_of_interest: Option<Vec<usize>>,
    covtyp: &CoverageType,
) -> (f64, usize, Vec<String>, Vec<usize>, HashMap<String, u64>) {
    // let DEBUG = with_counts;

    let coi = match counters_of_interest.clone() {
        Some(v) => v,
        None => vec![],
    };
    let track_all_counters = counters_of_interest.is_some() && coi.len() == 0;

    let ve = vec![9999999999999999999];
    let skip_counters = match skip_counters {
        Some(v) => v,
        None => &ve,
    };

    let mut file = File::open(filename).unwrap();

    let (version, data_size, counters_size) = read_header(&mut file).unwrap();

    let function_records = read_function_records(&mut file, data_size, version);
    if function_records.is_err() {
        return (0.0, 0, vec![], vec![], HashMap::new());
    }
    let function_records = function_records.unwrap();

    let counters = read_counters(&mut file, counters_size);
    if counters.is_err() {
        return (0.0, 0, vec![], vec![], HashMap::new());
    }
    let counters = counters.unwrap();

    let mut current_counter_index: usize = 0;
    let mut executed_fs = Vec::with_capacity(counters.len() / 2);
    let mut executed_counters = Vec::with_capacity(counters.len());
    let mut skipped_counters = 0;

    let mut execution_counts = HashMap::new();

    let mut current_skip_index = 0;

    // Find which function was executed by checking each functions' counters
    for r in 0..function_records.len() {
        let counter_amount = function_records[r].num_counters;
        if counter_amount > 0 {
            for c in 0..counter_amount {
                // Ensure we do not go out of bounds
                if current_counter_index >= counters.len() {
                    break;
                }

                if current_skip_index < skip_counters.len() && current_counter_index == skip_counters[current_skip_index] {
                    if counters[current_counter_index] > 0 {
                        skipped_counters += 1;
                    }
                    current_skip_index += 1;
                    if covtyp == &CoverageType::FUNCTIONS {
                        current_counter_index += (counter_amount - c) as usize;
                        break;
                    } else {
                        current_counter_index += 1;
                        continue;
                    }
                }

                let function_execution_count = counters[current_counter_index];
                if function_execution_count > 0 {
                    if covtyp == &CoverageType::FUNCTIONS {
                        // Convert to hex value, pad with leading 0s to ensure its 16 characters long
                        let a = format!("{:016x?}", function_records[r].name_ref);

                        // If this counter should be tracked, add its execution count
                        if track_all_counters || coi.len() > 0 {
                            if track_all_counters || coi.contains(&current_counter_index) {
                                execution_counts.insert(a.clone(), function_execution_count);
                            }
                        }
                        executed_fs.push(a);

                        // Subtracting c to ensure the beginning of the function is added as a counter -> This prevents problems if a later part of a function is discovered earlier, which would otherwise confuse the algorithm
                        executed_counters.push(current_counter_index - c as usize);
                        current_counter_index += (counter_amount - c) as usize;

                        break;
                    } else {
                        executed_counters.push(current_counter_index as usize);
                        current_counter_index += 1;

                        continue;
                    }
                }
                current_counter_index += 1;
            }
        }
    }

    let mut executed_functions = Vec::with_capacity(executed_fs.len());
    let mut executed_functions_wc = HashMap::new();

    let mut current_insert = 0;

    if covtyp == &CoverageType::FUNCTIONS {
        // Map each executed function to its full name
        for v in executed_fs {
            match func_names.get(&v) {
                Some(func) => {
                    // Use a reference to avoid cloning the full name for the vector
                    let cleaned_name = remove_hashes(&func.full_name);
                    executed_functions.insert(current_insert, cleaned_name.clone());
                    current_insert += 1;
                }
                None => {}
            }
        }
        // Do this seperately to safe time -> Usually we will only have a small number of functions that are tracked
        if execution_counts.len() > 0 {
            for v in execution_counts.iter() {
                let cleaned_name = remove_hashes(&func_names.get(v.0).unwrap().full_name);
                executed_functions_wc.insert(cleaned_name, *v.1);
            }
        }
    }

    drop(file);

    return (
        skipped_counters as f64,
        executed_counters.len(),
        executed_functions,
        executed_counters,
        executed_functions_wc,
    );
}
