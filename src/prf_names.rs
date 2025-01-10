use object::{Object, ObjectSection};
use rustc_demangle::demangle;
use std::{collections::HashMap, fs, io::Read, str::from_utf8};

// Get the length of the length field itself
fn get_size_len(data: &[u8]) -> (usize, usize) {
    let mut i = 0;
    let mut uncom_size = true;
    let mut loc_com_len = 0;
    while data[i] >= 128 || uncom_size {
        if data[i] < 128 {
            uncom_size = false;
            loc_com_len = i;
        }
        i += 1;
    }
    // Return value after second time MSF was not 0
    (i + 1, loc_com_len + 1)
}

// Get size of an unencrypted section
fn get_size_unenc(data: &[u8]) -> (u64, usize) {
    let mut sizes = vec![];
    let mut cur_ind = 0;
    loop {
        // MSB is just there to indiciate if there comes more data -> Remove it with modulo
        let val = data[cur_ind];
        let v = val % 128;
        cur_ind += 1;
        sizes.push(v);
        if val < 128 as u8 {
            break;
        }
    }

    let mut total = 0;
    for (i, v) in sizes.iter().enumerate() {
        total += (*v as u64) * 2u64.pow((i * 7) as u32);
    }
    total += get_size_len(data).0 as u64;
    (total, sizes.len())
}

fn get_size_enc(data: &[u8]) -> u64 {
    let start_loc = get_size_len(&data).1;
    let cur = data[start_loc..].to_vec();
    let s = get_size_unenc(&cur).0;
    s
}

fn decompress(data: &[u8]) -> Vec<String> {
    let mut decompressed = vec![];

    // If the comp-len is 0, the data is not compressed
    if data[get_size_len(data).1] == 0 {
        let mut cur_data = data.to_vec();
        loop {
            // The data is separated by files -> Process one file at a time
            let size = get_size_unenc(&cur_data).0 as usize;
            let frag = cur_data[get_size_len(&cur_data).0..size].to_vec();

            decompressed.push(from_utf8(&frag).unwrap().to_string());

            cur_data = cur_data[size..].to_vec();
            if cur_data.len() < 2 {
                break;
            }
        }

        return decompressed;
    } else {
        println!("Info: Data is zLib compressed");

        let mut cur_data = data.to_vec();
        loop {
            // The data is separated by files -> Process one file at a time
            let size = get_size_enc(&cur_data) as usize;
            let frag = cur_data[get_size_len(&cur_data).0..size + 1].to_vec();

            let mut d = flate2::read::ZlibDecoder::new(&frag[..]);
            let mut s = String::with_capacity(frag.len());
            d.read_to_string(&mut s).unwrap();
            decompressed.push(s);

            cur_data = cur_data[size..].to_vec();
            if cur_data.len() < 2 {
                break;
            }
        }

        return decompressed;
    }
}

fn change_endian(data: String) -> String {
    let mut ret = String::with_capacity(data.len());
    for i in (0..data.len() - 1).step_by(2) {
        ret += &data.chars().nth(i + 1).unwrap().to_string();
        ret += &data.chars().nth(i).unwrap().to_string();
    }

    ret
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct FunctionInfo {
    pub base_name: String,
    pub base_crate: String,
    pub function_part: String,
    pub function_name: String,
    pub full_name: String,
    pub file_id: u32,
    pub is_closure: bool,
    pub is_trade_implementation: bool,
}

fn find_base_name(input: &str) -> String {
    let mut open_brackets = 0;
    if input.is_empty() {
        return input.to_string();
    }
    if input.chars().nth(0).unwrap() != '<' {
        return input.to_string();
    }

    for i in 0..input.len() {
        if input.chars().nth(i).unwrap() == '<' {
            open_brackets += 1;
        }
        if input.chars().nth(i).unwrap() == '>' {
            open_brackets -= 1;
        }
        if open_brackets == 0 {
            return input[1..i].to_string();
        }
    }
    return input.to_string();
}

pub fn remove_hash(input: &str) -> String {
    if input.contains("[") {
        return input
            .split("[")
            .collect::<Vec<&str>>()
            .first()
            .unwrap()
            .to_string();
    }
    return input.to_string();
}

fn clean_base(input: &str) -> String {
    let mut ret = input.to_string();
    ret = ret.replace("<", "");
    ret = ret.replace("&mut ", "");
    ret = ret.replace("&", "");

    ret
}

fn parse_demangled_string(input: &str, file_id: u32) -> FunctionInfo {
    let base_name = find_base_name(input);

    let base_crate;
    let is_trade_implementation;

    let split_name = base_name.split("::").collect::<Vec<&str>>();
    if split_name.first().unwrap().contains(" as ") {
        let base_crate_raw = split_name.last().unwrap().to_string();
        base_crate = clean_base(&remove_hash(
            base_crate_raw
                .split("::")
                .collect::<Vec<&str>>()
                .first()
                .unwrap_or(&""),
        ));

        is_trade_implementation = true;
    } else {
        base_crate = clean_base(&remove_hash(split_name.first().unwrap_or(&"")));
        is_trade_implementation = false;
    }
    let function_part;
    if input.len() > base_name.len() + 2 {
        function_part = input[base_name.len() + 2..].to_string();
    } else {
        function_part = "".to_string();
    }
    let fc = function_part.clone();
    let s = function_part.split("::").collect::<Vec<&str>>();
    let function_name = if s.len() > 1 { s[1] } else { "" };
    let is_closure = input.contains("closure#");
    let demang = FunctionInfo {
        base_name,
        base_crate,
        function_part: fc,
        function_name: function_name.to_string(),
        full_name: input.to_string(),
        is_closure,
        is_trade_implementation,
        file_id,
    };
    demang
}

// Functions in LLVM are identified by part of the MD5 hash of their name
fn get_identification_hash(val: &str) -> String {
    let hash = md5::compute(&val.as_bytes());
    let val = hash.to_vec();
    let val = hex::encode(val);
    let val = change_endian(val);
    let val = val.chars().rev().collect::<String>();
    let val = val[val.len() / 2..].to_string();
    val
}

// Read the name of all functions from the __llvm_prf_names section
pub fn get_function_names(data: &[u8]) -> HashMap<String, FunctionInfo> {
    let obj_file = object::File::parse(&*data).expect("Failed to parse binary");

    let s = obj_file.section_by_name("__llvm_prf_names").unwrap();
    let data = s.data().unwrap();

    let decompressed_data = decompress(data);

    let mut map = HashMap::new();
    let placeholder = "\u{1}";

    for i in 0..decompressed_data.len() {
        let v = &decompressed_data[i];
        let vals = v.split(&placeholder).collect::<Vec<&str>>().clone();

        for k in vals {
            let hash = get_identification_hash(k);

            let demangled_name = demangle(k).to_string();
            let obj = parse_demangled_string(&demangled_name, i as u32);

            map.insert(hash, obj);
        }
    }
    // println!("Info: Found {} Files", decompressed_data.len());
    // println!("Info: Found {} Functions", map.len());
    map
}
