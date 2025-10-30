use std::{collections::HashSet, fs, io, process::{Command, Output}};
use crate::coverage;
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CoverageFactory{
    pub map_size: usize,
    pub max_val: usize,
    pub indicators: Vec<usize>,
    pub known_counters: HashSet<usize>,
    pub zero_wrap: bool // Does value wrap to zero (yes for Rust, no for C / C++)
}

impl CoverageFactory{
    pub fn execute_coverage(&mut self, cmd: &str) -> (Vec<(u16, usize)>, bool){
    
        let (cov_res, new_known, crashed) = coverage::track_coverage(cmd, &self.indicators, &self.known_counters, self.max_val, self.map_size, self.zero_wrap);
        self.known_counters.extend(new_known);

        println!("Total coverage {}/{}", self.known_counters.len(), self.max_val);
    
        (cov_res, crashed)
    }

    pub fn new_empty() -> CoverageFactory{
        CoverageFactory{
            map_size: 0,
            max_val: 0,
            indicators: vec![],
            known_counters: HashSet::new(),
            zero_wrap: false
        }
    }
}


#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct BinaryRunner{
    pub fac: CoverageFactory,
    pub cmd: String,
    pub bin_hash: String,
    pub name: String,
    pub coverage: bool,
    pub working_folders: Vec<String>, // Folders to create / clear before execution
    pub working_files: Vec<String>, // Files to delete before execution
}

impl BinaryRunner{
    pub fn execute_bin(&mut self) -> (Vec<(u16, usize)>, bool){
        for folder in &self.working_folders{
            remove_folder_content(&folder);
            fs::create_dir_all(folder).unwrap_or_default();
        }

        for file in &self.working_files{
            fs::remove_file(file).unwrap_or_default();
        }

        if !self.coverage {
            self.run_cmd().unwrap();
            return (vec![(0,1)], false)
        }
        else{
            return self.fac.execute_coverage(&self.cmd);
        }
    }

    pub fn run_cmd(&self) -> io::Result<Output>{
        Command::new("sh")
        .arg("-c")
        .arg(&self.cmd)
        .output()
    }
}

pub fn remove_folder_content(folder: &str) {
    let paths = fs::read_dir(folder);
    if paths.is_err() {
        return;
    }
    let paths = paths.unwrap();
    for path in paths {
        let p = path.unwrap().path();
        if p.is_file() {
            fs::remove_file(p).unwrap_or_default();
        } else {
            let v = p.to_str();
            if v.is_none() {
                continue;
            }
            remove_folder_content(v.unwrap());
            
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct CoverageList{
    pub name: String,
    pub coverage_list: Vec<(u16, usize)>
}