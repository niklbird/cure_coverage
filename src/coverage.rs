use std::{
    cmp::max, collections::{HashMap, HashSet}, env, process::Command, ptr, thread::{self}, time::Duration
};
use libc::{shmat, shmctl, shmget, shmdt, IPC_CREAT, IPC_RMID};
use smallvec::SmallVec;


/// Setup shared memory segment. Signal this to target binary over env variable.
/// @param map_size: Size of the shared memory map
fn setup(map_size: usize) -> Option<( *mut u8, i32)>{
    let shm_id = unsafe { shmget(0, map_size, IPC_CREAT | 0o600) };

    if shm_id < 0 {
        eprintln!("Failed to create shared memory!");
        return None;
    }

    // Step 2: Attach shared memory
    let shm_addr = unsafe { shmat(shm_id, ptr::null_mut(), 0) } as *mut u8;
    if shm_addr.is_null() {
        eprintln!("Failed to attach shared memory!");
        return None;
    }

    // Step 3: Set AFL_SHM_ID for target binary
    env::set_var("AFL_SHM_ID", shm_id.to_string());
    env::set_var("__AFL_SHM_ID", shm_id.to_string()); // Some builds use this
    env::set_var("AFL_MAP_SIZE", map_size.to_string());

    Some((shm_addr, shm_id))
}

/// Clean up shared memory after execution.
fn cleanup(shm_addr: *mut u8, shm_id: i32){
    unsafe { shmdt(shm_addr as *const libc::c_void) };
    unsafe { shmctl(shm_id, IPC_RMID, ptr::null_mut()) };

}



/// Read coverage counter values from shared Memory.
/// @param cmd: The command to run the target binary
/// @param map_size: The size of the shared memory map
pub fn read_coverage(cmd: &str, map_size: usize) -> Vec<u16>{
    let shm_addr_o = setup(map_size);
    if shm_addr_o.is_none(){
        return vec![];
    }

    let (shm_addr, shm_id) = shm_addr_o.unwrap();

    let mut child = Command::new("sh").arg("-c").arg(cmd)
        .spawn()
        .expect("Failed to start target binary");

    let mut prev_coverage = vec![0u16; map_size];
    let mut actual_coverage = vec![0u16; map_size];

    loop {
        for i in 0..map_size {            
            let hit_count = unsafe { *shm_addr.add(i) };
            
            if hit_count == 0{
                continue;
            }

            let (abs, wrapped) = abs_from(prev_coverage[i], hit_count);

            prev_coverage[i] += abs as u16;
            actual_coverage[i] += abs as u16;

            if wrapped{
                actual_coverage[i] -= 1; // LLVM wraps from 255 -> 1 not 0, so need to subtract 1 after wrapping
            }
    
            
        }

        if let Ok(status) = child.try_wait() {
            if status.is_some() {
                break;
            }
        }

    }
    cleanup(shm_addr, shm_id);

    return actual_coverage;
}


/// Takes a list of candidates for Indication Functions.
/// Removes all candidates that indicate the same location in the Code.
pub fn reduce_candidates(cmd: &str, candidates: HashSet<usize>, map_size: usize) -> (Vec<usize>, usize){
    let shm_addr_o = setup(map_size);
    if shm_addr_o.is_none(){
        return (vec![], 0);
    }

    let (shm_addr, shm_id) = shm_addr_o.unwrap();

    let mut child = Command::new("sh").arg("-c").arg(cmd)
        .spawn()
        .expect("Failed to start target binary");
    let mut candidate_performance: HashMap<usize, (usize, usize, u16)>    = HashMap::new();

    let mut prev_coverage = vec![0u16; map_size];

    let mut current_count = 0;
    loop {
        for &i in candidates.iter() {
            let hit_count = unsafe { *shm_addr.add(i) };

            let (abs, wrapped) = abs_from(prev_coverage[i], hit_count);
        
            if abs > 0 {
                let entry = candidate_performance.entry(i).or_insert((current_count, current_count, prev_coverage[i]));
                entry.1 = current_count;
                entry.2 += abs as u16;
                if wrapped{
                    entry.2 -= 1;
                }
            }
            prev_coverage[i] += abs as u16;
        }


        if let Ok(status) = child.try_wait() {
            if status.is_some() {
                break;
            }
        }

        current_count += 1;
    }


    let mut final_candidates = vec![];
    let mut cands = HashSet::new();
    for can in candidate_performance.keys(){
        let val = candidate_performance.get(can).unwrap();
        if cands.contains(val){
            continue;
        }
        final_candidates.push(*can);
        cands.insert(val);
        
    }

    let mut largest = 0;
    for i in 0..map_size{
        let hit_count = unsafe { *shm_addr.add(i) };

        if hit_count > 0{
            largest = i;
        }
    }

    cleanup(shm_addr, shm_id);

    (final_candidates, largest)
}



/// Specifically for Fuzzing. Identifies Identification Functions by running on a state with **amount** Objects
/// of a given Type. E.g. create a state with 1000 ROAs, and run this function. It will give back all counters that have an exact value of 1000.
/// @param cmd: Command to run
/// @param amount: Amount of Objects (Searches for counters with this value)
/// @param map_size: Size of shared memory
pub fn find_candidates(cmd: &str, amount: u8, map_size: usize) -> Vec<usize>{
    let shm_addr_o = setup(map_size);
    if shm_addr_o.is_none(){
        return vec![];
    }

    let (shm_addr, shm_id) = shm_addr_o.unwrap();

    let mut child = Command::new("sh").arg("-c").arg(cmd)
        .spawn()
        .expect("Failed to start target binary");

    loop {
        if let Ok(status) = child.try_wait() {
            if status.is_some() {
                println!("Target process exited.");
                break;
            }
        }

        thread::sleep(Duration::from_millis(100));
    }

    let mut candidates = vec![];
    for i in 0..map_size {        
        let hit_count = unsafe { *shm_addr.add(i) };

        if hit_count == amount{
            candidates.push(i);
        }

    }

    // print_cov_map();

    cleanup(shm_addr, shm_id);

    candidates
    
}


pub fn majority_vote_counters(all_counters: &Vec<u16>) -> usize {
    let min_value = all_counters.iter().min();
    let max_value = all_counters.iter().max();
    if min_value == max_value {
        // Since all are equal, use first element
        return 0;
    }

    let mut canidates = Vec::with_capacity(all_counters.len());
    for i in 0..all_counters.len() {
        let v = all_counters[i];
        if v == 0 || v == *max_value.unwrap() {
            continue;
        }
        canidates.push((v, i));
    }

    if canidates.len() == 0 {
        return 0;
    }

    // Find median value in vector
    canidates.sort_by(|a, b| a.0.cmp(&b.0));
    let median_index = canidates[canidates.len() / 2].1;
    return median_index;
}

/// Track Coverage over the Execution of the Binary.
/// @param cmd: Command to run
/// @param indicators: Identification Function Counters
/// @param known_counters: All counters that should be skipped
/// @param max_val: Large counter index (for optimization)
/// @param map_size: Size of shared memory map
pub fn track_coverage(cmd: &str, indicators: &Vec<usize>, known_counters: &HashSet<usize>, max_val: usize, map_size: usize, zero_wrap: bool) -> (Vec<(u16, usize)>, HashSet<usize>, bool){
    let shm_addr_o = setup(map_size);
    if shm_addr_o.is_none(){
        return (vec![], HashSet::new(), false);
    }

    let mut build_iter = vec![];
    for i in 0..max_val{
        if known_counters.contains(&i) && !indicators.contains(&i){
            continue;
        }
        build_iter.push(i);
    }

    let (shm_addr, shm_id) = shm_addr_o.unwrap();

    let mut child = Command::new("sh").arg("-c").arg(cmd)
        .spawn()
        .expect("Failed to start target binary");

    let mut prev_coverage = vec![0u16; max_val];
    let mut actual_coverage = vec![0u16; max_val]; // This is necessary as LLVM wrappes to 255 -> 1

    let mut coverage_results = vec![];
    let mut has_crashed = false;
    loop {
        let mut new_edges: SmallVec<[usize; 64]> = SmallVec::new();        

        for &i in build_iter.iter() {            
            let hit_count = unsafe { *shm_addr.add(i) };
            if hit_count == 0 && (!zero_wrap || prev_coverage[i] == 0){
                continue;
            }

            let p = prev_coverage[i];
            let (abs, wrapped) = abs_from(p, hit_count);

            if p == 0{
                new_edges.push(i);
            }

            prev_coverage[i] += abs as u16;
            if indicators.contains(&i) {
                actual_coverage[i] += abs as u16;
                if wrapped && !zero_wrap{
                    actual_coverage[i] -= 1;
                }
    
            }
        }

        if !new_edges.is_empty() {
            // Collect indicator values efficiently
            let ind_vals: Vec<u16> = indicators.iter().map(|&ind| actual_coverage[ind]).collect();
        
            let cind = majority_vote_counters(&ind_vals) ;
            let mut c = ind_vals.get(cind).copied().unwrap_or(0);
            if c > 0{
                c -= 1;
            }
            coverage_results.extend(new_edges.iter().map(|&edge| (c, edge)));
            
        }


        if let Ok(status) = child.try_wait() {
            if status.is_some() {
                if status.unwrap().code().unwrap_or(0) != 0{
                    has_crashed = true;
                }
                break;
            }
        }
    }

    let mut all_counters = HashSet::new();
    for i in 0..max_val{
        if prev_coverage[i] > 0{
            all_counters.insert(i);
        }
    }

    cleanup(shm_addr, shm_id);

    return (coverage_results, all_counters, has_crashed);
}


/// Print the Coverage results.
pub fn print_cov_map(cov: Vec<(u16, usize)>){
    let mut current_i = 0;
    let mut current_count = 1;
    for val in cov{
        if val.0 != current_i{
            println!("{}: {}", current_i, current_count);

            current_i = val.0;
            current_count = 1;
        }
        else{
            current_count += 1;
        }
    }
    println!("{}: {}", current_i, current_count);
}


/// Absolute different. Since hit_count wrappes, this calculates the absolute increase even if it wrapped.
fn abs_from(prev_cov_val: u16, hit_count: u8) -> (u8, bool){
    let modo: u8 = (prev_cov_val % 256).try_into().unwrap();
    let wrapped = hit_count < modo;
    let abs: u8;
    if wrapped{
        let tmp: u8 = (256 as u16 - modo as u16).try_into().unwrap();
        abs = tmp + hit_count;
    }
    else{
        abs = hit_count - modo;
    }

    (abs, wrapped)
}
