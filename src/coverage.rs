use std::{collections::{HashMap, HashSet}, env, process::Command, ptr};
use libc::{shmat, shmctl, shmget, shmdt, IPC_CREAT, IPC_RMID};
use smallvec::SmallVec;
use rayon::*;

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use std::thread;

/// Setup shared memory segment. Signal this to target binary over env variable.
/// @param map_size: Size of the shared memory map
fn setup(map_size: usize) -> Option<( *mut u8, i32)>{
    let shm_id = unsafe { shmget(0, map_size, IPC_CREAT | 0o600) };

    if shm_id < 0 {
        let err = std::io::Error::last_os_error();
        println!("shmget failed with error: {}", err);
        
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



/// Execute binary and get coverage map after execution. 
/// @param cmd: The command to run the target binary
/// @param map_size: The size of the shared memory map
pub fn execute_with_coverage(cmd: &str, map_size: usize) -> Vec<u16>{
    let shm_addr_o = setup(map_size);
    if shm_addr_o.is_none(){
        eprintln!("ERROR: Could not setup shared memory");
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


/// Execute the target binary to completion and read the AFL coverage bitmap
/// exactly once, *after* the process has exited.
///
///
/// Returns an empty vector if shared memory setup or the target launch fails.
pub fn execute_with_coverage_once(cmd: &str, map_size: usize) -> Vec<u16> {
    let Some((shm_addr, shm_id)) = setup(map_size) else {
        eprintln!("ERROR: Could not setup shared memory");
        return vec![];
    };

    // Run to completion. stdio is inherited so the target's output is visible,
    // and `status()` blocks until the process has fully exited.
    let status = Command::new("sh").arg("-c").arg(cmd).status();

    match status {
        Ok(s) if !s.success() => eprintln!("source_cov: target exited with {}", s),
        Err(e) => {
            eprintln!("source_cov: failed to run target: {}", e);
            cleanup(shm_addr, shm_id);
            return vec![];
        }
        _ => {}
    }

    // Single, consistent pass over the now-final map.
    let mut coverage = vec![0u16; map_size];
    for (i, slot) in coverage.iter_mut().enumerate() {
        *slot = unsafe { *shm_addr.add(i) } as u16;
    }

    cleanup(shm_addr, shm_id);
    coverage
}


/// Takes a list of candidates for Indication Functions.
/// Removes all candidates that indicate the same location in the Code.
/// @param cmd: The command to run the target binary
/// @param candidates: The candidate counters for the IFs
/// @param map_size: The size of the shared memory map
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

    Command::new("sh").arg("-c").arg(cmd)
        .output()
        .expect("Failed to start target binary");

    let mut candidates = vec![];
    for i in 0..map_size {        
        let hit_count = unsafe { *shm_addr.add(i) };

        if hit_count == amount{
            candidates.push(i);
        }

    }

    cleanup(shm_addr, shm_id);

    candidates
}


/// Necessary if multiple IFs are used. Implements a majority vote to determine the correct counter value.
/// @param all_counters: All counter values of the IFs
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
    let median_index = canidates[canidates.len()- 1].1;
    return median_index;
}



fn internal_loop(indicators: Vec<usize>, zero_wrap: bool, build_iter: Vec<usize>, max_val: usize, shm_id: i32, stop: Arc<AtomicBool>) -> (Vec<(u16, usize)>, HashSet<usize>){
    let indicator_set = indicators.iter().cloned().collect::<HashSet<_>>();

    let mut prev_coverage = vec![0u16; max_val];
    let mut actual_coverage = vec![0u16; max_val]; // This is necessary as LLVM wrapps to 255 -> 1

    let mut coverage_results = vec![];
    let mut new_edges: SmallVec<[usize; 64]> = SmallVec::new();        

    let shm_addr = unsafe { shmat(shm_id, ptr::null_mut(), 0) } as *mut u8;

    loop {
        new_edges.clear();
        for &i in build_iter.iter() { 

            let hit_count = unsafe { *shm_addr.add(i) };

            if hit_count == 0 && !zero_wrap{
                continue;
            }

            let pc = unsafe { prev_coverage.get_unchecked_mut(i)};
            let p = *pc;

            // If no hit, skip. If the counter value > 0, only look at it if the counter was 0 previously (new edge). If zero wrap is enabled, we must check anyway because it could have wrapped to 0.
            if hit_count == 0 && (!zero_wrap ||  p == 0){
                continue;
            }


            let (abs, wrapped) = abs_from(p, hit_count);
      

            // Only look at new edges if they are not an IF
            if p == 0 && !indicator_set.contains(&i) {
                new_edges.push(i);                
            }

            if indicator_set.contains(&i) {
                let ac = unsafe{actual_coverage.get_unchecked_mut(i)};
                *ac = ac.wrapping_add(abs as u16);
                if wrapped && !zero_wrap && *ac > 0 {
                    *ac = ac.wrapping_sub(1);
                }
            }
            // If indicator set contains this, track the actual coverage as its important for the score
            *pc += abs as u16;

        }


        // If a new edge is found, check the IFs to find which object in the batch caused the increase.
        if !new_edges.is_empty() {
            let ind_vals: Vec<u16> = indicators.iter().map(|&ind| actual_coverage[ind]).collect();
        
            let cind = majority_vote_counters(&ind_vals);
            let mut c = ind_vals.get(cind).copied().unwrap_or(0);
            if c > 0{
                c -= 1;
            }
            coverage_results.extend(new_edges.iter().map(|&edge| (c, edge)));
            
        }
        if stop.load(Ordering::SeqCst) {
            break;
        }
    }

    let mut all_counters = HashSet::new();
    for i in 0..max_val{
        if prev_coverage[i] > 0{
            all_counters.insert(i);
        }
    }

    cleanup(shm_addr, shm_id);
    return (coverage_results, all_counters);
}


/// Tracks coverage over the execution of the binary.
/// @param cmd: Command to run
/// @param indicators: Identification Function Counters
/// @param known_counters: All counters that should be skipped
/// @param max_val: Large counter index (for optimization)
/// @param map_size: Size of shared memory map (dictated by the binary so all counters fit into it)
pub fn track_coverage(cmd: &str, indicators: &Vec<usize>, known_counters: &HashSet<usize>, max_val: usize, map_size: usize, zero_wrap: bool) -> (Vec<(u16, usize)>, HashSet<usize>, bool){
    let shm_addr_o = setup(map_size);
    if shm_addr_o.is_none(){
        return (vec![], HashSet::new(), false);
    }

    let mut build_iter = vec![];
    for i in 0..max_val{
        if known_counters.contains(&i) || indicators.contains(&i){
            continue;
        }

        build_iter.push(i);
    }

    let (_, shm_id) = shm_addr_o.unwrap();

    let mut child = Command::new("sh").arg("-c").arg(cmd)
        .spawn()
        .expect("Failed to start target binary");


    // let mut coverage_results = vec![];
    let mut has_crashed = false;

    let workers = 4;
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = vec![];
    let b_len = build_iter.len() / workers;

    for i in 0..workers{

        let cindic = indicators.clone();
        let stop_clone = Arc::clone(&stop);
        let mut new_build_iter = build_iter[i*b_len..(i+1)*b_len].to_vec();
        // let mut new_build = indicators.clone();
        new_build_iter.extend(indicators);

        let handle = thread::spawn(move || {
            internal_loop(cindic, zero_wrap, new_build_iter, max_val, shm_id, stop_clone)
        });
        handles.push(handle);

    }

    loop{
        if let Ok(status) = child.try_wait() {
                if status.is_some() {
                    stop.store(true, Ordering::SeqCst); // Stop the threats
                    if status.unwrap().code().unwrap_or(0) != 0{
                        has_crashed = true;
                    }
                    break;
                }
            }
    }


    let mut coverage_results: Vec<(u16, usize)> = vec![];
    let mut all_counters = HashSet::new();
    for h in handles {
        let res = h.join().unwrap();
        all_counters.extend(res.1);
        coverage_results.extend(res.0);
    }

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
#[inline]
fn abs_from(prev_cov_val: u16, hit_count: u8) -> (u8, bool) {
    let modo = prev_cov_val as u8; // directly get low byte
    if hit_count < modo {
        (hit_count.wrapping_sub(modo), true) // will wrap correctly
    } else {
        (hit_count - modo, false)
    }
}