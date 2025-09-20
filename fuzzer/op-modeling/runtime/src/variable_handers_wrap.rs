// use std::fs::OpenOptions;
// use std::io::Write;
// use std::os::raw::c_ulonglong;
use super::*;
use crate::{tag_set_wrap::*};
use crate::variable_handers::*;
use lazy_static::lazy_static;
use std::{slice, sync::Mutex};
use crate::bb_taint_set::*;
use libc::c_char;

lazy_static! {
    static ref VARIABLE_USAGE_COUNTER: Mutex<Option<VariableUsageCounter>> = Mutex::new(Some(VariableUsageCounter::new()));
    static ref BB_TAINT_SET: Mutex<Option<BB_taint_set>> = Mutex::new(Some(BB_taint_set::new()));
}



#[no_mangle]
pub extern "C" fn __variable_add_usage_counter(_addr: *const i32, _distance: i32, _conditional: bool, _bb_hash: u64) {
    panic!("Forbid calling __chunk_get_load_label directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___variable_add_usage_counter(
    ptr: *const i32,
    distance: i32,
    conditional: bool,
    bb_hash: u64,
    _l0: DfsanLabel,
    _l1: DfsanLabel,
    _l2: DfsanLabel,
    _l3: DfsanLabel
) {
//    println!("__dfsw___variable_add_usage_counter: ptr {:?}", ptr);
   let label = unsafe { dfsan_read_label(ptr as *const i8, 1) };
   if label == 0 {
    return;
   }
//    println!("__dfsw___variable_add_usage_counter: label {:?}, variable_label {:?}, input_label {:?}", 
    //  label, get_variable_real_label(label), get_input_label(label));
//    let tag_set = tag_set_find(label as usize);
//    println!("tag_set: {:?}", tag_set);
   let mut vusl = VARIABLE_USAGE_COUNTER.lock().unwrap();
   if let Some(ref mut vus) = *vusl {
        vus.meet_load_label(label, distance, conditional, bb_hash);
   }
   let mut BTS = BB_TAINT_SET.lock().unwrap();
   if let Some(ref mut bts) = *BTS {
        bts.add_taint(label, bb_hash);
   }
}

#[no_mangle]
pub extern "C" fn __variable_cmpfn(_a: *mut i8, _b: *mut i8, _c: u32, _d: u8, _e: u8, _f:*mut u8, _g:*mut u8) {
    panic!("Forbid calling __variable_cmpfn directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___variable_cmpfn(
    parg1: *const c_char,
    parg2: *const c_char,
    size: u32,
    _is_cnst1: u8,
    _is_cnst2: u8,
    arv_value1:  *const c_char,
    arv_value2:  *const c_char,
    _l0: DfsanLabel,
    _l1: DfsanLabel,
    _l2: DfsanLabel,
    _l3: DfsanLabel,
    _l4: DfsanLabel,
    _l5: DfsanLabel,
    _l6: DfsanLabel,
) {

    // println!("@@runtime: __dfsw___variable_cmpfn");
    
    // println!("@@runtime: parg1 ptr: {:?}", parg1);
    // println!("@@runtime: parg2 ptr: {:?}", parg2);
    let (arglen1, arglen2) = if size == 0 {
        unsafe { (libc::strlen(arv_value1) as usize, libc::strlen(arv_value2) as usize) }
    } else {
        (size as usize, size as usize)
    };

    let lb1: u32 = unsafe { dfsan_read_label(parg1, 1) };
    let lb2: u32 = unsafe { dfsan_read_label(parg2, 1) };

    // println!("@@runtime: __dfsw___variable_cmpfn: lb1 = {}, lb2 = {}", lb1, lb2);

    if lb1 == 0 && lb2 == 0 {
        return;
    }

    let arg1 = unsafe { slice::from_raw_parts(arv_value1 as *mut u8, arglen1) }.to_vec();
    let arg2 = unsafe { slice::from_raw_parts(arv_value2 as *mut u8, arglen2) }.to_vec();

    // println!("@@runtime: arv len1: {:?}", arglen1);
    // println!("@@runtime: arv len2: {:?}", arglen2);

    // println!("@@runtime: arg1: {:?}", String::from_utf8_lossy(&arg1).to_string());
    // println!("@@runtime: arg2: {:?}", String::from_utf8_lossy(&arg2).to_string());

    let variable_lb1 = get_variable_real_label(lb1);
    let variable_lb2 = get_variable_real_label(lb2);

    // println!("@@runtime: variable_lb1: {:?}", variable_lb1);
    // println!("@@runtime: variable_lb2: {:?}", variable_lb2);

    if variable_lb1 > 0 && variable_lb2 == 0 {
        log_magic_number(lb1, String::from_utf8_lossy(&arg2).to_string());
    } else if variable_lb2 > 0 && variable_lb1 == 0 {
        log_magic_number(lb2, String::from_utf8_lossy(&arg1).to_string());
    } else if variable_lb1 > 0 && variable_lb2 > 0 {
        log_eq_constrain(lb1, lb2);
    }
}

#[no_mangle]
pub extern "C" fn __variable_cmp_inst(
    _a: u32,
    _b: u32,
    _c: u64,
    _d: u64,
    _e: u32,
    _f: u8,
    _g: u8,
) {
    panic!("Forbid calling __variable_cmp_inst directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___variable_cmp_inst(
    size: u32,
    op: u32,
    arg1: u64,
    arg2: u64,
    _condition: u32,
    is_cnst1: u8,
    is_cnst2: u8,
    _l0: DfsanLabel,
    _l1: DfsanLabel,
    l2: DfsanLabel,
    l3: DfsanLabel,
    _l4: DfsanLabel,
    _l5: DfsanLabel,
    _l6: DfsanLabel,
) {
    let lb1 = l2;
    let lb2 = l3;
    if lb1 == 0 && lb2 == 0 {
        return;
    }
    let mut size1 = 0;
    let mut size2 = 0;
    if cfg!(debug_assertions) {
        eprintln!("[DEBUG] __dfsw___chunk_trace_cmp_tt");
    }

    infer_shape(lb1, size);
    infer_shape(lb2, size);

    // let op = infer_eq_sign(op, lb1, lb2);
    if cfg!(debug_assertions) {
        eprintln!("[DEBUG] op is {}, lb1 is {}, lb2 is {}, is_cnst2 is {}, arg2 is {}, size = {}, size1 = {}, size2 = {}", op, lb1, lb2, is_cnst2, arg2, size, size1, size2);
    }

    let variable_lb1 = get_variable_real_label(lb1);
    let variable_lb2 = get_variable_real_label(lb2);
    
    // 32 = ICMP_EQ
    // 33 = ICMP_NE 
    if op == 32 || op == 33 {
        if variable_lb1 != 0 && variable_lb2 == 0 {
            log_magic_number(lb1, arg2.to_string());
            return;
        } else if variable_lb1 == 0 && variable_lb2 != 0 {
            log_magic_number(lb2, arg1.to_string());
            return;
        } else if variable_lb1 != 0 && variable_lb2 != 0 {
            log_eq_constrain(lb1, lb2);
        }
    }
}



#[no_mangle]
pub extern "C" fn __variable_switch_inst(_a: u32, _b: u64, _c: u32, _d: *mut u64, _e: u8) {
    panic!("Forbid calling __variable_switch_arg_values directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___variable_switch_inst(
    size: u32,
    condition: u64,
    num: u32,
    args: *mut u64,
    _l0: DfsanLabel,
    _l1: DfsanLabel,
    _l2: DfsanLabel,
    _l3: DfsanLabel,
) {

    // println!("meet switch inst");

    let lb = _l1;
    if lb == 0 {
        return;
    }
    
    // let mut op = defs::COND_ICMP_EQ_OP;
    let sw_args = unsafe { slice::from_raw_parts(args, num as usize) }.to_vec();
    

    for arg in sw_args {
        // println!("arg: {}", arg);
        log_magic_number(lb, arg.to_string());
    }
}


#[no_mangle]
pub extern "C" fn __variable_counter_fini() {

    let mut BTS = BB_TAINT_SET.lock().unwrap();
    if let Some(ref mut bts) = *BTS {
        bts.fini();
    } else {
        panic!("BB_TAINT_SET FINI ERROR!");
    }

    let mut VUC = VARIABLE_USAGE_COUNTER.lock().unwrap();
    if let Some(ref mut vts) = *VUC {
        vts.fini();
    } else {
        panic!("TAG SET FINI ERROR!");
    }
    
}

fn log_eq_constrain(lb1: u32, lb2: u32) {
    let mut VUC = VARIABLE_USAGE_COUNTER.lock().unwrap();
    if let Some(ref mut vts) = *VUC {
        vts.add_eq_constrain(lb1, lb2);
    } else {
        panic!("TAG SET FINI ERROR!");
    }
}

fn log_magic_number(lb: u32, magic_number: String) {
    let mut VUC = VARIABLE_USAGE_COUNTER.lock().unwrap();
    if let Some(ref mut vts) = *VUC {
        vts.add_variable_magic_number(lb, magic_number);
    } else {
        panic!("TAG SET FINI ERROR!");
    }
}

fn infer_shape(lb: u32, size: u32) {
    if lb > 0 {
        tag_set_wrap::__angora_tag_set_infer_shape_in_math_op(lb, size);
    }
}
// #[no_mangle]
// pub extern "C" fn __variable_set_label(addr: *const c_ulonglong, id: u32) {

//     let file_result = OpenOptions::new()
//         .create(true)
//         .append(true)
//         .open("output.txt");

//     match file_result {
//         Ok(mut file) => {

//             let _ = file.write_all(addr_str.as_bytes());
//             let lb: u32 = __option_variable_tag_set_insert(id);
//             unsafe {
//                 __dfsan_set_label(lb, addr as *mut std::ffi::c_void, 1);
//             }
//         }
//         Err(e) => {


//         }
//     }
// }


// unsafe extern "C" {
//     pub fn __dfsan_set_label(label: u32, addr: *mut std::ffi::c_void, size: usize);
// }