use crate::{tag_set::TagSet};
use angora_common::{config, tag::TagSeg};
use lazy_static::lazy_static;
use std::{collections::HashMap, slice, sync::Mutex};


pub const VARIABLE_LABEL_OFFSET: u32 = 20;
pub const MAX_VARIABLE_LABEL_COUNT: u32 = 1 << (32 - VARIABLE_LABEL_OFFSET);
pub const NORMAL_INPUT_MASK: u32 = (1 << VARIABLE_LABEL_OFFSET) - 1;

// Lazy static doesn't have reference count and won't call drop after the program finish.
// So, we should call drop manually.. see ***_fini.
lazy_static! {
    static ref TS: Mutex<Option<TagSet>> = Mutex::new(Some(TagSet::new("input".to_string())));
    static ref VTS: Mutex<Option<TagSet>> = Mutex::new(Some(TagSet::new("variable".to_string())));
}

#[no_mangle]
pub fn get_variable_real_label(lb: u32) -> u32 {
    return  lb >> VARIABLE_LABEL_OFFSET;
}

#[no_mangle]
pub fn get_input_label(lb: u32) -> u32 {
    return  lb & NORMAL_INPUT_MASK;
}


#[no_mangle]
pub fn get_label(variable_lb: u32, input_lb: u32) -> u32 {
    (variable_lb << VARIABLE_LABEL_OFFSET) + input_lb
}

#[no_mangle]
pub extern "C" fn __angora_tag_set_insert(offset: u32) -> u32 {
    let mut tsl: std::sync::MutexGuard<'_, Option<TagSet>> = TS.lock().unwrap();
    if let Some(ref mut ts) = *tsl {
        ts.insert(offset) as u32
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn __option_variable_tag_set_insert(offset: u32) -> u32 {
    // println!("into rust: __option_variable_tag_set_insert, offset = {}", offset);
    let mut vtsl = VTS.lock().unwrap();
    if let Some(ref mut vts) = *vtsl {
        let label = vts.insert(offset) as u32;
        if label > MAX_VARIABLE_LABEL_COUNT {
            println!("variable label count overflow");
            return 0;
        }

        
        return get_label(label, 0)
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn __angora_tag_set_combine(lb1: u32, lb2: u32) -> u32 {

    let input_lb1 = get_input_label(lb1);
    let variable_lb1 = get_variable_real_label(lb1);


    let input_lb2 = get_input_label(lb2);
    let variable_lb2 = get_variable_real_label(lb2);

    let mut tsl = TS.lock().unwrap();
    let mut vtsl = VTS.lock().unwrap();

    let input_lb = if let Some(ref mut ts) = *tsl {
        ts.combine(input_lb1 as usize, input_lb2 as usize) as u32
    } else {
        0
    };

    let variable_lb = if let Some(ref mut vts) = *vtsl {
        vts.combine(variable_lb1 as usize, variable_lb2 as usize) as u32
    } else {
        0
    };

    get_label(variable_lb, input_lb)
}

#[no_mangle]
pub extern "C" fn __angora_tag_set_combine_n(lbs: *const u32, size: u32, infer_shape: bool) -> u32 {

    

    let lbs = unsafe { slice::from_raw_parts(lbs, size as usize) };
    let intput_lbs: Vec<usize> = lbs
        .iter()
        .map(|l| {
            get_input_label(*l) as usize
        })
        .collect::<Vec<usize>>();

    let variable_lbs: Vec<usize> = lbs
        .iter()
        .map(|l| {
            get_variable_real_label(*l) as usize
        })
        .collect::<Vec<usize>>();
    
    // println!("variable_lbs: {:?}", variable_lbs);
    let mut tsl = TS.lock().unwrap();
    let mut vtsl = VTS.lock().unwrap();
    let input_lb = if let Some(ref mut ts) = *tsl {
        ts.combine_n(intput_lbs, infer_shape) as u32
    } else {
        0
    };

    let variable_lb = if let Some(ref mut vts) = *vtsl {
        vts.combine_n(variable_lbs, infer_shape) as u32
    } else {
        0
    };
    
    get_label(variable_lb, input_lb)
}

// called in dfsan/pass/DFSanPass
#[no_mangle]
pub extern "C" fn __angora_tag_set_mark_sign(lb: u32) {
    let mut tsl = TS.lock().unwrap();
    if let Some(ref mut ts) = *tsl {
        ts.set_sign(get_input_label(lb) as usize);
    }
    let mut vtsl = VTS.lock().unwrap();
    if let Some(ref mut vts) = *vtsl {
        vts.set_sign(get_variable_real_label(lb) as usize);
    }
}

#[no_mangle]
pub extern "C" fn __angora_tag_set_infer_shape_in_math_op(lb: u32, len: u32) {
    let mut tsl = TS.lock().unwrap();
    if let Some(ref mut ts) = *tsl {
        ts.infer_shape2(get_input_label(lb )as usize, len as usize);
    }
    // let mut vtsl = VTS.lock().unwrap();
    // if let Some(ref mut vts) = *vtsl {
    //     vts.infer_shape2(get_variable_real_label(lb) as usize, len as usize);
    // }
}

// called in dfsan/pass/DFSanPass
#[no_mangle]
pub extern "C" fn __angora_tag_set_combine_and(lb: u32) {
    if config::DISABLE_INFER_SHAPE_IF_HAS_AND_OP {
        let mut tsl = TS.lock().unwrap();
        if let Some(ref mut ts) = *tsl {
            ts.combine_and(get_input_label(lb) as usize);
        }
    }
}

#[no_mangle]
pub extern "C" fn __angora_tag_set_fini() {
    // let mut tsl = TS.lock().unwrap();
    // *tsl = None;
    let mut vtsl = VTS.lock().unwrap();
    *vtsl = None;
}

#[no_mangle]
pub fn tag_set_find(lb: usize) -> Vec<Vec<TagSeg>> {
    let mut res = Vec::with_capacity(2);
    let mut tsl = TS.lock().unwrap();
    if let Some(ref mut ts) = *tsl {
        res.push(ts.find(get_input_label(lb as u32) as usize));
    }
    let mut vtsl = VTS.lock().unwrap();
    if let Some(ref mut vts) = *vtsl {
        res.push(vts.find(get_variable_real_label(lb as u32) as usize));
    }
    res
}

pub fn tag_set_get_sign(lb: usize) -> bool {
    let tsl = TS.lock().unwrap();
    if let Some(ref ts) = *tsl {
        ts.get_sign(get_input_label(lb as u32) as usize)
    } else {
        false
    }
}

#[no_mangle]
pub fn get_variable_tag_num() -> usize {
    let vtsl = VTS.lock().unwrap();
    if let Some(ref vts) = *vtsl {
        vts.get_num_nodes()
    } else {
        0
    }
}

#[no_mangle]
pub fn print_variable_nodes() {
    
    let mut vtsl = VTS.lock().unwrap();
    if let Some(ref mut vts) = *vtsl {
        let num: usize = get_variable_tag_num();
        for i in 0..num {
            // println!(i);
            println!("{:?}", vts.find(i));
        }
    } else {
       eprintln!("获取标签失败");
    }
}


#[no_mangle]
pub extern "C" fn __angora_tag_set_show(lb: usize) {
    println!("{:?}", tag_set_find(lb));
}


#[no_mangle]
pub extern "C" fn __tag_set_fini() {
    let mut vtsl = VTS.lock().unwrap();
    if let Some(ref mut vts) = *vtsl {
        vts.fini();
    } else {
        panic!("TAG SET FINI ERROR!");
    }
    // let mut tsl = TS.lock().unwrap();
    // if let Some(ref mut ts ) = *tsl {
    //     ts.fini();
    // } else {
    //     panic!("TAG SET FINI ERROR!");
    // }
}

