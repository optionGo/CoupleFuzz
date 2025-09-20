use super::*;
use crate::logger::*;
use crate::{tag_set_wrap::*};
use angora_common::{cond_stmt_base::*, log_data::*, tag::*};
use std::collections::{HashMap, HashSet};
use std::{cmp::*, env, fs::File, io::prelude::*, path::PathBuf, sync::Mutex, time::*};
use lazy_static::lazy_static;
use std::hash::{Hash, Hasher};
use serde_derive::{Serialize, Deserialize};
lazy_static! {
    pub static ref LC: Mutex<Option<Logger>> = Mutex::new(Some(Logger::new()));
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BBCondition {
    pub bb_hash: u64,
    pub distance: i32,
    pub conditional: bool,
}

impl Hash for BBCondition {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bb_hash.hash(state);
    }
}

impl PartialEq for BBCondition {
    fn eq(&self, other: &Self) -> bool {
        self.bb_hash == other.bb_hash
    }
}

impl Eq for BBCondition {}


#[derive(Debug, Clone)]
pub struct VariableUsageCounter {
    pub variable_usages: Vec<HashMap<BBCondition, u32>>,
    pub size: u32,
    pub variable_magic_number: HashMap<u32, HashSet<String>>,
    pub varibble_eq_constrain: HashSet<Vec<u32>>, // {[1, 2], [2, 3]}
}


impl VariableUsageCounter {
    pub fn new() -> Self {
        Self { 
            variable_usages: vec![HashMap::new(); MAX_VARIABLE_LABEL_COUNT as usize], 
            size: 0,
            variable_magic_number: HashMap::new(),
            varibble_eq_constrain: HashSet::new()
        }
    }

    pub fn add_usage(&mut self, id: u32, distance: i32, conditional: bool, bb_hash: u64) -> u32 {
        if id >= MAX_VARIABLE_LABEL_COUNT {
            panic!("Variable label out of range");
        }
        if self.size < id {
            self.size = id;
        }
        let condition = BBCondition { bb_hash, distance, conditional };
        let map = &mut self.variable_usages[id as usize];
        if let Some(count) = map.get_mut(&condition) {
            *count += 1;
            return *count;
        } else {
            map.insert(condition, 1);
            return 1;
        }
    }



    pub fn meet_load_label(&mut self,  lb: u32, distance: i32, conditional: bool, bb_hash: u64) -> u32 {
        let saved = variable_handers::VariableUsageCounter::access_check(lb as u64, Offset::new(0, 0, 0));
        if saved != 0 {
            if cfg!(debug_assertions) {
                eprintln!("[DEBUG] Meet saved load label");
            }
            return saved;
        }
        let mut set_list = self.get_variable_taint_set(lb);

        for tag_seg in set_list{
            for i in tag_seg.begin..tag_seg.end{
                self.add_usage(i as u32, distance, conditional, bb_hash);
            }
        }
        return 1;
    }

    pub fn add_variable_magic_number(&mut self, lb: u32, magic_number: String) {
        let mut set_list = self.get_variable_taint_set(lb);

        for tag_seg in set_list{
            for i in tag_seg.begin..tag_seg.end{
                if let Some(set) = self.variable_magic_number.get_mut(&i) {
                    set.insert(magic_number.clone());
                } else {
                    self.variable_magic_number.insert(i, HashSet::from([magic_number.clone()]));
                }
            }
        }

        
    }

    pub fn add_eq_constrain(&mut self, lb1: u32, lb2: u32) {
        let variable_list1 = self.get_variable_taint_set(lb1);
        let variable_list2 = self.get_variable_taint_set(lb2);

        let mut size1 = 0;
        let mut size2 = 0;

        let mut pos1 = 0;
        let mut pos2 = 0;

        for tag_seg in variable_list1 {
            size1 += tag_seg.end - tag_seg.begin;
            pos1 = tag_seg.begin;
        }

        for tag_seg in variable_list2 {
            size2 += tag_seg.end - tag_seg.begin;
            pos2 = tag_seg.begin;
        }

        if size1 != 1 && size2 != 1{
            return ;
        }
        self.varibble_eq_constrain.insert(vec![pos1, pos2]);
    }

    pub fn get_variable_taint_set(&self, lb: u32) -> Vec<TagSeg> {
        let mut set_list = tag_set_wrap::tag_set_find(lb as usize);
        for list in &mut set_list {
            list.sort_by(|a: &TagSeg, b: &TagSeg| match a.begin.cmp(&b.begin) {
                Ordering::Equal => b.end.cmp(&a.end),
                other => other,
            });
        }
        
        let variable_list: Vec<TagSeg> = if set_list.len() > 1 {
            set_list[1].clone()
        } else {
            Vec::new()
        };
        return variable_list;
    }

    // if size == 0 ,search lb in LC, return 0 if not found
    // if size != 0, save lb in LC, always return 0
    pub fn access_check(lb: u64, filed: Offset) -> u32 {
        let mut lcl = LC.lock().unwrap();
        if let Some(ref mut lc) = *lcl {
            lc.save_tag(lb, filed)
        } else {
            0
        }
    }
    
    pub fn fini(&self) {
        // for i in 1..(self.size + 1) {
        //     println!("Variable {} has {} different BB", i, self.variable_usages[i as usize].len());
        //     let map = &self.variable_usages[i as usize];
        //     if !map.is_empty() {
        //         let total_usages: u32 = map.values().sum();
        //         println!("  Total usages: {}", total_usages);
        //         for (condition, count) in map {
        //             println!("    BB {} (distance: {}, conditional: {}) -> {} usages", 
        //                      condition.bb_hash, condition.distance, condition.conditional, count);
        //         }
        //     }
        // }

        if let Err(e) = self.save_to_json("variable_usage_counter.json") {
            eprintln!("Failed to save JSON: {}", e);
        }
        
    }

    pub fn save_to_json(&self, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::File;
        use std::io::Write;
        
        

        
        
        #[derive(Serialize)]
        struct SerializableMagicNumber {
            variable_magic_number: std::collections::HashMap<String, Vec<String>>,
        }

        
        let mut variable_magic_number_map = std::collections::HashMap::new();
        for (id, set) in self.variable_magic_number.iter() {
            
            let key = format!("id_{}", id);
            let mut values: Vec<String> = set.iter().cloned().collect();
            values.sort();
            variable_magic_number_map.insert(key, values);
        }

        
        #[derive(Serialize)]
        struct BBConditionData {
            bb_hash: u64,
            distance: i32,
            conditional: bool,
            count: u32,
        }
        
        #[derive(Serialize)]
        struct SerializableData {
            size: u32,
            variable_usages: std::collections::HashMap<String, Vec<BBConditionData>>,
            variable_magic_number: std::collections::HashMap<String, Vec<String>>,
            variable_eq_constrain: Vec<Vec<u32>>,
        }
        
        let mut variable_usages_map = std::collections::HashMap::new();
        for (id, map) in self.variable_usages.iter().enumerate() {
            if !map.is_empty() {
                let conditions: Vec<BBConditionData> = map.iter().map(|(condition, count)| {
                    BBConditionData {
                        bb_hash: condition.bb_hash,
                        distance: condition.distance,
                        conditional: condition.conditional,
                        count: *count,
                    }
                }).collect();
                variable_usages_map.insert(format!("id_{}", id), conditions);
            }
        }
        
        let serializable_data = SerializableData {
            size: self.size,
            variable_usages: variable_usages_map,
            variable_magic_number: variable_magic_number_map,
            variable_eq_constrain: self.varibble_eq_constrain.iter().cloned().collect(),
        };
        
        let json_string = serde_json::to_string_pretty(&serializable_data)?;
        let mut file = File::create(file_path)?;
        file.write_all(json_string.as_bytes())?;
        // println!("VariableUsageCounter data saved to: {}", file_path);
        Ok(())
    }
}