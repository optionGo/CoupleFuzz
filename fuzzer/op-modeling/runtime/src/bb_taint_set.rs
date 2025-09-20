use std::collections::HashMap;
use std::cmp::{Ordering, max};
use crate::tag_set_wrap;
use angora_common::tag::TagSeg;
use serde_derive::{Serialize, Deserialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSeg {
    pub begin: u32,
    pub end: u32,
}

impl TaintSeg {
    pub fn new(begin: u32, end: u32) -> Self {
        Self { begin, end }
    }
}

#[derive(Debug, Clone)]
pub struct BB_taint_set {
    // pub data: HashMap<u64, HashSet<u32>>, // key: bb_hash, value: taint_label_set
    pub bb_taint: HashMap<u64, Vec<TaintSeg>>,
}

impl BB_taint_set {

    pub fn new() -> Self {
        Self { bb_taint: HashMap::new() }
    }

    pub fn add_taint(&mut self, lb: u32, bb_hash: u64) {
        if lb <= 0 {
            return;
        }
        // self.data.entry(bb_hash).or_insert(HashSet::new()).insert(lb);
        if self.bb_taint.contains_key(&bb_hash) {
            let set_list = tag_set_wrap::tag_set_find(lb as usize);
            if set_list.len() > 1 {
                let mut set_list = set_list[0].clone();
                // println!("@@ lb: {}, set_list: {:?}", lb, set_list);
                let mut taint_seg = self.seg_tag_2_taint_tag(&mut set_list);
                let origin_taint_seg = self.bb_taint.get(&bb_hash).unwrap().clone();
                let merged_taint_seg = self.merge_taint_seg(&mut origin_taint_seg.clone(), &mut taint_seg);
                if merged_taint_seg.len() > 0 {
                    self.bb_taint.insert(bb_hash, merged_taint_seg);
                }
                
            }
        } else {
            let set_list = tag_set_wrap::tag_set_find(lb as usize);
            if set_list.len() > 1 {
                let mut set_list = set_list[0].clone();
                // println!("@@ lb: {}, set_list: {:?}", lb, set_list);
                let taint_seg = self.seg_tag_2_taint_tag(&mut set_list);
                if taint_seg.len() > 0 {
                    self.bb_taint.insert(bb_hash, taint_seg);
                }
            }
        }
    }
    
    pub fn fini(&mut self) {
        // println!("@@ BB_taint_set fini");
        // let data_clone = self.bb_taint.clone();
        // let mut logger = BB_taint_seg_logger {
        //     BB_Taint: HashMap::new()   
        // };
        
        // for (bb_hash, taint_set) in &data_clone {
        //     let mut taint_segs = vec![];
        //     println!("@@ bb_hash: {}, taint_set: {:?}", bb_hash, taint_set);
        //     for lb in taint_set {
        //         let set_list = tag_set_wrap::tag_set_find(*lb as usize);
        //         if set_list.len() > 1 {
        //             let mut set_list = set_list[1].clone();
        //             println!("@@ lb: {}, set_list: {:?}", lb, set_list);
        //             let taint_seg = self.seg_tag_2_taint_tag(&mut set_list);
        //             println!("@@ lb: {}, taint_seg: {:?}", lb, taint_seg);
        //             taint_segs.push(taint_seg);
        //         }
        //     }
        //     println!("@@ taint_segs: {:?}", taint_segs);
        //     let taint_seg = self.merge_taint_segs(&mut taint_segs);
        //     println!("@@ merged taint_seg: {:?}", taint_seg);
        //     logger.BB_Taint.insert(bb_hash.to_string(), taint_seg);
        // }
        // println!("@@ BB_taint_set will save to json");
        
        if let Err(e) = self.save_to_json("bb_taint_seg_logger.json") {
            eprintln!("Failed to save JSON: {}", e);
        }
    }

    pub fn merge_taint_segs(&mut self, taint_segs: &mut Vec<Vec<TaintSeg>>) -> Vec<TaintSeg> {
        if taint_segs.is_empty() {
            return vec![];
        }
        if taint_segs.len() == 1 {
            return taint_segs[0].clone();
        }
        
        let mut result = taint_segs[0].clone();
        
        for i in 1..taint_segs.len() {
            let mut next_segs = taint_segs[i].clone();
            result = self.merge_taint_seg(&mut result, &mut next_segs);
        }
        
        result
    }

    pub fn merge_taint_seg(&mut self, taint_segA: &mut Vec<TaintSeg>, taint_segB: &mut Vec<TaintSeg>) -> Vec<TaintSeg> {
        let mut merged = vec![];
        let mut i = 0;
        let mut j = 0;
        
        while i < taint_segA.len() && j < taint_segB.len() {
            let mut current = if taint_segA[i].begin <= taint_segB[j].begin {
                let seg = taint_segA[i].clone();
                i += 1;
                seg
            } else {
                let seg = taint_segB[j].clone();
                j += 1;
                seg
            };
            
            
            loop {
                let mut merged_any = false;
                
                
                while i < taint_segA.len() && taint_segA[i].begin <= current.end {
                    current.end = max(current.end, taint_segA[i].end);
                    i += 1;
                    merged_any = true;
                }
                
                
                while j < taint_segB.len() && taint_segB[j].begin <= current.end {
                    current.end = max(current.end, taint_segB[j].end);
                    j += 1;
                    merged_any = true;
                }
                
                if !merged_any {
                    break;
                }
            }
            
            merged.push(current);
        }
        
        
        while i < taint_segA.len() {
            merged.push(taint_segA[i].clone());
            i += 1;
        }
        
        while j < taint_segB.len() {
            merged.push(taint_segB[j].clone());
            j += 1;
        }
        
        merged
    }

    pub fn seg_tag_2_taint_tag(&mut self, list: &mut Vec<TagSeg>) -> Vec<TaintSeg> {
        list.sort_by(|a, b| match a.begin.cmp(&b.begin) {
            Ordering::Equal => b.end.cmp(&a.end),
            other => other,
        });
        let mut cur_begin = 0;
        let mut cur_end = 0;
        let mut new_list = vec![];
        for i in list {
            //new tag
            if cur_begin == cur_end {
                cur_begin = i.begin;
                cur_end = i.end;
            } else {
                // push current tag into new_list
                if i.begin > cur_end {
                    new_list.push(TaintSeg::new(cur_begin, cur_end));
                    cur_begin = i.begin;
                    cur_end = i.end;
                } else {
                    cur_end = max(i.end, cur_end);
                }
            }
        }
        if cur_begin != cur_end {
            new_list.push(TaintSeg::new(cur_begin, cur_end));
        }
        new_list
    }
    
    pub fn save_to_json(&self, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::File;
        use std::io::Write;
        
        // Convert u64 keys to strings for JSON compatibility
        let string_keyed_map: HashMap<String, Vec<TaintSeg>> = self.bb_taint
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect();
        
        let json_string = serde_json::to_string_pretty(&string_keyed_map)?;
        let mut file = File::create(file_path)?;
        file.write_all(json_string.as_bytes())?;
        // println!("BB_taint_seg_logger data saved to: {}", file_path);
        Ok(())
    }
}