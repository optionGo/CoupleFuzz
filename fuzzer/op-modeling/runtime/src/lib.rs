pub mod ffds;
pub mod heapmap;
pub mod len_label;
mod tag_set;
pub mod tag_set_wrap;
// pub mod track;
pub mod variable_handers_wrap;
mod variable_handers;
mod logger;
mod bb_taint_set;
pub mod stats;
pub use crate::{tag_set::TagSet};

pub type DfsanLabel = u32;
extern "C" {
    fn dfsan_read_label(addr: *const i8, size: usize) -> DfsanLabel;
}
