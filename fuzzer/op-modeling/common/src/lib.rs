pub mod config;
pub mod defs;
pub mod shm;
pub mod tag;
pub mod log_data;
pub mod cond_stmt_base;

// void __unfold_branch_fn(uint32_t) {}

#[no_mangle]
pub fn __unfold_branch_fn(_x: u32) {

}
