#include "cJSON.h"
#include "types.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <math.h>
#include <signal.h>
#include "alloc-inl.h"
#include "debug.h"
#include "types.h"
#include "option_mutation.h"

typedef struct {
    int begin;
    int end;
} range_t;

typedef struct {
    char *hash_key;
    range_t *ranges;
    int range_count;
} bb_taint_seg_t;

bb_taint_seg_t* parse_hash_ranges_json(const u8 *path, u32 *count);
void free_hash_ranges_data(bb_taint_seg_t *data, int count);
void print_hash_ranges_data(bb_taint_seg_t *data, int count);
bb_taint_seg_t* find_hash_data(bb_taint_seg_t *data, int count, const char *hash_key);

bb_taint_seg_t* hash_ranges_difference(bb_taint_seg_t *data1, int count1, 
                                         bb_taint_seg_t *data2, int count2, int *diff_count);
range_t* merge_ranges(range_t *ranges, int range_count, int *merged_count);
bb_taint_seg_t* merge_all_ranges_in_difference(bb_taint_seg_t *diff_data, int diff_count);

u8* get_source_filename(const u8 *seed_filename, const u8 *queue_dir);

u8* extract_bytes_from_ranges(u8 *out_buf, int out_buf_len, range_t *ranges, int range_count, int *extracted_len);
void restore_bytes_to_ranges(u8 *out_buf, u8 *extracted_buf, int extracted_buf_len, range_t *ranges, int range_count);
