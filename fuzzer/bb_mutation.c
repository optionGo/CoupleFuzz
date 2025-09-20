#include "bb_mutation.h"

bb_taint_seg_t* parse_hash_ranges_json(const u8 *path, u32 *count) {
    FILE *fp = fopen((const char *)path, "r");
    if (fp == NULL) {
        return NULL;
    }
    fclose(fp);
    cJSON *json_root = get_json(path);
    if (!json_root) {
        PFATAL("Failed to parse JSON file '%s'", path);
    }

    int hash_count = 0;
    cJSON *current_hash = json_root->child;
    while (current_hash) {
        hash_count++;
        current_hash = current_hash->next;
    }
    
    *count = hash_count;
    
    if (hash_count <= 0) {
        cJSON_Delete(json_root);
        bb_taint_seg_t *empty_data = ck_alloc(sizeof(bb_taint_seg_t));
        empty_data[0].hash_key = NULL;
        empty_data[0].range_count = 0;
        empty_data[0].ranges = NULL;
        return empty_data;
    }

    bb_taint_seg_t *all_data = ck_alloc(sizeof(bb_taint_seg_t) * (hash_count + 1));
    

    current_hash = json_root->child;
    int data_index = 0;
    
    while (current_hash && data_index < hash_count) {
        all_data[data_index].hash_key = (char*)ck_strdup((u8*)current_hash->string);
        
        if (cJSON_IsArray(current_hash)) {
            int range_count = cJSON_GetArraySize(current_hash);
            all_data[data_index].range_count = range_count;
            all_data[data_index].ranges = ck_alloc(sizeof(range_t) * range_count);
            
            for (int i = 0; i < range_count; i++) {
                cJSON *range_obj = cJSON_GetArrayItem(current_hash, i);
                if (cJSON_IsObject(range_obj)) {
                    cJSON *begin_item = cJSON_GetObjectItem(range_obj, "begin");
                    cJSON *end_item = cJSON_GetObjectItem(range_obj, "end");
                    
                    if (begin_item && end_item && 
                        cJSON_IsNumber(begin_item) && cJSON_IsNumber(end_item)) {
                        all_data[data_index].ranges[i].begin = begin_item->valueint;
                        all_data[data_index].ranges[i].end = end_item->valueint;
                    } else {
                        PFATAL("Invalid range object in JSON '%s'", path);
                    }
                } else {
                    PFATAL("Expected object in range array in JSON '%s'", path);
                }
            }
        } else {
            PFATAL("Expected array for hash key '%s' in JSON '%s'", 
                   current_hash->string, path);
        }
        
        current_hash = current_hash->next;
        data_index++;
    }
    
    all_data[data_index].hash_key = NULL;
    all_data[data_index].range_count = 0;
    all_data[data_index].ranges = NULL;
    
    cJSON_Delete(json_root);
    return all_data;
}

void free_hash_ranges_data(bb_taint_seg_t *data, int count) {
    if (!data) return;
    
    for (int i = 0; i < count; i++) {
        if (data[i].hash_key) {
            ck_free(data[i].hash_key);
        }
        if (data[i].ranges) {
            ck_free(data[i].ranges);
        }
    }
    ck_free(data);
}


bb_taint_seg_t* find_hash_data(bb_taint_seg_t *data, int count, const char *hash_key) {
    for (int i = 0; i < count; i++) {
        if (strcmp(data[i].hash_key, hash_key) == 0) {
            return &data[i];
        }
    }
    return NULL;
}

static int ranges_equal(range_t *r1, range_t *r2) {
    return (r1->begin == r2->begin && r1->end == r2->end);
}

static int range_in_array(range_t *range, range_t *ranges, int range_count) {
    for (int i = 0; i < range_count; i++) {
        if (ranges_equal(range, &ranges[i])) {
            return 1;
        }
    }
    return 0;
}

bb_taint_seg_t* hash_ranges_difference(bb_taint_seg_t *data1, int count1, 
                                         bb_taint_seg_t *data2, int count2, int *diff_count) {
    
    if (!data2 || count2 <= 0) {
        *diff_count = 0;
        return NULL;
    }
    
    
    if (!data1 || count1 <= 0) {
        *diff_count = count2;
        bb_taint_seg_t *diff_data = ck_alloc(sizeof(bb_taint_seg_t) * count2);
        
        for (int i = 0; i < count2; i++) {
            diff_data[i].hash_key = ck_strdup((u8*)data2[i].hash_key);
            diff_data[i].range_count = data2[i].range_count;
            diff_data[i].ranges = ck_alloc(sizeof(range_t) * data2[i].range_count);
            
            
            for (int j = 0; j < data2[i].range_count; j++) {
                diff_data[i].ranges[j] = data2[i].ranges[j];
            }
        }
        return diff_data;
    }
    
    int count = 0;
    bb_taint_seg_t *diff_data = ck_alloc(sizeof(bb_taint_seg_t) * count2);
    
    for (int i = 0; i < count2; i++) {

        bb_taint_seg_t *found = find_hash_data(data1, count1, data2[i].hash_key);
        
        if (!found) {
            
            diff_data[count].hash_key = ck_strdup((u8*)data2[i].hash_key);
            diff_data[count].range_count = data2[i].range_count;
            diff_data[count].ranges = ck_alloc(sizeof(range_t) * data2[i].range_count);
            
            
            for (int j = 0; j < data2[i].range_count; j++) {
                diff_data[count].ranges[j] = data2[i].ranges[j];
            }
            count++;
        } else {
            int range_diff_count = 0;
            range_t *range_diff = ck_alloc(sizeof(range_t) * data2[i].range_count);
            
            for (int j = 0; j < data2[i].range_count; j++) {
                if (!range_in_array(&data2[i].ranges[j], found->ranges, found->range_count)) {
                    range_diff[range_diff_count] = data2[i].ranges[j];
                    range_diff_count++;
                }
            }
            
            if (range_diff_count > 0) {
                diff_data[count].hash_key = ck_strdup((u8*)data2[i].hash_key);
                diff_data[count].range_count = range_diff_count;
                diff_data[count].ranges = range_diff;
                count++;
            } else {
                ck_free(range_diff);
            }
        }
    }
    
    *diff_count = count;
    
    if (count == 0) {
        ck_free(diff_data);
        return NULL;
    }
    
    return diff_data;
}

static void sort_ranges(range_t *ranges, int range_count) {
    if (!ranges || range_count <= 1) {
        return;
    }
    
    for (int i = 0; i < range_count - 1; i++) {
        for (int j = 0; j < range_count - i - 1; j++) {
            if (ranges[j].begin > ranges[j + 1].begin) {
                range_t temp = ranges[j];
                ranges[j] = ranges[j + 1];
                ranges[j + 1] = temp;
            }
        }
    }
}

range_t* merge_ranges(range_t *ranges, int range_count, int *merged_count) {
    if (range_count <= 0) {
        *merged_count = 0;
        return NULL;
    }
    
    sort_ranges(ranges, range_count);
    
    range_t *merged = ck_alloc(sizeof(range_t) * range_count);
    int merge_count = 0;
    
    merged[0] = ranges[0];
    merge_count = 1;
    
    for (int i = 1; i < range_count; i++) {
        if (ranges[i].begin <= merged[merge_count - 1].end + 1) {
            if (ranges[i].end > merged[merge_count - 1].end) {
                merged[merge_count - 1].end = ranges[i].end;
            }
        } else {
            merged[merge_count] = ranges[i];
            merge_count++;
        }
    }
    
    *merged_count = merge_count;
    return merged;
}

bb_taint_seg_t* merge_all_ranges_in_difference(bb_taint_seg_t *diff_data, int diff_count) {
    if (!diff_data || diff_count <= 0) {
        return NULL;
    }
    
    bb_taint_seg_t *merged_data = ck_alloc(sizeof(bb_taint_seg_t) * diff_count);
    
    for (int i = 0; i < diff_count; i++) {
        merged_data[i].hash_key = ck_strdup((u8*)diff_data[i].hash_key);
        
        int merged_count;
        merged_data[i].ranges = merge_ranges(diff_data[i].ranges, 
                                           diff_data[i].range_count, 
                                           &merged_count);
        merged_data[i].range_count = merged_count;
    }
    
    return merged_data;
}

u8* get_source_filename(const u8 *seed_filename, const u8 *queue_dir) {
    if (!seed_filename || !queue_dir) {
        return NULL;
    }
    
    u8 *src_pos = strstr((char*)seed_filename, "src:");
    if (!src_pos) {
        char *last_slash = strrchr((char*)seed_filename, '/');
        if (last_slash) {
            return ck_strdup((u8*)(last_slash + 1));
        } else {
            return ck_strdup(seed_filename);
        }
    }
    
    u32 src_id;
    if (sscanf(src_pos, "src:%06u", &src_id) != 1) {
        return ck_strdup(seed_filename);
    }
    
    u8 *pattern = alloc_printf("id:%06u,", src_id);
    if (!pattern) {
        return ck_strdup(seed_filename);
    }
    
    DIR *dir = opendir((char*)queue_dir);
    if (!dir) {
        ck_free(pattern);
        return ck_strdup(seed_filename);
    }
    
    struct dirent *entry;
    u8 *source_filename = NULL;
    
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, (char*)pattern, strlen((char*)pattern)) == 0) {
            source_filename = alloc_printf("%s/%s", queue_dir, entry->d_name);
            break;
        }
    }
    
    closedir(dir);
    ck_free(pattern);
    
    if (source_filename) {
        char *last_slash = strrchr((char*)source_filename, '/');
        u8 *result;
        if (last_slash) {
            result = ck_strdup((u8*)(last_slash + 1));
        } else {
            result = ck_strdup(source_filename);
        }
        ck_free(source_filename);  
        return result;
    } else {
        return ck_strdup(seed_filename);
    }
}

u8* extract_bytes_from_ranges(u8 *out_buf, int out_buf_len, range_t *ranges, int range_count, int *extracted_len) {
    if (!out_buf || out_buf_len <= 0 || !ranges || range_count <= 0 || !extracted_len) {
        *extracted_len = 0;
        return NULL;
    }
    
    int total_bytes = 0;
    for (int i = 0; i < range_count; i++) {
        int begin = ranges[i].begin;
        int end = ranges[i].end;
        if (begin >= 0 && end >= begin && end <= out_buf_len) {  
            total_bytes += (end - begin);  
        }
    }
    
    if (total_bytes <= 0) {
        *extracted_len = 0;
        return NULL;
    }
    
    u8 *extracted_buf = ck_alloc(total_bytes);
    if (!extracted_buf) {
        *extracted_len = 0;
        return NULL;
    }

    int offset = 0;
    for (int i = 0; i < range_count; i++) {
        int begin = ranges[i].begin;
        int end = ranges[i].end;
        
        if (begin >= 0 && end >= begin && end <= out_buf_len) {  
            for (int j = begin; j < end; j++) {  
                extracted_buf[offset++] = out_buf[j];
            }
        }
    }
    
    *extracted_len = total_bytes;
    return extracted_buf;
}

void restore_bytes_to_ranges(u8 *out_buf, u8 *extracted_buf, int extracted_buf_len, range_t *ranges, int range_count) {
    if (!out_buf || !extracted_buf || extracted_buf_len <= 0 || !ranges || range_count <= 0) {
        return;
    }
    
    int total_bytes = 0;
    for (int i = 0; i < range_count; i++) {
        int begin = ranges[i].begin;
        int end = ranges[i].end;
        if (begin >= 0 && end >= begin) {
            total_bytes += (end - begin);
        }
    }
    
    if (total_bytes > extracted_buf_len) {
        return;
    }
    
    int offset = 0;
    for (int i = 0; i < range_count; i++) {
        int begin = ranges[i].begin;
        int end = ranges[i].end;
        
        if (begin >= 0 && end >= begin) {
            for (int j = begin; j < end; j++) {  
                if (offset < extracted_buf_len) {
                    out_buf[j] = extracted_buf[offset++];
                } else {
                    return;
                }
            }
        }
    }
}

