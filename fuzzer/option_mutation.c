#include "option_mutation.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <math.h>
#include <signal.h>
#include "alloc-inl.h"
#include "debug.h"
#include "hashmap.h"
#include "types.h"

struct div_option_map dom;
struct option option_list[MAX_OPTION_NAME_COUNT];
u32 option_list_size = 0;

hashmap_str_t *option_div_map;

int max_option_distance = 0;
int min_option_distance = INT_MAX;

int continuoused(u8 datatype) {
  return datatype == INT_TYPE || datatype == DOUBLE_TYPE || datatype == STRING_TYPE;
}

cJSON *get_json(const u8 *path) {
  cJSON *cjson_head;
  s32 fd;
  u8 *in_buf;
  struct stat st;
  s32 n;
  if (lstat((const char*)path, &st)) {
    PFATAL("Lstat read '%s'", path);
  }
  fd = open((const char*)path, O_RDONLY);
  if (fd < 0) {
    PFATAL("open failed '%s' errno is %d, %s, fd is %d",
            path, errno, strerror(errno), fd);
  }
  in_buf = ck_alloc(st.st_size);
  n = read(fd, in_buf, st.st_size);
  if (n < st.st_size) {
    PFATAL("Short read '%s' n is %d, size is %ld, errno is %d, %s, fd is %d", path, n, st.st_size, errno, strerror(errno), fd);
  }
  cjson_head = cJSON_ParseWithLength((const char*)in_buf, st.st_size);
  // if (cjson_head == NULL) {
  //   PFATAL("Unable to parse '%s'", path);
  // }
  close(fd);
  ck_free(in_buf);
  return cjson_head;
}



void read_option_list(const u8 *option_list_path) {
    cJSON *cjson_head = get_json(option_list_path);
    if (cjson_head == NULL) {
        PFATAL("Failed to parse JSON from option_list_path");
    }

    if (!cJSON_IsArray(cjson_head)) {
        cJSON_Delete(cjson_head);
        PFATAL("JSON root is not an array");
    }

    u32 size = cJSON_GetArraySize(cjson_head);
    if (size > MAX_OPTION_NAME_COUNT) {
        cJSON_Delete(cjson_head);
        PFATAL("Too many options in option list: %u", size);
    }

    for (u32 i = 0; i < size; i++) {
        cJSON *option_item = cJSON_GetArrayItem(cjson_head, i);
        if (!cJSON_IsObject(option_item)) continue;

        struct option opt;
        memset(&opt, 0, sizeof(struct option));

        cJSON *option_name_json = cJSON_GetObjectItemCaseSensitive(option_item, "option_name");
        if (cJSON_IsString(option_name_json) && option_name_json->valuestring != NULL) {
            size_t name_len = strlen(option_name_json->valuestring);
            opt.option_name = (u8*)ck_alloc(name_len + 1);
            strcpy((char*)opt.option_name, option_name_json->valuestring);
        } else {
            opt.option_name = NULL;
        }

        cJSON *need_value_json = cJSON_GetObjectItemCaseSensitive(option_item, "need_value");
        opt.need_value = cJSON_IsTrue(need_value_json) ? 1 : 0;

        cJSON *str_template_json = cJSON_GetObjectItemCaseSensitive(option_item, "str_template");
        if (cJSON_IsString(str_template_json) && str_template_json->valuestring != NULL) {
            size_t str_template_len = strlen(str_template_json->valuestring);
            opt.str_template = (u8*)ck_alloc(str_template_len + 1);
            strcpy((char*)opt.str_template, str_template_json->valuestring);
            // printf("str_template = %s \n", str_template_json->valuestring);
        } else {
            opt.str_template = NULL;
            // printf("not str_template\n");
        }

        cJSON *data_type_json = cJSON_GetObjectItemCaseSensitive(option_item, "data_type");
        if (cJSON_IsString(data_type_json)) {
            opt.data_type = 0; 
        } else if (cJSON_IsNumber(data_type_json)) {
            opt.data_type = (u8)data_type_json->valueint;
        }

        cJSON *candidates_array = cJSON_GetObjectItemCaseSensitive(option_item, "candidates_list");
        if (cJSON_IsArray(candidates_array)) {
            u32 candidates_size = cJSON_GetArraySize(candidates_array);
            if (candidates_size > 0) {
                opt.candidates_list = (u8**)ck_alloc(candidates_size * sizeof(u8*));
                opt.candidate_count = 0;
                
                for (u32 j = 0; j < candidates_size; j++) {
                    cJSON *candidate_item = cJSON_GetArrayItem(candidates_array, j);
                    if (cJSON_IsString(candidate_item) && candidate_item->valuestring != NULL) {
                        size_t candidate_len = strlen(candidate_item->valuestring);
                        opt.candidates_list[opt.candidate_count] = (u8*)ck_alloc(candidate_len + 1);
                        strcpy((char*)opt.candidates_list[opt.candidate_count], candidate_item->valuestring);
                        opt.candidate_count++;
                    }
                }
            } else {
                opt.candidates_list = NULL;
                opt.candidate_count = 0;
            }
        }

        opt.distance = 0.0;

        if (option_list_size < MAX_OPTION_NAME_COUNT) {
            option_list[option_list_size++] = opt;
        } else {
            if (opt.option_name) ck_free(opt.option_name);
            if (opt.candidates_list) {
                for (u32 k = 0; k < opt.candidate_count; k++) {
                    ck_free(opt.candidates_list[k]);
                }
                ck_free(opt.candidates_list);
            }
            PFATAL("option_list_size exceeds MAX_OPTION_NAME_COUNT");
        }
    }

    cJSON_Delete(cjson_head);
}

struct div_option_map *generate_div_option_map(const u8 *div_2_option_path) {
  if (div_2_option_path == NULL) {
    PFATAL("div_2_option_path is NULL");
  }

  struct div_option_map *div_option_map = ck_alloc(sizeof(struct div_option_map));
  
  div_option_map->size = 0;
  for (int i = 0; i < MAX_OPTION_NAME_COUNT; i++) {
    div_option_map->option_div_map[i].size = 0;
  }

  cJSON *div_id_json = get_json(div_2_option_path);
  if (div_id_json == NULL) {
    PFATAL("Failed to parse JSON from div_2_option_path");
  }
  
  cJSON *item = NULL;
  cJSON_ArrayForEach(item, div_id_json) {
      if (!cJSON_IsArray(item)) continue;
      
      int div_id = atoi(item->string);
      if (div_id < 0 || div_id >= MAX_OPTION_NAME_COUNT) {
        PFATAL("div_id %d is out of range", div_id);
      }
      
      
      int arr_size = cJSON_GetArraySize(item);
      for (int i = 0; i < arr_size; i++) {
        cJSON *opt = cJSON_GetArrayItem(item, i);
        if (cJSON_IsString(opt)) {
          if (div_option_map->option_div_map[div_id].size >= MAX_ONE_DIV_OPTION_COUNT) {
            PFATAL("Too many options for div_id %d", div_id);
          }
          
          u8 *option_name = ck_alloc(strlen(opt->valuestring) + 1);
          if (option_name == NULL) {
            PFATAL("Failed to allocate memory for option name");
          }
          strcpy((char*)option_name, opt->valuestring);
          
          div_option_map->option_div_map[div_id].option_name[div_option_map->option_div_map[div_id].size] = option_name;
          div_option_map->option_div_map[div_id].size++;
        }
      }
      
      if (div_id >= div_option_map->size) {
        div_option_map->size = div_id + 1;
        if (div_option_map->size > MAX_OPTION_NAME_COUNT) {
          PFATAL("div_option_map size exceeds MAX_OPTION_NAME_COUNT");
        }
      }
  }
  
  cJSON_Delete(div_id_json);
  return div_option_map;
}

hashmap_str_t *generate_option_div_map(struct div_option_map *dom) {
  hashmap_str_t *option_div_map = hashmap_str_create(dom->size);
  for (int i = 0; i < dom->size; i++) {
    for (int j = 0; j < dom->option_div_map[i].size; j++) {
      hashmap_str_put(option_div_map, dom->option_div_map[i].option_name[j], i);
    }
  }
  return option_div_map;
}

void free_div_option_map(struct div_option_map *dom) {
  if (dom == NULL) return;
  
  for (int i = 0; i < dom->size; i++) {
    for (int j = 0; j < dom->option_div_map[i].size; j++) {
      if (dom->option_div_map[i].option_name[j]) {
        ck_free(dom->option_div_map[i].option_name[j]);
      }
    }
  }
  ck_free(dom);
}

struct option_candidate_list *generate_candidate_option_list(const u8 *taint_analysis_path, 
  const u8 *source_taint_analysis_path, const char **argv, u8 *conflict_option) {

  if (taint_analysis_path == NULL) {
    PFATAL("taint_analysis_path is NULL");
    return NULL;
  }
  
  FILE *fp = fopen((const char *)taint_analysis_path, "r");
  if (fp == NULL) {
    return NULL;
  }
  fclose(fp);
  
  hashmap_int_t *souce_bb_hash = hashmap_int_create(1024);

  // read conflict options
  cJSON *conflict_option_root = get_json(conflict_option);
  int conflict_option_size = cJSON_GetArraySize(conflict_option_root);
  char **conflict_option_array = (char**)malloc(sizeof(char*) * conflict_option_size);
  for (int i = 0; i < conflict_option_size; i++) {
      cJSON *item = cJSON_GetArrayItem(conflict_option_root, i);
      if (cJSON_IsString(item)) {
          conflict_option_array[i] = (char*)malloc(strlen(item->valuestring) + 1);
          strcpy(conflict_option_array[i], item->valuestring);
      }
  }

  if (source_taint_analysis_path) {
    FILE *fp = fopen((const char *)source_taint_analysis_path, "r");
    if (fp == NULL) {
      return NULL;
    }
    fclose(fp);
    cJSON *souce_cjson_head = get_json(source_taint_analysis_path);
    // read json file into div_list
    cJSON *source_variable_item = NULL;
    cJSON *souce_variable_usages_json = cJSON_GetObjectItemCaseSensitive(source_variable_item, "variable_usages");
    cJSON_ArrayForEach(source_variable_item, souce_variable_usages_json) {
      if (!cJSON_IsArray(source_variable_item)) continue;
      char *variable_id = source_variable_item->string;
      // extract the number part of variable_id, e.g. "id_8" -> 8
      int variable_num = -1;
      if (variable_id != NULL) {
        char *underscore = strchr((const char *)variable_id, '_');
        if (underscore != NULL) {
          variable_num = atoi(underscore + 1);
        }
      }
      if (variable_num < 0 || variable_num >= MAX_OPTION_NAME_COUNT) {
        cJSON_Delete(source_variable_item);
        ck_free(source_variable_item);
        PFATAL("variable_num %d is out of range", variable_num);
      }

      int usage_count = cJSON_GetArraySize(source_variable_item);

      
      for (int i = 0; i < usage_count; i++) {
        cJSON *usage_info = cJSON_GetArrayItem(source_variable_item, i);
        if (!cJSON_IsObject(usage_info)) continue;
        
        cJSON *bb_hash_json = cJSON_GetObjectItemCaseSensitive(usage_info, "bb_hash");
        if (bb_hash_json && cJSON_IsNumber(bb_hash_json)) {
          u64 bb_hash = (u64)bb_hash_json->valuedouble;
          hashmap_int_put(souce_bb_hash, bb_hash, 1);
        }
      }
    }
  }


  struct div_list_ty *div_list = ck_alloc(sizeof(struct div_list_ty));
  
  div_list->size = 0;
  for (int i = 0; i < MAX_OPTION_NAME_COUNT; i++) {
    div_list->div_list[i].min_distance = INT_MAX;
    div_list->div_list[i].conditional_count = 0;
    div_list->div_list[i].use_count = 0;
    div_list->div_list[i].use_bb_count = 0;
    div_list->div_list[i].used = 0;
    div_list->div_list[i].isDeleted = 0;
    div_list->div_list[i].bb_hash = 0;
  }
  
  int all_bb_count = 0;
  cJSON *cjson_head = get_json(taint_analysis_path);
  if (cjson_head == NULL) {
    ck_free(div_list);
    PFATAL("Failed to parse JSON from taint_analysis_path");
  }

  cJSON *variable_usages_json = cJSON_GetObjectItemCaseSensitive(cjson_head, "variable_usages");
  if (variable_usages_json == NULL) {
    cJSON_Delete(cjson_head);
    ck_free(div_list);
    PFATAL("variable_usages_json is NULL");
  }
  
  // read json file into div_list
  cJSON *variable_item = NULL;
  cJSON_ArrayForEach(variable_item, variable_usages_json) {
    if (!cJSON_IsArray(variable_item)) continue;
    char *variable_id = variable_item->string;
    // extract the number part of variable_id, e.g. "id_8" -> 8
    int variable_num = -1;
    if (variable_id != NULL) {
      char *underscore = strchr((const char *)variable_id, '_');
      if (underscore != NULL) {
        variable_num = atoi(underscore + 1);
      }
    }
    if (variable_num < 0 || variable_num >= MAX_OPTION_NAME_COUNT) {
      cJSON_Delete(cjson_head);
      ck_free(div_list);
      PFATAL("variable_num %d is out of range", variable_num);
    }

    int usage_count = cJSON_GetArraySize(variable_item);
    struct div_ty *div = &div_list->div_list[variable_num];
    div->used = 0;
    if (variable_num > div_list->size) {
      div_list->size = variable_num;
    }
    
    for (int i = 0; i < usage_count; i++) {
      cJSON *usage_info = cJSON_GetArrayItem(variable_item, i);
      if (!cJSON_IsObject(usage_info)) continue;
      
      cJSON *bb_hash_json = cJSON_GetObjectItemCaseSensitive(usage_info, "bb_hash");
      cJSON *distance_json = cJSON_GetObjectItemCaseSensitive(usage_info, "distance");
      cJSON *conditional_json = cJSON_GetObjectItemCaseSensitive(usage_info, "conditional");
      cJSON *count_json = cJSON_GetObjectItemCaseSensitive(usage_info, "count");
      
      if (bb_hash_json && cJSON_IsNumber(bb_hash_json) &&
          distance_json && cJSON_IsNumber(distance_json) &&
          conditional_json && cJSON_IsBool(conditional_json) &&
          count_json && cJSON_IsNumber(count_json)) {
        
        u64 bb_hash = (u64)bb_hash_json->valuedouble;
        int distance = distance_json->valueint;
        int conditional = cJSON_IsTrue(conditional_json);
        int count = count_json->valueint;

        
        if (distance == -1) {
          continue;
        }
        div->used = 1;
        
        if (distance < div->min_distance) {
          div->min_distance = distance;
        }

        div->conditional_count += conditional;
        div->use_count += count;
        div->use_bb_count++;
        div->bb_hash = bb_hash;
        div->isDeleted = hashmap_int_get(souce_bb_hash, bb_hash) == -1;
        all_bb_count++;
      }
    }
  }
  
  if (option_list_size > MAX_OPTION_NAME_COUNT) {
    cJSON_Delete(cjson_head);
    ck_free(div_list);
    PFATAL("option_list_size %d exceeds MAX_OPTION_NAME_COUNT", option_list_size);
  }

  struct option_candidate_list *candidate_list = ck_alloc(sizeof(struct option_candidate_list));
  if (candidate_list == NULL) {
    cJSON_Delete(cjson_head);
    ck_free(div_list);
    PFATAL("Failed to allocate memory for option_candidate_list");
  }
  candidate_list->size = 0;

  candidate_list->candidate_list = ck_alloc(MAX_OPTION_NAME_COUNT * sizeof(struct option));
  if (candidate_list->candidate_list == NULL) {
    cJSON_Delete(cjson_head);
    ck_free(div_list);
    ck_free(candidate_list);
    PFATAL("Failed to allocate memory for candidate_list array");
  }

  struct option *candidate_options = candidate_list->candidate_list;
  
  for (int i = 0 ; i < option_list_size ; i++) {
    struct option *opt = &option_list[i];
    // check conflict
    for (int j = 0 ; j < conflict_option_size ; j++) {
      if (!strcmp(opt->option_name, conflict_option_array[j])) {
        continue;
      }
    }
    int used = 0;
    char **argvp = argv;
    // pass cur_option
    while(*argvp) {
      if (strcmp(*argvp, (char*)opt->option_name) == 0) {
        used = 1;
        break;
      }
      argvp++;
    }
    if (used) continue;
    u8 *current_option_name = opt->option_name;
    double distance_total = 0;
    double delta_distance_total = 0;
    int div_count;
    int delta_div_count;
    int flag = 0; 
    int delta_flag = 0;
    for (int j = 0 ; j < dom.size ; j++) { 
      for (int k = 0 ; k < dom.option_div_map[j].size ; k++) {
        // if find
        if (strcmp((char*)dom.option_div_map[j].option_name[k], (char*)current_option_name) == 0) {
          struct div_ty cur_div = div_list->div_list[j];
          if (cur_div.used == 0) {
            continue;
          }
          flag = 1;
          distance_total += cur_div.min_distance;
          div_count++;
          if (cur_div.isDeleted) {
            delta_distance_total += cur_div.min_distance;
            delta_div_count++;
            delta_flag = 1;
          }
        }
      }
    }
    if (flag) {
      if (candidate_list->size >= MAX_OPTION_NAME_COUNT) {
        cJSON_Delete(cjson_head);
        ck_free(div_list);
        free_option_candidate_list(candidate_list);
        PFATAL("Too many candidate options");
      }

      double distance = delta_flag ? (delta_distance_total / delta_div_count) : (distance_total / div_count);
      min_option_distance = MIN(min_option_distance, distance);
      max_option_distance = MAX(max_option_distance, distance);
      // calculate score
      struct option *temp_opt = copy_option(opt, distance);
      candidate_options[candidate_list->size++] = *temp_opt;
      ck_free(temp_opt);
    }
  }
  
  ck_free(div_list);
  
  cJSON_Delete(cjson_head);
  return candidate_list;
}

struct option *find_option_in_option_list(u8 *option_name) {
  for (int i = 0; i < option_list_size; i++) {
    if (option_list[i].option_name && strcmp((char*)option_list[i].option_name, (char*)option_name) == 0) {
      return &option_list[i];
    }
  }
  return NULL;
}

/* will exclued argv options */
struct option_candidate_list *copy_option_candidate_list(struct option_candidate_list *src, u8 **argv) {
  if (src == NULL) return NULL;
  
  struct option_candidate_list *dst = ck_alloc(sizeof(struct option_candidate_list));
  if (dst == NULL) {
    PFATAL("Failed to allocate memory for option_group_list copy");
  }
  
  dst->size = 0;  
  
  
  dst->candidate_list = ck_alloc(MAX_OPTION_NAME_COUNT * sizeof(struct option));
  if (dst->candidate_list == NULL) {
    ck_free(dst);
    PFATAL("Failed to allocate memory for candidate_list array in copy");
  }
  
  
  for (u32 i = 0; i < src->size; i++) {
    if (argv != NULL) {
      int skip = 0;
      for (u32 arg_idx = 0; argv[arg_idx] != NULL; arg_idx++) {
       
        if (src->candidate_list[i].option_name &&
            strcmp((char*)src->candidate_list[i].option_name, (char*)argv[arg_idx]) == 0) {
          skip = 1;
          break;
        }
        
        if (skip) break;
      }
      if (skip) {
        continue;
      }
    }
    

    struct option *src_opt = &src->candidate_list[i];
    struct option *dst_opt = &dst->candidate_list[dst->size];
    
    dst_opt->need_value = src_opt->need_value;
    dst_opt->data_type = src_opt->data_type;
    dst_opt->candidate_count = src_opt->candidate_count;
    dst_opt->distance = src_opt->distance;
    
    if (src_opt->option_name) {
      dst_opt->option_name = ck_alloc(strlen((char*)src_opt->option_name) + 1);
      strcpy((char*)dst_opt->option_name, (char*)src_opt->option_name);
    } else {
      dst_opt->option_name = NULL;
    }
    
    if (src_opt->candidates_list && src_opt->candidate_count > 0) {
      dst_opt->candidates_list = ck_alloc(src_opt->candidate_count * sizeof(u8*));
      for (u32 k = 0; k < src_opt->candidate_count; k++) {
        if (src_opt->candidates_list[k]) {
          dst_opt->candidates_list[k] = ck_alloc(strlen((char*)src_opt->candidates_list[k]) + 1);
          strcpy((char*)dst_opt->candidates_list[k], (char*)src_opt->candidates_list[k]);
        } else {
          dst_opt->candidates_list[k] = NULL;
        }
      }
    } else {
      dst_opt->candidates_list = NULL;
    }

    dst->size++;
  }
  
  return dst;
}

struct option *find_option_in_candidate_list(u8 *option_name, struct option_candidate_list* candidate_list) {
  if (candidate_list == NULL) return NULL;
  for (int i = 0; i < candidate_list->size; i++) {
    if (candidate_list->candidate_list[i].option_name == NULL) continue;
    if (strcmp(candidate_list->candidate_list[i].option_name, (char*)option_name) == 0) {
      return &candidate_list->candidate_list[i];
    }
  }
  return NULL;
}


struct option *copy_option(struct option *opt, double score) {
  if (opt == NULL) {
    PFATAL("opt is NULL in copy_option");
  }
  
  struct option *new_opt = ck_alloc(sizeof(struct option));
  if (new_opt == NULL) {
    PFATAL("Failed to allocate memory for new_opt");
  }
  new_opt->distance = score;
  
  if (opt->option_name == NULL) {
    ck_free(new_opt);
    PFATAL("opt->option_name is NULL");
  }
  new_opt->option_name = ck_alloc(strlen((char*)opt->option_name) + 1);
  if (new_opt->option_name == NULL) {
    ck_free(new_opt);
    PFATAL("Failed to allocate memory for option_name");
  }
  strcpy((char*)new_opt->option_name, (char*)opt->option_name);
  
  new_opt->need_value = opt->need_value;
  new_opt->data_type = opt->data_type;
  new_opt->candidate_count = opt->candidate_count;
  new_opt->str_template = opt->str_template;
  
  if (opt->candidates_list) {
    new_opt->candidates_list = ck_alloc(opt->candidate_count * sizeof(u8*));
    for (int i = 0; i < opt->candidate_count; i++) {
      if (opt->candidates_list[i]) {
        new_opt->candidates_list[i] = ck_alloc(strlen((char*)opt->candidates_list[i]) + 1);
        strcpy((char*)new_opt->candidates_list[i], (char*)opt->candidates_list[i]);
      } else {
        new_opt->candidates_list[i] = NULL;
      }
    }
  } else {
    new_opt->candidates_list = NULL;
  }
  
  return new_opt;
}

u8* single_option_mutation(struct option *opt) {
  
  if (!opt) return NULL;
  int allocated_size = 64;
  char *value_str = ck_alloc(allocated_size * sizeof(char));
  
  switch (opt->data_type) {
    case 0: // INT_TYPE
      {
        int value = generate_random_int(INT_MIN, INT_MAX);
        snprintf(value_str, allocated_size, "%d", value);
      }
      break;
    case 1: // DOUBLE_TYPE
      {
        double value = ((double)generate_random_int(0, 1000000) / 1000000.0) * 1000;
        snprintf(value_str, allocated_size, "%.2f", value);
      }
      break;
    case 2: // BOOL_TYPE
      {
        int value = generate_random_int(0, 1);
        snprintf(value_str, allocated_size, "%d", value);
      }
      break;
    case 3: // ENUM_TYPE
      {
        if (opt->candidate_count > 0) {
          u32 candidate_index = generate_random_int(0, opt->candidate_count - 1);
          if (candidate_index < opt->candidate_count && opt->candidates_list[candidate_index]) {
            snprintf(value_str, allocated_size, "%s", opt->candidates_list[candidate_index]);
          } else {
            strcpy(value_str, "default_value");
          }
        } else {
          int value = generate_random_int(INT_MIN, INT_MAX);
          snprintf(value_str, allocated_size, "%d", value);
        }
      }
      break;              
    case 4: // STRING_TYPE
      {
        if (opt->str_template != NULL) {
          char* parameter = regex_generate(opt->str_template);
          snprintf(value_str, allocated_size, "%s", parameter);
        } else {
          strcpy(value_str, "random_string");
        }
        
      }
      break;
    default:
      {
        int value = generate_random_int(INT_MIN, INT_MAX);
        snprintf(value_str, allocated_size, "%d", value);
      }
  }
  
  return value_str;
}



u8** option_havoc_mutation(struct option_candidate_list *candidate_list, u32 *argc) {
  

  *argc = 0;
  
  if (!candidate_list) return NULL;

  u8** args = ck_alloc(MAX_CMDLINE_PAR * sizeof(u8*));
  memset(args, 0, MAX_CMDLINE_PAR * sizeof(u8*));
  
  u32 num_options = candidate_list->size;
  
  if (num_options == 0) {
    args[0] = ck_alloc(15); 
    strcpy((char*)args[0], "default_option");
    *argc = 1;
    return args;
  }
  
  for (u32 i = 0; i < candidate_list->size && *argc < MAX_CMDLINE_PAR - 1; i++) {

    int may_pass = generate_random_int(0, 100) / 50;

    if(may_pass &&  candidate_list->size != 1) continue;
    
    struct option* opt = &candidate_list->candidate_list[i];
    if (!opt || !opt->option_name) continue;
    

    char option_str[256];
    option_str[0] = '\0';
    
    if (opt->option_name) {
      snprintf(option_str, sizeof(option_str), "%s", opt->option_name);
      
      u32 option_len = strlen(option_str);
      args[*argc] = ck_alloc(option_len + 1);
      strcpy((char*)args[*argc], option_str);
      (*argc)++;
      
      /* if need value */
      if (opt->need_value && *argc < MAX_CMDLINE_PAR - 1) {
        char *value_str = single_option_mutation(opt);
        
        u32 value_len = strlen(value_str);
        args[*argc] = ck_alloc(value_len + 1);
        strcpy((char*)args[*argc], value_str);
        (*argc)++;
        
        ck_free(value_str);
      }
    }
  }
  
  if (*argc == 0) {
    args[0] = ck_alloc(15);
    strcpy((char*)args[0], " ");
    *argc = 1;
  }
  
  return args;
}


void free_option_candidate_list(struct option_candidate_list *opts) {
  if (opts == NULL) return;
  
  
  u32 size = opts->size;
  
  if (size == 0) {
    return;
  }
  
  for (u32 i = 0; i < size; i++) {
    struct option *opt = &opts->candidate_list[i];

    if (opt->option_name) {
      ck_free(opt->option_name);
      opt->option_name = NULL;
    }
    
    if (opt->candidates_list) {
      for (u32 k = 0; k < opt->candidate_count; k++) {
        if (opt->candidates_list[k]) {
          ck_free(opt->candidates_list[k]);
          opt->candidates_list[k] = NULL;
        }
      }
      ck_free(opt->candidates_list);
      opt->candidates_list = NULL;
    }
  }
  
  if (opts->candidate_list) {
    ck_free(opts->candidate_list);
    opts->candidate_list = NULL;
  }
  
  ck_free(opts);
}

void free_argv(u8 **argv, u32 argc) {
  if (argv == NULL) return;
  
  for (u32 i = 0; i < argc; i++) {
    if (argv[i]) {
      ck_free(argv[i]);
      argv[i] = NULL;
    }
  }
  ck_free(argv);
}

int assign_option_energy(double distance) {
  double score = (distance - min_option_distance) / (max_option_distance - min_option_distance);
  return MAX(500, DEFAULT_ENERGY * score); 
}

int assign_option_list_energy(struct option_candidate_list *opts) {
  int res = 0;
  for (int i = 0 ; i < opts->size ; i++) {
    res += assign_option_energy(opts->candidate_list[i].distance);
  }
  return res / opts->size;
}

int generate_random_int(int min, int max) {
    if (min > max) {
        return min; 
    }
    
    if (min == max) {
        return min; 
    }
    
    static int urandom_fd = -1;
    if (urandom_fd == -1) {
        urandom_fd = open("/dev/urandom", O_RDONLY);
        if (urandom_fd == -1) {
            long long ll_range = (long long)max - min + 1;
            long long ll_rand = (long long)rand() * ll_range / (RAND_MAX + 1LL);
            return (int)(min + ll_rand);
        }
    }
    
    unsigned int random_value;
    ssize_t result = read(urandom_fd, &random_value, sizeof(random_value));
    
    if (result != sizeof(random_value)) {
        long long ll_range = (long long)max - min + 1;
        long long ll_rand = (long long)rand() * ll_range / (RAND_MAX + 1LL);
        return (int)(min + ll_rand);
    }
    
    long long ll_range = (long long)max - min + 1;

    long long ll_rand = ((long long)random_value * ll_range) >> 32;
    
    return (int)(min + ll_rand);
}

void free_option(struct option *opt) {
    if (!opt) return;  

    if (opt->option_name) {
        ck_free(opt->option_name);
        opt->option_name = NULL;  
    }

    if (opt->candidates_list && opt->candidate_count > 0) {
        for (u32 i = 0; i < opt->candidate_count; i++) {
            if (opt->candidates_list[i]) {
                ck_free(opt->candidates_list[i]); 
                opt->candidates_list[i] = NULL;
            }
        }
        ck_free(opt->candidates_list);  
        opt->candidates_list = NULL;
        opt->candidate_count = 0;   
    }

}