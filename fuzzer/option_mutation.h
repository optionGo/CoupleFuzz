

#ifndef OPTION_MUTATION_H
#define OPTION_MUTATION_H

#include "types.h"
#include "cJSON.h"
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "regex.h"
#include "hashmap.h"


#define MAX_DIV_COUNT 50
#define MAX_OPTION_NAME_COUNT 50
#define MAX_ONE_DIV_OPTION_COUNT 32
#define MAX_CONFLICT_LIST_COUNT 5
#define MAX_DEPENDENT_LIST_COUNT 5
#define MAX_CMDLINE_PAR 32
#define DEFAULT_ENERGY 2000
enum {
    INT_TYPE,
    DOUBLE_TYPE,
    BOOL_TYPE,
    ENUM_TYPE,
    STRING_TYPE,
};

struct option {
    u8 *option_name;
    u8 need_value;
    u8 data_type;
    u8 **candidates_list;
    u32 candidate_count;
    u8 *str_template;
    double distance;
};


struct option_candidate_list {
    u32 size;
    struct option *candidate_list;
};


struct list {
    u32 size;
    u8 *option_name[MAX_ONE_DIV_OPTION_COUNT];
};

struct div_option_map {
    u32 size;
    // index: div_id value: option_list
    struct list option_div_map[MAX_DIV_COUNT];
};


struct div_ty {
    u32 min_distance;
    u32 conditional_count;
    u32 use_count;
    u32 use_bb_count;
    u8 used;
    u64 bb_hash;
    u8 isDeleted;
};

struct div_list_ty {
    u32 size;
    /*
    "bb_hash": 6511688456250617286,
    "distance": -1,
    "conditional": true,
    "count": 1
    */
    // index: div_id, value: div_ty
    struct div_ty div_list[MAX_DIV_COUNT];
};


extern struct div_option_map dom;
extern struct option option_list[MAX_OPTION_NAME_COUNT];
extern u32 option_list_size;

int continuoused(u8 datatype);
cJSON *get_json(const u8 *path);
void read_option_list(const u8 *option_list_path);
hashmap_str_t *generate_option_div_map(struct div_option_map *dom);
struct div_option_map *generate_div_option_map(const u8 *div_2_option_path);
void free_div_option_map(struct div_option_map *dom);
struct option_candidate_list *generate_candidate_option_list(const u8 *taint_analysis_path, const u8 *source_taint_analysis_path, const char **argv, u8 *conflict_option);
struct option *find_option_in_option_list(u8 *option_name);
struct option *copy_option(struct option *opt, double score);
// u8** option_group_mutation(struct option_group *group, u32 *argc);
u8* single_option_mutation(struct option *opt);
u8** option_havoc_mutation(struct option_candidate_list *candidate_list, u32 *argc);
int assign_option_energy(double score);
int assign_option_list_energy(struct option_candidate_list *opt);
// void free_option_group_list(struct option_group_list *ogl);
void free_option_candidate_list(struct option_candidate_list *opts);
void free_argv(u8 **argv, u32 argc);
void free_option(struct option *opt);
struct option_candidate_list *copy_option_candidate_list(struct option_candidate_list *src, u8 **argv);
struct option *find_option_in_candidate_list(u8 *option_name, struct option_candidate_list* candidate_list);


int generate_random_int(int min, int max);
#endif /* OPTION_MUTATION_H */
