
#ifndef HASHMAP_H
#define HASHMAP_H

#include <stdint.h>
#include <stddef.h>


typedef struct hashmap_str_entry {
    char *key;
    int value;
    struct hashmap_str_entry *next;
} hashmap_str_entry_t;

typedef struct {
    hashmap_str_entry_t **buckets;
    size_t size;
    size_t count;
} hashmap_str_t;


typedef struct hashmap_int_entry {
    uint64_t key;
    int value;
    struct hashmap_int_entry *next;
} hashmap_int_entry_t;

typedef struct {
    hashmap_int_entry_t **buckets;
    size_t size;
    size_t count;
} hashmap_int_t;


hashmap_str_t *hashmap_str_create(size_t size);
void hashmap_str_free(hashmap_str_t *map);
int hashmap_str_put(hashmap_str_t *map, const char *key, int value);
int hashmap_str_get(hashmap_str_t *map, const char *key);
int hashmap_str_remove(hashmap_str_t *map, const char *key);


hashmap_int_t *hashmap_int_create(size_t size);
void hashmap_int_free(hashmap_int_t *map);
int hashmap_int_put(hashmap_int_t *map, uint64_t key, int value);
int hashmap_int_get(hashmap_int_t *map, uint64_t key);
int hashmap_int_remove(hashmap_int_t *map, uint64_t key);

#endif // HASHMAP_H

