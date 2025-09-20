

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "hashmap.h"

#define HASHMAP_STR_INIT_SIZE 128
#define HASHMAP_INT_INIT_SIZE 128


static unsigned long hash_str(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}


static unsigned long hash_int64(uint64_t key) {
    // Knuth's multiplicative method
    return (unsigned long)(key * 2654435761UL);
}



hashmap_str_t *hashmap_str_create(size_t size) {
    hashmap_str_t *map = (hashmap_str_t *)malloc(sizeof(hashmap_str_t));
    if (!map) return NULL;
    map->size = size ? size : HASHMAP_STR_INIT_SIZE;
    map->count = 0;
    map->buckets = (hashmap_str_entry_t **)calloc(map->size, sizeof(hashmap_str_entry_t *));
    if (!map->buckets) {
        free(map);
        return NULL;
    }
    return map;
}

void hashmap_str_free(hashmap_str_t *map) {
    if (!map) return;
    for (size_t i = 0; i < map->size; ++i) {
        hashmap_str_entry_t *entry = map->buckets[i];
        while (entry) {
            hashmap_str_entry_t *next = entry->next;
            free(entry->key);
            free(entry);
            entry = next;
        }
    }
    free(map->buckets);
    free(map);
}

int hashmap_str_put(hashmap_str_t *map, const char *key, int value) {
    if (!map || !key) return -1;
    unsigned long hash = hash_str(key) % map->size;
    hashmap_str_entry_t *entry = map->buckets[hash];
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            entry->value = value;
            return 0;
        }
        entry = entry->next;
    }
    entry = (hashmap_str_entry_t *)malloc(sizeof(hashmap_str_entry_t));
    if (!entry) return -1;
    entry->key = strdup(key);
    entry->value = value;
    entry->next = map->buckets[hash];
    map->buckets[hash] = entry;
    map->count++;
    return 0;
}

int hashmap_str_get(hashmap_str_t *map, const char *key) {
    if (!map || !key) return -1;
    unsigned long hash = hash_str(key) % map->size;
    hashmap_str_entry_t *entry = map->buckets[hash];
    while (entry) {
        if (strcmp(entry->key, key) == 0)
            return entry->value;
        entry = entry->next;
    }
    return -1;
}

int hashmap_str_remove(hashmap_str_t *map, const char *key) {
    if (!map || !key) return -1;
    unsigned long hash = hash_str(key) % map->size;
    hashmap_str_entry_t *entry = map->buckets[hash];
    hashmap_str_entry_t *prev = NULL;
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            if (prev)
                prev->next = entry->next;
            else
                map->buckets[hash] = entry->next;
            free(entry->key);
            free(entry);
            map->count--;
            return 0;
        }
        prev = entry;
        entry = entry->next;
    }
    return -1;
}



hashmap_int_t *hashmap_int_create(size_t size) {
    hashmap_int_t *map = (hashmap_int_t *)malloc(sizeof(hashmap_int_t));
    if (!map) return NULL;
    map->size = size ? size : HASHMAP_INT_INIT_SIZE;
    map->count = 0;
    map->buckets = (hashmap_int_entry_t **)calloc(map->size, sizeof(hashmap_int_entry_t *));
    if (!map->buckets) {
        free(map);
        return NULL;
    }
    return map;
}

void hashmap_int_free(hashmap_int_t *map) {
    if (!map) return;
    for (size_t i = 0; i < map->size; ++i) {
        hashmap_int_entry_t *entry = map->buckets[i];
        while (entry) {
            hashmap_int_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
    }
    free(map->buckets);
    free(map);
}

int hashmap_int_put(hashmap_int_t *map, uint64_t key, int value) {
    if (!map) return -1;
    unsigned long hash = hash_int64(key) % map->size;
    hashmap_int_entry_t *entry = map->buckets[hash];
    while (entry) {
        if (entry->key == key) {
            entry->value = value;
            return 0;
        }
        entry = entry->next;
    }
    entry = (hashmap_int_entry_t *)malloc(sizeof(hashmap_int_entry_t));
    if (!entry) return -1;
    entry->key = key;
    entry->value = value;
    entry->next = map->buckets[hash];
    map->buckets[hash] = entry;
    map->count++;
    return 0;
}

int hashmap_int_get(hashmap_int_t *map, uint64_t key) {
    if (!map) return -1;
    unsigned long hash = hash_int64(key) % map->size;
    hashmap_int_entry_t *entry = map->buckets[hash];
    while (entry) {
        if (entry->key == key)
            return entry->value;
        entry = entry->next;
    }
    return -1;
}

int hashmap_int_remove(hashmap_int_t *map, uint64_t key) {
    if (!map) return -1;
    unsigned long hash = hash_int64(key) % map->size;
    hashmap_int_entry_t *entry = map->buckets[hash];
    hashmap_int_entry_t *prev = NULL;
    while (entry) {
        if (entry->key == key) {
            if (prev)
                prev->next = entry->next;
            else
                map->buckets[hash] = entry->next;
            free(entry);
            map->count--;
            return 0;
        }
        prev = entry;
        entry = entry->next;
    }
    return -1;
}
