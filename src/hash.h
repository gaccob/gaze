#ifndef HASH_H_
#define HASH_H_

#include <stdint.h>

typedef uint32_t (*hash_func)(const void*);
typedef int32_t (*hash_cmp_func)(const void*, const void*);
typedef void (*hash_loop_func)(void* data, void* args);
struct hash_t;

struct hash_t* hash_create(hash_func hash, hash_cmp_func cmp, int32_t hint_size);
int32_t hash_release(struct hash_t* htable);

int32_t hash_clean(struct hash_t* htable);
int32_t hash_insert(struct hash_t* htable, void* data);
int32_t hash_remove(struct hash_t* htable, void* data);
int32_t hash_count(struct hash_t* htable);
void hash_loop(struct hash_t* htable, hash_loop_func func, void* args);
void* hash_find(struct hash_t* htable, void* data);

uint32_t hash_jhash(const void* key, uint32_t length);

#endif
