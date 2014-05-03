#include <stdlib.h>
#include <string.h>

#include "link.h"
#include "hash.h"

typedef struct link_t {
    link_key_t key;
    link_value_t value;
} link_t;

static struct hash_t* g_links = NULL;

uint32_t
_link_hash(const void* data) {
    const link_t* link = (const link_t*)data;
    return hash_jhash((const void*)&link->key, sizeof(link_key_t));
}

int32_t
_link_cmp(const void* data1, const void* data2) {
    const link_t* link1 = (const link_t*)data1;
    const link_t* link2 = (const link_t*)data2;
    return memcmp(&link1->key, &link2->key, sizeof(link_key_t));
}

int
link_create() {
    g_links = hash_create(_link_hash, _link_cmp, GAZE_MAX_LINK_NUM);
    return g_links ? 0 : -1;
}

link_value_t*
link_find(link_key_t* key) {
    link_t link;
    link.key = *key;
    void* dst = hash_find(g_links, &link);
    if (dst) {
        return &((link_t*)dst)->value;
    }
    return NULL;
}

link_value_t*
link_insert(link_key_t* key) {
    link_t* link = (link_t*)malloc(sizeof(link_t));
    memset(link, 0, sizeof(link_t));
    link->key = *key;
    if (hash_insert(g_links, link)) {
        free(link);
        return NULL;
    }
    return &link->value;
}

void
link_erase(link_key_t* key) {
    link_t link;
    link.key = *key;
    void* dst = hash_find(g_links, &link);
    if (dst) {
        hash_remove(g_links, &link);
    }
    free(dst);
}

void
link_release() {
    if (g_links) {
        hash_release(g_links);
        g_links = NULL;
    }
}

