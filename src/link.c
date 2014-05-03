#ifdef MINGW
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "link.h"
#include "hash.h"
#include "main.h"

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

#define PKG_SEND 0
#define PKG_RECV 1

link_value_t*
link_find_insert(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {
    // send packet
    link_key_t key;
    int flow = PKG_SEND;
    if (is_local_address(sip) == 0) {
        key.local_ip = sip;
        key.peer_ip = dip;
        key.local_port = sport;
        key.peer_port = dport;
    } else {
        flow = PKG_RECV;
        key.peer_ip = sip;
        key.local_ip = dip;
        key.peer_port = sport;
        key.local_port = dport;
    }

    link_value_t* val = link_find(&key);
    if (!val) {
        val = link_insert(&key);
        if (!val) {
            return NULL;
        }
        printf("\tadd new link[%u:%d->%u:%d]\n", key.local_ip, key.local_port,
            key.peer_ip, key.peer_port);
        memset(val, 0, sizeof(link_value_t));
    }
    val->flow = flow;
    return val;
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

void
link_value_on_seq(link_value_t* val, uint32_t seq) {
    if (val && val->flow == PKG_SEND && val->start_send_seq == 0) {
        val->start_send_seq = seq;
        printf("\tS = %u\n", seq);
    }
    if (val && val->flow == PKG_RECV && val->start_recv_seq == 0) {
        val->start_recv_seq = seq;
        printf("\tR = %u\n", seq);
    }

    if (val->flow == PKG_SEND) {
        printf("\tSEQ[S + %u] \n", seq - val->start_send_seq);
    } else {
        printf("\tSEQ[R + %u] \n", seq - val->start_recv_seq);
    }
}

void
link_value_on_ack(link_value_t* val, uint32_t ack) {
    if (val->flow == PKG_SEND) {
        val->acked_recv_seq = ack;
        if (val->start_recv_seq == 0) {
            printf("\tACK[%u]\n", ack);
        } else {
            printf("\tACK[R + %u]\n", ack - val->start_recv_seq);
        }
    } else {
        val->acked_send_seq = ack;
        if (val->start_send_seq == 0) {
            printf("\tACK[%u]\n", ack);
        } else {
            printf("\tACK[S + %u]\n", ack - val->start_send_seq);
        }
    }
}

