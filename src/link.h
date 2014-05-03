#ifndef LINK_H_
#define LINK_H_

#include <stdint.h>
#include "hash.h"

// ignore same port+ip pair
typedef struct link_key_t {
    int sip;
    int dip;
    uint16_t sport;
    uint16_t dport;
} link_key_t;

typedef struct link_value_t {
    uint8_t flow;
    uint32_t start_send_seq;
    uint32_t start_recv_seq;
    uint32_t acked_send_seq;
    uint32_t acked_recv_seq;
} link_value_t;

#define GAZE_MAX_LINK_NUM 19997

int link_create();
link_value_t* link_find(link_key_t*);
link_value_t* link_insert(link_key_t*);
void link_erase(link_key_t*);
void link_release();

#endif

