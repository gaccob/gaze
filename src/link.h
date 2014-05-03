#ifndef LINK_H_
#define LINK_H_

#include <stdint.h>
#include "hash.h"

// ignore same port+ip pair
typedef struct link_key_t {
    int local_ip;
    int peer_ip;
    uint16_t local_port;
    uint16_t peer_port;
} link_key_t;

struct link_value_t;

#define GAZE_MAX_LINK_NUM 19997

int link_create();
struct link_value_t* link_find(link_key_t*);
struct link_value_t* link_insert(link_key_t*);
struct link_value_t* link_find_insert(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport);
void link_erase(link_key_t*);
void link_release();

void link_value_on_seq(struct link_value_t*, uint32_t seq);
void link_value_on_ack(struct link_value_t*, uint32_t ack);

#endif

