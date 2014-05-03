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

#define LINK_BUFFER_SIZE 65536

typedef struct link_value_t {
    uint8_t flow;
    uint32_t start_send_seq;
    uint32_t start_recv_seq;
    uint32_t acked_send_seq;
    uint32_t acked_recv_seq;

    // uint32_t send_buffer_seq;
    // char send_buffer[LINK_BUFFER_SIZE];
    // uint32_t recv_buffer_seq;
    // char recv_buffer[LINK_BUFFER_SIZE];
} link_value_t;

#define GAZE_MAX_LINK_NUM 19997

int link_create();
link_value_t* link_find(link_key_t*);
link_value_t* link_insert(link_key_t*);
link_value_t* link_find_insert(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport);
void link_erase(link_key_t*);
void link_release();

void link_value_on_seq(link_value_t*, uint32_t seq);
void link_value_on_ack(link_value_t*, uint32_t ack);

#endif

