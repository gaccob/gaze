#ifndef TCP_H_
#define TCP_H_

#include <stdint.h>

typedef struct tcp_head_t {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t offx2; // offset & reserved
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t ptr;
} tcp_head_t;

int tcp_parse(const tcp_head_t* head, uint32_t sip, uint32_t dip);

#endif
