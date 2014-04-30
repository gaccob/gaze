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

#define TCP_OPTION_EOF 0x0
#define TCP_OPTION_NOP 0x01
#define TCP_OPTION_MSS 0x02
#define TCP_OPTION_WND_SCALE 0x03
#define TCP_OPTION_SACK 0x04
#define TCP_OPTION_TS  0x08

} tcp_head_t;

int tcp_parse(const tcp_head_t* head, uint32_t sip, uint32_t dip, uint16_t len);

#endif
