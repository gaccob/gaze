#ifndef ETH_H_
#define ETH_H_

#include <stdint.h>

// RFC 894 ethernet frame
// 以太网封装 不需要做CRC校验(硬件会做)
typedef struct eth_head_t {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
} eth_head_t;

#define ETH_IP 0x0800
#define ETH_ARP 0x0806
#define ETH_RARP 0x8035

int eth_parse(const unsigned char* data);

#endif
