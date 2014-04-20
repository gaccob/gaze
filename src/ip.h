#ifndef IP_H_
#define IP_H_

#include <stdint.h>

typedef struct ip_addr_t {
    uint8_t data[4];
} ip_addr_t;

typedef struct ip_head_t {
    uint8_t vhl;
    #define IP_V(ip) (((ip)->vhl & 0xf0) >> 4)
    #define IP_HL(ip) ((ip)->vhl & 0x0f)
    uint8_t tos;
    uint16_t totlen;
    uint16_t ident;
    uint16_t offset;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    ip_addr_t src;
    ip_addr_t dst;
    // ignore option
} ip_head_t;

#define IP_ICMP 1
#define IP_IGMP 2
#define IP_TCP 6
#define IP_UDP 17
#define IP_IGRP 88
#define IP_OSPF 89

int ip_parse(const ip_head_t* head);

#endif
