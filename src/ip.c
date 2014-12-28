#ifdef MINGW
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include <stdio.h>

#include "gaze.h"
#include "tcp.h"
#include "main.h"
#include "checksum.h"
#include "ip.h"

// TCP的MSS会尽量保证TCP段不会超过IP的MTU, 避免IP分片
// 目前只做TCP的解析, 所以这里不考虑IP分片的情况
int
ip_parse(const ip_head_t* ip) {

    // only IP V4 support
    if (IP_V(ip) != 4) {
        return GAZE_IP_NOT_V4;
    }

    // ignore IP option
    if (IP_HL(ip) != sizeof(ip_head_t) / 4) {
        return GAZE_IP_WITH_OPTION;
    }

    // ignore MF (more fragment)
    if (ip->offset & IP_MF) {
        return GAZE_IP_MF_NOT_SUPPORT;
    }

    // source & dst ip address
    uint32_t sip = *(uint32_t*)&ip->src;
    uint32_t dip = *(uint32_t*)&ip->dst;

    // checksum (only recv fragment)
    if (is_local_address(sip)) {
        struct cksum_vec vec;
        vec.ptr = (const uint8_t*)(ip);
        vec.len = sizeof(ip_head_t);
        uint16_t sum = checksum(&vec, 1);
        if (sum != 0) {
            uint16_t ipsum = ntohs(ip->checksum);
            PRINTF("bad ip checksum: %x, got %x\n", sum, ipsum);
            return GAZE_IP_CHECKSUM_ERROR;
        }
    }

    // parse by sub-protocol
    switch (ip->proto) {
        case IP_TCP: {
            uint16_t tcplen = ntohs(ip->totlen) - sizeof(ip_head_t);
            return tcp_parse((tcp_head_t*)(ip + 1), sip, dip, tcplen);
        }
        case IP_UDP:
        case IP_ICMP:
        case IP_IGMP:
        case IP_IGRP:
        case IP_OSPF:
            return GAZE_IP_NOT_SUPPORT;
    }
    return GAZE_IP_FAIL;
}

