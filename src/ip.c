#include "errdef.h"
#include "tcp.h"
#include "ip.h"

// TCP的MSS会尽量保证TCP段不会超过IP的MTU, 避免IP分片
// 目前只做TCP的解析, 所以这里不考虑IP分片的情况
int
ip_parse(const ip_head_t* head) {

    // only IP V4 support
    if (IP_V(head) != 4) {
        return GAZE_IP_NOT_V4;
    }

    // ignore IP option
    if (IP_HL(head) != sizeof(ip_head_t) / 4) {
        return GAZE_IP_WITH_OPTION;
    }

    // checksum
    uint32_t sip = *(uint32_t*)&head->src;
    uint32_t dip = *(uint32_t*)&head->dst;
    // TODO: checksum

    // parse by sub-protocol
    switch (head->proto) {
        case IP_TCP:
            return tcp_parse((tcp_head_t*)(head + 1), sip, dip);
        case IP_UDP:
        case IP_ICMP:
        case IP_IGMP:
        case IP_IGRP:
        case IP_OSPF:
            return GAZE_IP_NOT_SUPPORT;
    }
    return GAZE_IP_FAIL;
}


