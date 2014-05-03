#ifdef MINGW
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <string.h>

#include "errdef.h"
#include "tcp.h"
#include "ip.h"
#include "main.h"
#include "checksum.h"
#include "link.h"

int
_tcp_checksum(const tcp_head_t* tcp, uint32_t sip, uint32_t dip, uint16_t tcpbytes) {
    // pseudo header
    struct phead {
        uint32_t sip;
        uint32_t dip;
        uint8_t mbz;
        uint8_t proto;
        uint16_t len;
    } ph;
    ph.mbz = 0;
    ph.proto = IP_TCP;
    ph.len = htons(tcpbytes);
    ph.sip = sip;
    ph.dip = dip;
    struct cksum_vec vec[2];
    vec[0].ptr = (const uint8_t*)(&ph);
    vec[0].len = sizeof(ph);
    vec[1].ptr = (const uint8_t*)(tcp);
    vec[1].len = tcpbytes;
    uint16_t sum = checksum(vec, 2);
    if (sum != 0) {
        uint16_t tcpsum = ntohs(tcp->checksum);
        printf("tcp checksum: %x, tcpbytes=%d, head->cksum=%d\n", sum, tcpbytes, tcpsum);
        return GAZE_TCP_CHECKSUM_ERROR;
    }
    return 0;
}

const char*
_tcp_timestamp(time_t ts) {
    static char timestamp[64];
    struct tm* p = localtime(&ts);
    snprintf(timestamp, sizeof(timestamp),
        "%04d-%02d-%02d %02d:%02d:%02d",
        p->tm_year + 1900, p->tm_mon + 1, p->tm_mday,
        p->tm_hour, p->tm_min, p->tm_sec);
    return timestamp;
}

int
_tcp_option(const unsigned char* start, int bytes) {
    printf("\t");
    for (int i  = 0; i < bytes; ) {
        if (start[i] == TCP_OPTION_NOP) {
            printf("<nop> ");
            ++ i;
            continue;
        }

        if (i + 1 >= bytes) return GAZE_TCP_OPTION_FAIL;
        int len = (int)start[i + 1];
        if (i + len > bytes) return GAZE_TCP_OPTION_FAIL;

        if (start[i] == TCP_OPTION_MSS) {
            assert(len == 4);
            printf("<mss %u> ", ntohs(*(uint16_t*)&start[i + 2]));
        } else if (start[i] == TCP_OPTION_TS) {
            assert(len == 10);
            printf("<ts %u %u> ", ntohl(*(uint32_t*)&start[i + 2]), ntohl(*(uint32_t*)&start[i + 6]));
        } else if (start[i] == TCP_OPTION_WND_SCALE) {
            assert(len == 3);
            printf("<window scale %d> ", (int)*(uint8_t*)&start[i + 2]);
        } else if (start[i] == TCP_OPTION_SACK) {
            assert(len == 2);
            printf("<SACK> ");
        } else if (start[i] == TCP_OPTION_EOF) {
            break;
        } else {
            printf("<option[%d]> ", start[i]);
        }
        i += len;
    }
    printf("\n");
    return 0;
}

int
_tcp_head_option(const tcp_head_t* tcp, uint32_t sip, uint32_t dip) {

    // tcp port
    uint16_t sport, dport;
    sport = ntohs(tcp->sport);
    dport = ntohs(tcp->dport);

    // print address
    struct in_addr addr;
    addr.s_addr = sip;
    printf("[%s:%d --> ", inet_ntoa(addr), sport);
    addr.s_addr = dip;
    printf("%s:%d]\n", inet_ntoa(addr), dport);

    // option
    int headbytes = (int)(tcp->offx2 >> 4) << 2;
    int optbytes = headbytes - sizeof(tcp_head_t);
    if (optbytes > 0) {
        const unsigned char* start = (const unsigned char*)tcp + sizeof(tcp_head_t);
        return _tcp_option(start, optbytes);
    }
    return 0;
}

#define PKG_SEND 0
#define PKG_RECV 1

link_value_t*
_tcp_link(const tcp_head_t* tcp, uint32_t sip, uint32_t dip) {
    // send packet
    link_key_t key;
    int flow = PKG_SEND;
    if (is_local_address(sip) == 0) {
        key.sip = sip;
        key.dip = dip;
        key.sport = ntohs(tcp->sport);
        key.dport = ntohs(tcp->dport);
    } else {
        flow = PKG_RECV;
        key.dip = sip;
        key.sip = dip;
        key.dport = ntohs(tcp->sport);
        key.sport = ntohs(tcp->dport);
    }

    link_value_t* val = link_find(&key);
    if (!val) {
        val = link_insert(&key);
        if (!val) {
            return NULL;
        }
        memset(val, 0, sizeof(link_value_t));
    }
    val->flow = flow;
    return val;
}

int
_tcp_flag(const tcp_head_t* tcp, link_value_t* val, uint16_t tcpbytes) {

    uint32_t seq = ntohl(tcp->seq);
    if (val->flow == PKG_SEND && val->start_send_seq == 0) {
        val->start_send_seq = seq;
        printf("\tSSEQ = %u\n", seq);
    }
    if (val->flow == PKG_RECV && val->start_recv_seq == 0) {
        val->start_recv_seq = seq;
        printf("\tRSEQ = %u\n", seq);
    }

    if (val->flow == PKG_SEND) {
        printf("\tseq[SSEQ + %u] ", seq - val->start_send_seq);
    } else {
        printf("\tseq[RSEQ + %u] ", seq - val->start_recv_seq);
    }

    if (tcp->flags & TCP_FLAG_ACK) {
        uint32_t ack = ntohl(tcp->ack);
        if (val->flow == PKG_SEND) {
            val->acked_recv_seq = ack;
            if (val->start_recv_seq == 0) {
                printf("ack[%u] ", ack);
            } else {
                printf("ack[RSEQ + %u] ", ack - val->start_recv_seq);
            }
        } else {
            val->acked_send_seq = ack;
            if (val->start_send_seq == 0) {
                printf("ack[%u] ", ack);
            } else {
                printf("ack[SSEQ + %u] ", ack - val->start_send_seq);
            }
        }
    }

    if (tcp->flags & TCP_FLAG_FIN) {
        printf("fin ");
    }
    if (tcp->flags & TCP_FLAG_SYN) {
        printf("syn ");
    }
    if (tcp->flags & TCP_FLAG_RST) {
        printf("rst ");
    }
    if (tcp->flags & TCP_FLAG_PSH) {
        int headbytes = (int)(tcp->offx2 >> 4) << 2;
        printf("psh[%d] ", tcpbytes - headbytes);
    }
    if (tcp->flags & TCP_FLAG_URG) {
        printf("urg ");
    }
    return 0;
}

int
tcp_parse(const tcp_head_t* tcp, uint32_t sip, uint32_t dip, uint16_t tcpbytes) {
    int ret;
    // tcp checksum
    if (is_local_address(sip)) {
        ret = _tcp_checksum(tcp, sip, dip, tcpbytes);
        if (ret < 0) { return ret; }
    }

    // tcp head option
    ret = _tcp_head_option(tcp, sip, dip);
    if (ret < 0) { return ret; }

    // tcpp link
    link_value_t* val = _tcp_link(tcp, sip, dip);
    if (!val) return GAZE_TCP_LINK_FAIL;

    // tcp flag
    ret = _tcp_flag(tcp, val, tcpbytes);
    if (ret < 0) { return ret; }

    printf("\n\n");
    return GAZE_OK;
}

