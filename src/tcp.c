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
#include "checksum.h"

int
_tcp_checksum(const tcp_head_t* tcp, uint32_t sip, uint32_t dip, uint16_t len) {
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
    ph.len = htons((len >> 1) << 1);
    ph.sip = sip;
    ph.dip = dip;

    struct cksum_vec vec[2];
    vec[0].ptr = (const uint8_t*)(&ph);
    vec[0].len = sizeof(ph);

    if (len & 1) {
        static uint8_t _buf[IP_MAX_LEN];
        memcpy(_buf, (const uint8_t*)tcp, len);
        _buf[len] = 0;
        vec[1].ptr = _buf;
        vec[1].len = len + 1;
    } else {
        vec[1].ptr = (const uint8_t*)(tcp);
        vec[1].len = len;
    }
    uint16_t sum = checksum(vec, 2);
    if (sum != 0) { // tcp->checksum) {
        printf("tcp checksum: %x, len=%d, head->cksum=%d\n", sum, len, tcp->checksum);
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
    for (int i  = 0; i < bytes; ) {

        // kind = 1
        if (start[i] == TCP_OPTION_NOP) {
            printf(" <nop>");
            ++ i;
            continue;
        }

        if (i + 1 >= bytes) return GAZE_TCP_OPTION_FAIL;
        int len = (int)start[i + 1];
        if (i + len > bytes) return GAZE_TCP_OPTION_FAIL;

        if (start[i] == TCP_OPTION_MSS) {
            assert(len == 4);
            printf(" <mss %u>", ntohs(*(uint16_t*)&start[i + 2]));
        } else if (start[i] == TCP_OPTION_TS) {
            assert(len == 10);
            printf(" <timestamp %u %u>", ntohl(*(uint32_t*)&start[i + 2]),
                ntohl(*(uint32_t*)&start[i + 6]));
        } else if (start[i] == TCP_OPTION_WND_SCALE) {
            assert(len == 3);
            printf(" <window scale %d>", (int)*(uint8_t*)&start[i + 2]);
        } else if (start[i] == TCP_OPTION_SACK) {
            assert(len == 2);
            printf(" <SACK>");
        } else if (start[i] == TCP_OPTION_EOF) {
            break;
        } else {
            printf(" <option[%d]>", start[i]);
        }

        i += len;
    }
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
    printf("%s:%d]\t", inet_ntoa(addr), dport);

    // option
    int headbytes = (int)(tcp->offx2 >> 4) * 4;
    int optbytes = headbytes - sizeof(tcp_head_t);
    if (optbytes > 0) {
        const unsigned char* start = (const unsigned char*)tcp + sizeof(tcp_head_t);
        return _tcp_option(start, optbytes);
    }
    return 0;
}

int
tcp_parse(const tcp_head_t* tcp, uint32_t sip, uint32_t dip, uint16_t len) {

    // tcp checksum
    int ret = _tcp_checksum(tcp, sip, dip, len);
    if (ret < 0) { return ret; }

    // tcp head option
    ret = _tcp_head_option(tcp, sip, dip);
    if (ret < 0) { return ret; }
/*
    if (tcp->flags & 0x08) printf("PSH\t");
    if (tcp->flags & 0x10) printf("ACK\t");
    if (tcp->flags & 0x02) printf("SYN\t");
    if (tcp->flags & 0x20) printf("URG\t");
    if (tcp->flags & 0x01) printf("FIN\t");
    if (tcp->flags & 0x04) printf("RST\t");
    */
    printf("\n\n");

    return GAZE_OK;
}
