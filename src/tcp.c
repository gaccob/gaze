#ifdef MINGW
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include <stdio.h>

#include "errdef.h"
#include "tcp.h"
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
    ph.proto = IPPROTO_TCP;
    ph.len = htons(len);
    ph.sip = sip;
    ph.dip = dip;

    struct cksum_vec vec[2];
    vec[0].ptr = (const uint8_t*)(&ph);
    vec[0].len = sizeof(ph);
    vec[1].ptr = (const uint8_t*)(tcp);
    vec[1].len = len;
    uint16_t sum = checksum(vec, 2);
    if (sum != 0) {
        uint16_t tcpsum = ntohs(tcp->checksum);
        printf("bad tcp checksum: %x -> %x\n", tcpsum, checksum_shouldbe(tcpsum, sum));
        return GAZE_TCP_CHECKSUM_ERROR;
    }
    return 0;
}

int
tcp_parse(const tcp_head_t* tcp, uint32_t sip, uint32_t dip, uint16_t len) {

    // tcp port
    uint16_t sport, dport;
    sport = ntohs(tcp->sport);
    dport = ntohs(tcp->dport);

    // tcp checksum
    int ret = _tcp_checksum(tcp, sip, dip, len);
    if (ret < 0) return ret;

    // print address
    struct in_addr addr;
    addr.s_addr = sip;
    printf("[%s:%d --> ", inet_ntoa(addr), sport);
    addr.s_addr = dip;
    printf("%s:%d]\t", inet_ntoa(addr), dport);

    if (tcp->flags & 0x08) printf("PSH\t");
    if (tcp->flags & 0x10) printf("ACK\t");
    if (tcp->flags & 0x02) printf("SYN\t");
    if (tcp->flags & 0x20) printf("URG\t");
    if (tcp->flags & 0x01) printf("FIN\t");
    if (tcp->flags & 0x04) printf("RST\t");
    printf("\n");

    return GAZE_OK;
}
