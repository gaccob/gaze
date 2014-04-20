#ifdef MINGW
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include <stdio.h>

#include "errdef.h"
#include "tcp.h"

int
tcp_parse(const tcp_head_t* head, uint32_t sip, uint32_t dip) {

    // tcp port
    uint16_t sport, dport;
    sport = ntohs(head->sport);
    dport = ntohs(head->dport);

    // print address
    struct in_addr addr;
    addr.s_addr = sip;
    printf("[%s:%d --> ", inet_ntoa(addr), sport);
    addr.s_addr = dip;
    printf("%s:%d]\t", inet_ntoa(addr), dport);

    if (head->flags & 0x08) printf("PSH\t");
    if (head->flags & 0x10) printf("ACK\t");
    if (head->flags & 0x02) printf("SYN\t");
    if (head->flags & 0x20) printf("URG\t");
    if (head->flags & 0x01) printf("FIN\t");
    if (head->flags & 0x04) printf("RST\t");
    printf("\n");

    return GAZE_OK;
}
