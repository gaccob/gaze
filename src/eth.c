#ifdef MINGW
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include "eth.h"
#include "gaze.h"
#include "ip.h"

int
eth_parse(const unsigned char* data) {
    const eth_head_t* eth = (eth_head_t*)data;
    uint16_t type = ntohs(eth->type);
    switch (type) {
        case ETH_IP:
            return ip_parse((const ip_head_t*)(eth + 1));
        case ETH_ARP:
        case ETH_RARP:
            return GAZE_ETH_NOT_SUPPORT;
    }
    return GAZE_ETH_FAIL;
}

