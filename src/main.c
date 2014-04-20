#ifdef MINGW
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pcap.h>

#include "eth.h"
#include "errdef.h"

int
main(int argc, char** argv) {
    if (argc < 2) {
        printf("usage: ./gaze device-name\n");
        return -1;
    }

    pcap_if_t* devs;
    char err[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&devs, err) < 0) {
        printf("find all devs error: %s\n", err);
        return -1;
    }

    pcap_if_t* dev = NULL;
    for (dev = devs; dev; dev = dev->next) {
        if (strcmp(dev->name, argv[1]) == 0) {
            break;
        }
    }
    if (!dev) {
        printf("dev[%s] not found error\n", argv[1]);
        return -1;
    }

    pcap_t* adhandle = pcap_open_live(dev->name, 65536, 0, 1000, err);
    if (!adhandle) {
        printf("unable to gaze %s: %s\n", dev->name, err);
        pcap_freealldevs(devs);
        return -1;
    }

    struct pcap_pkthdr* header;
    const unsigned char* data;
    int res;
    while ((res = pcap_next_ex(adhandle, &header, &data)) >= 0) {
        if (0 == res) continue; // timeout
        errno = eth_parse(data);
        if (errno != GAZE_OK) {
            printf("parse packet fail: %d\n", errno);
        }
    }

    printf("reading packet: %s\n", pcap_geterr(adhandle));
    pcap_freealldevs(devs);
    return 0;
}

