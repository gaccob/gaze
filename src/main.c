#ifdef MINGW
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <pcap.h>

#include "eth.h"
#include "errdef.h"

void
usage() {
    printf("usage:\n"
        "--tcp          \"tcp packets\"\n"
        "--udp          \"udp packets\"\n"
        "--eth <name>   \"sniff device name, required!\"\n"
        "--ip <ip address>\n"
        "--port <port>\n");
}

static const char* g_device = NULL;
static const char* g_filter = NULL;

int
parse_args(int argc, char** argv) {

    struct option opts[] = {
        { "tcp",    no_argument,        0,  't'},
        { "udp",    no_argument,        0,  'u'},
        { "eth",    required_argument,  0,  'e'},
        { "ip",     required_argument,  0,  'i'},
        { "port",   required_argument,  0,  'p'},
        { 0,        0,                  0,  0}
    };

    int index, c;
    int success = 0;
    static char filter[1024] = {0};
    static char device[1024];
    int first = 0;
    while ((c = getopt_long(argc, argv, "", opts, &index)) != -1) {
        switch (c) {
            case 't':
                snprintf(filter + strlen(filter), sizeof(filter) - strlen(filter),
                    first == 0 ? "tcp" : " and tcp");
                first = 1;
                break;

            case 'u':
                printf("udp currently not support yet, expect...\n");
                snprintf(filter + strlen(filter), sizeof(filter) - strlen(filter),
                    first == 0 ? "udp" : " and udp");
                first = 1;
                break;

            case 'e':
                snprintf(device, sizeof(device), "%s", optarg);
                g_device = device;
                break;

            case 'i':
                snprintf(filter + strlen(filter), sizeof(filter) - strlen(filter),
                    first == 0 ? "host %s" : " and host %s", optarg);
                first = 1;
                break;

            case 'p':
                snprintf(filter + strlen(filter), sizeof(filter) - strlen(filter),
                    first == 0 ? "port %d" : " and port %d", atoi(optarg));
                first = 1;
                break;

            case '?':
            default:
                usage();
                success = -1;
                break;
        };
    }

    g_filter = filter[0] ? filter : NULL;
    return success;
}

int
main(int argc, char** argv) {

    int ret = parse_args(argc, argv);
    if (ret < 0) return -1;

    pcap_if_t* devs;
    pcap_if_t* dev = NULL;
    char err[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&devs, err) < 0) {
        printf("find all devs error: %s\n", err);
        return -1;
    }

    if (!g_device) {
        usage();
        printf("\nlocal devices as following: \n");
        for (dev = devs; dev; dev = dev->next) {
            printf("\t%s\n", dev->name);
        }
        goto FAIL;
    }

    for (dev = devs; dev; dev = dev->next) {
        if (strcmp(dev->name, g_device) == 0) {
            break;
        }
    }
    if (!dev) {
        printf("dev[%s] not found error\n", g_device);
        goto FAIL;
    }

    pcap_t* adhandle = pcap_open_live(dev->name, 65536, 0, 1000, err);
    if (!adhandle) {
        printf("unable to gaze %s: %s\n", dev->name, err);
        goto FAIL;
    }

    if (g_filter) {

        struct bpf_program fcode;
        if (pcap_compile(adhandle, &fcode, g_filter, 1, 0) < 0) {
            printf("unable to compile filter: %s\n", g_filter);
            goto FAIL;
        }

        if (pcap_setfilter(adhandle, &fcode) < 0) {
            printf("unable to set filter: %s\n", g_filter);
            goto FAIL;
        }
    }

    printf("listening on %s", dev->description ? dev->description : dev->name);
    if (g_filter) printf("(%s)", g_filter);
    printf(" ...\n");

    struct pcap_pkthdr* header;
    const unsigned char* data;
    int res;
    while ((res = pcap_next_ex(adhandle, &header, &data)) >= 0) {
        if (0 == res) continue; // timeout
        errno = eth_parse(data);
        if (errno != GAZE_OK) {
            printf("parse packet fail: %d\n\n", errno);
        }
    }

    printf("reading packet: %s\n", pcap_geterr(adhandle));
    pcap_freealldevs(devs);
    return 0;

FAIL:
    pcap_freealldevs(devs);
    return -1;
}

