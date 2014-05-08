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
#include <assert.h>

#include "eth.h"
#include "errdef.h"
#include "link.h"
#include "output.h"

void
_usage() {
    printf("_usage:\n"
        "--tcp          \"tcp packets\"\n"
        "--udp          \"udp packets\"\n"
        "--eth <name>   \"sniff device name, required! You can use default\"\n"
        "--plugin <name>  \"plugin shared library name, default not used\"\n"
        "--ip <ip address>\n"
        "--debug    \"print ip & tcp level debug info\"\n"
        "--port <port>\n");
}

static const char* g_name = NULL;
static const char* g_filter = NULL;
static pcap_if_t* g_device = NULL;

typedef struct ip_addrs_t {
    int num;
    #define MAX_LOCAL_IP_ADDR_NUM 8
    uint32_t addrs[MAX_LOCAL_IP_ADDR_NUM];
} ip_addrs_t;

static ip_addrs_t g_addrs;

int
is_local_address(uint32_t addr) {
    for (int i = 0; i < g_addrs.num; ++ i) {
        if (g_addrs.addrs[i] == addr) return 0;
    }
    return -1;
}

int g_debug = 0;

int
_parse(int argc, char** argv) {

    struct option opts[] = {
        { "tcp",    no_argument,        0,  't'},
        { "udp",    no_argument,        0,  'u'},
        { "eth",    required_argument,  0,  'e'},
        { "ip",     required_argument,  0,  'i'},
        { "port",   required_argument,  0,  'p'},
        { "plugin", required_argument,  0,  'g'},
        { "debug",  no_argument,        0,  'd'},
        { 0,        0,                  0,  0}
    };

    int index, c;
    static char filter[1024] = {0};
    static char name[1024];
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
                snprintf(name, sizeof(name), "%s", optarg);
                g_name = name;
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

            case 'd':
                g_debug = 1;
                break;

            case 'g':
                if (output_load_dylib(optarg)) {
                    _usage();
                    exit(-1);
                }
                break;

            case '?':
            default:
                _usage();
                exit(-1);
                break;
        };
    }

    g_filter = filter[0] ? filter : NULL;
    return 0;
}

pcap_if_t*
_get_device() {
    pcap_if_t* dev = NULL;
    char err[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&g_device, err) < 0) {
        printf("find all devs error: %s\n", err);
        return NULL;
    }
    if (!g_name) {
        _usage();
        printf("\nlocal devices as following: \n");
        for (dev = g_device; dev; dev = dev->next) {
            printf("\t%s\n", dev->name);
        }
        return NULL;
    }
    if (strcmp(g_name, "default")) {
        for (dev = g_device; dev; dev = dev->next) {
            if (strcmp(dev->name, g_name) == 0) {
                break;
            }
        }
    } else {
        dev = g_device;
    }

    if (!dev) {
        printf("dev[%s] not found error\n", g_name);
        return NULL;
    }
    return dev;
}

void
_get_address(pcap_if_t* dev) {
    if (dev) {
        pcap_addr_t* addr = dev->addresses;
        // maybe multi ip addresses
        while (addr) {
            struct sockaddr_in* self = (struct sockaddr_in*)addr->addr;
            printf("self ip: %s\n", inet_ntoa(self->sin_addr));

            assert(g_addrs.num < MAX_LOCAL_IP_ADDR_NUM);
            g_addrs.addrs[g_addrs.num ++] = *(uint32_t*)&self->sin_addr;

            addr = addr->next;
        }
    }
}

pcap_t*
_open_device(pcap_if_t* dev) {
    char err[PCAP_ERRBUF_SIZE];
    pcap_t* adhandle = pcap_open_live(dev->name, 65536, 0, 1000, err);
    if (!adhandle) {
        printf("unable to gaze %s: %s\n", dev->name, err);
        return NULL;
    }
    return adhandle;
}

int
_filter(pcap_if_t* dev, pcap_t* adhandle) {
    if (g_filter) {
        struct bpf_program fcode;
        if (pcap_compile(adhandle, &fcode, g_filter, 1, 0) < 0) {
            printf("unable to compile filter: %s\n", g_filter);
            return -1;
        }
        if (pcap_setfilter(adhandle, &fcode) < 0) {
            printf("unable to set filter: %s\n", g_filter);
            return -1;
        }
    }
    printf("listening on %s", dev->description ? dev->description : dev->name);
    if (g_filter) printf("(%s)", g_filter);
    printf(" ...\n");
    return 0;
}

void
_poll_device(pcap_t* adhandle) {
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
}

int
main(int argc, char** argv) {

    int ret = _parse(argc, argv);
    if (ret < 0) return -1;

    pcap_if_t* dev = _get_device();
    if (!dev) goto EXIT;

    memset(&g_addrs, 0, sizeof(g_addrs));
    _get_address(dev);

    pcap_t* adhandle = _open_device(dev);
    if (!adhandle) goto EXIT;

    ret = _filter(dev, adhandle);
    if (ret < 0) goto EXIT;

    ret = link_create();
    if (ret < 0) goto EXIT;

    _poll_device(adhandle);

EXIT:
    if (!g_device) {
        pcap_freealldevs(g_device);
    }
    link_release();
    return 0;
}

