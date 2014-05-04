#include <stdio.h>
#include <dlfcn.h>

#include "errdef.h"
#include "output.h"

void
_output_bytes(const char* buffer, int len) {
    for (int i = 0; i < len; ++ i) {
        if (i % 10 == 0) printf("\t");
        printf("%02X ", (const unsigned char)buffer[i]);
        if (i % 10 == 9) printf("\n");
    }
    printf("\n");
}

void
_output_send(link_key_t* key, const char* buffer, int len) {
    _output_bytes(buffer, len);
}

void
_output_recv(link_key_t* key, const char* buffer, int len) {
    _output_bytes(buffer, len);
}

// local default hook functions
send_hook g_send_hook = _output_send;
send_hook g_recv_hook = _output_recv;

int
output_load_dylib(const char* file) {
    void* handle = dlopen(file, RTLD_NOW|RTLD_GLOBAL);
    if (!handle) {
        printf("load %s fail: %s\n", file, dlerror());
        return GAZE_DYLIB_FAIL;
    }

    void* dlsend = dlsym(handle, DYLIB_SEND_SYMBOL);
    void* dlrecv = dlsym(handle, DYLIB_RECV_SYMBOL);
    if (!dlsend || !dlrecv) {
        printf("load %s symble %s|%s not found\n", file, DYLIB_SEND_SYMBOL, DYLIB_RECV_SYMBOL);
        return GAZE_DYLIB_SYMBLE_FAIL;
    }
    g_send_hook = (send_hook)dlsend;
    g_recv_hook = (recv_hook)dlrecv;
    return 0;
}

