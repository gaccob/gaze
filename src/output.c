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

void
_output_build(link_key_t* key) {
}

void
_output_finish(link_key_t* key) {
}

// local default hook functions
send_hook g_send_hook = _output_send;
recv_hook g_recv_hook = _output_recv;
build_hook g_build_hook = _output_build;
finish_hook g_finish_hook = _output_finish;

int
output_load_dylib(const char* file) {
    void* handle = dlopen(file, RTLD_NOW|RTLD_GLOBAL);
    if (!handle) {
        printf("load %s fail: %s\n", file, dlerror());
        return GAZE_DYLIB_FAIL;
    }

    void* dlsend = dlsym(handle, DYLIB_SEND_SYMBOL);
    void* dlrecv = dlsym(handle, DYLIB_RECV_SYMBOL);
    void* dlbuild = dlsym(handle, DYLIB_BUILD_SYMBOL);
    void* dlfinish = dlsym(handle, DYLIB_FINISH_SYMBOL);
    if (!dlsend || !dlrecv || !dlbuild || !dlfinish) {
        printf("load %s symble not found\n", file);
        return GAZE_DYLIB_SYMBLE_FAIL;
    }
    g_send_hook = (send_hook)dlsend;
    g_recv_hook = (recv_hook)dlrecv;
    g_build_hook = (build_hook)dlbuild;
    g_finish_hook = (finish_hook)dlfinish;
    return 0;
}

