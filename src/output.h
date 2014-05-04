#ifndef OUTPUT_H_
#define OUTPUT_H_

#include "link.h"

typedef void (*send_hook)(link_key_t* key, const char* buffer, int len);
typedef void (*recv_hook)(link_key_t* key, const char* buffer, int len);

#define DYLIB_SEND_SYMBOL "OnSend"
#define DYLIB_RECV_SYMBOL "OnRecv"
int output_load_dylib(const char* file);

extern send_hook g_send_hook;
extern recv_hook g_recv_hook;

#endif
