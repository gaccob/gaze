#ifndef OUTPUT_H_
#define OUTPUT_H_

#include "link.h"
#include "gaze.h"

int output_load_dylib(const char* file);

extern send_hook g_send_hook;
extern recv_hook g_recv_hook;
extern build_hook g_build_hook;
extern finish_hook g_finish_hook;

#endif
