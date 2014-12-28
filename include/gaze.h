#ifndef GAZE_H_
#define GAZE_H_

#include <stdint.h>

#if defined(__LINUX__) || defined(__linux__)
    #define COLOR_RED  { printf("\033[31;1m"); }
    #define COLOR_GREEN { printf("\033[32;1m"); }
    #define COLOR_RESET { printf("\033[;0m"); }

#elif defined(WIN32)
    #include <windows.h>
    #define COLOR_RED \
        { \
            HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE); \
            SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_INTENSITY); \
        }
    #define COLOR_GREEN \
        { \
            HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE); \
            SetConsoleTextAttribute(h, FOREGROUND_GREEN | FOREGROUND_INTENSITY); \
        }
    #define COLOR_RESET \
        { \
            HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE); \
            SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_BLUE \
                | FOREGROUND_GREEN | FOREGROUND_INTENSITY); \
        }

#else
    #define COLOR_RED
    #define COLOR_GREEN
    #define COLOR_RESET
#endif

// ignore same port+ip pair
typedef struct link_key_t {
    int local_ip;
    int peer_ip;
    uint16_t local_port;
    uint16_t peer_port;
} link_key_t;

#define DYLIB_SEND_SYMBOL "OnSend"
#define DYLIB_RECV_SYMBOL "OnRecv"
#define DYLIB_BUILD_SYMBOL "OnBuild"
#define DYLIB_FINISH_SYMBOL "OnFinish"

typedef void (*send_hook)(link_key_t* key, const char* buffer, int len);
typedef void (*recv_hook)(link_key_t* key, const char* buffer, int len);
typedef void (*build_hook)(link_key_t* key);
typedef void (*finish_hook)(link_key_t* key);

#define GAZE_OK 0

#define GAZE_ETH_FAIL -100
#define GAZE_ETH_NOT_SUPPORT -101

#define GAZE_IP_FAIL -200
#define GAZE_IP_NOT_SUPPORT -201
#define GAZE_IP_NOT_V4 -202
#define GAZE_IP_WITH_OPTION -203
#define GAZE_IP_CHECKSUM_ERROR -204
#define GAZE_IP_MF_NOT_SUPPORT -205

#define GAZE_TCP_FAIL -300
#define GAZE_TCP_CHECKSUM_ERROR -301
#define GAZE_TCP_OPTION_FAIL -302
#define GAZE_TCP_LINK_FAIL -303

#define GAZE_DYLIB_FAIL -400
#define GAZE_DYLIB_SYMBLE_FAIL -401

#endif

