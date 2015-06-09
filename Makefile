.PHONY : mingw linux macos undefined

CFLAGS := -g -Wall -std=c99
LDFLAGS :=
LIBS :=
TARGET := gaze
INCLUDES := -I./include/ -I./src/

SRC := \
    src/main.c \
    src/eth.c \
    src/ip.c \
    src/tcp.c \
	src/checksum.c \
	src/hash.c \
	src/link.c \
	src/output.c

UNAME=$(shell uname)
SYS=$(if $(filter Linux%, $(UNAME)), linux,\
		$(if $(filter CYGWIN%, $(UNAME)), cygwin,\
			$(if $(filter MINGW%, $(UNAME)), mingw,\
				$(if $(filter Darwin%, $(UNAME)), macos,\
				undefined))))

all: $(SYS)

undefined:
	@echo "please do 'make PLATFORM' where PLATFORM is one of these:"
	@echo "      macos linux mingw"

mingw : CFLAGS += -DHAVE_REMOTE -DMINGW
mingw : INCLUDES += -I./winpcap/include -I./dlfcn
mingw : LDFLAGS += -lmingw32 -lws2_32 -lpthread
mingw : LIBS += ./winpcap/lib/Packet.lib ./winpcap/lib/wpcap.lib
mingw : SRC += dlfcn/dlfcn.c
mingw : $(SRC) $(TARGET)

cygwin : CFLAGS += -DCYGWIN
cygwin : INCLUDES += -I./winpcap/include -I./dlfcn
cygwin : LDFLAGS += -lpthread
cygwin : LIBS += ./winpcap/lib/libpacket.a ./winpcap/lib/libwpcap.a
cygwin : SRC += dlfcn/dlfcn.c
cygwin : $(SRC) $(TARGET)

linux : CFLAGS += -DLINUX
linux : INCLUDES += -I./libpcap/include
linux : LDFLAGS += -ldl
linux : LIBS += ./libpcap/lib/libpcap.linux.a -lpthread
linux : $(SRC) $(TARGET)

macos : CFLAGS += -DMACOS
macos : INCLUDES += -I./libpcap/include
macos : LIBS += ./libpcap/lib/libpcap.macos.a -lpthread
macos : $(SRC) $(TARGET)

$(TARGET) :
	gcc $(CFLAGS) -o $(TARGET) $(SRC) $(INCLUDES) $(LDFLAGS) $(LIBS)

clean :
	@(rm -f gaze src/*.o)
