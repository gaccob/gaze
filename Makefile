.PHONY : mingw linux macos undefined

CFLAGS := -g -Wall -std=c99
LDFLAGS :=
LIBS :=
TARGET := gaze

SRC := \
    src/main.c \
    src/eth.c \
    src/ip.c \
    src/tcp.c \
	src/checksum.c \
	src/hash.c \
	src/link.c

UNAME=$(shell uname)
SYS=$(if $(filter Linux%, $(UNAME)), linux,\
	    $(if $(filter MINGW%, $(UNAME)), mingw,\
            $(if $(filter Darwin%, $(UNAME)), macos,\
	        undefined)))

all: $(SYS)

undefined:
	@echo "please do 'make PLATFORM' where PLATFORM is one of these:"
	@echo "      macos linux mingw"


mingw : CFLAGS += -Iwinpcap/include -DHAVE_REMOTE -DMINGW
mingw : LDFLAGS += -lmingw32 -lws2_32
mingw : LIBS += winpcap/lib/Packet.lib winpcap/lib/wpcap.lib
mingw : $(SRC) $(TARGET)

linux : CFLAGS += -Ilibpcap/include -DLINUX
linux : LIBS += libpcap/lib/libpcap.linux.a
linux : $(SRC) $(TARGET)

macos : CFLAGS += -Ilibpcap/include -DMACOS
macos : LIBS += libpcap/lib/libpcap.macos.a
macos : $(SRC) $(TARGET)

$(TARGET) :
	gcc $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS) $(LIBS)

clean :
	-rm -rf $(TARGET).dSYM $(TARGET)
