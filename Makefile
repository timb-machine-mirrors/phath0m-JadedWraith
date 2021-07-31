include wraith.conf.make

CC := gcc
LD := gcc
CFLAGS = -c -std=gnu99 -fno-stack-protector -fPIE -fno-stack-check -fvisibility=hidden -I ./include
LD_FLAGS = -fvisibility=hidden -ldl -lpthread -lrt
UNAME_P := $(shell uname -m)
UNAME_S := $(shell uname -s)
VERSION := 2.0.0

NAME = JadedWraith-$(VERSION)-$(UNAME_S)-$(UNAME_P).elf
JADEDWRAITH = bin/$(NAME)

SOURCE_OBJECTS += src/wraith_cmd.o
SOURCE_OBJECTS += src/main.o
SOURCE_OBJECTS += src/packet_sniffer.o
SOURCE_OBJECTS += src/salsa20.o
SOURCE_OBJECTS += src/salsa20_session.o
SOURCE_OBJECTS += src/sha256.o
SOURCE_OBJECTS += src/session.o
SOURCE_OBJECTS += src/popen_ex.o

UNAME_S := $(shell uname -s)

ifeq ($(USE_LIBPCAP),yes)
	LD_FLAGS += -lpcap
	CFLAGS += -DUSE_LIBPCAP
endif

ifeq ($(INJECTABLE),yes)
	LD_FLAGS += -shared -fPIC
	CFLAGS += -shared -fPIC -DINJECTABLE
	JADEDWRAITH = bin/JadedWraith-$(VERSION)-$(UNAME_S)-$(UNAME_P).so
endif

all: $(JADEDWRAITH)

debug: $(JADEDWRAITH)
debug: CFLAGS +=  -D DEBUG

$(JADEDWRAITH): $(SOURCE_OBJECTS)
	mkdir -p bin
	$(LD) -o $@ $^ $(LD_FLAGS)
	strip $@
%.o: %.c
	$(CC) -O2 $(CFLAGS) $^ -o $@

clean:
	rm $(JADEDWRAITH) $(SOURCE_OBJECTS)
