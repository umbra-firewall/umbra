BIN_NORMAL = shim shim-dbg
BIN = $(BIN_NORMAL) shim-trace config_printer
SRC = shim.c shim.h bytearray.c bytearray.h config_printer.c \
    http_parser.c http_parser.h http_callbacks.c http_callbacks.h \
    session.c session.h http_util.c http_util.h net_util.c net_util.h log.h \
    struct_array.c struct_array.h
SHIM_SRC = shim.c shim.h http_parser.c http_parser.h \
    bytearray.c bytearray.h http_callbacks.c http_callbacks.h \
    session.c session.h http_util.c http_util.h net_util.c net_util.h \
    config.c config.h shim_struct.c shim_struct.h log.h \
    struct_array.c struct_array.h
SHIM_OBJ = shim.o http_parser.o bytearray.o http_callbacks.o session.o \
	http_util.o net_util.o shim_struct.o config.o struct_array.o
LDLIBS = -lssl -lcrypto

# Set CROSS_COMPILE variable if needed when running make
# Example: make CROSS_COMPILE=arm-linux-
CC := $(CROSS_COMPILE)$(CC)

# CFLAGS versions
CFLAGS_DEBUG = -Wall -g -DDEBUG
CFLAGS_RELEASE = -Wall -O2
CFLAGS_TRACE = -Wall -O0 -finstrument-functions -g -DDEBUG

.PHONY: all debug trace release clean dist-clean

all: shim

config.h config.c: ../config/config.json ../config/parse_config.py
	../config/parse_config.py $< config.h config.c

debug: shim-dbg
shim-dbg: CFLAGS := $(CFLAGS_DEBUG)

release: shim
shim: CFLAGS := $(CFLAGS_RELEASE)

trace: shim-trace
shim-trace: $(SHIM_SRC) trace.c
	$(CC) $(CFLAGS_TRACE) -c shim.c
	$(CC) $(CFLAGS_TRACE) -c http_parser.c
	$(CC) -c trace.c
	$(CC) shim.o http_parser.o trace.o -o shim-trace

$(BIN_NORMAL): $(SHIM_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

shim.o: shim.c shim.h config.h log.h
bytearray.o: bytearray.c bytearray.h
http_parser.o: http_parser.c http_parser.h
http_callbacks.o: http_callbacks.c http_callbacks.h log.h
session.o: session.c session.h log.h
http_util.o: http_util.c http_util.h log.h
net_util.o: net_util.c net_util.h log.h
shim_struct.o: shim_struct.c shim_struct.h log.h
config.o: config.c config.h
struct_array.o: struct_array.c struct_array.h bytearray.h

config_printer: config_printer.c config.o
	$(CC) $(CFLAGS_DEBUG) -o $@ $^

clean:
	rm -f *.o $(BIN) config.h config.c

dist-clean: clean
	rm -f gmon.out *.pyc
