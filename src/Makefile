BIN_NORMAL = shim shim-dbg
BIN = $(BIN_NORMAL) shim-trace config_printer
SRC = shim.c shim.h bytearray.c bytearray.h config_printer.c \
    http_parser.c http_parser.h
SHIM_SRC = shim.c shim.h config_header.h http_parser.c http_parser.h
SHIM_OBJ = shim.o http_parser.o bytearray.o

# Set CROSS_COMPILE variable if needed when running make
# Example: make CROSS_COMPILE=arm-linux-
CC := $(CROSS_COMPILE)$(CC)

# CFLAGS versions
CFLAGS_DEBUG = -Wall -g -DDEBUG
CFLAGS_RELEASE = -Wall -O2
CFLAGS_TRACE = -Wall -O0 -finstrument-functions -g -DDEBUG

.PHONY: all debug trace release clean dist-clean

all: shim

config_header.h: ../config/config.json ../config/parse_config.py
	../config/parse_config.py $< $@

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
	$(CC) $(CFLAGS) $^ -o $@

shim.o: shim.c shim.h config_header.h
bytearray.o: bytearray.c bytearray.h
http_parser.o: http_parser.c http_parser.h

config_printer: config_printer.c config_header.h

clean:
	rm -f *.o $(BIN) config_header.h

dist-clean: clean
	rm -f gmon.out *.pyc
