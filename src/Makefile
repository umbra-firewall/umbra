BIN_NORMAL = shim shim-dbg
BIN = $(BIN_NORMAL) shim-trace
SRC = shim.c shim.h bytearray.c bytearray.h
SHIM_SRC = shim.c shim.h config_header.h

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
	$(CC) -c trace.c
	$(CC) shim.o trace.o -o shim-trace

$(BIN_NORMAL): $(SHIM_SRC)
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *.o $(BIN) config_header.h

dist-clean: clean
	rm -f gmon.out *.pyc
