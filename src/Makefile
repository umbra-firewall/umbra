BIN_NORMAL = shim shim-dbg
BIN = $(BIN_NORMAL) shim-trace
SRC = shim.c shim.h bytearray.c bytearray.h

# Set CROSS_COMPILE variable if needed when running make
# Example: make CROSS_COMPILE=arm-linux-
CC := $(CROSS_COMPILE)$(CC)

# CFLAGS versions
CFLAGS_DEBUG = -Wall -g -DDEBUG
CFLAGS_RELEASE = -Wall -O2
CFLAGS_TRACE = -Wall -O0 -finstrument-functions -g -DDEBUG

.PHONY: all debug trace release clean dist-clean

all: shim

debug: shim-dbg
shim-dbg: CFLAGS := $(CFLAGS_DEBUG)

release: shim
shim: CFLAGS := $(CFLAGS_RELEASE)

trace: shim-trace
shim-trace: shim.c trace.c shim.h
	$(CC) $(CFLAGS_TRACE) -c shim.c
	$(CC) -c trace.c
	$(CC) shim.o trace.o -o shim-trace

$(BIN_NORMAL): $(SRC)
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *.o $(BIN)

dist-clean: clean
	rm -f gmon.out *.pyc
