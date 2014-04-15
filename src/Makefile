BIN = shim shim-release
SRC = shim.c shim.h bytearray.c bytearray.h

CFLAGS_DEBUG = -Wall -g -DDEBUG
CFLAGS_RELEASE = -Wall

.PHONY: all debug release clean

all: shim

debug: shim
shim: CFLAGS := $(CFLAGS_DEBUG)

release: shim-release
shim-release: CFLAGS := $(CFLAGS_RELEASE)


$(BIN): $(SRC)
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *.o $(BIN)
