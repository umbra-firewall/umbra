# Copyright 2015 Regents of the University of Michigan
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Makefile for Unit Tests

# Binaries and objects
BIN_NORMAL = check_all check_all_dbg
BIN = $(BIN_NORMAL)
OBJ = check_all.o check_session.o

FILTER_OUT := ../src/shim.c
SHIM_CFILES := $(filter-out $(FILTER_OUT),$(wildcard ../src/*.c))

CFILES=$(wildcard *.c)
DEPS=$(patsubst %.c, .deps/%.d, $(CFILES))

# Flags
CFLAGS += -Wall
LDFLAGS += -lcheck

CFLAGS_DEBUG = $(CFLAGS) -g -DDEBUG
CFLAGS_RELEASE = $(CFLAGS) -O2

.PHONY: all clean nuke check

all: $(BIN) check

../src/config.h: ../config/config.json
	make -C ../src config.h

check_session.o: check_session.c
check_all.o: check_all.c check_all.h
shim_strip.o: ../src/shim.c
	$(CC) $(CFLAGS) -c $^ -o $@
	objcopy --strip-symbol=main $@

check_all_dbg: CFLAGS := $(CFLAGS_DEBUG)

check_all: CFLAGS := $(CFLAGS_RELEASE)

$(BIN_NORMAL): $(OBJ) $(SHIM_CFILES) shim_strip.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

check: check_all
	./$<

check_dbg: check_all_dbg
	./$<

clean:
	rm -f *.o $(BIN)


# Trick for tracking dependencies
.deps/%.d: %.c .deps ../src/config.h
	@$(CC) $(CFLAGS) -M -o $@ $<

# Create .deps directory
.deps:
	@mkdir .deps

# Include each dependency file
-include $(DEPS)

# Cleanup dependency tracking files
nuke: clean
	rm -rf .deps