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

# Makefile for Umbra source

BIN_NORMAL = shim shim-dbg
BIN = $(BIN_NORMAL) shim-trace config_printer
SHIM_SRC = shim.c shim.h http_parser.c http_parser.h \
    bytearray.c bytearray.h http_callbacks.c http_callbacks.h \
    session.c session.h http_util.c http_util.h net_util.c net_util.h \
    config.c config.h shim_struct.c shim_struct.h log.h \
    struct_array.c struct_array.h config_printer.c config_printer.h
SHIM_OBJ = shim.o http_parser.o bytearray.o http_callbacks.o session.o \
	http_util.o net_util.o shim_struct.o config.o struct_array.o \
	config_printer.o
LDLIBS := -lssl -lcrypto

CFILES=$(wildcard *.c)
DEPS=$(patsubst %.c, .deps/%.d, $(CFILES))

# Set CROSS_COMPILE variable if needed when running make
# Example: make CROSS_COMPILE=arm-linux-
CC := $(CROSS_COMPILE)$(CC)

# CFLAGS versions
CFLAGS += -Wall
CFLAGS_DEBUG := $(CFLAGS) -g -DDEBUG
CFLAGS_RELEASE := $(CFLAGS)
CFLAGS_TRACE := $(CFLAGS) -O0 -finstrument-functions -g -DDEBUG

.PHONY: all debug trace release clean dist-clean

all: shim

config.h config.c: ../config/config.json ../config/parse_config.py
	../config/parse_config.py $< config.h config.c

debug: shim-dbg
shim-dbg: CFLAGS := $(CFLAGS_DEBUG)

release: shim
shim: CFLAGS := $(CFLAGS_RELEASE)

trace: shim-trace
shim-trace: CFLAGS := $(CFLAGS_TRACE)
shim-trace: $(SHIM_OBJ) trace.c
	$(CC) $(CFLAGS_DEBUG) $^ -o $@ $(LDLIBS)

$(BIN_NORMAL): $(SHIM_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

clean:
	rm -f *.o *.pyc $(BIN) gmon.out config.h config.c

# Trick for tracking dependencies
.deps/%.d: %.c .deps config.h
	@$(CC) $(CFLAGS) -M -o $@ $<

# Create .deps directory
.deps:
	@mkdir .deps

# Include each dependency file
-include $(DEPS)

# Cleanup dependency tracking files
nuke: clean
	rm -rf .deps
