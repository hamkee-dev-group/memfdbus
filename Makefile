CC ?= cc
AR ?= ar
CPPFLAGS ?=
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2
LDFLAGS ?=
PREFIX ?= /usr/local

BIN := build/memfdbus
LIB := build/libmemfdbus.a
BENCH := build/bench_memfdbus
BIN_OBJ := build/memfdbus.o
API_OBJ := build/memfdbus_api.o
SHA_OBJ := build/sha256.o
LIB_OBJS := $(API_OBJ) $(SHA_OBJ)
BIN_OBJS := $(BIN_OBJ) $(SHA_OBJ)

.PHONY: all clean install test bench

all: $(BIN) $(LIB)

bench: $(BENCH)

$(BENCH): bench/bench_memfdbus.c $(LIB)
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Iinclude -o $@ bench/bench_memfdbus.c $(LIB) $(LDFLAGS)

build/%.o: src/%.c
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Iinclude -c -o $@ $<

$(BIN): $(BIN_OBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(BIN_OBJS) $(LDFLAGS)

$(LIB): $(LIB_OBJS)
	$(AR) rcs $@ $(LIB_OBJS)

test: $(BIN) $(LIB)
	CC="$(CC)" CFLAGS="$(CPPFLAGS) $(CFLAGS)" LDFLAGS="$(LDFLAGS)" tests/smoke.sh ./$(BIN)

install: $(BIN) $(LIB)
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -d "$(DESTDIR)$(PREFIX)/include"
	install -d "$(DESTDIR)$(PREFIX)/lib"
	install -m 0755 $(BIN) "$(DESTDIR)$(PREFIX)/bin/memfdbus"
	install -m 0644 include/memfdbus.h "$(DESTDIR)$(PREFIX)/include/memfdbus.h"
	install -m 0644 $(LIB) "$(DESTDIR)$(PREFIX)/lib/libmemfdbus.a"

clean:
	rm -rf build
