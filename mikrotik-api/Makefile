# Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
#
# smartdns is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# smartdns is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

BIN=mikrotik-api
PREFIX := /usr
SBINDIR := $(PREFIX)/sbin
SLIBDIR := $(PREFIX)/lib
DESTDIR :=
CARGO_BUILD_ENV :=
SMARTDNS_SRC_DIR=../../src

ifeq ($(origin CC), environment)
  ifeq ($(CARGO_BUILD_TARGET),)
    ifeq ($(CARGO_BUILD_ARGS),)
      ARCH_TARGET:=$(shell $(CC) -dumpmachine)
      override CARGO_BUILD_TARGET:=$(shell rustc --print target-list | grep $(ARCH_TARGET) | head -n 1)

      ifeq ($(CARGO_BUILD_TARGET),)
        ARCH_TARGET:=$(shell $(CC) -dumpmachine | sed 's/-[^-]*-linux-/-linux-/')
        ARCH=$(shell echo $(ARCH_TARGET) | cut -d - -f 1)
        ABI=$(shell echo $(ARCH_TARGET) | cut -d - -f 3)
        ifneq ($(ABI),)
          override CARGO_BUILD_TARGET:=$(shell rustc --print target-list | grep $(ARCH) | grep linux | grep $(ABI) | grep unknown | head -n 1)
        endif
      endif

      ifneq ($(CARGO_BUILD_TARGET),)
        ARCH_TARGET_PATH=$(CARGO_BUILD_TARGET)/
        override CARGO_RUSTFLAGS=-C linker=$(CC)
         CARGO_BUILD_ARGS +=--target=$(CARGO_BUILD_TARGET)
      endif
    endif
  endif

  IS_NATIVE_BUILD=$(shell [ "$(CC)" = "cc" ] || [ "$(CC)" = "gcc" ] && echo 1 || echo 0)
  ifeq ($(IS_NATIVE_BUILD), 0)
    SYSROOT:=$(shell $(CC) -print-sysroot)
    ifeq ($(SYSROOT),)
      SYSROOT:=$(shell $(CC) -xc /dev/null -E -Wp,-v 2>&1 | sed -n 's,^ ,,p' | head -n 1)
      ifneq ($(SYSROOT),)
        SYSROOT:=$(SYSROOT)/..
        override CARGO_BUILD_ENV += BINDGEN_EXTRA_CLANG_ARGS="--sysroot=$(SYSROOT)"
        CARGO_BUILD_ARGS +=--target=$(CARGO_BUILD_TARGET)
      endif
    endif
  endif
endif

ifneq ($(CARGO_BUILD_TARGET),)
  ARCH_TARGET_PATH=$(CARGO_BUILD_TARGET)/
endif

IS_BINDGEN_INSTALL=$(shell which bindgen 2>/dev/null)
ifeq ($(IS_BINDGEN_INSTALL),)
  $(shell cargo install --force --locked bindgen-cli)
endif

ifneq ($(CARGO_BUILD_TARGET),)
  CARGO_BUILD_TARGET_INSTALL=$(shell rustup target list | grep $(CARGO_BUILD_TARGET) | grep installed)
  ifeq ($(CARGO_BUILD_TARGET_INSTALL),)
    $(shell rustup target add $(CARGO_BUILD_TARGET))
  endif
endif

IS_MUSL=$(shell $(CC) -v 2>&1 | grep -i musl >/dev/null 2>&1 && echo 1 || echo 0)
ifeq ($(IS_MUSL), 1)
override CARGO_RUSTFLAGS +=-C target-feature=-crt-static
endif

ifdef DEBUG
  CARGO_BUILD_PATH=target/$(ARCH_TARGET_PATH)debug
  SMARTDNS_BUILD_TYPE=DEBUG=1
else
  ifdef OPTIMIZE_SIZE
    CARGO_BUILD_ARGS += --profile release-optmize-size
	CARGO_BUILD_PATH=target/$(ARCH_TARGET_PATH)release-optmize-size
  else
    CARGO_BUILD_ARGS +=--release
  	CARGO_BUILD_PATH=target/$(ARCH_TARGET_PATH)release
  endif

  SMARTDNS_BUILD_TYPE=
endif

.PHONY: all clean install test test-prepare $(BIN)

all: $(BIN)

test-prepare:
	$(MAKE) WITH_ZLIB=0 -B -C $(SMARTDNS_SRC_DIR) libsmartdns-test.a

$(BIN):
	CXXFLAGS= CFLAGS= MAKEFLAGS= RUSTFLAGS="$(CARGO_RUSTFLAGS) $(RUSTFLAGS)" $(CARGO_BUILD_ENV) cargo build $(CARGO_BUILD_ARGS) --features "build-release"
	cp $(CARGO_BUILD_PATH)/libmikrotik_api.so target/mikrotik_api.so

install: $(BIN)
	install -v -m 0644 -D -t $(DESTDIR)$(SLIBDIR)/smartdns target/mikrotik_api.so

test: test-prepare
	MAKEFLAGS= WITH_ZLIB=0 cargo test

clean:
	cargo clean
	$(MAKE) -C $(SMARTDNS_SRC_DIR) clean
	rm -rf target/mikrotik_api.so
