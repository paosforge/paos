# Use an explicitly selected, retained static Linux C toolchain for shipping.
# HOST compilation does not qualify that toolchain or boot the result.
CC ?= cc
CFLAGS := -std=c11 -O2 -Wall -Wextra -Werror -static -fno-ident -Wl,--build-id=none -Wl,-z,noexecstack
OUT ?= paos-chat-adapter
PORTAL_OUT ?= paos-chat-portal
ROOT := $(abspath ../..)
SUPERVISOR := $(ROOT)/gauntlet_v2/tools/llm_cpu_guest/ai_run.c
CODEC := $(ROOT)/tools/browser/browser_appliance/agent/paos_snapshot.h

ifeq ($(abspath $(OUT)),$(abspath $(PORTAL_OUT)))
$(error OUT and PORTAL_OUT must name distinct outputs)
endif

.DELETE_ON_ERROR:
.PHONY: all adapter portal clean
all: adapter portal
adapter: $(OUT)
portal: $(PORTAL_OUT)

$(OUT): adapter.c sha256.h $(SUPERVISOR) $(CODEC) Makefile
	$(CC) $(CPPFLAGS) -I"$(dir $(CODEC))" $(CFLAGS) adapter.c -o "$@"

$(PORTAL_OUT): portal.c sha256.h Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS) portal.c -o "$@"

clean:
	rm -f -- "$(OUT)" "$(PORTAL_OUT)"
