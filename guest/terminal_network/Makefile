# Shipping toolchain/packaging belongs to VM; HOST compilation is not boot proof.
CC ?= cc
CFLAGS := -std=c11 -Os -Wall -Wextra -Werror -static -fno-ident -Wl,--build-id=none -Wl,-z,noexecstack
OUT ?= terminal-connect
$(OUT): stream.c stream.h stream_abi.h proxy.c proxy.h main.c
	$(CC) $(CFLAGS) stream.c proxy.c main.c -o $(OUT)
.PHONY: clean
clean:
	rm -f -- $(OUT)
