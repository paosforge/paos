# Use an explicitly selected, retained static Linux C toolchain for shipping.
# HOST fixture compilation does not qualify that toolchain or boot the result.
CC ?= cc
CFLAGS := -std=c11 -Os -Wall -Wextra -Werror -static -fno-ident -Wl,--build-id=none -Wl,-z,noexecstack
OUT ?= app-init
$(OUT): init.c payload.h
	$(CC) $(CFLAGS) init.c -o $(OUT)
.PHONY: clean
clean:
	rm -f -- $(OUT)
