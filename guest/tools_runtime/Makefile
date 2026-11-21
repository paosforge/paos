# Prepared source build only; never installs, signs, launches or reboots.
CC ?= cc
OUT ?= tools-init
CFLAGS := -std=c11 -Os -Wall -Wextra -Werror -static -fno-ident -Wl,--build-id=none -Wl,-z,noexecstack
$(OUT): init.c
	$(CC) $(CFLAGS) init.c -o $(OUT)

CONNECT_OUT ?= tools-connect
$(CONNECT_OUT): connect.c ../terminal_network/main.c ../terminal_network/stream.c ../terminal_network/proxy.c ../terminal_network/stream.h ../terminal_network/proxy.h ../terminal_network/stream_abi.h
	$(CC) $(CFLAGS) connect.c ../terminal_network/stream.c ../terminal_network/proxy.c -o $(CONNECT_OUT)
