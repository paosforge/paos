# Use an explicitly selected, retained static Linux C toolchain for shipping.
# HOST fixture compilation does not qualify that toolchain or boot the result.
CC ?= cc
CFLAGS := -std=c11 -Os -Wall -Wextra -Werror -static -fno-ident -Wl,--build-id=none -Wl,-z,noexecstack
ifeq ($(APP_RUNTIME_OBSERVER_ABI_V1),1)
override CFLAGS += -DAPP_RUNTIME_OBSERVER_ABI_V1
endif
OUT ?= app-init
$(OUT): mail_observer.c mail_observer.h curl_prefix.c curl_prefix.h runtime_observer.c runtime_observer.h init.c payload.h network.c network.h clock.c clock.h isolation.c isolation.h mail_supervisor.c mail_supervisor.h mail_public.c mail_public.h mail_worker.c mail_worker.h mail_codec.c mail_codec.h account_transport.c account_transport.h
	$(CC) $(CFLAGS) mail_observer.c curl_prefix.c runtime_observer.c init.c network.c clock.c isolation.c mail_supervisor.c mail_public.c mail_worker.c mail_codec.c account_transport.c -o $(OUT)
.PHONY: clean
clean:
	rm -f -- $(OUT)
