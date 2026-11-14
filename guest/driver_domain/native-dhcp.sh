#!/bin/busybox sh
# udhcpc executes one callback path, with its event as argv[1]. Pass the fixed
# native selector to the shared callback explicitly; never infer it from env.
exec /bin/busybox sh /sbin/paos-driver-dhcp --native "$@"
