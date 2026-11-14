; App-private SOCKS worker to native broker. This wire carries no identity,
; grant, secret, pointer, IP address, TCB or route authority. See APP_NETWORK.md.
%ifndef PAOS_APP_NETWORK_INC
%define PAOS_APP_NETWORK_INC
AN_CONTROL equ 0x5090
AN_DATA equ 0x5094
AN_VERSION equ 1
AN_HEADER equ 32
AN_CAPACITY equ 1024
AN_MAX_FRAME equ AN_HEADER+AN_CAPACITY
AN_HOST_MAX equ 253
AN_OPEN equ 1
AN_SEND equ 2
AN_READ equ 3
AN_CLOSE equ 4
AN_STATUS equ 5
AN_OK equ 0
AN_DENY equ 1
AN_PENDING equ 2
AN_BUSY equ 3
AN_EOF equ 4
AN_FAULT equ 5
%endif
