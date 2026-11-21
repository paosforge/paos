; Creator: Claude / rc-vm-claude. Tools hostname stream ABI v1, co-owned by VM
; and AV (AV120723 proposal, VM120734 response, AV120737 accepted the split).
; The single exact source of the shared constants; VM transport and AV parser
; both include it. Lengths only: no field is a pointer, GPA or authority.
%ifndef PAOS_TOOLS_STREAM_ABI_INCLUDED
%define PAOS_TOOLS_STREAM_ABI_INCLUDED 1

; Scalar 32-bit PIO, tools instance only (never app/ordinary/driver).
TSTREAM_PORT_CONTROL equ 0x50f0
TSTREAM_PORT_DATA equ 0x50f4

; Control IN32 status word: lengths, never pointers.
TSTREAM_STATUS_IDLE equ 0
TSTREAM_STATUS_RECEIVING equ 0x40000000   ; | bytes received so far
TSTREAM_STATUS_REPLY equ 0x80000000       ; | reply bytes not yet read
TSTREAM_REFUSED equ 0xffffffff            ; IN32 value of any refused access

; Record framing (request and reply): exact header plus payload.
TSTREAM_HEADER equ 32
TSTREAM_PAYLOAD_MAX equ 1024
TSTREAM_RECORD_MAX equ TSTREAM_HEADER+TSTREAM_PAYLOAD_MAX
TSTREAM_VERSION equ 1
TSTREAM_H_VERSION equ 0                   ; u32
TSTREAM_H_OPCODE equ 4                    ; u32 request / status u32 reply
TSTREAM_H_SEQUENCE equ 8                  ; u64 (reply: original sequence)
TSTREAM_H_HANDLE equ 16                   ; u64
TSTREAM_H_LENGTH equ 24                   ; u32 payload length
TSTREAM_H_RESERVED equ 28                 ; u32 zero

; Request opcodes (AV-owned semantics).
TSTREAM_OPEN equ 1
TSTREAM_SEND equ 2
TSTREAM_READ equ 3
TSTREAM_CLOSE equ 4
TSTREAM_STATUS equ 5
; Reply statuses (AV-owned semantics).
TSTREAM_OK equ 0
TSTREAM_PENDING equ 1
TSTREAM_BUSY equ 2
TSTREAM_EOF equ 3
TSTREAM_REFUSED_STATUS equ 4
TSTREAM_FAILED equ 5

; Native VM->AV calls (AV implements; VM transport is the only caller):
;  terminal_stream_submit(RDI request, ESI length 32..1056, RDX reply buffer
;    of TSTREAM_RECORD_MAX bytes) ->EAX reply length 32..1056, or 0 when AV
;    publishes no reply (VM then latches the transport terminal). Called once
;    per complete frame, inside the open tools exit; AV rechecks its own
;    binding (tools_vm_exit_endpoint) before any effect or reply write. Both
;    buffers are VM-private native arrays; the guest chooses neither.
;  terminal_stream_retire() ->EAX 1 when every broker effect and copyout for
;    the binding is fenced, else 0. VM wipes transport bytes only after 1.
;    It never resets the native sequence.
%endif
