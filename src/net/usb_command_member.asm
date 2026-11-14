;; MODULE net/usb_command_member
;; LAYER 4
;; EXPORTS usb_command_member, usb_nic_link_repoll, usb_nic_bound_backend
;; IMPORTS net/netdev, dev/net/ax88179, dev/net/ax88179b, dev/net/cdc_ecm, dev/net/cdc_ncm, core/time, boot/serial
;; CAPS
;; OWNER saga:net

; Read-only projection of one registered native USB NIC member for the secondary
; USB command endpoint (ROOT109521/109528, TARGET2109529, INPUT109540). It selects
; nothing, attaches nothing and polls nothing: the endpoint (command_usb_endpoint)
; owns attachment state, address ownership and the poll.
;
; usb_command_member(EDI=netdev slot, RSI=expected 6-byte unicast MAC,
;                    RDX=64-byte output) -> RAX 0 projected / -1 refused.
; Output, written only when RAX=0 (a refusal leaves all 64 bytes untouched):
;   +0  handle (struct dev*)        +8  ops (netdev_ops*)
;   +16 ops.rx_poll                 +24 ops.tx
;   +32 registration epoch pointer (pinned equality only, never serialized)
;   +40 registration epoch          +48 cached MAC, 6 bytes; +54..+63 zero
;
; A member projects only when every check below holds:
; - the slot holds a registered CLASS_NET member at native priority, HEALTH_OK, not
;   NETDEV_F_ABSENT, with a live non-saturated epoch (netdev_member_brief and
;   netdev_power_member: registry reads, no driver op);
; - its ops table is exactly one of the four native USB NIC backends (ax88179,
;   ax88179b, cdc_ecm, cdc_ncm), with rx_poll, tx and get_mac present;
; - that backend is bound, its host controller provides the non-blocking
;   usbhc_ops.bulk_in_poll (otherwise ax88179/cdc_ecm/cdc_ncm RX would fall back to
;   a blocking bulk_in), and an ax88179b member is active (state 3). A parked newer
;   AX is not ready: activating it is its own link_status op, which does USB
;   transfers and is never called here;
; - the backend's cached MAC (get_mac copies it in every USB backend; no transfer)
;   is a non-zero unicast address equal to the expected MAC;
; - the member, ops and epoch are unchanged after that copy.
; The only driver op called is get_mac. No transfer, reset, link probe, selection,
; health or epoch change. Bounded: one registry slot, two registry rechecks.
; Preserves RBX/RBP/R12-R15; clobbers RAX,RCX,RDX,RSI,RDI,R8-R11 and flags.

UCM_OUT_SIZE    equ 64
UCM_FRAME       equ 72                  ; minfo 0..47, epoch 48, MAC 56..63
UCM_EPOCH       equ 48
UCM_MAC         equ 56
%if netdev_minfo_size > UCM_EPOCH
%error "usb_command_member: netdev_minfo outgrew its frame slot"
%endif

usb_command_member:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, UCM_FRAME
    mov  r12d, edi                      ; slot (unsigned dword)
    mov  r13, rsi                       ; expected MAC
    mov  r14, rdx                       ; output
    test r13, r13
    jz   .refuse
    test r14, r14
    jz   .refuse
    mov  edi, r12d
    mov  rsi, rsp
    call netdev_member_brief            ; bounds the slot; registry part only, no driver op
    test rax, rax
    jnz  .refuse
    mov  rbx, [rsp + netdev_minfo.handle]
    test rbx, rbx
    jz   .refuse
    cmp  dword [rsp + netdev_minfo.prio], PRIO_NATIVE_EXPERIMENTAL
    jb   .refuse
    mov  r15, [rbx + dev.ops]
    test r15, r15
    jz   .refuse
    ; Closed set of native USB NIC backends, by exact ops table.
    lea  rax, [rel cdc_ecm_ops]
    cmp  r15, rax
    je   .ecm
    lea  rax, [rel cdc_ncm_ops]
    cmp  r15, rax
    je   .ncm
    lea  rax, [rel axb_ops]
    cmp  r15, rax
    je   .axb
    lea  rax, [rel ax_ops]
    cmp  r15, rax
    jne  .refuse
    cmp  byte [rel ax_present], 1
    jne  .refuse
    mov  rax, [rel ax_hcops]
    jmp  .hc
.ecm:
    cmp  byte [rel cdc_ecm_present], 1
    jne  .refuse
    mov  rax, [rel cdc_ecm_hcops]
    jmp  .hc
.ncm:
    cmp  byte [rel cdc_ncm_present], 1
    jne  .refuse
    mov  rax, [rel cdc_ncm_hcops]
    jmp  .hc
.axb:
    cmp  byte [rel axb_registered], 1
    jne  .refuse
    cmp  byte [rel axb_state], 3        ; active; parked (2) is not ready
    jne  .refuse
    mov  rax, [rel axb_hcops]
.hc:
    test rax, rax
    jz   .refuse
    cmp  qword [rax + usbhc_ops.bulk_in_poll], 0
    je   .refuse                        ; no non-blocking RX on this controller
    cmp  qword [r15 + netdev_ops.rx_poll], 0
    je   .refuse
    cmp  qword [r15 + netdev_ops.tx], 0
    je   .refuse
    cmp  qword [r15 + netdev_ops.get_mac], 0
    je   .refuse
    mov  rdi, rbx
    mov  rsi, r15
    call netdev_power_member            ; member, CLASS_NET, HEALTH_OK, not ABSENT, exact ops, live epoch
    test rax, rax
    jz   .refuse
    mov  rbp, rax
    mov  [rsp + UCM_EPOCH], rdx
    mov  qword [rsp + UCM_MAC], 0
    mov  rdi, rbx
    lea  rsi, [rsp + UCM_MAC]
    call [r15 + netdev_ops.get_mac]     ; cached copy in every USB backend
    test rax, rax
    jnz  .refuse
    mov  word [rsp + UCM_MAC + 6], 0    ; only six bytes are the MAC
    cmp  qword [rsp + UCM_MAC], 0
    je   .refuse
    test byte [rsp + UCM_MAC], 1
    jnz  .refuse                        ; group address is never an endpoint MAC
    mov  eax, [rsp + UCM_MAC]
    cmp  eax, [r13]
    jne  .refuse
    mov  ax, [rsp + UCM_MAC + 4]
    cmp  ax, [r13 + 4]
    jne  .refuse
    mov  rdi, rbx
    mov  rsi, r15
    call netdev_power_member            ; same member, ops and epoch after the copy
    cmp  rax, rbp
    jne  .refuse
    cmp  rdx, [rsp + UCM_EPOCH]
    jne  .refuse
    mov  [r14], rbx
    mov  [r14 + 8], r15
    mov  rax, [r15 + netdev_ops.rx_poll]
    mov  [r14 + 16], rax
    mov  rax, [r15 + netdev_ops.tx]
    mov  [r14 + 24], rax
    mov  [r14 + 32], rbp
    mov  rax, [rsp + UCM_EPOCH]
    mov  [r14 + 40], rax
    mov  rax, [rsp + UCM_MAC]           ; MAC in 48..53, zero in 54..55
    mov  [r14 + 48], rax
    mov  qword [r14 + 56], 0
    xor  eax, eax
    jmp  .out
.refuse:
    mov  rax, -1
.out:
    add  rsp, UCM_FRAME
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; usb_nic_bound_backend() -> EAX = mask of bound USB NIC backends, by their BINDUSB
; ids: bit5 ax88179, bit6 ax88179b, bit7 cdc_ecm, bit8 cdc_ncm (ROOT109541 (a),
; AXSTAT usb_backends). Reads each backend's sticky bound flag; no driver op.
; Clobbers EAX only.
usb_nic_bound_backend:
    xor  eax, eax
    cmp  byte [rel ax_present], 1
    jne  .axb
    or   eax, 1 << 5
.axb:
    cmp  byte [rel axb_registered], 1
    jne  .ecm
    or   eax, 1 << 6
.ecm:
    cmp  byte [rel cdc_ecm_present], 1
    jne  .ncm
    or   eax, 1 << 7
.ncm:
    cmp  byte [rel cdc_ncm_present], 1
    jne  .out
    or   eax, 1 << 8
.out:
    ret

; usb_nic_link_repoll() -> EAX = 1 when this call activated a parked USB NIC
; member, else 0 (ROOT109541 (b); call site reserved by TARGET2109547, once per
; ordinary pump pass, attached endpoint or not).
; The newer AX (ax88179b) binds in one activation attempt: when the PHY has no link
; at that moment it stays parked (state 2), and only its own link_status op
; activates it. Nothing re-polls a member that is not the selected egress (a PCI NIC
; at priority 100 outranks it at 50), so a cable plugged in after boot never came
; up. This tick re-polls it:
; - not due: one tsc_now read and a compare. Due at most once per UCM_REPOLL_MS;
; - due: the member must be registered, parked, and accepted by the real
;   netdev_power_member (HEALTH_OK, not ABSENT, exact ops, live epoch); then ONE
;   call of its existing link_status op, on each due tick for the first
;   NETDEV_REPROBE_FAST, then every NETDEV_REPROBE_SLOW-th (netdev_link_reprobe's
;   backoff; it never gives up). The count restarts whenever the member is not
;   parked;
; - link_status takes the driver's busy lock and, with link up, runs its own
;   bounded activation (synchronous control transfers within the host
;   controller's budget, no reset). No priority, selection, health or epoch write
;   here.
; Preserves RBX/RBP/R12-R15; clobbers RAX,RCX,RDX,RSI,RDI,R8-R11 and flags.
UCM_REPOLL_MS   equ 1000
usb_nic_link_repoll:
    sub  rsp, 8
    call tsc_now
    cmp  rax, [rel ucm_repoll_due]
    jb   .none
    mov  rcx, [rel tsc_khz]
    test rcx, rcx
    jnz  .khz
    mov  ecx, 1000000
.khz:
    imul rcx, rcx, UCM_REPOLL_MS
    add  rax, rcx
    jnc  .due
    mov  rax, -1
.due:
    mov  [rel ucm_repoll_due], rax
    cmp  byte [rel axb_registered], 1
    jne  .idle
    cmp  byte [rel axb_state], 2        ; parked
    jne  .idle
    lea  rdi, [rel axb_dev]
    lea  rsi, [rel axb_ops]
    call netdev_power_member
    test rax, rax
    jz   .idle
    inc  dword [rel ucm_repoll_ticks]
    mov  eax, [rel ucm_repoll_ticks]
    cmp  eax, NETDEV_REPROBE_FAST
    jbe  .probe
    sub  eax, NETDEV_REPROBE_FAST
    xor  edx, edx
    mov  ecx, NETDEV_REPROBE_SLOW
    div  ecx
    test edx, edx
    jnz  .none                          ; backoff: not this tick
.probe:
    lea  rdi, [rel axb_dev]
    call [rel axb_ops + netdev_ops.link_status]
    cmp  byte [rel axb_state], 3
    jne  .none
    mov  dword [rel ucm_repoll_ticks], 0
    lea  rdi, [rel str_ucm_link_late]
    call serial_string
    mov  eax, 1
    jmp  .out
.idle:
    mov  dword [rel ucm_repoll_ticks], 0
.none:
    xor  eax, eax
.out:
    add  rsp, 8
    ret

str_ucm_link_late: db '[PAOS64] L2 netdev: [net.usbnic.link_late] parked ax88179b activated on a later link re-poll',13,10,0
align 8
ucm_repoll_due:   dq 0
ucm_repoll_ticks: dd 0
