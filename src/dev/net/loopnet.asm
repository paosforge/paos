;; MODULE dev/net/loopnet
;; LAYER 3
;; EXPORTS loopnet_create, loopnet_dev, loopnet_ops, loopnet_tx_frames, loopnet_power_gate, loopnet_power_running, loopnet_tx, loopnet_start, loopnet_stop
;; IMPORTS net/netdev
;; CAPS
;; OWNER saga:net
; ============================================================================
; dev/net/loopnet.asm — the FAKE/loopback netdev backend, and by charter the
; REFERENCE IMPLEMENTATION of the netdev_ops vtable (DRIVER_MODEL.md §7). It is
; BOTH (a) the QEMU-no-hardware regression target — always present, needs zero
; silicon — AND (b) the ops-contract documentation every chip backend
; (e1000e/rtl8168/ax88179/...) matches byte-for-byte. Write the fake first; it
; defines the semantics the real drivers must honour (known_trap: every backend's
; ops struct signature matches loopnet).
;
; It registers at PRIO_DOMAIN (a software fallback: a native chip, when present,
; is preferred by the class core's egress-select scan). Its .tx loops the frame
; back internally (counted) and never touches DMA/MMIO — a pure software member
; that proves the TABLE + HANDLE + egress-select seam with no hardware coupling.
;
; The L3->L4 `call netdev_register` is the ONE sanctioned upward edge
; (DRIVER_MODEL §5) — modlint whitelists it for L3 backends.
; ============================================================================

; loopnet_create() -> RAX = assigned slot index / -1. Builds the netdev_ops
;   vtable at RUNTIME (lea -> mov: function pointers must be runtime VAs; a static
;   `dq loopnet_init` would bake the org-0 RVA and dispatch into low memory —
;   the PE ImageBase is not applied to baked-in dq symbols, so the whole tree
;   fills pointer tables with lea, exactly like core/idt's gate build), fills the
;   uniform struct dev header, and registers with the netdev class core.
loopnet_create:
    cld
    ; An attached lifetime is pinned. Re-create cannot erase its fencing.
    cmp qword [rel loopnet_power_gate], 0
    jne .attached
    ; --- build the ops vtable in place (runtime VAs) ---
    lea  rdi, [rel loopnet_ops]
    lea  rax, [rel loopnet_init]
    mov  [rdi + netdev_ops.init], rax
    lea  rax, [rel loopnet_start]
    mov  [rdi + netdev_ops.start], rax
    lea  rax, [rel loopnet_stop]
    mov  [rdi + netdev_ops.stop], rax
    lea  rax, [rel loopnet_tx]
    mov  [rdi + netdev_ops.tx], rax
    lea  rax, [rel loopnet_rx_poll]
    mov  [rdi + netdev_ops.rx_poll], rax
    lea  rax, [rel loopnet_link_status]
    mov  [rdi + netdev_ops.link_status], rax
    lea  rax, [rel loopnet_get_mac]
    mov  [rdi + netdev_ops.get_mac], rax
    lea  rax, [rel loopnet_recover]
    mov  [rdi + netdev_ops.recover], rax
    ; --- fill the uniform struct dev header ---
    lea  rdi, [rel loopnet_dev]
    lea  rax, [rel loopnet_ops]
    mov  [rdi + dev.ops], rax
    lea  rax, [rel str_loopnet_name]
    mov  [rel loopnet_info + netdev_info.name], rax   ; runtime address (abs_ptr_check)
    lea  rax, [rel loopnet_info]
    mov  [rdi + dev.info], rax
    mov  qword [rdi + dev.priv], 0
    mov  dword [rdi + dev.prio], PRIO_DOMAIN     ; software fallback (native preferred)
    mov  dword [rdi + dev.health], HEALTH_OK
    mov  dword [rdi + dev.class], CLASS_NET
    mov  dword [rdi + dev.flags], 0
    lea  rax, [rel str_loopnet_name]
    mov  [rdi + dev.name], rax
    ; --- register (the sanctioned L3->L4 upward edge) ---
    sub rsp, 8
    call netdev_register                          ; RDI=dev* -> RAX slot
    add rsp, 8
    ret

.attached:
    mov rax, -1
    ret

; --- netdev_ops implementations (the reference semantics) --------------------
; Unattached start/stop preserve software-only success. Attached stop closes
; software readiness; admission independently fences every attached TX.
loopnet_init:
    xor  eax, eax
    ret
loopnet_start:
    mov byte [rel loopnet_power_running], 1
    xor  eax, eax
    ret
loopnet_stop:
    cmp qword [rel loopnet_power_gate], 0
    je .done
    mov byte [rel loopnet_power_running], 0
.done:
    xor  eax, eax
    ret

; tx(self, RSI=frame, RDX=len) -> RAX 0 ok / -1 ring-full. Loopback: count the
;   frame (a v2 rx_poll could return it); never blocks.
loopnet_tx:
    cld
    ; Optional kernel-owned admission callback, installed only by explicit
    ; service attachment. No upward service import and no boot wiring.
    cmp qword [rel loopnet_power_gate], 0
    je .count
    push rdi
    push rsi
    push rdx
    call [rel loopnet_power_gate]
    pop rdx
    pop rsi
    pop rdi
    test rax, rax
    jnz .out
    cmp byte [rel loopnet_power_running], 1
    jne .stopped
.count:
    lock inc qword [rel loopnet_tx_frames]
    xor  eax, eax
.out:
    ret
.stopped:
    mov rax, -1
    ret

; rx_poll(self, RSI=buf, RDX=cap) -> RAX = len (0 none). v1: no queued frames.
loopnet_rx_poll:
    xor  eax, eax
    ret

; link_status(self) -> RAX: bit0=up | speed<<8. A loopback is always up @ 1 Gbps.
loopnet_link_status:
    mov  eax, (1000 << 8) | 1
    ret

; get_mac(self, RSI=out6) -> RAX 0/-1. Locally-administered loopback MAC.
loopnet_get_mac:
    mov  byte [rsi + 0], 0x02
    mov  byte [rsi + 1], 0x00
    mov  byte [rsi + 2], 0x00
    mov  byte [rsi + 3], 0x00
    mov  byte [rsi + 4], 0x00
    mov  byte [rsi + 5], 0x01
    xor  eax, eax
    ret

; recover(self) -> RAX 0. A software member never faults; recovery is a no-op OK.
loopnet_recover:
    xor  eax, eax
    ret

; --- loopnet data (in-image writable) ----------------------------------------
loopnet_dev:        times dev_size db 0            ; the uniform handle (filled at create)
loopnet_ops:        times netdev_ops_size db 0     ; vtable (filled at create, runtime VAs)
loopnet_tx_frames:  dq 0
; BSP-owned synchronous software device: no queued DMA/IRQ/flush obligations.
loopnet_power_gate: dq 0
loopnet_power_running: db 1
loopnet_info:
    dq 0                                   ; .name: set at register time (org 0 image: no static pointers)
    dd 1500                                        ; .mtu
    db 64                                          ; .dma_mask
    dd 0                                           ; .flags
    dd 0                                           ; .speed_caps
str_loopnet_name:   db "loopnet", 0
