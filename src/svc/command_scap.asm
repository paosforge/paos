;; MODULE svc/command_scap
;; LAYER 5
;; EXPORTS scap_poll, scap_pending, scap_cancel, scap_init, scap_profile_enabled, scap_on_screen, scap_on_screen2, scap_grant_open, scap_grant_close, scap_capture_admitted, scap_request_admitted, scap_grant_stage_refusal, scap_out_ready, scap_out_buf, scap_peer_handle
;; IMPORTS boot/serial, boot/gop, core/time, core/lib/cksum, net/netdev
;; CAPS
;; OWNER saga:screenshot
; ============================================================================
; svc/command_scap.asm — the NATIVE SCREENSHOT SERVER (1108): UDP :9996 dumps
; the live GOP framebuffer over the wire in the monolith's proven chunked
; START/DATA/COMMIT protocol (ported from paos.asm screenshot_send_task — the
; sequence capture_screenshot.py has spoken against bare metal for months).
;
; Protocol (request "SCREEN\n" on UDP :9996, replies to the sender's port):
;   START  (0x01): type(1) + magic(4 'SCRE') + width(4) + height(4)
;                  + pixel_format(4) + total_size(4)            = 21 bytes
;   DATA   (0x02): type(1) + offset(4 LE) + chunk(<=1024)       = 5+N bytes
;   COMMIT (0x03): type(1) + checksum(4 LE, additive byte sum)  = 5 bytes
;
; Rework-seam differences from the monolith (earned, not drift):
;   - The rework paints straight into the GOP fb (no full back buffer), so the
;     pixel source is fb_base and rows are re-PACKED during copy: the wire image
;     is width*4 bytes/row while the fb is fb_stride pixels/row. The monolith
;     read its packed back_buffer and could stream a flat range; a flat copy
;     here would leak the stride slack and shear every row.
;   - The rework net path is a single polled thread (no task_create), so the
;     RX only admits owned capture state. The normal idle sweep sends at most
;     one packet per turn, with a monotonic 500us next-send time; input/recovery
;     and network service run between packets. No recursive RX or busy delay.
;   - Transport uses the snapshotted ingress handle's netdev_ops.tx seam;
;     generic background NIC selection cannot redirect a reply. No chip is named.
;
; Degrade (contract negative gate): fb_base==0 -> stay silent, never fault the
; net task. A malformed/short request never reaches scap_on_screen (the :9996
; branch in udp_handle_ipv4 validates "SCREEN\n" byte-for-byte).
; ============================================================================

SCAP_UDP_PORT   equ 9996
SCAP_MAGIC      equ 0x53435245          ; 'SCRE' little-endian
SCAP_PKT_START  equ 0x01
SCAP_PKT_DATA   equ 0x02
SCAP_PKT_COMMIT equ 0x03
SCAP_PKT_REFUSE equ 0x04
SCAP_MAGIC_V2   equ 0x32524353          ; raw wire bytes 'SCR2'
SCAP_RF_BAD_RECT     equ 1
SCAP_RF_BUSY         equ 2
SCAP_RF_MODE_CHANGED equ 3
SCAP_CHUNK      equ 1024                ; bytes per DATA packet (fits one MTU)
SCAP_DELAY_US   equ 500                 ; monolith-proven inter-packet pacing

; Task3017: production builds fail closed. A deliberate lab build must opt in
; with `make PAOS_SCAP_PROFILE=lab`; no packet can change this policy.
%ifndef PAOS_SCAP_LAB_PROFILE
    %define PAOS_SCAP_LAB_PROFILE 0
%endif

scap_profile_enabled:
    mov  eax, PAOS_SCAP_LAB_PROFILE
    ret

; ---------------------------------------------------------------------------
; scap_init — announce the screenshot server surface. The "bind" is structural
;   (udp_handle_ipv4 routes dport 9996 here unconditionally); the marker is
;   EARNED on a real framebuffer (fb_base != 0 via the genuine GOP path) —
;   headless boots emit the honest skip line and no marker.
;   clobbers: RDI (serial_string clobbers caller-saved)
; ---------------------------------------------------------------------------
scap_init:
    call scap_grant_kat                       ; Task3404 clock-free grant KAT
    call scap_profile_enabled
    test eax, eax
    jnz  .grant_announced
    lea  rdi, [rel str_scap_grant_closed]
    call serial_string
.grant_announced:
    cmp  qword [rel fb_base], 0
    je   .nofb
    lea  rdi, [rel str_scap_ready]
    call serial_string
    lea  rdi, [rel str_scap_v2_ready]
    call serial_string
    ret
.nofb:
    lea  rdi, [rel str_scap_nofb]
    call serial_string
    ret


; ---------------------------------------------------------------------------
; Task3404 — owner-authenticated STILL-FRAME GRANT (the D1 pixel observer).
;   Release builds keep :9996 closed exactly as Task3017/3020 shipped it. The
;   ONLY way to open it is an owner AUTH1-signed SCAPGRANT <seconds> on :9997,
;   which opens ONE bounded window (<= SCAP_GRANT_MAX_S) for the GRANTING PEER
;   IP alone; any other peer, any request outside the window, and every request
;   in the shipped default is refused before parse, route capture, TX or fb
;   read — the same silence as before. SCAPGRANT 0 revokes; expiry closes it
;   without any packet. Lab builds (PAOS_SCAP_PROFILE=lab) are unchanged.
;   SEC-S1b: the window also names the SCAPGRANT datagram's Ethernet source MAC
;   and ingress NIC. The reply goes to the request's own source MAC, so an
;   IP-only grant handed the owner's frames to any LAN host spoofing that IP. A
;   request from the granted IP with another MAC or NIC is a foreign peer.
;   Residual: a host that spoofs the MAC as well (an active L2 attacker) is not
;   stopped; that needs an authenticated channel.
; ---------------------------------------------------------------------------
SCAP_GRANT_MAX_S equ 120

; scap_grant_open(EDI=peer_ip wire-order, ESI=seconds, RDX=6-byte source MAC,
;   RCX=ingress handle) -> RAX=until_us (0=closed). A missing, all-zero,
;   broadcast or multicast MAC closes.
scap_grant_open:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, edi
    mov  ebx, esi
    mov  r13, rdx
    mov  r14, rcx
    test ebx, ebx
    jz   .close
    test r13, r13
    jz   .close
    ; No real granting host sends from these (root 2026-10-17 20:38): a
    ; broadcast or multicast source (I/G bit) or an all-zero MAC closes, as a
    ; missing one does.
    test byte [r13], 1
    jnz  .close
    mov  eax, [r13]
    movzx ecx, word [r13 + 4]
    or   eax, ecx
    jz   .close
    cmp  ebx, SCAP_GRANT_MAX_S
    jbe  .bounded
    mov  ebx, SCAP_GRANT_MAX_S
.bounded:
    call scap_cancel                         ; a new grant retires any older capture
    call time_monotonic_now_us
    mov  rcx, rbx
    imul rcx, rcx, 1000000
    add  rax, rcx
    mov  [rel scap_grant_peer_ip], r12d
    mov  ecx, [r13]
    mov  [rel scap_grant_peer_mac], ecx
    mov  cx, [r13 + 4]
    mov  [rel scap_grant_peer_mac + 4], cx
    mov  [rel scap_grant_handle], r14
    mov  [rel scap_grant_until_us], rax
    lea  rdi, [rel str_scap_grant_open]
    call serial_string
    mov  rax, [rel scap_grant_until_us]
    jmp  .out
.close:
    call scap_grant_close
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; scap_grant_stage_refusal() — stage the bounded SCAPGRANT refusal reply. command_udp's
; generic envelope prints "<VERB> OK ARG=" for every verb but DIAGRING regardless of
; RSP_CODE, so an over-limit/garbled grant must stage its own text or the wire lies
; (Task3404 bad_arg_negative). Consumed exactly like form_out: one lean datagram.
scap_grant_stage_refusal:
    push rdi
    push rsi
    lea  rsi, [rel str_scap_grant_refused]
    lea  rdi, [rel scap_out_buf]
.cp:
    mov  al, [rsi]
    mov  [rdi], al
    inc  rsi
    inc  rdi
    test al, al
    jnz  .cp
    mov  byte [rel scap_out_ready], 1
    pop  rsi
    pop  rdi
    ret
; scap_grant_close() — revoke (SCAPGRANT 0) or expiry; restores the shipped posture.
scap_grant_close:
    call scap_cancel                         ; revoke/expiry retires pending pixels and route
    mov  qword [rel scap_grant_until_us], 0
    mov  dword [rel scap_grant_peer_ip], 0
    mov  dword [rel scap_grant_peer_mac], 0
    mov  word [rel scap_grant_peer_mac + 4], 0
    mov  qword [rel scap_grant_handle], 0
    lea  rdi, [rel str_scap_grant_close]
    call serial_string
    ret

; scap_grant_admits(EDI=peer_ip, RSI=now_us) -> EAX 1/0. Pure over the grant state.
scap_grant_admits:
    xor  eax, eax
    mov  rcx, [rel scap_grant_until_us]
    test rcx, rcx
    jz   .no
    cmp  rsi, rcx
    jae  .no                                  ; window elapsed
    cmp  edi, [rel scap_grant_peer_ip]
    jne  .no                                  ; not the granting owner host
    mov  eax, 1
.no:
    ret

; scap_grant_route_matches() -> EAX 1/0: the snapshotted request's source MAC and
;   ingress handle are the grant's (SEC-S1b). Pure over the snapshots; clobbers RCX.
scap_grant_route_matches:
    xor  eax, eax
    mov  rcx, [rel scap_peer_handle]
    cmp  rcx, [rel scap_grant_handle]
    jne  .no
    mov  ecx, [rel scap_peer_mac]
    cmp  ecx, [rel scap_grant_peer_mac]
    jne  .no
    mov  cx, [rel scap_peer_mac + 4]
    cmp  cx, [rel scap_grant_peer_mac + 4]
    jne  .no
    mov  eax, 1
.no:
    ret

; scap_capture_admitted() -> EAX: lab profile, or a grant window is pending.
;   The pre-parse :9996 gate (clobbers EAX only, like scap_profile_enabled).
scap_capture_admitted:
    call scap_profile_enabled
    test eax, eax
    jnz  .yes
    cmp  qword [rel scap_grant_until_us], 0
    je   .no
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; scap_request_admitted() -> EAX: lab profile, or the snapshotted requester
;   (scap_peer_ip) holds a live grant. An elapsed window is closed here, silently.
;   Preserves every register except RAX (called before the handlers save state).
scap_request_admitted:
    push rdi
    push rsi
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    call scap_profile_enabled
    test eax, eax
    jnz  .yes
    cmp  qword [rel scap_grant_until_us], 0
    je   .no
    call time_monotonic_now_us
    mov  rsi, rax
    mov  edi, [rel scap_peer_ip]
    call scap_grant_admits
    test eax, eax
    jz   .not_granted
    call scap_grant_route_matches
    test eax, eax
    jnz  .yes
    jmp  .no                                  ; granted IP, other MAC/NIC: foreign, window kept
.not_granted:
    call time_monotonic_now_us
    cmp  rax, [rel scap_grant_until_us]
    jb   .no                                  ; foreign peer inside a live window: keep it for the owner
    call scap_grant_close                     ; elapsed: restore the shipped posture
.no:
    xor  eax, eax
    jmp  .out
.yes:
    mov  eax, 1
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rsi
    pop  rdi
    ret

; scap_grant_kat — clock-free KAT over the pure admit function: the granting peer
;   is admitted inside its window, another peer is refused, the same peer is
;   refused once the window elapsed, and the closed state refuses everyone.
scap_grant_kat:
    push rbx
    mov  dword [rel scap_grant_peer_ip], 0x0100A8C0
    mov  qword [rel scap_grant_until_us], 1000
    mov  edi, 0x0100A8C0
    mov  esi, 999
    call scap_grant_admits
    mov  ebx, eax                             ; expect 1
    mov  edi, 0x0200A8C0
    mov  esi, 999
    call scap_grant_admits
    shl  eax, 1
    or   ebx, eax                             ; expect 0
    mov  edi, 0x0100A8C0
    mov  esi, 1000
    call scap_grant_admits
    shl  eax, 2
    or   ebx, eax                             ; expect 0
    mov  qword [rel scap_grant_until_us], 0
    mov  dword [rel scap_grant_peer_ip], 0
    mov  edi, 0x0100A8C0
    xor  esi, esi
    call scap_grant_admits
    shl  eax, 3
    or   ebx, eax                             ; expect 0
    ; SEC-S1b: the granted MAC/NIC matches; another MAC or NIC does not.
    mov  dword [rel scap_grant_peer_mac], 0xccbbaa02
    mov  word [rel scap_grant_peer_mac + 4], 0x09dd
    mov  qword [rel scap_grant_handle], 0x1000
    mov  dword [rel scap_peer_mac], 0xccbbaa02
    mov  word [rel scap_peer_mac + 4], 0x09dd
    mov  qword [rel scap_peer_handle], 0x1000
    call scap_grant_route_matches
    shl  eax, 4
    or   ebx, eax                             ; expect 1
    mov  word [rel scap_peer_mac + 4], 0x66dd
    call scap_grant_route_matches
    shl  eax, 5
    or   ebx, eax                             ; expect 0
    mov  word [rel scap_peer_mac + 4], 0x09dd
    mov  qword [rel scap_peer_handle], 0x2000
    call scap_grant_route_matches
    shl  eax, 6
    or   ebx, eax                             ; expect 0
    call scap_grant_close
    mov  dword [rel scap_peer_mac], 0
    mov  word [rel scap_peer_mac + 4], 0
    mov  qword [rel scap_peer_handle], 0
    cmp  ebx, 0x11
    jne  .fail
    lea  rdi, [rel str_scap_grant_kat]
    call serial_string
    pop  rbx
    ret
.fail:
    lea  rdi, [rel str_scap_grant_kat_fail]
    call serial_string
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; scap_on_screen2(RDI=request, ESI=request length) — serve SCREEN2 full-frame
;   or RECT. command_udp has already recognized the exact trigger/prefix and
;   snapshotted the reply route. All RECT syntax and geometry are linted before
;   the first packet is sent. Preserves callee-saved registers.
; ---------------------------------------------------------------------------
scap_on_screen2:
    call scap_request_admitted                ; Task3404: lab profile OR the requester's live owner grant
    test eax, eax
    jz   .disabled                            ; release: before TX or framebuffer read
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13d, esi

    ; Degrade law: no framebuffer means no v2 protocol at all, including REFUSE.
    cmp  qword [rel fb_base], 0
    je   .done

    ; Exact full-frame request: "SCREEN2\n". The dispatcher recognizes this
    ; shape too; repeat the lint here so no future caller can bypass it.
    cmp  r13d, 8
    jne  .parse_rect
    cmp  dword [r12], 'SCRE'
    jne  .bad_rect
    cmp  word [r12 + 4], 'EN'
    jne  .bad_rect
    cmp  byte [r12 + 6], '2'
    jne  .bad_rect
    cmp  byte [r12 + 7], 10
    jne  .bad_rect
    xor  r14d, r14d
    xor  r15d, r15d
    mov  ebx, [rel fb_width]
    mov  ebp, [rel fb_height]
    jmp  .lint_done

.parse_rect:
    ; Exact grammar: SCREEN2 RECT <x> <y> <w> <h>\n, decimal u16 values,
    ; single separators, no multi-digit leading zeroes, and no trailing bytes.
    cmp  r13d, 13
    jb   .bad_rect
    cmp  dword [r12], 'SCRE'
    jne  .bad_rect
    cmp  dword [r12 + 4], 'EN2 '
    jne  .bad_rect
    cmp  dword [r12 + 8], 'RECT'
    jne  .bad_rect
    cmp  byte [r12 + 12], ' '
    jne  .bad_rect
    lea  rsi, [r12 + 13]
    lea  rdx, [r12 + r13]
    call scap_parse_u16
    jc   .bad_rect
    mov  r14d, eax
    cmp  rsi, rdx
    jae  .bad_rect
    cmp  byte [rsi], ' '
    jne  .bad_rect
    inc  rsi
    call scap_parse_u16
    jc   .bad_rect
    mov  r15d, eax
    cmp  rsi, rdx
    jae  .bad_rect
    cmp  byte [rsi], ' '
    jne  .bad_rect
    inc  rsi
    call scap_parse_u16
    jc   .bad_rect
    mov  ebx, eax
    cmp  rsi, rdx
    jae  .bad_rect
    cmp  byte [rsi], ' '
    jne  .bad_rect
    inc  rsi
    call scap_parse_u16
    jc   .bad_rect
    mov  ebp, eax
    cmp  rsi, rdx
    jae  .bad_rect
    cmp  byte [rsi], 10
    jne  .bad_rect
    inc  rsi
    cmp  rsi, rdx
    jne  .bad_rect

    ; Bounds use widened u32 sums after each input was proven <=65535.
    cmp  ebx, 1
    jb   .bad_rect
    cmp  ebp, 1
    jb   .bad_rect
    mov  eax, r14d
    add  eax, ebx
    cmp  eax, [rel fb_width]
    ja   .bad_rect
    mov  eax, r15d
    add  eax, ebp
    cmp  eax, [rel fb_height]
    ja   .bad_rect

.lint_done:
    cmp  ebx, 1
    jb   .bad_rect
    cmp  ebp, 1
    jb   .bad_rect

    ; An in-flight capture owns separate geometry and route state.
    cmp  byte [rel scap_sending], 0
    jne  .busy
    mov  byte [rel scap_sending], 1
    mov  [rel scap_cap_x], r14d
    mov  [rel scap_cap_y], r15d
    mov  [rel scap_cap_w], ebx
    mov  [rel scap_cap_h], ebp

    cmp  byte [rel scap_first_req], 0
    jne  .no_log
    mov  byte [rel scap_first_req], 1
    lea  rdi, [rel str_scap_req]
    call serial_string
.no_log:
    mov  byte [rel scap_stream_v2], 1
    call scap_queue_begin
    jmp  .done
.bad_rect:
    mov  edi, SCAP_RF_BAD_RECT
    call scap_send_refuse
    jmp  .done
.busy:
    mov  edi, SCAP_RF_BUSY
    call scap_send_refuse
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
.disabled:
    mov  qword [rel scap_peer_handle], 0
    ret

; ---------------------------------------------------------------------------
; scap_on_screen — serve one screenshot request. The caller (udp_handle_ipv4
;   :9996 branch) has already validated "SCREEN\n" and filled the reply route
;   (scap_peer_mac/ip/port + scap_our_mac + scap_src_ip). The idle service sends
;   START, row-packed DATA with an additive byte checksum, then COMMIT.
;   Queues owned state and returns without pacing or framebuffer reads.
;   Preserves callee-saved regs (runs inside the RX dispatch).
; ---------------------------------------------------------------------------
scap_on_screen:
    call scap_request_admitted                ; Task3404: lab profile OR the requester's live owner grant
    test eax, eax
    jz   .disabled                            ; release: before TX or framebuffer read
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    ; degrade: no framebuffer -> silent (never fault the net task)
    cmp  qword [rel fb_base], 0
    je   .done
    ; reentrancy guard (paranoia: the poll loop is single-threaded today)
    cmp  byte [rel scap_sending], 0
    jne  .done
    mov  byte [rel scap_sending], 1
    ; log the first request only (monolith shape — no per-capture serial spam)
    cmp  byte [rel scap_first_req], 0
    jne  .no_log
    mov  byte [rel scap_first_req], 1
    lea  rdi, [rel str_scap_req]
    call serial_string
.no_log:
    ; total wire size = width * height * 4 (packed BGRX)
    mov  eax, [rel fb_width]
    imul eax, [rel fb_height]
    shl  eax, 2
    mov  [rel scap_total], eax
    mov  dword [rel scap_cap_x], 0
    mov  dword [rel scap_cap_y], 0
    mov  eax, [rel fb_width]
    mov  [rel scap_cap_w], eax
    mov  eax, [rel fb_height]
    mov  [rel scap_cap_h], eax
    mov  byte [rel scap_stream_v2], 0
    call scap_queue_begin
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
.disabled:
    mov  qword [rel scap_peer_handle], 0
    ret

; Advance per-boot identity and snapshot the live geometry triple.
scap_capture_begin:
    mfence                              ; 1249: the framebuffer is WC-mapped; drain combining buffers before readback
    inc  dword [rel scap_capture_seq]
    mov  eax, [rel fb_width]
    cmp  eax, [rel scap_geom_width]
    jne  .changed
    mov  eax, [rel fb_height]
    cmp  eax, [rel scap_geom_height]
    jne  .changed
    mov  eax, [rel fb_stride]
    cmp  eax, [rel scap_geom_stride]
    jne  .changed
    ret
.changed:
    inc  dword [rel scap_geom_epoch]
    mov  eax, [rel fb_width]
    mov  [rel scap_geom_width], eax
    mov  eax, [rel fb_height]
    mov  [rel scap_geom_height], eax
    mov  eax, [rel fb_stride]
    mov  [rel scap_geom_stride], eax
    ret

; Admission executes in trusted RX context; no request/framebuffer buffer is
; borrowed across a return. NIC contexts/vtables have registry lifetime; the
; existing registration epoch invalidates same-address re-registration. The
; normal BSP poll is serialized with registry/device/framebuffer publication.
scap_queue_begin:
    mov  eax, [rel fb_width]
    test eax, eax
    jz   scap_cancel
    cmp  eax, [rel fb_stride]
    ja   scap_cancel
    mov  ecx, [rel fb_height]
    test ecx, ecx
    jz   scap_cancel
    mov  eax, [rel fb_stride]
    imul rax, rcx
    mov  rdx, rax
    shr  rdx, 62
    jnz  scap_cancel
    shl  rax, 2
    cmp  rax, [rel fb_size]
    ja   scap_cancel
    mov  rdx, [rel fb_base]
    add  rdx, rax
    jc   scap_cancel
    mov  eax, [rel scap_cap_w]
    mov  ecx, [rel scap_cap_h]
    imul rax, rcx
    mov  ecx, 0x3fffffff
    cmp  rax, rcx
    ja   scap_cancel
    test rax, rax
    jz   scap_cancel
    shl  eax, 2
    mov  [rel scap_total], eax
    call scap_capture_begin
    ; Trusted current RX ingress, before any yield. Subsequent turns first use
    ; the registry membership seam, never this unchecked handle dereference.
    mov  rdi, [rel scap_peer_handle]
    test rdi, rdi
    jz   scap_cancel
    mov  rsi, [rdi + dev.ops]
    mov  [rel scap_active_ops], rsi
    call netdev_power_member
    test rax, rax
    jz   scap_cancel
    mov  [rel scap_active_epoch_ptr], rax
    mov  [rel scap_active_epoch], rdx
    mov  rax, [rel scap_active_ops]
    mov  rax, [rax + netdev_ops.tx]
    test rax, rax
    jz   scap_cancel
    mov  [rel scap_active_tx], rax
    lea  rsi, [rel scap_peer_mac]
    lea  rdi, [rel scap_active_route]
    mov  ecx, SCAP_ROUTE_SIZE
    cld
    rep  movsb
    mov  rax, [rel fb_base]
    mov  [rel scap_geom_base], rax
    mov  rax, [rel fb_size]
    mov  [rel scap_geom_size], rax
    mov  eax, [rel fb_pixel_format]
    mov  [rel scap_geom_format], eax
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel scap_capture_tsc], rax
    call time_monotonic_now_us
    mov  [rel scap_next_us], rax
    add  rax, SCAP_GRANT_MAX_S * 1000000
    jc   scap_cancel
    mov  [rel scap_deadline_us], rax       ; also finite in deliberate lab profile
    mov  dword [rel scap_row], 0
    mov  dword [rel scap_row_offset], 0
    mov  dword [rel scap_offset], 0
    mov  dword [rel scap_sum], 0
    mov  byte [rel scap_phase], 1          ; START is built in the service turn
    mov  qword [rel scap_peer_handle], 0   ; release RX scratch route
    ret

; scap_poll() — one packet/copy <=1024 bytes per normal main-loop turn.
; Never loops over packets or polls RX. Fresh post-TX pacing prevents a catchup
; burst after a slow/late sweep. The driver retains its own existing TX bound.
; The finite pending state bypasses voluntary BSP HLT so timer IRQ frequency
; cannot throttle the 500us pacing; every pass still serves the whole idle loop.
scap_pending:
    movzx eax, byte [rel scap_sending]
    ret

scap_poll:
    cmp  byte [rel scap_sending], 0
    je   .idle
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    lea  rsi, [rel scap_active_route]
    lea  rdi, [rel scap_peer_mac]
    mov  ecx, SCAP_ROUTE_SIZE
    cld
    rep  movsb
    call scap_request_admitted             ; recheck privacy even before the next due time
    test eax, eax
    jz   .cancel
    call time_monotonic_now_us
    cmp  rax, [rel scap_deadline_us]
    jae  .cancel
    ; Validate membership/epoch BEFORE dereferencing retained handle or ops.
    mov  rdi, [rel scap_active_handle]
    mov  rsi, [rel scap_active_ops]
    call netdev_power_member
    test rax, rax
    jz   .cancel
    cmp  rax, [rel scap_active_epoch_ptr]
    jne  .cancel
    cmp  rdx, [rel scap_active_epoch]
    jne  .cancel
    mov  rax, [rel scap_active_ops]
    mov  rax, [rax + netdev_ops.tx]
    cmp  rax, [rel scap_active_tx]
    jne  .cancel
    ; A mode/base/extent/format change ends BOTH protocols before any pixel
    ; load. Recompute the source pointer from the freshly checked live base;
    ; no per-chunk framebuffer pointer survives a yield.
    mov  rax, [rel fb_base]
    cmp  rax, [rel scap_geom_base]
    jne  .mode_changed
    mov  rax, [rel fb_size]
    cmp  rax, [rel scap_geom_size]
    jne  .mode_changed
    mov  eax, [rel fb_width]
    cmp  eax, [rel scap_geom_width]
    jne  .mode_changed
    mov  eax, [rel fb_height]
    cmp  eax, [rel scap_geom_height]
    jne  .mode_changed
    mov  eax, [rel fb_stride]
    cmp  eax, [rel scap_geom_stride]
    jne  .mode_changed
    mov  eax, [rel fb_pixel_format]
    cmp  eax, [rel scap_geom_format]
    jne  .mode_changed
    call time_monotonic_now_us
    cmp  rax, [rel scap_next_us]
    jb   .out
    cmp  byte [rel scap_phase], 1
    je   .start
    cmp  byte [rel scap_phase], 3
    je   .commit
    ; Exactly one row chunk, preserving the historical wire offsets and
    ; partial-row packet boundaries, without exporting pitch slack.
    mov  eax, [rel scap_cap_y]
    add  eax, [rel scap_row]
    mov  ecx, [rel scap_geom_stride]
    imul rax, rcx
    mov  ecx, [rel scap_cap_x]
    add  rax, rcx
    shl  rax, 2
    mov  ecx, [rel scap_row_offset]
    add  rax, rcx
    mov  rsi, [rel fb_base]
    add  rsi, rax
    mov  r12d, [rel scap_cap_w]
    shl  r12d, 2
    sub  r12d, [rel scap_row_offset]
    cmp  r12d, SCAP_CHUNK
    jbe  .chunk_size
    mov  r12d, SCAP_CHUNK
.chunk_size:
    mfence                                ; drain WC writes before this chunk read
    lea  rdi, [rel scap_frame + 42]
    mov  byte [rdi], SCAP_PKT_DATA
    mov  eax, [rel scap_offset]
    mov  [rdi + 1], eax
    add  rdi, 5
    mov  ecx, r12d
    mov  edx, [rel scap_sum]
.copy:
    movzx eax, byte [rsi]
    mov  [rdi], al
    add  edx, eax
    inc  rsi
    inc  rdi
    dec  ecx
    jnz  .copy
    mov  [rel scap_sum], edx
    add  [rel scap_offset], r12d
    add  [rel scap_row_offset], r12d
    mov  eax, [rel scap_cap_w]
    shl  eax, 2
    cmp  eax, [rel scap_row_offset]
    jne  .data_ready
    mov  dword [rel scap_row_offset], 0
    inc  dword [rel scap_row]
    mov  eax, [rel scap_row]
    cmp  eax, [rel scap_cap_h]
    jne  .data_ready
    mov  byte [rel scap_phase], 3
.data_ready:
    lea  edi, [r12d + 5]
    jmp  .send
.start:
    lea  rbx, [rel scap_frame + 42]
    mov  byte [rbx], SCAP_PKT_START
    mov  dword [rbx + 1], SCAP_MAGIC
    mov  eax, [rel scap_cap_w]
    mov  [rbx + 5], eax
    mov  eax, [rel scap_cap_h]
    mov  [rbx + 9], eax
    mov  eax, [rel scap_geom_format]
    mov  [rbx + 13], eax
    mov  eax, [rel scap_total]
    mov  [rbx + 17], eax
    mov  edi, 21
    cmp  byte [rel scap_stream_v2], 0
    je   .start_ready
    mov  dword [rbx + 1], SCAP_MAGIC_V2
    mov  eax, [rel scap_capture_seq]
    mov  [rbx + 21], eax
    mov  eax, [rel scap_geom_epoch]
    mov  [rbx + 25], eax
    mov  rax, [rel scap_capture_tsc]
    mov  [rbx + 29], rax
    mov  edi, 37
.start_ready:
    mov  byte [rel scap_phase], 2
.send:
    call scap_tx
    test rax, rax
    jnz  .cancel
    call time_monotonic_now_us
    add  rax, SCAP_DELAY_US
    jc   .cancel
    mov  [rel scap_next_us], rax
    jmp  .out
.commit:
    lea  rbx, [rel scap_frame + 42]
    mov  byte [rbx], SCAP_PKT_COMMIT
    mov  eax, [rel scap_sum]
    mov  [rbx + 1], eax
    mov  edi, 5
    call scap_tx
    jmp  .cancel
.mode_changed:
    cmp  byte [rel scap_stream_v2], 0
    je   .cancel                         ; V1 has no mode-change token
    mov  edi, SCAP_RF_MODE_CHANGED
    call scap_send_refuse
.cancel:
    call scap_cancel
.out:
    mov  qword [rel scap_peer_handle], 0
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
.idle:
    ret

; Terminal paths (completion, revoke/regrant, expiry, TX/lifecycle failure)
; retire every retained route, pointer, pacing and progress field. No retry.
scap_cancel:
    mov  byte [rel scap_sending], 0
    mov  qword [rel scap_peer_handle], 0
    lea  rdi, [rel scap_active_state]
    mov  ecx, SCAP_ACTIVE_SIZE
    xor  eax, eax
    cld
    rep  stosb
    ret

; scap_parse_u16(RSI=cursor, RDX=end) -> EAX=value, RSI=first non-digit,
; CF=0 success. Multi-digit leading zeroes and values >65535 are rejected.
scap_parse_u16:
    xor  eax, eax
    xor  ecx, ecx
    cmp  rsi, rdx
    jae  .fail
    movzx r8d, byte [rsi]
    cmp  r8b, '0'
    jne  .digits
    inc  rsi
    cmp  rsi, rdx
    jae  .success
    movzx r8d, byte [rsi]
    cmp  r8b, '0'
    jb   .success
    cmp  r8b, '9'
    jbe  .fail
    jmp  .success
.digits:
    cmp  r8b, '1'
    jb   .fail
    cmp  r8b, '9'
    ja   .fail
.loop:
    cmp  rsi, rdx
    jae  .finish
    movzx r8d, byte [rsi]
    cmp  r8b, '0'
    jb   .finish
    cmp  r8b, '9'
    ja   .finish
    sub  r8d, '0'
    cmp  eax, 6553
    ja   .fail
    jb   .accumulate
    cmp  r8d, 5
    ja   .fail
.accumulate:
    imul eax, eax, 10
    add  eax, r8d
    inc  rsi
    inc  ecx
    jmp  .loop
.finish:
    test ecx, ecx
    jz   .fail
.success:
    clc
    ret
.fail:
    stc
    ret

scap_send_refuse:
    lea  rax, [rel scap_frame + 42]
    mov  byte [rax], SCAP_PKT_REFUSE
    mov  byte [rax + 1], dil
    mov  edi, 2
    call scap_tx
    ret

; ---------------------------------------------------------------------------
; scap_tx(EDI = UDP payload length; payload already staged at scap_frame+42) —
;   wrap eth+IPv4+UDP headers around the staged payload (src :9996 -> the
;   requester's addr/port), pad to the 60-byte Ethernet minimum, TX through the
;   netdev seam. Same header recipe as the proven :9997 reply path.
;   clobbers: caller-saved only (loop state lives in callee-saved regs)
; ---------------------------------------------------------------------------
scap_tx:
    push rbx
    mov  ebx, edi                       ; ebx = payload length
    lea  rsi, [rel scap_frame]
    ; eth: dst = requester MAC, src = our MAC, type = IPv4
    mov  eax, [rel scap_peer_mac]
    mov  [rsi + 0], eax
    mov  ax,  [rel scap_peer_mac + 4]
    mov  [rsi + 4], ax
    mov  eax, [rel scap_our_mac]
    mov  [rsi + 6], eax
    mov  ax,  [rel scap_our_mac + 4]
    mov  [rsi + 10], ax
    mov  byte [rsi + 12], 0x08           ; ethertype IPv4
    mov  byte [rsi + 13], 0x00
    ; IPv4 header at r8+14
    mov  byte [rsi + 14], 0x45           ; version 4, IHL 5
    mov  byte [rsi + 15], 0x00
    lea  eax, [rbx + 28]                ; total length = 20 + 8 + payload
    mov  [rsi + 16], ah                  ; network order
    mov  [rsi + 17], al
    mov  word [rsi + 18], 0              ; identification
    mov  byte [rsi + 20], 0              ; flags/frag
    mov  byte [rsi + 21], 0
    mov  byte [rsi + 22], 64             ; TTL
    mov  byte [rsi + 23], 17             ; protocol UDP
    mov  word [rsi + 24], 0              ; checksum (computed below)
    mov  eax, [rel scap_src_ip]         ; src IP = the addr the request came to
    mov  [rsi + 26], eax
    mov  eax, [rel scap_peer_ip]        ; dst IP = requester
    mov  [rsi + 30], eax
    lea  rdi, [rsi + 14]
    mov  esi, 20
    call net_cksum16                    ; AX = header checksum (clobbers r8? no: RAX,RCX,RDX,RDI)
    lea  rsi, [rel scap_frame]
    mov  cx, ax
    mov  [rsi + 24], ch                  ; store network order
    mov  [rsi + 25], cl
    ; UDP header at r8+34
    mov  byte [rsi + 34], (SCAP_UDP_PORT >> 8) & 0xFF   ; src port 9996
    mov  byte [rsi + 35], SCAP_UDP_PORT & 0xFF
    mov  ax,  [rel scap_peer_port]      ; dst port (already network order)
    mov  [rsi + 36], ax
    lea  eax, [rbx + 8]                 ; UDP length = 8 + payload
    mov  [rsi + 38], ah
    mov  [rsi + 39], al
    mov  word [rsi + 40], 0              ; UDP checksum 0 = not computed (valid IPv4)
    ; frame length (pad to the 60-byte minimum)
    lea  edx, [rbx + 42]
    cmp  edx, 60
    jae  .send
    lea  rdi, [rsi + rdx]
    mov  ecx, 60
    sub  ecx, edx
    xor  eax, eax
    cld
    rep  stosb
    mov  edx, 60
.send:
    lea  rsi, [rel scap_frame]
    ; This is a reply to the admitted ingress tuple, not background traffic.
    ; A different primary/domain NIC must never inherit this frame or peer MAC.
    mov  rdi, [rel scap_peer_handle]
    test rdi, rdi
    jz   .drop
    mov  r10, [rdi + dev.ops]
    test r10, r10
    jz   .drop
    mov  r11, [r10 + netdev_ops.tx]
    test r11, r11
    jz   .drop
    call r11
    pop  rbx
    ret
.drop:
    mov  rax, -1
    pop  rbx
    ret

; --- data ------------------------------------------------------------------
; reply route — filled by udp_handle_ipv4's :9996 branch before scap_on_screen
scap_peer_mac:  times 6 db 0
scap_our_mac:   times 6 db 0
scap_peer_ip:   dd 0
scap_src_ip:    dd 0
scap_peer_port: dw 0
align 8
scap_peer_handle: dq 0                   ; RX/service scratch only; retained route is owned below
SCAP_ROUTE_SIZE equ $ - scap_peer_mac
scap_grant_until_us: dq 0                 ; Task3404: monotonic us the owner grant elapses (0 = closed)
scap_grant_peer_ip:  dd 0                 ; Task3404: the granting owner host (wire order)
scap_grant_peer_mac: times 6 db 0         ; SEC-S1b: the SCAPGRANT datagram's source MAC
align 8
scap_grant_handle:   dq 0                 ; SEC-S1b: and its ingress NIC
scap_total:     dd 0
scap_sending:   db 0
scap_first_req: db 0
scap_stream_v2: db 0
align 4
scap_capture_seq: dd 0
scap_geom_epoch: dd 0
scap_geom_width: dd 0
scap_geom_height: dd 0
scap_geom_stride: dd 0
scap_cap_x:     dd 0
scap_cap_y:     dd 0
scap_cap_w:     dd 0
scap_cap_h:     dd 0
scap_capture_tsc: dq 0
align 8
scap_active_state:
scap_active_route: times (scap_peer_handle - scap_peer_mac) db 0
scap_active_handle: dq 0
scap_active_ops: dq 0
scap_active_tx: dq 0
scap_active_epoch_ptr: dq 0
scap_active_epoch: dq 0
scap_geom_base: dq 0
scap_geom_size: dq 0
scap_geom_format: dd 0
scap_row: dd 0
scap_row_offset: dd 0
scap_offset: dd 0
scap_sum: dd 0
scap_phase: db 0
align 8
scap_next_us: dq 0
scap_deadline_us: dq 0
SCAP_ACTIVE_SIZE equ $ - scap_active_state
; one TX frame: eth(14) + ip(20) + udp(8) + type(1)+offset(4)+chunk(1024)
scap_frame:     times (42 + 5 + SCAP_CHUNK + 16) db 0

str_scap_ready: db "[PAOS64] L5 svc: screenshot server bound UDP :9996 (GOP fb dump, SCREEN -> START/DATA/COMMIT) [scap.server.ready]", 13, 10, 0
str_scap_v2_ready: db "[PAOS64] M6 scap: protocol v2 ready (SCREEN2 seq/epoch/tsc + RECT, refuse tokens) [gui.scap.v2]", 13, 10, 0
%if PAOS_SCAP_LAB_PROFILE                ; SEC-P2-release: plain-byte floor identity (release_floor_guard.py)
str_scap_floor_identity: db "PAOS-FLOOR scap=lab", 0
%else
str_scap_floor_identity: db "PAOS-FLOOR scap=shipped", 0
%endif
str_scap_nofb:  db "[PAOS64] L5 svc: screenshot server skipped (no GOP framebuffer)", 13, 10, 0
str_scap_req:   db "[PAOS64] L5 svc: screenshot request received, streaming framebuffer", 13, 10, 0
str_scap_grant_closed: db "[PAOS64] M6 scap: release still-frame grant CLOSED by default; owner AUTH1 SCAPGRANT opens one peer-bound window <= 120s [security.scap.grant.closed]", 13, 10, 0
str_scap_grant_kat: db "[PAOS64] M6 scap: still-frame grant KAT peer-bound/elapsed/closed refusals PASS [security.scap.grant.kat]", 13, 10, 0
str_scap_grant_kat_fail: db "[PAOS64] M6 scap: still-frame grant KAT FAIL", 13, 10, 0
scap_out_ready: db 0
scap_out_buf:   times 64 db 0
str_scap_grant_refused: db " SCAPGRANT REFUSED reason=bad_arg max_s=120", 0
str_scap_grant_open: db "[PAOS64] M6 scap: still-frame grant OPEN (owner AUTH1, peer-bound, bounded)", 13, 10, 0
str_scap_grant_close: db "[PAOS64] M6 scap: still-frame grant CLOSED (revoked or elapsed; shipped posture restored)", 13, 10, 0
