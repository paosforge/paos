;; MODULE boot/beacon
;; LAYER 0
;; EXPORTS beacon_nonce_init, beacon_gop_paint, beacon_gop_dismiss, beacon_gop_floor_skip, beacon_wire_send, beacon_wire_mark_sent, boot_nonce, str_wire_magic
;; IMPORTS boot/serial, boot/gop
;; CAPS
;; OWNER saga:boot
; ============================================================================
; boot/beacon.asm — 1076 boot_beacon: the bare-metal OBSERVABILITY bootstrap.
;
; The M1/P2 keep is HEADLESS on real hardware — it emits a serial marker but
; paints NOTHING to the screen and puts NO frame on the wire, so deploy-rework's
; GLKVM/UDP verify has nothing to confirm and every bare_metal deploy runs
; deploy -> verify-fails -> recovers. This module gives boot two independent,
; un-fakeable beacons so a headless-DISPLAY box OR a no-cmd-NIC box is still
; confirmable on real hardware:
;
;   (A) GOP PAINT  — a KNOWN-COLOR block (rgb 0,180,90 = PaOS accent green) at a
;                    KNOWN region (24,24,320,64) with the per-boot NONCE rendered
;                    as hex text (black-on-green, OCR-friendly) inside it. A real
;                    boot shows the colored badge + nonce; a POST/black screen
;                    does not. GLKVM screendumps + PIL-mean-color + OCR grade it.
;   (B) WIRE BEACON— gratuitous-ARP + UDP-broadcast :9998 'PAOS_BOOT_BEACON <n>'
;                    that gpu sniffs via tcpdump — so a headless-display keep is
;                    STILL confirmable on the wire. Rides the 1009 netdev egress.
;
; ONE nonce per boot (TSC-seeded, derived ONCE) feeds BOTH signals, so the probe
; correlates wire-nonce == screen-nonce — un-fakeable by a latch (contract
; writing best practices §3.11: a marker firing proves CODE ran; the GATE is the
; content). Degrade-never-crash: no GOP -> serial notes it, wire still fires; no
; NIC -> 'boot_beacon.wire: skipped (no NIC)', GOP paint still runs.
;
; STATUS (1094 wire leg landed): the GOP paint + nonce legs are LIVE. The wire
; SEND rides the 1009/1029 netdev egress from svc/command_udp.asm
; (udp_boot_beacon_tick): at P5 the egress is not yet warmed (the 1051 split
; defers e1000e bring-up + autoneg to P8), so the P5 rung here still reports the
; honest skip; once P8 link-up completes the svc tick broadcasts the beacon
; (repeating ~10s so a sniffer window always catches it) and calls back into
; beacon_wire_mark_sent below. No phantom: beacon.wire.sent is emitted ONLY when
; netdev_tx actually accepted a frame (hw-only marker).
; ============================================================================

; --- fixed convention (the probe hardcodes these; keep + probe agree, not discover) ---
BEACON_COLOR   equ 0x0000B45A       ; (R<<16)|(G<<8)|B for rgb(0,180,90) in the BGRX fb dword (see gop_fill)
BEACON_X       equ 24
BEACON_Y       equ 24
BEACON_W       equ 320
BEACON_H       equ 64
GLYPH_SCALE    equ 4                 ; 8x8 hex font scaled 4x -> 32x32 per digit (OCR-legible)
GLYPH_ADV      equ 36               ; per-digit advance (32px glyph + 4px gap): 32 + 7*36 + 32 = 316 < block right (344)
GLYPH_TX       equ 32               ; nonce text origin x (inside the block: 24..344)
GLYPH_TY       equ 40               ; nonce text origin y (40..72, inside the block: 24..88)

; ---------------------------------------------------------------------------
; beacon_nonce_init — derive the per-boot nonce ONCE (TSC-seeded + mixed), store
; it, and emit the beacon.nonce marker with the value. Uses rdtsc INLINE (an
; instruction, not the L1 core/time helper — keeps boot/beacon a pure L0 module),
; so it is safe pre- or post-paging; called at P2. The SAME boot_nonce feeds the
; GOP paint and (when the egress lands) the wire beacon.
; ---------------------------------------------------------------------------
beacon_nonce_init:
    push rax
    push rdx
    rdtsc                           ; EDX:EAX = time-stamp counter
    xor  eax, edx                   ; fold high^low -> 32 bits
    imul eax, eax, 0x9E3779B1       ; Fibonacci-hash mix so low bits aren't raw TSC
    test eax, eax
    jnz  .have
    mov  eax, 0x0A0B0C0D            ; never emit an all-zero nonce (degenerate)
.have:
    mov  [rel boot_nonce], eax
    lea  rdi, [rel str_bnonce_pre]
    call serial_string
    mov  edi, [rel boot_nonce]
    call beacon_hex8_serial
    lea  rdi, [rel str_bnonce_post]
    call serial_string
    pop  rdx
    pop  rax
    ret

; ---------------------------------------------------------------------------
; beacon_gop_paint — paint the known-color block + render the nonce as hex text.
; Runs POST-paging (the fb window is identity-mapped RW+NX by boot/paging.asm).
; Degrades cleanly if GOP is absent (serial notes it, boot continues).
; ---------------------------------------------------------------------------
beacon_gop_paint:
    push rax
    mov  rax, [rel fb_base]
    test rax, rax
    jz   .no_gop
    ; (1) fill the known-color block
    mov  edi, BEACON_X
    mov  esi, BEACON_Y
    mov  edx, BEACON_W
    mov  ecx, BEACON_H
    mov  r8d, BEACON_COLOR
    call beacon_fill_rect
    ; (2) render the nonce as 8 hex digits (black text) inside the block
    call beacon_render_nonce_text
    ; (3) marker (proves the code ran; the GATE is the GLKVM color+OCR on hardware)
    lea  rdi, [rel str_bgop_pre]
    call serial_string
    mov  edi, [rel boot_nonce]
    call beacon_hex8_serial
    lea  rdi, [rel str_bgop_post]
    call serial_string
    pop  rax
    ret
.no_gop:
    lea  rdi, [rel str_bgop_none]
    call serial_string
    pop  rax
    ret

; beacon_gop_floor_skip — boot audit item 3: the shipped floor paints no badge, PLV1 panel or
; first-GOP crop. Say so with the per-boot nonce, so serial still carries what the badge showed.
beacon_gop_floor_skip:
    lea  rdi, [rel str_bgop_floor_pre]
    call serial_string
    mov  edi, [rel boot_nonce]
    call beacon_hex8_serial
    lea  rdi, [rel str_bgop_floor_post]
    call serial_string
    ret

; ---------------------------------------------------------------------------
; beacon_gop_dismiss — 1323: DECLUTTER the green nonce badge off the SETTLED
; desktop once its verification job is done. The badge is a DEBUG readout, not a
; wanted feature (1320 DEFECT 3): it exists so 1094's boot-confirm (GLKVM reads
; the on-screen nonce, correlates it with the :9998 wire nonce) has something to
; grade. Once the wire beacon has taken over verification AND the boot-confirm
; window has elapsed, the idle loop (udp_boot_beacon_tick) calls this ONCE.
;
; Boot audit item 3 (root 2026-10-17 17:53:44): the post-sign-in re-assert is gone, so the
; badge only exists on screen between the early paint and the first composed present. This
; now records the transition and its marker only (LOCKSTATE badge_*, LIVENESS, the CLI
; redraw read the dismissed state); it paints nothing.
; ---------------------------------------------------------------------------
BEACON_BG_COLOR equ 0x00103048       ; = gui/window.asm DESKTOP_COLOR (keep in sync); desktop backdrop
beacon_gop_dismiss:
    push rax
    mov  rax, [rel fb_base]
    test rax, rax
    jz   .nd_no_gop
    ; Boot audit item 3: no fill. Nothing re-paints the badge after the sign-in is composed, so
    ; the rect holds sign-in or desktop pixels by now; a backdrop fill would draw over them.
    lea  rdi, [rel str_bgop_dismiss]
    call serial_string
    pop  rax
    ret
.nd_no_gop:
    pop  rax
    ret

; ---------------------------------------------------------------------------
; beacon_wire_send — the P5 wire-beacon RUNG. At P5 the netdev egress is not yet
; warmed (the 1051 split defers the real e1000e bring-up + autoneg to P8), so
; this rung ALWAYS reports the honest skip — NOT a fabricated beacon.wire.sent
; (that would be the exact latch §3.11 forbids). The REAL send (gratuitous-ARP +
; UDP broadcast :9998 carrying str_wire_magic + boot_nonce) fires from
; svc/command_udp.asm's udp_boot_beacon_tick once P8 link-up completes; it calls
; back into beacon_wire_mark_sent below so the marker text + nonce stay owned
; here, next to the GOP leg that paints the SAME per-boot value.
; ---------------------------------------------------------------------------
beacon_wire_send:
    push rdi
    lea  rdi, [rel str_wire_skip]
    call serial_string
    pop  rdi
    ret

; ---------------------------------------------------------------------------
; beacon_wire_mark_sent — emit the earned [beacon.wire.sent] marker with the
; per-boot nonce (hw-only). Called ONLY by the svc-layer wire sender AFTER
; netdev_tx accepted the beacon frame — never on the skip path, so a stub
; cannot latch it. clobbers: RDI (serial path preserves the rest).
; ---------------------------------------------------------------------------
beacon_wire_mark_sent:
    lea  rdi, [rel str_wire_sent]
    call serial_string
    mov  edi, [rel boot_nonce]
    call beacon_hex8_serial
    lea  rdi, [rel str_wire_sent_post]
    call serial_string
    ret

; ---------------------------------------------------------------------------
; beacon_fill_rect(edi=x, esi=y, edx=w, ecx=h, r8d=color) — fill an axis-aligned
; rect in the GOP framebuffer. Simple [base + rax*4] / [rbx] addressing only
; (avoids the NASM [rsp+const+reg*scale-const] displacement pitfall).
; ---------------------------------------------------------------------------
beacon_fill_rect:
    push rax
    push rbx
    push rcx
    push rdx
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    mov  r9,  [rel fb_base]
    test r9, r9
    jz   .frdone
    mov  r10d, [rel fb_stride]      ; pixels per scanline
    mov  r12d, edi                 ; x
    mov  r13d, edx                 ; w
    mov  r14d, r8d                 ; color
    mov  r11d, esi                 ; cur y
.fr_row:
    test ecx, ecx
    jz   .frdone
    mov  eax, r11d
    imul eax, r10d                 ; y * stride
    add  eax, r12d                 ; + x  (eax zero-extends into rax)
    lea  rbx, [r9 + rax*4]         ; row pixel ptr
    mov  edx, r13d                 ; w columns
.fr_col:
    mov  [rbx], r14d
    add  rbx, 4
    dec  edx
    jnz  .fr_col
    inc  r11d
    dec  ecx
    jmp  .fr_row
.frdone:
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    ret

; ---------------------------------------------------------------------------
; beacon_render_nonce_text — draw the 8 hex digits of boot_nonce (high nibble
; first) as scaled glyphs, left to right, inside the block.
; ---------------------------------------------------------------------------
beacon_render_nonce_text:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    mov  r12d, [rel boot_nonce]    ; nonce
    xor  r13d, r13d                ; i = 0 (digit index, high first)
.dloop:
    cmp  r13d, 8
    jge  .ddone
    mov  ecx, 7
    sub  ecx, r13d                 ; 7 - i
    shl  ecx, 2                    ; * 4  -> shift count
    mov  eax, r12d
    shr  eax, cl                   ; nonce >> ((7-i)*4)
    and  eax, 0x0F                 ; digit 0..15
    lea  rbx, [rel beacon_font]
    shl  eax, 3                    ; digit * 8 bytes
    add  rbx, rax                  ; glyph ptr
    mov  r14d, r13d
    imul r14d, r14d, GLYPH_ADV
    add  r14d, GLYPH_TX            ; x0 = GLYPH_TX + i*GLYPH_ADV
    mov  rdi, rbx                  ; glyph ptr
    mov  esi, r14d                 ; x0
    mov  edx, GLYPH_TY             ; y0
    call beacon_draw_glyph
    inc  r13d
    jmp  .dloop
.ddone:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    ret

; ---------------------------------------------------------------------------
; beacon_draw_glyph(rdi=glyph ptr, esi=x0, edx=y0) — blit one 8x8 glyph scaled
; GLYPH_SCALE in black. Each set bit becomes a SCALE x SCALE filled block.
; ---------------------------------------------------------------------------
beacon_draw_glyph:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    mov  r12, rdi                  ; glyph ptr
    mov  r13d, esi                 ; x0
    mov  ebp, edx                  ; y0
    xor  r10d, r10d                ; gy = 0
.grow:
    cmp  r10d, 8
    jge  .gdone
    movzx ebx, byte [r12 + r10]    ; row bits (MSB = leftmost) in bl
    xor  r11d, r11d                ; gx = 0
.gcol:
    cmp  r11d, 8
    jge  .gnext
    test bl, 0x80
    jz   .gskip
    mov  edi, r11d
    imul edi, edi, GLYPH_SCALE
    add  edi, r13d                 ; px = x0 + gx*SCALE
    mov  esi, r10d
    imul esi, esi, GLYPH_SCALE
    add  esi, ebp                  ; py = y0 + gy*SCALE
    mov  edx, GLYPH_SCALE          ; w
    mov  ecx, GLYPH_SCALE          ; h
    xor  r8d, r8d                  ; color = black (0x000000)
    call beacon_fill_rect          ; preserves bl/r10/r11/r12/r13/rbp
.gskip:
    shl  bl, 1                     ; advance to next column's bit
    inc  r11d
    jmp  .gcol
.gnext:
    inc  r10d
    jmp  .grow
.gdone:
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rbp
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    ret

; ---------------------------------------------------------------------------
; beacon_hex8_serial(edi = 32-bit value) — print 8 uppercase hex digits (no 0x).
; serial_char preserves rbx/rcx/rsi; mirrors boot/serial.asm serial_hex64.
; ---------------------------------------------------------------------------
beacon_hex8_serial:
    push rax
    push rbx
    push rcx
    mov  ebx, edi                  ; value (copy before we clobber edi)
    mov  ecx, 8                    ; 8 nibbles, high-to-low
.nib:
    rol  ebx, 4
    mov  al, bl
    and  al, 0x0F
    cmp  al, 10
    jb   .dec
    add  al, 'A' - 10
    jmp  .emit
.dec:
    add  al, '0'
.emit:
    movzx edi, al
    call serial_char
    dec  ecx
    jnz  .nib
    pop  rcx
    pop  rbx
    pop  rax
    ret

; ---------------------------------------------------------------------------
; data (in-image; the image page stays RW+X post-paging per boot/paging.asm, so
; boot_nonce is writable, like core/time.asm timer_ticks). Fixed-convention
; strings carry the marker tags the regression suite + probe key off.
; ---------------------------------------------------------------------------
boot_nonce:      dd 0

str_bnonce_pre:  db "[PAOS64] P2 boot_beacon: boot nonce=", 0
str_bnonce_post: db " (TSC-seeded, per-boot) [beacon.nonce]", 13, 10, 0

str_bgop_pre:    db "[PAOS64] P2 boot_beacon: GOP marker painted @(24,24) rgb(0,180,90) nonce=", 0
str_bgop_post:   db " [beacon.gop.painted]", 13, 10, 0
str_bgop_none:   db "[PAOS64] P2 boot_beacon: GOP not available (skipped) [beacon.gop.skipped]", 13, 10, 0
str_bgop_floor_pre:  db "[PAOS64] P2 boot_beacon: GOP marker not painted (shipped floor) nonce=", 0
str_bgop_floor_post: db " [beacon.gop.floor_skipped]", 13, 10, 0
str_bgop_dismiss: db "[PAOS64] boot_beacon: GOP nonce badge dismissed off settled desktop (post boot-confirm) [beacon.gop.dismissed]", 13, 10, 0

str_wire_skip:   db "[PAOS64] P5 boot_beacon.wire: skipped (no NIC) [beacon.wire.skipped]", 13, 10, 0
; (emitted only when a frame actually goes out — svc tick calls beacon_wire_mark_sent)
str_wire_sent:   db "[PAOS64] P8 boot_beacon: wire beacon sent (gARP + UDP bcast :9998) nonce=", 0
str_wire_sent_post: db " [beacon.wire.sent]", 13, 10, 0
str_wire_magic:  db "PAOS_BOOT_BEACON ", 0

; 8x8 hex font, digits 0-9 A-F, one byte per row (MSB = leftmost pixel).
beacon_font:
    db 0x3C,0x66,0x6E,0x76,0x66,0x66,0x3C,0x00   ; 0
    db 0x18,0x38,0x18,0x18,0x18,0x18,0x7E,0x00   ; 1
    db 0x3C,0x66,0x06,0x0C,0x30,0x60,0x7E,0x00   ; 2
    db 0x3C,0x66,0x06,0x1C,0x06,0x66,0x3C,0x00   ; 3
    db 0x0C,0x1C,0x3C,0x6C,0x7E,0x0C,0x0C,0x00   ; 4
    db 0x7E,0x60,0x7C,0x06,0x06,0x66,0x3C,0x00   ; 5
    db 0x1C,0x30,0x60,0x7C,0x66,0x66,0x3C,0x00   ; 6
    db 0x7E,0x06,0x0C,0x18,0x30,0x30,0x30,0x00   ; 7
    db 0x3C,0x66,0x66,0x3C,0x66,0x66,0x3C,0x00   ; 8
    db 0x3C,0x66,0x66,0x3E,0x06,0x0C,0x38,0x00   ; 9
    db 0x18,0x3C,0x66,0x66,0x7E,0x66,0x66,0x00   ; A
    db 0x7C,0x66,0x66,0x7C,0x66,0x66,0x7C,0x00   ; B
    db 0x3C,0x66,0x60,0x60,0x60,0x66,0x3C,0x00   ; C
    db 0x78,0x6C,0x66,0x66,0x66,0x6C,0x78,0x00   ; D
    db 0x7E,0x60,0x60,0x7C,0x60,0x60,0x7E,0x00   ; E
    db 0x7E,0x60,0x60,0x7C,0x60,0x60,0x60,0x00   ; F
