;; MODULE svc/command_filmstrip
;; LAYER 5
;; EXPORTS filmstrip_init, filmstrip_declare, filmstrip_capture_first_gop, filmstrip_capture_storage, filmstrip_capture_net, filmstrip_capture_desktop, filmstrip_selftest, filmstrip_try_reply
;; IMPORTS boot/serial, boot/gop, boot/paging, boot/header, core/lib/fmt, core/lib/crc32, svc/command, svc/command_udp
;; CAPS public-read
;; OWNER saga:boot_logging_ladder
; Task2302: four fixed boot-time framebuffer checkpoints, RAM-only. Arena:
; header | slot0 frame | slot0 native crop | slot1 | slot2 | slot3.  Slot 0 is
; physically contiguous with its crop so its BLG2 body is exactly 263,168 bytes.

FS_MAGIC             equ 0x32525346       ; raw bytes "FSR2"
FS_VERSION           equ 2
FS_H_MAGIC           equ 0
FS_H_VERSION         equ 4
FS_H_SLOTS           equ 8
FS_H_BYTES           equ 12
FS_H_TOTAL           equ 16
FS_H_RECORDS         equ 64
FS_REC_SIZE          equ 32
FS_R_STAGE           equ 0                ; dd
FS_R_VALID           equ 4                ; dd, published last
FS_R_TSC             equ 8                ; dq
FS_R_W               equ 16               ; dd
FS_R_H               equ 20               ; dd
FS_R_BYTES           equ 24               ; dd, complete stream body bytes
FS_R_CROP_BYTES      equ 28               ; dd

FS_STAGE_FIRST_GOP   equ 1
FS_STAGE_STORAGE     equ 2
FS_STAGE_NET         equ 3
FS_STAGE_DESKTOP     equ 4

FS_REPLY_NONE        equ 0
FS_REPLY_INDEX       equ 1
FS_REPLY_GET         equ 2
FS_REPLY_BAD_NONCE   equ 3
FS_REPLY_BAD_SLOT    equ 4
FS_REPLY_UNAVAILABLE equ 5
FS_REPLY_BUSY        equ 6

%if FILMSTRIP_RING_SIZE != 954624
    %error "filmstrip arena geometry drift"
%endif
%if FILMSTRIP_FRAME_BYTES != 230400 || FILMSTRIP_CROP_BYTES != 32768
    %error "filmstrip wire-size geometry drift"
%endif
%if FS_H_RECORDS + FILMSTRIP_SLOTS * FS_REC_SIZE > FILMSTRIP_HEADER_SIZE
    %error "filmstrip records exceed fixed header"
%endif

; Initialize the already-reserved arena immediately after EBS. No checkpoint
; allocates, and this module has no disk or ESP path.
filmstrip_init:
    mov  rdi, [rel filmstrip_ring_base]
    test rdi, rdi
    jz   .noarena
    push rdi
    xor  eax, eax
    mov  ecx, FILMSTRIP_HEADER_SIZE / 8
    cld
    rep  stosq
    pop  rdi
    mov  dword [rdi + FS_H_MAGIC], FS_MAGIC
    mov  dword [rdi + FS_H_VERSION], FS_VERSION
    mov  dword [rdi + FS_H_SLOTS], FILMSTRIP_SLOTS
    mov  dword [rdi + FS_H_BYTES], FILMSTRIP_HEADER_SIZE
    mov  dword [rdi + FS_H_TOTAL], FILMSTRIP_RING_SIZE
    mov  dword [rel filmstrip_valid_count], 0
    mov  byte [rel filmstrip_captured_marked], 0
    mov  byte [rel filmstrip_kat_ready], 0
    mov  byte [rel filmstrip_sending], 0
    mov  byte [rel filmstrip_reply_pending], 0
    mov  byte [rel filmstrip_arena_ready], 1
    ret
.noarena:
    mov  byte [rel filmstrip_arena_ready], 0
    lea  rdi, [rel str_filmstrip_noarena]
    call serial_string
    ret

; Checkpoint 0 follows the boot orchestrator's immediately preceding call into
; Task2100's PLV1 renderer; this function owns only the frame and native crop.
filmstrip_capture_first_gop:
    xor  edi, edi
    mov  esi, FS_STAGE_FIRST_GOP
    call filmstrip_capture_slot
    ret

filmstrip_capture_storage:
    mov  edi, 1
    mov  esi, FS_STAGE_STORAGE
    call filmstrip_capture_slot
    ret

filmstrip_capture_net:
    mov  edi, 2
    mov  esi, FS_STAGE_NET
    call filmstrip_capture_slot
    ret

filmstrip_capture_desktop:
    mov  edi, 3
    mov  esi, FS_STAGE_DESKTOP
    call filmstrip_capture_slot
    cmp  dword [rel filmstrip_valid_count], FILMSTRIP_SLOTS
    jne  .done
    cmp  byte [rel filmstrip_captured_marked], 0
    jne  .done
    mov  byte [rel filmstrip_captured_marked], 1
    lea  rdi, [rel str_filmstrip_captured]
    call serial_string
.done:
    ret

; EDI=slot, ESI=stage. Each record is immutable once valid. Validity publishes
; after every sampled pixel, the native crop, and all metadata are complete.
filmstrip_capture_slot:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mfence                              ; 1249: WC framebuffer — drain combining buffers before the frame copy
    mov  r13d, edi
    mov  r15d, esi
    cmp  r13d, FILMSTRIP_SLOTS
    jae  .out
    cmp  byte [rel filmstrip_arena_ready], 1
    jne  .out
    mov  r12, [rel filmstrip_ring_base]
    test r12, r12
    jz   .out
    mov  eax, r13d
    imul eax, FS_REC_SIZE
    lea  r14, [r12 + FS_H_RECORDS]
    add  r14, rax
    cmp  dword [r14 + FS_R_VALID], 0
    jne  .out
    mov  rsi, [rel fb_base]
    test rsi, rsi
    jz   .out
    mov  edx, [rel fb_width]
    mov  ecx, [rel fb_height]
    mov  r8d, [rel fb_stride]
    test edx, edx
    jz   .out
    test ecx, ecx
    jz   .out
    cmp  r8d, edx
    jb   .out
    test r13d, r13d
    jnz  .geometry_ok
    cmp  edx, FILMSTRIP_CROP_W
    jb   .out
    cmp  ecx, FILMSTRIP_CROP_H
    jb   .out
.geometry_ok:
    ; Raw dword sampling supports the two linear GOP layouts. Bound the last
    ; visible pixel, allowing unmapped padding after the final scan line.
    cmp dword [rel fb_bpp], 32
    jne .out
    cmp dword [rel fb_pixel_format], 1
    ja .out
    test sil, 3
    jnz .out
    mov r9d, edx
    mov eax, ecx
    dec eax
    mul r8                              ; (height - 1) * stride fits in 64 bits
    add rax, r9
    jc .out
    mov r10d, 4
    mul r10
    test rdx, rdx
    jnz .out
    cmp rax, [rel fb_size]
    ja .out
    mov r10, rsi
    add r10, rax                        ; exclusive source end
    jc .out
    mov r11, 0x0000800000000000
    cmp r10, r11                        ; framebuffer is low canonical memory
    ja .out
    mov r11, r12
    add r11, FILMSTRIP_RING_SIZE
    jc .out
    cmp rsi, r11
    jae .disjoint
    cmp r12, r10
    jb .out
.disjoint:
    sfence
    mov  edi, r13d
    call filmstrip_slot_ptr
    mov  rdi, rax
    mov  rsi, [rel fb_base]
    mov  edx, [rel fb_width]
    mov  ecx, [rel fb_height]
    mov  r8d, [rel fb_stride]
    mov  r9d, FILMSTRIP_W
    mov  r10d, FILMSTRIP_H
    call filmstrip_scale_copy

    test r13d, r13d
    jnz  .metadata
    ; Native crop is SCREEN origin (0,0), never the PLV1 panel's (2,2) origin.
    mov  rsi, [rel fb_base]
    mov  rdi, [rel filmstrip_ring_base]
    add  rdi, FILMSTRIP_HEADER_SIZE + FILMSTRIP_FRAME_BYTES
    mov  ebx, FILMSTRIP_CROP_H
    mov  ebp, [rel fb_stride]
    shl  rbp, 2
.crop_row:
    mov  ecx, FILMSTRIP_CROP_W
    cld
    rep  movsd
    add  rsi, rbp
    sub  rsi, FILMSTRIP_CROP_W * 4
    dec  ebx
    jnz  .crop_row
.metadata:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [r14 + FS_R_TSC], rax
    mov  [r14 + FS_R_STAGE], r15d
    mov  dword [r14 + FS_R_W], FILMSTRIP_W
    mov  dword [r14 + FS_R_H], FILMSTRIP_H
    mov  dword [r14 + FS_R_BYTES], FILMSTRIP_FRAME_BYTES
    mov  dword [r14 + FS_R_CROP_BYTES], 0
    test r13d, r13d
    jnz  .publish
    mov  dword [r14 + FS_R_BYTES], FILMSTRIP_FRAME_BYTES + FILMSTRIP_CROP_BYTES
    mov  dword [r14 + FS_R_CROP_BYTES], FILMSTRIP_CROP_BYTES
.publish:
    sfence
    mov  dword [r14 + FS_R_VALID], 1
    inc  dword [rel filmstrip_valid_count]
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; EDI=slot -> RAX=contiguous stream body start.
filmstrip_slot_ptr:
    mov  eax, edi
    imul rax, rax, FILMSTRIP_FRAME_BYTES
    add  rax, FILMSTRIP_HEADER_SIZE
    test edi, edi
    jz   .base
    add  rax, FILMSTRIP_CROP_BYTES
.base:
    add  rax, [rel filmstrip_ring_base]
    ret

; Shared nearest-neighbor copier. RSI=src, EDX=src_w, ECX=src_h,
; R8D=src_stride_pixels, RDI=dst, R9D=dst_w, R10D=dst_h.
filmstrip_scale_copy:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rsi
    mov  r13d, edx
    mov  r14d, ecx
    mov  r15d, r8d
    mov  rbp, rdi
    mov  ebx, r9d
    mov  r11d, r10d
    xor  r10d, r10d                       ; destination y
.row:
    mov  eax, r10d
    mul  r14d
    div  r11d
    imul rax, r15
    lea  rsi, [r12 + rax*4]
    xor  ecx, ecx                         ; destination x
.pixel:
    mov  eax, ecx
    mul  r13d
    div  ebx
    mov  eax, [rsi + rax*4]
    mov  [rbp + rcx*4], eax
    inc  ecx
    cmp  ecx, ebx
    jb   .pixel
    lea  rbp, [rbp + rbx*4]
    inc  r10d
    cmp  r10d, r11d
    jb   .row
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; First prove the fixed arena offsets that make slot 0's frame+crop contiguous
; while keeping slots 1..3 frame-only. Then run a synthetic 4x2 -> 2x1 capture
; and two-piece reassembly through the same copy primitive used by live DATA
; packets. Pixel identity and shared CRC32 must agree.
filmstrip_selftest:
    push rbx
    mov  edi, 0
    call filmstrip_slot_ptr
    mov  rdx, [rel filmstrip_ring_base]
    add  rdx, FILMSTRIP_HEADER_SIZE
    cmp  rax, rdx
    jne  .fail
    mov  edi, 1
    call filmstrip_slot_ptr
    add  rdx, FILMSTRIP_FRAME_BYTES + FILMSTRIP_CROP_BYTES
    cmp  rax, rdx
    jne  .fail
    mov  edi, FILMSTRIP_SLOTS - 1
    call filmstrip_slot_ptr
    add  rax, FILMSTRIP_FRAME_BYTES
    mov  rdx, [rel filmstrip_ring_base]
    add  rdx, FILMSTRIP_RING_SIZE
    cmp  rax, rdx
    jne  .fail
    lea  rsi, [rel filmstrip_kat_src]
    mov  edx, 4
    mov  ecx, 2
    mov  r8d, 4
    lea  rdi, [rel filmstrip_kat_capture]
    mov  r9d, 2
    mov  r10d, 1
    call filmstrip_scale_copy
    cmp  dword [rel filmstrip_kat_capture], 0x00112233
    jne  .fail
    cmp  dword [rel filmstrip_kat_capture + 4], 0x00778899
    jne  .fail
    lea  rdi, [rel filmstrip_kat_start]
    lea  rsi, [rel filmstrip_kat_nonce]
    mov  edx, 8
    mov  ecx, 1
    call filmstrip_build_start
    cmp  byte [rel filmstrip_kat_start], 0x01
    jne  .fail
    cmp  dword [rel filmstrip_kat_start + 1], BOOTLOG_FULL_MAGIC
    jne  .fail
    mov  rax, 0x0706050403020100
    cmp  qword [rel filmstrip_kat_start + 5], rax
    jne  .fail
    mov  rax, 0x0F0E0D0C0B0A0908
    cmp  qword [rel filmstrip_kat_start + 13], rax
    jne  .fail
    cmp  dword [rel filmstrip_kat_start + 21], 8
    jne  .fail
    cmp  dword [rel filmstrip_kat_start + 25], 1
    jne  .fail
    lea  rsi, [rel filmstrip_kat_capture]
    lea  rdi, [rel filmstrip_kat_roundtrip]
    mov  ecx, 4
    call filmstrip_chunk_copy
    lea  rsi, [rel filmstrip_kat_capture + 4]
    lea  rdi, [rel filmstrip_kat_roundtrip + 4]
    mov  ecx, 4
    call filmstrip_chunk_copy
    mov  rax, [rel filmstrip_kat_capture]
    cmp  [rel filmstrip_kat_roundtrip], rax ; contract KAT requires byte-exact reassembly
    jne  .fail
    lea  rdi, [rel filmstrip_kat_capture]
    mov  esi, 8
    call hotpatch_crc32
    mov  ebx, eax
    lea  rdi, [rel filmstrip_kat_roundtrip]
    mov  esi, 8
    call hotpatch_crc32
    cmp  eax, ebx
    jne  .fail
    mov  byte [rel filmstrip_kat_ready], 1
    lea  rdi, [rel str_filmstrip_kat]
    call serial_string
    pop  rbx
    ret
.fail:
    mov  byte [rel filmstrip_kat_ready], 0
    lea  rdi, [rel str_filmstrip_kat_fail]
    call serial_string
    pop  rbx
    ret

filmstrip_chunk_copy:
    cld
    rep  movsb
    ret

; Shared BLG2 START builder. RDI=29-byte destination, RSI=16-byte nonce,
; EDX=total_size, ECX=item_count.
filmstrip_build_start:
    push rbx
    mov  rbx, rdi
    mov  r8d, edx
    mov  r9d, ecx
    mov  byte [rbx], 0x01
    mov  dword [rbx + 1], BOOTLOG_FULL_MAGIC
    lea  rdi, [rbx + 5]
    mov  ecx, 16
    call filmstrip_chunk_copy
    mov  [rbx + 21], r8d
    mov  [rbx + 25], r9d
    pop  rbx
    ret

; Registry metadata is the only authority: public cap=0, ARGT_TEXT,
; destructiveness=0. The handler validates and stages before UDP can emit.
filmstrip_declare:
    lea  rdi, [rel str_verb_filmstrip]
    lea  rsi, [rel cmd_verb_filmstrip]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ret

cmd_verb_filmstrip:
    call cmd_handler_prologue
    push r12
    push r13
    mov  r12, rdi                         ; request envelope
    mov  r13, rsi                         ; response envelope
    mov  byte [rel filmstrip_reply_kind], FS_REPLY_NONE
    mov  rdx, [r12 + REQ_ARG]
    test rdx, rdx
    jz   .bad_nonce
    cmp  dword [rdx], 'GET '
    jne  .index
    movzx eax, byte [rdx + 4]
    cmp  al, '0'
    jb   .bad_slot
    cmp  al, '3'
    ja   .bad_slot
    cmp  byte [rdx + 5], ' '
    jne  .bad_slot
    sub  eax, '0'
    mov  [rel filmstrip_reply_slot], al
    lea  rdi, [rdx + 6]
    lea  rsi, [rel filmstrip_reply_nonce]
    call filmstrip_decode_nonce
    test eax, eax
    jz   .bad_nonce
    cmp  byte [rel filmstrip_kat_ready], 1
    jne  .unavailable
    cmp  byte [rel filmstrip_sending], 0
    jne  .busy
    movzx eax, byte [rel filmstrip_reply_slot]
    imul eax, FS_REC_SIZE
    mov  rdx, [rel filmstrip_ring_base]
    test rdx, rdx
    jz   .unavailable
    cmp  dword [rdx + rax + FS_H_RECORDS + FS_R_VALID], 1
    jne  .unavailable
    mov  byte [rel filmstrip_reply_kind], FS_REPLY_GET
    mov  qword [r13 + RSP_CODE], CMDE_OK
    jmp  .pending
.index:
    mov  rdi, rdx
    lea  rsi, [rel filmstrip_reply_nonce]
    call filmstrip_decode_nonce
    test eax, eax
    jz   .bad_nonce
    cmp  byte [rel filmstrip_kat_ready], 1
    jne  .unavailable
    mov  byte [rel filmstrip_reply_kind], FS_REPLY_INDEX
    mov  qword [r13 + RSP_CODE], CMDE_OK
    jmp  .pending
.bad_nonce:
    mov  byte [rel filmstrip_reply_kind], FS_REPLY_BAD_NONCE
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    jmp  .pending
.bad_slot:
    mov  byte [rel filmstrip_reply_kind], FS_REPLY_BAD_SLOT
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    jmp  .pending
.unavailable:
    mov  byte [rel filmstrip_reply_kind], FS_REPLY_UNAVAILABLE
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    jmp  .pending
.busy:
    mov  byte [rel filmstrip_reply_kind], FS_REPLY_BUSY
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
.pending:
    mov  byte [rel filmstrip_reply_pending], 1
    xor  eax, eax
    mov  [r13 + RSP_VAL], rax
    pop  r13
    pop  r12
    ret

; Exact 32 hex chars -> 16 raw bytes; use rung-0's shipped nibble decoder.
filmstrip_decode_nonce:
    mov  ecx, 16
.byte:
    movzx eax, byte [rdi]
    call bootlog_full_hex_nibble
    jc   .bad
    shl  al, 4
    mov  dl, al
    movzx eax, byte [rdi + 1]
    call bootlog_full_hex_nibble
    jc   .bad
    or   al, dl
    mov  [rsi], al
    add  rdi, 2
    inc  rsi
    dec  ecx
    jnz  .byte
    cmp  byte [rdi], 0
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; Called by udp_send_reply after canonical registry dispatch. EAX=1 means this
; module sent the response; zero preserves the ordinary reply byte-for-byte.
filmstrip_try_reply:
    cmp  byte [rel filmstrip_reply_pending], 1
    jne  .not_ours
    mov  byte [rel filmstrip_reply_pending], 0
    movzx eax, byte [rel filmstrip_reply_kind]
    cmp  eax, FS_REPLY_INDEX
    je   .index
    cmp  eax, FS_REPLY_GET
    je   .get
    cmp  eax, FS_REPLY_BAD_NONCE
    je   .bad_nonce
    cmp  eax, FS_REPLY_BAD_SLOT
    je   .bad_slot
    cmp  eax, FS_REPLY_BUSY
    je   .busy
    lea  rdi, [rel str_filmstrip_unavailable]
    jmp  .ascii
.bad_nonce:
    lea  rdi, [rel str_filmstrip_bad_nonce]
    jmp  .ascii
.bad_slot:
    lea  rdi, [rel str_filmstrip_bad_slot]
    jmp  .ascii
.busy:
    lea  rdi, [rel str_filmstrip_busy]
.ascii:
    call bootlog_full_send_ascii
    mov  eax, 1
    ret
.index:
    call filmstrip_build_index
    ; The rung-0 ASCII helper is intentionally a 63-byte refusal path.  The
    ; filmstrip index is a bounded (<=767-byte) success datagram, so stage the
    ; complete body in the proven UDP TX payload and transmit its earned size.
    mov  edx, eax
    lea  rsi, [rel filmstrip_index_buf]
    lea  rdi, [rel udp_tx_frame + ETH_HLEN + 28]
    mov  ecx, eax
    cld
    rep  movsb
    mov  edi, edx
    call bootlog_full_tx
    mov  eax, 1
    ret
.get:
    mov  byte [rel filmstrip_sending], 1
    call filmstrip_send_slot
    mov  byte [rel filmstrip_sending], 0
    mov  eax, 1
    ret
.not_ours:
    xor  eax, eax
    ret

filmstrip_build_index:
    push rbx
    push r14
    lea  rax, [rel filmstrip_index_buf]
    mov  [rel filmstrip_index_cur], rax
    lea  rdi, [rel str_filmstrip_index_pre]
    call filmstrip_index_put_str
    mov  rdi, [rel boot_tsc_start]
    call filmstrip_index_put_dec
    lea  rdi, [rel str_filmstrip_geometry]
    call filmstrip_index_put_str
    xor  ebx, ebx
.slot:
    lea  rdi, [rel str_filmstrip_slot]
    call filmstrip_index_put_str
    mov  edi, ebx
    call filmstrip_index_put_dec
    lea  rdi, [rel str_filmstrip_eq]
    call filmstrip_index_put_str
    mov  edi, ebx
    call filmstrip_stage_name
    mov  rdi, rax
    call filmstrip_index_put_str
    lea  rdi, [rel str_filmstrip_slash]
    call filmstrip_index_put_str
    mov  r14, [rel filmstrip_ring_base]
    test r14, r14
    jz   .invalid_value
    mov  eax, ebx
    imul eax, FS_REC_SIZE
    add  r14, rax
    add  r14, FS_H_RECORDS
    mov  rdi, [r14 + FS_R_TSC]
    call filmstrip_index_put_dec
    cmp  dword [r14 + FS_R_VALID], 1
    jne  .invalid
    lea  rdi, [rel str_filmstrip_valid]
    jmp  .state
.invalid_value:
    xor  edi, edi
    call filmstrip_index_put_dec
.invalid:
    lea  rdi, [rel str_filmstrip_invalid]
.state:
    call filmstrip_index_put_str
    inc  ebx
    cmp  ebx, FILMSTRIP_SLOTS
    jb   .slot
    mov  rax, [rel filmstrip_index_cur]
    mov  word [rax], 0x0a0d
    mov  byte [rax + 2], 0
    lea  rcx, [rel filmstrip_index_buf]
    sub  rax, rcx
    add  eax, 2                          ; return bounded datagram bytes incl CR/LF
    pop  r14
    pop  rbx
    ret

filmstrip_stage_name:
    lea  rax, [rel str_stage_first_gop]
    test edi, edi
    jz   .done
    lea  rax, [rel str_stage_storage]
    cmp  edi, 1
    je   .done
    lea  rax, [rel str_stage_net]
    cmp  edi, 2
    je   .done
    lea  rax, [rel str_stage_desktop]
.done:
    ret

filmstrip_index_put_dec:
    lea  rsi, [rel filmstrip_dec_buf]
    call fmt_dec
    lea  rdi, [rel filmstrip_dec_buf]
    jmp  filmstrip_index_put_str

filmstrip_index_put_str:
    mov  rsi, [rel filmstrip_index_cur]
    lea  rcx, [rel filmstrip_index_buf + 765] ; reserve final CR/LF/NUL bytes
.copy:
    mov  al, [rdi]
    test al, al
    jz   .done
    cmp  rsi, rcx
    jae  .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .copy
.done:
    mov  [rel filmstrip_index_cur], rsi
    ret

; BLG2 START/DATA/COMMIT over rung-0's route snapshot and TX primitive. The
; request nonce is echoed raw in START; shared crc32 commits the whole body.
filmstrip_send_slot:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    movzx edi, byte [rel filmstrip_reply_slot]
    call filmstrip_slot_ptr
    mov  r12, rax
    mov  r13d, FILMSTRIP_FRAME_BYTES
    cmp  byte [rel filmstrip_reply_slot], 0
    jne  .size
    add  r13d, FILMSTRIP_CROP_BYTES
.size:
    mov  rdi, r12
    mov  esi, r13d
    call hotpatch_crc32
    mov  r14d, eax
    lea  rbx, [rel udp_tx_frame + ETH_HLEN + 28]
    lea  rsi, [rel filmstrip_reply_nonce]
    mov  rdi, rbx
    mov  edx, r13d
    mov  ecx, 1
    call filmstrip_build_start
    mov  edi, 29
    call bootlog_full_tx
    mov  edi, BOOTLOG_FULL_DELAY_US
    call tsc_delay_us
    xor  r15d, r15d                       ; offset
    xor  ebp, ebp                          ; sequence
.data:
    cmp  r15d, r13d
    jae  .commit
    mov  edi, r13d
    sub  edi, r15d
    call bootlog_full_chunk_len
    mov  [rel filmstrip_tx_chunk_len], eax
    lea  rbx, [rel udp_tx_frame + ETH_HLEN + 28]
    mov  byte [rbx], 0x02
    mov  [rbx + 1], ebp
    mov  [rbx + 5], r15d
    lea  rsi, [r12 + r15]
    lea  rdi, [rbx + 9]
    mov  ecx, [rel filmstrip_tx_chunk_len]
    call filmstrip_chunk_copy
    mov  edi, [rel filmstrip_tx_chunk_len]
    add  edi, 9
    call bootlog_full_tx
    add  r15d, [rel filmstrip_tx_chunk_len]
    inc  ebp
    mov  edi, BOOTLOG_FULL_DELAY_US
    call tsc_delay_us
    jmp  .data
.commit:
    lea  rbx, [rel udp_tx_frame + ETH_HLEN + 28]
    mov  byte [rbx], 0x03
    mov  [rbx + 1], r14d
    mov  edi, 5
    call bootlog_full_tx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

filmstrip_arena_ready:      db 0
filmstrip_valid_count:      dd 0
filmstrip_captured_marked:  db 0
filmstrip_kat_ready:        db 0
filmstrip_sending:          db 0
filmstrip_reply_pending:    db 0
filmstrip_reply_kind:       db 0
filmstrip_reply_slot:       db 0
filmstrip_tx_chunk_len:     dd 0
filmstrip_reply_nonce:      times 16 db 0
filmstrip_index_cur:        dq 0
filmstrip_index_buf:        times 768 db 0
filmstrip_dec_buf:          times 24 db 0
filmstrip_kat_src:          dd 0x00112233,0x00445566,0x00778899,0x00AABBCC
                            dd 0x00DDEEFF,0x00010203,0x00040506,0x00070809
filmstrip_kat_capture:      times 8 db 0
filmstrip_kat_roundtrip:    times 8 db 0
filmstrip_kat_nonce:        db 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
filmstrip_kat_start:        times 29 db 0

str_verb_filmstrip:         db "FILMSTRIP",0
str_filmstrip_index_pre:    db "FILMSTRIP SLOTS=4 BOOT_SESSION=",0
str_filmstrip_geometry:     db " W=320 H=180 CROP0=32768",0
str_filmstrip_slot:         db " slot",0
str_filmstrip_eq:           db "=",0
str_filmstrip_slash:        db "/",0
str_filmstrip_valid:        db "/valid",0
str_filmstrip_invalid:      db "/invalid",0
str_stage_first_gop:        db "first_gop",0
str_stage_storage:          db "storage_ready",0
str_stage_net:              db "net_ready",0
str_stage_desktop:          db "desktop_first_paint",0
str_filmstrip_bad_nonce:    db "FILMSTRIP ERR bad_nonce",13,10,0
str_filmstrip_bad_slot:     db "FILMSTRIP ERR bad_slot",13,10,0
str_filmstrip_unavailable:  db "FILMSTRIP ERR unavailable",13,10,0
str_filmstrip_busy:         db "FILMSTRIP ERR busy",13,10,0
str_filmstrip_noarena:      db "[PAOS64] P2 boot filmstrip unavailable (fixed arena reservation failed; slots invalid)",13,10,0
str_filmstrip_captured:     db "[PAOS64] P7 gui: boot filmstrip captured [boot.filmstrip.captured]",13,10,0
str_filmstrip_kat:          db "[PAOS64] P6 svc: filmstrip capture-serve KAT PASS [boot.filmstrip.kat]",13,10,0
str_filmstrip_kat_fail:     db "[PAOS64] P6 svc: filmstrip capture-serve KAT FAIL",13,10,0
