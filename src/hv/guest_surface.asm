;; MODULE hv/guest_surface
%include "core/abi/build_profile.inc"
;; LAYER 5
;; EXPORTS guest_surface_init, guest_surface_prepare, guest_surface_foreign_start, guest_surface_receive, guest_surface_revoke_ept, guest_surface_bind, guest_surface_copy, gws_bound, gws_fixture_mode, gws_out_ready, gws_out_buf
;; IMPORTS hv/vmx, hv/hv_ops, hv/vtd, hv/browser_appliance, svc/command, svc/command_auth, core/lib/crc32, core/lib/fmt, boot/serial, core/heap, core/lib/mem, hv/vcpu_ap_run, hv/vcpu_bsp
;; CAPS extension
;; OWNER saga:web_browser
%include "hv/guest_media_contract.inc"
; Contract 2716. GWS1 binary records use the EXISTING virtio-console TX split
; queue. Host-owned grant, no raw host pointers. Validate -> copy damage into
; unpublished storage -> verify guest tile CRCs -> exchange completed view.
; No window/Chromium/Linux-boot claim and no native cadence instrumentation.
;
; v1 bounds: one BGRX surface <=128x128, <=64KiB including row padding,
; four rectangles and sixteen 32x32 tiles. Snapshots + KAT fit in 256KiB.
; Fixed 256-byte little-endian record:
;   0 magic, 4 size; 8 generation; 16 begin_seq; 24 completed flip_seq;
;   32 guest TSC; 40 grant GPA; 48 capacity; 52 W; 56 H; 60 byte stride;
;   64 format=1; 68 rect count; 72 tile mask; 76 reserved=0;
;   80 four {x,y,w,h} u32 rectangles; 144 sixteen IEEE CRC32s;
;   208 nonce[24]; 232 reserved[24]=0.
; Producer: pixels -> CRC/rects -> SFENCE -> flip_seq -> SFENCE -> avail.idx.
; Consumer: acquire avail -> snapshot -> bounds/CRC -> release view -> used.
; CRC entries outside tile_mask retain the last accepted generation's values
; (zero for unused tiles/new generations); they cannot be silently replaced.
; One vCPU, stopped at notify exit; no yield while consuming/publishing.
; Diagnostic operations use the shipped EPT/VMCS runner, boot parameters for
; inputs, TX ring for output, and terminate at a real guest HLT. Each invocation
; revokes its EPT before returning. No fixture pointer escapes into the GUI.

GWS_SIZE       equ 256
GWS_MAX        equ 65536
GWS_DIM        equ 128
GWS_RUN_MS     equ 5000
GWS_PIX_GPA    equ 0x200000
GWS_DESC_GPA   equ 0x10000
GWS_RING_GPA   equ 0x11000
GWS_AVAIL_GPA  equ 0x12000
GWS_USED_GPA   equ 0x13000
GWS_CONFIG_GPA equ 0x14000
GWS_CRC_GPA    equ 0x15000
GWS_PACK_GPA   equ 0x16000
GWS_TILE_GPA   equ 0x17000
GWS_ENTRY_GPA  equ HV_LINUX_KERN_GPA + 0x200
; The two private snapshots (A/B) and the KAT source are ONE zeroed kernel-heap
; slab (gws_slab, allocated by guest_surface_init after PH_HEAP_INIT) instead of
; 3 x 64 KiB of zero bytes in the image (Dell ESP payload budget). Each buffer is
; bracketed by an overrun guard qword inside the slab, as the image layout was.
GWS_SLAB_GUARD equ 16
GWS_SLAB_A     equ GWS_SLAB_GUARD
GWS_SLAB_B     equ GWS_SLAB_A + GWS_MAX + GWS_SLAB_GUARD
GWS_SLAB_KAT   equ GWS_SLAB_B + GWS_MAX + GWS_SLAB_GUARD
GWS_SLAB_BYTES equ GWS_SLAB_KAT + GWS_MAX + GWS_SLAB_GUARD
GWS_GUARD_MAGIC equ 0x2716DEADBEEF2716
%include "core/abi/heap_once.inc"

guest_surface_init:
    push rbx
    call gws_kat
    lea rdi, [rel gws_verb]
    lea rsi, [rel cmd_verb_gwsurface]
    mov rdx, CMD_AUTH_CAP_EXTENSION
    mov ecx, ARGT_TEXT
    xor r8d, r8d
    mov r9d, 1
    call command_register_verb
    test eax, eax
    jns .registered
    lea rdi, [rel gws_registry_fail]
    call serial_string
.registered:
    pop rbx
    ret

; Host-side compositor seam. RDI=owned pixel destination, ESI=capacity >=64KiB,
; RDX=owned 256-byte descriptor destination. EAX=0 stable snapshot / 1 refuse.
; No borrowed mutable pointer escapes: a concurrent publish changes the epoch
; and forces a retry. Callers MUST discard their destinations on refusal.
guest_surface_copy:
    push rbx
    push r12
    push r13
    push r14
    mov r12, rdi
    mov r13, rdx
    mov ebx, 4
    test rdi, rdi
    jz .bad
    test rdx, rdx
    jz .bad
    cmp esi, GWS_MAX
    jb .bad
.retry:
    mov r14, [rel gws_publication]
    test r14b, 1
    jnz .again
    lfence
    cmp byte [rel gws_active], 1
    jne .bad
    mov rsi, [rel gws_front]
    mov rdi, r12
    mov ecx, GWS_MAX / 8
    rep movsq
    lea rsi, [rel gws_present]
    mov rdi, r13
    mov ecx, GWS_SIZE / 8
    rep movsq
    lfence
    cmp r14, [rel gws_publication]
    jne .again
    xor eax, eax
    jmp .out
.again:
    dec ebx
    jnz .retry
.bad:
    mov eax, 1
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Host-only negotiation for ANY producer on the existing console split queue.
; Invoke at a stopped-vCPU boundary, before granting the producer this channel.
; EDI=W, ESI=H, EDX=stride; EAX=0/1, R8=new generation, R9=GPA, R10=capacity.
; The fixed GPA is owned by this guest's
; reserved RAM, checked through the shipped GPA helper. No device is added.
guest_surface_bind:
    push rbx
    push r12
    push r13
    push r14
    cmp byte [rel hvw_bound], 0
    jne .bad
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp byte [rel hv_vcon_pmr_bound], 1
    je .bad
%endif
%endif
    mov r12d, edi
    mov r13d, esi
    mov r14d, edx
    test edi, edi
    jz .bad
    cmp edi, GWS_DIM
    ja .bad
    test esi, esi
    jz .bad
    cmp esi, GWS_DIM
    ja .bad
    test edx, 3
    jnz .bad
    shl edi, 2
    cmp edx, edi
    jb .bad
    mov eax, edx
    imul rax, r13
    jo .bad
    cmp rax, GWS_MAX
    ja .bad
    cmp qword [rel hv_linux_ram], 0
    je .bad
    mov edi, GWS_PIX_GPA
    mov esi, GWS_MAX
    call hv_linux_gpa2hva
    test rax, rax
    jz .bad
    mov rbx, rax
    call gws_request_base
    mov [rel gws_request + 52], r12d
    mov [rel gws_request + 56], r13d
    mov [rel gws_request + 60], r14d
    inc qword [rel gws_generation]
    mov rax, [rel gws_generation]
    mov [rel gws_request + 8], rax
    mov [rel gws_source], rbx
    sfence
    mov byte [rel gws_bound], 1
    mov byte [rel gws_mapped], 1
    mov r8, [rel gws_generation]
    mov r9d, GWS_PIX_GPA
    mov r10d, GWS_MAX
    xor eax, eax
    jmp .out
.bad:
    mov eax, 1
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Called from hv_linux_prepare: R14=RAM, R15=control. Grant fixed by host.
guest_surface_prepare:
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp byte [rel hv_vcon_pmr_bound], 1
    je .bad                               ; before any RAM/control overwrite
%endif
%endif
    ; Runtime HPA alignment, never a file-offset ALIGN assumption.
    test r14, 0x1FFFFF
    jnz .bad
    test r15, 0x1FFFFF
    jnz .bad
    cmp byte [rel gws_active], 1
    je .control
    ; A fresh fixture cannot inherit data from an earlier appliance. Only
    ; later operations on this same surface retain their own pixel grant.
    mov rdi, r14
    xor eax, eax
    mov rcx, [rel hv_linux_ram_bytes]
    shr rcx, 3
    rep stosq
.control:
    mov rdi, r14
    xor eax, eax
    mov ecx, 0x18000 / 8
    rep stosq
    lea rsi, [rel gws_guest_begin]
    lea rdi, [r14 + GWS_ENTRY_GPA]
    mov ecx, gws_guest_end - gws_guest_begin
    rep movsb
    ; Port the actual shipped CRC bytes, including their RIP-relative table.
    lea rsi, [rel hotpatch_crc32]
    lea rdi, [r14 + GWS_CRC_GPA]
    mov ecx, crc32_table + 1024 - hotpatch_crc32
    rep movsb
    lea rsi, [rel gws_tile_pack]
    lea rdi, [r14 + GWS_PACK_GPA]
    mov ecx, gws_tile_pack_end - gws_tile_pack
    rep movsb
    lea rsi, [rel gws_request]
    lea rdi, [r14 + GWS_CONFIG_GPA]
    mov ecx, GWS_SIZE / 8
    rep movsq
    mov eax, [rel gws_seed]
    mov [r14 + GWS_CONFIG_GPA + GWS_SIZE], eax
    mov eax, [rel gws_hostile]
    mov [r14 + GWS_CONFIG_GPA + GWS_SIZE + 4], eax
    ; PDPT[0] is normal guest RAM. PDPT[3] maps the console virtual window;
    ; the established EPT MMIO subtree still traps all console writes.
    mov qword [r14 + 0x2000 + 3*8], 0x4003
    mov eax, HV_VCON_GPA | 0x83
    mov [r14 + 0x4000 + 128*8], rax
    mov edi, GWS_PIX_GPA
    mov esi, GWS_MAX
    call hv_linux_gpa2hva
    test rax, rax
    jz .bad
    mov [rel gws_source], rax
    mov byte [rel gws_bound], 1
    mov byte [rel gws_mapped], 1
    xor eax, eax
    ret
.bad:
    mov byte [rel hv_linux_load_err], 2
    mov eax, -1
    ret

; Any ordinary appliance restart takes ownership of the reusable guest RAM.
; Drop the old surface view before that runner can overwrite its pixel grant.
guest_surface_foreign_start:
    cmp byte [rel gws_fixture_mode], 1
    je .out
    mov al, [rel gws_active]
    or al, [rel gws_bound]
    test al, al
    je .out
    call gws_clear
    call gws_request_base
.out:
    ret

; Revoke while in VMX root. VMXOFF alone doesn't invalidate reused EPTPs.
guest_surface_revoke_ept:
    ; S7: table lifetime is frozen until both vCPUs are retired.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    cmp byte [rel gws_bound], 1
    jne .out
    mov rax, [rel hv_linux_region]
    mov qword [rax + 0x2000], 0
    sfence
    call hv_slat_flush
    cmp eax, 1
    jne .failed
    mov byte [rel gws_mapped], 0
    mov byte [rel gws_bound], 0
    mov qword [rel gws_source], 0
    inc qword [rel gws_revocations]
    ret
.failed:
    mov dword [rel gws_error], 12
    mov byte [rel gws_poisoned], 1
.out:
    ret

; ECX=bytes assembled by the existing split-ring walker. Preserve its state.
guest_surface_receive:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    inc qword [rel gws_ring_seen]
    cmp ecx, GWS_SIZE
    jne .size
    lfence
    lea rsi, [rel hv_vcon_txbuf]
    lea rdi, [rel gws_candidate]
    mov ecx, GWS_SIZE / 8
    rep movsq
    call gws_accept
    jmp .out
.size:
    mov dword [rel gws_error], 1
    inc qword [rel gws_refused]
.out:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    ret

; Snapshot validation. EAX=0 or stable refusal class. All memory products and
; sums are widened and checked before use. Geometry cannot choose the grant.
gws_validate:
    lea rdx, [rel gws_candidate]
    mov eax, 1
    cmp dword [rdx], 'GWS1'
    jne .out
    cmp dword [rdx + 4], GWS_SIZE
    jne .out
    cmp dword [rdx + 76], 0
    jne .out
    mov rcx, [rdx + 232]
    or rcx, [rdx + 240]
    or rcx, [rdx + 248]
    jnz .out
    mov eax, 2
    mov rcx, [rdx + 8]
    cmp rcx, [rel gws_generation]
    jne .out
    mov eax, 3
    mov rcx, [rdx + 24]
    test rcx, rcx
    jz .out
    cmp rcx, [rdx + 16]
    jne .out
    cmp rcx, [rel gws_present + 24]
    jbe .out
    mov rcx, [rdx + 32]
    cmp rcx, [rel gws_present + 32]
    jbe .out
    mov eax, 4
    cmp dword [rdx + 64], 1
    jne .out
    mov ecx, [rdx + 52]
    test ecx, ecx
    jz .out
    cmp ecx, GWS_DIM
    ja .out
    cmp ecx, [rel gws_request + 52]
    jne .out
    mov r8d, [rdx + 56]
    test r8d, r8d
    jz .out
    cmp r8d, GWS_DIM
    ja .out
    cmp r8d, [rel gws_request + 56]
    jne .out
    shl rcx, 2
    mov r9d, [rdx + 60]
    test r9d, 3
    jnz .out
    cmp r9, rcx
    jb .out
    cmp r9d, [rel gws_request + 60]
    jne .out
    imul r9, r8
    jo .out
    cmp r9, GWS_MAX
    ja .out
    cmp dword [rdx + 48], GWS_MAX
    jne .out
    cmp qword [rdx + 40], GWS_PIX_GPA
    jne .out
    mov ecx, [rdx + 68]
    test ecx, ecx
    jz .out
    cmp ecx, 4
    ja .out
    mov eax, 5
    lea rsi, [rdx + 80]
    xor r11d, r11d
.rect:
    mov r8d, [rsi]
    mov r9d, [rsi + 4]
    mov edi, [rsi + 8]
    test edi, edi
    jz .out
    add rdi, r8
    jc .out
    mov r10d, [rdx + 52]
    cmp rdi, r10
    ja .out
    mov r10d, [rsi + 12]
    test r10d, r10d
    jz .out
    add r10, r9
    jc .out
    push rcx
    mov ecx, [rdx + 56]
    cmp r10, rcx
    pop rcx
    ja .out
    dec edi
    shr edi, 5
    dec r10d
    shr r10d, 5
    shr r8d, 5
    shr r9d, 5
    push rcx
.ty:
    mov ecx, r8d
.tx:
    push rcx
    lea ecx, [rcx + r9*4]
    bts r11d, ecx
    pop rcx
    inc ecx
    cmp ecx, edi
    jbe .tx
    inc r9d
    cmp r9d, r10d
    jbe .ty
    pop rcx
    add rsi, 16
    dec ecx
    jnz .rect
    mov eax, 6
    cmp r11d, [rdx + 72]
    jne .out
    ; First frame after renegotiation must initialize every pixel.
    mov rcx, [rdx + 8]
    cmp rcx, [rel gws_present + 8]
    je .nonce
    cmp dword [rdx + 68], 1
    jne .out
    cmp qword [rdx + 80], 0
    jne .out
    mov ecx, [rdx + 52]
    cmp ecx, [rdx + 88]
    jne .out
    mov ecx, [rdx + 56]
    cmp ecx, [rdx + 92]
    jne .out
.nonce:
    mov eax, 7
    mov rcx, [rdx + 208]
    cmp rcx, [rel gws_request + 208]
    jne .out
    mov rcx, [rdx + 216]
    cmp rcx, [rel gws_request + 216]
    jne .out
    mov rcx, [rdx + 224]
    cmp rcx, [rel gws_request + 224]
    jne .out
    xor eax, eax
.out:
    ret

; Pure row packer, copied verbatim into guest. RSI=source, EDI=W, EDX=H,
; ECX=stride, R8D=tile index (4 columns), R9=scratch(4096); EAX=length.
; Uses window.asm::fb_present_rect's bounded span/row discipline without fb
; global redirection. Caller has validated the geometry and selected tile.
gws_tile_pack:
    push rbx
    push r12
    push r13
    mov ebx, ecx
    mov eax, r8d
    and eax, 3
    shl eax, 5
    sub edi, eax
    cmp edi, 32
    jbe .width
    mov edi, 32
.width:
    mov r12d, edi
    shl r12d, 2
    lea rsi, [rsi + rax*4]
    shr r8d, 2
    shl r8d, 5
    sub edx, r8d
    cmp edx, 32
    jbe .height
    mov edx, 32
.height:
    imul r8d, ebx
    add rsi, r8
    mov r13d, edx
    mov rdi, r9
    mov eax, r12d
    imul eax, edx
.row:
    mov ecx, r12d
    rep movsb
    add rsi, rbx
    sub rsi, r12
    dec r13d
    jnz .row
    pop r13
    pop r12
    pop rbx
    ret
gws_tile_pack_end:


; ---------------------------------------------------------------------------
; Embedded producer. All addresses below are guest GPAs. It cannot call host
; code: the two shared helpers are byte copies at private executable guest GPAs.
; Pixel oracle: 0xFF000000 | ((crc32(nonce) ^ x*0x10203 ^ y*0x30405 ^
;                            begin_seq*0x010101) & 0xFFFFFF).
; Only the requested rectangle changes; guest storage survives invocations.
; ---------------------------------------------------------------------------
gws_guest_begin:
    cld
    mov esi, GWS_CONFIG_GPA
    mov edi, GWS_DESC_GPA
    mov ecx, GWS_SIZE / 8
    rep movsq
    mov ebp, GWS_DESC_GPA
    mov qword [rbp + 24], 0
    cmp dword [GWS_CONFIG_GPA + GWS_SIZE + 4], 0
    jne .crc
    mov r12d, [rbp + 80]
    mov r13d, [rbp + 84]
    mov r14d, [rbp + 88]
    add r14d, r12d
    mov r15d, [rbp + 92]
    add r15d, r13d
.row:
    mov ecx, r12d
.pixel:
    mov eax, ecx
    imul eax, 0x10203
    mov edx, r13d
    imul edx, 0x30405
    xor eax, edx
    xor eax, [GWS_CONFIG_GPA + GWS_SIZE]
    mov edx, [rbp + 16]
    imul edx, 0x010101
    xor eax, edx
    and eax, 0xFFFFFF
    or eax, 0xFF000000
    mov edi, r13d
    imul edi, [rbp + 60]
    lea edi, [rdi + rcx*4 + GWS_PIX_GPA]
    mov [rdi], eax
    inc ecx
    cmp ecx, r14d
    jb .pixel
    inc r13d
    cmp r13d, r15d
    jb .row
.crc:
    ; Calculate every selected tile through the canonical CRC implementation.
    xor r12d, r12d
.tile:
    bt dword [rbp + 72], r12d
    jnc .next_tile
    mov esi, GWS_PIX_GPA
    mov edi, [rbp + 52]
    mov edx, [rbp + 56]
    mov ecx, [rbp + 60]
    mov r8d, r12d
    mov r9d, GWS_TILE_GPA
    mov eax, GWS_PACK_GPA
    call rax
    mov esi, eax
    mov edi, GWS_TILE_GPA
    mov eax, GWS_CRC_GPA
    call rax
    mov [rbp + 144 + r12*4], eax
.next_tile:
    inc r12d
    cmp r12d, 16
    jb .tile
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rbp + 32], rax
    ; Hostile mutations occur AFTER safe rendering/CRC. Thus an invalid stride
    ; is exercised by the host validator, never used to scribble in the guest.
    mov eax, [GWS_CONFIG_GPA + GWS_SIZE + 4]
    cmp eax, 1
    jne .not_stale
    dec qword [rbp + 8]
.not_stale:
    cmp eax, 2
    jne .not_rect
    mov dword [rbp + 80], 0xFFFFFFFF
    mov dword [rbp + 88], 8
.not_rect:
    cmp eax, 4
    jne .not_stride
    mov dword [rbp + 60], 0xFFFFFFFC
.not_stride:
    cmp eax, 5
    jne .not_crc
    ; First selected tile, not an unused table entry.
    mov edx, [rbp + 72]
    bsf edx, edx
    xor dword [rbp + 144 + rdx*4], 1
.not_crc:
    cmp eax, 6
    jne .not_gpa
    mov qword [rbp + 40], -32
.not_gpa:
    cmp eax, 7
    jne .not_order
    dec qword [rbp + 16]
.not_order:
    cmp eax, 8
    jne .not_unchanged_crc
    xor dword [rbp + 144 + 4], 1     ; tile 1 is outside the 1x1 damage rect
.not_unchanged_crc:
    sfence
    cmp eax, 3
    je .partial
    mov rdx, [rbp + 16]
    mov [rbp + 24], rdx             ; last descriptor field: commit
.partial:
    ; Standard split virtqueue: one device-readable, unchained descriptor.
    mov qword [GWS_RING_GPA], GWS_DESC_GPA
    mov dword [GWS_RING_GPA + 8], GWS_SIZE
    mov dword [GWS_RING_GPA + 12], 0
    mov word [GWS_AVAIL_GPA + 4], 0
    sfence
    mov word [GWS_AVAIL_GPA + 2], 1
    mov ebx, HV_VCON_GPA
    cmp dword [rbx], 0x74726976
    jne .failed
    cmp dword [rbx + 4], 2
    jne .failed
    cmp dword [rbx + 8], 3
    jne .failed
    ; Virtio 1.0 acknowledge/driver/version/features sequence, as used by the
    ; shipped appliance. All stores use the existing MOV r/m32,r32 decoder.
    mov eax, 1
    mov [rbx + 0x070], eax
    mov eax, 3
    mov [rbx + 0x070], eax
    mov eax, 1
    mov [rbx + 0x024], eax
    mov [rbx + 0x020], eax           ; VIRTIO_F_VERSION_1
    mov eax, 11
    mov [rbx + 0x070], eax
    mov eax, 1
    mov [rbx + 0x030], eax           ; select TX queue
    mov eax, 8
    mov [rbx + 0x038], eax           ; power-of-two queue length
    mov eax, GWS_RING_GPA
    mov [rbx + 0x080], eax
    mov eax, GWS_AVAIL_GPA
    mov [rbx + 0x090], eax
    mov eax, GWS_USED_GPA
    mov [rbx + 0x0A0], eax
    mov eax, 1
    mov [rbx + 0x044], eax           ; QueueReady
    mov eax, 15
    mov [rbx + 0x070], eax           ; DRIVER_OK
    sfence
    mov eax, 1
    mov [rbx + 0x050], eax           ; QueueNotify -> existing serve_tx
    lfence
    cmp word [GWS_USED_GPA + 2], 1
    jne .failed
    mov dword [GWS_CONFIG_GPA + GWS_SIZE + 8], 'USED'
    sfence
    hlt
.failed:
    ud2
    ; Negative TIMES refuses a future producer that exceeds its private page.
    times 4096 - ($ - gws_guest_begin) db 0
gws_guest_end:

; Host request setup. Bounds here protect the deterministic producer itself;
; gws_validate independently treats every returned field as hostile.
gws_request_base:
    lea rdi, [rel gws_request]
    xor eax, eax
    mov ecx, GWS_SIZE / 8
    rep stosq
    mov dword [rel gws_request], 'GWS1'
    mov dword [rel gws_request + 4], GWS_SIZE
    mov qword [rel gws_request + 40], GWS_PIX_GPA
    mov dword [rel gws_request + 48], GWS_MAX
    mov dword [rel gws_request + 64], 1
    mov dword [rel gws_request + 68], 1
    ret

; Compute mask for the already bounded single request rectangle.
gws_request_mask:
    mov eax, [rel gws_request + 80]
    mov edx, [rel gws_request + 84]
    mov r8d, [rel gws_request + 88]
    mov r9d, [rel gws_request + 92]
    add r8d, eax
    dec r8d
    add r9d, edx
    dec r9d
    shr eax, 5
    shr edx, 5
    shr r8d, 5
    shr r9d, 5
    xor r10d, r10d
.y:
    mov r11d, eax
.x:
    lea ecx, [r11 + rdx*4]
    bts r10d, ecx
    inc r11d
    cmp r11d, r8d
    jbe .x
    inc edx
    cmp edx, r9d
    jbe .y
    mov [rel gws_request + 72], r10d
    ret

; Release the private snapshots; slab addresses stay reserved but all bytes,
; view authority, source pointer and generation are invalidated.
gws_clear:
    inc qword [rel gws_publication]
    sfence
    mov byte [rel gws_active], 0
    mov byte [rel gws_bound], 0
    sfence
    call gws_slab
    test rax, rax
    jz .no_slab
    lea rdi, [rax + GWS_SLAB_A]
    mov [rel gws_front], rdi
    lea rdi, [rax + GWS_SLAB_B]
    mov [rel gws_back], rdi
    lea rdi, [rax + GWS_SLAB_A]
    xor eax, eax
    mov ecx, GWS_MAX / 8
    rep stosq                            ; A
    add rdi, GWS_SLAB_GUARD              ; step over the B guard
    mov ecx, GWS_MAX / 8
    rep stosq                            ; B
    add rdi, GWS_SLAB_GUARD              ; step over the KAT guard
    mov ecx, GWS_MAX / 8
    rep stosq                            ; KAT source
    jmp .slab_clear
.no_slab:
    ; Heap refused: no snapshot storage. gws_accept refuses (error 8) on a NULL
    ; back buffer and guest_surface_copy needs gws_active, so nothing derefs 0.
    mov qword [rel gws_front], 0
    mov qword [rel gws_back], 0
.slab_clear:
    xor eax, eax
    lea rdi, [rel gws_present]
    mov ecx, GWS_SIZE / 8
    rep stosq
    lea rdi, [rel gws_tile_scratch]
    mov ecx, 4096 / 8
    rep stosq
    mov qword [rel gws_source], 0
    inc qword [rel gws_generation]
    sfence
    inc qword [rel gws_publication]
    ret

; Every invocation is isolated from other users of the one VMX task.
gws_run:
    push rbx
    cmp byte [rel hvw_bound], 0
    jne .out
    mov dword [rel gws_error], 10
    cmp byte [rel hv_linux_running], 0
    jne .out
    cmp byte [rel hv_linux_start_active], 0
    jne .out
    cmp byte [rel hv_linux_run_req], 0
    jne .out
    cmp byte [rel gws_poisoned], 0
    jne .out
    cmp byte [rel gws_mapped], 0
    jne .out
    cmp byte [rel vtd_owner_guest], 0
    jne .out
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp byte [rel hv_vcon_pmr_bound], 0
    jne .out                              ; RCQ-37: the media owner holds the vCPU seam
%endif
%endif
%if !PAOS_PUBLIC_BUILD
    call browser_appliance_deselect
%endif
    call hv_linux_select_default_artifacts
    mov rax, [rel gws_generation]
    mov [rel gws_request + 8], rax
    ; Carry the accepted CRC table, not the original request's zero entries.
    ; Resizing starts a fresh table; its required full frame populates it.
    lea rdi, [rel gws_request + 144]
    cmp rax, [rel gws_present + 8]
    jne .new_crc_table
    lea rsi, [rel gws_present + 144]
    mov ecx, 64 / 8
    rep movsq
    jmp .crc_table_ready
.new_crc_table:
    xor eax, eax
    mov ecx, 64 / 8
    rep stosq
.crc_table_ready:
    mov rax, [rel gws_present + 24]
    inc rax
    jz .out
    mov [rel gws_request + 16], rax
    mov [rel gws_request + 24], rax
    mov qword [rel gws_ring_seen], 0
    mov qword [rel gws_used_ack], 0
    mov byte [rel gws_fixture_mode], 1
    mov byte [rel hv_linux_release_deferred], 1 ; RC-speed-reserve: the span outlives the stop until .out
    mov byte [rel hv_launch_mode], 1
    call hv_ops_launch_active
    mov byte [rel hv_launch_mode], 0
    mov byte [rel gws_fixture_mode], 0
    cmp byte [rel hv_launch_vmxonfail], 1
    jne .check_ack
    cmp byte [rel hv_linux_vmx_live], 0
    jne .check_ack
    ; VMXON refused: this prepared EPT was never installed on the CPU. The
    ; previous successful fixture already invalidated its own EPT context.
    ; Cancel this preparation without claiming an INVEPT completion.
    cmp byte [rel gws_bound], 1
    jne .check_ack
    mov rax, [rel hv_linux_region]
    mov qword [rax + 0x2000], 0
    sfence
    mov byte [rel gws_bound], 0
    mov byte [rel gws_mapped], 0
    mov qword [rel gws_source], 0
.check_ack:
    ; Used-ring observation was written by guest AFTER the host released it.
    mov rax, [rel hv_linux_ram]
    test rax, rax
    jz .out
    cmp dword [rax + GWS_CONFIG_GPA + GWS_SIZE + 8], 'USED'
    jne .failed
    cmp dword [rel hv_exit_reason], 12
    jne .failed
    cmp byte [rel hv_linux_load_err], 0
    jne .failed
    cmp qword [rel gws_ring_seen], 1
    jne .failed
    mov qword [rel gws_used_ack], 1
    jmp .out
.failed:
    mov dword [rel gws_error], 11
.out:
    call hv_linux_release_after_fixture   ; after the ack read: a pinned live surface keeps the span
    pop rbx
    ret

; Fixed tokenization: <=160 input bytes, <=8 tokens, no implicit prefixes.
; RDI=source; returns EAX=token count (0 malformed), token addresses are RVAs
; only during assembly: populate every address from relocated storage here.
gws_tokens:
    lea rsi, [rel gws_args]
    xor ecx, ecx
.copy:
    mov al, [rdi + rcx]
    mov [rsi + rcx], al
    test al, al
    jz .split
    inc ecx
    cmp ecx, 159
    jb .copy
    xor eax, eax
    ret
.split:
    xor eax, eax
    lea rdx, [rel gws_tok]
.skip:
    cmp byte [rsi], 0
    je .out
    cmp byte [rsi], ' '
    jne .token
    inc rsi
    jmp .skip
.token:
    cmp eax, 8
    jae .bad
    mov [rdx + rax*8], rsi
    inc eax
.scan:
    cmp byte [rsi], 0
    je .out
    cmp byte [rsi], ' '
    je .end
    inc rsi
    jmp .scan
.end:
    mov byte [rsi], 0
    inc rsi
    jmp .skip
.bad:
    xor eax, eax
.out:
    ret

; RDI=decimal token -> EAX=u32, CF=bad. Refuse overflow and trailing bytes.
gws_number:
    xor eax, eax
    cmp byte [rdi], 0
    je .bad
.loop:
    movzx ecx, byte [rdi]
    test ecx, ecx
    jz .ok
    sub ecx, '0'
    cmp ecx, 9
    ja .bad
    cmp eax, 429496729
    ja .bad
    jne .digit
    cmp ecx, 5
    ja .bad
.digit:
    imul eax, 10
    add eax, ecx
    inc rdi
    jmp .loop
.ok:
    clc
    ret
.bad:
    stc
    ret

; RDI=nonce token. Exactly 24 lower-case hex chars. EAX=0/1.
gws_nonce_check:
    xor ecx, ecx
.loop:
    mov al, [rdi + rcx]
    cmp al, '0'
    jb .bad
    cmp al, '9'
    jbe .next
    cmp al, 'a'
    jb .bad
    cmp al, 'f'
    ja .bad
.next:
    inc ecx
    cmp ecx, 24
    jb .loop
    cmp byte [rdi + 24], 0
    jne .bad
    xor eax, eax
    ret
.bad:
    mov eax, 1
    ret


; The registry is authoritative; all GWSURFACE diagnostics carry EXTENSION
; authority (including retained pixels/nonce). No public-floor exception.
cmd_verb_gwsurface:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call cmd_handler_prologue
    mov r12, rsi
    mov rdi, [rdi + REQ_ARG]
    mov al, 1
    xchg al, [rel gws_busy]
    test al, al
    jnz .busy
    test rdi, rdi
    jz .syntax
    call gws_tokens
    mov r13d, eax
    test eax, eax
    jz .syntax
%macro GWS_MATCH 2
    mov rdi, [rel gws_tok]
    lea rsi, [rel %1]
    call hv_tok_is
    test al, al
    jnz %2
%endmacro
    GWS_MATCH gws_stat, .stat
    GWS_MATCH gws_stop, .stop
    GWS_MATCH gws_selftest, .selftest
    GWS_MATCH gws_delta, .delta
    GWS_MATCH gws_resize, .resize
    GWS_MATCH gws_hostile_word, .hostile
    jmp .syntax
.stat:
    cmp r13d, 1
    jne .syntax
    jmp .render
.stop:
    cmp r13d, 1
    jne .syntax
    cmp byte [rel gws_mapped], 0
    jne .unavailable
    ; EPT was invalidated before every prior invocation returned. Scrub only
    ; our fixed former grant; never a running different guest's RAM.
    cmp byte [rel hv_linux_running], 0
    jne .unavailable
    cmp byte [rel hv_linux_start_active], 0
    jne .unavailable
    cmp byte [rel hv_linux_run_req], 0
    jne .unavailable
    cmp byte [rel gws_active], 1
    jne .stopped
    mov rdi, [rel hv_linux_ram]
    test rdi, rdi
    jz .stopped
    add rdi, GWS_PIX_GPA
    xor eax, eax
    mov ecx, GWS_MAX / 8
    rep stosq
.stopped:
    call gws_clear
    call hv_linux_release_idle            ; RC-speed-reserve: the surface no longer pins the span
    call gws_request_base
    mov dword [rel gws_error], 0
    jmp .render
.selftest:
    cmp r13d, 4
    jne .syntax
    xor r15d, r15d
    jmp .geometry
.resize:
    cmp r13d, 4
    jne .syntax
    mov r15d, 1
.geometry:
    mov rdi, [rel gws_tok + 8]
    call gws_nonce_check
    test eax, eax
    jnz .syntax
    test r15d, r15d
    jz .dims
    call gws_same_nonce
    test eax, eax
    jnz .syntax
.dims:
    mov rdi, [rel gws_tok + 16]
    call gws_number
    jc .syntax
    test eax, eax
    jz .syntax
    cmp eax, GWS_DIM
    ja .syntax
    mov r14d, eax
    mov rdi, [rel gws_tok + 24]
    call gws_number
    jc .syntax
    test eax, eax
    jz .syntax
    cmp eax, GWS_DIM
    ja .syntax
    mov r13d, eax
    call gws_idle
    test eax, eax
    jnz .unavailable
    test r15d, r15d
    jnz .resize_generation
    call gws_clear
    call gws_request_base
    mov rsi, [rel gws_tok + 8]
    lea rdi, [rel gws_request + 208]
    mov ecx, 24
    rep movsb
    lea rdi, [rel gws_request + 208]
    mov esi, 24
    call hotpatch_crc32
    mov [rel gws_seed], eax
    jmp .set_geometry
.resize_generation:
    inc qword [rel gws_generation]
.set_geometry:
    mov [rel gws_request + 52], r14d
    mov [rel gws_request + 56], r13d
    shl r14d, 2
    mov [rel gws_request + 60], r14d
    call gws_full_rect
    jmp .good_run
.delta:
    cmp r13d, 6
    jne .syntax
    call gws_idle
    test eax, eax
    jnz .unavailable
    call gws_same_nonce
    test eax, eax
    jnz .syntax
    xor r14d, r14d
.delta_args:
    lea rdx, [rel gws_tok + 16]
    mov rdi, [rdx + r14*8]
    call gws_number
    jc .syntax
    lea rdx, [rel gws_numbers]
    mov [rdx + r14*4], eax
    inc r14d
    cmp r14d, 4
    jb .delta_args
    ; Widen before addition; an overflowing u32 rectangle is never clipped.
    mov eax, [rel gws_numbers + 8]
    test eax, eax
    jz .syntax
    mov edx, [rel gws_numbers]
    add rax, rdx
    mov ecx, [rel gws_request + 52]
    cmp rax, rcx
    ja .syntax
    mov eax, [rel gws_numbers + 12]
    test eax, eax
    jz .syntax
    mov edx, [rel gws_numbers + 4]
    add rax, rdx
    mov ecx, [rel gws_request + 56]
    cmp rax, rcx
    ja .syntax
    lea rsi, [rel gws_numbers]
    lea rdi, [rel gws_request + 80]
    mov ecx, 2
    rep movsq
.good_run:
    mov dword [rel gws_hostile], 0
    call gws_request_mask
    call gws_run
    jmp .render
.hostile:
    cmp r13d, 2
    jne .syntax
    call gws_idle
    test eax, eax
    jnz .unavailable
    cmp byte [rel gws_active], 1
    jne .syntax
    mov rdi, [rel gws_tok + 8]
    lea rsi, [rel gws_stale]
    call hv_tok_is
    test al, al
    jnz .stale
    mov rdi, [rel gws_tok + 8]
    lea rsi, [rel gws_rect]
    call hv_tok_is
    test al, al
    jnz .rect
    mov rdi, [rel gws_tok + 8]
    lea rsi, [rel gws_partial]
    call hv_tok_is
    test al, al
    jnz .partial
    mov rdi, [rel gws_tok + 8]
    lea rsi, [rel gws_stride]
    call hv_tok_is
    test al, al
    jnz .stride
    mov rdi, [rel gws_tok + 8]
    lea rsi, [rel gws_crc_word]
    call hv_tok_is
    test al, al
    jnz .crc
    mov rdi, [rel gws_tok + 8]
    lea rsi, [rel gws_gpa]
    call hv_tok_is
    test al, al
    jnz .gpa
    mov rdi, [rel gws_tok + 8]
    lea rsi, [rel gws_order]
    call hv_tok_is
    test al, al
    jnz .order
    mov rdi, [rel gws_tok + 8]
    lea rsi, [rel gws_unchanged_crc]
    call hv_tok_is
    test al, al
    jnz .unchanged_crc
    jmp .syntax
.stale:   mov eax, 1
    jmp .bad_run
.rect:    mov eax, 2
    jmp .bad_run
.partial: mov eax, 3
    jmp .bad_run
.stride:  mov eax, 4
    jmp .bad_run
.crc:     mov eax, 5
    jmp .bad_run
.gpa:     mov eax, 6
    jmp .bad_run
.order:   mov eax, 7
    jmp .bad_run
.unchanged_crc: mov eax, 8
.bad_run:
    mov [rel gws_hostile], eax
    call gws_full_rect
    cmp dword [rel gws_hostile], 8
    jne .hostile_rect_ready
    mov dword [rel gws_request + 88], 1
    mov dword [rel gws_request + 92], 1
.hostile_rect_ready:
    call gws_request_mask
    call gws_run
    jmp .render
.syntax:
    mov dword [rel gws_error], 13
    jmp .render
.unavailable:
    mov dword [rel gws_error], 10
.render:
    call gws_render
    mov byte [rel gws_busy], 0
    mov qword [r12 + RSP_CODE], CMDE_OK
    jmp .done
.busy:
    mov qword [r12 + RSP_CODE], CMDE_BADARG
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
%unmacro GWS_MATCH 2

gws_idle:
    mov al, [rel hv_linux_running]
    or al, [rel hv_linux_start_active]
    or al, [rel hv_linux_run_req]
    or al, [rel vtd_owner_guest]
    or al, [rel gws_poisoned]
    or al, [rel gws_mapped]
    movzx eax, al
    ret

gws_same_nonce:
    cmp byte [rel gws_active], 1
    jne .bad
    mov rdi, [rel gws_tok + 8]
    call gws_nonce_check
    test eax, eax
    jnz .bad
    mov rdi, [rel gws_tok + 8]
    lea rsi, [rel gws_request + 208]
    mov ecx, 24
    repe cmpsb
    jne .bad
    xor eax, eax
    ret
.bad:
    mov eax, 1
    ret

gws_full_rect:
    mov qword [rel gws_request + 80], 0
    mov eax, [rel gws_request + 52]
    mov [rel gws_request + 88], eax
    mov eax, [rel gws_request + 56]
    mov [rel gws_request + 92], eax
    ret

; Bounded output, every decimal is at most 20 chars and the complete reply
; including sixteen tile CRCs is <1200 bytes (UDP clamp is 1472).
gws_put:
    mov rsi, [rel gws_out_cur]
    lea rdx, [rel gws_out_buf + 1399]
.loop:
    mov al, [rdi]
    test al, al
    jz .out
    cmp rsi, rdx
    jae .out
    mov [rsi], al
    inc rdi
    inc rsi
    jmp .loop
.out:
    mov byte [rsi], 0
    mov [rel gws_out_cur], rsi
    ret
gws_dec:
    mov rsi, [rel gws_out_cur]
    lea rdx, [rel gws_out_buf + 1378]
    cmp rsi, rdx
    jae .out
    call fmt_dec
    mov byte [rsi], 0
    mov [rel gws_out_cur], rsi
.out:
    ret

%macro GWS_FIELD 3
    lea rdi, [rel %1]
    call gws_put
    xor edi, edi
    mov %2, [rel %3]
    call gws_dec
%endmacro
gws_render:
    push rbx
    lea rax, [rel gws_out_buf]
    mov [rel gws_out_cur], rax
    lea rdi, [rel gws_prefix]
    call gws_put
    mov edi, [rel gws_error]
    call gws_dec
    GWS_FIELD gws_f_active, dil, gws_active
    GWS_FIELD gws_f_mapped, dil, gws_mapped
    GWS_FIELD gws_f_gen, rdi, gws_present + 8
    GWS_FIELD gws_f_seq, rdi, gws_present + 24
    GWS_FIELD gws_f_ts, rdi, gws_present + 32
    GWS_FIELD gws_f_w, edi, gws_present + 52
    GWS_FIELD gws_f_h, edi, gws_present + 56
    GWS_FIELD gws_f_stride, edi, gws_present + 60
    lea rdi, [rel gws_f_format]
    call gws_put
    GWS_FIELD gws_f_mask, edi, gws_present + 72
    lea rdi, [rel gws_f_damage]
    call gws_put
    xor ebx, ebx
.rect:
    lea rax, [rel gws_present + 80]
    mov edi, [rax + rbx*4]
    call gws_dec
    inc ebx
    cmp ebx, 4
    jae .crcs
    lea rdi, [rel gws_comma]
    call gws_put
    jmp .rect
.crcs:
    lea rdi, [rel gws_f_tiles]
    call gws_put
    xor ebx, ebx
.tile:
    lea rax, [rel gws_present + 144]
    mov edi, [rax + rbx*4]
    call gws_dec
    inc ebx
    cmp ebx, 16
    jae .rest
    lea rdi, [rel gws_comma]
    call gws_put
    jmp .tile
.rest:
    GWS_FIELD gws_f_ring, rdi, gws_ring_seen
    GWS_FIELD gws_f_ack, rdi, gws_used_ack
    GWS_FIELD gws_f_accepted, rdi, gws_accepted
    GWS_FIELD gws_f_refused, rdi, gws_refused
    GWS_FIELD gws_f_revoke, rdi, gws_revocations
    lea rdi, [rel gws_f_guards]
    call gws_put
    call gws_guards
    mov edi, eax
    call gws_dec
    ; Full-frame CRC is a diagnostic observation ONLY, never per-flip work.
    lea rdi, [rel gws_f_crc]
    call gws_put
    mov rdi, [rel gws_front]
    mov esi, [rel gws_present + 60]
    imul esi, [rel gws_present + 56]
    call hotpatch_crc32
    mov edi, eax
    call gws_dec
    lea rdi, [rel gws_f_nonce]
    call gws_put
    lea rsi, [rel gws_present + 208]
    lea rdi, [rel gws_nonce_text]
    mov ecx, 24
    rep movsb
    mov byte [rdi], 0
    lea rdi, [rel gws_nonce_text]
    call gws_put
    mov byte [rel gws_out_ready], 1
    pop rbx
    ret
%unmacro GWS_FIELD 3


; Boot KAT executes the production snapshot/validator/consumer, entirely in
; private RAM. Literal CRC vector + independent pixel/padding oracle; no VMX.
gws_kat:
    push rbx
    push r12
    push r13
    call gws_clear
    call gws_request_base
    cmp qword [rel gws_front], 0         ; heap slab refused -> honest KAT FAIL
    je .fail
    lea rdi, [rel gws_crc_vector]
    mov esi, 9
    call hotpatch_crc32
    cmp eax, 0xCBF43926
    jne .fail
    mov dword [rel gws_request + 52], 8
    mov dword [rel gws_request + 56], 4
    mov dword [rel gws_request + 60], 40 ; padded stride, not width*4
    call gws_full_rect
    call gws_request_mask
    mov rax, [rel gws_generation]
    mov [rel gws_request + 8], rax
    mov qword [rel gws_request + 16], 1
    mov qword [rel gws_request + 24], 1
    mov qword [rel gws_request + 32], 1
    call gws_kat_src
    mov rdi, rax
    mov [rel gws_source], rdi
    mov eax, 0xFF123456
    mov ecx, GWS_MAX / 4
    rep stosd
    call gws_kat_src
    mov rsi, rax
    mov edi, 8
    mov edx, 4
    mov ecx, 40
    xor r8d, r8d
    lea r9, [rel gws_tile_scratch]
    call gws_tile_pack
    cmp eax, 128
    jne .fail
    mov esi, eax
    lea rdi, [rel gws_tile_scratch]
    call hotpatch_crc32
    mov [rel gws_request + 144], eax
    call gws_kat_candidate
    call gws_accept
    test eax, eax
    jnz .fail
    ; Independently inspect every dword. Only 8 pixels in each of 4 rows may
    ; have changed; row padding and the rest of the slab must stay zero.
    mov rsi, [rel gws_front]
    xor ebx, ebx
.scan:
    xor r8d, r8d
    cmp ebx, 40
    jae .expected
    mov eax, ebx
    xor edx, edx
    mov ecx, 10
    div ecx
    cmp edx, 8
    jae .expected
    mov r8d, 0xFF123456
.expected:
    cmp [rsi + rbx*4], r8d
    jne .fail
    inc ebx
    cmp ebx, GWS_MAX / 4
    jb .scan
    ; Exercise the compositor snapshot seam and its capacity refusal.
    call gws_kat_src
    mov rdi, rax
    mov esi, GWS_MAX - 1
    lea rdx, [rel gws_candidate]
    call guest_surface_copy
    test eax, eax
    jz .fail
    call gws_kat_src
    mov rdi, rax
    mov esi, GWS_MAX
    lea rdx, [rel gws_candidate]
    call guest_surface_copy
    test eax, eax
    jnz .fail
    cmp qword [rel gws_candidate + 24], 1
    jne .fail
    call gws_kat_src
    cmp dword [rax], 0xFF123456
    jne .fail
    cmp dword [rax + 32], 0
    jne .fail
    ; A second, genuinely partial flip must retain every non-damaged pixel
    ; and padded byte. The copied snapshot is now the producer's next source.
    mov dword [rax + 44], 0xFFABCDEF
    mov dword [rax + 48], 0xFFABCDEF
    mov dword [rax + 84], 0xFFABCDEF
    mov dword [rax + 88], 0xFFABCDEF
    mov dword [rel gws_request + 80], 1
    mov dword [rel gws_request + 84], 1
    mov dword [rel gws_request + 88], 2
    mov dword [rel gws_request + 92], 2
    mov qword [rel gws_request + 16], 2
    mov qword [rel gws_request + 24], 2
    mov qword [rel gws_request + 32], 2
    call gws_kat_crc
    call gws_kat_candidate
    call gws_accept
    test eax, eax
    jnz .fail
    mov rsi, [rel gws_front]
    call gws_kat_src
    mov rdi, rax
    mov ecx, GWS_MAX / 8
    repe cmpsq
    jne .fail
    mov r12, [rel gws_front]
    mov qword [rel gws_request + 16], 3
    mov qword [rel gws_request + 24], 3
    mov qword [rel gws_request + 32], 3
    ; Eight isolated mutations; record must refuse and retain exact front VA,
    ; generation and sequence, including when failure follows the pixel copy.
    xor r13d, r13d
.negative:
    call gws_kat_candidate
    cmp r13d, 0
    jne .n1
    dec qword [rel gws_candidate + 8]
    jmp .reject
.n1:
    cmp r13d, 1
    jne .n2
    mov qword [rel gws_candidate + 24], 0
    jmp .reject
.n2:
    cmp r13d, 2
    jne .n3
    mov dword [rel gws_candidate + 60], 0xFFFFFFFC
    jmp .reject
.n3:
    cmp r13d, 3
    jne .n4
    mov dword [rel gws_candidate + 80], 0xFFFFFFFF
    jmp .reject
.n4:
    cmp r13d, 4
    jne .n5
    xor dword [rel gws_candidate + 144], 1
    jmp .reject
.n5:
    cmp r13d, 5
    jne .n6
    mov qword [rel gws_candidate + 40], -16
    jmp .reject
.n6:
    cmp r13d, 6
    jne .n7
    xor dword [rel gws_candidate + 148], 1 ; unselected tile CRC
    jmp .reject
.n7:
    mov qword [rel gws_candidate + 16], 2
    mov qword [rel gws_candidate + 24], 2 ; replay of last completed flip
.reject:
    call gws_accept
    lea rdx, [rel gws_kat_errors]
    movzx edx, byte [rdx + r13]
    cmp eax, edx
    jne .fail
    cmp [rel gws_front], r12
    jne .fail
    cmp qword [rel gws_present + 24], 2
    jne .fail
    inc r13d
    cmp r13d, 8
    jb .negative
    ; Known bad CRC must not change a single published byte.
    mov rsi, [rel gws_front]
    cmp dword [rsi], 0xFF123456
    jne .fail
    cmp dword [rsi + 32], 0
    jne .fail
    call gws_kat_src
    mov rdi, rax
    mov ecx, GWS_MAX / 8
    repe cmpsq
    jne .fail
    ; Resize through a new generation, preserving sequence order but clearing
    ; the previous layout and all padding outside the new bounded surface.
    inc qword [rel gws_generation]
    mov rax, [rel gws_generation]
    mov [rel gws_request + 8], rax
    mov dword [rel gws_request + 52], 4
    mov dword [rel gws_request + 56], 2
    mov dword [rel gws_request + 60], 24
    call gws_full_rect
    call gws_request_mask
    call gws_kat_src
    mov rdi, rax
    mov eax, 0xFFA0B0C0
    mov ecx, GWS_MAX / 4
    rep stosd
    call gws_kat_crc
    call gws_kat_candidate
    call gws_accept
    test eax, eax
    jnz .fail
    mov rax, [rel gws_generation]
    cmp [rel gws_present + 8], rax
    jne .fail
    cmp qword [rel gws_present + 24], 3
    jne .fail
    mov rsi, [rel gws_front]
    xor ebx, ebx
.resize_scan:
    xor r8d, r8d
    cmp ebx, 12
    jae .resize_expected
    mov eax, ebx
    xor edx, edx
    mov ecx, 6
    div ecx
    cmp edx, 4
    jae .resize_expected
    mov r8d, 0xFFA0B0C0
.resize_expected:
    cmp [rsi + rbx*4], r8d
    jne .fail
    inc ebx
    cmp ebx, GWS_MAX / 4
    jb .resize_scan
    call gws_guards
    test eax, eax
    jz .fail
    lea rdi, [rel gws_flip_pass]
    call serial_string
    lea rdi, [rel gws_damage_pass]
    call serial_string
    jmp .clean
.fail:
    lea rdi, [rel gws_kat_fail]
    call serial_string
.clean:
    call gws_clear
    call gws_request_base
    mov qword [rel gws_accepted], 0
    mov qword [rel gws_refused], 0
    mov dword [rel gws_error], 0
    ; (gws_clear above already zeroed the KAT source inside the slab)
    pop r13
    pop r12
    pop rbx
    ret
gws_kat_candidate:
    lea rsi, [rel gws_request]
    lea rdi, [rel gws_candidate]
    mov ecx, GWS_SIZE / 8
    rep movsq
    ret

; KAT request is always a bounded tile-0 surface, with deliberately padded rows.
gws_kat_crc:
    call gws_kat_src
    mov rsi, rax
    mov edi, [rel gws_request + 52]
    mov edx, [rel gws_request + 56]
    mov ecx, [rel gws_request + 60]
    xor r8d, r8d
    lea r9, [rel gws_tile_scratch]
    call gws_tile_pack
    mov esi, eax
    lea rdi, [rel gws_tile_scratch]
    call hotpatch_crc32
    mov [rel gws_request + 144], eax
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_hv_guest_surface_0 0
align 8
gws_front: dq 0
gws_publication: dq 0
gws_back: dq 0
gws_source: dq 0
gws_generation: dq 0
gws_accepted: dq 0
gws_refused: dq 0
gws_ring_seen: dq 0
gws_used_ack: dq 0
gws_revocations: dq 0
gws_out_cur: dq 0
gws_seed: dd 0
gws_hostile: dd 0
gws_error: dd 0
gws_active: db 0
gws_bound: db 0
gws_mapped: db 0
gws_poisoned: db 0
gws_fixture_mode: db 0
gws_busy: db 0
gws_out_ready: db 0
align 8
gws_request: times GWS_SIZE db 0
gws_candidate: times GWS_SIZE db 0
gws_present: times GWS_SIZE db 0
gws_tok: times 8 dq 0
gws_numbers: times 4 dd 0
gws_args: times 160 db 0
gws_nonce_text: times 25 db 0
gws_out_buf: times 1400 db 0
align 8
gws_slab_ptr: dq 0                       ; -> heap A/B/KAT slab (gws_slab); was 196,632 image bytes
gws_slab_armed: db 0
align 8
gws_guard_d: dq 0x2716DEADBEEF2716
gws_tile_scratch: times 4096 db 0
gws_guard_e: dq 0x2716DEADBEEF2716

gws_verb: db "GWSURFACE",0
gws_stat: db "STAT",0
gws_stop: db "STOP",0
gws_selftest: db "SELFTEST",0
gws_delta: db "DELTA",0
gws_resize: db "RESIZE",0
gws_hostile_word: db "HOSTILE",0
gws_stale: db "STALE",0
gws_rect: db "RECT",0
gws_partial: db "PARTIAL",0
gws_stride: db "STRIDE",0
gws_crc_word: db "CRC",0
gws_gpa: db "GPA",0
gws_order: db "ORDER",0
gws_unchanged_crc: db "UNCHANGED_CRC",0
gws_comma: db ",",0
gws_prefix: db "GWSURFACE error=",0
gws_f_active: db " active=",0
gws_f_mapped: db " mapped=",0
gws_f_gen: db " generation=",0
gws_f_seq: db " flip_seq=",0
gws_f_ts: db " flip_ts=",0
gws_f_w: db " width=",0
gws_f_h: db " height=",0
gws_f_stride: db " stride=",0
gws_f_format: db " format=BGRX",0
gws_f_mask: db " tile_mask=",0
gws_f_damage: db " damage=",0
gws_f_tiles: db " crc_tile=",0
gws_f_ring: db " ring_seen=",0
gws_f_ack: db " guest_used_ack=",0
gws_f_accepted: db " accepted=",0
gws_f_refused: db " refused=",0
gws_f_revoke: db " revocations=",0
gws_f_guards: db " guards=",0
gws_f_crc: db " frame_crc=",0
gws_f_nonce: db " nonce=",0
gws_crc_vector: db "123456789"
gws_flip_pass: db "[PAOS64] guest surface descriptor/flip generation KAT PASS [guest.surface.flip.kat]",13,10,0
gws_damage_pass: db "[PAOS64] guest surface damage/tile CRC KAT PASS [guest.surface.damage.kat]",13,10,0
gws_kat_fail: db "[PAOS64] guest surface KAT FAIL",13,10,0
gws_kat_errors: db 2,3,4,5,9,4,9,3
gws_registry_fail: db "[PAOS64] guest surface registry FULL",13,10,0
gws_slab_fail: db "[PAOS64] guest surface: heap refused the snapshot slab",13,10,0
%endmacro
WDATA_DEFER WDATA_hv_guest_surface_0

; gws_slab -> RAX = the zeroed A/B/KAT slab (GWS_SLAB_BYTES), or 0 if the heap
; refused. Preserves every register except RAX. First successful use arms the
; four in-slab overrun guards exactly once (a later overrun stays visible).
HEAP_ONCE_ACCESSOR gws_slab_heap, gws_slab_ptr, GWS_SLAB_BYTES, gws_slab_fail
gws_slab:
    call gws_slab_heap
    test rax, rax
    jz .out
    cmp byte [rel gws_slab_armed], 0
    jne .out
    push rdx
    mov rdx, GWS_GUARD_MAGIC
    mov [rax + GWS_SLAB_A - 8], rdx
    mov [rax + GWS_SLAB_B - 8], rdx
    mov [rax + GWS_SLAB_KAT - 8], rdx
    mov [rax + GWS_SLAB_KAT + GWS_MAX], rdx
    pop rdx
    mov byte [rel gws_slab_armed], 1
.out:
    ret

; gws_kat_src -> RAX = the KAT source buffer (slab + GWS_SLAB_KAT). Only called
; inside gws_kat, which fails before any use when the slab is absent.
gws_kat_src:
    call gws_slab
    add rax, GWS_SLAB_KAT
    ret

gws_guards:
    mov rdx, GWS_GUARD_MAGIC
    mov rax, [rel gws_slab_ptr]
    test rax, rax
    jz .bad
    cmp [rax + GWS_SLAB_A - 8], rdx
    jne .bad
    cmp [rax + GWS_SLAB_B - 8], rdx
    jne .bad
    cmp [rax + GWS_SLAB_KAT - 8], rdx
    jne .bad
    cmp [rax + GWS_SLAB_KAT + GWS_MAX], rdx
    jne .bad
    cmp [rel gws_guard_d], rdx
    jne .bad
    cmp [rel gws_guard_e], rdx
    jne .bad
    mov eax, 1
    ret
.bad:
    xor eax, eax
    ret

gws_accept:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call gws_validate
    test eax, eax
    jnz .refused
    mov eax, 8
    cmp qword [rel gws_source], 0
    je .refused
    cmp qword [rel gws_back], 0          ; no heap slab -> no snapshot storage
    je .refused
    ; R10-H2: successful geometry validation AND source/back admission must
    ; finish before pixel effects or candidate-dependent addresses/counts.
    ; The ingress size LFENCE and publication SFENCE serve other boundaries.
    lfence
    mov rdi, [rel gws_back]
    mov rsi, [rel gws_front]
    mov ecx, GWS_MAX / 8
    rep movsq
    mov rax, [rel gws_candidate + 8]
    cmp rax, [rel gws_present + 8]
    je .copy_damage
    mov rdi, [rel gws_back]
    xor eax, eax
    mov ecx, GWS_MAX / 8
    rep stosq
.copy_damage:
    lea r12, [rel gws_candidate + 80]
    mov r13d, [rel gws_candidate + 68]
    mov r14d, [rel gws_candidate + 60]
.rect:
    mov eax, [r12 + 4]
    imul rax, r14
    mov ecx, [r12]
    lea rax, [rax + rcx*4]
    mov rsi, [rel gws_source]
    add rsi, rax
    mov rdi, [rel gws_back]
    add rdi, rax
    mov ebx, [r12 + 8]
    shl ebx, 2
    mov r15d, [r12 + 12]
.row:
    mov ecx, ebx
    rep movsb
    add rsi, r14
    sub rsi, rbx
    add rdi, r14
    sub rdi, rbx
    dec r15d
    jnz .row
    add r12, 16
    dec r13d
    jnz .rect
    xor r12d, r12d
.tile:
    bt dword [rel gws_candidate + 72], r12d
    jnc .unchanged_tile
    mov rsi, [rel gws_back]
    mov edi, [rel gws_candidate + 52]
    mov edx, [rel gws_candidate + 56]
    mov ecx, [rel gws_candidate + 60]
    mov r8d, r12d
    lea r9, [rel gws_tile_scratch]
    call gws_tile_pack
    mov esi, eax
    lea rdi, [rel gws_tile_scratch]
    call hotpatch_crc32
    lea rdx, [rel gws_candidate + 144]
    cmp eax, [rdx + r12*4]
    jne .crc_bad
    jmp .next_tile
.unchanged_tile:
    xor eax, eax
    mov rdx, [rel gws_candidate + 8]
    cmp rdx, [rel gws_present + 8]
    jne .check_unchanged
    lea rdx, [rel gws_present + 144]
    mov eax, [rdx + r12*4]
.check_unchanged:
    lea rdx, [rel gws_candidate + 144]
    cmp eax, [rdx + r12*4]
    jne .crc_bad
.next_tile:
    inc r12d
    cmp r12d, 16
    jb .tile
    inc qword [rel gws_publication]
    sfence
    lea rsi, [rel gws_candidate]
    lea rdi, [rel gws_present]
    mov ecx, GWS_SIZE / 8
    rep movsq
    mov rax, [rel gws_back]
    sfence
    xchg rax, [rel gws_front]
    mov [rel gws_back], rax
    mov byte [rel gws_active], 1
    sfence
    inc qword [rel gws_publication]
    inc qword [rel gws_accepted]
    mov dword [rel gws_error], 0
    xor eax, eax
    jmp .out
.crc_bad:
    mov eax, 9
.refused:
    mov [rel gws_error], eax
    inc qword [rel gws_refused]
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
