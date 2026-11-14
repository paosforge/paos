;; MODULE core/font_cache
;; LAYER 1
;; EXPORTS fpc_init, fpc_register, fpc_fetch, fpc_begin, fpc_pin, fpc_publish, fpc_unbind, fpc_view, fpc_cell, fpc_phase, fpc_epoch
;; IMPORTS
;; CAPS
;; OWNER rc-codex-relops
;; CONTEXT: bsp_only
; RCQ-38 G2. Include-free private caller context, owned callbacks/RAM only.
; No production wiring, signature/PPGH/PFNT parser, renderer, or storage driver.
; SysV. Owned/disjoint context128B, inputs and outputs. BSP, non-reentrant.
; Context starts zero ONCE. Allocator returns owned2.5MiB or0; no retry/free.
; Trusted callbacks: alloc(bytes)->ptr; read(handle,page,out,n)->exact n or -1;
; sha(out32,data,n)->0; restore(binding,originalEnglish)->0 after fallback.
; Descriptor40: total u32, pages u32, hashes ptr, handle, auth u32=1,
; epoch u32, hashes bytes u32, reserved u32=0. G0 authenticates this context.
; Auth=1 is a prerequisite, NOT signature verification; caller owns source lease.
; Three independently selected AA artifacts/epoch. Register copies authenticated hashes, not media.
; One2.5MiB allocation splits into512KiB pages and2MiB control; all zeroed.
; Root07:34:35 AA-2.5; boot07:28:19 floor4.5MiB and four validity flags.
; See NATIVE_FONT_CACHE.md. All preparation APIs refuse in paint phase.
FPC_TOTAL equ 2621440
FPC_PAGES equ 524288
FPC_CONTROL equ 2097152
FPC_USED_CONTROL equ 1683456
; Margin[0:128] can own the persistent context after bootstrap; never erase it.
FPC_SLOTS equ 127
FPC_PIN_CAP equ 125
FPC_DESC equ 1257472
FPC_POOL equ 1417216
FPC_BITS equ 1679360
FPC_META equ 4096
FPC_ARTIFACTS equ 3
FPC_BITMAP_QWORDS equ 2
FPC_FLOOR equ 4718592
%macro FPC_ENTER 0
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
%endmacro
%macro FPC_LEAVE 0
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
%endmacro
; ctx: state0 epoch4 pages8 control16 clock24 distinctpins28 phase32 busy36
; poolused40 refusal_reason44 alloc48 read56 sha64 restore72; rest reserved zero.
fpc_preparing:
    xor eax, eax
    test rdi, rdi
    jz .out
    cmp dword [rdi], 1
    jne .out
    cmp dword [rdi+32], 0
    jne .out
    cmp dword [rdi+36], 0
    jne .out
    mov eax, 1
.out: ret
fpc_copy:
    mov ecx, edx
    cld
    rep movsb
    ret
; RDIctx128, RSIcallbacks32, RDXprivate admission64 ->1 ready/0 English.
; Admission QWORDS: heap_base0,heap_size8,owned heap_next pointer16,
; measured absolute heap_next24,flags32,owner floor40,version1@48,reserved0@56.
; Flags0..3 all required: no model,model arena exists,current consumer census,
; bind not earlier than owner point. Bit4 S1 charged, bit5 prefs charged.
; Unknown bits refuse. All inputs private/trusted-owned, never serialized DATA.
; Single BSP/no-yield turn; heap_next must be owned/aligned; no IRQ/AP allocator.
; Reason44:0 ready,1 callbacks,2 admission,3 profile,4 floor,5 bounds,6 stale,
; 7 overflow,8 headroom,9 allocatorOOM,10 allocatorrange. Stable on no-retry.
fpc_init:
    FPC_ENTER
    mov rbx, rdi
    mov r12, rsi
    mov r14, rdx
    test rbx, rbx
    jz .bad
    cmp dword [rbx], 1
    je .good
    cmp dword [rbx], 0
    jne .bad
    mov dword [rbx], 2             ; even admission/OOM consume the attempt
    mov dword [rbx+44], 1
    test r12, r12
    jz .bad
    cmp qword [r12], 0
    je .bad
    cmp qword [r12+8], 0
    je .bad
    cmp qword [r12+16], 0
    je .bad
    cmp qword [r12+24], 0
    je .bad
    test r14, r14
    jz .admission
    mov rax, r14
    add rax, 64
    jc .admission
    cmp qword [r14+48], 1
    jne .admission
    cmp qword [r14+56], 0
    jne .admission
    mov r13, [r14+32]
    mov eax, r13d
    and eax, 15
    cmp eax, 15
    jne .profile
    mov rax, r13
    shr rax, 6
    jnz .profile
    cmp qword [r14+40], FPC_FLOOR
    jne .floor
    mov r8, [r14]
    mov r9, [r14+8]
    mov r10, r8
    add r10, r9
    jc .overflow
    mov r11, [r14+16]
    test r11, r11
    jz .bounds
    test r11b, 7
    jnz .bounds
    mov rax, r11
    add rax, 8
    jc .bounds
    mov r15, [r11]                 ; live same-BSP heap cursor, no callback/yield
    cmp r15, r8
    jb .bounds
    cmp r15, r10
    ja .bounds
    mov rax, [r14+24]
    cmp rax, r8
    jb .bounds
    cmp rax, r10
    ja .bounds
    cmp r15, rax
    jne .stale
    mov eax, FPC_TOTAL
    add rax, [r14+40]
    jc .overflow
    test r13b, 16
    jnz .prefs
    add rax, 3145728               ; S1 not already included in live heap cursor
    jc .overflow
.prefs:
    test r13b, 32
    jnz .budget
    add rax, 240
    jc .overflow
.budget:
    mov rcx, r10
    sub rcx, r15                   ; range checked before subtraction
    cmp rcx, rax
    jb .headroom
    cmp [r11], r15                 ; final check immediately before owned allocator
    jne .stale
    mov edi, FPC_TOTAL
    call [r12]
    test rax, rax
    jz .oom
    test al, 15
    jnz .allocator
    mov rdx, rax
    add rdx, FPC_TOTAL
    jc .allocator
    mov r13, rax
    mov rdi, rax
    xor eax, eax
    mov ecx, FPC_TOTAL/8
    cld
    rep stosq
    lea rdi, [rbx+4]
    mov ecx, 124
    rep stosb
    mov [rbx+8], r13
    add r13, FPC_PAGES
    mov [rbx+16], r13
    lea rdi, [rbx+48]
    mov rsi, r12
    mov edx, 32
    call fpc_copy
    mov dword [rbx+4], 1
    mov dword [rbx], 1
.good:
    mov eax, 1
    jmp .out
.admission:
    mov dword [rbx+44], 2
    jmp .bad
.profile:
    mov dword [rbx+44], 3
    jmp .bad
.floor:
    mov dword [rbx+44], 4
    jmp .bad
.bounds:
    mov dword [rbx+44], 5
    jmp .bad
.stale:
    mov dword [rbx+44], 6
    jmp .bad
.overflow:
    mov dword [rbx+44], 7
    jmp .bad
.headroom:
    mov dword [rbx+44], 8
    jmp .bad
.oom:
    mov dword [rbx+44], 9
    jmp .bad
.allocator:
    mov dword [rbx+44], 10
.bad: xor eax, eax
.out: FPC_LEAVE
; RDIctx ESIordinal0..2 RDXtrusted40Bdesc ->1/0. No replacement/epoch.
fpc_register:
    FPC_ENTER
    mov rbx, rdi
    mov ebp, esi
    mov r12, rdx
    call fpc_preparing
    test eax, eax
    jz .bad
    cmp ebp, FPC_ARTIFACTS
    jae .bad
    test r12, r12
    jz .bad
    mov eax, [r12]
    test eax, eax
    jz .bad
    cmp eax, 16777216
    ja .bad
    add eax, 4095
    shr eax, 12
    cmp eax, [r12+4]
    jne .bad
    shl eax, 5
    cmp eax, [r12+32]
    jne .bad
    mov r13d, eax
    cmp dword [r12+24], 1
    jne .bad
    mov eax, [r12+28]
    cmp eax, [rbx+4]
    jne .bad
    cmp dword [r12+36], 0
    jne .bad
    cmp qword [r12+16], 0
    je .bad
    mov rax, [r12+8]
    test rax, rax
    jz .bad
    add rax, r13
    jc .bad
    mov r14d, ebp
    shl r14, 6
    add r14, [rbx+16]
    add r14, FPC_DESC
    cmp dword [r14+32], 0
    jne .bad
    mov eax, ebp
    imul rax, 135168               ; each copied page-hash table has33pages
    add rax, [rbx+16]
    add rax, 65536
    mov r15, rax
    mov rdi, rax
    mov rsi, [r12+8]
    mov edx, r13d
    call fpc_copy
    mov rax, [r12]                 ; total and pages
    mov [r14], rax
    mov [r14+8], r15
    mov rax, [r12+16]
    mov [r14+16], rax
    mov eax, [rbx+4]
    mov [r14+24], eax
    mov dword [r14+32], 1          ; only after the immutable hashes are owned
    mov eax, 1
    jmp .out
.bad: xor eax, eax
.out: FPC_LEAVE
; Internal resident lookup ctx,ordinal,page ->slot/-1; no fetch/hash/alloc.
fpc_slot:
    mov r8, [rdi+8]
    mov r9d, [rdi+4]
    xor eax, eax
.loop:
    mov ecx, eax
    shl rcx, 4
    add rcx, r8
    cmp byte [rcx+32+12], 1
    jne .next
    cmp [rcx+32], si
    jne .next
    cmp [rcx+32+4], edx
    jne .next
    cmp [rcx+32+8], r9d
    jne .next
    ret
.next:
    inc eax
    cmp eax, FPC_SLOTS
    jb .loop
    mov eax, -1
    ret
; RDIctx ESIordinal EDXpage ->slot/-1. Bounded clock; pins never evicted.
fpc_fetch:
    FPC_ENTER
    mov rbx, rdi
    mov r12d, esi
    mov r13d, edx
    call fpc_preparing
    test eax, eax
    jz .bad
    cmp r12d, FPC_ARTIFACTS
    jae .bad
    mov r14d, r12d
    shl r14, 6
    add r14, [rbx+16]
    add r14, FPC_DESC
    cmp dword [r14+32], 1
    jne .bad
    mov eax, [rbx+4]
    cmp [r14+24], eax
    jne .bad
    cmp r13d, [r14+4]
    jae .bad
    mov esi, r12d
    mov edx, r13d
    call fpc_slot
    test eax, eax
    jns .hit
    mov ebp, FPC_SLOTS*2
.scan:
    mov r15d, [rbx+24]
    cmp r15d, FPC_SLOTS
    jae .bad
    lea eax, [r15+1]
    cmp eax, FPC_SLOTS
    jb .hand
    xor eax, eax
.hand:
    mov [rbx+24], eax
    mov eax, r15d
    shl rax, 4
    add rax, [rbx+8]
    add rax, 32
    cmp word [rax+2], 0
    jne .next
    cmp byte [rax+12], 1
    jne .chosen
    cmp byte [rax+13], 0
    je .chosen
    mov byte [rax+13], 0
.next:
    dec ebp
    jnz .scan
    jmp .bad
.chosen:
    mov dword [rax+12], 0          ; destroy old verification before refetch
    mov eax, r13d
    shl eax, 12
    mov edx, [r14]
    sub edx, eax
    cmp edx, 4096
    jbe .length
    mov edx, 4096
.length:
    mov [rsp+32], edx
    mov eax, r15d
    shl rax, 12
    add rax, [rbx+8]
    add rax, FPC_META
    mov rbp, rax
    mov rdi, rax
    xor eax, eax
    mov ecx, 512
    cld
    rep stosq                     ; initialize the full slot, including last tail
    mov dword [rbx+36], 1
    mov rdi, [r14+16]
    mov esi, r13d
    mov rdx, rbp
    mov ecx, [rsp+32]
    call [rbx+56]
    cmp eax, [rsp+32]
    jne .unavailable
    mov rdi, rsp
    mov rsi, rbp
    mov edx, [rsp+32]
    call [rbx+64]
    test eax, eax
    jnz .unavailable
    mov eax, r13d
    shl rax, 5
    add rax, [r14+8]
    xor ecx, ecx
    xor edx, edx
.hash:
    mov r8b, [rsp+rcx]
    xor r8b, [rax+rcx]
    or dl, r8b
    inc ecx
    cmp ecx, 32
    jb .hash
    test dl, dl
    jnz .unavailable
    mov eax, r15d
    shl rax, 4
    add rax, [rbx+8]
    add rax, 32
    mov [rax], r12w
    mov word [rax+2], 0
    mov [rax+4], r13d
    mov edx, [rbx+4]
    mov [rax+8], edx
    mov byte [rax+13], 1
    mov byte [rax+12], 1           ; publish after exact-length hash of SAME bytes
    mov dword [rbx+36], 0
    mov eax, r15d
    jmp .out
.unavailable:
    mov dword [r14+32], 2          ; terminal unavailable, never free until epoch
    mov dword [rbx+36], 0
.bad:
    mov eax, -1
    jmp .out
.hit:
    mov edx, eax
    shl rdx, 4
    add rdx, [rbx+8]
    mov byte [rdx+32+13], 1
.out: FPC_LEAVE
; Internal ctrl -> binding pointer from ctx RDI, ID ESI, returned RAX.
fpc_binding:
    mov eax, esi
    shl rax, 5
    add rax, [rdi+16]
    add rax, FPC_DESC+FPC_ARTIFACTS*64
    ret
; Reclaim only outside paint, ordered memmove towards lower offsets, <=80^2 scans.
fpc_compact:
    FPC_ENTER
    mov rbx, rdi
    xor r12d, r12d                 ; old cursor
    xor r13d, r13d                 ; packed cursor
    mov ebp, 80
.again:
    xor esi, esi
    mov r14d, 0xffffffff
    xor r15d, r15d
.scan:
    mov rdi, rbx
    call fpc_binding
    cmp dword [rax], 0
    je .next
    mov edx, [rax+8]
    cmp edx, r12d
    jb .next
    cmp edx, r14d
    jae .next
    mov r14d, edx
    mov r15, rax
.next:
    inc esi
    cmp esi, 80
    jb .scan
    test r15, r15
    jz .done
    mov edx, [r15+12]
    inc edx
    lea r12d, [r14+rdx]
    mov rsi, [rbx+16]
    add rsi, FPC_POOL
    mov rdi, rsi
    add rsi, r14
    add rdi, r13
    mov [r15+8], r13d
    add r13d, edx
    call fpc_copy
    dec ebp
    jnz .again
.done:
    mov [rbx+40], r13d
    FPC_LEAVE
; RDIctx ESIbinding0..79 RDXownedUTF8 ECXbytes1..8192 R8originalEnglish.
; G4 supplies strict UTF8/shaping/cell-budget preflight, then pins/publishes.
fpc_begin:
    FPC_ENTER
    mov rbx, rdi
    mov ebp, esi
    mov r12, rdx
    mov r13d, ecx
    mov r14, r8
    call fpc_preparing
    test eax, eax
    jz .bad
    cmp ebp, 80
    jae .bad
    test r12, r12
    jz .bad
    test r14, r14
    jz .bad
    test r13d, r13d
    jz .bad
    cmp r13d, 8192
    ja .bad
    mov rax, r12
    add rax, r13
    jc .bad
    add rax, 1
    jc .bad
    cmp byte [r12+r13], 0
    jne .bad
    mov rdi, rbx
    mov esi, ebp
    call fpc_unbind                ; restore prior English before reusing its pins
    test eax, eax
    jz .bad
    mov eax, [rbx+40]
    lea rdx, [rax+r13+1]
    cmp rdx, 262144
    ja .bad
    mov r15d, eax
    mov [rbx+40], edx
    mov rdi, [rbx+16]
    add rdi, FPC_POOL
    add rdi, r15
    mov rsi, r12
    lea edx, [r13+1]
    call fpc_copy
    mov rdi, rbx
    mov esi, ebp
    call fpc_binding
    mov [rax+8], r15d
    mov [rax+12], r13d
    mov [rax+16], r14
    mov edx, [rbx+4]
    mov [rax+4], edx
    mov dword [rax], 1             ; preparing, never paint-visible yet
    mov eax, 1
    jmp .out
.bad: xor eax, eax
.out: FPC_LEAVE
; RDIctx ESIbinding EDXresidentSlot. Once per binding, <=125 distinct pins.
fpc_pin:
    FPC_ENTER
    mov rbx, rdi
    mov ebp, esi
    mov r12d, edx
    call fpc_preparing
    test eax, eax
    jz .bad
    cmp ebp, 80
    jae .bad
    cmp r12d, FPC_SLOTS
    jae .bad
    mov esi, ebp
    call fpc_binding
    cmp dword [rax], 1
    jne .bad
    mov edx, [rbx+4]
    cmp [rax+4], edx
    jne .bad
    mov r13d, r12d
    shl r13, 4
    add r13, [rbx+8]
    add r13, 32
    cmp byte [r13+12], 1
    jne .bad
    cmp [r13+8], edx
    jne .bad
    movzx eax, word [r13]
    cmp eax, FPC_ARTIFACTS
    jae .bad
    shl rax, 6
    add rax, [rbx+16]
    cmp dword [rax+FPC_DESC+32], 1
    jne .bad
    mov r14d, ebp
    shl r14, 4
    add r14, [rbx+16]
    add r14, FPC_BITS
    bt qword [r14], r12
    jc .good
    cmp word [r13+2], 80
    jae .bad
    cmp word [r13+2], 0
    jne .count
    cmp dword [rbx+28], FPC_PIN_CAP
    jae .bad
    inc dword [rbx+28]
.count:
    inc word [r13+2]
    bts qword [r14], r12
.good: mov eax, 1
    jmp .out
.bad: xor eax, eax
.out: FPC_LEAVE
; Internal pure whole-binding validation ctx RDI, ID ESI, required state EDX.
fpc_binding_ok:
    test rdi, rdi
    jz .bad
    cmp dword [rdi], 1
    jne .bad
    cmp esi, 80
    jae .bad
    call fpc_binding
    cmp [rax], edx
    jne .bad
    mov r8d, [rdi+4]
    cmp [rax+4], r8d
    jne .bad
    mov r9d, [rax+8]
    mov ecx, [rax+12]
    test ecx, ecx
    jz .bad
    cmp ecx, 8192
    ja .bad
    lea r10, [r9+rcx+1]
    cmp r10, 262144
    ja .bad
    cmp r10d, [rdi+40]
    ja .bad
    mov r10d, esi
    shl r10, 4
    add r10, [rdi+16]
    add r10, FPC_BITS
    mov r11, [r10+8]
    shr r11, 63
    jnz .bad
    xor ecx, ecx
.loop:
    bt qword [r10], rcx
    jnc .next
    mov eax, ecx
    shl rax, 4
    add rax, [rdi+8]
    add rax, 32
    cmp byte [rax+12], 1
    jne .bad
    cmp word [rax+2], 0
    je .bad
    cmp [rax+8], r8d
    jne .bad
    movzx r9d, word [rax]
    cmp r9d, FPC_ARTIFACTS
    jae .bad
    shl r9, 6
    add r9, [rdi+16]
    add r9, FPC_DESC
    cmp dword [r9+32], 1
    jne .bad
    cmp [r9+24], r8d
    jne .bad
    mov eax, [rax+4]
    cmp eax, [r9+4]
    jae .bad
.next:
    inc ecx
    cmp ecx, FPC_SLOTS
    jb .loop
    mov eax, 1
    ret
.bad: xor eax, eax
    ret
fpc_publish:
    FPC_ENTER
    mov rbx, rdi
    mov ebp, esi
    call fpc_preparing
    test eax, eax
    jz .bad
    mov esi, ebp
    mov edx, 1
    call fpc_binding_ok
    test eax, eax
    jz .bad
    mov esi, ebp
    call fpc_binding
    mov dword [rax], 2
    mov eax, 1
    jmp .out
.bad: xor eax, eax
.out: FPC_LEAVE
; Unbind restores original English before page pins disappear; no work in paint.
fpc_unbind:
    FPC_ENTER
    mov rbx, rdi
    mov ebp, esi
    call fpc_preparing
    test eax, eax
    jz .bad
    cmp ebp, 80
    jae .bad
    mov esi, ebp
    call fpc_binding
    mov r12, rax
    cmp dword [r12], 0
    je .good
    mov edi, ebp
    mov rsi, [r12+16]
    mov dword [rbx+36], 1          ; guard trusted restore callback too
    call [rbx+72]
    mov dword [rbx+36], 0
    test eax, eax
    jnz .bad
    mov r13d, ebp
    shl r13, 4
    add r13, [rbx+16]
    add r13, FPC_BITS
    xor r14d, r14d
.loop:
    bt qword [r13], r14
    jnc .next
    mov eax, r14d
    shl rax, 4
    add rax, [rbx+8]
    add rax, 32
    cmp word [rax+2], 0
    je .bad
    dec word [rax+2]
    jnz .next
    dec dword [rbx+28]
.next:
    inc r14d
    cmp r14d, FPC_SLOTS
    jb .loop
    mov rdi, r13
    xor eax, eax
    mov ecx, FPC_BITMAP_QWORDS
    cld
    rep stosq
    mov rdi, r12
    mov ecx, 4
    rep stosq
    mov rdi, rbx
    call fpc_compact
.good: mov eax, 1
    jmp .out
.bad: xor eax, eax
.out: FPC_LEAVE
; RDIctx ESIbinding RDXowned32Boutput ->1 all-ready/0 whole-English.
; Out: copied-text ptr0, originalEnglish ptr8, textlen16, epoch20, rest0.
fpc_view:
    FPC_ENTER
    mov rbx, rdi
    mov ebp, esi
    mov r12, rdx
    test r12, r12
    jz .bad
    mov rdi, r12
    xor eax, eax
    mov ecx, 4
    cld
    rep stosq
    mov rdi, rbx
    mov esi, ebp
    mov edx, 2
    call fpc_binding_ok
    test eax, eax
    jz .bad
    mov esi, ebp
    call fpc_binding
    mov edx, [rax+8]
    add rdx, [rbx+16]
    add rdx, FPC_POOL
    mov [r12], rdx
    mov rdx, [rax+16]
    mov [r12+8], rdx
    mov edx, [rax+12]
    mov [r12+16], edx
    mov edx, [rax+4]
    mov [r12+20], edx
    mov eax, 1
    jmp .out
.bad: xor eax, eax
.out: FPC_LEAVE
; RDIctx ESIartifact EDXoffset ECXbytes1..4096 R8ownedoutput4096 ->1/0.
; Both pages must be ready AND pinned before ANY copy. No naked page pointers.
fpc_cell:
    FPC_ENTER
    mov rbx, rdi
    mov ebp, esi
    mov r13d, edx
    mov r14d, ecx
    mov r12, r8
    test rbx, rbx
    jz .bad
    cmp dword [rbx], 1
    jne .bad
    cmp ebp, FPC_ARTIFACTS
    jae .bad
    test r12, r12
    jz .bad
    test r14d, r14d
    jz .bad
    cmp r14d, 4096
    ja .bad
    mov rax, r12
    add rax, r14
    jc .bad
    mov eax, ebp
    shl rax, 6
    add rax, [rbx+16]
    add rax, FPC_DESC
    cmp dword [rax+32], 1
    jne .bad
    mov edx, [rbx+4]
    cmp [rax+24], edx
    jne .bad
    lea rdx, [r13+r14]
    mov eax, [rax]
    cmp rdx, rax
    ja .bad
    mov edx, r13d
    shr edx, 12
    mov esi, ebp
    mov rdi, rbx
    call fpc_slot
    test eax, eax
    js .bad
    mov r15d, eax
    shl rax, 4
    add rax, [rbx+8]
    cmp word [rax+32+2], 0
    je .bad
    mov eax, r13d
    and eax, 4095
    mov edx, 4096
    sub edx, eax
    cmp edx, r14d
    jbe .first_len
    mov edx, r14d
.first_len:
    mov [rsp+36], edx
    mov dword [rsp+32], -1
    cmp edx, r14d
    je .copy
    mov edx, r13d
    shr edx, 12
    inc edx
    mov esi, ebp
    mov rdi, rbx
    call fpc_slot
    test eax, eax
    js .bad
    mov [rsp+32], eax
    shl rax, 4
    add rax, [rbx+8]
    cmp word [rax+32+2], 0
    je .bad
.copy:
    mov esi, r15d
    shl rsi, 12
    add rsi, [rbx+8]
    add rsi, FPC_META
    mov eax, r13d
    and eax, 4095
    add rsi, rax
    mov rdi, r12
    mov edx, [rsp+36]
    call fpc_copy
    sub r14d, [rsp+36]
    jz .good
    mov esi, [rsp+32]
    shl rsi, 12
    add rsi, [rbx+8]
    add rsi, FPC_META
    mov rdi, r12
    mov eax, [rsp+36]
    add rdi, rax
    mov edx, r14d
    call fpc_copy
.good: mov eax, 1
    jmp .out
.bad: xor eax, eax
.out: FPC_LEAVE
; Caller enters/leaves paint explicitly; pure view/cell never change this phase.
fpc_phase:
    xor eax, eax
    test rdi, rdi
    jz .out
    cmp dword [rdi], 1
    jne .out
    cmp dword [rdi+36], 0
    jne .out
    cmp esi, 1
    ja .out
    mov [rdi+32], esi
    mov eax, 1
.out: ret
; Restore ALL English bindings before dropping generation state; refuse wrap.
fpc_epoch:
    FPC_ENTER
    mov rbx, rdi
    call fpc_preparing
    test eax, eax
    jz .bad
    cmp dword [rbx+4], 0xffffffff
    je .bad
    xor ebp, ebp
.unbind:
    mov rdi, rbx
    mov esi, ebp
    call fpc_unbind
    test eax, eax
    jz .bad
    inc ebp
    cmp ebp, 80
    jb .unbind
    mov rdi, [rbx+8]
    xor eax, eax
    mov ecx, FPC_META/8
    cld
    rep stosq
    mov rdi, [rbx+16]
    mov ecx, FPC_USED_CONTROL/8    ; preserve reserved persistent context/margin
    rep stosq
    mov dword [rbx+24], 0
    mov dword [rbx+28], 0
    mov dword [rbx+40], 0
    inc dword [rbx+4]
    mov eax, [rbx+4]
    jmp .out
.bad: xor eax, eax
.out: FPC_LEAVE
