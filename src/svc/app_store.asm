;; MODULE svc/app_store
;; LAYER 5
;; EXPORTS app_store_list, app_store_snapshot
;; IMPORTS fs/app_store_data, fs/app_store_layout, fs/data_config_provider, sec/app_store_seal, sec/session, core/smp, core/heap, core/lib/mem, core/lib/sha256
;; CAPS
;; OWNER saga:command
;; CONTEXT: bsp_only
; Native OWNER observations only. No writer, guest API, deletion authority,
; cached pointer export or success fallback for the captain-owned real seal.
%include "fs/app_store_layout.inc"

asp_code_begin:
; RDI ordinal0..15, RSI out256, RDX exactly256, RCX expected generation.
; Expected0 only ordinal0. EAX1 row/RDXgen,2 end/RDXgen,3 unavailable/RDX0,
; 0 refused/stale/RDX0. Only1 writes output. ANY REMOVING makes list3.
app_store_list:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    cld
    mov r12, rdi
    mov r13, rsi
    mov r14, rcx
    cmp r12, 15
    ja .refused
    cmp rdx, 256
    jne .refused
    test r14, r14
    jnz .args
    test r12, r12
    jnz .refused
.args:
    call asp_enter
    test eax, eax
    jz .refused
    mov rdi, r13
    mov esi, 256
    call asp_output
    test eax, eax
    jz .release_refused
    call asp_load
    cmp eax, 1
    jne .unavailable
    ; Allocation happened during load: recheck its entire span before output.
    mov rdi, r13
    mov esi, 256
    call asp_output
    test eax, eax
    jz .release_refused
    mov rbx, [rel asp_cache]
    mov r15, [rbx + ASL_GENERATION]
    test r14, r14
    jz .select
    cmp r14, r15
    jne .release_refused
.select:
    lea rbp, [rbx + ASL_HEADER]
    mov ebx, ASL_SLOTS
.denial:
    ; Captain92368: interrupted removal is unavailable, never empty/Removed.
    ; Native snapshot remains authenticated1 for recovery composition.
    cmp dword [rbp + ASL_STATE], ASL_REMOVING
    je .unavailable
    add rbp, ASL_SLOT_BYTES
    dec ebx
    jnz .denial
    mov rbx, [rel asp_cache]
    lea rbp, [rbx + ASL_HEADER]
    mov ebx, ASL_SLOTS
.scan:
    cmp dword [rbp + ASL_STATE], ASL_LIVE
    jne .next
    test r12, r12
    jz .row
    dec r12
.next:
    add rbp, ASL_SLOT_BYTES
    dec ebx
    jnz .scan
    mov ebx, 2
    jmp .publish
.row:
    lea rdi, [rel asp_row]
    xor esi, esi
    mov edx, 256
    call memset
    mov qword [rel asp_row], 1
    mov [rel asp_row + 8], r15
    mov rax, [rbp + ASL_ID]
    mov [rel asp_row + 16], rax
    lea rdi, [rel asp_row + 24]
    lea rsi, [rbp + ASL_DIGEST]
    mov edx, 160                 ; digest32 + bundle ID64 + display64
    call memcpy
    mov ebx, 1
.publish:
    call asp_final
    test eax, eax
    jz .unavailable
    cmp ebx, 1
    jne .end
    mov rdi, r13
    lea rsi, [rel asp_row]
    mov edx, 256
    call memcpy
.end:
    mov eax, ebx
    mov rdx, r15
    jmp .release
.unavailable:
    call asp_current
    test eax, eax
    jz .release_refused
    mov eax, 3
    xor edx, edx
    jmp .release
.release_refused:
    xor eax, eax
    xor edx, edx
.release:
    mov byte [rel asp_busy], 0
    jmp .out
.refused:
    xor eax, eax
    xor edx, edx
.out:
    cld
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; RDI out1MiB, RSI exactly1MiB, RDX outtoken112, RCX outlength8.
; EAX1 authentic image copied,2 confirmed absent,0 refused/unavailable/corrupt.
; Only1 writes ANY output. Caller owns the independent copies/lifetime.
app_store_snapshot:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    cld
    mov r12, rdi
    mov r13, rdx
    mov r14, rcx
    cmp rsi, ASL_MAX
    jne .refused
    call asp_enter
    test eax, eax
    jz .refused
    call asp_snapshot_outputs
    test eax, eax
    jz .release_refused
    call asp_load
    mov ebx, eax
    test eax, eax
    jz .release_refused
    call asp_snapshot_outputs
    test eax, eax
    jz .release_refused
    call asp_final
    test eax, eax
    jz .release_refused
    cmp ebx, 2
    je .absent
    mov rdi, r12
    mov rsi, [rel asp_cache]
    mov rdx, [rel asp_length]
    call memcpy
    mov rdi, r13
    lea rsi, [rel asp_token]
    mov edx, 112
    call memcpy
    mov rax, [rel asp_length]
    mov [r14], rax
    mov eax, 1
    jmp .release
.absent:
    mov eax, 2
    jmp .release
.release_refused:
    xor eax, eax
.release:
    mov byte [rel asp_busy], 0
    jmp .out
.refused:
    xor eax, eax
.out:
    cld
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; All calls run without yielding on local BSP, depth0, keyed OWNER.
asp_local:
    sub rsp, 8
    cmp dword [rel cmd_dispatch_depth], 0
    jne .no
    call smp_current_logical
    test eax, eax
    jnz .no
    call session_shell_local_authority
    cmp rax, PRIN_OWNER
    jne .no
    test rdx, rdx
    jz .no
    cmp rdx, -1
    je .no
    mov eax, 1
    jmp .out
.no:
    xor eax, eax
.out:
    add rsp, 8
    ret
asp_enter:
    sub rsp, 8
    call asp_local
    test eax, eax
    jz .out
    mov al, 1
    xchg al, [rel asp_busy]
    test al, al
    jnz .no
    mov [rel asp_epoch], rdx
    mov eax, 1
    jmp .out
.no:
    xor eax, eax
.out:
    add rsp, 8
    ret
asp_current:
    sub rsp, 8
    call asp_local
    test eax, eax
    jz .out
    cmp rdx, [rel asp_epoch]
    jne .no
    mov eax, 1
    jmp .out
.no:
    xor eax, eax
.out:
    add rsp, 8
    ret
asp_final:
    sub rsp, 8
    lea rdi, [rel asp_token]
    call data_config_current      ; revalidate the canonical sealed DATA role
    test rax, rax
    jnz .no
    add rsp, 8
    jmp asp_current
.no:
    xor eax, eax
    add rsp, 8
    ret

; Fresh transport + structural bounds + current-owner seal + every occupied
; digest, including REMOVING. Nothing from an earlier read can be published.
; ->1 authenticated/2 absent/0 unavailable. Real seal remains link dependency.
asp_load:
    push rbx
    push rbp
    sub rsp, 8
    mov qword [rel asp_length], 0
    cmp qword [rel asp_cache], 0
    jne .allocated
    mov edi, ASL_MAX
    call kmalloc
    test rax, rax
    jz .no
    mov [rel asp_cache], rax
.allocated:
    lea rdi, [rel asp_token]
    call app_store_data_bind
    cmp eax, 1
    jne .no
    lea rdi, [rel asp_token]
    mov rsi, [rel asp_cache]
    mov edx, ASL_MAX
    call app_store_data_read
    cmp rax, -4
    je .absent
    cmp rax, ASL_PAYLOAD
    jb .no
    cmp rax, ASL_MAX
    ja .no
    mov [rel asp_length], rax
    mov rdi, [rel asp_cache]
    mov rsi, rax
    call app_store_layout_check
    cmp eax, 1
    jne .no
    mov rdi, [rel asp_cache]
    mov rsi, [rel asp_length]
    call app_store_seal_open
    cmp eax, 1
    jne .no
    mov rbp, [rel asp_cache]
    add rbp, ASL_HEADER
    mov ebx, ASL_SLOTS
.hash:
    cmp dword [rbp + ASL_STATE], 0
    je .next
    lea rdi, [rel asp_hash]
    mov rsi, [rel asp_cache]
    add rsi, [rbp + ASL_OFFSET]
    mov rdx, [rbp + ASL_LENGTH]
    call sha256_hash
    test rax, rax
    jnz .no
    lea rdi, [rel asp_hash]
    lea rsi, [rbp + ASL_DIGEST]
    mov edx, 32
    call memcmp
    test rax, rax
    jnz .no
.next:
    add rbp, ASL_SLOT_BYTES
    dec ebx
    jnz .hash
    call asp_final
    test eax, eax
    jz .no
    mov eax, 1
    jmp .out
.absent:
    call asp_final
    test eax, eax
    jz .no
    mov eax, 2
    jmp .out
.no:
    xor eax, eax
.out:
    add rsp, 8
    pop rbp
    pop rbx
    ret

; RDI output, RSI nonzero span. Require canonical endpoints in same half,
; no wrap and no overlap with this module's code/data or full allocated cache.
; R8 is exclusive end on success; outputs are never dereferenced here.
asp_output:
    test rdi, rdi
    jz .no
    mov r8, rdi
    add r8, rsi
    jc .no
    mov rax, rdi
    shl rax, 16
    sar rax, 16
    cmp rax, rdi
    jne .no
    lea r9, [r8 - 1]
    mov rax, r9
    shl rax, 16
    sar rax, 16
    cmp rax, r9
    jne .no
    xor r9, rdi
    bt r9, 47
    jc .no
    lea rax, [rel asp_code_begin]
    cmp r8, rax
    jbe .data
    lea rax, [rel asp_code_end]
    cmp rdi, rax
    jb .no
.data:
    lea rax, [rel asp_data_begin]
    cmp r8, rax
    jbe .cache
    lea rax, [rel asp_data_end]
    cmp rdi, rax
    jb .no
.cache:
    mov rax, [rel asp_cache]
    test rax, rax
    jz .yes
    cmp r8, rax
    jbe .yes
    add rax, ASL_MAX
    cmp rdi, rax
    jb .no
.yes:
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; R12 image span1MiB, R13 token112, R14 length8. Validate whole capacities,
; pairwise disjoint even if an output would fit the current shorter record.
asp_snapshot_outputs:
    sub rsp, 8
    mov rdi, r12
    mov esi, ASL_MAX
    call asp_output
    test eax, eax
    jz .out
    mov r15, r8
    mov rdi, r13
    mov esi, 112
    call asp_output
    test eax, eax
    jz .out
    cmp r8, r12
    jbe .token_ok
    cmp r13, r15
    jb .no
.token_ok:
    mov rdi, r14
    mov esi, 8
    call asp_output
    test eax, eax
    jz .out
    cmp r8, r12
    jbe .length_image_ok
    cmp r14, r15
    jb .no
.length_image_ok:
    cmp r8, r13
    jbe .yes
    lea rax, [r13 + 112]
    cmp r14, rax
    jb .no
.yes:
    mov eax, 1
.out:
    add rsp, 8
    ret
.no:
    xor eax, eax
    add rsp, 8
    ret
asp_code_end:

%include "core/abi/wdata.inc"
%macro WDATA_BSS_svc_app_store 0
alignb 8
asp_data_begin:
asp_cache: resq 1
asp_epoch: resq 1
asp_length: resq 1
asp_token: resb 112
asp_hash: resb 32
asp_row: resb 256
asp_busy: resb 1
asp_data_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_svc_app_store
