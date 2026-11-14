;; MODULE media/avi_demux_private
;; LAYER 4
;; EXPORTS media_avi_demux_init, media_avi_demux_step, media_avi_demux_frame_at, media_avi_demux_control
;; IMPORTS
;; CAPS
;; OWNER saga:media
; Private UNWIRED port of Classic paos.asm AVI traversal/seek (0cabd75).
; Exact ABI and format references: RCQ-37-S2c1 contract4b0d7e848.
; Context/index are native owned. Read windows are borrowed for one call only.

%define A_STATE 4
%define A_SESS 8
%define A_EPOCH 16
%define A_LEASE 24
%define A_FILE 32
%define A_INDEX 40
%define A_CAP 48
%define A_LIMIT 56
%define A_SELECT 60
%define A_BASE 64
%define A_REASON 68
%define A_JOB 72
%define A_OFF 80
%define A_LEN 88
%define A_PHASE 92
%define A_CTL 96
%define A_MOVI 120
%define A_MEND 128
%define A_IDX 136
%define A_IEND 144
%define A_MC 152
%define A_IC 160
%define A_SEEN 168
%define A_STREAMS 172
%define A_W 176
%define A_H 180
%define A_NS 184
%define A_VIDEO 188
%define A_COUNT 192
%define A_LENGTH 196
%define A_SCALE 200
%define A_RATE 204
%define A_START 208
%define A_KIND 212
%define A_RAW 216
%define A_ID 220
%define A_WALK 224
%define A_DEPTH 228
%define A_TOTAL 232
%define A_CROSS 236
%define A_ORIGIN 240
%define A_SH 352
%define A_SF 356
%define A_STYPE 360
%define A_HANDLER 364
%define A_SSCALE 368
%define A_SRATE 372
%define A_SSTART 376
%define A_SLENGTH 380
%define A_SAMPLE 384
%define A_FLAGS 388
%define A_ORD 392
%define A_CHUNK 400
%define A_PAY 408
%define A_NEXT 416
%define A_SIZE 424
%define A_TAG 428

media_avi_demux_init:
    xor eax, eax
    jmp avi_enter
media_avi_demux_step:
    mov eax, 1
    jmp avi_enter
media_avi_demux_frame_at:
    mov eax, 2
    jmp avi_enter
media_avi_demux_control:
    mov eax, 3
avi_enter:
    pushfq
    cld
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov ebx, eax
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    call avi_preflight
    test eax, eax
    jnz avi_refuse
    test ebx, ebx
    jz avi_init
    cmp dword [r12], 0x31564941
    jne avi_refuse
    mov r15, [r12+A_INDEX]
    cmp ebx, 1
    je avi_step
    cmp ebx, 2
    je avi_frame
    jmp avi_control
avi_refuse:
    mov rax, -1
    jmp avi_exit
avi_ok:
    xor eax, eax
avi_exit:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret

; Fixed <=5 spans, pairwise half-open interval checks. Stack80+return; no I/O.
avi_preflight:
    sub rsp, 80
    mov r8, rsp
    xor r9d, r9d
    mov rax, r12
    mov ecx, 512
    call avi_span
    jc .bad
    mov rax, r14
    mov ecx, 128
    call avi_span
    jc .bad
    test r13, r13
    jnz .input
    cmp ebx, 1
    jne .bad
    jmp .index
.input:
    mov rax, r13
    mov ecx, 64
    cmp ebx, 2
    jae .size
    mov ecx, 96
.size:
    call avi_span
    jc .bad
    cmp dword [r13], 1
    jne .bad
    cmp [r13+4], ecx
    jne .bad
.index:
    mov rax, [r12+A_INDEX]
    mov rcx, [r12+A_CAP]
    mov edx, [r12+A_LIMIT]
    test ebx, ebx
    jnz .icap
    mov rax, [r13+40]
    mov rcx, [r13+48]
    mov edx, [r13+56]
.icap:
    dec edx
    cmp edx, 4095
    ja .bad
    inc edx
    shl rdx, 5
    cmp rcx, rdx
    jne .bad
    call avi_span
    jc .bad
    cmp ebx, 1
    jne .pairs
    test r13, r13
    jz .pairs
    cmp dword [r13+12], 0
    jne .bad
    cmp qword [r13+88], 0
    jne .bad
    mov eax, [r13+8]
    dec eax
    cmp eax, 2
    ja .bad
    test eax, eax
    jnz .nodata
    mov rcx, [r13+80]
    cmp rcx, 64
    ja .bad
    mov rax, [r13+72]
    cmp rax, rcx
    ja .bad
    cmp rax, [r13+56]
    ja .bad
    mov rax, [r13+64]
    call avi_span
    jc .bad
    jmp .pairs
.nodata:
    mov rax, [r13+64]
    or rax, [r13+72]
    or rax, [r13+80]
    jnz .bad
.pairs:
    xor edx, edx
.outer:
    lea ecx, [edx+1]
.inner:
    cmp ecx, r9d
    jae .advance
    mov eax, edx
    shl eax, 4
    mov r10, [rsp+rax]
    mov r11, [rsp+rax+8]
    mov eax, ecx
    shl eax, 4
    cmp r10, [rsp+rax+8]
    jae .apart
    cmp [rsp+rax], r11
    jb .bad
.apart:
    inc ecx
    jmp .inner
.advance:
    inc edx
    cmp edx, r9d
    jb .outer
    xor eax, eax
    add rsp, 80
    ret
.bad:
    mov eax, 1
    add rsp, 80
    ret
avi_span:
    test rax, rax
    jz .bad
    test rcx, rcx
    jz .bad
    mov [r8], rax
    add rax, rcx
    jc .bad
    mov [r8+8], rax
    add r8, 16
    inc r9d
    clc
    ret
.bad:
    stc
    ret

avi_init:
    mov rax, [r13+8]
    test rax, rax
    jz avi_refuse
    cmp qword [r13+16], 0
    je avi_refuse
    cmp qword [r13+24], 0
    je avi_refuse
    cmp qword [r13+32], 12
    jb avi_refuse
    cmp dword [r13+64], 0
    jne avi_refuse
    mov eax, [r13+68]
    dec eax
    cmp eax, 1
    ja avi_refuse
    mov rax, [r13+72]
    or rax, [r13+80]
    or rax, [r13+88]
    jnz avi_refuse
    mov eax, [r13+60]
    cmp eax, -1
    je .zero
    cmp eax, 99
    ja avi_refuse
.zero:
    xor ecx, ecx
.check:
    cmp qword [r12+rcx*8], 0
    jne avi_refuse
    inc ecx
    cmp ecx, 64
    jb .check
    mov dword [r12], 0x31564941
    mov dword [r12+A_STATE], 1
    mov ecx, 6
.copy:
    mov rax, [r13+rcx*8]
    mov [r12+rcx*8], rax
    dec ecx
    jnz .copy
    mov rax, [r13+56]
    mov [r12+56], rax
    mov eax, [r13+68]
    mov [r12+A_BASE], eax
    mov dword [r12+A_VIDEO], -1
    mov r15, [r12+A_INDEX]
    xor eax, eax
    mov ecx, 12
    mov edx, 1
    call avi_request
    jmp avi_emit

avi_step:
    test r13, r13
    jz avi_emit
    ; Full read response identity, no 32-bit truncation.
    mov rax, [r13+16]
    cmp rax, [r12+A_SESS]
    jne avi_refuse
    mov rax, [r13+24]
    cmp rax, [r12+A_EPOCH]
    jne avi_refuse
    mov rax, [r13+32]
    cmp rax, [r12+A_LEASE]
    jne avi_refuse
    mov rax, [r13+40]
    cmp rax, [r12+A_JOB]
    jne avi_refuse
    mov rax, [r13+48]
    cmp rax, [r12+A_OFF]
    jne avi_refuse
    mov eax, [r12+A_LEN]
    test eax, eax
    jz avi_refuse
    cmp rax, [r13+56]
    jne avi_refuse
    cmp dword [r12+A_STATE], 3
    je .cancel
    cmp dword [r12+A_STATE], 1
    jne avi_refuse
    cmp dword [r13+8], 3
    je avi_refuse
    cmp dword [r13+8], 2
    je .io
    cmp [r13+72], rax
    jne .io
    mov rbp, [r13+64]
    mov dword [r12+A_LEN], 0
    call avi_parse
    test eax, eax
    jnz avi_fault
    call avi_next
    test eax, eax
    jnz avi_fault
    jmp avi_emit
.cancel:
    cmp dword [r13+8], 3
    jne avi_refuse
    mov dword [r12+A_LEN], 0
    mov dword [r12+A_STATE], 4
    jmp avi_emit
.io:
    mov eax, 4
avi_fault:
    mov [r12+A_REASON], eax
    mov dword [r12+A_STATE], 5
    mov dword [r12+A_LEN], 0
    jmp avi_emit

avi_frame:
    mov rax, [r13+8]
    cmp rax, [r12+A_SESS]
    jne avi_refuse
    mov rax, [r13+16]
    cmp rax, [r12+A_EPOCH]
    jne avi_refuse
    mov rax, [r13+24]
    cmp rax, [r12+A_LEASE]
    jne avi_refuse
    mov rax, [r13+40]
    or rax, [r13+48]
    or rax, [r13+56]
    jnz avi_refuse
    cmp dword [r12+A_STATE], 2
    jne avi_refuse
    mov rbp, [r13+32]
    mov eax, [r12+A_COUNT]
    cmp rbp, rax
    jae avi_refuse
    jmp avi_emit_frame
avi_control:
    cmp dword [r13+12], 0
    jne avi_refuse
    mov rax, [r13+16]
    cmp rax, [r12+A_SESS]
    jne avi_refuse
    mov rax, [r13+24]
    cmp rax, [r12+A_EPOCH]
    jne avi_refuse
    mov rax, [r13+32]
    cmp rax, [r12+A_LEASE]
    jne avi_refuse
    mov rax, [r13+40]
    cmp rax, [r12+A_CTL]
    jbe avi_refuse
    cmp dword [r13+8], 1
    je .close
    cmp dword [r13+8], 2
    jne avi_refuse
    cmp dword [r12+A_STATE], 2
    jne avi_refuse
    cmp dword [r12+A_LEN], 0
    jne avi_refuse
    mov rbp, [r13+48]
    mov eax, [r12+A_COUNT]
    cmp rbp, rax
    jae avi_refuse
    mov rax, [r12+A_EPOCH]
    add rax, 1
    jc avi_refuse
    cmp rax, [r13+56]
    jne avi_refuse
    mov [r12+A_EPOCH], rax
    mov rax, [r13+40]
    mov [r12+A_CTL], rax
    jmp avi_emit_frame
.close:
    mov rax, [r13+48]
    or rax, [r13+56]
    jnz avi_refuse
    mov rax, [r13+40]
    mov [r12+A_CTL], rax
    mov dword [r12+A_STATE], 4
    cmp dword [r12+A_LEN], 0
    je avi_emit
    mov dword [r12+A_STATE], 3
    jmp avi_emit

avi_result_base:
    mov rdi, r14
    xor eax, eax
    mov ecx, 16
    rep stosq
    mov dword [r14], 1
    mov rax, [r12+A_SESS]
    mov [r14+8], rax
    mov rax, [r12+A_EPOCH]
    mov [r14+16], rax
    mov rax, [r12+A_LEASE]
    mov [r14+24], rax
    ret
avi_format_result:
    mov eax, [r12+A_SCALE]
    mov [r14+96], eax
    mov eax, [r12+A_RATE]
    mov [r14+100], eax
    mov eax, [r12+A_W]
    mov [r14+104], eax
    mov eax, [r12+A_H]
    mov [r14+108], eax
    mov eax, [r12+A_KIND]
    mov [r14+112], eax
    mov eax, [r12+A_VIDEO]
    mov [r14+116], eax
    mov eax, [r12+A_ORIGIN]
    mov [r14+124], eax
    ret
avi_emit:
    call avi_result_base
    mov eax, [r12+A_STATE]
    cmp eax, 1
    je .read
    cmp eax, 3
    je .cancel
    cmp eax, 2
    je .ready
    cmp eax, 4
    je .closed
    mov dword [r14+4], 6
    mov eax, [r12+A_REASON]
    mov [r14+120], eax
    jmp avi_ok
.closed:
    mov dword [r14+4], 5
    jmp avi_ok
.ready:
    mov dword [r14+4], 2
    call avi_format_result
    jmp avi_ok
.cancel:
    mov dword [r14+4], 4
    jmp .job
.read:
    mov dword [r14+4], 1
.job:
    mov rax, [r12+A_JOB]
    mov [r14+32], rax
    mov rax, [r12+A_OFF]
    mov [r14+40], rax
    mov eax, [r12+A_LEN]
    mov [r14+48], rax
    jmp avi_ok
avi_emit_frame:
    call avi_result_base
    call avi_format_result
    mov dword [r14+4], 3
    mov [r14+56], rbp
    shl rbp, 5
    add rbp, r15
    mov rax, [rbp]
    mov [r14+64], rax
    mov eax, [rbp+8]
    mov [r14+72], rax
    mov rax, [rbp+16]
    mov [r14+80], rax
    mov rax, [rbp+24]
    mov [r14+88], rax
    jmp avi_ok

; Request only bounded metadata. Called with offset RAX, length ECX, phase EDX.
avi_request:
    mov r8, rax
    add r8, rcx
    jc avi_corrupt
    cmp r8, [r12+A_FILE]
    ja avi_corrupt
    cmp qword [r12+A_JOB], -1
    je avi_limit
    inc qword [r12+A_JOB]
    mov [r12+A_OFF], rax
    mov [r12+A_LEN], ecx
    mov [r12+A_PHASE], edx
    xor eax, eax
    ret
avi_corrupt:
    mov eax, 1
    ret
avi_unsupported:
    mov eax, 2
    ret
avi_limit:
    mov eax, 3
    ret
avi_good:
    xor eax, eax
    ret

; Parent selection is a fixed three-level stack, no file-dependent recursion.
avi_top:
    mov eax, [r12+A_DEPTH]
    dec eax
    shl eax, 5
    lea r11, [r12+rax+256]
    ret
avi_next:
    cmp dword [r12+A_LEN], 0
    jne avi_good
    cmp qword [r12+A_MOVI], 0
    je .parents
    mov rax, [r12+A_MC]
    cmp rax, [r12+A_MEND]
    jb .movi
    ja avi_corrupt
    mov eax, [r12+A_COUNT]
    cmp eax, [r12+A_LENGTH]
    jne avi_corrupt
    cmp qword [r12+A_IDX], 0
    je .parents
    mov rax, [r12+A_IC]
    cmp rax, [r12+A_IEND]
    jb .idx
    ja avi_corrupt
    mov eax, [r12+A_CROSS]
    cmp eax, [r12+A_COUNT]
    jne avi_corrupt
.parents:
    mov ecx, 3
.unwind:
    cmp dword [r12+A_DEPTH], 0
    je .done
    call avi_top
    mov rax, [r11]
    cmp rax, [r11+8]
    jb .header
    ja avi_corrupt
    cmp dword [r11+16], 3
    jne .pop
    cmp dword [r12+A_SH], 1
    jne avi_corrupt
    cmp dword [r12+A_SF], 1
    jne avi_corrupt
.pop:
    dec dword [r12+A_DEPTH]
    dec ecx
    jnz .unwind
.done:
    mov eax, [r12+A_SEEN]
    and eax, 7
    cmp eax, 7
    jne avi_corrupt
    cmp dword [r12+A_KIND], 0
    je avi_corrupt
    mov eax, [r12+A_NS]
    cmp eax, [r12+A_STREAMS]
    jne avi_corrupt
    mov eax, [r12+A_COUNT]
    cmp eax, [r12+A_LENGTH]
    jne avi_corrupt
    test eax, eax
    jz avi_corrupt
    mov dword [r12+A_ORIGIN], 1
    test dword [r12+A_SEEN], 8
    jz .ready
    mov dword [r12+A_ORIGIN], 2
.ready:
    mov dword [r12+A_STATE], 2
    xor eax, eax
    ret
.header:
    mov r8, rax
    add r8, 8
    jc avi_corrupt
    cmp r8, [r11+8]
    ja avi_corrupt
    mov ecx, 8
    mov edx, 2
    jmp avi_request
.movi:
    mov r8, rax
    add r8, 8
    jc avi_corrupt
    cmp r8, [r12+A_MEND]
    ja avi_corrupt
    mov ecx, 8
    mov edx, 7
    jmp avi_request
.idx:
    mov ecx, 16
    mov edx, 8
    jmp avi_request

; Consumes exactly one requested record. RBP borrowed data (12/8/4/56/40/16).
avi_parse:
    mov eax, [r12+A_PHASE]
    cmp eax, 1
    je avi_riff
    cmp eax, 2
    je avi_header
    cmp eax, 3
    je avi_list
    cmp eax, 4
    je avi_avih
    cmp eax, 5
    je avi_strh
    cmp eax, 6
    je avi_strf
    cmp eax, 7
    je avi_movi
    jmp avi_idx
avi_riff:
    cmp dword [rbp], 'RIFF'
    jne avi_unsupported
    cmp dword [rbp+8], 'AVI '
    jne avi_unsupported
    mov eax, [rbp+4]
    add rax, 8
    cmp rax, [r12+A_FILE]
    jne avi_corrupt
    mov [r12+264], rax
    mov qword [r12+256], 12
    mov dword [r12+272], 1
    mov dword [r12+A_DEPTH], 1
    mov dword [r12+A_WALK], 1
    jmp avi_good

avi_chunk_bounds:
    cmp dword [r12+A_WALK], 16384
    jae avi_limit
    inc dword [r12+A_WALK]
    mov rax, [r12+A_OFF]
    mov [r12+A_CHUNK], rax
    add rax, 8
    jc avi_corrupt
    mov [r12+A_PAY], rax
    mov edx, [rbp+4]
    mov [r12+A_SIZE], edx
    add rax, rdx
    jc avi_corrupt
    mov r10, rax
    and edx, 1
    add rax, rdx
    jc avi_corrupt
    cmp rax, r9
    ja avi_corrupt
    cmp rax, [r12+A_FILE]
    ja avi_corrupt
    mov [r12+A_NEXT], rax
    mov edx, [rbp]
    mov [r12+A_TAG], edx
    xor eax, eax
    ret
avi_header:
    call avi_top
    mov r9, [r11+8]
    call avi_chunk_bounds
    test eax, eax
    jnz .ret
    mov rax, [r12+A_NEXT]
    mov [r11], rax
    mov eax, [r12+A_TAG]
    cmp eax, 'LIST'
    je .list
    cmp eax, 'avih'
    je .avih
    cmp eax, 'strh'
    je .strh
    cmp eax, 'strf'
    je .strf
    cmp eax, 'idx1'
    je .idx
    cmp eax, 'RIFF'
    je avi_unsupported
    jmp avi_good
.list:
    cmp dword [r12+A_SIZE], 4
    jb avi_corrupt
    mov rax, [r12+A_PAY]
    mov ecx, 4
    mov edx, 3
    jmp avi_request
.avih:
    cmp dword [r11+16], 2
    jne avi_corrupt
    test dword [r12+A_SEEN], 2
    jnz avi_corrupt
    cmp dword [r12+A_NS], 0
    jne avi_corrupt
    cmp dword [r12+A_SIZE], 56
    jne avi_corrupt
    mov edx, 4
    jmp .body56
.strh:
    cmp dword [r11+16], 3
    jne avi_corrupt
    cmp dword [r12+A_SH], 0
    jne avi_corrupt
    cmp dword [r12+A_SIZE], 56
    jne avi_corrupt
    mov edx, 5
.body56:
    mov rax, [r12+A_PAY]
    mov ecx, 56
    jmp avi_request
.strf:
    cmp dword [r11+16], 3
    jne avi_corrupt
    cmp dword [r12+A_SH], 1
    jne avi_corrupt
    cmp dword [r12+A_SF], 0
    jne avi_corrupt
    cmp dword [r12+A_STYPE], 'vids'
    jne .audiofmt
    cmp dword [r12+A_SIZE], 40
    jne avi_unsupported
    mov rax, [r12+A_PAY]
    mov ecx, 40
    mov edx, 6
    jmp avi_request
.audiofmt:
    mov dword [r12+A_SF], 1
    jmp avi_good
.idx:
    cmp dword [r11+16], 1
    jne avi_corrupt
    test dword [r12+A_SEEN], 4
    jz avi_corrupt
    test dword [r12+A_SEEN], 8
    jnz avi_corrupt
    mov eax, [r12+A_SIZE]
    test eax, 15
    jnz avi_corrupt
    shr eax, 4
    test eax, eax
    jz avi_corrupt
    cmp eax, 4096
    ja avi_limit
    or dword [r12+A_SEEN], 8
    mov rax, [r12+A_PAY]
    mov [r12+A_IDX], rax
    mov [r12+A_IC], rax
    mov [r12+A_IEND], r10
    jmp avi_good
.ret:
    ret

avi_list:
    call avi_top
    mov eax, [rbp]
    cmp eax, 'hdrl'
    je .hdrl
    cmp eax, 'strl'
    je .strl
    cmp eax, 'movi'
    je .movi
    cmp eax, 'rec '
    je avi_unsupported
    jmp avi_good
.hdrl:
    cmp dword [r11+16], 1
    jne avi_corrupt
    cmp dword [r12+A_SEEN], 0
    jne avi_corrupt
    or dword [r12+A_SEEN], 1
    mov edx, 2
    jmp .push
.strl:
    cmp dword [r11+16], 2
    jne avi_corrupt
    test dword [r12+A_SEEN], 2
    jz avi_corrupt
    mov eax, [r12+A_NS]
    cmp eax, 100
    jae avi_limit
    mov [r12+A_ORD], eax
    inc dword [r12+A_NS]
    mov dword [r12+A_SH], 0
    mov dword [r12+A_SF], 0
    mov edx, 3
.push:
    cmp dword [r12+A_DEPTH], 3
    jae avi_limit
    inc dword [r12+A_DEPTH]
    call avi_top
    mov rax, [r12+A_PAY]
    add rax, 4
    mov [r11], rax
    mov eax, [r12+A_SIZE]
    add rax, [r12+A_PAY]
    mov [r11+8], rax
    mov [r11+16], edx
    jmp avi_good
.movi:
    cmp dword [r11+16], 1
    jne avi_corrupt
    mov eax, [r12+A_SEEN]
    and eax, 7
    cmp eax, 3
    jne avi_corrupt
    cmp dword [r12+A_KIND], 0
    je avi_corrupt
    mov eax, [r12+A_NS]
    cmp eax, [r12+A_STREAMS]
    jne avi_corrupt
    mov eax, [r12+A_TOTAL]
    cmp eax, [r12+A_LENGTH]
    jne avi_corrupt
    or dword [r12+A_SEEN], 4
    mov rax, [r12+A_PAY]
    mov [r12+A_MOVI], rax
    lea rcx, [rax+4]
    mov [r12+A_MC], rcx
    mov ecx, [r12+A_SIZE]
    add rax, rcx
    mov [r12+A_MEND], rax
    jmp avi_good

avi_avih:
    mov eax, [rbp+12]
    test eax, ~0x110
    jnz avi_unsupported
    mov rax, [rbp+40]
    or rax, [rbp+48]
    jnz avi_unsupported
    mov eax, [rbp+24]
    dec eax
    cmp eax, 99
    ja avi_unsupported
    inc eax
    mov [r12+A_STREAMS], eax
    mov eax, [rbp+32]
    dec eax
    cmp eax, 639
    ja avi_unsupported
    inc eax
    mov [r12+A_W], eax
    mov eax, [rbp+36]
    dec eax
    cmp eax, 359
    ja avi_unsupported
    inc eax
    mov [r12+A_H], eax
    mov eax, [rbp+16]
    mov [r12+A_TOTAL], eax
    or dword [r12+A_SEEN], 2
    jmp avi_good
avi_strh:
    cmp qword [rbp+8], 0
    jne avi_unsupported
    cmp dword [rbp+16], 0
    jne avi_unsupported
    mov eax, [rbp]
    cmp eax, 'vids'
    je .video
    cmp eax, 'auds'
    jne avi_unsupported
    jmp .copy
.video:
    cmp dword [r12+A_VIDEO], -1
    jne avi_unsupported
    mov eax, [r12+A_ORD]
    cmp dword [r12+A_SELECT], -1
    je .selected
    cmp eax, [r12+A_SELECT]
    jne avi_unsupported
.selected:
    mov [r12+A_VIDEO], eax
    mov eax, [rbp+20]
    test eax, eax
    jz avi_unsupported
    mov ecx, [rbp+24]
    test ecx, ecx
    jz avi_unsupported
    imul rax, rax, 30
    cmp rcx, rax
    ja avi_unsupported
    cmp dword [rbp+28], 0
    jl avi_unsupported
    mov eax, [rbp+32]
    dec eax
    cmp eax, 4095
    ja avi_limit
    cmp dword [rbp+44], 0
    jne avi_unsupported
    cmp qword [rbp+48], 0
    jne avi_unsupported
.copy:
    mov eax, [rbp]
    mov [r12+A_STYPE], eax
    mov eax, [rbp+4]
    mov [r12+A_HANDLER], eax
    mov eax, [rbp+20]
    mov [r12+A_SSCALE], eax
    mov eax, [rbp+24]
    mov [r12+A_SRATE], eax
    mov eax, [rbp+28]
    mov [r12+A_SSTART], eax
    mov eax, [rbp+32]
    mov [r12+A_SLENGTH], eax
    mov eax, [rbp+44]
    mov [r12+A_SAMPLE], eax
    mov dword [r12+A_SH], 1
    jmp avi_good
avi_strf:
    cmp dword [rbp], 40
    jne avi_unsupported
    cmp word [rbp+12], 1
    jne avi_unsupported
    mov rax, [rbp+24]
    or rax, [rbp+32]
    jnz avi_unsupported
    mov eax, [rbp+4]
    cmp eax, [r12+A_W]
    jne avi_corrupt
    mov ecx, [rbp+8]
    mov edx, [r12+A_H]
    mov eax, [rbp+16]
    test eax, eax
    jz .raw
    cmp eax, 'MJPG'
    jne avi_unsupported
    cmp dword [r12+A_HANDLER], 'MJPG'
    jne avi_unsupported
    cmp ecx, edx
    jne avi_corrupt
    cmp word [rbp+14], 24
    jne avi_unsupported
    cmp dword [rbp+20], 524288
    ja avi_unsupported
    mov dword [r12+A_KIND], 1
    mov r8d, '00dc'
    jmp .timing
.raw:
    mov eax, [r12+A_HANDLER]
    test eax, eax
    jz .rawfmt
    cmp eax, 'DIB '
    jne avi_unsupported
.rawfmt:
    neg edx
    cmp ecx, edx
    jne avi_unsupported
    cmp word [rbp+14], 32
    jne avi_unsupported
    mov eax, [r12+A_W]
    imul eax, [r12+A_H]
    shl eax, 2
    mov [r12+A_RAW], eax
    cmp dword [rbp+20], 0
    je .rawok
    cmp [rbp+20], eax
    jne avi_corrupt
.rawok:
    mov dword [r12+A_KIND], 2
    mov r8d, '00db'
.timing:
    mov eax, [r12+A_VIDEO]
    xor edx, edx
    mov ecx, 10
    div ecx
    add al, '0'
    add dl, '0'
    mov r8b, al
    shl edx, 8
    and r8d, 0xFFFF00FF
    or r8d, edx
    mov [r12+A_ID], r8d
    mov eax, [r12+A_SSCALE]
    mov [r12+A_SCALE], eax
    mov eax, [r12+A_SRATE]
    mov [r12+A_RATE], eax
    mov eax, [r12+A_SSTART]
    mov [r12+A_START], eax
    mov eax, [r12+A_SLENGTH]
    mov [r12+A_LENGTH], eax
    mov dword [r12+A_SF], 1
    jmp avi_good

; Recognized ignored audio tag NNwb with stream index existing and nonselected.
avi_audio_tag:
    mov edx, eax
    shr edx, 16
    cmp dx, 'wb'
    jne avi_unsupported
    mov edx, eax
    and edx, 255
    sub edx, '0'
    cmp edx, 9
    ja avi_unsupported
    shr eax, 8
    and eax, 255
    sub eax, '0'
    cmp eax, 9
    ja avi_unsupported
    imul edx, edx, 10
    add eax, edx
    cmp eax, [r12+A_NS]
    jae avi_corrupt
    cmp eax, [r12+A_VIDEO]
    je avi_unsupported
    jmp avi_good
avi_movi:
    mov r9, [r12+A_MEND]
    call avi_chunk_bounds
    test eax, eax
    jnz .ret
    mov rax, [r12+A_NEXT]
    mov [r12+A_MC], rax
    mov eax, [r12+A_TAG]
    cmp eax, [r12+A_ID]
    je .frame
    cmp eax, 'JUNK'
    je avi_good
    jmp avi_audio_tag
.frame:
    mov eax, [r12+A_COUNT]
    cmp eax, [r12+A_LIMIT]
    jae avi_limit
    cmp eax, [r12+A_LENGTH]
    jae avi_corrupt
    mov ecx, [r12+A_SIZE]
    cmp dword [r12+A_KIND], 2
    je .raw
    test ecx, ecx
    jz avi_corrupt
    cmp ecx, 524288
    ja avi_unsupported
    jmp .append
.raw:
    cmp ecx, [r12+A_RAW]
    jne avi_corrupt
.append:
    mov edx, eax
    shl edx, 5
    add rdx, r15
    mov r8, [r12+A_PAY]
    mov [rdx], r8
    mov [rdx+8], ecx
    mov dword [rdx+12], 0
    mov r8d, [r12+A_START]
    add rax, r8
    mov [rdx+16], rax
    mov qword [rdx+24], 1
    inc dword [r12+A_COUNT]
    jmp avi_good
.ret:
    ret
avi_idx:
    test dword [rbp+4], ~0x10
    jnz avi_unsupported
    mov eax, [rbp]
    cmp eax, [r12+A_ID]
    je .selected
    call avi_audio_tag
    test eax, eax
    jnz .ret
    jmp .advance
.selected:
    mov eax, [r12+A_CROSS]
    cmp eax, [r12+A_COUNT]
    jae avi_corrupt
    shl eax, 5
    add rax, r15
    mov ecx, [rbp+12]
    cmp ecx, [rax+8]
    jne avi_corrupt
    mov edx, [rbp+8]
    cmp dword [r12+A_BASE], 1
    jne .absolute
    add rdx, [r12+A_MOVI]
    jc avi_corrupt
.absolute:
    add rdx, 8
    jc avi_corrupt
    cmp rdx, [rax]
    jne avi_corrupt
    inc dword [r12+A_CROSS]
.advance:
    add qword [r12+A_IC], 16
    jmp avi_good
.ret:
    ret
