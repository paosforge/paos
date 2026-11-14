;; MODULE media/flac_primitives
;; LAYER 4
;; EXPORTS media_flac_read_bits, media_flac_read_signed, media_flac_read_unary, media_flac_simple, media_flac_residual, media_flac_fixed, media_flac_lpc, media_flac_decorrelate
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
;
; Native Classic0cab bit/Rice/escape/FIXED/LPC/stereo math port. Private UNWIRED
; primitives, NOT a frame/file decoder. No allocator, globals, CRC or audio sink.
; Trusted mapped stable context and truthful mapped buffer spans for whole call.
; Every active declared span is disjoint from context and every other active
; span. Only caller scratch may change on refusal; destination and entire
; context stay unchanged. Scratch is unpublished until status0; stale outputs
; never imply success. Input/source/coefficients are immutable.
; Status0 success, -1 invalid/EOF/overflow/capacity, -4 byte/count/bit-work limit.
; SysV RBX/RBP/R12..R15/RSP preserved; ordinary volatile GPRs/flags clobbered.

FLACP_MAX_BYTES equ 16*1024*1024
FLACP_MAX_SAMPLES equ 16384
FLACP_MAX_BITS equ 1048576
FLACP_MAX_UNARY equ 65535

struc media_flac_work
    .src:           resq 1
    .src_bytes:     resq 1
    .bitpos:        resq 1
    .budget:        resq 1
    .input:         resq 1
    .input_bytes:   resq 1
    .other:         resq 1
    .other_bytes:   resq 1
    .dst:           resq 1
    .dst_bytes:     resq 1
    .scratch:       resq 1
    .scratch_bytes: resq 1
    .count:         resd 1
    .param:         resd 1
    .width:         resd 1
    .shift:         resd 1
    .result:        resq 1
endstruc

; RDI=120-byte work. Reader ESI=bit count0..32, signed1..32, or unary maximum
; zeros0..65535. Source is MSB-first. Only bitpos/budget/result publish on success.
media_flac_read_bits:
    mov edx, esi
    xor esi, esi
    jmp flacp_run
media_flac_read_signed:
    mov edx, esi
    mov esi, 1
    jmp flacp_run
media_flac_read_unary:
    mov edx, esi
    mov esi, 2
    jmp flacp_run

; Simple: param0 constant,1 verbatim; width1..32, count1..16384; signed int32.
media_flac_simple:
    mov esi, 3
    jmp flacp_run
; Residual: count=whole block, param=predictor order0..32 <=count. Decode
; method0/1 and partitions; write dst[param..count), preserving warmup prefix.
; result=count-param. Escape width0 produces zeros. Rice result must fit uint32
; before signed zigzag; bounded unary quotient, no masked shift/truncation.
media_flac_residual:
    mov esi, 4
    jmp flacp_run
; FIXED/LPC: input[count] contains warmups then residuals, dst[count] output.
; FIXED param0..4; LPC param1..32, other[param] signed int32 coefficients,
; shift -16..15 (negative means checked multiplication by power of two).
; Intermediate sums checked in int64, final samples must fit signed int32.
media_flac_fixed:
    mov esi, 5
    jmp flacp_run
media_flac_lpc:
    mov esi, 6
    jmp flacp_run
; Stereo: input[count], other[count] planar int32 -> dst[2*count] interleaved.
; param1 independent,8 left-side,9 right-side,10 mid-side. Inputs and output
; are int32; a 33-bit side-channel representation is outside this private seam.
media_flac_decorrelate:
    mov esi, 7

flacp_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 312
    test rdi, rdi
    jz .invalid
    mov rax, rdi
    add rax, media_flac_work_size
    jc .invalid
    mov rbp, rdi
    mov r12, rsp                    ; transaction-local context
    mov [r12+120], esi              ; operation
    mov [r12+124], edx              ; scalar reader argument
    mov dword [r12+128], 0          ; number of active spans
    mov dword [r12+132], 0          ; first output dword
    mov dword [r12+136], 0          ; output dwords
    xor ecx, ecx
.snapshot:
    mov rax, [rbp+rcx*8]
    mov [r12+rcx*8], rax
    inc ecx
    cmp ecx, 15
    jb .snapshot
    cmp esi, 4
    ja .block_fields
    cmp qword [r12+media_flac_work.src_bytes], FLACP_MAX_BYTES
    ja .limit
    cmp qword [r12+media_flac_work.budget], FLACP_MAX_BITS
    ja .limit
    mov rax, [r12+media_flac_work.src_bytes]
    shl rax, 3
    cmp [r12+media_flac_work.bitpos], rax
    ja .invalid
    mov rsi, [r12+media_flac_work.src]
    mov rdx, [r12+media_flac_work.src_bytes]
    call flacp_span
    jc .error
    mov eax, [r12+120]
    cmp eax, 2
    ja .block_fields
    mov ecx, [r12+124]
    cmp eax, 2
    je .unary
    cmp ecx, 32
    ja .invalid
    test eax, eax
    jz .bits
    test ecx, ecx
    jz .invalid
    call flacp_signed
    jmp .reader_result
.bits:
    call flacp_bits
    jmp .reader_result
.unary:
    cmp ecx, FLACP_MAX_UNARY
    ja .limit
    call flacp_unary
.reader_result:
    jc .error
    mov [r12+media_flac_work.result], rax
    jmp .commit

.block_fields:
    mov eax, [r12+media_flac_work.count]
    test eax, eax
    jz .invalid
    cmp eax, FLACP_MAX_SAMPLES
    ja .limit
    mov r14d, eax
    shl r14, 2
    mov ecx, [r12+media_flac_work.param]
    mov edx, [r12+120]
    cmp edx, 3
    je .simple_fields
    cmp edx, 7
    je .stereo_fields
    cmp ecx, eax
    ja .invalid
    cmp edx, 5
    je .fixed_fields
    cmp ecx, 32
    ja .invalid
    cmp edx, 4
    je .output_spans
    test ecx, ecx
    jz .invalid
    cmp dword [r12+media_flac_work.shift], -16
    jl .invalid
    cmp dword [r12+media_flac_work.shift], 15
    jg .invalid
    jmp .input_span
.fixed_fields:
    cmp ecx, 4
    ja .invalid
    jmp .input_span
.simple_fields:
    cmp ecx, 1
    ja .invalid
    mov eax, [r12+media_flac_work.width]
    test eax, eax
    jz .invalid
    cmp eax, 32
    ja .invalid
    jmp .output_spans
.stereo_fields:
    cmp ecx, 1
    je .input_span
    cmp ecx, 8
    jb .invalid
    cmp ecx, 10
    ja .invalid
.input_span:
    mov rsi, [r12+media_flac_work.input]
    mov rdx, [r12+media_flac_work.input_bytes]
    cmp rdx, r14
    jb .invalid
    call flacp_span
    jc .error
    cmp dword [r12+120], 5
    je .output_spans
    mov eax, [r12+media_flac_work.param]
    shl rax, 2
    cmp dword [r12+120], 7
    jne .other_need
    mov rax, r14
.other_need:
    mov rsi, [r12+media_flac_work.other]
    mov rdx, [r12+media_flac_work.other_bytes]
    cmp rdx, rax
    jb .invalid
    call flacp_span
    jc .error
    cmp dword [r12+120], 7
    jne .output_spans
    shl r14, 1
.output_spans:
    mov rsi, [r12+media_flac_work.dst]
    mov rdx, [r12+media_flac_work.dst_bytes]
    cmp rdx, r14
    jb .invalid
    call flacp_span
    jc .error
    mov rsi, [r12+media_flac_work.scratch]
    mov rdx, [r12+media_flac_work.scratch_bytes]
    cmp rdx, r14
    jb .invalid
    call flacp_span
    jc .error
    mov r15, [r12+media_flac_work.scratch]
    mov eax, [r12+120]
    cmp eax, 3
    je .simple
    cmp eax, 4
    je .residual
    cmp eax, 7
    je .stereo
    jmp .reconstruct

.simple:
    xor r13d, r13d
    mov ecx, [r12+media_flac_work.width]
    cmp dword [r12+media_flac_work.param], 0
    jne .verbatim
    call flacp_signed
    jc .error
    mov r14d, eax
.constant_loop:
    mov [r15+r13*4], r14d
    inc r13d
    cmp r13d, [r12+media_flac_work.count]
    jb .constant_loop
    jmp .block_done
.verbatim:
    mov ecx, [r12+media_flac_work.width]
    call flacp_signed
    jc .error
    mov [r15+r13*4], eax
    inc r13d
    cmp r13d, [r12+media_flac_work.count]
    jb .verbatim
    jmp .block_done

.residual:
    mov dword [r12+252], 0          ; Rice/escape selection
    mov eax, [r12+media_flac_work.param]
    mov [r12+132], eax
    mov [r12+248], eax              ; output index
    mov ecx, 2
    call flacp_bits
    jc .error
    cmp eax, 1
    ja .invalid
    add eax, 4
    mov [r12+232], eax              ; Rice parameter bits
    mov ecx, 4
    call flacp_bits
    jc .error
    mov ecx, eax
    mov r14d, 1
    shl r14d, cl
    mov [r12+224], r14d             ; partition count
    mov eax, [r12+media_flac_work.count]
    xor edx, edx
    div r14d
    test edx, edx
    jnz .invalid                    ; partitions must divide block exactly
    cmp eax, [r12+media_flac_work.param]
    jb .invalid
    mov [r12+228], eax              ; samples per partition
    mov dword [r12+236], 0          ; partition index
.partition:
    mov eax, [r12+236]
    cmp eax, [r12+224]
    jae .residual_done
    mov edx, [r12+228]
    test eax, eax
    jnz .partition_count
    sub edx, [r12+media_flac_work.param]
.partition_count:
    mov [r12+240], edx
    mov ecx, [r12+232]
    call flacp_bits
    jc .error
    mov [r12+244], eax
    mov ecx, [r12+232]
    mov edx, 1
    shl edx, cl
    dec edx
    cmp eax, edx
    je .escape
.rice_loop:
    cmp dword [r12+240], 0
    je .next_partition
    mov ecx, FLACP_MAX_UNARY
    call flacp_unary
    jc .error
    mov r13, rax
    mov ecx, [r12+244]
    call flacp_bits
    jc .error
    mov ecx, [r12+244]
    shl r13, cl
    or r13, rax
    mov rax, r13
    shr rax, 32
    jnz .invalid                    ; refuse Rice uint32 overflow
    mov eax, r13d
    shr eax, 1
    mov edx, r13d
    and edx, 1
    neg edx
    xor eax, edx                    ; Classic zigzag, after checked widening
    jmp .store_residual
.escape:
    mov dword [r12+252], 1
    mov ecx, 5
    call flacp_bits
    jc .error
    mov [r12+244], eax
.escape_loop:
    cmp dword [r12+240], 0
    je .next_partition
    mov ecx, [r12+244]
    call flacp_signed               ; width0 is the defined zero residual
    jc .error
.store_residual:
    mov ecx, [r12+248]
    mov [r15+rcx*4], eax
    inc dword [r12+248]
    dec dword [r12+240]
    ; Preserve escape selection independently of the raw width now in244.
    cmp dword [r12+252], 1
    je .escape_loop
    jmp .rice_loop
.next_partition:
    inc dword [r12+236]
    mov dword [r12+252], 0
    jmp .partition
.residual_done:
    mov eax, [r12+media_flac_work.count]
    sub eax, [r12+media_flac_work.param]
    mov [r12+136], eax
    mov [r12+media_flac_work.result], rax
    jmp .commit

.reconstruct:
    mov r13, [r12+media_flac_work.input]
    xor r14d, r14d
.warmup:
    cmp r14d, [r12+media_flac_work.param]
    jae .prediction
    mov eax, [r13+r14*4]
    mov [r15+r14*4], eax
    inc r14d
    jmp .warmup
.prediction:
    cmp r14d, [r12+media_flac_work.count]
    jae .block_done
    cmp dword [r12+120], 6
    je .lpc
    lea rcx, [r15+r14*4]
    mov edx, [r12+media_flac_work.param]
    xor eax, eax
    test edx, edx
    jz .add_residual
    movsxd rax, dword [rcx-4]
    cmp edx, 1
    je .add_residual
    cmp edx, 2
    je .fixed2
    cmp edx, 3
    je .fixed3
    imul rax, 4
    movsxd rdx, dword [rcx-8]
    imul rdx, 6
    sub rax, rdx
    movsxd rdx, dword [rcx-12]
    imul rdx, 4
    add rax, rdx
    movsxd rdx, dword [rcx-16]
    sub rax, rdx
    jmp .add_residual
.fixed3:
    imul rax, 3
    movsxd rdx, dword [rcx-8]
    imul rdx, 3
    sub rax, rdx
    movsxd rdx, dword [rcx-12]
    add rax, rdx
    jmp .add_residual
.fixed2:
    imul rax, 2
    movsxd rdx, dword [rcx-8]
    sub rax, rdx
    jmp .add_residual
.lpc:
    xor ebx, ebx
    xor r8d, r8d
    mov r9, [r12+media_flac_work.other]
.dot:
    cmp ebx, [r12+media_flac_work.param]
    jae .shift_prediction
    movsxd rax, dword [r9+rbx*4]
    mov ecx, r14d
    dec ecx
    sub ecx, ebx
    movsxd rdx, dword [r15+rcx*4]
    imul rax, rdx
    jo .invalid
    add r8, rax
    jo .invalid
    inc ebx
    jmp .dot
.shift_prediction:
    mov rax, r8
    mov ecx, [r12+media_flac_work.shift]
    test ecx, ecx
    js .left_shift
    sar rax, cl
    jmp .add_residual
.left_shift:
    neg ecx
    mov rdx, rax
    shl rax, cl
    mov rsi, rax
    sar rsi, cl
    cmp rsi, rdx
    jne .invalid
.add_residual:
    movsxd rdx, dword [r13+r14*4]
    add rax, rdx
    jo .invalid
    movsxd rdx, eax
    cmp rax, rdx
    jne .invalid                    ; no silent final int32 wrap
    mov [r15+r14*4], eax
    inc r14d
    jmp .prediction

.stereo:
    mov r13, [r12+media_flac_work.input]
    mov r14, [r12+media_flac_work.other]
    xor ebx, ebx
.stereo_loop:
    movsxd r8, dword [r13+rbx*4]
    movsxd r9, dword [r14+rbx*4]
    mov rax, r8
    mov rdx, r9
    mov ecx, [r12+media_flac_work.param]
    cmp ecx, 1
    je .stereo_store
    cmp ecx, 8
    je .left_side
    cmp ecx, 9
    je .right_side
    lea rax, [r8+r8]
    mov rdx, r9
    and edx, 1
    or rax, rdx                    ; mid2 = 2*mid + (side &1)
    mov rdx, rax
    add rax, r9
    sar rax, 1
    sub rdx, r9
    sar rdx, 1
    jmp .stereo_store
.left_side:
    mov rdx, r8
    sub rdx, r9
    jmp .stereo_store
.right_side:
    add rax, r9
.stereo_store:
    movsxd rsi, eax
    cmp rax, rsi
    jne .invalid
    movsxd rsi, edx
    cmp rdx, rsi
    jne .invalid
    mov [r15+rbx*8], eax
    mov [r15+rbx*8+4], edx
    inc ebx
    cmp ebx, [r12+media_flac_work.count]
    jb .stereo_loop
.block_done:
    mov eax, [r12+media_flac_work.count]
    mov [r12+media_flac_work.result], rax
    cmp dword [r12+120], 7
    jne .copy_count
    shl eax, 1
.copy_count:
    mov [r12+136], eax
.commit:
    mov ecx, [r12+136]
    test ecx, ecx
    jz .publish
    mov rsi, [r12+media_flac_work.scratch]
    mov rdi, [r12+media_flac_work.dst]
    mov edx, [r12+132]
.copy:
    mov eax, [rsi+rdx*4]
    mov [rdi+rdx*4], eax
    inc edx
    dec ecx
    jnz .copy
.publish:
    mov rax, [r12+media_flac_work.bitpos]
    mov [rbp+media_flac_work.bitpos], rax
    mov rax, [r12+media_flac_work.budget]
    mov [rbp+media_flac_work.budget], rax
    mov rax, [r12+media_flac_work.result]
    mov [rbp+media_flac_work.result], rax
    xor eax, eax
    jmp .out
.error:
    mov rax, r11
    jmp .out
.invalid:
    mov rax, -1
    jmp .out
.limit:
    mov rax, -4
.out:
    add rsp, 312
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Active declared span admission. R12=local transaction, RBP=original context.
; RSI=base RDX=extent. Empty spans are allowed (no memory access); nonempty
; spans require nonnull base and carry-free exclusive end. Full declared spans
; must be disjoint, not merely the bytes expected to be touched.
flacp_span:
    test rdx, rdx
    jz .ok
    test rsi, rsi
    jz .bad
    mov r8, rsi
    add r8, rdx
    jc .bad
    lea r9, [rbp+media_flac_work_size]
    cmp rsi, r9
    jae .context_safe
    cmp rbp, r8
    jb .bad
.context_safe:
    xor r9d, r9d
    mov r10d, [r12+128]
.pair:
    cmp r9d, r10d
    jae .add
    mov rcx, r9
    shl rcx, 4
    cmp rsi, [r12+rcx+152]
    jae .next
    cmp [r12+rcx+144], r8
    jb .bad
.next:
    inc r9d
    jmp .pair
.add:
    shl r10, 4
    mov [r12+r10+144], rsi
    mov [r12+r10+152], r8
    inc dword [r12+128]
.ok:
    clc
    ret
.bad:
    mov r11, -1
    stc
    ret

; Internal MSB-first reader, ECX0..32. RAX=value, CF on refusal, R11=status.
; Transaction-local cursor/quota advance only after the whole scalar is bounded.
flacp_bits:
    cmp ecx, 32
    ja .invalid
    mov r8, [r12+media_flac_work.bitpos]
    mov r9, [r12+media_flac_work.budget]
    cmp r9, rcx
    jb .limit
    mov rax, [r12+media_flac_work.src_bytes]
    shl rax, 3
    sub rax, r8
    cmp rcx, rax
    ja .invalid
    mov edx, ecx
    mov edi, ecx
    xor r10d, r10d
    test edi, edi
    jz .done
.loop:
    mov rsi, r8
    shr rsi, 3
    mov rax, [r12+media_flac_work.src]
    movzx eax, byte [rax+rsi]
    mov ecx, r8d
    and ecx, 7
    xor ecx, 7
    shr eax, cl
    and eax, 1
    shl r10, 1
    or r10, rax
    inc r8
    dec edi
    jnz .loop
.done:
    sub r9, rdx
    mov [r12+media_flac_work.bitpos], r8
    mov [r12+media_flac_work.budget], r9
    mov rax, r10
    clc
    ret
.invalid:
    mov r11, -1
    stc
    ret
.limit:
    mov r11, -4
    stc
    ret

flacp_signed:
    push rbx
    mov ebx, ecx
    call flacp_bits
    jc .error
    test ebx, ebx
    jz .success
    mov ecx, 64
    sub ecx, ebx
    shl rax, cl
    sar rax, cl
.success:
    clc
    pop rbx
    ret
.error:
    stc
    pop rbx
    ret

flacp_unary:
    push rbx
    push r13
    sub rsp, 8
    mov r13d, ecx
    xor ebx, ebx
.loop:
    mov ecx, 1
    call flacp_bits
    jc .done
    test eax, eax
    jnz .value
    cmp ebx, r13d
    jae .limit
    inc ebx
    jmp .loop
.value:
    mov eax, ebx
    clc
    jmp .done
.limit:
    mov r11, -4
    stc
.done:
    lea rsp, [rsp+8]                ; keep status carry intact
    pop r13
    pop rbx
    ret
