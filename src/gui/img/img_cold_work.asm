;; MODULE gui/img/img_cold_work
;; LAYER 6
;; EXPORTS img_cold_movsb, img_cold_movsd, img_cold_stosb, img_cold_stosw, img_cold_stosd, img_cold_stosq, img_cold_hash, img_cold_crc
;; IMPORTS gui/img/img_cold_idle, core/lib/sha256, core/lib/crc32
;; CAPS
;; OWNER saga:gui_image_pipeline
;; CONTEXT: bsp_only
; Resumable pure operations used by the cold worker. Each checkpoint follows
; at most64 elements or one SHA block. No checkpoint runs inside a transform,
; allocator or external call. The inactive checkpoint is an exact no-op.
;
; REP wrappers keep the instruction's integer/flags contract: RCX ends at0,
; RSI/RDI advance only as that REP would, and every other register/flag survives.
; In particular forward overlapping LZ copies retain byte-at-a-time semantics.
%macro IMG_COLD_REP 2
%1:
    pushfq
    push rax
    push r8
    mov r8,rcx
%%next:
    test r8,r8
    jz %%done
    mov rcx,r8
    mov eax,64
    cmp rcx,rax
    cmova rcx,rax
    sub r8,rcx
    ; STOS uses the original accumulator, not the temporary chunk constant.
    mov rax,[rsp+8]
    rep %2
    call img_cold_checkpoint
    jmp %%next
%%done:
    xor ecx,ecx
    pop r8
    pop rax
    popfq
    ret
%endmacro

IMG_COLD_REP img_cold_movsb, movsb
IMG_COLD_REP img_cold_movsd, movsd
IMG_COLD_REP img_cold_stosb, stosb
IMG_COLD_REP img_cold_stosw, stosw
IMG_COLD_REP img_cold_stosd, stosd
IMG_COLD_REP img_cold_stosq, stosq

; sha256_hash-compatible arguments/result. The context belongs to this private
; worker frame, so an AUTH2 operation between turns cannot overwrite a partial
; digest through sha256_one_ctx. Each stream update consumes <=64 source bytes;
; the transform's module scratch is never live across a checkpoint.
img_cold_hash:
    push r12
    push r13
    push r14
    push r15
    sub rsp,S256_CTX_SZ+8              ;private context + stack alignment
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov rdi,rsp
    call sha256_stream_init
.next:
    test r14,r14
    jz .final
    mov rdx,r14
    cmp rdx,64
    jbe .chunk
    mov edx,64
.chunk:
    mov r15,rdx
    mov rdi,rsp
    mov rsi,r13
    call sha256_stream_update
    test rax,rax
    jnz .clear
    add r13,r15
    sub r14,r15
    call img_cold_checkpoint
    jmp .next
.final:
    mov rdi,rsp
    mov rsi,r12
    call sha256_stream_final
.clear:
    mov r15,rax
    mov rdi,rsp
    mov ecx,S256_CTX_SZ
    xor eax,eax
    cld
    call img_cold_stosb
    mov rax,r15
    add rsp,S256_CTX_SZ+8
    pop r15
    pop r14
    pop r13
    pop r12
    ret

; hotpatch_crc32-compatible wrapper over the existing streaming primitive.
; Keep RCX/RDX as the public one-shot ABI requires, and checkpoint only after
; a bounded update has returned. CRC state is a worker-local register.
img_cold_crc:
    push rcx
    push rdx
    push r8
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13d,esi
    xor r14d,r14d
.next:
    test r13,r13
    jz .done
    mov r15,r13
    cmp r15,64
    jbe .chunk
    mov r15d,64
.chunk:
    mov edi,r14d
    mov rsi,r12
    mov rdx,r15
    call crc32_update
    mov r14d,eax
    add r12,r15
    sub r13,r15
    call img_cold_checkpoint
    jmp .next
.done:
    mov eax,r14d
    mov rdi,r12
    xor esi,esi
    pop r15
    pop r14
    pop r13
    pop r12
    pop r8
    pop rdx
    pop rcx
    ret
