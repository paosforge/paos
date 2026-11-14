;; MODULE fs/ext4_refusal
;; LAYER 4
;; EXPORTS ext4_refusal_reset, ext4_refusal_record, ext4_refusal_lookup, ext4_refusal_epoch, ext4_refusal_overflow, ext4_refusal_conflict
;; IMPORTS fs/blockdev
;; OWNER saga:fs_wave
;; CONTEXT: bsp_only
; Actual ext discovery refusals, not a new probe or mount policy. Fixed 16-record
; cache. Overflow/conflict are explicit: an incomplete scan cannot prove absence.
; record: dev*, partition LBA, observed media generation, reason u32, incompat u32.
EXT_REFUSAL_MAX equ 16
ext4_refusal_reset:
    mov dword [rel ext4_refusal_count],0
    mov byte [rel ext4_refusal_overflow],0
    mov byte [rel ext4_refusal_conflict],0
    inc qword [rel ext4_refusal_epoch]
    jnz .done
    mov byte [rel ext4_refusal_conflict],1
.done:
    ret

; RDI actual device, RSI partition start, EDX reason, ECX actual superblock bits.
; Only caller-volatile registers changed. No IO, allocation or authority changes.
ext4_refusal_record:
    test rdi,rdi
    jz .invalid
    mov r8,[rdi+dev.info]
    test r8,r8
    jz .invalid
    mov r8,[r8+blk_info.media_generation]
    test r8,r8
    jz .invalid
    lea r9,[rel ext4_refusal_records]
    xor r10d,r10d
.find:
    cmp r10d,[rel ext4_refusal_count]
    jae .append
    cmp [r9],rdi
    jne .next
    cmp [r9+8],rsi
    jne .next
    cmp [r9+16],r8
    jne .invalid
    cmp [r9+24],edx
    jne .invalid
    cmp [r9+28],ecx
    jne .invalid
    ret
.next:
    add r9,32
    inc r10d
    jmp .find
.append:
    cmp r10d,EXT_REFUSAL_MAX
    jae .full
    mov [r9],rdi
    mov [r9+8],rsi
    mov [r9+16],r8
    mov [r9+24],edx
    mov [r9+28],ecx
    inc dword [rel ext4_refusal_count]
    ret
.full:
    mov byte [rel ext4_refusal_overflow],1
    ret
.invalid:
    mov byte [rel ext4_refusal_conflict],1
    ret

; RDI device, RSI partition LBA -> RAX record or zero. Generation is returned,
; never refreshed here: a stale record remains distinguishable by the consumer.
ext4_refusal_lookup:
    lea rax,[rel ext4_refusal_records]
    xor ecx,ecx
.next:
    cmp ecx,[rel ext4_refusal_count]
    jae .missing
    cmp [rax],rdi
    jne .advance
    cmp [rax+8],rsi
    je .done
.advance:
    add rax,32
    inc ecx
    jmp .next
.missing:
    xor eax,eax
.done:
    ret

%include "core/abi/wdata.inc"
%macro WDATA_BSS_ext4_refusal 0
alignb 8
ext4_refusal_epoch: resq 1
ext4_refusal_count: resd 1
ext4_refusal_overflow: resb 1
ext4_refusal_conflict: resb 1
alignb 8
ext4_refusal_records: resb EXT_REFUSAL_MAX*32
%endmacro
WDATA_BSS_DEFER WDATA_BSS_ext4_refusal
