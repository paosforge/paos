;; MODULE rescue/efi_entry_trace
;; LAYER 0
; Diagnostic UKI entry wrapper. The whole resulting image must be signed normally.
; ORG and the original entry RVA are supplied by boot_v2_rescue_efi_trace.py.
; One RX page followed by separate RW data; no absolute image addresses/relocations.
bits 64
default rel
org TRACE_CODE_RVA

entry:
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40                      ; MS x64 home area, call RSP 0 mod16
    mov rbx, rcx                     ; unchanged ImageHandle
    mov rbp, rdx                     ; unchanged SystemTable
    mov [rel system_table], rbp
    mov qword [rel record + 16], 1
    mov qword [rel record + 24], -1
    call publish                     ; phase1: wrapper entered, original not yet called
    mov rcx, rbx
    mov rdx, rbp
    call ORIGINAL_ENTRY_RVA          ; original pinned systemd-stub, same loaded image
    mov r12, rax                     ; preserve full EFI_STATUS across observation
    mov qword [rel record + 16], 2
    mov [rel record + 24], rax
    call publish                     ; phase2: original stub returned
    mov rax, r12
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret

publish:
    sub rsp, 40                      ; helper entry RSP8 -> call RSP0
    mov rax, [rel system_table]
    test rax, rax
    jz .out
    mov rax, [rax + 88]              ; EFI_SYSTEM_TABLE.RuntimeServices
    test rax, rax
    jz .out
    cmp qword [rax + 0x58], 0
    je .out
    lea rcx, [rel variable_name]
    lea rdx, [rel variable_guid]
    mov r8d, 7                       ; NV | boot-service | runtime, observation only
    mov r9d, 40
    lea r10, [rel record]
    mov [rsp + 32], r10
    call [rax + 0x58]                ; SetVariable; ignore failure, never retry/gate
.out:
    add rsp, 40
    ret

%ifdef TRACE_NESTED
; Fixed rel32 jump table, consumed by the transform after exact text/call pins.
; Each entry is five bytes. These are call adapters, never service-table hooks.
times 256 - ($ - $$) db 0
    jmp near linux_exec_trace
    jmp near load_image_trace
    jmp near handle_protocol_trace
    jmp near start_image_trace

linux_exec_trace:
    ; Original linux_exec uses SysV, not MS x64. Save all six argument registers
    ; (including rdi/rsi), and every other GPR across the MS-ABI observation.
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    sub rsp, 32                      ; after 15 pushes, call RSP0; home area
    mov qword [rel record + 16], 3
    mov qword [rel record + 24], -1
    call publish
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    jmp ORIGINAL_LINUX_EXEC_RVA       ; same caller return address, original cleanup

%macro firmware_trace 5              ; label, BS offset, pre phase/0, post phase, six args
%1:
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 104                     ; call RSP0; own 32-byte home + stack args
    mov rbx, rax                     ; exact original BS table/target
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    mov r15, r9
%if %5
    ; Original incoming arg5/6 at entry RSP+40/+48, before 64+104 bytes.
    mov r10, [rsp + 208]
    mov [rsp + 32], r10
    mov r10, [rsp + 216]
    mov [rsp + 40], r10
%endif
%if %3
    mov qword [rel record + 16], %3
    mov qword [rel record + 24], -1
    call publish
%endif
    mov rcx, r12
    mov rdx, r13
    mov r8, r14
    mov r9, r15
    call [rbx + %2]                  ; same MS-ABI call, exactly once
    mov r12, rax                     ; retain all 64 bits, including EFI error bit
    mov qword [rel record + 16], %4
    mov [rel record + 24], rax
    call publish
    mov rax, r12
    add rsp, 104
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
%endmacro

firmware_trace load_image_trace,      0xc8, 4, 5, 1
firmware_trace handle_protocol_trace, 0x98, 0, 6, 0
firmware_trace start_image_trace,     0xd0, 7, 8, 0
%endif

times 4096 - ($ - $$) db 0
record:
    db 'P','R','S','E','F','I','0','1'
    dq TRACE_NONCE
    dq 1                            ; phase: entered
    dq 0xFFFFFFFFFFFFFFFF           ; status unavailable until phase2
    dq TRACE_NONCE ^ 0xFFFFFFFFFFFFFFFF
variable_name:
    dw 'P','a','O','S','R','e','s','c','u','e','E','F','I',0
variable_guid:
    ; Same PaOS diagnostic namespace as PaOSMgrDiag; distinct variable name.
    db 0xAC,0xB7,0xE0,0xD9,0xC9,0x86,0x1B,0x48
    db 0x97,0xDD,0x35,0x5F,0x57,0xB0,0xC2,0x63

align 8
system_table: dq 0                  ; initialized only by the outer wrapper
