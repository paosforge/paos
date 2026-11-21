;; MODULE hv/tools_vm_mmio
;; LAYER 5
;; EXPORTS tools_vm_mmio_exit, tools_vm_mmio_reset, tvmm_rip, tvmm_reads, tvmm_writes, tvmm_ilen_mismatch
;; IMPORTS hv/tools_vm_devices, hv/tools_vm_memory, hv/tools_vm_cpu, hv/tools_vm_console
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Claude / rc-vm-claude. Tools D4a: the trapped register window
; [TVM_MMIO_GPA, +4 KiB) and a minimal decoder, reached only from the tools
; dispatcher for reason 48 (Intel EPT violation, SVM NPF normalized by
; hv_svm_exit_record_at) while the actual tools exit is open. SEC 121319 M1-M6:
; - the access is the hardware's: reported GPA, read/write bit, no fetch, and on
;   Intel a final-translation access (qualification bits 7 and 8). The decoded
;   direction must equal the hardware's; the decoded address is never used.
; - 4-byte, 4-aligned accesses inside the window. D5b (SEC 121716 N2): 1- and
;   2-byte LOADS also at config offsets 0x100..0x107, naturally aligned, never
;   crossing 0x108. The offset is always the hardware GPA's, checked once the
;   opcode gives the width.
; - 64-bit code at CPL0 only (EFER.LMA, CS.L=1/D=0, CR0.PE|PG, CR4.PAE, no
;   LA57). Compatibility, protected, real, v8086 and 16-bit code are terminal.
; - accepted forms: optional REX without W, then 89 /r (store) or 8B /r (load)
;   with a memory ModRM, SIB accepted for length, no RIP-relative. N1 adds
;   66 [REX no W] 8B /r (word load) and [REX] 8A /r (byte load). One 66, and
;   only as the first byte; REX only right before the opcode. Without REX,
;   8A's AH-BH (reg 4-7) are refused, and a narrow load into SP/SPL is refused
;   (N4). Every other legacy prefix, 66 8A, 66 89, 88, MOVZX/MOVSX and every
;   narrow store are terminal. At most 9 bytes, so at most one page boundary.
; - bytes: SVM DecodeAssists bytes below the hardware count, else a 4-level
;   walk of the tools CR3 with every table and code byte converted through
;   tools_vm_gpa against own RAM; present, no XD, a supervisor page.
; - an exit taken during event delivery (vectoring valid) is terminal.
; - RFLAGS.TF is terminal. The dispatcher's .skip advances RIP by the decoded
;   length and consumes STI/MOV-SS blocking exactly as completion would.
; - D4b: the device is hv/tools_vm_console. It sees only the hardware's window
;   offset, the direction, the width (N5) and the value (SEC 121371): a 4-byte
;   load's value goes to the decoded register zero-extended, a 1- or 2-byte
;   load replaces only its low byte or word (N4), a store's value is the
;   decoded register's low 32 bits. The hardware instruction length is
;   advisory (undefined for EPT violations; 0 for NPF): a nonzero
;   disagreement is counted, never trusted.
%include "hv/tools_vm.inc"
%include "core/abi/wdata.inc"

; Assemble-time: the window lies wholly above the largest tools RAM, so no
; SLAT leaf can ever cover it (a negative TIMES count is an assembly error).
times (TVM_MMIO_GPA < TVM_RAM_LARGE) * -1 db 0
times (TVM_MMIO_GPA + TVM_MMIO_BYTES > 0x100000000) * -1 db 0
times (TVM_MMIO_BYTES & 3) * -1 db 0     ; a 4-aligned offset is a whole dword inside
TVMM_ADDR equ 0x000ffffffffff000

; Actual open tools exit, reason 48 ->EAX 1 handled (tvm_exit+16 = decoded
; length) /0 terminal. The context is one-shot either way.
tools_vm_mmio_exit:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,16
    cmp byte [rel tvm_exit_ctx+TXC_VALID],1
    mov byte [rel tvm_exit_ctx+TXC_VALID],0
    jne .bad
    call tools_vm_exit_endpoint
    test rax,rax
    jz .bad
    ; SRC 121403 R1: an access made while the CPU was delivering an event
    ; (IDT-vectoring / EXITINTINFO valid) was not made by the instruction at
    ; RIP; decoding and skipping it would drop or misplace that event.
    test dword [rel tvm_vectoring],0x80000000
    jnz .bad
    ; M1: the hardware's GPA, inside the window. Width and alignment (M2/N2)
    ; are checked at .where, once the opcode gives the width.
    mov rax,[rel tvm_exit+24]
    mov ecx,TVM_MMIO_GPA
    sub rax,rcx                      ; below the window wraps above it
    cmp rax,TVM_MMIO_BYTES-1
    ja .bad
    mov r15d,eax
    mov rbx,[rel tvm_exit+8]
    test ebx,4                       ; instruction fetch
    jnz .bad
    test ebx,3
    jz .bad
    cmp qword [rel tvm_arch],1
    jne .direction
    mov eax,ebx
    and eax,0x180                    ; linear address valid, final translation
    cmp eax,0x180
    jne .bad
.direction:
    and ebx,2                        ; EBX nonzero: the hardware wrote
    ; M5: a trap flag would owe a #DB after completion; never skip it.
    mov edi,0x6820
    call tools_vm_field_read
    test eax,1<<8
    jnz .bad
    ; M3: 64-bit CPL0 code under 4-level long-mode paging.
    mov edi,0x2806
    call tools_vm_field_read
    test eax,1<<10
    jz .bad
    mov eax,[rel tvm_exit_ctx+TXC_CS_AR]
    and eax,(1<<16)|(1<<14)|(1<<13)|(1<<7)
    cmp eax,(1<<13)|(1<<7)           ; usable, present, L=1, D=0
    jne .bad
    cmp byte [rel tvm_exit_ctx+TXC_CPL],0
    jne .bad
    mov edi,0x6800
    call tools_vm_field_read
    and eax,0x80000001
    cmp eax,0x80000001
    jne .bad
    mov edi,0x6804
    call tools_vm_field_read
    test eax,1<<5
    jz .bad
    test eax,1<<12
    jnz .bad
    mov edi,0x6802
    call tools_vm_field_read
    mov [rel tvmm_cr3],rax
    mov edi,0x681e
    call tools_vm_field_read
    mov [rel tvmm_rip],rax
    ; Decode. R12 index, R13 REX, R14 ModRM, [rsp+8] width, [rsp+12] 66 seen.
    xor r12d,r12d
    xor r13d,r13d
    mov qword [rsp+8],0
    mov edi,r12d
    call tvmm_fetch
    cmp eax,0x66                     ; N1: one operand-size prefix, first only
    jne .rex
    mov dword [rsp+12],1
    inc r12d
    mov edi,r12d
    call tvmm_fetch
.rex:
    mov ecx,eax
    and ecx,0xf0
    cmp ecx,0x40
    jne .opcode
    test eax,8                       ; REX.W: not a 4-byte access
    jnz .bad
    mov r13d,eax
    inc r12d
    mov edi,r12d
    call tvmm_fetch
.opcode:
    cmp eax,0x89
    je .store
    mov ecx,1
    cmp eax,0x8a                     ; byte load
    je .byte
    cmp eax,0x8b
    jne .bad
    mov ecx,4
    cmp dword [rsp+12],0
    je .load
    mov ecx,2                        ; 66 8B: word load
    jmp .load
.byte:
    cmp dword [rsp+12],0             ; 66 8A is not an accepted form
    jne .bad
.load:
    test ebx,ebx                     ; decoded load, hardware write
    jnz .bad
    jmp .where
.store:
    cmp dword [rsp+12],0             ; stores are 4-byte only
    jne .bad
    test ebx,ebx                     ; decoded store, hardware read
    jz .bad
    mov ecx,4
.where:
    ; M2/N2 at the hardware's offset: 4 bytes 4-aligned anywhere in the
    ; window; 1 and 2 bytes only at config 0x100..0x107, naturally aligned,
    ; so never crossing 0x108.
    mov [rsp+8],ecx
    cmp ecx,4
    jne .narrow
    test r15d,3
    jnz .bad
    jmp .modrm
.narrow:
    lea eax,[r15-0x100]              ; below the config region wraps above it
    cmp eax,8
    jae .bad
    lea edx,[rcx-1]
    test eax,edx
    jnz .bad
.modrm:
    inc r12d
    mov edi,r12d
    call tvmm_fetch
    cmp eax,-1
    je .bad
    mov r14d,eax
    inc r12d
    mov ecx,eax
    shr ecx,6                        ; mod
    cmp ecx,3                        ; a register operand cannot fault on a GPA
    je .bad
    mov edx,eax
    and edx,7                        ; rm
    xor r8d,r8d                      ; displacement bytes
    cmp ecx,1
    jne .disp32
    mov r8d,1
.disp32:
    cmp ecx,2
    jne .rm
    mov r8d,4
.rm:
    cmp edx,4
    je .sib
    test ecx,ecx
    jnz .disp
    cmp edx,5                        ; mod 00 rm 101: RIP-relative
    je .bad
    jmp .disp
.sib:
    mov [rsp],r8d
    mov [rsp+4],ecx
    mov edi,r12d
    call tvmm_fetch
    cmp eax,-1
    je .bad
    inc r12d
    mov r8d,[rsp]
    mov ecx,[rsp+4]
    and eax,7
    cmp eax,5                        ; SIB base 101 with mod 00: disp32
    jne .disp
    test ecx,ecx
    jnz .disp
    mov r8d,4
.disp:
    test r8d,r8d
    jz .decoded
    mov [rsp],r8d
    mov edi,r12d
    call tvmm_fetch
    cmp eax,-1
    je .bad
    inc r12d
    mov r8d,[rsp]
    dec r8d
    jmp .disp
.decoded:
    mov eax,r14d
    shr eax,3
    and eax,7
    cmp dword [rsp+8],1
    jne .reg
    test r13d,r13d                   ; N1: without REX, 8A reg 4-7 is AH-BH
    jnz .reg
    cmp eax,4
    jae .bad
.reg:
    mov ecx,r13d
    and ecx,4                        ; REX.R
    lea eax,[rax+rcx*2]
    lea rdx,[rel tvmd_gpr_map]
    movzx eax,byte [rdx+rax]
    mov [rsp],eax                    ; the register's tvm_gpr offset, 0xff RSP
    cmp eax,0xff
    jne .access
    cmp dword [rsp+8],4              ; N4: SP/SPL never takes a narrow load
    jne .bad
.access:
    test ebx,ebx
    jnz .write
    mov edi,r15d                     ; the hardware's window offset
    mov esi,[rsp+8]                  ; N5: and the width
    call tools_vm_console_read
    mov edx,eax                      ; zero-extended
    mov eax,[rsp]
    cmp eax,0xff
    jne .gpr
    mov edi,0x681c
    mov rsi,rdx
    call tools_vm_field_write
    cmp eax,1
    jne .bad
    jmp .read_done
.gpr:
    lea rcx,[rel tvm_gpr]
    cmp dword [rsp+8],2
    jb .gpr_byte
    je .gpr_word
    mov [rcx+rax],rdx                ; 4 bytes: zero-extended
    jmp .read_done
.gpr_word:
    mov [rcx+rax],dx                 ; N4: the low word only
    jmp .read_done
.gpr_byte:
    mov [rcx+rax],dl                 ; N4: the low byte only
.read_done:
    inc qword [rel tvmm_reads]
    jmp .length
.write:
    mov eax,[rsp]
    cmp eax,0xff
    jne .write_gpr
    mov edi,0x681c
    call tools_vm_field_read
    jmp .write_value
.write_gpr:
    lea rcx,[rel tvm_gpr]
    mov rax,[rcx+rax]
.write_value:
    mov edi,r15d
    mov esi,eax                      ; the 32-bit value only
    call tools_vm_console_write
    inc qword [rel tvmm_writes]
.length:
    mov eax,[rel tvm_exit+16]
    test eax,eax
    jz .own_length
    cmp eax,r12d
    je .own_length
    inc qword [rel tvmm_ilen_mismatch]
.own_length:
    mov [rel tvm_exit+16],r12d
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; EDI byte index from RIP ->EAX byte / -1. DecodeAssists bytes below the
; hardware count; otherwise the tools CR3 walk. Caller-saved registers clobbered.
tvmm_fetch:
    cmp edi,9                        ; the longest accepted form: 66 REX 8B ModRM SIB disp32
    jae .bad
    movzx eax,byte [rel tvm_exit_ctx+TXC_INSN_N]
    cmp edi,eax
    jae .walk
    lea rax,[rel tvm_exit_ctx+TXC_INSN]
    movzx eax,byte [rax+rdi]
    ret
.walk:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    mov r12,[rel tvmm_rip]
    add r12,rdi
    mov rax,r12
    shl rax,16
    sar rax,16
    cmp rax,r12
    jne .walk_bad
    mov rbx,[rel tvmm_cr3]
    mov rax,TVMM_ADDR
    and rbx,rax
    mov r13d,39
    mov r14d,4                       ; U/S accumulated over every level
.level:
    mov rax,r12
    mov ecx,r13d
    shr rax,cl
    and eax,0x1ff
    lea rdx,[rbx+rax*8]
    mov ecx,8
    call tvmm_ram
    test rax,rax
    jz .walk_bad
    mov rax,[rax]
    test al,1
    jz .walk_bad
    bt rax,63                        ; XD: this byte was not fetchable
    jc .walk_bad
    and r14d,eax
    cmp r13d,12
    je .page4k
    test al,0x80
    jz .table
    cmp r13d,30
    je .page1g
    cmp r13d,21
    jne .walk_bad                    ; PS in a PML4E
    mov rcx,0x000fffffffe00000
    and rax,rcx
    mov rdx,r12
    and edx,0x1fffff
    jmp .leaf
.page1g:
    mov rcx,0x000fffffc0000000
    and rax,rcx
    mov rdx,r12
    and edx,0x3fffffff
    jmp .leaf
.table:
    mov rbx,TVMM_ADDR
    and rbx,rax
    sub r13d,9
    jmp .level
.page4k:
    mov rcx,TVMM_ADDR
    and rax,rcx
    mov rdx,r12
    and edx,0xfff
.leaf:
    test r14d,4                      ; CPL0 code lives on a supervisor page
    jnz .walk_bad
    add rdx,rax
    mov ecx,1
    call tvmm_ram
    test rax,rax
    jz .walk_bad
    movzx eax,byte [rax]
    jmp .walk_out
.walk_bad:
    mov eax,-1
.walk_out:
    add rsp,8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.bad:
    mov eax,-1
    ret

; RDX tools GPA, ECX length ->RAX own-RAM HVA /0, through the original
; allocation join (tools_vm_gpa); never a foreign or control byte.
tvmm_ram:
    mov rdi,[rel tvm_start]
    mov rsi,[rel tvm_token]
    jmp tools_vm_gpa

; Private state only; called by tools_vm_devices_reset.
tools_vm_mmio_reset:
    xor eax,eax
    mov [rel tvmm_rip],rax
    mov [rel tvmm_cr3],rax
    mov [rel tvmm_reads],rax
    mov [rel tvmm_writes],rax
    mov [rel tvmm_ilen_mismatch],rax
    mov byte [rel tvm_exit_ctx+TXC_VALID],0
    ret

%macro WDATA_hv_tools_vm_mmio 0
align 8
tvmm_rip: dq 0
tvmm_cr3: dq 0
tvmm_reads: dq 0
tvmm_writes: dq 0
tvmm_ilen_mismatch: dq 0
; Snapshot disjointness loads this span with ECX. Reject empty, reversed
; or truncated layouts at WDATA expansion, after both labels are defined.
times (((tvmm_ilen_mismatch+8-tvmm_rip) <= 0) || ((tvmm_ilen_mismatch+8-tvmm_rip) > 0xffffffff)) * -1 db 0
%endmacro
WDATA_DEFER WDATA_hv_tools_vm_mmio
