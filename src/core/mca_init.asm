;; MODULE core/mca_init
;; LAYER 1
;; EXPORTS mca_boot_init, mca_boot_copy, mca_boot_rows, mca_enable_copy, mca_enable_rows
;; IMPORTS core/diag, core/idt, core/mca_poll
;; CAPS
;; OWNER saga:core
; CPU-local OS MCA initialization. Intel SDM vol3 15.8 / AMD APM vol2 9.3.
; All raw boot STATUS values are retained and each VAL=1 error is counted and
; offered to the existing diagnostic ring BEFORE any control write. No STATUS,
; CONFIG, CTL2, interrupt ownership or firmware-first state is changed here.
; Unknown layout, >32 banks or a refused boot log refuses enablement. Each CPU
; invokes this once after its IDT/TSS and the BSP's diagnostic ring are ready.
; Intel family6 before model1a: bank0 CTL aliases a firmware register (SDM,
; also Linux intel_apply_cpu_quirks); retain/observe it, never write it.
%include "core/abi/mca_poll.inc"
%include "core/abi/mca_enable.inc"
MCA_BOOT_STRIDE equ 320
; Immutable after state2/3/4: state,banks,seen,committed,drops,written mask,
; global-written,layout, then32 raw STATUS qwords. State1 is never exposed.
mca_boot_init:
    cmp edi,MCA_POLL_CPUS
    jae .ret
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,16
    mov r12d,edi
    imul r13,r12,MCA_BOOT_STRIDE
    lea rax,[rel mca_boot_rows]
    add r13,rax
    cmp qword [r13],0
    jne .done
    mov qword [r13],1
    mov dword [rsp],0                     ; old Intel bank0 exception
    mov dword [rsp+4],0                   ; exact75h bank-before-global order
    xor eax,eax
    cpuid
    cmp eax,1
    jb .refuse
    cmp ebx,0x756e6547
    jne .amd
    cmp edx,0x49656e69
    jne .refuse
    cmp ecx,0x6c65746e
    jne .refuse
    mov r14d,1
    jmp .features
.amd:
    cmp ebx,0x68747541
    jne .refuse
    cmp edx,0x69746e65
    jne .refuse
    cmp ecx,0x444d4163
    jne .refuse
    mov r14d,4
.features:
    mov eax,1
    cpuid
    mov r15d,eax
    and edx,0x40a0
    cmp edx,0x40a0
    jne .refuse
    cmp r14d,4
    je .smca
    ; Normalize Intel family/model. Ancient family<6 is not this MCA layout.
    mov eax,r15d
    shr eax,8
    and eax,15
    cmp eax,6
    jb .refuse
    jne .cap
    mov eax,r15d
    shr eax,12
    and eax,0xf0
    shr r15d,4
    and r15d,15
    or eax,r15d
    cmp eax,0x1a
    jae .cap
    mov dword [rsp],1
    jmp .cap
.smca:
    cmp r15d,0x00a70f52
    jne .smca_features
    mov dword [rsp+4],1                   ; PPR57019 applies to this signature
.smca_features:
    mov eax,0x80000000
    cpuid
    cmp eax,0x80000007
    jb .refuse
    mov eax,0x80000007
    cpuid
    test ebx,8
    jz .refuse
.cap:
    mov [r13+56],r14
    mov ecx,0x179
    rdmsr
    shl rdx,32
    or rax,rdx
    mov [rsp+8],rax
    movzx eax,al
    test eax,eax
    jz .refuse
    cmp eax,MCA_POLL_BANKS
    ja .refuse
    mov [r13+8],rax
    imul rbx,r12,MCA_POLL_STRIDE
    lea rdx,[rel mca_poll_rows]
    add rbx,rdx
    mov rdx,[rsp+8]
    mov [rbx+MCA_POLL_CAP],rdx
    mov [rbx+MCA_POLL_NBANK],eax
    mov [rbx+MCA_POLL_QUAL],r14b
    xor r15d,r15d
.sample:
    cmp r15,[r13+8]
    jae .sampled
    lea ecx,[r15*4+0x401]
    cmp r14d,4
    jne .status
    mov ecx,r15d
    shl ecx,4
    add ecx,0xc0002001
.status:
    rdmsr
    shl rdx,32
    or rax,rdx
    mov [r13+64+r15*8],rax
    ; Dedup the unchanged boot sample in the existing later observation stream.
    mov [rbx+MCA_POLL_LAST+r15*8],rax
    bt rax,63                          ; VAL=0 is no error, including threshold bits
    jnc .next
    inc qword [r13+16]
    mov rdx,rax
    mov edi,DIAG_K_MCA
    mov esi,r15d
    mov rcx,r12
    mov r8,[r13+16]
    lea r9,[rel mca_boot_tag]
    cmp r14d,4
    jne .log
    lea r9,[rel smca_boot_tag]
.log:
    call diag_ring_append
    cmp eax,1
    jne .drop
    inc qword [r13+24]
    jmp .next
.drop:
    inc qword [r13+32]
.next:
    inc r15d
    jmp .sample
.sampled:
    cmp qword [r13+32],0
    jne .log_refused
    ; No enable write can precede completion of the entire boot-status pass.
    ; Exact75h PPR57019 §3.1.5.3: bank CTLs before global reporting enable.
    ; Other CPUs retain existing order; preserve the full log/refusal pass.
    cmp dword [rsp+4],1
    je .banks
.global:
    test qword [rsp+8],0x100
    jz .global_done
    mov ecx,0x17b
    mov eax,-1
    mov edx,eax
    wrmsr
    mov qword [r13+48],1
.global_done:
    cmp dword [rsp+4],1
    je .mce
.banks:
    xor r15d,r15d
.control:
    cmp r15,[r13+8]
    jae .banks_done
    test r15d,r15d
    jnz .write
    cmp dword [rsp],1
    je .advance
.write:
    lea ecx,[r15*4+0x400]
    cmp r14d,4
    jne .ctl
    mov ecx,r15d
    shl ecx,4
    add ecx,0xc0002000
.ctl:
    mov eax,-1
    mov edx,eax
    wrmsr
    bts qword [r13+40],r15
.advance:
    inc r15d
    jmp .control
.banks_done:
    cmp dword [rsp+4],1
    je .global
.mce:
    mov edi,r12d
    mov esi,r14d
    mov rcx,[rsp+8]
    mov r8,[r13+40]
    mov r9,[r13+48]
    call mca_enable_capture
    call idt_machine_check_enable
    mov qword [r13],2
    jmp .done
.log_refused:
    mov qword [r13],4
    jmp .done
.refuse:
    mov qword [r13],3
.done:
    add rsp,16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
.ret:
    ret

; EDI CPU, RSI private320B. Only copies completed immutable native RAM.
mca_boot_copy:
    cmp edi,MCA_POLL_CPUS
    jae .busy
    imul eax,edi,MCA_BOOT_STRIDE
    lea rdx,[rel mca_boot_rows]
    add rdx,rax
    cmp qword [rdx],2
    jb .busy
    mov rdi,rsi
    mov rsi,rdx
    mov ecx,MCA_BOOT_STRIDE/8
    rep movsq
    xor eax,eax
    ret
.busy:
    mov eax,1
    ret
; CPU-local boot-only capture. No added writes; refused init never calls here.
; EDI CPU, ESI layout, RCX CAP, R8 bank-write mask, R9 global-write.
mca_enable_capture:
    push rbx
    push r12
    push r13
    push r14
    push r15
    imul eax,edi,MCA_E_STRIDE
    lea r12,[rel mca_enable_rows]
    add r12,rax
    mov dword [r12+MCA_E_STATE],1
    mov [r12+MCA_E_CAP],rcx
    mov [r12+MCA_E_GLOBAL_WRITE],r9
    mov [r12+MCA_E_CTL_WRITE],r8d
    mov [r12+MCA_E_LAYOUT],esi
    mov r13d,esi
    movzx eax,cl
    mov [r12+MCA_E_COUNT],eax
    ; Keep the established initializer stack frame / QEMU witness unwind site.
    ; This CPU remains local; retain a fresh raw signature before bank metadata.
    mov eax,1
    cpuid
    mov [r12+MCA_E_SIGNATURE],eax
    test qword [r12+MCA_E_CAP],0x100
    jz .banks
    cmp r9,1
    jne .banks
    mov ecx,0x17b
    rdmsr
    shl rdx,32
    or rax,rdx
    mov [r12+MCA_E_GLOBAL_AFTER],rax
    mov dword [r12+MCA_E_GLOBAL_VALID],1
.banks:
    xor r14d,r14d
.next:
    cmp r14d,[r12+MCA_E_COUNT]
    jae .done
    imul r15d,r14d,MCA_E_ENTRY
    lea r15,[r12+r15+MCA_E_DATA]
    bt dword [r12+MCA_E_CTL_WRITE],r14d
    jnc .advance                         ; e.g. old Intel bank0: no write proof
    lea ecx,[r14*4+0x400]
    cmp r13d,4
    jne .ctl
    mov ecx,r14d
    shl ecx,4
    add ecx,0xc0002000
.ctl:
    rdmsr
    shl rdx,32
    or rax,rdx
    mov [r15],rax
    bts dword [r12+MCA_E_CTL_VALID],r14d
    ; PPR57019 metadata applies only to this exact signature. Do not invent
    ; ownership or read IPID of McaX=0 / architectural bank4 RAZ.
    cmp r13d,4
    jne .advance
    cmp dword [r12+MCA_E_SIGNATURE],0x00a70f52
    jne .advance
    cmp dword [r12+MCA_E_GLOBAL_VALID],1
    jne .advance
    bt qword [r12+MCA_E_GLOBAL_AFTER],r14
    jc .advance
    mov ebx,r14d
    shl ebx,4
    add ebx,0xc0002000
    lea ecx,[rbx+4]
    rdmsr
    shl rdx,32
    or rax,rdx
    mov [r15+8],rax
    bts dword [r12+MCA_E_CONFIG_VALID],r14d
    test eax,1
    jz .advance
    cmp r14d,4
    je .advance
    lea ecx,[rbx+5]
    rdmsr
    shl rdx,32
    or rax,rdx
    mov [r15+16],rax
    bts dword [r12+MCA_E_IPID_VALID],r14d
.advance:
    inc r14d
    jmp .next
.done:
    mov dword [r12+MCA_E_STATE],2          ; x86 stores publish immutable row
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; EDI CPU, ESI page0..3, RDX private256B. No MSRs or writes to retained rows.
; Refusal leaves destination untouched. State2 is immutable for this boot.
mca_enable_copy:
    cmp edi,MCA_POLL_CPUS
    jae .busy
    cmp esi,4
    jae .busy
    imul eax,edi,MCA_E_STRIDE
    lea rcx,[rel mca_enable_rows]
    add rcx,rax
    cmp dword [rcx+MCA_E_STATE],2
    jne .busy
    mov r8d,esi
    shl r8d,3
    mov rdi,rdx
    mov rsi,rcx
    mov ecx,MCA_E_DATA/8
    rep movsq
    mov [rdx+MCA_E_FIRST],r8d
    imul eax,r8d,MCA_E_ENTRY
    add rsi,rax
    mov ecx,(MCA_E_COPY_BYTES-MCA_E_DATA)/8
    rep movsq
    xor eax,eax
    ret
.busy:
    mov eax,1
    ret

mca_boot_tag: db 'mca-boot',0
smca_boot_tag: db 'smca-boot',0
%include "core/abi/wdata.inc"
%macro WDATA_mca_init 0
alignb 64
mca_boot_rows: resb MCA_POLL_CPUS*MCA_BOOT_STRIDE
alignb 64
mca_enable_rows: resb MCA_POLL_CPUS*MCA_E_STRIDE
%endmacro
WDATA_BSS_DEFER WDATA_mca_init
