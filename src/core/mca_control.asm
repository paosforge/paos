;; MODULE core/mca_control
;; LAYER 1
;; EXPORTS mca_control_sample, mca_control_copy, mca_control_rows, mca_bank_copy, mca_bank_rows
;; IMPORTS core/time
;; CAPS
;; OWNER saga:core
; CPU-local readback only, after the existing qualified corrected-MCA scan.
; Intel SDM15.3: MCi_CTL=400h+4i, optional MCG_CTL.CAP[8],
; optional MCi_CTL2=280h+i iff MCG_CAP[10]. CMCI_EN is bit30.
; AMD APM9: qualified SMCA CTL=C0002000h+10h*i, CONFIG=+4;
; CONFIG.IntPresent[10], IntEn[40]. No Intel CTL2 access on AMD.
; No MSR writes, error clearing, APIC setup or interrupt ownership claim.
; CTL all/any masks summarize actual bank readbacks. IRQ bits do not establish
; a live APIC route. A zero/partial bounded sample is never hardware absence.
%include "core/abi/mca_poll.inc"
%include "core/abi/mca_bank.inc"

; EDI=dense CPU, RSI=that CPU's retained MCA_POLL row. Caller is that CPU.
; Single writer per row; odd/even sequence brackets all fields. 64-byte rows:
; seq Q; qual D; bounded banks D; MCG_CAP Q; CR4 Q; CTL all D; CTL any D;
; AMD IntPresent D (Intel unknown); IRQ enable D; sampled us Q; MCG_CTL Q.
mca_control_sample:
    cmp edi,32
    jae .ret
    test rsi,rsi
    jz .ret
    movzx eax,byte [rsi+MCA_POLL_QUAL]
    cmp eax,1
    je .qual
    cmp eax,4
    jne .ret
.qual:
    cmp dword [rsi+MCA_POLL_NBANK],32
    ja .ret
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    mov r12,rsi
    mov ebx,edi
    shl rbx,6
    lea r13,[rel mca_control_rows]
    add r13,rbx
    mov rax,[r13]
    test al,1
    jnz .done
    cmp rax,-2
    jae .done                            ; sequence exhaustion: keep old sample
    inc qword [r13]
    ; Same publication sequence covers aggregate and bank metadata. CONFIG/CTL
    ; reuse the existing reads; only qualified IPID below adds an MSR read.
    mov r15,rbx
    shl r15,4
    lea rax,[rel mca_bank_rows]
    add r15,rax
    mov qword [r15],0
    mov qword [r15+8],0
    mov qword [r15+16],0
    mov qword [r15+24],0
    mov eax,1
    cpuid
    mov [r15+MCA_B_SIGNATURE],eax
    cmp byte [r12+MCA_POLL_QUAL],4
    jne .identity_done
    ; AMD OSRR56255 rev3.03 covers family17h, models00h-2fh only.
    ; Qualification4 already checked AuthenticAMD and ScalableMca on this CPU.
    ; PPR57019 rev3.00 §§3.1.2.2.4/3.1.5.5: exact saved Reatan
    ; signature only. Distinct rule2; never widen the family17h rule.
    cmp eax,0x00a70f52
    jne .family17
    mov dword [r15+MCA_B_RULE],2
    jmp .identity_done
.family17:
    mov edx,eax
    and edx,0x0ff00f00
    cmp edx,0x00800f00
    jne .identity_done
    shr eax,16
    and eax,15
    cmp eax,2
    ja .identity_done
    mov dword [r15+MCA_B_RULE],1
.identity_done:
    movzx eax,byte [r12+MCA_POLL_QUAL]
    mov [r13+8],eax
    mov eax,[r12+MCA_POLL_NBANK]
    mov [r13+12],eax
    mov rax,[r12+MCA_POLL_CAP]
    mov [r13+16],rax
    mov rax,cr4
    mov [r13+24],rax
    mov qword [r13+32],0
    mov qword [r13+40],0
    mov qword [r13+56],0
    bt qword [r12+MCA_POLL_CAP],8
    jnc .banks
    mov ecx,0x17b
    rdmsr
    shl rdx,32
    or rax,rdx
    mov [r13+56],rax
.banks:
    xor r14d,r14d
.bank:
    cmp r14d,[r13+12]
    jae .publish
    imul ebp,r14d,MCA_B_ENTRY
    lea rbp,[r15+rbp+MCA_B_DATA]
    lea ecx,[r14*4+0x400]
    cmp dword [r13+8],4
    jne .ctl
    mov ecx,r14d
    shl ecx,4
    add ecx,0xc0002000
.ctl:
    rdmsr
    shl rdx,32
    or rax,rdx
    mov [rbp],rax
    bts dword [r15+MCA_B_CTL_VALID],r14d
    test rax,rax
    jz .aux
    bts dword [r13+36],r14d
    cmp rax,-1
    jne .aux
    bts dword [r13+32],r14d
.aux:
    cmp dword [r13+8],4
    je .smca
    bt qword [r13+16],10
    jnc .next
    lea ecx,[r14+0x280]
    rdmsr
    bt eax,30
    jnc .next
    bts dword [r13+44],r14d
    jmp .next
.smca:
    mov ecx,r14d
    shl ecx,4
    add ecx,0xc0002004
    rdmsr
    shl rdx,32
    or rax,rdx
    mov [rbp+8],rax
    bts dword [r15+MCA_B_CONFIG_VALID],r14d
    bt rax,10
    jnc .smca_en
    bts dword [r13+40],r14d
.smca_en:
    bt rax,40                           ; raw enable independent of present
    jnc .ipid
    bts dword [r13+44],r14d
.ipid:
    ; OSRR56255 §§3.4/3.5/3.7: +5 exists iff McaX=1. Bank4 is
    ; always RAZ/WRIG in this model range and rule2 (PPR57019 p287).
    ; Rule2 still needs CONFIG.McaX: no implemented IPID/ownership claim
    ; follows from a zero CONFIG. At most31 additional reads per CPU scan.
    ; Never probe unknown layouts/models.
    cmp dword [r15+MCA_B_RULE],1
    je .ipid_model
    cmp dword [r15+MCA_B_RULE],2
    jne .next
.ipid_model:
    cmp r14d,4
    je .next
    test al,1
    jz .next
    mov ecx,r14d
    shl ecx,4
    add ecx,0xc0002005
    rdmsr
    shl rdx,32
    or rax,rdx
    mov [rbp+16],rax
    bts dword [r15+MCA_B_IPID_VALID],r14d
    ; Positive architectural local view only; zero/unknown is never absence.
    ; CONFIG/control registers are available to one thread (§3.4); a nonzero
    ; HardwareID qualifies a populated local bank. This is not CMCI ownership.
    shr rax,32
    test eax,0xfff
    jz .next
    bts dword [r15+MCA_B_LOCAL],r14d
.next:
    inc r14d
    jmp .bank
.publish:
    call time_monotonic_now_us
    mov [r13+48],rax
    inc qword [r13]                     ; x86 store order publishes complete even row
.done:
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
.ret:
    ret

; EDI=dense CPU, RSI=private writable64B -> EAX0 stable copy/1 unavailable.
; Read-only bounded copy, no CPU/MSR/config I/O. Refusal leaves output untouched.
mca_control_copy:
    cmp edi,32
    jae .bad
    test rsi,rsi
    jz .bad
    mov rax,rsi
    add rax,63
    jc .bad
    sub rsp,72
    mov r8,rsi
    shl edi,6
    lea r9,[rel mca_control_rows]
    add r9,rdi
    mov r10,[r9]
    test r10,r10
    jz .refuse
    test r10b,1
    jnz .refuse
    lfence
    mov rdi,rsp
    mov rsi,r9
    mov ecx,8
    rep movsq
    lfence
    cmp r10,[r9]
    jne .refuse
    mov rdi,r8
    mov rsi,rsp
    mov ecx,8
    rep movsq
    xor eax,eax
    add rsp,72
    ret
.refuse:
    add rsp,72
.bad:
    mov eax,1
    ret

; EDI=dense CPU, ESI=page0..3, RDX=private writable MCA_B_COPY_BYTES.
; Stable single-attempt copy of aggregate64B, bank header32B, eight triples.
; Read-only; refusal leaves output untouched. Sequence is the SAME aggregate
; sequence (no cross-generation pairing); callers compare seq across pages.
mca_bank_copy:
    cmp edi,32
    jae .bad
    cmp esi,4
    jae .bad
    test rdx,rdx
    jz .bad
    mov rax,rdx
    add rax,MCA_B_COPY_BYTES-1
    jc .bad
    sub rsp,MCA_B_COPY_BYTES+8
    mov r8,rdx
    shl edi,6
    lea r9,[rel mca_control_rows]
    add r9,rdi
    mov r10,[r9]
    test r10,r10
    jz .refuse
    test r10b,1
    jnz .refuse
    mov r11d,esi
    shl r11d,3
    shl edi,4
    lea rax,[rel mca_bank_rows]
    add rax,rdi
    lfence
    mov rdi,rsp
    mov rsi,r9
    mov ecx,8
    rep movsq
    mov rsi,rax
    mov ecx,MCA_B_DATA/8
    rep movsq
    mov [rsp+88],r11d                    ; explicit first bank in this page
    imul ecx,r11d,MCA_B_ENTRY
    lea rsi,[rax+rcx+MCA_B_DATA]
    mov ecx,8*MCA_B_ENTRY/8
    rep movsq
    lfence
    cmp r10,[r9]
    jne .refuse
    mov rdi,r8
    mov rsi,rsp
    mov ecx,MCA_B_COPY_BYTES/8
    rep movsq
    xor eax,eax
    add rsp,MCA_B_COPY_BYTES+8
    ret
.refuse:
    add rsp,MCA_B_COPY_BYTES+8
.bad:
    mov eax,1
    ret

%include "core/abi/wdata.inc"
%macro WDATA_mca_control 0
alignb 64
mca_control_rows: resb 32*64
alignb 64
mca_bank_rows: resb 32*MCA_B_STRIDE
%endmacro
WDATA_BSS_DEFER WDATA_mca_control
