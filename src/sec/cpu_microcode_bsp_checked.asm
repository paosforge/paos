;; MODULE sec/cpu_microcode_bsp_checked
;; LAYER 2
;; EXPORTS cpu_microcode_boot_bsp_checked, cpu_microcode_boot_checked_get
;; IMPORTS sec/cpu_microcode_boot, sec/cpu_microcode_checked, sec/cpu_microcode, sec/cpu_security, core/idt, boot/serial
;; CAPS
;; OWNER saga:security
; Normal BSP, IF=0, existing IDT/GDT/TSS installed and trial/deadman armed.
; This is the deployed entry; the original raw entry remains a compatibility
; API. No raw fallback. APs keep their own records and independent attempts.
;
; Preserve the entire MCB_SIZE prefix and serial grammar for existing readers.
; Separate write-once evidence binds the actual full local APIC, each checked
; I/O completion, matching load readback, and a fresh post-load CSS. A load
; followed by a failed post sample remains partial (-22), never APPLIED proof.
; The admitted immutable pack, pure envelope/selector and vendor checks are
; unchanged. This is evidence, not a fleet/boot/mitigation completeness gate.
MCBC_READY equ 0                      ; 0 absent,2 writing,1 immutable
MCBC_OWNER equ 4                      ; actual full local APIC (zero valid)
MCBC_OWNER_VALID equ 8
MCBC_LOAD_MATCH equ 12
MCBC_POST_VALID equ 16
MCBC_VERSION equ 20
MCBC_AFTER equ 24                     ; independent CSS_SIZE=112
MCBC_IO equ 136                       ; CIO_SIZE=1056
MCBC_APPLY equ 1192                   ; MCA_SIZE=32
MCBC_SIZE equ 1232
%if MCBC_AFTER + CSS_SIZE > MCBC_IO || MCBC_IO + CIO_SIZE > MCBC_APPLY || MCBC_APPLY + MCA_SIZE > MCBC_SIZE
    %error "checked BSP evidence ranges overlap"
%endif

; Once per boot. Safe/Rescue have no CPU/TSC/MSR/state side effect.
; -> RAX signed original result or explicit checked I/O/post refusal.
; Keeps RBX,RBP,R12-R15. Reentry never repeats a hardware edge or receipt.
cpu_microcode_boot_bsp_checked:
    cmp byte [rel pbm_profile],PBM_PROFILE_NORMAL
    jne .state_bad
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea rbx,[rel mcb_state]
    lea r14,[rel mcbc_state]
    xor eax,eax
    mov edx,2
    lock cmpxchg dword [r14 + MCBC_READY],edx
    jne .existing
    ; A compatibility caller must not have already published the legacy row.
    cmp dword [rbx + MCB_DONE],0
    jne .legacy_done
    mov dword [r14 + MCBC_VERSION],1
    call cpu_microcode_boot_tsc
    mov [rbx + MCB_TSC_START],rax
    mov dword [rbx + MCB_RESULT],-21
    call idt_gp_fixup_cpu
    mov [r14 + MCBC_OWNER],eax
    cmp eax,-1
    je .report
    mov dword [r14 + MCBC_OWNER_VALID],1
    lea rdi,[r14 + MCBC_IO]
    mov esi,eax
    call cpu_checked_io_init
    mov dword [r14 + MCBC_IO + CIO_PHASE],1
    lea rdi,[rbx + MCB_SAMPLE]
    mov esi,CSS_SIZE
    lea rdx,[r14 + MCBC_IO]
    call cpu_security_sample_checked
    cmp dword [r14 + MCBC_IO + CIO_FAILURE],0
    jne .sample_failed
    mov dword [rbx + MCB_RESULT],MC_E_VENDOR
    cmp dword [rbx + MCB_SAMPLE + CSS_VENDOR],0
    je .report
    mov dword [rbx + MCB_RESULT],MC_E_GUEST
    cmp dword [rbx + MCB_SAMPLE + CSS_HV],0
    jne .report
    mov dword [rbx + MCB_RESULT],MC_E_REVISION
    cmp dword [rbx + MCB_SAMPLE + CSS_REV_VALID],1
    jne .report
    mov dword [rbx + MCB_RESULT],MCB_NOPACK
    mov r12,[rel mcb_pack_buf]
    mov r13,[rel mcb_pack_len]
    test r12,r12
    jz .report
    test r13,r13
    jz .report
    mov rdi,r12
    mov rsi,r13
    mov edx,[rbx + MCB_SAMPLE + CSS_VENDOR]
    call ucode_pack_slice
    mov [rbx + MCB_RESULT],eax
    test eax,eax
    jnz .report
    mov r12,rdi
    mov r13,rsi
    xor ecx,ecx
    cmp dword [rbx + MCB_SAMPLE + CSS_VENDOR],1
    jne .select
    mov dword [r14 + MCBC_IO + CIO_PHASE],2
    lea rdi,[r14 + MCBC_IO]
    mov esi,1
    mov ecx,0x17
    call cpu_checked_io
    cmp r10d,1
    jne .io_failed
    mov ecx,edx
    shr ecx,18
    and ecx,7
.select:
    mov [rbx + MCB_PID],ecx
    mov rdi,r12
    mov rsi,r13
    lea rdx,[rbx + MCB_SAMPLE]
    lea r8,[rbx + MCB_RECORD]
    call cpu_microcode_select
    mov [rbx + MCB_RESULT],eax
    cmp eax,MC_NONE
    je .current
    cmp eax,MC_SELECTED
    jne .report
    mov dword [r14 + MCBC_IO + CIO_PHASE],3
    mov rdi,r12
    mov rsi,r13
    lea rdx,[rbx + MCB_SAMPLE]
    lea r8,[rbx + MCB_RECORD]
    lea rax,[r14 + MCBC_IO]
    mov [r14 + MCBC_APPLY + MCA_IO],rax
    lea rax,[r14 + MCBC_AFTER]
    mov [r14 + MCBC_APPLY + MCA_POST],rax
    lea r9,[r14 + MCBC_APPLY]
    call cpu_microcode_apply_checked
    mov [rbx + MCB_RESULT],eax
    mov eax,[r14 + MCBC_APPLY + MCA_LOAD_MATCH]
    mov [r14 + MCBC_LOAD_MATCH],eax
    mov eax,[r14 + MCBC_APPLY + MCA_POST_VALID]
    mov [r14 + MCBC_POST_VALID],eax
    jmp .report
.current:
    ; No newer selection still requires an independent checked local readback.
    ; No update trigger, raw fallback or copied firmware sample is permitted.
    mov dword [r14 + MCBC_IO + CIO_PHASE],4
    lea rdi,[r14 + MCBC_AFTER]
    mov esi,CSS_SIZE
    lea rdx,[r14 + MCBC_IO]
    call cpu_security_sample_checked
    cmp dword [r14 + MCBC_IO + CIO_FAILURE],0
    jne .sample_failed
    mov dword [rbx + MCB_RESULT],-22
    cmp dword [r14 + MCBC_AFTER + CSS_REV_VALID],1
    jne .report
    mov eax,[r14 + MCBC_AFTER + CSS_VENDOR]
    cmp eax,[rbx + MCB_SAMPLE + CSS_VENDOR]
    jne .report
    mov eax,[r14 + MCBC_AFTER + CSS_SIG]
    cmp eax,[rbx + MCB_SAMPLE + CSS_SIG]
    jne .report
    cmp dword [r14 + MCBC_AFTER + CSS_HV],0
    jne .report
    mov eax,[r14 + MCBC_AFTER + CSS_REV]
    mov [rbx + MCB_RECORD + MCS_AFTER],eax
    cmp eax,[rbx + MCB_SAMPLE + CSS_REV]
    jne .report
    mov dword [r14 + MCBC_POST_VALID],1
    mov dword [rbx + MCB_RESULT],MC_NONE
    jmp .report
.sample_failed:
    mov r10d,[r14 + MCBC_IO + CIO_FAILURE]
.io_failed:
    call cpu_checked_mc_status
    mov [rbx + MCB_RESULT],eax
.report:
    call cpu_microcode_boot_line
    call cpu_microcode_boot_tsc
    mov [rbx + MCB_TSC_END],rax
    lea rdi,[rel mcb_line]
    call serial_string
    mov dword [rbx + MCB_DONE],1
    mov dword [r14 + MCBC_READY],1
    movsxd rax,dword [rbx + MCB_RESULT]
    jmp .out
.legacy_done:
    ; Preserve raw caller's published prefix; checked evidence stays absent.
    mov dword [r14 + MCBC_READY],0
    mov rax,MC_E_STATE
    jmp .out
.existing:
    cmp eax,1
    jne .busy
    movsxd rax,dword [rbx + MCB_RESULT]
    jmp .out
.busy:
    mov rax,MC_E_BUSY
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.state_bad:
    mov rax,MC_E_STATE
    ret

; EDI expected full APIC -> immutable MCBC record or0. No CPU/I/O action.
; Unknown identity has a completed legacy refusal, but no owned checked row.
cpu_microcode_boot_checked_get:
    lea rax,[rel mcbc_state]
    cmp dword [rax + MCBC_READY],1
    jne .absent
    cmp dword [rax + MCBC_OWNER_VALID],1
    jne .absent
    cmp [rax + MCBC_OWNER],edi
    jne .absent
    ret
.absent:
    xor eax,eax
    ret

%include "core/abi/wdata.inc"
%macro WDATA_cpu_microcode_bsp_checked 0
align 16, db 0
mcbc_state: times MCBC_SIZE db 0
%endmacro
WDATA_DEFER WDATA_cpu_microcode_bsp_checked
