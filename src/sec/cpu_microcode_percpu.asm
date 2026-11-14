;; MODULE sec/cpu_microcode_percpu
;; LAYER 2
;; EXPORTS cpu_microcode_percpu_early, cpu_microcode_percpu_get
;; IMPORTS sec/cpu_microcode_checked, sec/cpu_microcode_boot, sec/cpu_microcode, sec/cpu_security, core/idt
;; CAPS
;; OWNER saga:security
; Early AP-local attempt, after private stack/GDT/TSS/IST and IDT, before
; scheduler/topology capability consumers. IF=0. Normal profile only. Uses
; ONLY the immutable pack admitted before EBS, never BSP selection/sample.
; Write-once per-dense-index records bind the full actual local APIC identity.
; A bounded lock serializes the established single exact-RIP #GP slot; busy
; is UNKNOWN, not permission to fall back to raw I/O or a boot/online gate.
; The getter reports evidence, never fleet completeness or mitigation policy.
MCP_COUNT equ 32
MCP_STRIDE equ 2048
MCP_READY equ 0                       ; 0 absent,2 writing,1 immutable
MCP_APIC equ 4                        ; expected full identity from validated mapping
MCP_RESULT equ 8
MCP_LOAD_MATCH equ 12                 ; guarded load+matching readback only
MCP_PID equ 16
MCP_POST_VALID equ 20                 ; fresh complete checked sample, same CPU
MCP_ACTUAL_APIC equ 24                ; independently observed local identity
MCP_OWNER_VALID equ 28                ; actual identity observation available
MCP_RECORD equ 32                     ; existing MCS_SIZE ABI
MCP_BEFORE equ 80                     ; independent full CSS
MCP_AFTER equ 192                     ; fresh full CSS, never before copied
MCP_IO equ 304                        ; bounded caller-owned CIO transcript
MCP_APPLY equ 1376                    ; independent MCA completion flags
; Additive private tail, original result/CSS/CIO/apply ABI remains fixed.
MCP_COST_CPU equ 1408
MCP_COST_PROFILE equ 1412
MCP_COST_OP equ 1416                  ; 0 no branch,1 checked apply,2 current readback
MCP_COST_VALID equ 1420               ; both local timestamps published
MCP_COST_START equ 1424
MCP_COST_END equ 1432
MCP_COST_VERSION equ 1440
MCP_SKIPPED equ 4                     ; Safe/Rescue: no CPUID/MSR/update I/O
MCP_E_OWNER equ -21
MCP_E_POST equ -22
%if MCP_APPLY + MCA_SIZE > MCP_COST_CPU || MCP_COST_VERSION + 4 > MCP_STRIDE
    %error "per CPU microcode record overflow"
%endif

; EDI dense logical id, ESI validated full APIC id. Once per AP, IF=0.
; -> EAX recorded result; all callee saves preserved. No online gate on result.
cpu_microcode_percpu_early:
    cmp edi,MCP_COUNT
    jae .bad
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r14d,esi
    mov ebx,edi
    shl rbx,11
    lea rax,[rel cpu_microcode_percpu_slots]
    add rbx,rax
    xor eax,eax
    mov edx,2
    lock cmpxchg dword [rbx + MCP_READY],edx
    jne .existing
    mov [rbx + MCP_APIC],r14d
    mov [rbx + MCP_COST_CPU],edi
    movzx eax,byte [rel pbm_profile]
    mov [rbx + MCP_COST_PROFILE],eax
    mov dword [rbx + MCP_COST_VERSION],1
    mov dword [rbx + MCP_RESULT],MCP_SKIPPED
    cmp byte [rel pbm_profile],PBM_PROFILE_NORMAL
    jne .publish                      ; Safe/Rescue do not even sample/TSC
    lea rdi,[rbx + MCP_COST_START]
    call cpu_microcode_percpu_stamp
    lea rdi,[rbx + MCP_IO]
    mov esi,r14d
    call cpu_checked_io_init
    call idt_gp_fixup_cpu
    mov [rbx + MCP_ACTUAL_APIC],eax
    cmp eax,-1
    je .owner_bad
    mov dword [rbx + MCP_OWNER_VALID],1
    cmp eax,r14d
    jne .owner_bad
    mov r15d,4096                     ; bounded try, never wait on another AP forever
.lock:
    xor eax,eax
    mov edx,1
    lock cmpxchg dword [rel cpu_microcode_percpu_lock],edx
    je .locked
    pause
    dec r15d
    jnz .lock
    mov dword [rbx + MCP_RESULT],MC_E_BUSY
    jmp .publish
.owner_bad:
    mov dword [rbx + MCP_RESULT],MCP_E_OWNER
    jmp .publish
.locked:
    mov dword [rbx + MCP_IO + CIO_PHASE],1
    lea rdi,[rbx + MCP_BEFORE]
    mov esi,CSS_SIZE
    lea rdx,[rbx + MCP_IO]
    call cpu_security_sample_checked
    mov dword [rbx + MCP_RESULT],MC_E_REVISION
    cmp dword [rbx + MCP_IO + CIO_FAILURE],0
    jne .sample_failed
    cmp dword [rbx + MCP_BEFORE + CSS_REV_VALID],1
    jne .unlock
    mov dword [rbx + MCP_RESULT],MCB_NOPACK
    mov r12,[rel mcb_pack_buf]
    mov r13,[rel mcb_pack_len]
    test r12,r12
    jz .unlock
    test r13,r13
    jz .unlock
    mov rdi,r12
    mov rsi,r13
    mov edx,[rbx + MCP_BEFORE + CSS_VENDOR]
    call ucode_pack_slice
    mov [rbx + MCP_RESULT],eax
    test eax,eax
    jnz .unlock
    mov r12,rdi
    mov r13,rsi
    xor ecx,ecx
    cmp dword [rbx + MCP_BEFORE + CSS_VENDOR],1
    jne .select
    ; The checked sample admitted Intel family6 bare metal with MSR support;
    ; don't read platform ID when any of those conditions is unavailable.
    cmp dword [rbx + MCP_BEFORE + CSS_HV],0
    jne .select
    mov dword [rbx + MCP_IO + CIO_PHASE],2
    lea rdi,[rbx + MCP_IO]
    mov esi,1
    mov ecx,0x17
    call cpu_checked_io
    cmp r10d,1
    jne .io_failed
    mov ecx,edx
    shr ecx,18
    and ecx,7
.select:
    mov [rbx + MCP_PID],ecx
    mov rdi,r12
    mov rsi,r13
    lea rdx,[rbx + MCP_BEFORE]
    lea r8,[rbx + MCP_RECORD]
    call cpu_microcode_select
    mov [rbx + MCP_RESULT],eax
    cmp eax,MC_NONE
    je .current
    cmp eax,MC_SELECTED
    jne .unlock
    mov dword [rbx + MCP_IO + CIO_PHASE],3
    mov rdi,r12
    mov rsi,r13
    lea rdx,[rbx + MCP_BEFORE]
    lea r8,[rbx + MCP_RECORD]
    lea rax,[rbx + MCP_IO]
    mov [rbx + MCP_APPLY + MCA_IO],rax
    lea rax,[rbx + MCP_AFTER]
    mov [rbx + MCP_APPLY + MCA_POST],rax
    lea r9,[rbx + MCP_APPLY]
    mov dword [rbx + MCP_COST_OP],1
    call cpu_microcode_apply_checked
    mov [rbx + MCP_RESULT],eax
    mov eax,[rbx + MCP_APPLY + MCA_LOAD_MATCH]
    mov [rbx + MCP_LOAD_MATCH],eax
    mov eax,[rbx + MCP_APPLY + MCA_POST_VALID]
    mov [rbx + MCP_POST_VALID],eax
    jmp .unlock
.current:
    mov dword [rbx + MCP_COST_OP],2
    ; No newer selection still requires an independent checked local readback.
    ; No update trigger, raw fallback or copied firmware sample is permitted.
    mov dword [rbx + MCP_IO + CIO_PHASE],4
    lea rdi,[rbx + MCP_AFTER]
    mov esi,CSS_SIZE
    lea rdx,[rbx + MCP_IO]
    call cpu_security_sample_checked
    cmp dword [rbx + MCP_IO + CIO_FAILURE],0
    jne .sample_failed
    mov dword [rbx + MCP_RESULT],-22
    cmp dword [rbx + MCP_AFTER + CSS_REV_VALID],1
    jne .unlock
    mov eax,[rbx + MCP_AFTER + CSS_VENDOR]
    cmp eax,[rbx + MCP_BEFORE + CSS_VENDOR]
    jne .unlock
    mov eax,[rbx + MCP_AFTER + CSS_SIG]
    cmp eax,[rbx + MCP_BEFORE + CSS_SIG]
    jne .unlock
    cmp dword [rbx + MCP_AFTER + CSS_HV],0
    jne .unlock
    mov eax,[rbx + MCP_AFTER + CSS_REV]
    mov [rbx + MCP_RECORD + MCS_AFTER],eax
    cmp eax,[rbx + MCP_BEFORE + CSS_REV]
    jne .unlock
    mov dword [rbx + MCP_POST_VALID],1
    mov dword [rbx + MCP_RESULT],MC_NONE
    jmp .unlock
.sample_failed:
    mov r10d,[rbx + MCP_IO + CIO_FAILURE]
.io_failed:
    call cpu_checked_mc_status
    mov [rbx + MCP_RESULT],eax
.unlock:
    mov dword [rel cpu_microcode_percpu_lock],0
.publish:
    cmp qword [rbx + MCP_COST_START],0
    je .publish_ready
    lea rdi,[rbx + MCP_COST_END]
    call cpu_microcode_percpu_stamp
    mov dword [rbx + MCP_COST_VALID],1
.publish_ready:
    ; WB stores publish all observations before READY. Never rewritten this boot.
    mov dword [rbx + MCP_READY],1
    mov eax,[rbx + MCP_RESULT]
    jmp .out
.existing:
    cmp eax,1
    jne .unavailable
    cmp [rbx + MCP_APIC],r14d
    jne .unavailable
    mov eax,[rbx + MCP_RESULT]
    jmp .out
.unavailable:
    mov eax,MCP_E_OWNER
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.bad:
    mov eax,MC_E_ARGS
    ret

; RDI private qword destination. Same-CPU elapsed TSC only; never converted
; with BSP rate/origin. No CPUID/MSR, exception slot, IF or policy changes.
; Preserve live RAX/EDX/flags across both original-path call sites.
cpu_microcode_percpu_stamp:
    pushfq
    push rax
    push rdx
    lfence
    rdtsc
    lfence
    shl rdx,32
    or rax,rdx
    mov [rdi],rax
    pop rdx
    pop rax
    popfq
    ret

; EDI dense logical, ESI expected full APIC -> immutable MCP_STRIDE record or0.
; Absent/writing/mismatched is UNKNOWN; no I/O, dispatch or all-CPU assertion.
cpu_microcode_percpu_get:
    cmp edi,MCP_COUNT
    jae .absent
    mov eax,edi
    shl rax,11
    lea rdx,[rel cpu_microcode_percpu_slots]
    add rax,rdx
    cmp dword [rax + MCP_READY],1
    jne .absent
    cmp [rax + MCP_APIC],esi
    jne .absent
    ret
.absent:
    xor eax,eax
    ret

%include "core/abi/wdata.inc"
%macro WDATA_cpu_microcode_percpu 0
align 128, db 0
cpu_microcode_percpu_lock: dd 0
align 128, db 0
cpu_microcode_percpu_slots: times MCP_COUNT * MCP_STRIDE db 0
%endmacro
WDATA_DEFER WDATA_cpu_microcode_percpu
