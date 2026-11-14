;; MODULE core/mca_poll
;; LAYER 1
;; EXPORTS mca_corrected_tick, mca_poll_rows, mca_poll_coverage_copy, mca_poll_coverage_rows, mca_poll_observed_copy
;; IMPORTS core/mca_cmci, core/time, core/diag, core/mca_control
;; CAPS
;; OWNER saga:core
; CPU-local Intel MCA / qualified AMD SMCA corrected observations.
; One caller per dense
; logical CPU (BSP idle or that AP's scheduler loop), never an IRQ callback.
; Intel SDM vol.3B: MCG_CAP.COUNT, MCi_STATUS.VAL[63] / UC[61].
; STATUS polling plus CPU-local control capture; no ADDR/MISC access.
; The CMCI module claims Intel banks and clears only committed owned records;
; unowned Intel and all qualified AMD observations remain read-only.
; AMD requires AuthenticAMD, the base MSR/MCE/MCA features, and advertised
; CPUID.80000007:EBX.ScalableMca. Only its C0002001h+bank*10h STATUS is read.
; Legacy AMD and unknown vendors remain unqualified. No CTL/CONFIG writes.
; AMD deferred, poison and corrupt/nonrestartable context are not corrected.
; Changed non-corrected VAL=1 samples receive a separate raw observation log;
; this passive poll neither clears them nor claims handling/containment.
;
; Counters describe changed sampled status, NOT hardware error totals: a bank
; can change between polls, shared banks can be observed by multiple CPUs, and
; identical later errors on unowned banks without an observed intervening change
; are suppressed. Owned corrected records clear STATUS after a committed log.
; Ring append can drop on contention; persistence remains the existing policy.
%include "core/abi/mca_poll.inc"

; EDI=dense logical CPU index (not APIC id). Preserves SysV nonvolatiles.
mca_corrected_tick:
    cmp edi, MCA_POLL_CPUS
    jae .ret
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,32
    mov r12d, edi
    imul r13, r12, MCA_POLL_STRIDE
    lea rax, [rel mca_poll_rows]
    add r13, rax
    call time_monotonic_now_us
    test rax, rax
    jz .done                            ; no usable clock: no MSR access
    cmp qword [r13 + MCA_POLL_DUE], -1
    je .done                            ; exhausted clock range: never wrap/rescan
    cmp rax, [r13 + MCA_POLL_DUE]
    jb .done
    mov [rsp+16],rax                     ; actual scan start, before qualification
    add rax, MCA_POLL_INTERVAL
    jnc .set_due
    mov rax, -1
.set_due:
    mov [r13 + MCA_POLL_DUE], rax
    mov eax,r12d
    shl eax,6
    lea rdx,[rel mca_poll_coverage_rows]
    add rax,rdx
    mov [rsp+24],rax
    inc qword [rax+MCA_Q_SEQ]             ; CPU-private writer, odd until complete
    mov dword [rax+MCA_Q_SCANNED],0
    cmp byte [r13 + MCA_POLL_QUAL], 0
    jne .qualified
    xor eax, eax
    cpuid
    cmp ebx, 0x756e6547                  ; GenuineIntel
    jne .check_amd
    cmp edx, 0x49656e69
    jne .vendor
    cmp ecx, 0x6c65746e
    jne .vendor
    mov r14d, 1                         ; layout survives CPUID
    jmp .base_features
.check_amd:
    cmp ebx, 0x68747541                  ; AuthenticAMD, all three words
    jne .vendor
    cmp edx, 0x69746e65
    jne .vendor
    cmp ecx, 0x444d4163
    jne .vendor
    mov r14d, 4
.base_features:
    cmp eax, 1
    jb .features
    mov eax, 1
    cpuid
    and edx, 0x40a0                     ; MSR + MCE + MCA, all required
    cmp edx, 0x40a0
    jne .features
    cmp r14d, 4
    jne .read_cap
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000007
    jb .features
    mov eax, 0x80000007
    cpuid
    test ebx, 8                         ; ScalableMca, not model-name inference
    jz .features
.read_cap:
    mov ecx, 0x179                      ; IA32_MCG_CAP
    rdmsr
    shl rdx, 32
    or rax, rdx
    mov [r13 + MCA_POLL_CAP], rax
    movzx eax, al                       ; COUNT only, ignore other capability bits
    cmp eax, MCA_POLL_BANKS
    jbe .bounded
    mov eax, MCA_POLL_BANKS
.bounded:
    mov [r13 + MCA_POLL_NBANK], eax
    mov [r13 + MCA_POLL_QUAL], r14b
.qualified:
    cmp byte [r13 + MCA_POLL_QUAL], 1
    je .scan
    cmp byte [r13 + MCA_POLL_QUAL], 4
    jne .census_done
.scan:
    mov edi,r12d
    mov rsi,r13
    call mca_cmci_prepare                 ; qualified local setup, before status scan
    mov r14d, [r13 + MCA_POLL_NBANK]
    xor r15d, r15d
.bank:
    cmp r15d, r14d
    jae .controls
    lea ecx, [r15*4 + 0x401]            ; MCi_STATUS only
    cmp byte [r13 + MCA_POLL_QUAL], 4
    jne .status
    mov ecx, r15d
    shl ecx, 4
    add ecx, 0xc0002001                 ; AMD scalable STATUS, no legacy alias
.status:
    rdmsr
    shl rdx, 32
    or rax, rdx
    mov rcx,[rsp+24]
    bts dword [rcx+MCA_Q_SCANNED],r15d
    bt rax,63                           ; Intel/AMD STATUS.VAL qualifies an error
    jnc .census_zero
    bts dword [rcx+MCA_Q_NONZERO],r15d
.census_zero:
    cmp rax,[r13+MCA_POLL_LAST+r15*8]
    je .unchanged_raw
    ; VAL-clear metadata changes do not describe an error transition. Preserve
    ; their raw value below, but do not disqualify a no-real-error observation.
    mov rdx,rax
    or rdx,[r13+MCA_POLL_LAST+r15*8]
    bt rdx,63
    jnc .unchanged_raw
    bts dword [rcx+MCA_Q_CHANGED],r15d
.unchanged_raw:
    ; All CPU-view STATUS slots are read, including a foreign shared bank.
    ; Ownership still excludes its event counting, logging and clearing.
    mov ecx,r12d
    shl ecx,6
    lea rdx,[rel mca_cmci_rows]
    bt dword [rdx+rcx+16],r15d
    jc .next
    cmp rax, [r13 + MCA_POLL_LAST + r15*8]
    je .next
    mov [r13 + MCA_POLL_LAST + r15*8], rax
    bt rax, 63                          ; VAL must be set
    jnc .next
    bt rax, 61                          ; UC must be clear
    jc .observed
    bt rax, 57                          ; PCC: never a corrected observation
    jc .observed
    cmp byte [r13 + MCA_POLL_QUAL], 4
    jne .corrected
    bt rax, 44                          ; Deferred is uncorrectable, even if UC=0
    jc .observed
    bt rax, 55                          ; TCC: thread cannot restart
    jc .observed
    bt rax, 43                          ; consumed poisoned data: no corrected claim
    jc .observed
.corrected:
    mov [rsp],rax                         ; status survives the ring writer
    mov r8, [r13 + MCA_POLL_COUNT]
    mov [rsp+8],r8
    cmp r8, -1
    je .record
    inc r8
.record:
    mov rdx, rax                        ; A=raw status
    mov edi, DIAG_K_MCA
    mov esi, r15d                       ; ARG=bank
    mov rcx, r12                        ; B=dense logical CPU
    lea r9, [rel mca_poll_tag]           ; C=software observation count
    cmp byte [r13 + MCA_POLL_QUAL], 4
    jne .append
    lea r9, [rel smca_poll_tag]
.append:
    call diag_ring_append
    ; Publish an owned count only after its ring commit. A concurrent report
    ; can never see the temporary increment of a refused owned record.
    test eax,eax
    jnz .publish_count
    mov edx,r12d
    shl edx,6
    lea rcx,[rel mca_cmci_rows]
    bt dword [rcx+rdx+12],r15d
    jc .count_done
.publish_count:
    mov rdx,[rsp+8]
    cmp rdx,-1
    je .store_count
    inc rdx
.store_count:
    mov [r13+MCA_POLL_COUNT],rdx
.count_done:
    mov ecx,eax                           ; native writer returns1 only on commit
    mov edi,r12d
    mov esi,r15d
    mov rdx,[rsp]
    call mca_cmci_recorded
    test eax,eax
    jz .next                              ; unowned read-only legacy observation
    mov qword [r13+MCA_POLL_LAST+r15*8],0   ; owned: allow a later identical error
    cmp eax,2
    jne .next
    mov rax,[rsp+8]                        ; busy ring: no clear and no count advance
    mov [r13+MCA_POLL_COUNT],rax
    jmp .next
.observed:
    ; The original STATUS and CPU/bank identity reach the existing ring. No
    ; CMCI acknowledgement or STATUS clear is offered for these observations.
    mov r8,[r13+MCA_POLL_OTHER_SEEN]
    cmp r8,-1
    je .observed_count
    inc r8
.observed_count:
    mov [r13+MCA_POLL_OTHER_SEEN],r8
    mov rdx,rax
    mov edi,DIAG_K_MCA
    mov esi,r15d
    mov rcx,r12
    lea r9,[rel mca_observed_tag]
    cmp byte [r13+MCA_POLL_QUAL],4
    jne .observed_log
    lea r9,[rel smca_observed_tag]
.observed_log:
    call diag_ring_append
    lea rdx,[r13+MCA_POLL_OTHER_DROP]
    cmp eax,1                           ; only the actual commit is logged
    jne .observed_result
    lea rdx,[r13+MCA_POLL_OTHER_LOG]
.observed_result:
    cmp qword [rdx],-1
    je .next
    inc qword [rdx]
.next:
    inc r15d
    jmp .bank
.controls:
    mov edi,r12d
    mov rsi,r13
    call mca_control_sample             ; same CPU, qualified layout only
    call time_monotonic_now_us
    mov rdx,[rsp+24]
    cmp qword [rdx+MCA_Q_POLLS],-1
    je .census_done
    inc qword [rdx+MCA_Q_POLLS]
    cmp qword [rdx+MCA_Q_FIRST],0
    jne .census_last
    mov rcx,[rsp+16]
    mov [rdx+MCA_Q_FIRST],rcx
.census_last:
    mov [rdx+MCA_Q_LAST],rax
    jmp .census_done
.vendor:
    mov byte [r13 + MCA_POLL_QUAL], 2
    jmp .census_done
.features:
    mov byte [r13 + MCA_POLL_QUAL], 3
.census_done:
    mov rdx,[rsp+24]
    mov rax,[r13+MCA_POLL_CAP]
    mov [rdx+MCA_Q_CAP],rax
    movzx eax,byte [r13+MCA_POLL_QUAL]
    mov [rdx+MCA_Q_QUAL],eax
    mov eax,[r13+MCA_POLL_NBANK]
    mov [rdx+MCA_Q_BANKS],eax
    inc qword [rdx+MCA_Q_SEQ]             ; release complete census on x86 TSO
.done:
    add rsp,32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
.ret:
    ret

; EDI dense CPU, RSI private64B -> EAX0 stable,1 busy/bad CPU.
; One bounded seqlock attempt; no waiting, sampling or hardware access.
mca_poll_coverage_copy:
    cmp edi,MCA_POLL_CPUS
    jae .busy
    mov eax,edi
    shl eax,6
    lea rdx,[rel mca_poll_coverage_rows]
    add rdx,rax
    mov r8,[rdx+MCA_Q_SEQ]
    test r8b,1
    jnz .busy
    mov rdi,rsi
    mov rsi,rdx
    mov ecx,8
    rep movsq
    cmp r8,[rdx+MCA_Q_SEQ]
    jne .busy
    xor eax,eax
    ret
.busy:
    mov eax,1
    ret

; EDI dense CPU, RSI private32B -> EAX0 stable /1 unavailable.
; Existing CPU-private scan sequence covers all three counters. One bounded
; attempt; qualification/initialization/busy never manufactures an empty sample.
mca_poll_observed_copy:
    cmp edi,MCA_POLL_CPUS
    jae .busy
    mov eax,edi
    shl eax,6
    lea rdx,[rel mca_poll_coverage_rows]
    add rdx,rax
    mov r8,[rdx+MCA_Q_SEQ]
    test r8,r8
    jz .busy
    test r8b,1
    jnz .busy
    imul eax,edi,MCA_POLL_STRIDE
    lea r9,[rel mca_poll_rows]
    add r9,rax
    movzx eax,byte [r9+MCA_POLL_QUAL]
    cmp eax,1
    je .copy
    cmp eax,4
    jne .busy
.copy:
    mov rax,[r9+MCA_POLL_OTHER_SEEN]
    mov [rsi],rax
    mov rax,[r9+MCA_POLL_OTHER_LOG]
    mov [rsi+8],rax
    mov rax,[r9+MCA_POLL_OTHER_DROP]
    mov [rsi+16],rax
    mov qword [rsi+24],0
    cmp r8,[rdx+MCA_Q_SEQ]
    jne .busy
    xor eax,eax
    ret
.busy:
    mov eax,1
    ret

mca_observed_tag: db 'mca-observed',0
smca_observed_tag: db 'smca-observed',0
mca_poll_tag: db 'mca-corrected', 0
smca_poll_tag: db 'smca-corrected', 0
; CPU state belongs in the page-isolated zero-fill tail, away from code.
%include "core/abi/wdata.inc"
%macro WDATA_mca_poll 0
mca_poll_rows: resb MCA_POLL_CPUS * MCA_POLL_STRIDE
alignb 64
mca_poll_coverage_rows: resb MCA_POLL_CPUS * MCA_Q_STRIDE
%endmacro
WDATA_BSS_DEFER WDATA_mca_poll
