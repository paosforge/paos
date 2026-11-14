;; MODULE svc/runtime_failure_sources
;; LAYER 5
;; CONTEXT: bsp_only
;; EXPORTS runtime_failure_heap_source, runtime_failure_handles_source, runtime_failure_app_source, runtime_failure_memory_source, runtime_failure_queue_source, runtime_failure_reconnect_source, runtime_failure_reconnect_controlled_source
;; IMPORTS core/runtime_failure_record, core/failure_record, core/heap, svc/command, svc/native_fault
;; CAPS
;; OWNER rc-vm-claude
; Typed scalar observation only, after original control/containment. No retry,
; allocation, command, cleanup, power, grant or authority change here. Diagnostic
; persistence results never replace the original control response.
%include "core/abi/runtime_failure.inc"
%include "core/abi/memory_consumer.inc"

; EDI=original OOM control result. Counter delta, never allocator addresses.
runtime_failure_heap_source:
    test edi,edi
    jnz .out
    mov rcx,[rel heap_stat_oom]
    mov r8,[rel diag_failure_baseline]
    mov rdx,rcx
    sub rdx,r8
    jbe .out
    mov edi,RFR_HEAP
    mov esi,1 ; controlled insufficient-capacity refusal
    jmp runtime_failure_save
.out:
    ret

runtime_failure_handles_source:
    lea rax,[rel command_job_control_snapshot]
    cmp qword [rax],0
    jne .out
    mov rdx,[rax+56] ; original first/last accepted IDs and actual refusal count
    mov rcx,[rax+64]
    mov r8,[rax+32]
    mov edi,RFR_HANDLES
    mov esi,1
    jmp runtime_failure_save
.out:
    ret

runtime_failure_app_source:
    lea rax,[rel native_fault_snapshot]
    cmp qword [rax],0 ; original complete containment/restart/cleanup predicate
    jne .out
    mov rdi,[rax+8]
    cmp rdi,1
    ja .out
    mov rsi,rdi
    inc rsi
    neg rsi ; original typed PMOD -1 fault / -2 timeout cause
    cmp rsi,[rax+56]
    jne .out
    add edi,RFR_APPFAULT
    mov rdx,[rax+16]
    mov rcx,[rax+24]
    mov r8,[rax+32]
    jmp runtime_failure_save
.out:
    ret

; RDI=actual successful mbc_snapshot's kernel-only72B. Called after core lock
; released. Terminal cleanup only; record each actual job at most once. Latch
; before fallible persistence, so status cannot resend an uncertain diagnostic.
runtime_failure_memory_source:
    cmp qword [rdi+MBC_SUM_PHASE],MBC_DONE
    jne .out
    cmp qword [rdi+MBC_SUM_OWNED],0
    jne .out
    test qword [rdi+MBC_SUM_FLAGS],MBC_F_CLEAN
    jz .out
    mov rsi,[rdi+MBC_SUM_ERROR]
    cmp rsi,MBC_E_CANCELLED
    je .cancel
    cmp rsi,MBC_E_DEADLINE
    jne .out
    mov eax,RFR_DEADLINE
    jmp .record
.cancel:
    mov eax,RFR_CANCEL
.record:
    mov rdx,[rdi+MBC_SUM_JOB]
    test rdx,rdx
    jz .out
    cmp rdx,[rel runtime_failure_memory_job]
    je .out
    mov [rel runtime_failure_memory_job],rdx
    mov rcx,[rdi+MBC_SUM_WORK_UNTIL]
    mov r8,[rdi+MBC_SUM_CLEANUP_UNTIL]
    mov edi,eax
    jmp runtime_failure_save
.out:
    ret

; Only actual vfs_copy_enqueue -3 after staged carry cleared. Opaque numeric
; mount handle/mode, never file paths, text, owner ticket or filesystem pointer.
runtime_failure_queue_source:
    mov edx,edi
    mov ecx,esi
    xor r8d,r8d
    mov edi,RFR_QUEUE
    mov esi,3 ; original queue_full (-3), normalized positive typed reason
    jmp runtime_failure_save

; Actual consumed HID reprobe rejected. Selection0..3, original full serial and
; normalized generation supplied by original coordinator; no HC/class pointer.
runtime_failure_reconnect_source:
    mov r8,rdx
    mov rcx,rsi
    mov edx,edi
    mov edi,RFR_RECONNECT
    mov esi,1 ; class_reprobe_rejected; not a preguard/pending release claim
    jmp runtime_failure_save

; Coordinator requires action3 plus the actual guarded leaf readonly status=2 witness.
runtime_failure_reconnect_controlled_source:
    mov r8,rdx
    mov rcx,rsi
    mov edx,edi
    mov edi,RFR_RECONNECT
    mov esi,2 ; explicit LAB one-use post-power guarded reprobe rejection
    jmp runtime_failure_save

%include "core/abi/wdata.inc"
%macro WDATA_runtime_failure_sources 0
align 8,db 0
runtime_failure_memory_job: dq 0
%endmacro
WDATA_DEFER WDATA_runtime_failure_sources
