;; MODULE svc/app_execution_state
;; LAYER 5
;; PURPOSE Native installed-app catalog mutation barrier, not execution authority.
;; EXPORTS app_execution_invalidate, app_execution_uncertain, app_execution_generation, app_execution_current
;; IMPORTS
;; CAPS
;; OWNER saga:app_store
;; CONTEXT: bsp_only
; Fixed native install/remove callers only, before the original catalog write.
; No command/guest API, filesystem IO, receipt input, key or execution grant.
; Future unsigned staging must independently authenticate the installed row and
; bind this boot-local generation; subsequent descriptor reads need no FS IO.

; Preserve every GPR. Advancing before any possible effect invalidates retained
; unsigned bindings. Saturation quarantines instead of wrapping/reusing a value.
app_execution_invalidate:
    cmp qword [rel aes_generation],-1
    je app_execution_uncertain
    inc qword [rel aes_generation]
    ret

; Preserve every GPR, including the original writer's actual result in RAX.
; An uncertain write may have copied an HMAC-valid policy. No later write,
; logout, or script retirement may turn those bytes into this boot's approval.
app_execution_uncertain:
    mov byte [rel aes_quarantined],1
    ret

; RAX native generation, RDX1 available/0 quarantined. Observation only.
app_execution_generation:
    mov rax,[rel aes_generation]
    xor edx,edx
    cmp byte [rel aes_quarantined],0
    jne .out
    cmp rax,-1
    je .out
    inc edx
.out:
    ret

; RDI retained native generation -> EAX1 current/0 stale or quarantined.
; Matching this counter alone never establishes installed-row authority.
app_execution_current:
    xor eax,eax
    cmp byte [rel aes_quarantined],0
    jne .out
    cmp qword [rel aes_generation],-1
    je .out
    cmp rdi,[rel aes_generation]
    jne .out
    inc eax
.out:
    ret

%macro WDATA_BSS_app_execution_state 0
alignb 8
aes_generation: resq 1
aes_quarantined: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_app_execution_state
