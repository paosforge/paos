;; MODULE svc/reinit_power_ram
;; LAYER 5
;; EXPORTS reinit_power_ram_register, reinit_power_ram_gate, reinit_power_ram_work_gate
;; IMPORTS svc/reinit_power, svc/command_reinit, fs/blockdev, dev/blk/ramblk, core/lib/mem
;; CAPS
;; OWNER saga:resource
;; CONTEXT: bsp_only
; Opt-in reference attachment to the EXISTING REINIT ramblk target and work
; queue. No boot registration, raw disk fallback, firmware or DMA/MMIO action.
%include "core/abi/driver_power.inc"

; Verify actual class membership before trusting cached REINIT dev/priv.
reinit_power_ram_owner:
    push rbx
    push r12
    sub rsp, 8
    mov rbx, rdi
    xor edi, edi
    mov r12d, BLK_REGISTRY_LIMIT
.next:
    xor esi, esi
    xor edx, edx
    call blk_iter_after
    test rax, rax
    jz .bad
    cmp rax, rbx
    je .found
    mov rdi, rax
    dec r12d
    jnz .next
.bad:
    mov rax, DP_CHANGED
    jmp .out
.found:
    lea rax, [rel ramblk_ops]
    cmp [rbx + dev.ops], rax
    jne .bad
    mov rax, [rbx + dev.info]
    test rax, rax
    jz .bad
    cmp dword [rax + blk_info.logical_sector_bytes], 512
    jne .bad
    cmp qword [rax + blk_info.media_generation], 0
    je .bad
    cmp qword [rbx + dev.priv], 0
    je .bad
    xor eax, eax
.out:
    add rsp, 8
    pop r12
    pop rbx
    ret

; RDI=initialized power plan. One sidecar for the existing single REINIT target;
; it cannot be rebound/reset while an old plan or work item owns it.
reinit_power_ram_register:
    push rbx
    push r12
    sub rsp, 8
    cld
    mov r12, rdi
    mov rax, DP_BUSY
    cmp qword [rel reinit_power_ram_context], 0
    jne .out
    call reinit_get_dev
    test rax, rax
    jz .unsupported
    mov rbx, rax
    mov rdi, rbx
    call reinit_power_ram_owner
    test rax, rax
    jnz .out
    lea rsi, [rel reinit_power_ram_declaration]
    mov dword [rsi + dp_driver.version], DP_VERSION
    mov dword [rsi + dp_driver.kind], DP_STORAGE
    mov [rsi + dp_driver.owner], rbx
    mov rax, [rbx + dev.info]
    lea rdx, [rax + blk_info.media_generation]
    mov [rsi + dp_driver.generation_ptr], rdx
    mov rax, [rdx]
    mov [rsi + dp_driver.generation], rax
    lea rax, [rel reinit_power_ram_callback]
    mov [rsi + dp_driver.callback], rax
    mov dword [rsi + dp_driver.dependencies], 0
    mov dword [rsi + dp_driver.capabilities], DP_CAP_FLUSH
    mov rdi, r12
    call reinit_power_register
    test rax, rax
    jnz .out
    mov [rel reinit_power_ram_context], r12
    jmp .out
.unsupported:
    mov rax, DP_UNSUPPORTED
.out:
    add rsp, 8
    pop r12
    pop rbx
    cld
    ret

; Existing REINIT mutation handlers call this additive gate. When unattached,
; old semantics are byte-for-byte equivalent; attached plans fence new work.
reinit_power_ram_gate:
    mov rdi, [rel reinit_power_ram_context]
    test rdi, rdi
    jz .unattached
    push rbx
    mov rsi, [rdi + dp_context.token]
    mov rdx, [rel reinit_power_ram_declaration + dp_driver.owner]
    mov rbx, rdx
    mov rcx, [rel reinit_power_ram_declaration + dp_driver.generation]
    call reinit_power_admit
    test rax, rax
    jnz .attached_out
    mov rdi, rbx
    call reinit_power_ram_owner           ; deregistration also fences admission
.attached_out:
    pop rbx
    ret
.unattached:
    xor eax, eax
    ret

; An attached single-item reference queue supplies backpressure before taking
; a new nonce. Existing unattached REINIT behavior is preserved.
reinit_power_ram_work_gate:
    sub rsp, 8
    call reinit_power_ram_gate
    add rsp, 8
    test rax, rax
    jnz .out
    cmp qword [rel reinit_power_ram_context], 0
    je .out
    cmp byte [rel reinit_work_state], 1
    jne .out
    mov rax, DP_BUSY
.out:
    ret

; Callback ABI shared with every class. RAM has no IRQ/DMA engine; its flush
; acknowledges only this volatile reference medium, never disk durability.
reinit_power_ram_callback:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12d, esi
    mov r13, rdx
    cmp rcx, [rel reinit_power_ram_context]
    jne .changed
    call reinit_power_ram_owner
    test rax, rax
    jnz .changed
    cmp r12d, DP_FENCE
    je .fence
    cmp r12d, DP_STOP
    je .stop
    cmp r12d, DP_RESTORE
    je .restore
    cmp r12d, DP_VERIFY
    jne .unsupported
    cmp r13, [rel reinit_power_ram_token]
    jne .untouched                      ; cancelled before this owner's FENCE
    ; Independent useful-readiness verification: preserved canary AND a sector
    ; read must still match bytes captured before the stop/reinit boundary.
    mov rax, [rbx + dev.priv]
    lea rdi, [rax + ramblk_priv.canary]
    lea rsi, [rel reinit_power_ram_canary]
    mov edx, 48
    call memcmp
    test eax, eax
    jnz .failed
    mov rdi, rbx
    mov esi, 3
    mov edx, 1
    lea rcx, [rel reinit_power_ram_after]
    call blk_read
    test rax, rax
    jnz .failed
    lea rdi, [rel reinit_power_ram_before]
    lea rsi, [rel reinit_power_ram_after]
    mov edx, 512
    call memcmp
    test eax, eax
    jnz .failed
    cmp byte [rel reinit_power_ram_work], 1
    jne .ready
    lea rdi, [rel reinit_work_nonce]
    lea rsi, [rel reinit_power_ram_nonce]
    mov edx, 41
    call memcmp
    test eax, eax
    jnz .failed
    cmp byte [rel reinit_work_state], 1
    jne .failed
    mov rdi, rbx
    call reinit_run_work                 ; existing gated write/read/byte compare
    test rax, rax
    jnz .failed
    mov byte [rel reinit_work_state], 2   ; exactly once after actual completion
    mov byte [rel reinit_power_ram_work], 0
    inc qword [rel reinit_power_ram_completions]
.ready:
    mov edx, DP_ACK_FENCED | DP_ACK_READY
    jmp .ok
.untouched:
    mov rdi, rbx
    mov esi, 3
    mov edx, 1
    lea rcx, [rel reinit_power_ram_after]
    call blk_read                       ; still independently verify readiness
    test rax, rax
    jnz .failed
    jmp .ready
.fence:
    mov rax, [rbx + dev.priv]
    lea rsi, [rax + ramblk_priv.canary]
    lea rdi, [rel reinit_power_ram_canary]
    mov edx, 48
    call memcpy
    mov al, [rel reinit_work_state]
    mov [rel reinit_power_ram_work], al
    lea rdi, [rel reinit_power_ram_nonce]
    lea rsi, [rel reinit_work_nonce]
    mov edx, 41
    call memcpy
    mov [rel reinit_power_ram_token], r13
    mov rdi, rbx
    mov esi, 3
    mov edx, 1
    lea rcx, [rel reinit_power_ram_before]
    call blk_read
    test rax, rax
    jnz .failed
    mov edx, DP_ACK_FENCED
    jmp .ok
.stop:
    mov rdi, rbx
    call blk_flush                      ; failure is NOT best-effort success
    test rax, rax
    jnz .failed
    mov edx, DP_ACK_FENCED | DP_ACK_DRAINED | DP_ACK_FLUSHED
    jmp .ok
.restore:
    cmp r13, [rel reinit_power_ram_token]
    jne .changed
    mov rdi, rbx
    call blk_reinit                     ; existing identify/geometry/verify seam
    test rax, rax
    jnz .failed
    mov edx, DP_ACK_FENCED
.ok:
    xor eax, eax
    jmp .out
.failed:
    mov rax, DP_FAILED
    jmp .error
.changed:
    mov rax, DP_CHANGED
    jmp .error
.unsupported:
    mov rax, DP_UNSUPPORTED
.error:
    xor edx, edx
.out:
    pop r13
    pop r12
    pop rbx
    cld
    ret

%macro WDATA_svc_reinit_power_ram 0
align 8
reinit_power_ram_context: dq 0
reinit_power_ram_declaration: times dp_driver_size db 0
reinit_power_ram_token: dq 0
reinit_power_ram_completions: dq 0
reinit_power_ram_work: db 0
reinit_power_ram_nonce: times 41 db 0
reinit_power_ram_canary: times 48 db 0
reinit_power_ram_before: times 512 db 0
reinit_power_ram_after: times 512 db 0
%endmacro
WDATA_DEFER WDATA_svc_reinit_power_ram
