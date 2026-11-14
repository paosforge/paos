; Actual per-core work projection for About Advanced / Next.
; form_percore_text -> RAX comma-delimited public rows, NUL, <=6144 bytes.
; Read-only: no dispatch, policy, work, clock sampling or stale one-second cache.
; Each field is an independent load; an original SMPSTAT bracket bounds it.
; Busy ticks describe PARFOR work, never utilization or scheduler time shares.
%include "core/abi/wdata.inc"
FORM_PERCORE_CAP equ 6144

form_percore_text:
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea r12,[rel percore_buf]
    lea rsi,[rel percore_heading]
    call percore_put
    mov r14d,[rel smp_discovered_count]
    test r14d,r14d
    jz .unsupported
    cmp r14d,32
    ja .unsupported
    cmp byte [rel smp_topology_overflow],0
    jne .unsupported
    xor ebx,ebx
.cpu:
    lea rax,[rel cpu_state]
    movzx r13d,byte [rax+rbx]
    call percore_prefix
    lea rsi,[rel percore_apic]
    call percore_put
    lea rax,[rel cpu_apic_id]
    mov edi,[rax+rbx*4]
    call percore_number
    lea rsi,[rel percore_state]
    call percore_put
    lea rsi,[rel percore_unknown]
    cmp r13d,4
    ja .state
    lea rax,[rel percore_states]
    mov rsi,[rax+r13*8]
    add rsi,rax
.state:
    call percore_put
    call percore_prefix
    lea rsi,[rel percore_ready]
    call percore_put
    lea rax,[rel cpu_runq_ready]
    movzx edi,byte [rax+rbx]
    call percore_number
    ; Snapshot both cumulative counters before publishing their rows. If the
    ; state changes during these loads, neither old nor new work is asserted.
    lea rax,[rel cpu_pf_chunks]
    mov r15,[rax+rbx*8]
    lea rax,[rel cpu_pf_busy_tsc]
    mov rdx,[rax+rbx*8]
    push rdx
    lea rax,[rel cpu_state]
    cmp r13b,[rax+rbx]
    jne .unavailable
    cmp r13d,1
    je .live
    cmp r13d,3
    jne .unavailable
.live:
    call percore_prefix
    lea rsi,[rel percore_chunks]
    call percore_put
    mov rdi,r15
    call percore_number
    call percore_prefix
    lea rsi,[rel percore_ticks]
    call percore_put
    pop rdi
    call percore_number
    jmp .next
.unavailable:
    pop rdx
    call percore_prefix
    lea rsi,[rel percore_chunks]
    call percore_put
    lea rsi,[rel percore_unavailable]
    call percore_put
    call percore_prefix
    lea rsi,[rel percore_ticks]
    call percore_put
    lea rsi,[rel percore_unavailable]
    call percore_put
.next:
    inc ebx
    cmp ebx,r14d
    jb .cpu
    jmp .done
.unsupported:
    lea rsi,[rel percore_unsupported]
    call percore_put
.done:
    mov byte [r12],0
    lea rax,[rel percore_buf]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

percore_prefix:
    lea rsi,[rel percore_cpu]
    call percore_put
    mov edi,ebx
    jmp percore_number

percore_number:
    lea rsi,[rel percore_num]
    call fmt_dec
    lea rsi,[rel percore_num]
    ; fall through to the bounded public string appender
percore_put:
    lea rax,[rel percore_buf+FORM_PERCORE_CAP-1]
.copy:
    cmp r12,rax
    jae .done
    mov dl,[rsi]
    test dl,dl
    jz .done
    mov [r12],dl
    inc r12
    inc rsi
    jmp .copy
.done:
    mov byte [r12],0
    ret

%macro WDATA_gui_form_percore 0
percore_heading: db 'Per-core PARFOR work ticks (not utilization)',0
percore_cpu: db ',CPU ',0
percore_apic: db ' APIC ',0
percore_state: db ' state ',0
percore_ready: db ' runq_ready ',0
percore_chunks: db ' work_chunks ',0
percore_ticks: db ' work_tsc ',0
percore_unknown: db 'unknown',0
percore_unavailable: db 'unavailable',0
percore_unsupported: db ',Per-core inventory unavailable',0
percore_discovered: db 'discovered',0
percore_bsp: db 'bsp',0
percore_pending: db 'pending',0
percore_online: db 'online',0
percore_failed: db 'failed',0
align 8
; org0 images relocate without fixing stored pointers; use the live anchor.
percore_states: dq percore_discovered-percore_states,percore_bsp-percore_states,percore_pending-percore_states,percore_online-percore_states,percore_failed-percore_states
percore_num: times 21 db 0
percore_buf: times FORM_PERCORE_CAP db 0
%endmacro
WDATA_DEFER WDATA_gui_form_percore
