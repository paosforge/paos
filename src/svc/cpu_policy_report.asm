;; MODULE svc/cpu_policy_report
;; LAYER 5
;; EXPORTS cpu_policy_report_capture, cpu_policy_report_page, cpu_policy_report_parse
;; IMPORTS core/smp, core/build_id, core/time, boot/header, sec/cpu_security_percpu, sec/cpu_microcode_percpu, sec/cpu_microcode_bsp_checked, sec/cpu_microcode_boot, hv/boundary_execution, core/lib/fmt
;; CAPS
;; OWNER saga:security
; Bounded serialized BSP read interface. Never samples/updates/dispatches a CPU.
; AUDIT cpu seals one cached historical snapshot, shared with Properties pages.
; Last completed paired receipt is NOT current/all-path/SMT mitigation efficacy.
; No policy selection/exemption, execution, private token or pointer is exported.
; 32 records768B, each in two384B pages (below both existing reply limits).
CPR_BYTES equ 768
CPR_PART equ 384
CPR_PAGES equ 64

cpu_policy_report_capture:
    push rbx
    push r12
    push r13
    push r14
    inc qword [rel cpr_epoch]
    call boot_ms_now
    mov r14,rax
    xor r12d,r12d
.cpu:
    imul ebx,r12d,CPR_BYTES
    lea rax,[rel cpr_records]
    add rbx,rax
    mov rdi,rbx
    xor eax,eax
    mov ecx,CPR_BYTES/8
    cld
    rep stosq
    mov qword [rbx],1
    mov [rbx+8],r12
    mov edi,r12d
    lea rsi,[rbx+16]
    call smp_cpu_report_copy
    mov rax,[rel boot_tsc_start]
    mov [rbx+80],rax
    movzx eax,byte [rel paos_build_state]
    mov [rbx+88],rax
    lea rdi,[rbx+96]
    lea rsi,[rel paos_build_measured]
    mov ecx,4
    rep movsq
    mov rax,[rel cpr_epoch]
    mov [rbx+128],rax
    mov [rbx+304],r14              ; snapshot boot-ms, never CPU elapsed time
    cmp dword [rbx+72],1          ; topology row exists; missing slots stay absent
    jne .next
    mov r13d,[rbx+32]             ; full APIC identity, zero is valid
    mov edi,r12d
    mov esi,r13d
    call cpu_security_percpu_get
    test rax,rax
    jz .ucode
    mov qword [rbx+136],1
    lea rdi,[rbx+144]
    mov rsi,rax
    mov ecx,14
    rep movsq
.ucode:
    cmp dword [rbx+36],1          ; CPU_STATE_BSP
    je .bsp
    mov edi,r12d
    mov esi,r13d
    call cpu_microcode_percpu_get
    test rax,rax
    jz .pair
    mov qword [rbx+256],1
    mov edx,[rax+MCP_RESULT]
    mov [rbx+264],edx
    mov dword [rbx+268],2
%macro CPR_AP 2
    mov edx,[rax+%2]
    mov [rbx+%1],edx
%endmacro
    CPR_AP 272,MCP_RECORD+MCS_REV
    CPR_AP 276,MCP_RECORD+MCS_AFTER
    CPR_AP 280,MCP_POST_VALID
    CPR_AP 284,MCP_OWNER_VALID
    CPR_AP 288,MCP_ACTUAL_APIC
    CPR_AP 292,MCP_LOAD_MATCH
%unmacro CPR_AP 2
    jmp .pair
.bsp:
    mov edi,r13d
    call cpu_microcode_boot_checked_get
    test rax,rax
    jz .pair
    cmp dword [rel mcb_state+MCB_DONE],1
    jne .pair
    mov qword [rbx+256],1
    mov edx,[rel mcb_state+MCB_RESULT]
    mov [rbx+264],edx
    mov dword [rbx+268],1
    mov edx,[rel mcb_state+MCB_RECORD+MCS_REV]
    mov [rbx+272],edx
    mov edx,[rel mcb_state+MCB_RECORD+MCS_AFTER]
    mov [rbx+276],edx
%macro CPR_BSP 2
    mov edx,[rax+%2]
    mov [rbx+%1],edx
%endmacro
    CPR_BSP 280,MCBC_POST_VALID
    CPR_BSP 284,MCBC_OWNER_VALID
    CPR_BSP 288,MCBC_OWNER
    CPR_BSP 292,MCBC_LOAD_MATCH
%unmacro CPR_BSP 2
.pair:
    mov edi,r12d
    lea rsi,[rbx+320]
    call hv_boundary_exec_copy
.next:
    inc r12d
    cmp r12d,32
    jb .cpu
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI canonical decimal page token, no spaces/suffix/leading zero. EAX page
; 0..63 or -1; bounded lookahead only after a nonzero preceding byte.
cpu_policy_report_parse:
    movzx eax,byte [rdi]
    sub eax,'0'
    cmp eax,9
    ja .bad
    cmp byte [rdi+1],0
    je .done
    test eax,eax
    jz .bad
    movzx edx,byte [rdi+1]
    sub edx,'0'
    cmp edx,9
    ja .bad
    cmp byte [rdi+2],0
    jne .bad
    imul eax,10
    add eax,edx
.done:
    cmp eax,CPR_PAGES
    jb .out
.bad:
    mov eax,-1
.out:
    ret

; RDI destination, ESI capacity, EDX page0..63. Cached only; no sampling or
; recapture. -1 clears destination if safe. Exact length excluding NUL, or -1.
cpu_policy_report_page:
    test rdi,rdi
    jz .bad_empty
    test esi,esi
    jz .bad_empty
    mov eax,esi
    add rax,rdi
    jc .bad_empty
    cmp edx,CPR_PAGES
    jae .bad
    cmp qword [rel cpr_epoch],0
    je .bad
    ; Fixed768 hex digits plus <240 header bytes; no truncation is possible.
    cmp esi,1024
    jb .bad
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,24
    mov rbx,rdi
    mov r12,rdi
    mov r13d,edx
    lea rsi,[rel cpr_prefix]
    call cpr_put
    mov edi,r13d
    call cpr_num
    lea rsi,[rel cpr_epoch_text]
    call cpr_put
    mov rdi,[rel cpr_epoch]
    call cpr_num
    lea rsi,[rel cpr_data_text]
    call cpr_put
    imul eax,r13d,CPR_PART
    lea r14,[rel cpr_records]
    add r14,rax
    mov r15d,CPR_PART
.hex:
    movzx eax,byte [r14]
    shr eax,4
    call cpr_nibble
    movzx eax,byte [r14]
    and eax,15
    call cpr_nibble
    inc r14
    dec r15d
    jnz .hex
    lea rsi,[rel cpr_suffix]
    call cpr_put
    mov byte [r12],0
    mov rax,r12
    sub rax,rbx
    add rsp,24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.bad:
    mov byte [rdi],0
.bad_empty:
    mov rax,-1
    ret
cpr_nibble:
    add al,'0'
    cmp al,'9'
    jbe .store
    add al,39
.store:
    mov [r12],al
    inc r12
    ret
cpr_num:
    lea rsi,[rsp+8]
    call fmt_dec
    lea rsi,[rsp+8]
cpr_put:
    lodsb
    test al,al
    jz .out
    mov [r12],al
    inc r12
    jmp cpr_put
.out:
    ret

cpr_prefix: db ' CPU_POLICY v=1 page=',0
cpr_epoch_text: db '/64 epoch=',0
cpr_data_text: db ' bytes=384 data=',0
cpr_suffix: db ' scope=last_pair coverage=incomplete end=1',0
%include "core/abi/wdata.inc"
%macro WDATA_cpu_policy_report 0
align 64,db 0
cpr_epoch: dq 0
cpr_records: times 32*CPR_BYTES db 0
%endmacro
WDATA_DEFER WDATA_cpu_policy_report
