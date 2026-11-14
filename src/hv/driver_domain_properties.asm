;; MODULE hv/driver_domain_properties
;; LAYER 6
;; EXPORTS nd_properties_append, nd_learn_properties_text
;; IMPORTS hv/driver_domain, hv/driver_domain_learned, hv/driver_domain_data, gui/form_loader, core/lib/fmt
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Append observations to the existing scrollable Properties facts list. The
; original machine/CPU rows retain their positions. A signed record in RAM is
; explicitly distinct from a verified DATA record. No IO or identity mutation.
nd_properties_append:
    sub rsp,8
    lea rdi,[rel nd_props_domain]
    call form_live_put_str
    mov edi,[rel nd_state]
    call form_live_put_dec
    lea rdi,[rel nd_props_learned]
    call form_live_put_str
    mov eax,[rel nd_learn_state]
    lea rdi,[rel nd_props_invalid]
    cmp eax,6
    ja .label
    lea rdx,[rel nd_props_offsets]
    movsxd rax,dword [rdx+rax*4]
    add rax,rdx
    mov rdi,rax
.label:
    call form_live_put_str
    lea rdi,[rel nd_props_data]
    call form_live_put_str
    mov eax,[rel nd_learn_persist_state]
    lea rdi,[rel nd_props_invalid]
    cmp eax,4
    ja .data_label
    lea rdx,[rel nd_props_data_offsets]
    movsxd rax,dword [rdx+rax*4]
    add rax,rdx
    mov rdi,rax
.data_label:
    call form_live_put_str
    lea rdi,[rel nd_props_received]
    call form_live_put_str
    mov edi,[rel nd_learn_received]
    call form_live_put_dec
    lea rdi,[rel nd_props_sequence]
    call form_live_put_str
    xor edi,edi
    cmp dword [rel nd_learn_state],4
    jne .sequence
    mov rdi,[rel nd_learn_sequence]
.sequence:
    call form_live_put_dec
    add rsp,8
    ret
nd_props_domain: db ',driver_domain=',0
nd_props_learned: db ',learned_manifest=',0
nd_props_received: db ',learned_received=',0
nd_props_sequence: db ',learned_sequence=',0
nd_props_invalid: db 'unknown',0
nd_props_waiting: db 'waiting',0
nd_props_receiving: db 'receiving',0
nd_props_verified: db 'hash_verified',0
nd_props_signed: db 'signed_not_saved',0
nd_props_saved: db 'DATA_verified',0
nd_props_refused: db 'refused',0
nd_props_pending: db 'node_identity_pending',0
align 4
nd_props_offsets:
    dd nd_props_waiting-nd_props_offsets,nd_props_receiving-nd_props_offsets
    dd nd_props_verified-nd_props_offsets,nd_props_signed-nd_props_offsets
    dd nd_props_saved-nd_props_offsets,nd_props_refused-nd_props_offsets
    dd nd_props_pending-nd_props_offsets

nd_props_data: db ',learned_DATA=',0
nd_props_data_pending: db 'pending',0
nd_props_data_bound: db 'bound_not_saved',0
nd_props_data_verified: db 'verified',0
nd_props_data_uncertain: db 'uncertain',0
nd_props_data_refused: db 'refused',0
align 4
nd_props_data_offsets:
    dd nd_props_data_pending-nd_props_data_offsets,nd_props_data_bound-nd_props_data_offsets
    dd nd_props_data_verified-nd_props_data_offsets,nd_props_data_uncertain-nd_props_data_offsets
    dd nd_props_data_refused-nd_props_data_offsets

%ifdef PAOS_DRIVER_DOMAIN_EVERYBOOT
; Read-only projection of the EXACT reopened DATA record from the original
; successful save. No new read, signer, persistence attempt or guest census.
; Keep it separate from form_live_buf so full CPU diagnostics cannot clip it.
; The independent saved reader still requires full original record/provenance.
nd_learn_properties_text:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp dword [rel nd_learn_state],4
    jne .missing
    cmp dword [rel nd_learn_persist_state],2
    jne .missing
    mov rax,[rel nd_generation]
    test rax,rax
    jz .missing
    cmp rax,[rel nd_learn_persist_gen]
    jne .missing
    mov rbx,[rel nd_learn_verify_buffer]
    test rbx,rbx
    jz .missing
    cmp rax,[rbx+24]
    jne .missing
    mov rax,[rel boot_tsc_start]
    test rax,rax
    jz .missing
    cmp rax,[rbx+128]
    jne .missing
    lea rdi,[rbx+40]
    lea rsi,[rel nd_nonce]
    mov ecx,16
    cld
    repe cmpsb
    jne .missing
    mov rax,'DDLEARN1'
    cmp [rbx],rax
    jne .missing
    cmp dword [rbx+8],1
    jne .missing
    cmp dword [rbx+12],512
    jne .missing
    mov rax,[rbx+16]
    test rax,rax
    jz .missing
    cmp rax,[rel nd_learn_sequence]
    jne .missing
    mov r13d,[rbx+36]
    cmp r13d,29
    jb .missing
    cmp r13d,8388608
    ja .missing
    lea r12,[rbx+512]
    add r13,r12
    ; BEGIN is one bounded original line. Do not interpret any subsequent
    ; release-like field as the observed kernel release.
    mov rsi,r12
    lea rdi,[rel nd_props_begin]
    mov ecx,29
    call nd_props_match
    jne .missing
    mov r14,r12
    mov ecx,1024
.line:
    cmp r14,r13
    jae .missing
    cmp byte [r14],10
    je .find_release
    inc r14
    loop .line
    jmp .missing
.find_release:
    mov rsi,r12
.find:
    lea rax,[rsi+9]
    cmp rax,r14
    ja .missing
    lea rdi,[rel nd_props_release_key]
    mov ecx,9
    call nd_props_match
    je .release
    inc rsi
    jmp .find
.release:
    add rsi,9
    mov r12,rsi
    xor r15d,r15d
.release_byte:
    cmp rsi,r14
    jae .missing
    mov al,[rsi]
    cmp al,' '
    je .release_done
    cmp r15d,80
    jae .missing
    cmp al,'0'
    jb .release_punct
    cmp al,'9'
    jbe .release_next
    cmp al,'A'
    jb .release_punct
    cmp al,'Z'
    jbe .release_next
    cmp al,'a'
    jb .release_punct
    cmp al,'z'
    jbe .release_next
.release_punct:
    cmp al,'.'
    je .release_next
    cmp al,'_'
    je .release_next
    cmp al,'-'
    je .release_next
    cmp al,'+'
    jne .missing
.release_next:
    inc rsi
    inc r15d
    jmp .release_byte
.release_done:
    test r15d,r15d
    jz .missing
    lea rsi,[r14+1]
    lea rax,[rsi+17]
    cmp rax,r13
    ja .missing
    lea rdi,[rel nd_props_memory_key]
    mov ecx,17
    call nd_props_match
    jne .missing
    add rsi,17
    mov [rel nd_props_memory_ptr],rsi
    xor edx,edx
.memory:
    cmp rsi,r13
    jae .missing
    mov al,[rsi]
    cmp al,' '
    je .memory_done
    cmp edx,20
    jae .missing
    sub al,'0'
    cmp al,9
    ja .missing
    inc edx
    inc rsi
    jmp .memory
.memory_done:
    test edx,edx
    jz .missing
    mov [rel nd_props_memory_len],edx
    lea rax,[rsi+4]
    cmp rax,r13
    ja .missing
    cmp dword [rsi],0x0a426b20       ; " kB\n"
    jne .missing
    lea rax,[rel nd_props_report_buf]
    mov [rel nd_props_report_cur],rax
    xor r14d,r14d
.release_rows:
    lea rdi,[rel nd_props_release0]
    test r14d,r14d
    jz .release_label
    lea rdi,[rel nd_props_release1]
    cmp r14d,1
    je .release_label
    lea rdi,[rel nd_props_release2]
.release_label:
    call nd_props_put_str
    mov ecx,r15d
    cmp ecx,32
    jbe .release_copy
    mov ecx,32
.release_copy:
    sub r15d,ecx
    mov rdi,r12
    add r12,rcx
    call nd_props_put_n
    inc r14d
    test r15d,r15d
    jnz .release_rows
    lea rdi,[rel nd_props_memory_label]
    call nd_props_put_str
    mov rdi,[rel nd_props_memory_ptr]
    mov ecx,[rel nd_props_memory_len]
    call nd_props_put_n
    lea rdi,[rel nd_props_digest0]
    call nd_props_put_str
    lea rdi,[rbx+88]
    call nd_props_hex16
    lea rdi,[rel nd_props_digest1]
    call nd_props_put_str
    lea rdi,[rbx+104]
    call nd_props_hex16
    lea rdi,[rel nd_props_start_label]
    call nd_props_put_str
    mov rdi,[rbx+24]
    call nd_props_dec
    lea rdi,[rel nd_props_seq_label]
    call nd_props_put_str
    mov rdi,[rbx+16]
    call nd_props_dec
    lea rax,[rel nd_props_report_buf]
    jmp .out
.missing:
    lea rax,[rel nd_props_report_missing]
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RSI available bounded bytes, RDI constant prefix, ECX length. Preserve RSI.
nd_props_match:
    push rsi
    cld
    repe cmpsb
    pop rsi
    ret

; Construction is <400 bytes: <=80 release, <=20 KiB, two32 hex fragments,
; two u64 decimals and fixed labels. Every byte comes from checked extents.
nd_props_put_str:
    xor ecx,ecx
.count:
    cmp byte [rdi+rcx],0
    je nd_props_put_n
    inc ecx
    jmp .count
nd_props_put_n:
    mov rsi,[rel nd_props_report_cur]
.copy:
    test ecx,ecx
    jz .done
    mov al,[rdi]
    mov [rsi],al
    inc rdi
    inc rsi
    dec ecx
    jmp .copy
.done:
    mov byte [rsi],0
    mov [rel nd_props_report_cur],rsi
    ret
nd_props_hex16:
    mov rsi,[rel nd_props_report_cur]
    lea r8,[rel nd_props_hex]
    mov ecx,16
.next:
    movzx edx,byte [rdi]
    mov eax,edx
    shr eax,4
    mov al,[r8+rax]
    mov [rsi],al
    and edx,15
    mov al,[r8+rdx]
    mov [rsi+1],al
    inc rdi
    add rsi,2
    loop .next
    mov byte [rsi],0
    mov [rel nd_props_report_cur],rsi
    ret
nd_props_dec:
    sub rsp,8
    mov rsi,[rel nd_props_report_cur]
    call fmt_dec
    add [rel nd_props_report_cur],rax
    mov rsi,[rel nd_props_report_cur]
    mov byte [rsi],0
    add rsp,8
    ret

nd_props_begin: db 'PAOS_DRIVER_CENSUS_BEGIN v=1 '
nd_props_release_key: db ' release='
nd_props_memory_key: db 'MEMORY MemTotal: '
nd_props_release0: db 'Learned release0: ',0
nd_props_release1: db ',Learned release1: ',0
nd_props_release2: db ',Learned release2: ',0
nd_props_memory_label: db ',Learned MemTotal KiB: ',0
nd_props_digest0: db ',Learned SHA256[0]: ',0
nd_props_digest1: db ',Learned SHA256[1]: ',0
nd_props_start_label: db ',Learned START: ',0
nd_props_seq_label: db ',Learned sequence: ',0
nd_props_report_missing: db 'Learned report: Unavailable',0
nd_props_hex: db '0123456789abcdef'
%macro WDATA_driver_domain_properties_report 0
align 8
nd_props_memory_ptr: dq 0
nd_props_memory_len: dd 0
align 8
nd_props_report_cur: dq 0
nd_props_report_buf: times 512 db 0
%endmacro
WDATA_DEFER WDATA_driver_domain_properties_report
%endif
