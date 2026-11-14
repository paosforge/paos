;; MODULE gui/app_package_disclosure
;; LAYER 6
;; PURPOSE Bounded escaped native disclosure document from actual immutable analysis.
;; EXPORTS app_disclosure_open, app_disclosure_current, app_disclosure_line, app_disclosure_close
;; IMPORTS svc/app_analysis, svc/app_package, svc/command, core/heap, core/smp
;; OWNER saga:app_package
;; CONTEXT: bsp_only
; Native caller-owned records only, no guest interface, approval or effects.
; 6144 lines * 40 bytes: text31+NUL, warning:u64. No text is silently cut.
PD_LINES equ 6144
PD_RECORD equ 40
PD_BYTES equ (PD_LINES*PD_RECORD)

; RDI exact candidate -> EAX1/0, EDX line count. Builds a new frozen document.
app_disclosure_open:
    push rbx
    push r12
    push r13
    mov r12,rdi
    call smp_current_logical
    test eax,eax
    jnz .refuse
    cmp byte [rel cmd_in_dispatch],0
    jne .refuse
    cmp byte [rel pd_busy],0
    jne .refuse
    mov byte [rel pd_busy],1
    call pd_clear
    mov rdi,r12
    call app_analysis_build
    cmp eax,1
    jne .bad
    mov rdi,r12
    lea rsi,[rel pd_header]
    mov edx,192
    call app_analysis_descriptor
    cmp eax,1
    jne .bad
    mov rdi,r12
    lea rsi,[rel pd_package]
    mov edx,704
    call app_package_descriptor
    cmp eax,1
    jne .bad
    cmp qword [rel pd_header+24],128
    ja .bad
    ; Join the actual descriptors, including complete original package digest.
    mov rax,[rel pd_header+8]
    cmp rax,r12
    jne .bad
    cmp rax,[rel pd_package+8]
    jne .bad
    mov rax,[rel pd_header+16]
    cmp rax,[rel pd_package+24]
    jne .bad
    lea rsi,[rel pd_header+32]
    lea rdi,[rel pd_package+32]
    mov ecx,4
    cld
    repe cmpsq
    jne .bad
    cmp qword [rel pd_heap],0
    jne .allocated
    mov edi,PD_BYTES
    call kmalloc
    test rax,rax
    jz .bad
    mov [rel pd_heap],rax
    mov rdi,rax
    xor eax,eax
    mov ecx,PD_BYTES/8
    cld
    rep stosq
.allocated:
    mov [rel pd_handle],r12
    mov qword [rel pd_count],0
    mov qword [rel pd_column],0
    mov qword [rel pd_warning],0
    lea rsi,[rel pd_intro]
    call pd_literal
    cmp qword [rel pd_package+80],1
    je .enrolled
    lea rsi,[rel pd_unknown]
    jmp .author
.enrolled:
    lea rsi,[rel pd_enrolled]
.author:
    call pd_literal
    lea rsi,[rel pd_title_label]
    call pd_literal
    lea rsi,[rel pd_package+192+256]
    mov ecx,96
    call pd_text
    call pd_newline
    lea rsi,[rel pd_id_label]
    call pd_literal
    lea rsi,[rel pd_package+192+16]
    mov ecx,64
    call pd_text
    call pd_newline
    lea rsi,[rel pd_version_label]
    call pd_literal
    lea rsi,[rel pd_package+192+352]
    mov ecx,32
    call pd_text
    call pd_newline
    lea rsi,[rel pd_hash_label]
    call pd_literal
    lea rsi,[rel pd_package+32]
    mov ecx,32
    call pd_hexbytes
    call pd_newline
    lea rsi,[rel pd_key_label]
    call pd_literal
    lea rsi,[rel pd_package+64]
    mov ecx,16
    call pd_hexbytes
    call pd_newline
    cmp qword [rel pd_header+144],0
    je .facts
    mov qword [rel pd_warning],1
    lea rsi,[rel pd_incomplete]
    call pd_literal
    mov qword [rel pd_warning],0
.facts:
    xor r13d,r13d
.fact:
    cmp r13,[rel pd_header+24]
    jae .finish
    mov rdi,r12
    mov rsi,r13
    lea rdx,[rel pd_fact]
    mov ecx,256
    call app_analysis_fact
    cmp eax,1
    jne .bad
    ; Even a damaged consumer may never print a request as effective policy.
    cmp qword [rel pd_fact+48],0
    jne .bad
    mov qword [rel pd_warning],0
    cmp qword [rel pd_fact],5
    je .uncovered
    cmp qword [rel pd_fact+40],0
    je .uncovered
    cmp qword [rel pd_fact+40],3
    je .uncovered
    lea rsi,[rel pd_requested]
    jmp .coverage
.uncovered:
    mov qword [rel pd_warning],1
    lea rsi,[rel pd_uncovered]
.coverage:
    call pd_literal
    lea rsi,[rel pd_req_label]
    call pd_literal
    mov rax,[rel pd_fact+40]
    cmp rax,3
    ja .bad
    lea rdx,[rel pd_requests]
    mov rsi,[rdx+rax*8]
    add rsi,rdx
    call pd_literal
    lea rsi,[rel pd_effective]
    call pd_literal
    ; Exact integer locations, no ambiguous truncation or decimal overflow.
    lea rsi,[rel pd_loc_label]
    call pd_literal
    lea rsi,[rel pd_fact+8]
    mov ecx,8
    call pd_hexnumber
    call pd_newline
    lea rsi,[rel pd_offset_label]
    call pd_literal
    lea rsi,[rel pd_fact+16]
    call pd_hexnumber
    call pd_newline
    lea rsi,[rel pd_length_label]
    call pd_literal
    lea rsi,[rel pd_fact+24]
    call pd_hexnumber
    call pd_newline
    lea rsi,[rel pd_line_label]
    call pd_literal
    lea rsi,[rel pd_fact+32]
    call pd_hexnumber
    call pd_newline
    mov rax,[rel pd_fact]
    cmp rax,1
    jb .bad
    cmp rax,7
    ja .bad
    lea rdx,[rel pd_kinds]
    mov rsi,[rdx+rax*8-8]
    add rsi,rdx
    call pd_literal
    mov rax,[rel pd_fact+56]
    mov rbx,rax
    and eax,15
    cmp eax,1
    jb .bad
    cmp eax,13
    ja .bad
    lea rdx,[rel pd_reasons]
    mov rsi,[rdx+rax*8-8]
    add rsi,rdx
    call pd_literal
    test ebx,32
    jnz .readwrite
    test ebx,16
    jnz .write
    jmp .fact_text
.readwrite:
    lea rsi,[rel pd_readwrite]
    call pd_literal
    jmp .fact_text
.write:
    lea rsi,[rel pd_write]
    call pd_literal
.fact_text:
    lea rsi,[rel pd_text_label]
    call pd_literal
    lea rsi,[rel pd_fact+64]
    mov ecx,192
    call pd_text
    call pd_newline
    inc r13
    jmp .fact
.finish:
    mov qword [rel pd_warning],0
    lea rsi,[rel pd_end]
    call pd_literal
    cmp byte [rel pd_overflow],0
    jne .bad
    mov rdi,r12
    lea rsi,[rel pd_header]
    call app_analysis_check
    cmp eax,1
    jne .bad
    mov byte [rel pd_busy],0
    mov edx,[rel pd_count]
    mov eax,1
    jmp .out
.bad:
    call pd_clear
    mov byte [rel pd_busy],0
.refuse:
    xor eax,eax
    xor edx,edx
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Exact report freshness, not owner consent. Drift permanently retires display.
app_disclosure_current:
    call smp_current_logical
    test eax,eax
    jnz .no
    cmp byte [rel cmd_in_dispatch],0
    jne .no
    cmp byte [rel pd_busy],0
    jne .no
    cmp qword [rel pd_handle],0
    je .no
    mov rdi,[rel pd_handle]
    lea rsi,[rel pd_header]
    call app_analysis_check
    cmp eax,1
    je .yes
    call pd_clear
.no:
    xor eax,eax
    ret
.yes:
    mov edx,[rel pd_count]
    ret

; RDI line index, RSI disjoint trusted native out40, RDX exact40 ->1/0.
; No output on refusal. The native UI uses its private scratch, never guest RAM.
app_disclosure_line:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12,rsi
    cmp rdx,PD_RECORD
    jne .bad
    test r12,r12
    jz .bad
    mov rax,r12
    add rax,PD_RECORD
    jc .bad
    mov r13,[rel pd_heap]
    test r13,r13
    jz .bad
    cmp r12,r13
    jb .below
    lea rcx,[r13+PD_BYTES]
    cmp r12,rcx
    jb .bad
    jmp .checked
.below:
    cmp rax,r13
    ja .bad
.checked:
    lea rcx,[rel pd_header]
    cmp r12,rcx
    jb .below_private
    add rcx,192+704+256
    cmp r12,rcx
    jb .bad
    jmp .private_checked
.below_private:
    cmp rax,rcx
    ja .bad
.private_checked:
    call app_disclosure_current
    cmp eax,1
    jne .bad
    cmp rbx,[rel pd_count]
    jae .bad
    imul rsi,rbx,PD_RECORD
    add rsi,r13
    mov rdi,r12
    mov ecx,PD_RECORD/8
    cld
    rep movsq
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Native depth-zero callers/idle only. Wipe previously displayed package data.
app_disclosure_close:
    call smp_current_logical
    test eax,eax
    jnz .out
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    cmp byte [rel pd_busy],0
    jne .out
    jmp pd_clear
.out:
    ret
pd_clear:
    mov qword [rel pd_handle],0
    mov qword [rel pd_count],0
    mov qword [rel pd_column],0
    mov qword [rel pd_warning],0
    mov byte [rel pd_overflow],0
    mov rdi,[rel pd_heap]
    test rdi,rdi
    jz .buffers
    mov ecx,PD_BYTES/8
    xor eax,eax
    cld
    rep stosq
.buffers:
    lea rdi,[rel pd_header]
    mov ecx,(192+704+256)/8
    xor eax,eax
    cld
    rep stosq
    ret

; Document writer. Every output line has <=31 printable characters + NUL.
; Escapes controls, slash and markup delimiters as \xHH. LF/TAB cannot paint
; native controls. Wrapping may split an escape but never drops a byte.
pd_emit:
    push rax
    push rdx
    cmp qword [rel pd_column],31
    jb .room
    call pd_newline
.room:
    mov rdx,[rel pd_count]
    cmp rdx,PD_LINES-1
    jae .overflow
    imul rdx,PD_RECORD
    add rdx,[rel pd_heap]
    mov rax,[rel pd_warning]
    mov [rdx+32],rax
    add rdx,[rel pd_column]
    mov al,[rsp+8]
    mov [rdx],al
    inc qword [rel pd_column]
    jmp .out
.overflow:
    mov byte [rel pd_overflow],1
.out:
    pop rdx
    pop rax
    ret
pd_newline:
    cmp qword [rel pd_count],PD_LINES-1
    jae .overflow
    inc qword [rel pd_count]
    mov qword [rel pd_column],0
    ret
.overflow:
    mov byte [rel pd_overflow],1
    ret
pd_literal:
    push rsi
.next:
    lodsb
    test al,al
    jz .done
    cmp al,10
    je .newline
    call pd_emit
    jmp .next
.newline:
    call pd_newline
    jmp .next
.done:
    pop rsi
    ret
pd_text:
    push rbx
    push rsi
    push rcx
.next:
    test ecx,ecx
    jz .done
    lodsb
    dec ecx
    test al,al
    jz .done
    cmp al,32
    jb .escape
    cmp al,126
    ja .escape
    cmp al,92
    je .escape
    cmp al,'<'
    je .escape
    cmp al,'>'
    je .escape
    cmp al,'&'
    je .escape
    call pd_emit
    jmp .next
.escape:
    mov bl,al
    mov al,92
    call pd_emit
    mov al,'x'
    call pd_emit
    mov al,bl
    shr al,4
    call pd_nibble
    mov al,bl
    and al,15
    call pd_nibble
    jmp .next
.done:
    pop rcx
    pop rsi
    pop rbx
    ret
pd_nibble:
    push rbx
    lea rbx,[rel pd_hex]
    movzx eax,al
    mov al,[rbx+rax]
    call pd_emit
    pop rbx
    ret
pd_hexnumber:
    ; u64 -> big endian byte order for the existing bounded hex writer.
    push rcx
    push rsi
    mov rax,[rsi]
    bswap rax
    push rax
    mov rsi,rsp
    mov ecx,8
    call pd_hexbytes
    pop rax
    pop rsi
    pop rcx
    ret
pd_hexbytes:
    push rbx
    push rcx
    push rsi
.next:
    lodsb
    mov bl,al
    shr al,4
    call pd_nibble
    mov al,bl
    and al,15
    call pd_nibble
    loop .next
    pop rsi
    pop rcx
    pop rbx
    ret

pd_intro: db 'What this app does',10,'Actions found in this package;',10,'dynamic actions may not be',10,'determined.',10,'All effective permissions: DENY',10,0
pd_unknown: db 'Unknown author',10,0
pd_enrolled: db 'Enrolled signing key;',10,'no author name registered.',10,0
pd_title_label: db 'Package title (untrusted):',10,0
pd_id_label: db 'Package ID:',10,0
pd_version_label: db 'Package version:',10,0
pd_hash_label: db 'Original file SHA256:',10,0
pd_key_label: db 'Signing key ID:',10,0
pd_incomplete: db '! UNCOVERED: analysis incomplete',10,'Dynamic actions may be unknown.',10,0
pd_requested: db 'Requested coverage only',10,0
pd_uncovered: db '! UNCOVERED',10,0
pd_req_label: db 'Requested:',10,0
pd_effective: db 'Effective: DENY',10,0
pd_loc_label: db 'Member (hex, zero based):',10,0
pd_offset_label: db 'Source byte offset (hex):',10,0
pd_length_label: db 'Source byte length (hex):',10,0
pd_line_label: db 'Source line (hex, one based):',10,0
pd_text_label: db 'Package text (untrusted):',10,0
pd_end: db 'End of native disclosure.',10,'Viewing grants no permission.',10,0
pd_hex: db '0123456789abcdef'
align 8
pd_requests: dq pd_deny-pd_requests,pd_allow-pd_requests,pd_ask-pd_requests,pd_unavailable-pd_requests
pd_deny: db 'DENY',10,0
pd_allow: db 'ALLOW (requested only)',10,0
pd_ask: db 'ASK (requested only)',10,0
pd_unavailable: db 'unavailable / unknown',10,0
align 8
pd_kinds: dq pd_kind_0-pd_kinds,pd_kind_1-pd_kinds,pd_kind_2-pd_kinds,pd_kind_3-pd_kinds,pd_kind_4-pd_kinds,pd_kind_5-pd_kinds,pd_kind_6-pd_kinds
pd_kind_0: db 'Action: command call',10,0
pd_kind_1: db 'Action: network endpoint',10,0
pd_kind_2: db 'Action: file path',10,0
pd_kind_3: db 'Requested permission',10,0
pd_kind_4: db 'Unresolved action',10,0
pd_kind_5: db 'Initial package data',10,0
pd_kind_6: db 'Form binding reference',10,0
align 8
pd_reasons: dq pd_reason_0-pd_reasons,pd_reason_1-pd_reasons,pd_reason_2-pd_reasons,pd_reason_3-pd_reasons,pd_reason_4-pd_reasons,pd_reason_5-pd_reasons,pd_reason_6-pd_reasons,pd_reason_7-pd_reasons,pd_reason_8-pd_reasons,pd_reason_9-pd_reasons,pd_reason_10-pd_reasons,pd_reason_11-pd_reasons,pd_reason_12-pd_reasons
pd_reason_0: db 'Typed WAIT operation',10,0
pd_reason_1: db 'Registered verb; unavailable',10,0
pd_reason_2: db 'Unknown command or call',10,0
pd_reason_3: db 'Dynamic / unsupported syntax',10,0
pd_reason_4: db 'Analysis truncated',10,0
pd_reason_5: db 'Literal network host and port',10,0
pd_reason_6: db 'Ambiguous / invalid endpoint',10,0
pd_reason_7: db 'Form reference; unavailable',10,0
pd_reason_8: db 'Initial data; no outbound proof',10,0
pd_reason_9: db 'Immutable indexed app file',10,0
pd_reason_10: db 'Own private data path',10,0
pd_reason_11: db 'Foreign / unsafe path',10,0
pd_reason_12: db 'Requested WAIT; BEGIN ALLOW also lets it read and change its own window text',10,0
pd_write: db 'Possible write',10,0
pd_readwrite: db 'Possible read and write',10,0
%macro WDATA_gui_app_package_disclosure 0
pd_heap: dq 0
pd_handle: dq 0
pd_count: dq 0
pd_column: dq 0
pd_warning: dq 0
pd_busy: db 0
pd_overflow: db 0
; Contiguous private frozen descriptors and single fact; wiped together.
align 64, db 0
pd_header: times (192+704+256) db 0
%endmacro
WDATA_DEFER WDATA_gui_app_package_disclosure
pd_package equ pd_header+192
pd_fact equ pd_package+704
