;; MODULE svc/app_analysis
;; LAYER 5
;; EXPORTS app_analysis_build, app_analysis_descriptor, app_analysis_fact, app_analysis_check
;; IMPORTS svc/app_package, svc/command, core/lib/sha256, core/heap, core/smp
;; CAPS
;; OWNER saga:command
; Revision-1 disclosure, not authorization. No dispatch, shell, DNS, file IO,
; AI, install or grants. Native-only, BSP/non-yielding; all views revalidate
; the exact private candidate, OWNER/session/trust and actual verb registry.
AA_HEAP equ 139264
AA_FACTS equ 65536
AA_REG equ 98304
AA_FACT equ 256
AA_HEADER equ 192
AA_TOKEN equ 224
AA_REG_ROWS equ (AA_HEAP-AA_REG-8)/96     ; test_app_analysis_host pins this above the build's VERB_MAX

app_analysis_build:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    call aa_enter
    test eax,eax
    jz .refuse
    mov qword [rel aa_handle],0
    cmp qword [rel aa_heap],0
    jne .allocated
    mov edi,AA_HEAP
    call kmalloc
    test rax,rax
    jz .fail
    mov [rel aa_heap],rax
.allocated:
    mov rdi,r12
    lea rsi,[rel aa_package]
    mov edx,704
    call app_package_descriptor
    test eax,eax
    jz .fail
    mov rdi,r12
    xor esi,esi
    mov rdx,[rel aa_heap]
    mov rcx,[rel aa_package+16]
    call app_package_copy
    test eax,eax
    jz .fail
    call aa_registry
    test eax,eax
    jz .fail
    lea rdi,[rel aa_header]
    xor eax,eax
    mov ecx,AA_HEADER/8
    cld
    rep stosq
    mov qword [rel aa_header],1
    mov [rel aa_header+8],r12
    mov rax,[rel aa_package+24]
    mov [rel aa_header+16],rax
    lea rsi,[rel aa_package+32]
    lea rdi,[rel aa_header+32]
    mov ecx,4
    rep movsq
    lea rsi,[rel aa_registry_hash]
    lea rdi,[rel aa_header+96]
    mov ecx,4
    rep movsq
    mov qword [rel aa_header+128],1
    mov qword [rel aa_header+136],2
    mov qword [rel aa_count],0
    mov byte [rel aa_overflow],0
    mov rbx,[rel aa_heap]
    mov r14,[rel aa_package+96]
    lea r13,[rbx+576]
.find_grants:
    cmp dword [r13],5
    je .grants
    add r13,80
    dec r14
    jnz .find_grants
    jmp .fail
.grants:
    mov eax,[r13+4]
    add rax,[rel aa_package+120]
    mov eax,[rbx+rax]
    mov [rel aa_requests],eax
    ; Reserve the four exact request facts before variable observations. Sorting
    ; restores source order, even when the script alone exceeds the fact cap.
    mov rax,r13
    sub rax,rbx
    sub rax,576
    xor edx,edx
    mov ecx,80
    div rcx
    mov [rel aa_member],rax
    call aa_request_facts
    mov qword [rel aa_member],0
.member:
    mov rax,[rel aa_member]
    cmp rax,[rel aa_package+96]
    jae .finish
    imul rax,80
    lea r13,[rbx+rax+576]
    mov eax,[r13+4]
    add rax,[rel aa_package+120]
    add rax,rbx
    mov [rel aa_body],rax
    mov eax,[r13+8]
    mov [rel aa_size],rax
    mov qword [rel aa_pos],0
    mov qword [rel aa_line],1
    cmp dword [r13],1
    je .script
    cmp dword [r13],2
    je .form
    cmp dword [r13],4
    je .data
    cmp dword [r13],3
    je .collateral
    cmp dword [r13],6
    je .collateral
    cmp dword [r13],7
    je .collateral
.next:
    inc qword [rel aa_member]
    jmp .member
.collateral:
    ; Verified role/path only. Never scan PNG/opaque credits as shell or data.
    mov qword [rel aa_kind],8
    mov qword [rel aa_off],0
    mov rax,[rel aa_size]
    mov [rel aa_len],rax
    mov qword [rel aa_fact_line],0
    mov qword [rel aa_request],0
    mov qword [rel aa_reason],14
    lea rsi,[rel aa_icon48]
    cmp dword [r13],3
    je .emit_collateral
    lea rsi,[rel aa_icon96]
    cmp dword [r13],6
    je .emit_collateral
    mov qword [rel aa_reason],15
    lea rsi,[rel aa_notices]
.emit_collateral:
    call aa_emit_z
    jmp .next
.script:
    push rbx
    call aa_script
    pop rbx
    jmp .next
.form:
    call aa_form
    jmp .next
.data:
    call aa_data
    jmp .next
.finish:
    jmp aa_build_finish

aa_icon48: db "icon.png: PNG RGBA8 48x48",0
aa_icon96: db "icon@2x.png: PNG RGBA8 96x96",0
aa_notices: db "NOTICES.json: credits metadata; contents not analyzed",0

aa_request_facts:
    push r14
    xor r14d,r14d
.request:
    mov qword [rel aa_kind],4
    mov [rel aa_off],r14
    mov qword [rel aa_len],1
    mov qword [rel aa_fact_line],1
    lea rax,[rel aa_requests]
    movzx eax,byte [rax+r14]
    mov [rel aa_request],rax
    mov qword [rel aa_reason],13
    mov rax,r14
    imul rax,16
    lea rsi,[rel aa_wait_text]
    add rsi,rax
    call aa_emit_z
    inc r14
    cmp r14,4
    jb .request
    pop r14
    ret

aa_build_finish:
    cmp byte [rel aa_overflow],0
    je .sort
    ; Slot 128 is always reserved for a visible, explicit truncation marker.
    mov qword [rel aa_member],-1
    mov qword [rel aa_off],0
    mov qword [rel aa_len],0
    mov qword [rel aa_fact_line],0
    mov qword [rel aa_kind],5
    mov qword [rel aa_request],3
    mov qword [rel aa_reason],5
    mov byte [rel aa_overflow],0
    mov byte [rel aa_final],1
    lea rsi,[rel aa_truncated]
    call aa_emit_z
    mov byte [rel aa_final],0
.sort:
    call aa_sort
    mov rax,[rel aa_count]
    mov [rel aa_header+24],rax
    shl rax,8
    mov rdx,rax
    mov rsi,[rel aa_heap]
    add rsi,AA_FACTS
    lea rdi,[rel aa_header+64]
    call sha256_hash
    ; Re-read the actual candidate and registry before publication.
    mov [rel aa_handle],r12
    mov rdi,r12
    call aa_current
    test eax,eax
    jz app_analysis_build.fail
    mov byte [rel aa_busy],0
    mov eax,1
    jmp app_analysis_build.out

; Build exits live under the exported function for refusal before allocation.
; These are qualified local labels so call-site failure paths stay unambiguous.
app_analysis_build.fail:
    mov qword [rel aa_handle],0
    mov byte [rel aa_busy],0
app_analysis_build.refuse:
    xor eax,eax
app_analysis_build.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Current registry serialization: count u64, then name64 + cap/argt/selk/destr
; u64 for every indexed slot, including vacant entries. No pointer is hashed.
aa_registry:
    push rbx
    push r12
    push r13
    call command_verb_count
    cmp rax,AA_REG_ROWS
    ja .bad
    mov r12,rax
    mov rbx,[rel aa_heap]
    add rbx,AA_REG
    mov [rbx],rax
    add rbx,8
    xor r13d,r13d
.slot:
    cmp r13,r12
    jae .hash
    mov rdi,rbx
    xor eax,eax
    mov ecx,12
    cld
    rep stosq
    mov rdi,r13
    call command_verb_name
    test rax,rax
    jz .bad
    xor ecx,ecx
.name:
    mov dl,[rax+rcx]
    test dl,dl
    jz .meta
    cmp dl,33
    jb .bad
    cmp dl,126
    ja .bad
    cmp ecx,63
    jae .bad
    mov [rbx+rcx],dl
    inc ecx
    jmp .name
.meta:
    mov rdi,r13
    call command_verb_cap
    mov [rbx+64],rax
    mov rdi,r13
    call command_verb_argt
    mov [rbx+72],rax
    mov rdi,r13
    call command_verb_selk
    mov [rbx+80],rax
    mov rdi,r13
    call command_verb_destr
    mov [rbx+88],rax
    add rbx,96
    inc r13
    jmp .slot
.hash:
    imul rdx,r12,96
    add rdx,8
    mov rsi,[rel aa_heap]
    add rsi,AA_REG
    lea rdi,[rel aa_registry_hash]
    call sha256_hash
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Preserve every input register used by native output APIs.
aa_enter:
    push rdi
    push rsi
    push rdx
    push rcx
    sub rsp,8
    call smp_current_logical
    add rsp,8
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    test eax,eax
    jnz .bad
    cmp byte [rel aa_busy],0
    jne .bad
    mov byte [rel aa_busy],1
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; RDI expected handle -> boolean, retires report on any mismatch. Caller owns
; aa_busy. Real package descriptor gates OWNER/epoch/current trust on every view.
aa_current:
    push rbx
    mov rbx,rdi
    test rdi,rdi
    jz .bad
    cmp rdi,[rel aa_handle]
    jne .bad
    lea rsi,[rel aa_check_package]
    mov edx,704
    call app_package_descriptor
    test eax,eax
    jz .bad
    lea rsi,[rel aa_package]
    lea rdi,[rel aa_check_package]
    mov ecx,88                        ; exact full descriptor, not just handle
    cld
    repe cmpsq
    jne .bad
    call aa_registry
    test eax,eax
    jz .bad
    lea rsi,[rel aa_registry_hash]
    lea rdi,[rel aa_header+96]
    mov ecx,4
    repe cmpsq
    jne .bad
    mov eax,1
    pop rbx
    ret
.bad:
    mov qword [rel aa_handle],0
    xor eax,eax
    pop rbx
    ret

; RSI output, RDX length -> no overlap with private heap or all mutable state.
aa_output:
    test rsi,rsi
    jz .bad
    mov rax,rsi
    add rax,rdx
    jc .bad
    mov rcx,[rel aa_heap]
    test rcx,rcx
    jz .bad
    cmp rax,rcx
    jbe .state
    add rcx,AA_HEAP
    cmp rsi,rcx
    jb .bad
.state:
    lea rcx,[rel aa_state]
    cmp rax,rcx
    jbe .ok
    lea rcx,[rel aa_state_end]
    cmp rsi,rcx
    jb .bad
.ok:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; RDI handle, RSI native output, RDX exact192 -> boolean. Writes only on success.
app_analysis_descriptor:
    push rbx
    push r12
    sub rsp,8
    mov rbx,rdi
    mov r12,rsi
    call aa_enter
    test eax,eax
    jz .refuse
    cmp rdx,AA_HEADER
    jne .bad
    call aa_output
    test eax,eax
    jz .bad
    mov rdi,rbx
    call aa_current
    test eax,eax
    jz .bad
    mov rdi,r12
    lea rsi,[rel aa_header]
    mov ecx,AA_HEADER/8
    cld
    rep movsq
    mov eax,1
    jmp .leave
.bad:
    xor eax,eax
.leave:
    mov byte [rel aa_busy],0
.refuse:
    add rsp,8
    pop r12
    pop rbx
    ret

; RDI handle, RSI index, RDX native output, RCX exact256 -> boolean.
app_analysis_fact:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    call aa_enter
    test eax,eax
    jz .refuse
    cmp rcx,AA_FACT
    jne .bad
    mov rsi,r13
    mov edx,AA_FACT
    call aa_output
    test eax,eax
    jz .bad
    mov rdi,rbx
    call aa_current
    test eax,eax
    jz .bad
    cmp r12,[rel aa_count]
    jae .bad
    mov rsi,r12
    shl rsi,8
    add rsi,[rel aa_heap]
    add rsi,AA_FACTS
    mov rdi,r13
    mov ecx,AA_FACT/8
    cld
    rep movsq
    mov eax,1
    jmp .leave
.bad:
    xor eax,eax
.leave:
    mov byte [rel aa_busy],0
.refuse:
    pop r13
    pop r12
    pop rbx
    ret

; RDI handle, RSI exact native192-byte expected report. No grants or commit.
; INPUT must use this at its confirmation boundary, plus its own human intent.
app_analysis_check:
    push rbx
    push r12
    sub rsp,8
    mov rbx,rdi
    mov r12,rsi
    call aa_enter
    test eax,eax
    jz .refuse
    mov edx,AA_HEADER
    call aa_output                    ; also refuses internal alias/wrapped input
    test eax,eax
    jz .bad
    mov rdi,rbx
    call aa_current
    test eax,eax
    jz .bad
    mov rsi,r12
    lea rdi,[rel aa_header]
    mov ecx,AA_HEADER/8
    cld
    repe cmpsq
    jne .bad
    mov eax,1
    jmp .leave
.bad:
    xor eax,eax
.leave:
    mov byte [rel aa_busy],0
.refuse:
    add rsp,8
    pop r12
    pop rbx
    ret

; Emit a pointer-free fact. RSI text bounded by RCX (or aa_emit_z <=192).
; All other values in aa_* emission fields. Never publishes a partial success.
aa_emit_z:
    xor ecx,ecx
.z:
    cmp ecx,192
    jae aa_emit
    cmp byte [rsi+rcx],0
    je aa_emit
    inc ecx
    jmp .z
aa_emit:
    push rdi
    push rsi
    push rcx
    mov rax,[rel aa_kind]
    cmp rax,5
    jne .size
    mov qword [rel aa_header+144],1
.size:
    cmp rcx,191
    jbe .capacity
    mov ecx,191
    mov qword [rel aa_kind],5
    mov qword [rel aa_request],3
    mov qword [rel aa_reason],4
    mov qword [rel aa_header+144],1
.capacity:
    mov rax,[rel aa_count]
    cmp rax,127
    jb .store
    cmp byte [rel aa_final],1
    je .store
    mov byte [rel aa_overflow],1
    mov qword [rel aa_header+144],1
    jmp .out
.store:
    shl rax,8
    add rax,[rel aa_heap]
    add rax,AA_FACTS
    mov rdi,rax
    push rax
    push rcx
    xor eax,eax
    mov ecx,32
    cld
    rep stosq
    pop rcx
    pop rdi
    mov rax,[rel aa_kind]
    mov [rdi],rax
    mov rax,[rel aa_member]
    mov [rdi+8],rax
    mov rax,[rel aa_off]
    mov [rdi+16],rax
    mov rax,[rel aa_len]
    mov [rdi+24],rax
    mov rax,[rel aa_fact_line]
    mov [rdi+32],rax
    mov rax,[rel aa_request]
    mov [rdi+40],rax
    ; Effective policy at +48 is ALWAYS zero. Requests never confer authority.
    mov rax,[rel aa_reason]
    mov [rdi+56],rax
    add rdi,64
    rep movsb
    inc qword [rel aa_count]
.out:
    pop rcx
    pop rsi
    pop rdi
    ret

; Bounded literal lexer. Per token: offset/length/line/reserved + text192.
; Shell constructs we do not model are explicit red, never guessed covered.
aa_script:
    mov qword [rel aa_nwords],0
    mov qword [rel aa_word_start],-1
    mov qword [rel aa_cmd_off],0
    mov qword [rel aa_cmd_line],1
    mov byte [rel aa_quote],0
    mov byte [rel aa_bad],0
    mov byte [rel aa_comment],0
.char:
    mov rax,[rel aa_pos]
    cmp rax,[rel aa_size]
    jae .eof
    mov rdx,[rel aa_body]
    movzx ebx,byte [rdx+rax]
    cmp byte [rel aa_comment],0
    je .normal
    cmp bl,10
    jne .advance
.normal:
    cmp byte [rel aa_quote],0
    jne .word
    cmp bl,35
    jne .space
    cmp qword [rel aa_word_start],-1
    jne .word
    mov byte [rel aa_comment],1
    jmp .advance
.space:
    cmp bl,32
    je .flush
    cmp bl,9
    je .flush
    cmp bl,10
    je .endcmd
    cmp bl,';'
    je .endcmd
    cmp bl,'|'
    je .unsupported_end
    cmp bl,'&'
    je .unsupported_end
    jmp .word
.flush:
    call aa_word_end
    jmp .advance
.unsupported_end:
    mov byte [rel aa_bad],1
.endcmd:
    call aa_word_end
    call aa_command
    mov qword [rel aa_nwords],0
    mov byte [rel aa_bad],0
    mov byte [rel aa_comment],0
    cmp bl,10
    jne .newstart
    inc qword [rel aa_line]
.newstart:
    mov rax,[rel aa_pos]
    inc rax
    mov [rel aa_cmd_off],rax
    mov rax,[rel aa_line]
    mov [rel aa_cmd_line],rax
    jmp .advance
.word:
    cmp qword [rel aa_word_start],-1
    jne .quote
    mov rax,[rel aa_pos]
    mov [rel aa_word_start],rax
    mov rax,[rel aa_line]
    mov [rel aa_word_line],rax
    mov qword [rel aa_word_len],0
    cmp qword [rel aa_nwords],0
    jne .quote
    mov rax,[rel aa_pos]
    mov [rel aa_cmd_off],rax
    mov rax,[rel aa_line]
    mov [rel aa_cmd_line],rax
.quote:
    cmp bl,39
    je .maybe_quote
    cmp bl,34
    jne .literal
.maybe_quote:
    mov al,[rel aa_quote]
    test al,al
    jz .open
    cmp al,bl
    jne .literal
    mov byte [rel aa_quote],0
    jmp .advance
.open:
    mov [rel aa_quote],bl
    jmp .advance
.literal:
    cmp byte [rel aa_quote],39
    je .append
    cmp bl,'$'
    je .dynamic
    cmp bl,'`'
    je .dynamic
    cmp bl,92
    je .dynamic
    cmp byte [rel aa_quote],0
    jne .append
    lea rsi,[rel aa_syntax]
    mov al,bl
    call aa_contains
    test eax,eax
    jz .append
.dynamic:
    mov byte [rel aa_bad],1
.append:
    mov rax,[rel aa_word_len]
    cmp rax,191
    jae .long
    lea rdx,[rel aa_word_text]
    mov [rdx+rax],bl
    inc rax
    mov [rel aa_word_len],rax
    mov byte [rdx+rax],0
    jmp .literal_line
.long:
    mov byte [rel aa_bad],1
.literal_line:
    cmp bl,10
    jne .advance
    inc qword [rel aa_line]
.advance:
    inc qword [rel aa_pos]
    jmp .char
.eof:
    cmp qword [rel aa_word_start],-1
    jne .tail
    cmp qword [rel aa_nwords],0
    je .out
.tail:
    call aa_word_end
    mov byte [rel aa_bad],1
    call aa_command
.out:
    ret

aa_word_end:
    cmp qword [rel aa_word_start],-1
    je .out
    mov rax,[rel aa_nwords]
    cmp rax,16
    jae .overflow
    imul rax,AA_TOKEN
    lea rdi,[rel aa_tokens]
    add rdi,rax
    mov rax,[rel aa_word_start]
    mov [rdi],rax
    mov rdx,[rel aa_pos]
    sub rdx,rax
    mov [rdi+8],rdx
    mov rax,[rel aa_word_line]
    mov [rdi+16],rax
    mov qword [rdi+24],0
    add rdi,32
    mov ecx,24
    xor eax,eax
    cld
    rep stosq
    sub rdi,192
    lea rsi,[rel aa_word_text]
    mov rcx,[rel aa_word_len]
    rep movsb
    inc qword [rel aa_nwords]
    jmp .clear
.overflow:
    mov byte [rel aa_bad],1
.clear:
    mov qword [rel aa_word_start],-1
.out:
    ret

; AL character in RSI NUL string -> boolean; preserves RBX and token state.
aa_contains:
    mov dl,[rsi]
    test dl,dl
    jz .no
    cmp al,dl
    je .yes
    inc rsi
    jmp aa_contains
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

; Compare RDI/RSI zero strings -> boolean, no registry/dispatch side effects.
aa_equal:
    mov al,[rdi]
    cmp al,[rsi]
    jne .no
    test al,al
    jz .yes
    inc rdi
    inc rsi
    jmp aa_equal
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

; All command-level unresolved spans refer to the original command bytes.
aa_unresolved:
    mov qword [rel aa_kind],5
    mov qword [rel aa_request],3
    mov rax,[rel aa_cmd_off]
    mov [rel aa_off],rax
    mov rdx,[rel aa_pos]
    sub rdx,rax
    mov [rel aa_len],rdx
    mov rax,[rel aa_cmd_line]
    mov [rel aa_fact_line],rax
    jmp aa_emit_z

; R14 token index -> emission span, RSI text. Preserves R14.
aa_token_span:
    imul rax,r14,AA_TOKEN
    lea rdx,[rel aa_tokens]
    add rdx,rax
    mov rax,[rdx]
    mov [rel aa_off],rax
    mov rax,[rdx+8]
    mov [rel aa_len],rax
    mov rax,[rdx+16]
    mov [rel aa_fact_line],rax
    lea rsi,[rdx+32]
    ret

aa_command:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp qword [rel aa_nwords],0
    je .out
    cmp byte [rel aa_bad],0
    jne .syntax
    lea r12,[rel aa_tokens+32]
    lea r13,[rel aa_inert]
.inert:
    cmp byte [r13],0
    je .paos
    mov rdi,r12
    mov rsi,r13
    call aa_equal
    test eax,eax
    jnz .out
.skip_inert:
    inc r13
    cmp byte [r13-1],0
    jne .skip_inert
    jmp .inert
.paos:
    mov rdi,r12
    lea rsi,[rel aa_paos]
    call aa_equal
    test eax,eax
    jz .network
    cmp qword [rel aa_nwords],2
    jb .paos_unresolved
    cmp qword [rel aa_nwords],3
    jb .registered
    lea rdi,[rel aa_tokens+AA_TOKEN+32]
    lea rsi,[rel aa_wait]
    call aa_equal
    test eax,eax
    jz .registered
    xor r15d,r15d
.wait_op:
    mov rax,r15
    imul rax,16
    lea rsi,[rel aa_wait_text+5]
    add rsi,rax
    lea rdi,[rel aa_tokens+2*AA_TOKEN+32]
    call aa_equal
    test eax,eax
    jnz .wait_found
    inc r15
    cmp r15,4
    jb .wait_op
    jmp .registered
.wait_found:
    lea rax,[rel aa_wait_counts]
    movzx eax,byte [rax+r15]
    cmp rax,[rel aa_nwords]
    jne .registered
    mov r14d,3
.number:
    call aa_token_span
    call aa_uint
    test eax,eax
    jz .registered
    cmp r14,3
    jne .tail_number
    test r8,r8                       ; actual helper requires nonzero window
    jz .registered
.tail_number:
    cmp r15,1
    jne .token_number
    cmp r14,5
    jne .number_next
    cmp r8,5000                      ; actual BEGIN timeout bound
    ja .registered
    jmp .number_next
.token_number:
    cmp r15,2
    jb .number_next
    cmp r14,4
    jne .number_next
    test r8,r8                       ; actual POLL/CANCEL token nonzero
    jz .registered
.number_next:
    inc r14
    cmp r14,[rel aa_nwords]
    jb .number
    mov r14d,2
    call aa_token_span
    lea rax,[rel aa_requests]
    movzx eax,byte [rax+r15]
    mov [rel aa_request],rax
    mov qword [rel aa_kind],1
    mov qword [rel aa_reason],1
    imul r15,16
    lea rsi,[rel aa_wait_text]
    add rsi,r15
    call aa_emit_z
    jmp .out
.registered:
    lea rdi,[rel aa_tokens+AA_TOKEN+32]
    call command_lookup
    cmp rax,-1
    je .paos_unresolved
    mov r14d,1
    call aa_token_span
    mov qword [rel aa_kind],1
    mov qword [rel aa_request],3
    mov qword [rel aa_reason],2
    call aa_emit_z
    jmp .out
.paos_unresolved:
    lea rsi,[rel aa_unknown_paos]
    jmp .unknown
.network:
    mov rdi,r12
    lea rsi,[rel aa_curl]
    call aa_equal
    test eax,eax
    jnz .net
    mov rdi,r12
    lea rsi,[rel aa_wget]
    call aa_equal
    test eax,eax
    jz .file
.net:
    xor r15d,r15d                    ; bit0 found, bit1 unsupported operand
    mov r14d,1
.net_arg:
    cmp r14,[rel aa_nwords]
    jae .net_end
    call aa_token_span
    call aa_endpoint
    cmp eax,0
    je .net_other
    or r15d,1
    cmp eax,1
    jne .net_invalid
    lea rsi,[rel aa_endpoint_text]
    mov qword [rel aa_kind],2
    mov qword [rel aa_request],3
    mov qword [rel aa_reason],6
    call aa_emit_z
    jmp .net_next
.net_invalid:
    mov qword [rel aa_kind],5
    mov qword [rel aa_request],3
    mov qword [rel aa_reason],7
    lea rsi,[rel aa_invalid_endpoint]
    call aa_emit_z
    jmp .net_next
.net_other:
    or r15d,2
.net_next:
    inc r14
    jmp .net_arg
.net_end:
    cmp r15d,1
    je .out
    lea rsi,[rel aa_net_args]
    jmp .syntax_text
.file:
    lea r13,[rel aa_files]
.file_name:
    cmp byte [r13],0
    je .unknown_command
    mov rdi,r12
    mov rsi,r13
    call aa_equal
    test eax,eax
    jnz .file_args
.skip_file:
    inc r13
    cmp byte [r13-1],0
    jne .skip_file
    jmp .file_name
.file_args:
    mov qword [rel aa_path_mode],16
    cmp byte [r12],'c'
    jne .mode_mv
    cmp byte [r12+1],'a'
    jne .mode_both
    mov qword [rel aa_path_mode],0
    jmp .mode_done
.mode_mv:
    cmp word [r12],'mv'
    jne .mode_done
.mode_both:
    mov qword [rel aa_path_mode],32
.mode_done:
    cmp qword [rel aa_nwords],2
    jb .file_missing
    mov r14d,1
.file_arg:
    call aa_token_span
    mov qword [rel aa_request],3
    cmp byte [rsi],'-'
    je .file_option
    call aa_path
    add rax,[rel aa_path_mode]
    mov [rel aa_reason],rax
    mov qword [rel aa_kind],3
    call aa_emit_z
    jmp .file_next
.file_option:
    mov qword [rel aa_kind],5
    mov qword [rel aa_reason],4
    lea rsi,[rel aa_file_option]
    call aa_emit_z
.file_next:
    inc r14
    cmp r14,[rel aa_nwords]
    jb .file_arg
    jmp .out
.file_missing:
    lea rsi,[rel aa_file_args]
    jmp .syntax_text
.unknown_command:
    lea rsi,[rel aa_unknown]
.unknown:
    mov qword [rel aa_reason],3
    call aa_unresolved
    jmp .out
.syntax:
    lea rsi,[rel aa_shell_syntax]
    mov qword [rel aa_reason],4
    call aa_unresolved
    ; Supplement the red warning with narrow, wholly literal redirections.
    ; Only separate operator/operand words, never expand or guess a path.
    mov r14d,1
.redir:
    cmp r14,[rel aa_nwords]
    jae .out
    imul rax,r14,AA_TOKEN
    lea r12,[rel aa_tokens+32-AA_TOKEN]
    add r12,rax
    mov qword [rel aa_path_mode],0
    cmp word [r12],'<'
    je .redir_path
    mov qword [rel aa_path_mode],16
    cmp word [r12],'>'
    je .redir_path
    cmp word [r12],'>>'
    jne .redir_next
    cmp byte [r12+2],0
    jne .redir_next
.redir_path:
    call aa_token_span
    mov r12,rsi
    cmp byte [r12],0
    je .redir_next
.redir_char:
    mov al,[r12]
    test al,al
    jz .redir_emit
    lea rsi,[rel aa_path_literal]
    call aa_contains
    test eax,eax
    jz .redir_next
    inc r12
    jmp .redir_char
.redir_emit:
    call aa_token_span
    call aa_path
    add rax,[rel aa_path_mode]
    mov [rel aa_reason],rax
    mov qword [rel aa_kind],3
    mov qword [rel aa_request],3
    call aa_emit_z
.redir_next:
    inc r14
    jmp .redir
.syntax_text:
    mov qword [rel aa_reason],4
    call aa_unresolved
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Literal decimal uint64 (1..20 digits) only; zero itself allowed here.
aa_uint:
    xor ecx,ecx
    xor r8d,r8d
    cmp byte [rsi],'0'
    jne .digit
    cmp byte [rsi+1],0
    jne .bad
.digit:
    movzx edx,byte [rsi+rcx]
    test edx,edx
    jz .end
    cmp dl,'0'
    jb .bad
    cmp dl,'9'
    ja .bad
    cmp ecx,20
    jae .bad
    mov rax,r8
    mov r9d,10
    mul r9
    test rdx,rdx
    jnz .bad
    movzx edx,byte [rsi+rcx]
    sub edx,'0'
    add rax,rdx
    jc .bad
    mov r8,rax
    inc ecx
    jmp .digit
.end:
    test ecx,ecx
    jz .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; RSI literal URL -> EAX0 not HTTP(S), 1 normalized, 2 invalid/ambiguous.
; Only DNS/IPv4 HTTP(S). No decoding, DNS, userinfo, IPv6 or inference.
aa_endpoint:
    push rsi
    mov rax,[rsi]
    mov rdx,'https://'
    cmp rax,rdx
    je .https
    mov rdx,'http://'
    shl rax,8
    shl rdx,8
    cmp rax,rdx
    jne .not_url
    add rsi,7
    mov r8d,80
    jmp .host
.https:
    add rsi,8
    mov r8d,443
.host:
    lea rdi,[rel aa_endpoint_text]
    xor ecx,ecx
.host_char:
    mov al,[rsi]
    test al,al
    jz .host_end
    cmp al,'/'
    je .host_end
    cmp al,'?'
    je .host_end
    cmp al,'#'
    je .host_end
    cmp al,':'
    je .port
    cmp ecx,128
    jae .bad
    cmp al,'A'
    jb .lower
    cmp al,'Z'
    ja .lower
    add al,32
.lower:
    cmp al,'a'
    jb .number
    cmp al,'z'
    jbe .store
.number:
    cmp al,'0'
    jb .punct
    cmp al,'9'
    jbe .store
.punct:
    cmp al,'.'
    je .store
    cmp al,'-'
    jne .bad
.store:
    mov [rdi+rcx],al
    inc ecx
    inc rsi
    jmp .host_char
.port:
    inc rsi
    xor r8d,r8d
    xor r9d,r9d
.port_char:
    movzx eax,byte [rsi]
    test al,al
    jz .port_end
    cmp al,'/'
    je .port_end
    cmp al,'?'
    je .port_end
    cmp al,'#'
    je .port_end
    cmp al,'0'
    jb .bad
    cmp al,'9'
    ja .bad
    inc r9d
    cmp r9d,5
    ja .bad
    imul r8d,10
    sub eax,'0'
    add r8d,eax
    inc rsi
    jmp .port_char
.port_end:
    test r9d,r9d
    jz .bad
    cmp r8d,1
    jb .bad
    cmp r8d,65535
    ja .bad
.host_end:
    test ecx,ecx
    jz .bad
    mov al,[rdi]
    cmp al,'.'
    je .bad
    cmp al,'-'
    je .bad
    mov al,[rdi+rcx-1]
    cmp al,'.'
    je .bad
    cmp al,'-'
    je .bad
    mov byte [rdi+rcx],':'
    inc ecx
    add rdi,rcx
    ; Convert u16 port without leading zeros, by reverse stack-free scratch.
    lea r10,[rel aa_port_digits+8]
    mov byte [r10],0
    mov eax,r8d
    mov r9d,10
.decimal:
    xor edx,edx
    div r9d
    add dl,'0'
    dec r10
    mov [r10],dl
    test eax,eax
    jnz .decimal
.copy_port:
    mov al,[r10]
    mov [rdi],al
    inc rdi
    inc r10
    test al,al
    jnz .copy_port
    mov eax,1
    jmp .out
.bad:
    mov eax,2
    jmp .out
.not_url:
    xor eax,eax
.out:
    pop rsi
    ret

; RSI path -> reason, no normalization into authority. Exact member lookup,
; then own data namespace with no empty/dot/dotdot segments; otherwise foreign.
aa_path:
    push rsi
    push r12
    push r13
    mov r12,rsi
    xor r13d,r13d
.member:
    cmp r13,[rel aa_package+96]
    jae .private
    imul rax,r13,80
    mov rdx,[rel aa_heap]
    lea rdx,[rdx+rax+576]
    cmp dword [rdx],4
    je .next
    lea rdi,[rdx+16]
    mov rsi,r12
    call aa_equal
    test eax,eax
    jnz .immutable
.next:
    inc r13
    jmp .member
.private:
    lea rdi,[rel aa_package+192+208]
    mov rsi,r12
.prefix:
    mov al,[rdi]
    test al,al
    jz .slash
    cmp al,[rsi]
    jne .foreign
    inc rdi
    inc rsi
    jmp .prefix
.slash:
    cmp byte [rsi],'/'
    jne .foreign
    inc rsi
.segment:
    mov rdi,rsi
.scan:
    mov al,[rsi]
    test al,al
    jz .end_segment
    cmp al,'/'
    je .end_segment
    inc rsi
    jmp .scan
.end_segment:
    mov rax,rsi
    sub rax,rdi
    test rax,rax
    jz .foreign
    cmp rax,1
    jne .dotdot
    cmp byte [rdi],'.'
    je .foreign
.dotdot:
    cmp rax,2
    jne .next_segment
    cmp word [rdi],'..'
    je .foreign
.next_segment:
    cmp byte [rsi],0
    je .own
    inc rsi
    jmp .segment
.immutable:
    mov eax,10
    jmp .out
.own:
    mov eax,11
    jmp .out
.foreign:
    mov eax,12
.out:
    pop r13
    pop r12
    pop rsi
    ret

; Form references are data, never dispatch. Native semantic lint remains INPUT.
; Conservatively search literal attribute references, including quoted/comment
; text, and label them unavailable. Source locations are retained exactly.
aa_form:
    push r12
    push r13
    push r14
    mov r12,[rel aa_body]
    xor r13d,r13d
.loop:
    cmp r13,[rel aa_size]
    jae .out
    mov al,[r12+r13]
    cmp al,10
    jne .match
    inc qword [rel aa_line]
.match:
    lea rsi,[rel aa_on_click]
    mov r14d,9
    call .prefix
    test eax,eax
    jnz .found
    lea rsi,[rel aa_bind]
    mov r14d,5
    call .prefix
    test eax,eax
    jz .next
.found:
    mov [rel aa_off],r13
    mov rax,[rel aa_line]
    mov [rel aa_fact_line],rax
    mov rdx,r13
    add rdx,r14
.end:
    cmp rdx,[rel aa_size]
    jae .emit
    mov al,[r12+rdx]
    cmp al,32
    je .emit
    cmp al,9
    je .emit
    cmp al,10
    je .emit
    inc rdx
    jmp .end
.emit:
    sub rdx,r13
    mov [rel aa_len],rdx
    mov rcx,rdx
    lea rsi,[r12+r13]
    mov qword [rel aa_kind],7
    mov qword [rel aa_request],3
    mov qword [rel aa_reason],8
    call aa_emit
.next:
    inc r13
    jmp .loop
.prefix:
    mov rax,r13
    add rax,r14
    cmp rax,[rel aa_size]
    ja .no
    xor ecx,ecx
.p:
    ; R13 source base is preserved; use temporary pointer for indexed compare.
    lea rdx,[r12+r13]
    mov al,[rdx+rcx]
    cmp al,[rsi+rcx]
    jne .no
    inc rcx
    cmp rcx,r14
    jb .p
    mov eax,1
    ret
.no:
    xor eax,eax
    ret
.out:
    pop r14
    pop r13
    pop r12
    ret

; Initial data references are bounded literal chunks, not outbound activity.
aa_data:
    push r12
    push r13
    mov r12,[rel aa_body]
    xor r13d,r13d
.chunk:
    cmp r13,[rel aa_size]
    jae .out
    mov [rel aa_off],r13
    mov rax,[rel aa_line]
    mov [rel aa_fact_line],rax
    mov rcx,[rel aa_size]
    sub rcx,r13
    cmp rcx,191
    jbe .size
    mov ecx,191
.size:
    mov [rel aa_len],rcx
    mov qword [rel aa_kind],6
    mov qword [rel aa_request],3
    mov qword [rel aa_reason],9
    lea rsi,[r12+r13]
    call aa_emit
    mov rdx,[rel aa_len]
.count_lines:
    cmp byte [r12+r13],10
    jne .advance
    inc qword [rel aa_line]
.advance:
    inc r13
    dec rdx
    jnz .count_lines
    jmp .chunk
.out:
    pop r13
    pop r12
    ret

; Deterministic stable bubble sort by unsigned member/offset/kind/text. <=128.
aa_sort:
    push rbx
    push r12
    push r13
    mov r12,[rel aa_count]
.outer:
    cmp r12,1
    jbe .out
    xor r13d,r13d
    mov rbx,[rel aa_heap]
    add rbx,AA_FACTS
.inner:
    lea rsi,[rbx+AA_FACT]
    mov rax,[rbx+8]
    cmp rax,[rsi+8]
    ja .swap
    jb .next
    mov rax,[rbx+16]
    cmp rax,[rsi+16]
    ja .swap
    jb .next
    mov rax,[rbx]
    cmp rax,[rsi]
    ja .swap
    jb .next
    lea rdi,[rbx+64]
    add rsi,64
    mov ecx,192
    cld
    repe cmpsb
    ja .swap
    jmp .next
.swap:
    mov rdi,rbx
    lea rsi,[rbx+AA_FACT]
    mov ecx,32
.swap_q:
    mov rax,[rdi]
    mov rdx,[rsi]
    mov [rdi],rdx
    mov [rsi],rax
    add rdi,8
    add rsi,8
    dec ecx
    jnz .swap_q
.next:
    add rbx,AA_FACT
    inc r13
    lea rax,[r13+1]
    cmp rax,r12
    jb .inner
    dec r12
    jmp .outer
.out:
    pop r13
    pop r12
    pop rbx
    ret

aa_syntax: db '(){}*?[]<>',0
aa_path_literal: db 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-',0
aa_inert: db 'echo',0,'printf',0,':',0,'true',0,'false',0,0
aa_files: db 'cat',0,'touch',0,'mkdir',0,'rm',0,'cp',0,'mv',0,0
aa_paos: db 'paos',0
aa_wait: db 'WAIT',0
aa_curl: db 'curl',0
aa_wget: db 'wget',0
aa_wait_counts: db 4,6,5,5
aa_wait_text:
    db 'WAIT STATUS',0,0,0,0,0
    db 'WAIT BEGIN',0,0,0,0,0,0
    db 'WAIT POLL',0,0,0,0,0,0,0
    db 'WAIT CANCEL',0,0,0,0,0
; each entry exactly16 bytes
aa_on_click: db 'on_click=',0
aa_bind: db 'bind=',0
aa_shell_syntax: db 'unresolved shell syntax',0
aa_unknown_paos: db 'unresolved paos call',0
aa_unknown: db 'unresolved command',0
aa_net_args: db 'unresolved network arguments',0
aa_file_args: db 'unresolved file arguments',0
aa_file_option: db 'unresolved file option',0
aa_invalid_endpoint: db 'unresolved endpoint',0
aa_truncated: db 'analysis truncated',0

%macro WDATA_BSS_app_analysis 0
alignb 8
aa_state:
aa_heap: resq 1
aa_handle: resq 1
aa_count: resq 1
aa_member: resq 1
aa_body: resq 1
aa_size: resq 1
aa_pos: resq 1
aa_line: resq 1
aa_kind: resq 1
aa_off: resq 1
aa_len: resq 1
aa_fact_line: resq 1
aa_request: resq 1
aa_reason: resq 1
aa_nwords: resq 1
aa_word_start: resq 1
aa_word_len: resq 1
aa_word_line: resq 1
aa_cmd_off: resq 1
aa_cmd_line: resq 1
aa_path_mode: resq 1
aa_requests: resb 4
aa_busy: resb 1
aa_overflow: resb 1
aa_final: resb 1
aa_quote: resb 1
aa_bad: resb 1
aa_comment: resb 1
alignb 8
aa_package: resb 704
aa_check_package: resb 704
aa_header: resb AA_HEADER
aa_registry_hash: resb 32
aa_tokens: resb 16*AA_TOKEN
aa_word_text: resb 192
aa_endpoint_text: resb 192
aa_port_digits: resb 16
aa_state_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_app_analysis
