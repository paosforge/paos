;; MODULE core/maintenance_record
;; LAYER 1
;; CONTEXT: bsp_only
;; EXPORTS maintenance_event_append, maintenance_event_snapshot, maintenance_event_page, maintenance_snapshot, maintenance_page, maintenance_event_wire_ok, maintenance_event_preview, maintenance_preview
;; IMPORTS core/lib/sha256, boot/boot_v2_handoff, boot/boot_v2_health, boot/header, boot/nvram_access
;; CAPS
;; OWNER rc-vm-claude
; Bounded typed diagnostic events, independent of boot/update/health authority.
; No raw source, text, pointer, nonce or timing is stored. Trusted adapters pass
; an exact allowlisted record; the fingerprint is computed here, never supplied.
; Normal BSP task context only, no allocations/IRQ callers. At most eight EFI
; writes per boot. Unknown stores are preserved; uncertainty latches until boot.
%include "core/abi/maintenance.inc"

; RDI=record, EAX=1 iff scalar allowlist/identity qualification is well-formed.
; Sequence and fingerprint are validated separately for candidate/stored roles.
maintenance_event_fields_ok:
    push rbx
    mov rbx,rdi
    mov eax,[rbx+ME_SOURCE]
    cmp eax,1
    jb .bad
    cmp eax,3
    ja .bad
    cmp [rbx+ME_COMPONENT],ax
    jne .bad
    mov al,[rbx+ME_PHASE]
    cmp al,0xff
    je .gate
    cmp al,8
    ja .bad
.gate:
    mov al,[rbx+ME_GATE]
    cmp al,0xff
    je .identity
    cmp al,11
    ja .bad
.identity:
    cmp dword [rbx+ME_ERROR],0
    je .bad
    cmp qword [rbx+ME_RESERVED],0
    jne .bad
    mov eax,[rbx+ME_IDENTITY]
    cmp eax,2
    ja .bad
    cmp eax,1
    je .full
    lea rdi,[rbx+ME_BUILD]
    mov ecx,32
    cmp eax,2
    jne .zero
    cmp dword [rdi],0
    je .bad
    add rdi,4
    mov ecx,28
.zero:
    xor eax,eax
    repe scasb
    jne .bad
    jmp .digest
.full:
    lea rdi,[rbx+ME_BUILD]
    call maintenance_nonzero32
    test eax,eax
    jz .bad
.digest:
    lea rdi,[rbx+ME_SOURCE_DIGEST]
    call maintenance_nonzero32
    test eax,eax
    jz .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

maintenance_nonzero32:
    mov rax,[rdi]
    or rax,[rdi+8]
    or rax,[rdi+16]
    or rax,[rdi+24]
    setnz al
    movzx eax,al
    ret

; RDI=fixed1064B, EAX=1 only for complete canonical schema/CRC/fingerprints.
; All unused bytes zero. Sequence is contiguous, no wrapping/dropped ambiguity.
maintenance_event_wire_ok:
    push rbp
    mov rbp,rsp
    and rsp,-16
    push rbx
    push r12
    push r13
    push r14
    mov rbx,rdi
    cmp dword [rbx],ME_MAGIC
    jne .bad
    cmp word [rbx+4],ME_VERSION
    jne .bad
    cmp word [rbx+6],ME_BYTES
    jne .bad
    cmp dword [rbx+12],0
    jne .bad
    cmp dword [rbx+1056],0
    jne .bad
    mov r12d,[rbx+ME_COUNT]
    cmp r12d,ME_CAPACITY
    ja .bad
    mov r13,[rbx+ME_DROPPED]
    test r13,r13
    jz .next
    cmp r12d,ME_CAPACITY                 ; no drop before capacity reached
    jne .bad
.next:
    mov rax,r13
    add rax,r12
    jc .bad
    inc rax
    jz .bad
    cmp rax,[rbx+ME_NEXT]
    jne .bad
    mov esi,ME_CRC_OFF
    call pbm_crc32
    cmp eax,[rbx+ME_CRC_OFF]
    jne .bad
    xor r14d,r14d
.record:
    cmp r14d,r12d
    jae .unused
    mov rax,r14
    shl rax,7
    lea rdi,[rbx+rax+ME_RECORDS]
    inc r13
    cmp [rdi],r13
    jne .bad
    call maintenance_event_fields_ok
    test eax,eax
    jz .bad
    ; A canonical store cannot contain the same source digest twice.
    lea r11,[rbx+ME_RECORDS]
    xor r10d,r10d
.unique:
    cmp r10d,r14d
    jae .fingerprint
    mov rax,r14
    shl rax,7
    lea rdi,[rbx+rax+ME_RECORDS+ME_SOURCE_DIGEST]
    lea rsi,[r11+ME_SOURCE_DIGEST]
    mov ecx,4
    repe cmpsq
    je .bad
    add r11,ME_RECORD_BYTES
    inc r10d
    jmp .unique
.fingerprint:
    mov rax,r14
    shl rax,7
    lea rsi,[rbx+rax+ME_RECORDS+8]
    lea rdi,[rel maintenance_hash]
    mov edx,48
    call sha256_hash
    test rax,rax
    jnz .bad
    mov rax,r14
    shl rax,7
    lea rdi,[rbx+rax+ME_RECORDS+ME_FINGERPRINT]
    lea rsi,[rel maintenance_hash]
    mov ecx,4
    repe cmpsq
    jne .bad
    inc r14d
    jmp .record
.unused:
    mov rax,r12
    shl rax,7
    lea rdi,[rbx+rax+ME_RECORDS]
    mov ecx,ME_CAPACITY
    sub ecx,r12d
    shl ecx,7
    xor eax,eax
    repe scasb
    jne .bad
    mov eax,1
    jmp .done
.bad:
    xor eax,eax
.done:
    pop r14
    pop r13
    pop r12
    pop rbx
    mov rsp,rbp
    pop rbp
    ret

; R12=runtime table, caller aligned. No writes, bounded one GetVariable.
maintenance_read:
    mov qword [rel maintenance_size],ME_BYTES
    mov dword [rel maintenance_attrs],0
    lea rcx,[rel maintenance_name]
    lea rdx,[rel storage_access_nvram_paos_data_guid]
    lea r8,[rel maintenance_attrs]
    lea r9,[rel maintenance_size]
    sub rsp,40
    lea rax,[rel maintenance_verify]
    mov [rsp+32],rax
    call [r12+0x48]
    add rsp,40
    ret

; 0 absent,1 valid,2 unavailable,3 malformed/unreadable. Read-only, never
; changes the writer latch or exposes previous scratch on any failed read.
maintenance_event_snapshot:
    push rbp
    mov rbp,rsp
    and rsp,-16
    push rbx
    push r12
    lea rdi,[rel maintenance_snapshot]
    xor eax,eax
    mov ecx,ME_BYTES/8
    rep stosq
    mov ebx,2
    cmp byte [rel pbm_manager_launch],1
    jne .done
    cmp byte [rel pbm_runtime_code_mapped],1
    jne .done
    mov r12,[rel runtime_services]
    test r12,r12
    jz .done
    call maintenance_read
    mov rdx,0x800000000000000e
    cmp rax,rdx
    jne .present
    xor ebx,ebx
    jmp .done
.present:
    mov ebx,3
    test rax,rax
    jnz .done
    cmp dword [rel maintenance_attrs],7
    jne .done
    cmp qword [rel maintenance_size],ME_BYTES
    jne .done
    lea rdi,[rel maintenance_verify]
    call maintenance_event_wire_ok
    test eax,eax
    jz .done
    lea rsi,[rel maintenance_verify]
    lea rdi,[rel maintenance_snapshot]
    mov ecx,ME_BYTES/8
    rep movsq
    mov ebx,1
.done:
    mov eax,ebx
    pop r12
    pop rbx
    mov rsp,rbp
    pop rbp
    ret

; RDI=128B candidate: seq/fingerprint zero, typed fields and source digest.
; 0 saved,1 duplicate,2 unavailable/refused,3 unknown/uncertain,4 invalid,
; 5 write/sequence budget. Never writes a foreign/unknown store or retries an
; uncertain offer. Exact readback before another append is possible.
maintenance_event_append:
    push rbp
    mov rbp,rsp
    and rsp,-16
    push rbx
    push r12
    push r13
    push r14
    test rdi,rdi
    jz .invalid
    mov rbx,rdi
    cmp qword [rbx],0
    jne .invalid
    mov rax,[rbx+ME_FINGERPRINT]
    or rax,[rbx+ME_FINGERPRINT+8]
    or rax,[rbx+ME_FINGERPRINT+16]
    or rax,[rbx+ME_FINGERPRINT+24]
    jnz .invalid
    call maintenance_event_fields_ok
    test eax,eax
    jz .invalid
    cmp byte [rel maintenance_uncertain],0
    jne .unknown
    cmp byte [rel pbm_manager_launch],1
    jne .unavailable
    cmp byte [rel pbm_runtime_code_mapped],1
    jne .unavailable
    test byte [rel pbm_flags],PBM_HF_MUTABLE_ATTEMPT
    jz .unavailable
    mov r12,[rel runtime_services]
    test r12,r12
    jz .unavailable
    mov rsi,rbx
    lea rdi,[rel maintenance_candidate]
    mov ecx,ME_RECORD_BYTES/8
    rep movsq
    lea rdi,[rel maintenance_candidate+ME_FINGERPRINT]
    lea rsi,[rel maintenance_candidate+8]
    mov edx,48
    call sha256_hash
    test rax,rax
    jnz .invalid
    call maintenance_read
    mov rdx,0x800000000000000e
    cmp rax,rdx
    je .empty
    test rax,rax
    jnz .unknown
    cmp dword [rel maintenance_attrs],7
    jne .unknown
    cmp qword [rel maintenance_size],ME_BYTES
    jne .unknown
    lea rdi,[rel maintenance_verify]
    call maintenance_event_wire_ok
    test eax,eax
    jz .unknown                         ; preserve unknown store
    lea rsi,[rel maintenance_verify]
    lea rdi,[rel maintenance_work]
    mov ecx,ME_BYTES/8
    rep movsq
    jmp .dedup
.empty:
    lea rdi,[rel maintenance_work]
    xor eax,eax
    mov ecx,ME_BYTES/8
    rep stosq
    mov dword [rel maintenance_work],ME_MAGIC
    mov word [rel maintenance_work+4],ME_VERSION
    mov word [rel maintenance_work+6],ME_BYTES
    mov qword [rel maintenance_work+ME_NEXT],1
.dedup:
    xor r13d,r13d
    lea r14,[rel maintenance_work+ME_RECORDS]
.find:
    cmp r13d,[rel maintenance_work+ME_COUNT]
    jae .append
    lea rdi,[r14+ME_SOURCE_DIGEST]
    lea rsi,[rel maintenance_candidate+ME_SOURCE_DIGEST]
    mov ecx,4
    repe cmpsq
    jne .advance
    lea rdi,[r14+8]
    lea rsi,[rel maintenance_candidate+8]
    mov ecx,(ME_RECORD_BYTES-8)/8
    repe cmpsq
    jne .invalid                        ; same source cannot change meaning
    mov eax,1
    jmp .done
.advance:
    add r14,ME_RECORD_BYTES
    inc r13d
    jmp .find
.append:
    cmp qword [rel maintenance_writes],ME_CAPACITY
    jae .budget
    cmp qword [rel maintenance_work+ME_NEXT],-1
    je .budget
    cmp r13d,ME_CAPACITY
    jb .room
    lea rsi,[rel maintenance_work+ME_RECORDS+ME_RECORD_BYTES]
    lea rdi,[rel maintenance_work+ME_RECORDS]
    mov ecx,(ME_CAPACITY-1)*ME_RECORD_BYTES/8
    rep movsq
    sub r14,ME_RECORD_BYTES
    inc qword [rel maintenance_work+ME_DROPPED]
    jmp .put
.room:
    inc dword [rel maintenance_work+ME_COUNT]
.put:
    mov rsi,[rel maintenance_work+ME_NEXT]
    mov [rel maintenance_candidate],rsi
    inc qword [rel maintenance_work+ME_NEXT]
    lea rsi,[rel maintenance_candidate]
    mov rdi,r14
    mov ecx,ME_RECORD_BYTES/8
    rep movsq
    lea rdi,[rel maintenance_work]
    mov esi,ME_CRC_OFF
    call pbm_crc32
    mov [rel maintenance_work+ME_CRC_OFF],eax
    lea rdi,[rel storage_access_nvram_paos_data_guid]
    lea rsi,[rel maintenance_name]
    xor edx,edx
    lea rcx,[rel maintenance_tag]
    call storage_access_nvram_require
    test rax,rax
    jnz .unavailable
    mov byte [rel maintenance_uncertain],1
    inc qword [rel maintenance_writes]
    lea rcx,[rel maintenance_name]
    lea rdx,[rel storage_access_nvram_paos_data_guid]
    mov r8d,7
    mov r9d,ME_BYTES
    sub rsp,48
    lea rax,[rel maintenance_work]
    mov [rsp+32],rax
    call [r12+0x58]
    add rsp,48
    test rax,rax
    jnz .unknown
    call maintenance_read
    test rax,rax
    jnz .unknown
    cmp dword [rel maintenance_attrs],7
    jne .unknown
    cmp qword [rel maintenance_size],ME_BYTES
    jne .unknown
    lea rsi,[rel maintenance_verify]
    lea rdi,[rel maintenance_work]
    mov ecx,ME_BYTES/8
    repe cmpsq
    jne .unknown
    mov byte [rel maintenance_uncertain],0
    xor eax,eax
    jmp .done
.unavailable:
    mov eax,2
    jmp .done
.unknown:
    mov eax,3
    jmp .done
.invalid:
    mov eax,4
    jmp .done
.budget:
    mov eax,5
.done:
    pop r14
    pop r13
    pop r12
    pop rbx
    mov rsp,rbp
    pop rbp
    ret

; EDI page0..7 -> same read-only snapshot. Page=header32+record128+SHA256
; exact1064B stored bytes. Missing page has zero record with valid header/hash.
; EAX=1 record,0 missing,2 unavailable,3 unknown,4 invalid index.
maintenance_event_page:
    push rbp
    mov rbp,rsp
    and rsp,-16
    push rbx
    push r12
    mov ebx,edi
    lea rdi,[rel maintenance_page]
    xor eax,eax
    mov ecx,ME_PAGE_BYTES/8
    rep stosq
    cmp ebx,ME_CAPACITY
    jae .invalid
    call maintenance_event_snapshot
    cmp eax,1
    jne .done
    lea rsi,[rel maintenance_snapshot]
    lea rdi,[rel maintenance_page]
    mov ecx,ME_HEADER_BYTES/8
    rep movsq
    lea rdi,[rel maintenance_page+160]
    lea rsi,[rel maintenance_snapshot]
    mov edx,ME_BYTES
    call sha256_hash
    test rax,rax
    jnz .unknown
    cmp ebx,[rel maintenance_snapshot+ME_COUNT]
    jae .missing
    shl ebx,7
    lea rsi,[rel maintenance_snapshot+ME_RECORDS]
    add rsi,rbx
    lea rdi,[rel maintenance_page+32]
    mov ecx,ME_RECORD_BYTES/8
    rep movsq
    mov eax,1
    jmp .done
.missing:
    xor eax,eax
    jmp .done
.unknown:
    lea rdi,[rel maintenance_page]
    xor eax,eax
    mov ecx,ME_PAGE_BYTES/8
    rep stosq
    mov eax,3
    jmp .done
.invalid:
    mov eax,4
.done:
    pop r12
    pop rbx
    mov rsp,rbp
    pop rbp
    ret

; Readable, side-effect-free preview over exactly maintenance_page. No source
; strings, host summaries, report transmission or consent. Same validated event
; fields as the page; all other source bytes are excluded by construction.
maintenance_event_preview:
    push rbp
    mov rbp,rsp
    and rsp,-16
    push rbx
    push r12
    call maintenance_event_page
    mov ebx,eax
    lea rdi,[rel maintenance_preview]
    xor eax,eax
    mov ecx,512/8
    rep stosq
    mov byte [rel maintenance_preview_overflow],0
    lea r12,[rel maintenance_preview]
    lea rsi,[rel maintenance_str_unknown]
    cmp ebx,1
    je .event
    cmp ebx,0
    jne .unavailable
    lea rsi,[rel maintenance_str_missing]
    jmp .status
.unavailable:
    cmp ebx,2
    jne .status
    lea rsi,[rel maintenance_str_unavailable]
.status:
    call maintenance_preview_text
    jmp .done
.event:
    lea rsi,[rel maintenance_str_sequence]
    call maintenance_preview_text
    mov rdi,[rel maintenance_page+32]
    call maintenance_preview_hex64
    lea rsi,[rel maintenance_str_source]
    call maintenance_preview_text
    mov eax,[rel maintenance_page+32+ME_SOURCE]
    lea rsi,[rel maintenance_str_boot]
    cmp eax,1
    je .source
    lea rsi,[rel maintenance_str_image]
    cmp eax,2
    je .source
    lea rsi,[rel maintenance_str_crash]
.source:
    call maintenance_preview_text
    lea rsi,[rel maintenance_str_component]
    call maintenance_preview_text
    movzx eax,word [rel maintenance_page+32+ME_COMPONENT]
    lea rsi,[rel maintenance_str_startup]
    cmp eax,1
    je .component
    lea rsi,[rel maintenance_str_manager]
    cmp eax,2
    je .component
    lea rsi,[rel maintenance_str_core]
.component:
    call maintenance_preview_text
    lea rsi,[rel maintenance_str_phase]
    call maintenance_preview_text
    movzx edi,byte [rel maintenance_page+32+ME_PHASE]
    mov al,'P'
    call maintenance_preview_enum
    lea rsi,[rel maintenance_str_gate]
    call maintenance_preview_text
    movzx edi,byte [rel maintenance_page+32+ME_GATE]
    mov al,'G'
    call maintenance_preview_enum
    lea rsi,[rel maintenance_str_error]
    call maintenance_preview_text
    mov edi,[rel maintenance_page+32+ME_ERROR]
    call maintenance_preview_hex64
    lea rsi,[rel maintenance_str_identity]
    call maintenance_preview_text
    mov eax,[rel maintenance_page+32+ME_IDENTITY]
    lea rsi,[rel maintenance_str_UNKNOWN]
    test eax,eax
    jz .identity
    lea rsi,[rel maintenance_str_full]
    cmp eax,1
    je .identity
    lea rsi,[rel maintenance_str_truncated]
.identity:
    call maintenance_preview_text
    lea rsi,[rel maintenance_str_build]
    call maintenance_preview_text
    lea rdi,[rel maintenance_page+32+ME_BUILD]
    call maintenance_preview_digest
    lea rsi,[rel maintenance_str_fingerprint]
    call maintenance_preview_text
    lea rdi,[rel maintenance_page+32+ME_FINGERPRINT]
    call maintenance_preview_digest
    lea rsi,[rel maintenance_str_digest]
    call maintenance_preview_text
    lea rdi,[rel maintenance_page+32+ME_SOURCE_DIGEST]
    call maintenance_preview_digest
.done:
    cmp byte [rel maintenance_preview_overflow],0
    je .out
    lea rdi,[rel maintenance_preview]
    xor eax,eax
    mov ecx,512/8
    rep stosq
    lea rdi,[rel maintenance_page]
    mov ecx,ME_PAGE_BYTES/8
    rep stosq
    mov ebx,3
.out:
    mov eax,ebx
    pop r12
    pop rbx
    mov rsp,rbp
    pop rbp
    ret

; R12 output cursor, all helpers preserve other nonvolatile registers.
maintenance_preview_char:
    lea rdx,[rel maintenance_preview+511]
    cmp r12,rdx
    jae .full
    mov [r12],al
    inc r12
    ret
.full:
    mov byte [rel maintenance_preview_overflow],1
    ret
maintenance_preview_text:
    lodsb
    test al,al
    jz .done
    call maintenance_preview_char
    jmp maintenance_preview_text
.done:
    ret
maintenance_preview_hex64:
    mov r9,rdi
    mov ecx,16
.loop:
    rol r9,4
    mov eax,r9d
    and eax,15
    lea r8,[rel maintenance_hex]
    mov al,[r8+rax]
    call maintenance_preview_char
    dec ecx
    jnz .loop
    ret
maintenance_preview_digest:
    mov r9,rdi
    mov ecx,32
.loop:
    movzx eax,byte [r9]
    shr eax,4
    lea r8,[rel maintenance_hex]
    mov al,[r8+rax]
    call maintenance_preview_char
    movzx eax,byte [r9]
    and eax,15
    mov al,[r8+rax]
    call maintenance_preview_char
    inc r9
    dec ecx
    jnz .loop
    ret
maintenance_preview_enum:
    cmp edi,255
    jne .known
    lea rsi,[rel maintenance_str_UNKNOWN]
    jmp maintenance_preview_text
.known:
    call maintenance_preview_char
    cmp edi,10
    jb .ones
    mov al,'1'
    call maintenance_preview_char
    sub edi,10
.ones:
    lea eax,[rdi+'0']
    jmp maintenance_preview_char

maintenance_hex: db '0123456789abcdef'
maintenance_str_unknown: db 'status=unknown',0
maintenance_str_missing: db 'status=missing',0
maintenance_str_unavailable: db 'status=unavailable',0
maintenance_str_sequence: db 'status=valid sequence=',0
maintenance_str_source: db ' source=',0
maintenance_str_boot: db 'boot_init',0
maintenance_str_image: db 'image_refusal',0
maintenance_str_crash: db 'crash',0
maintenance_str_component: db ' component=',0
maintenance_str_startup: db 'startup',0
maintenance_str_manager: db 'manager',0
maintenance_str_core: db 'core',0
maintenance_str_phase: db ' phase=',0
maintenance_str_gate: db ' gate=',0
maintenance_str_error: db ' error=',0
maintenance_str_identity: db ' identity=',0
maintenance_str_UNKNOWN: db 'UNKNOWN',0
maintenance_str_full: db 'source_image_sha256',0
maintenance_str_truncated: db 'truncated_build32',0
maintenance_str_build: db ' build=',0
maintenance_str_fingerprint: db ' fingerprint=',0
maintenance_str_digest: db ' source_digest=',0

align 2
maintenance_name: dw 'P','a','O','S','M','a','i','n','t','e','n','a','n','c','e','R','e','c','o','r','d',0
maintenance_tag: db 'maintenance_events',0
%include "core/abi/wdata.inc"
%macro WDATA_maintenance_record 0
maintenance_preview: times 512 db 0
maintenance_preview_overflow: db 0
align 8
maintenance_writes: dq 0
maintenance_uncertain: db 0
align 8
maintenance_size: dq 0
maintenance_attrs: dd 0
align 8
maintenance_hash: times 32 db 0
maintenance_candidate: times ME_RECORD_BYTES db 0
maintenance_work: times ME_BYTES db 0
maintenance_verify: times ME_BYTES db 0
maintenance_snapshot: times ME_BYTES db 0
maintenance_page: times ME_PAGE_BYTES db 0
%endmacro
WDATA_DEFER WDATA_maintenance_record
