;; MODULE sec/platform_key_health
;; LAYER 3
;; EXPORTS platform_key_health_snapshot, platform_key_health_classify, platform_key_health_text, platform_key_health_state
;; IMPORTS boot/header
;; CAPS
;; OWNER saga:sec
;; CONTEXT: bsp_only
; Read-only, pre-EBS PK label observation. NOT a certificate/trust validator.
; 0 unknown (including unsupported/malformed), 1 no test label, 2 test label.
; Only an X509 PK with one ESL/entry is understood. A nonmatch never means safe.
; Names are walked structurally; arbitrary extensions/signatures are not labels.

PK_HEALTH_MAX equ 8192

platform_key_health_snapshot:
    push rbx
    mov byte [rel platform_key_health_state],0
    mov rax,[rel runtime_services]
    test rax,rax
    jz .done
    cmp qword [rax+0x48],0
    je .done
    mov qword [rel pk_health_size],PK_HEALTH_MAX
    mov dword [rel pk_health_attrs],0
    lea rcx,[rel pk_health_name]
    lea rdx,[rel pk_health_guid]
    lea r8,[rel pk_health_attrs]
    lea r9,[rel pk_health_size]
    sub rsp,48                         ; caller aligned + EFI shadow/fifth arg
    lea rbx,[rel pk_health_buf]
    mov [rsp+32],rbx
    call [rax+0x48]                     ; GetVariable only, never SetVariable
    add rsp,48
    test rax,rax
    jnz .done
    mov rsi,[rel pk_health_size]
    cmp rsi,PK_HEALTH_MAX
    ja .done
    ; PK must have NV|BS|RT, with only documented authenticated-write bits.
    mov eax,[rel pk_health_attrs]
    mov edx,eax
    and edx,7
    cmp edx,7
    jne .done
    and eax,~0x37
    jnz .done
    mov rdi,rbx
    call platform_key_health_classify
    mov [rel platform_key_health_state],al
.done:
    pop rbx
    ret

; RDI=raw EFI_SIGNATURE_LIST bytes (no efivarfs attrs), ESI=size -> EAX enum.
; Caller owns buffer; bounded to8KiB; no firmware or pointer retention.
platform_key_health_classify:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    xor ebx,ebx
    test rdi,rdi
    jz .out
    cmp esi,74                         ; header28 + owner16 + certificate
    jb .out
    cmp esi,PK_HEALTH_MAX
    ja .out
    mov eax,esi
    add rax,rdi
    jc .out
    mov rax,0x4aa794e4a5c059a1         ; EFI_CERT_X509_GUID, bytes_le
    cmp [rdi],rax
    jne .out
    mov rax,0x72f02b5c15abb587
    cmp [rdi+8],rax
    jne .out
    cmp [rdi+16],esi                   ; exactly one list
    jne .out
    cmp dword [rdi+20],0               ; X509 header is empty
    jne .out
    mov eax,esi
    sub eax,28
    cmp [rdi+24],eax                   ; exactly one signature/owner
    jne .out
    lea rsi,[rdi+rsi]
    add rdi,44
    call pk_health_tlv
    jc .out
    cmp eax,0x30
    jne .out
    cmp rdi,rsi                       ; exact one certificate DER object
    jne .out
    mov rdi,r8
    mov rsi,r9
    call pk_health_tlv                 ; TBSCertificate
    jc .out
    cmp eax,0x30
    jne .out
    mov r12,r8
    mov r13,r9
    call pk_health_tlv                 ; signatureAlgorithm
    jc .out
    cmp eax,0x30
    jne .out
    test ecx,ecx
    jz .out
    call pk_health_tlv                 ; signatureValue BIT STRING
    jc .out
    cmp eax,3
    jne .out
    cmp ecx,2
    jb .out
    cmp byte [r8],7
    ja .out
    cmp rdi,rsi
    jne .out
    mov rdi,r12
    mov rsi,r13
    call pk_health_tlv
    jc .out
    cmp eax,0xa0                      ; optional explicit version
    jne .serial
    ; version must contain one short INTEGER0..2
    cmp ecx,3
    jne .out
    cmp word [r8],0x0102
    jne .out
    cmp byte [r8+2],2
    ja .out
    call pk_health_tlv
    jc .out
.serial:
    cmp eax,2
    jne .out
    test ecx,ecx
    jz .out
    call pk_health_tlv                 ; signature AlgorithmIdentifier
    jc .out
    cmp eax,0x30
    jne .out
    call pk_health_tlv                 ; issuer Name
    jc .out
    cmp eax,0x30
    jne .out
    mov r14,rdi
    mov rdi,r8
    mov rsi,r9
    call pk_health_name_labels
    cmp eax,-1
    je .out
    mov ebp,eax
    mov rdi,r14
    mov rsi,r13
    call pk_health_tlv                 ; validity
    jc .out
    cmp eax,0x30
    jne .out
    call pk_health_tlv                 ; subject Name
    jc .out
    cmp eax,0x30
    jne .out
    mov r14,rdi
    mov rdi,r8
    mov rsi,r9
    call pk_health_name_labels
    cmp eax,-1
    je .out
    or ebp,eax
    mov rdi,r14
    mov rsi,r13
    call pk_health_tlv                 ; subjectPublicKeyInfo, not verified here
    jc .out
    cmp eax,0x30
    jne .out
.optional:
    cmp rdi,rsi
    je .parsed
    call pk_health_tlv                 ; bounded optional unique IDs/extensions
    jc .out
    cmp eax,0x81
    je .optional
    cmp eax,0x82
    je .optional
    cmp eax,0xa3
    jne .out
    jmp .optional
.parsed:
    lea ebx,[rbp+1]
.out:
    mov eax,ebx
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; RDI cursor, RSI exclusive bound -> EAX tag,ECX length,R8 value,R9 end,
; RDI advanced to end, CF refusal. Only canonical definite DER lengths <=3B.
pk_health_tlv:
    cmp rdi,rsi
    jae .bad
    mov rdx,rsi
    sub rdx,rdi
    cmp rdx,2
    jb .bad
    movzx eax,byte [rdi]
    movzx ecx,byte [rdi+1]
    add rdi,2
    test cl,0x80
    jz .length
    and ecx,0x7f
    jz .bad
    cmp ecx,3
    ja .bad
    mov rdx,rsi
    sub rdx,rdi
    cmp rdx,rcx
    jb .bad
    cmp byte [rdi],0
    je .bad
    mov edx,ecx
    xor ecx,ecx
.long:
    shl ecx,8
    movzx r10d,byte [rdi]
    or ecx,r10d
    inc rdi
    dec edx
    jnz .long
    cmp ecx,128
    jb .bad
.length:
    mov rdx,rsi
    sub rdx,rdi
    cmp rdx,rcx
    jb .bad
    mov r8,rdi
    add rdi,rcx
    mov r9,rdi
    clc
    ret
.bad:
    stc
    ret

; Name SEQUENCE content. Walk SET/SEQUENCE/OID/value; only DirectoryString
; bytes from actual issuer/subject attributes are searched. EAX=0/1,-1 malformed.
pk_health_name_labels:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    xor ebx,ebx
    mov r12,rsi
.set:
    cmp rdi,r12
    je .done
    mov rsi,r12
    call pk_health_tlv
    jc .bad
    cmp eax,0x31
    jne .bad
    test ecx,ecx
    jz .bad
    mov r13,r9
    mov rdi,r8
.attribute:
    mov rsi,r13
    call pk_health_tlv
    jc .bad
    cmp eax,0x30
    jne .bad
    mov r14,r9
    mov rdi,r8
    mov rsi,r14
    call pk_health_tlv
    jc .bad
    cmp eax,6
    jne .bad
    test ecx,ecx
    jz .bad
    call pk_health_tlv
    jc .bad
    cmp rdi,r14
    jne .bad
    mov r15,rdi
    cmp eax,0x0c                      ; UTF8String
    je .ascii
    cmp eax,0x13                      ; PrintableString
    je .ascii
    cmp eax,0x14                      ; TeletexString (ASCII label subset)
    je .ascii
    cmp eax,0x16                      ; IA5String
    je .ascii
    cmp eax,0x1e                      ; BMPString
    jne .bad
    test ecx,1
    jnz .bad
    mov ebp,2
    jmp .scan
.ascii:
    mov ebp,1
.scan:
    mov rdi,r8
    mov rsi,r9
    lea rdx,[rel pk_health_dont_trust]
    call pk_health_contains
    or ebx,eax
    lea rdx,[rel pk_health_dont_ship]
    call pk_health_contains
    or ebx,eax
.next:
    mov rdi,r15
    cmp rdi,r13
    jb .attribute
    jmp .set
.bad:
    mov ebx,-1
.done:
    mov eax,ebx
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Search complete label with ascii-folding, EBP=1 ASCII/UTF8 or2 BMP big-endian.
; RDI/RSI/ RDX retained. Fixed two needles; <=8KiB total input.
pk_health_contains:
    mov r8,rdi
.start:
    cmp r8,rsi
    jae .no
    mov r9,r8
    mov r10,rdx
.char:
    movzx eax,byte [r10]
    test al,al
    jz .yes
    mov rcx,rsi
    sub rcx,r9
    cmp rcx,rbp
    jb .advance
    cmp ebp,2
    jne .byte
    cmp byte [r9],0
    jne .advance
.byte:
    movzx ecx,byte [r9+rbp-1]
    cmp cl,'a'
    jb .folded
    cmp cl,'z'
    ja .folded
    sub cl,32
.folded:
    cmp cl,al
    jne .advance
    add r9,rbp
    inc r10
    jmp .char
.advance:
    add r8,rbp
    jmp .start
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

platform_key_health_text:
    lea rax,[rel pk_health_unknown]
    cmp byte [rel platform_key_health_state],1
    jne .test
    lea rax,[rel pk_health_no_label]
    ret
.test:
    cmp byte [rel platform_key_health_state],2
    jne .out
    lea rax,[rel pk_health_warning]
.out:
    ret

align 8
pk_health_guid: dd 0x8be4df61
    dw 0x93ca,0x11d2
    db 0xaa,0x0d,0x00,0xe0,0x98,0x03,0x2b,0x8c
pk_health_name: dw 'P','K',0
pk_health_dont_trust: db 'DO NOT TRUST',0
pk_health_dont_ship: db 'DO NOT SHIP',0
pk_health_unknown: db 'Firmware PK: unread/unsupported - trust unknown',0
pk_health_no_label: db 'Firmware PK: no test label - trust unverified',0
pk_health_warning: db 'WARNING: firmware PK is marked DO NOT TRUST/SHIP',0
%macro WDATA_sec_platform_key_health 0
align 8, db 0
pk_health_size: dq 0
pk_health_attrs: dd 0
platform_key_health_state: db 0
align 16
pk_health_buf: times PK_HEALTH_MAX db 0

%endmacro
WDATA_DEFER WDATA_sec_platform_key_health
