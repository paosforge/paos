;; MODULE bus/hest
;; LAYER 2
;; EXPORTS hest_cmci_policy
;; IMPORTS
;; CAPS
;; OWNER saga:bus
; ACPI HEST (18.3), byte-packed layouts, no firmware execution or hardware I/O.
; RDI=already RAM-range-qualified SDT, ESI=accessible bytes, EDX=acpi_find_table
; state (0 absent,1 valid), ECX=present. Return EAX=0 unknown,1 OS,2 firmware.
; The caller supplies 0 bytes on failed lookup. Never dereference absent input.
; Recheck exact signature/length/checksum and walk EVERY source. Unsupported or
; malformed tails defeat all positive ownership conclusions, including FF.
hest_cmci_policy:
    test ecx,ecx
    jnz .present
    test rdi,rdi
    jnz .unknown
    test esi,esi
    jnz .unknown
    test edx,edx
    jnz .unknown
    mov eax,1
    ret
.present:
    cmp ecx,1
    jne .unknown
    cmp edx,1
    jne .unknown
    test rdi,rdi
    jz .unknown
    cmp esi,40
    jb .unknown
    cmp esi,65536
    ja .unknown
    mov rax,rdi
    add rax,rsi
    jc .unknown
    cmp dword [rdi],'HEST'
    jne .unknown
    cmp [rdi+4],esi
    jne .unknown
    cmp byte [rdi+8],1
    jne .unknown
    xor eax,eax
    xor r8d,r8d
.checksum:
    add al,[rdi+r8]
    inc r8d
    cmp r8d,esi
    jb .checksum
    test al,al
    jnz .unknown
    mov r9d,[rdi+36]
    cmp r9d,4096
    ja .unknown
    mov r8d,40
    mov r11d,1                          ; OS only after the complete walk
.source:
    test r9d,r9d
    jz .done
    mov eax,esi
    sub eax,r8d
    cmp eax,4
    jb .unknown
    lea r10,[rdi+r8]
    movzx edx,word [r10]
    cmp edx,0
    je .mce
    cmp edx,1
    je .cmc
    cmp edx,2
    je .nmi
    cmp edx,6
    je .root
    cmp edx,7
    je .endpoint
    cmp edx,8
    je .bridge
    cmp edx,9
    je .ghes
    cmp edx,10
    je .ghes2
    cmp edx,11
    jne .unknown
    jmp .cmc
.mce:
    cmp eax,40
    jb .unknown
    movzx edx,byte [r10+32]
    imul edx,28
    add edx,40
    jmp .advance
.cmc:
    cmp eax,48
    jb .unknown
    cmp byte [r10+17],28
    jne .unknown
    cmp byte [r10+16],11
    ja .unknown
    cmp word [r10],1
    jne .cmc_size
    test byte [r10+6],1                 ; CMC FIRMWARE_FIRST only
    jz .cmc_size
    mov r11d,2
.cmc_size:
    movzx edx,byte [r10+44]
    imul edx,28
    add edx,48
    jmp .advance
.nmi:
    mov edx,20
    jmp .advance
.root:
    mov edx,48
    jmp .advance
.endpoint:
    mov edx,44
    jmp .advance
.bridge:
    mov edx,56
    jmp .advance
.ghes:
    mov edx,64
    jmp .generic
.ghes2:
    mov edx,92
.generic:
    cmp eax,edx
    jb .unknown
    cmp byte [r10+33],28
    jne .unknown
    cmp byte [r10+32],11
    ja .unknown
    cmp byte [r10+32],5                 ; GHES CMCI is firmware's route
    jne .advance
    mov r11d,2
.advance:
    cmp eax,edx
    jb .unknown
    add r8d,edx
    dec r9d
    jmp .source
.done:
    cmp r8d,esi                         ; unaccounted tail is not parsed
    jne .unknown
    mov eax,r11d
    ret
.unknown:
    xor eax,eax
    ret
