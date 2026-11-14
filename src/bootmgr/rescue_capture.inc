; Diagnostic only. A signed capture build changes no boot authorization.
; Fixed RAM is accessed only after AllocateAddress(EfiReservedMemoryType).
; Kernel discovers it through the opt-in EFI config table, never a blind read.
CAPTURE_BASE equ 0x20000000
CAPTURE_BYTES equ 0x200000
CAPTURE_MAGIC equ 0x314d415250414350 ; PCAPRAM1
CAPTURE_USB_MAGIC equ 0x3142535550414350 ; PCAPUSB1

capture_header_identity:                 ; RSI = bounded 64-byte header
    mov rax,PBM_RESCUE_CAPTURE_NONCE
    cmp [rsi+8],rax
    jne .bad
    not rax
    cmp [rsi+16],rax
    jne .bad
    cmp qword [rsi+24],CAPTURE_BASE
    jne .bad
    cmp qword [rsi+32],CAPTURE_BYTES
    jne .bad
    cmp dword [rsi+60],1
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

capture_boot_init:
    ; Warm reset must not rely on dirty cache eviction. Known Intel/QEMU
    ; backends use 64-byte lines; refuse CPUs without that CLFLUSH contract.
    push rbx
    mov eax,1
    cpuid
    test edx,1<<19
    jz .no_flush
    shr ebx,8
    and ebx,0xff
    cmp ebx,8
    pop rbx
    jne .out
    ; No load, scan, allocation or touch of this range precedes reservation.
    mov qword [rel capture_address],CAPTURE_BASE
    mov ecx,2                           ; AllocateAddress
    xor edx,edx                         ; EfiReservedMemoryType
    mov r8d,CAPTURE_BYTES/4096
    lea r9,[rel capture_address]
    mov rax,[rel boot_services]
    PBM_FW_ENTER 32
    call [rax+0x28]                     ; AllocatePages
    PBM_FW_LEAVE 32
    test rax,rax
    jnz .out
    cmp qword [rel capture_address],CAPTURE_BASE
    jne .out
    mov byte [rel capture_available],1
    mov esi,CAPTURE_BASE
    mov rax,CAPTURE_MAGIC
    cmp [rsi],rax
    jne .out
    call capture_header_identity
    test eax,eax
    jz .out
    mov esi,CAPTURE_BASE
    cmp dword [rsi+40],1
    je .pending
    cmp dword [rsi+40],2
    jne .out
    mov byte [rel capture_pending],2    ; exported already; never relaunch same trial
    jmp .out
.pending:
    cmp dword [rsi+44],1                ; only our actual arm, not arbitrary RAM
    jne .out
    mov byte [rel capture_pending],1
    call capture_tco_disarm             ; before a slow USB/FAT operation
.out:
    ret
.no_flush:
    pop rbx
    ret

capture_flush_header:
    mov eax,CAPTURE_BASE
    clflush [rax]
    mfence
    ret

capture_begin:                          ; EAX=0 armed, nonzero refuse Rescue
    cmp byte [rel capture_available],1
    jne .fail
    cmp byte [rel capture_pending],0
    jne .fail
    ; Pre-created exact-size nonce marker must be on one USB volume. A missing
    ; or ambiguous destination refuses before watchdog or child side effects.
    call capture_find_usb
    mov [rel capture_io_result],eax
    call capture_close_destination
    cmp dword [rel capture_io_result],0
    jne .fail
    mov edi,CAPTURE_BASE
    mov ecx,CAPTURE_BYTES/8
    xor eax,eax
    rep stosq
    mov edi,CAPTURE_BASE
    mov rax,CAPTURE_MAGIC
    mov [rdi],rax
    mov rax,PBM_RESCUE_CAPTURE_NONCE
    mov [rdi+8],rax
    not rax
    mov [rdi+16],rax
    mov qword [rdi+24],CAPTURE_BASE
    mov qword [rdi+32],CAPTURE_BYTES
    mov dword [rdi+60],1
    ; Persist the cleared range too: an early EFI hang must not expose stale
    ; ramoops bytes that happened to survive only in DRAM under dirty zeros.
    mov eax,CAPTURE_BASE
.flush_initial:
    clflush [rax]
    add eax,64
    cmp eax,CAPTURE_BASE+CAPTURE_BYTES
    jb .flush_initial
    mfence
    lea rcx,[rel capture_config_guid]
    mov edx,CAPTURE_BASE
    mov rax,[rel boot_services]
    PBM_FW_ENTER 32
    call [rax+0x80]                     ; InstallConfigurationTable
    PBM_FW_LEAVE 32
    test rax,rax
    jnz .fail
    call capture_tco_arm
    mov edi,CAPTURE_BASE
    mov edx,[rel capture_tco_state]
    mov [rdi+44],edx
    test eax,eax
    jnz .fail
    mov dword [rdi+40],1                ; publish only after verified hardware arm
    call capture_flush_header
    lea rdi,[rel capture_text_armed]
    call serial_string
    xor eax,eax
    ret
.fail:
    lea rdi,[rel capture_text_unavailable]
    call serial_string
    mov eax,1
    ret

capture_export:                         ; called before normal policy/journal processing
    cmp byte [rel capture_pending],1
    jne .out
    call capture_find_usb
    test eax,eax
    jnz .fail
    mov rcx,[rel capture_file]
    xor edx,edx
    mov rax,rcx
    PBM_FW_ENTER 32
    call [rax+56]                       ; SetPosition(0)
    PBM_FW_LEAVE 32
    test rax,rax
    jnz .fail
    mov qword [rel capture_size],CAPTURE_BYTES
    mov rcx,[rel capture_file]
    lea rdx,[rel capture_size]
    mov r8d,CAPTURE_BASE
    mov rax,rcx
    PBM_FW_ENTER 32
    call [rax+40]                       ; Write only the preallocated PaOS file
    PBM_FW_LEAVE 32
    test rax,rax
    jnz .fail
    cmp qword [rel capture_size],CAPTURE_BYTES
    jne .fail
    mov rcx,[rel capture_file]
    mov rax,rcx
    PBM_FW_ENTER 32
    call [rax+80]                       ; Flush
    PBM_FW_LEAVE 32
    test rax,rax
    jnz .fail
    ; Bounded 4KiB streaming readback: no second 2MiB allocation or stale tail.
    mov rcx,[rel capture_file]
    xor edx,edx
    mov rax,rcx
    PBM_FW_ENTER 32
    call [rax+56]
    PBM_FW_LEAVE 32
    test rax,rax
    jnz .fail
    push rbx
    mov ebx,CAPTURE_BASE
.verify:
    mov qword [rel capture_size],4096
    mov rcx,[rel capture_file]
    lea rdx,[rel capture_size]
    lea r8,[rel capture_scratch]
    mov rax,rcx
    PBM_FW_ENTER 32
    call [rax+32]
    PBM_FW_LEAVE 32
    test rax,rax
    jnz .verify_fail
    cmp qword [rel capture_size],4096
    jne .verify_fail
    mov esi,ebx
    lea rdi,[rel capture_scratch]
    mov ecx,4096
    repe cmpsb
    jne .verify_fail
    add ebx,4096
    cmp ebx,CAPTURE_BASE+CAPTURE_BYTES
    jb .verify
    pop rbx
    ; File size was validated before opening and this transaction writes only
    ; its original extent. Check EOF again to reject concurrent/stale tails.
    mov qword [rel capture_size],1
    mov rcx,[rel capture_file]
    lea rdx,[rel capture_size]
    lea r8,[rel capture_scratch]
    mov rax,rcx
    PBM_FW_ENTER 32
    call [rax+32]
    PBM_FW_LEAVE 32
    test rax,rax
    jnz .fail
    cmp qword [rel capture_size],0
    jne .fail
    mov edi,CAPTURE_BASE
    mov dword [rdi+40],2                ; after durable, exact readback only
    call capture_flush_header
    mov byte [rel capture_exported],1
    call capture_close_destination
    lea rdi,[rel capture_text_exported]
    call serial_string
    ret
.verify_fail:
    pop rbx
.fail:
    call capture_close_destination
    lea rdi,[rel capture_text_failed]
    call serial_string
.out:
    ret

%include "bootmgr/rescue_capture_usb.inc"
%include "bootmgr/rescue_capture_tco.inc"
align 8
capture_config_guid: dd 0x9f8346e1
    dw 0x72b3,0x4c91
    db 0x9f,0x6a,0x70,0xae,0xb1,0x24,0x39,0x91
capture_file_info_guid: dd 0x09576e92
    dw 0x6d3f,0x11d2
    db 0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b
capture_path: dw __utf16__("\EFI\PaOS\rescue-capture.bin"),0
capture_text_armed: db "[PBM] capture.hardware-armed",13,10,0
capture_text_unavailable: db "[PBM] capture.UNAVAILABLE; Rescue not started",13,10,0
capture_text_exported: db "[PBM] capture.USB-exported exact-readback",13,10,0
capture_text_failed: db "[PBM] capture.export-failed; RAM retained",13,10,0
%macro PBM_CAPTURE_DATA 0
align 8
capture_address: dq 0
capture_size: dq 0
capture_file: dq 0
capture_root: dq 0
capture_handles: dq 0
capture_handle_count: dq 0
capture_scan_fs: dq 0
capture_scan_path: dq 0
capture_candidate: dq 0
capture_candidate_root: dq 0
capture_io_result: dd 0
capture_available: db 0
capture_pending: db 0
capture_exported: db 0
align 8
capture_scratch: times 4096 db 0
PBM_CAPTURE_TCO_DATA
%endmacro
