; Opt-in Rescue capture hardware watchdog. Same TCO register/discovery model
; as core/tco_deadman.asm, restricted to measured MSI 7f23 and QEMU ICH9 2918.
; Firmware LOCK means unavailable: no TCO/RCBA writes on that path.
; No firmware watchdog or software reset is represented as hardware coverage.
%ifndef PBM_CAPTURE_TCO_TICKS
%define PBM_CAPTURE_TCO_TICKS 125 ; two 75-second periods = 150 seconds
%endif
%if PBM_CAPTURE_TCO_TICKS < 4 || PBM_CAPTURE_TCO_TICKS > 1023
%error capture TCO ticks must fit hardware and exceed minimum
%endif
capture_tco_arm:
    push rbx
    push r12
    push r13
    mov dword [rel capture_tco_state],2
    call capture_tco_discover
    test eax,eax
    jz .fail
    mov ebx,eax
    mov [rel capture_tco_base],ax
    mov r13d,edx
    lea edx,[rbx+8]
    in ax,dx
    movzx r12d,ax
    test ax,0x1000
    jnz .locked
    test r13d,r13d
    jnz .modern
    xor edi,edi
    mov esi,0x1f
    xor edx,edx
    mov ecx,0xf0
    call capture_tco_cfg_read32
    test eax,1
    jz .noreboot
    and eax,0xffffc000
    jz .noreboot
    lea rcx,[rax+0x3410]
    mov eax,[rcx]
    and eax,~0x20
    mov [rcx],eax
    test dword [rcx],0x20
    jnz .noreboot
    jmp .timer
.modern:
    lea edx,[rbx+8]
    mov eax,r12d
    and ax,0xfffe
    out dx,ax
    in ax,dx
    test ax,1
    jnz .noreboot
.timer:
    ; Halt while changing the period and clear stale expiry, then start.
    lea edx,[rbx+8]
    in ax,dx
    or ax,0x0800
    out dx,ax
    lea edx,[rbx+0x12]
    in ax,dx
    and ax,0xfc00
    or ax,PBM_CAPTURE_TCO_TICKS
    out dx,ax
    in ax,dx
    and ax,0x3ff
    cmp ax,PBM_CAPTURE_TCO_TICKS
    jne .readback
    lea edx,[rbx+4]
    mov ax,8
    out dx,ax
    lea edx,[rbx+6]
    mov ax,6
    out dx,ax
    mov edx,ebx
    mov ax,1
    out dx,ax
    lea edx,[rbx+8]
    in ax,dx
    and ax,0xf7ff
    out dx,ax
    in ax,dx
    test ax,0x0800
    jnz .readback
    mov dword [rel capture_tco_state],1
    xor eax,eax
    jmp .out
.locked:
    mov dword [rel capture_tco_state],3
    jmp .fail
.noreboot:
    mov dword [rel capture_tco_state],4
    jmp .fail
.readback:
    mov dword [rel capture_tco_state],5
    ; A partially programmed unlocked timer must not follow a failed launch.
    call capture_tco_disarm
.fail:
    mov eax,1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Called only for this nonce's validated pending capture or our own arm.
; Rediscover; never use a persisted port number or touch a locked watchdog.
capture_tco_disarm:
    push rbx
    call capture_tco_discover
    test eax,eax
    jz .out
    mov ebx,eax
    lea edx,[rbx+8]
    in ax,dx
    test ax,0x1000
    jnz .out
    or ax,0x0800
    out dx,ax
.out:
    pop rbx
    ret

capture_tco_discover:
    push rbx
    push r12
    lea  r12, [rel capture_tco_buses]
    xor  ebx, ebx
.smbus:
    cmp  ebx, 2
    jae  .lpc
    movzx edi, byte [r12 + rbx]
    mov  esi, 0x1f
    mov  edx, 4
    xor  ecx, ecx
    call capture_tco_cfg_read32
    cmp  eax, 0x7f238086
    jne  .next_bus
    movzx edi, byte [r12 + rbx]
    mov  esi, 0x1f
    mov  edx, 4
    mov  ecx, 0x08
    call capture_tco_cfg_read32
    shr  eax, 16
    cmp  ax, 0x0c05                     ; SMBus
    jne  .next_bus
    movzx edi, byte [r12 + rbx]
    mov  esi, 0x1f
    mov  edx, 4
    mov  ecx, 0x54                      ; TCOCTL
    call capture_tco_cfg_read32
    test eax, 0x100                     ; TCO_BASE_EN
    jz   .next_bus
    movzx edi, byte [r12 + rbx]
    mov  esi, 0x1f
    mov  edx, 4
    mov  ecx, 0x50                      ; TCOBASE
    call capture_tco_cfg_read32
    and  eax, 0xffe0
    jz   .next_bus
    mov  edx, 1
    jmp  .out
.next_bus:
    inc  ebx
    jmp  .smbus
.lpc:
    xor  edi, edi
    mov  esi, 0x1f
    xor  edx, edx
    xor  ecx, ecx
    call capture_tco_cfg_read32
    cmp  eax, 0x29188086
    jne  .none
    xor  edi, edi
    mov  esi, 0x1f
    xor  edx, edx
    mov  ecx, 0x08
    call capture_tco_cfg_read32
    shr  eax, 16
    cmp  ax, 0x0601                     ; ISA bridge (LPC)
    jne  .none
    xor  edi, edi
    mov  esi, 0x1f
    xor  edx, edx
    mov  ecx, 0x44                      ; ACPI_CNTL
    call capture_tco_cfg_read32
    test eax, 0x80                      ; ACPI_EN
    jz   .none
    xor  edi, edi
    mov  esi, 0x1f
    xor  edx, edx
    mov  ecx, 0x40                      ; ACPI base (PMBASE)
    call capture_tco_cfg_read32
    and  eax, 0xff80
    jz   .none
    add  eax, 0x60
    xor  edx, edx
    jmp  .out
.none:
    xor  eax, eax
    xor  edx, edx
.out:
    pop  r12
    pop  rbx
    ret

; capture_tco_cfg_read32(EDI bus, ESI device, EDX function, ECX offset) -> EAX: the
; same CF8/CFC read as bus/pci, local so this layer-1 module imports no driver.
capture_tco_cfg_read32:
    mov  eax, edi
    shl  eax, 16
    mov  r8d, esi
    shl  r8d, 11
    or   eax, r8d
    mov  r8d, edx
    shl  r8d, 8
    or   eax, r8d
    mov  r8d, ecx
    and  r8d, 0xfc
    or   eax, r8d
    or   eax, 0x80000000
    mov  dx, 0x0cf8
    out  dx, eax
    mov  dx, 0x0cfc
    in   eax, dx
    ret

capture_tco_buses: db 0x80,0
%macro PBM_CAPTURE_TCO_DATA 0
capture_tco_state: dd 0
capture_tco_base: dw 0
align 8
%endmacro
