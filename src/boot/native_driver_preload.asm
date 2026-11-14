;; MODULE boot/native_driver_preload
;; LAYER 0
;; EXPORTS native_driver_preload, native_driver_selected_policy, native_driver_boot_bdf
;; IMPORTS boot/header, boot/native_driver_policy
;; CAPS
;; OWNER saga:boot
; Read-only, PRE-EBS selector on the firmware-selected LoadedImage.DeviceHandle.
; Exact ASCII normal/boot_only/network_guest in the engineering-only selector,
; \EFI\PaOS\native-drivers.cfg, no terminator.
; The compiled default is normal: retain existing native driver authorization.
; Devices not claimed natively keep the existing isolated driver-domain path.
; PAOS_NATIVE_DRIVER_DEFAULT=1 selects the optional boot_only proof profile;
; it is not a public-release prerequisite (Peter 11/04, spec 0.80).
; DEFAULT=2 reserves PCI NICs for the trusted network guest; ordinary non-NIC
; devices and exact USB NICs remain eligible. Assignment/reset are separate.
; Engineering builds retain the exact read-only selector. Invalid selection/read/
; close errors refuse (-1); failed controller discovery never grants storage.
; The selector conveys no storage grant or hardware assignment authority.
; A selected boot_only also captures the PCI controller on that exact volume's
; device path, using the same firmware protocol rail as rescue0_snp. Unknown or
; nonzero-segment location stays -1, never a wildcard. BDF alone does not select
; a USB child: USB storage additionally needs the existing boot port-chain match.
; No LocateHandle enumeration, writes, firmware variables, heap or allocation.
; Publication into the boot probe graph belongs to the complete policy unit.
; A public build never opens a file: policy is fixed at build and the file name
; is not in the image: the ESP is writable by any other OS. The retired
; boot_only release default is not restored by this exclusion.
; PAOS_PUBLIC_BUILD=0 is an engineering
; build, so defined alone is not public.
%ifndef PAOS_NATIVE_DRIVER_DEFAULT
%define PAOS_NATIVE_DRIVER_DEFAULT 0
%endif
%if PAOS_NATIVE_DRIVER_DEFAULT != 0 && PAOS_NATIVE_DRIVER_DEFAULT != 1 && PAOS_NATIVE_DRIVER_DEFAULT != 2
%error "PAOS_NATIVE_DRIVER_DEFAULT must be 0, 1 or 2"
%endif
%define NDP_FILE_SELECTOR 1
%ifdef PAOS_PUBLIC_BUILD
%if PAOS_PUBLIC_BUILD != 0
%undef NDP_FILE_SELECTOR
%define NDP_FILE_SELECTOR 0
%ifndef PAOS_DRIVER_DOMAIN_EVERYBOOT
%error "public build requires PAOS_DRIVER_DOMAIN_EVERYBOOT"
%endif
%endif
%endif

native_driver_preload:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    and rsp, -16
    sub rsp, 80
    mov qword [rel native_driver_selected_policy], PAOS_NATIVE_DRIVER_DEFAULT
    mov qword [rel native_driver_boot_bdf], -1
    mov qword [rsp + 40], 0          ; root
    mov qword [rsp + 48], 0          ; config file
    mov qword [rsp + 56], 0          ; read position
    mov qword [rsp + 72], -1         ; provisional parsed value
%if NDP_FILE_SELECTOR == 0 && PAOS_NATIVE_DRIVER_DEFAULT != 1
    ; Fixed normal/network_guest need no volume/controller or ESP policy.
    jmp .out
%endif
    mov rbx, [rel boot_services]
    test rbx, rbx
    jz .out
    mov qword [rsp + 64], 0
    mov rcx, [rel image_handle]
    lea rdx, [rel ndp_loaded_guid]
    lea r8, [rsp + 64]
    call [rbx + 0x98]
    test rax, rax
    jnz .out
    mov rax, [rsp + 64]
    test rax, rax
    jz .out
    mov r12, [rax + 24]             ; real/PAX1 boot volume, never FilePath
    test r12, r12
    jz .out
%if NDP_FILE_SELECTOR == 0
    mov rdi, r12
    call ndp_capture_controller
%else
    mov qword [rsp + 64], 0
    mov rcx, r12
    lea rdx, [rel ndp_fs_guid]
    lea r8, [rsp + 64]
    call [rbx + 0x98]
    test rax, rax
    jnz .out
    mov rcx, [rsp + 64]
    test rcx, rcx
    jz .out
    lea rdx, [rsp + 40]
    call [rcx + 8]                  ; OpenVolume
    test rax, rax
    jnz .out
    mov rcx, [rsp + 40]
    test rcx, rcx
    jz .out
    lea rdx, [rsp + 48]
    lea r8, [rel ndp_config_path]
    mov r9d, 1                      ; EFI_FILE_MODE_READ
    mov qword [rsp + 32], 0         ; no attributes/create/write
    call [rcx + 8]
    mov rdx, 0x800000000000000e     ; EFI_NOT_FOUND alone means no selection
    cmp rax, rdx
    je .close_root_absent
    mov qword [rel native_driver_selected_policy], -1
    test rax, rax
    jnz .close_opened
    cmp qword [rsp + 48], 0
    je .close_root
.read:
    mov rax, 16
    sub rax, [rsp + 56]
    jz .close_file                  ; 16 bytes cannot be an accepted value
    mov [rsp + 64], rax
    mov [rsp + 32], rax             ; requested size, preserved over firmware
    mov rcx, [rsp + 48]
    lea rdx, [rsp + 64]
    lea r8, [rel ndp_config_bytes]
    add r8, [rsp + 56]
    call [rcx + 32]                 ; Read, including exact EOF after partials
    test rax, rax
    jnz .close_file
    mov rax, [rsp + 64]
    cmp rax, [rsp + 32]
    ja .close_file
    test rax, rax
    jz .parse
    add [rsp + 56], rax
    jmp .read
.parse:
    lea rdi, [rel ndp_config_bytes]
    mov rsi, [rsp + 56]
    call native_driver_policy_parse
    mov [rsp + 72], rax
.close_file:
    mov rcx, [rsp + 48]
    call [rcx + 16]
    test rax, rax
    jz .close_root
    mov qword [rsp + 72], -1
.close_root:
    mov rcx, [rsp + 40]
    call [rcx + 16]
    test rax, rax
    jnz .out                       ; selected already -1
    mov rax, [rsp + 72]
    mov [rel native_driver_selected_policy], rax
    cmp rax, 1
    jne .out
    mov rdi, r12
    call ndp_capture_controller
    jmp .out
.close_opened:
    cmp qword [rsp + 48], 0
    je .close_root
    jmp .close_file
.close_root_absent:
    mov rcx, [rsp + 40]
    call [rcx + 16]
    test rax, rax
    jnz .close_absent_failed
%if PAOS_NATIVE_DRIVER_DEFAULT == 1
    mov rdi,r12
    call ndp_capture_controller
%endif
    jmp .out
.close_absent_failed:
    mov qword [rel native_driver_selected_policy], -1
%endif
.out:
    lea rsp, [rbp - 16]
    pop r12
    pop rbx
    pop rbp
    ret

; RDI exact LoadedImage.DeviceHandle. Capture only validated segment-zero BDF.
ndp_capture_controller:
    push rbp
    mov rbp, rsp
    push rbx
    and rsp, -16
    sub rsp, 96
    mov rbx, [rel boot_services]
    mov rcx, rdi
    lea rdx, [rel ndp_dp_guid]
    lea r8, [rsp + 40]
    mov qword [rsp + 40], 0
    call [rbx + 0x98]
    test rax, rax
    jnz .out
    cmp qword [rsp + 40], 0
    je .out
    lea rcx, [rel ndp_pci_guid]
    lea rdx, [rsp + 40]             ; firmware advances only this local copy
    lea r8, [rsp + 48]
    mov qword [rsp + 48], 0
    call [rbx + 0xb8]               ; LocateDevicePath(PciIo,&path,&handle)
    test rax, rax
    jnz .out
    mov rcx, [rsp + 48]
    test rcx, rcx
    jz .out
    lea rdx, [rel ndp_pci_guid]
    lea r8, [rsp + 40]
    mov qword [rsp + 40], 0
    call [rbx + 0x98]
    test rax, rax
    jnz .out
    mov rcx, [rsp + 40]
    test rcx, rcx
    jz .out
    mov qword [rsp + 56], -1
    mov qword [rsp + 64], -1
    mov qword [rsp + 72], -1
    mov qword [rsp + 80], -1
    lea rdx, [rsp + 56]
    lea r8, [rsp + 64]
    lea r9, [rsp + 72]
    lea rax, [rsp + 80]
    mov [rsp + 32], rax
    call [rcx + 112]                ; GetLocation(This,&segment,&bus,&dev,&fn)
    test rax, rax
    jnz .out
    cmp qword [rsp + 56], 0
    jne .out
    cmp qword [rsp + 64], 255
    ja .out
    cmp qword [rsp + 72], 31
    ja .out
    cmp qword [rsp + 80], 7
    ja .out
    mov rax, [rsp + 64]
    shl eax, 8
    mov rdx, [rsp + 72]
    shl edx, 3
    or eax, edx
    or rax, [rsp + 80]
    mov [rel native_driver_boot_bdf], rax
.out:
    lea rsp, [rbp - 8]
    pop rbx
    pop rbp
    ret

align 2
%if NDP_FILE_SELECTOR
ndp_config_path: dw __utf16__('\EFI\PaOS\native-drivers.cfg'), 0
%endif
ndp_loaded_guid: dd 0x5b1b31a1
                 dw 0x9562, 0x11d2
                 db 0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b
%if NDP_FILE_SELECTOR
ndp_fs_guid: dd 0x964e5b22
             dw 0x6459, 0x11d2
             db 0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b
%endif
ndp_dp_guid: dd 0x09576e91
             dw 0x6d3f,0x11d2
             db 0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b
ndp_pci_guid: dd 0x4cf5b200
              dw 0x68b8,0x4ca5
              db 0x9e,0xec,0xb2,0x3e,0x3f,0x50,0x02,0x9a

%include "core/abi/wdata.inc"
%macro WDATA_native_driver_preload 0
alignb 8
native_driver_selected_policy: resq 1
native_driver_boot_bdf: resq 1
ndp_config_bytes: resb 16
%endmacro
WDATA_BSS_DEFER WDATA_native_driver_preload
