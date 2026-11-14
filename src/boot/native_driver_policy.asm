;; MODULE boot/native_driver_policy
;; LAYER 0
;; EXPORTS native_driver_policy_parse, native_driver_policy_decide
;; IMPORTS
;; CAPS
;; OWNER saga:boot
; Pure early policy contract. Callers must bind the selected configuration and
; invoke admission BEFORE any probe/hardware access, including lazy backends.
; This leaf alone does not activate or enforce a boot profile.
;
; parse: RDI readable byte span, RSI exact uint64 length; RAX policy or -1.
; Missing configuration is a caller decision (ordinary boot defaults to NORMAL);
; an explicitly supplied invalid value never falls back to NORMAL here.
; decide: RDI policy, RSI class, RDX candidate packed PCI BDF,
;         RCX verified boot-storage packed PCI BDF; RAX 0 allow / -1 deny.
; Both BDFs are uint64 inputs, valid only in [0,65535]. There is no wildcard or
; missing-binding sentinel in boot_only. Its caller must establish the firmware
; storage route before requesting STORAGE; equality cannot establish provenance.
; These two functions touch no hardware, allocate no state, preserve nonvolatile
; registers and accept full-width arguments (no truncation into valid values).

NDP_NORMAL          equ 0
NDP_BOOT_ONLY       equ 1
NDP_NETWORK_GUEST   equ 2            ; build selector, not A1 R2.MODE's enum
NDP_PLATFORM        equ 0            ; timers, PCI/IOMMU/VM substrate
NDP_FIRMWARE_GOP    equ 1
NDP_USB_CONTROLLER  equ 2
NDP_USB_HID         equ 3
NDP_DOMAIN_NET      equ 4            ; guest-backed, never native fallback
NDP_BOOT_STORAGE    equ 5
NDP_NATIVE_NET      equ 6            ; native PCI Ethernet / unclassified backend
NDP_NATIVE_SOUND    equ 7
NDP_ACCEL_DISPLAY   equ 8
NDP_OTHER_USB       equ 9
NDP_USB_NET         equ 10           ; exact USB Ethernet backends, HC owns DMA

native_driver_policy_parse:
    test rdi, rdi
    jz .invalid
    cmp rsi, 6
    je .normal
    cmp rsi, 9
    je .boot_only
    cmp rsi, 13
    jne .invalid
    cmp dword [rdi], 'netw'
    jne .invalid
    cmp dword [rdi + 4], 'ork_'
    jne .invalid
    cmp dword [rdi + 8], 'gues'
    jne .invalid
    cmp byte [rdi + 12], 't'
    jne .invalid
    mov eax, NDP_NETWORK_GUEST
    ret
.boot_only:
    cmp dword [rdi], 'boot'
    jne .invalid
    cmp dword [rdi + 4], '_onl'
    jne .invalid
    cmp byte [rdi + 8], 'y'
    jne .invalid
    mov eax, NDP_BOOT_ONLY
    ret
.normal:
    cmp dword [rdi], 'norm'
    jne .invalid
    cmp word [rdi + 4], 'al'
    jne .invalid
    xor eax, eax
    ret
.invalid:
    mov rax, -1
    ret

native_driver_policy_decide:
    cmp rdi, NDP_NORMAL
    je .allow                       ; ordinary boot keeps its existing choices
    cmp rdi, NDP_NETWORK_GUEST
    je .network_guest
    cmp rdi, NDP_BOOT_ONLY
    jne .deny
    cmp rsi, NDP_DOMAIN_NET
    jbe .allow
    cmp rsi, NDP_BOOT_STORAGE
    jne .deny                       ; native/unknown classes never admitted
    cmp rdx, 0xffff
    ja .deny
    cmp rcx, 0xffff
    ja .deny
    cmp rdx, rcx
    jne .deny
    jmp .allow
.network_guest:
    ; This suppresses native probes; it grants no assignment, reset method,
    ; IOMMU group, signed guest policy or return authority. USB NIC requesters
    ; remain the already witnessed host controllers. Unknown classes refuse.
    cmp rsi, NDP_USB_NET
    ja .deny
    cmp rsi, NDP_NATIVE_NET
    je .deny
.allow:
    xor eax, eax
    ret
.deny:
    mov rax, -1
    ret
