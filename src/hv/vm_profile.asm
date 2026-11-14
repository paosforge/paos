;; MODULE hv/vm_profile
;; LAYER 5
;; EXPORTS vm_profile_smp2_match, vm_profile_name83_valid, vm_profile_pair_configure, vm_profile_request, vm_profile_pair_finish, vm_profile_pair_health, vm_profile_pair_recover, vm_profile_pair_durable, vm_profile_pair_state, vm_profile_validate, vm_profile_plan, vm_profile_plan_mask, vm_profile_find, vm_profile_select, vm_profile_reset_legacy, vm_profile_bind_launch, vm_profile_compose_cmdline, vm_profile_dep_verify, vm_profile_page_selected, vm_profile_live_reset, vm_profile_render_list, vm_profile_render_plan, vm_profile_render_live, vm_profile_active, vm_profile_dev_mask, vm_profile_gen, vm_profile_kdep, vm_profile_idep, vm_profile_plan_cur, vm_profile_live_devices, vm_profile_live_mmio, vm_profile_live_leaves, vm_profile_live_reserve, vp_builtin_table
;; IMPORTS hv/vcpu_ap_run, hv/vcpu_bsp, core/lib/sha256, hv/vmx, hv/pad_channel, hv/filesystem_domain, hv/wifi_channel, hv/guestpower
;; CAPS
;; OWNER saga:hv
; ============================================================================
; RCQ-18 slice 1: typed, signed VM profiles for the modular Linux guest.
;
; A profile names what one guest gets: vCPUs, RAM, the emulated devices, and
; the exact artifacts it boots (kind, 8.3 name, size, SHA-256). The built-in
; records below live in the signed payload image, so the image signature covers
; them, and every artifact byte is bound to the record's size and hash at
; START (vmx.asm hv_linux_prepare). A record is parsed fail-closed: wrong
; length/version, a bad name, reserved bits, an unsupported vCPU count, RAM out
; of bounds or unaligned, an unknown device, a broken closure, or a malformed
; dependency each refuse with a distinct status before any resource is used.
;
; Closure rules (v1):
;   - TIMER (PIT/PIC + IRQ0) is required: userspace cannot run without it
;     (ESSENCE E2). CONSOLE is required: both classes are CLI profiles.
;   - The thin-cli class is EXACTLY timer+console. Anything more is not thin.
;   - RCQ-23: the desktop class is timer+console+display+input, optionally SOUND; no
;     other class may select display or input (a display without the desktop
;     that owns it, or an input device without its display, is not a closure).
;   - RCQ-36: PADCHAN gives hvc0 to the PAD1 service. Only a CLI class may
;     select it, and then EXACTLY timer+console+padchan: no text-line device
;     (net injection, restore) can share the private console.
;   - Exactly one kernel and one initrd dependency; unused slots are all zero.
;   - Page-rounded kernel+initrd extents must fit above the kernel load address
;     in profile RAM. The loader also checks the kernel's actual init_size.
;
; An omitted device costs nothing: vmx.asm maps, resets, declares on the guest
; cmdline and services a device page only when its bit is selected, and an
; access to an omitted device's page is a foreign GPA (the guest stops). The
; plan below counts what each selection costs; the live counters record what
; the loader actually built, so the two can be compared.
;
; No selection (GUESTVM START with no name, GUESTNET, VTD, browser, fixtures)
; keeps the legacy fixed shape byte-for-byte: 64 MiB, timer+console+net.
; A selection is bound to the one START generation that requested it; any
; other launch restores the legacy selectors first (vm_profile_bind_launch).
;
; SysV ABI; caller-saved registers clobbered unless noted.
; ============================================================================

; The RCQ-37 media contract (hv/guest_media_contract.inc) is included by paos.asm before
; this file; harnesses that assemble this file alone see the flag undefined (OFF).

VP_VERSION       equ 0                  ; u32 = 1
VP_SIZE          equ 4                  ; u32 = VP_BYTES (exact extent)
VP_NAME          equ 8                  ; 24 bytes: [a-z0-9-]{1,23}, NUL, zero pad
VP_CLASS         equ 32                 ; u8
VP_FLAGS         equ 33                 ; u8 = 0 in v1
VP_NDEPS         equ 34                 ; u8, used dependency slots
VP_RSVD0         equ 35                 ; u8 = 0
VP_VCPUS         equ 36                 ; u32
VP_RAM           equ 40                 ; u64 bytes
VP_DEVICES       equ 48                 ; u32 device mask
VP_RSVD1         equ 52                 ; u32 = 0
VP_DEPS          equ 56                 ; VP_DEP_MAX * VP_DEP_BYTES
VP_DEP_MAX       equ 4
VP_DEP_BYTES     equ 56
VP_BYTES         equ VP_DEPS + VP_DEP_MAX * VP_DEP_BYTES
VP_NAME_BYTES    equ 24

VPD_KIND         equ 0                  ; u8: 1 kernel, 2 initrd
VPD_RSVD         equ 1                  ; 4 bytes = 0
VPD_NAME         equ 5                  ; 11 bytes, FAT 8.3 form (the VFS name)
VPD_SIZE         equ 16                 ; u64 exact byte length
VPD_SHA          equ 24                 ; 32-byte SHA-256 of the whole file

VP_CLASS_THIN_CLI equ 1
VP_CLASS_CLI      equ 2
VP_CLASS_DESKTOP  equ 3                 ; RCQ-23: a graphical guest in a PaOS window

VP_DEV_TIMER     equ 1
VP_DEV_CONSOLE   equ 2
VP_DEV_NET       equ 4
VP_DEV_DISPLAY   equ 8                  ; RCQ-23: private framebuffer, simplefb via screen_info
VP_DEV_INPUT     equ 16                 ; RCQ-23: virtio-input keyboard+pointer (third MMIO page)
VP_DEV_ENTROPY   equ 32                 ; opt-in modern virtio-rng, IRQ3
VP_DEV_SOUND     equ 64                 ; opt-in virtio-snd playback, IRQ7
VP_DEV_RESTORE   equ 128                ; opt-in paos.restore control port, IRQ5 shared with console
VP_DEV_PADCHAN   equ 256                ; RCQ-36: hvc0 is the private PAD1 port (hv/pad_channel)
VP_DEV_PCIHDA    equ 512                ; RCQ-36 V2: the host HDA function assigned (hv/pci_assign), IRQ6 polled
VP_DEV_LAPIC     equ 1024               ; RCQ-50 S4: virtual x2APIC (hv/guest_lapic), CLI class only; 512 is V2's
VP_DEV_NIC       equ 32768              ; exclusive selected physical NIC, no virtio page
VP_DEV_NICDOMAIN equ VP_DEV_TIMER | VP_DEV_CONSOLE | VP_DEV_NET | VP_DEV_NIC
VP_DEV_WIFI      equ 65536              ; private association console, NIC-domain only
VP_DEV_WIFIDOMAIN equ VP_DEV_NICDOMAIN | VP_DEV_WIFI
VP_DEV_PINCHAN   equ 8192               ; exclusive reverse PIN1 console, no hardware assignment
VP_DEV_PINDOMAIN equ VP_DEV_TIMER | VP_DEV_CONSOLE | VP_DEV_PINCHAN
VP_DEV_WARMCHAN  equ 4096               ; exclusive expendable warm guest control channel
VP_DEV_WARMDOMAIN equ VP_DEV_TIMER | VP_DEV_CONSOLE | VP_DEV_WARMCHAN
VP_DEV_FILESYSTEM equ 16384             ; exclusive hvc1 + partition-block, two register pages
VP_DEV_FSDOMAIN equ VP_DEV_TIMER | VP_DEV_CONSOLE | VP_DEV_FILESYSTEM
VP_DEV_KNOWN_RC  equ VP_DEV_WIFI | VP_DEV_NIC | VP_DEV_FILESYSTEM | VP_DEV_PINCHAN | VP_DEV_WARMCHAN | VP_DEV_TIMER | VP_DEV_CONSOLE | VP_DEV_NET | VP_DEV_DISPLAY | VP_DEV_INPUT | VP_DEV_ENTROPY | VP_DEV_SOUND | VP_DEV_RESTORE | VP_DEV_PADCHAN | VP_DEV_PCIHDA | VP_DEV_LAPIC
; RCQ-50 G0 (lab only, default OFF: no byte in either floor): PCIFLR selects the assigned-function
; seam's FLR kind (hv/pci_assign): the one pinned PCIe endpoint instead of the HDA function. It is
; valid only inside VP_DEV_FLRDOMAIN, so it always rides with PCIHDA (pci=conf1, polled line 6, BAR).
%ifidn RCQ50_G0_FLR_LAB,1
VP_DEV_PCIFLR    equ 2048
VP_DEV_FLRDOMAIN equ VP_DEV_TIMER | VP_DEV_CONSOLE | VP_DEV_PCIHDA | VP_DEV_PCIFLR
VP_DEV_KNOWN     equ VP_DEV_KNOWN_RC | VP_DEV_PCIFLR
%else
VP_DEV_KNOWN     equ VP_DEV_KNOWN_RC
%endif
VP_DEV_PADDOMAIN equ VP_DEV_TIMER | VP_DEV_CONSOLE | VP_DEV_PADCHAN ; the PAD1 closure
VP_DEV_HDADOMAIN equ VP_DEV_PADDOMAIN | VP_DEV_PCIHDA ; RCQ-36 V2: PAD1 playing through the assigned HDA
; Console mode / CPU state / host function: not an omittable priced device. The NIC closure
; (0x8007/0x18007) carries the paos.power page (C10b-1a, SEC 107064 B3): it is priced inside
; that closure, never as an omittable device, so NIC stays outside this mask.
VP_DEV_PRICED    equ VP_DEV_KNOWN_RC & ~(VP_DEV_PADCHAN | VP_DEV_PCIHDA | VP_DEV_LAPIC | VP_DEV_WARMCHAN | VP_DEV_PINCHAN | VP_DEV_NIC)
VP_DEV_LEGACY    equ VP_DEV_TIMER | VP_DEV_CONSOLE | VP_DEV_NET ; the fixed shape every legacy START gets
VP_DEV_DESKTOP   equ VP_DEV_TIMER | VP_DEV_CONSOLE | VP_DEV_DISPLAY | VP_DEV_INPUT

; RCQ-23 DISPLAY: one fixed mode in v1. x8r8g8b8 (memory bytes B,G,R,X) is the
; PaOS compositor's own pixel layout, so the window copies rows unconverted.
VP_FB_WIDTH      equ 800
VP_FB_HEIGHT     equ 600
VP_FB_STRIDE     equ VP_FB_WIDTH * 4
VP_FB_BYTES      equ 0x200000           ; one 2 MiB EPT leaf (>= stride * height)
VP_FB_GPA        equ 0xC0000000         ; outside guest RAM; PDPT[3] PD index 0
%if VP_FB_STRIDE * VP_FB_HEIGHT > VP_FB_BYTES
    %error "DISPLAY mode must fit its 2 MiB leaf"
%endif

VP_DEP_KERNEL    equ 1
VP_DEP_INITRD    equ 2

VP_VCPU_MAX      equ 256                ; representable
VP_VCPU_RUNTIME  equ 1                  ; ordinary profiles; exact signed S7 tuple admits two
VP_RAM_ALIGN     equ 0x200000           ; EPT/guest paging use 2 MiB leaves
VP_RAM_MIN       equ 0x1000000          ; 16 MiB
VP_RAM_MAX       equ 0xD0000000         ; 3328 MiB RAM amount: NIC domains split above the 3..4 GiB MMIO hole
VP_RAM_DISPLAY_MAX equ 0x40000000       ; a DISPLAY guest keeps one RAM PD (guestdisplay_clear)
VP_INITRD_MAX    equ 0x40000000         ; 1 GiB pinned initramfs ceiling
VP_KERNEL_MIN    equ 0x400
VP_KERNEL_MAX    equ 0x2000000          ; HV_LINUX_INITRD_GPA - HV_LINUX_KERN_GPA
VP_KERN_GPA      equ 0x1000000          ; == HV_LINUX_KERN_GPA

VP_OK            equ 0
VP_E_LENGTH      equ 1
VP_E_VERSION     equ 2
VP_E_NAME        equ 3
VP_E_CLASS       equ 4
VP_E_RESERVED    equ 5
VP_E_VCPU        equ 6
VP_E_RAM         equ 7
VP_E_DEVICE      equ 8
VP_E_CLOSURE     equ 9
VP_E_DEP         equ 10
VP_E_FIT         equ 11
VP_E_UNSUPPORTED equ 12
VP_E_UNKNOWN     equ 13
VP_E_BUSY        equ 14
VP_E_PIN         equ 15
VP_E_DURABLE     equ 16                 ; no durable guest journal exists
VP_E_STATE       equ 17
VP_E_HEALTH      equ 18                 ; no trusted guest service-health policy
VP_E_INTERRUPTED equ 19
VP_E_GENERATION  equ 20
VP_E_AUTHORITY   equ 21                 ; not an exact signed built-in record

; Same-boot paired selection. Each published bank describes ONE complete tuple
; by its immutable signed record address (record binds all pins and VM shape).
; No writer yields; aligned pointer publication is the only commit boundary.
; Never interpret these volatile banks as Boot-v2 journal or strong health.
VPS_GOOD         equ 0
VPS_RECOVERY     equ 8
VPS_TRIAL        equ 16
VPS_GEN          equ 24                 ; last accepted generation; no wrap/reuse
VPS_PHASE        equ 28                 ; 0 idle, 1 trial armed, 2 trial run, 3 promoted run
                                       ; 4 recovery armed, 5 recovery run
VPS_PROOF        equ 32                 ; exact kernel/initrd verification bits
VPS_BYTES        equ 40


; Plan: what a selection costs. Filled from the record (or the legacy shape).
VPP_RAM          equ 0                  ; u64 guest RAM
VPP_RESERVE      equ 8                  ; u64 host bytes reserved (RAM + control)
VPP_VCPUS        equ 16                 ; u32
VPP_DEVICES      equ 20                 ; u32 selected mask
VPP_OMITTED      equ 24                 ; u32 known & ~selected
VPP_MMIO_PAGES   equ 28                 ; u32 trapped virtio-mmio register pages
VPP_IRQ_LINES    equ 32                 ; u32 PIC line mask (bit0 timer, 5 console, 6 net)
VPP_EPT_LEAVES   equ 36                 ; u32 RAM 2 MiB leaves + MMIO pages
VPP_DECLS        equ 40                 ; u32 virtio_mmio.device= cmdline declarations
VPP_FB_BYTES     equ 44                 ; u32 RCQ-23 framebuffer bytes (0 without DISPLAY)
VPP_BYTES        equ 48

VP_CTRL_BYTES    equ 0x200000           ; == HV_LINUX_CTRL_BYTES
VP_LEGACY_RAM    equ 0x4000000          ; == HV_LINUX_NORMAL_RAM_BYTES
VP_CMDLINE_CAP   equ 2048               ; Linux 6.6 x86 COMMAND_LINE_SIZE

; ---------------------------------------------------------------------------
; vm_profile_validate(RDI=record, RSI=exact length) -> EAX=status. Writes nothing.
; ---------------------------------------------------------------------------
vm_profile_validate:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  eax, VP_E_LENGTH
    test rdi, rdi
    jz   .out
    cmp  rsi, VP_BYTES
    jne  .out
    cmp  dword [rdi + VP_SIZE], VP_BYTES
    jne  .out
    mov  rbx, rdi
    mov  eax, VP_E_VERSION
    cmp  dword [rbx + VP_VERSION], 1
    jne  .out
    ; Name: 1..23 of [a-z0-9-], then NUL and zero padding to the full field.
    mov  eax, VP_E_NAME
    xor  ecx, ecx
.name:
    movzx edx, byte [rbx + VP_NAME + rcx]
    test edx, edx
    jz   .name_end
    cmp  ecx, VP_NAME_BYTES - 1
    jae  .out
    cmp  dl, '-'
    je   .name_ok
    cmp  dl, '0'
    jb   .out
    cmp  dl, '9'
    jbe  .name_ok
    cmp  dl, 'a'
    jb   .out
    cmp  dl, 'z'
    ja   .out
.name_ok:
    inc  ecx
    jmp  .name
.name_end:
    test ecx, ecx
    jz   .out
.pad:
    cmp  ecx, VP_NAME_BYTES
    jae  .class
    cmp  byte [rbx + VP_NAME + rcx], 0
    jne  .out
    inc  ecx
    jmp  .pad
.class:
    mov  eax, VP_E_CLASS
    movzx edx, byte [rbx + VP_CLASS]
    cmp  edx, VP_CLASS_THIN_CLI
    je   .reserved
    cmp  edx, VP_CLASS_CLI
    je   .reserved
    cmp  edx, VP_CLASS_DESKTOP
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    je   .reserved
    cmp  edx, VP_CLASS_MEDIA
%endif
%endif
    jne  .out
.reserved:
    mov  eax, VP_E_RESERVED
    cmp  byte [rbx + VP_FLAGS], 0
    jne  .out
    cmp  byte [rbx + VP_RSVD0], 0
    jne  .out
    cmp  dword [rbx + VP_RSVD1], 0
    jne  .out
    mov  eax, VP_E_VCPU
    mov  edx, [rbx + VP_VCPUS]
    test edx, edx
    jz   .out
    cmp  edx, VP_VCPU_MAX
    ja   .out
    mov  eax, VP_E_UNSUPPORTED              ; representable, not runnable here
    cmp  edx, VP_VCPU_RUNTIME
    jbe  .vcpu_ok
    cmp  edx, 2
    jne  .out
    mov  rdi, rbx
    call vm_profile_smp2_match             ; every byte, not just a name/class
    test eax, eax
    mov  eax, VP_E_UNSUPPORTED
    jz   .out
.vcpu_ok:
    mov  eax, VP_E_RAM
    mov  rdx, [rbx + VP_RAM]
    test rdx, VP_RAM_ALIGN - 1
    jnz  .out
    cmp  rdx, VP_RAM_MIN
    jb   .out
    mov  ecx, VP_RAM_MAX                    ; RCQ-50: above 2^31, so never an imm32 compare
    cmp  rdx, rcx
    ja   .out
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rbx + VP_CLASS], VP_CLASS_MEDIA
    jne  .ram_ok
    cmp  rdx, VP_MEDIA_RAM                 ; command line and e820 use this exact geometry
    jne  .out
.ram_ok:
%endif
%endif
    ; Only the maintained full NIC domain uses split RAM. Other closures retain
    ; their old flat-RAM bound; no optional device acquires an unproved layout.
    mov  ecx, 0xC0000000
    cmp  rdx, rcx
    jbe  .flat_ram_ok
    cmp  byte [rbx + VP_CLASS], VP_CLASS_CLI
    jne  .out
    cmp  dword [rbx + VP_DEVICES], VP_DEV_NICDOMAIN
    je   .flat_ram_ok
    cmp  dword [rbx + VP_DEVICES], VP_DEV_WIFIDOMAIN
    jne  .out
.flat_ram_ok:
    mov  eax, VP_E_DEVICE
    mov  edx, [rbx + VP_DEVICES]
    test edx, ~VP_DEV_KNOWN
    jnz  .out
    mov  eax, VP_E_CLOSURE
    test edx, VP_DEV_TIMER
    jz   .out
    test edx, VP_DEV_CONSOLE
    jz   .out
    %ifidn RCQ50_G0_FLR_LAB,1
    test edx, VP_DEV_PCIFLR
    jz   .no_flr
    cmp  byte [rbx + VP_CLASS], VP_CLASS_CLI ; exactly the FLR closure, CLI class only
    jne  .out
    cmp  edx, VP_DEV_FLRDOMAIN
    jne  .out
    jmp  .deps
.no_flr:
    %endif
    test edx, VP_DEV_NIC
    jz   .not_nic
    cmp  byte [rbx + VP_CLASS], VP_CLASS_CLI
    jne  .out
    cmp  dword [rbx + VP_VCPUS], 1
    jne  .out
    cmp  edx, VP_DEV_NICDOMAIN
    je   .deps
    cmp  edx, VP_DEV_WIFIDOMAIN
    jne  .out
    jmp  .deps
.not_nic:
    test edx, VP_DEV_WIFI
    jnz  .out
    test edx, VP_DEV_FILESYSTEM
    jz   .not_fs
    cmp byte [rbx + VP_CLASS], VP_CLASS_CLI
    jne .out
    cmp dword [rbx + VP_VCPUS], 1
    jne .out
    cmp edx, VP_DEV_FSDOMAIN
    jne .out
    jmp .deps
.not_fs:
    test edx, VP_DEV_PINCHAN
    jz   .not_pin
    cmp  byte [rbx + VP_CLASS], VP_CLASS_CLI
    jne  .out
    cmp  edx, VP_DEV_PINDOMAIN
    jne  .out
    jmp  .deps
.not_pin:
    test edx, VP_DEV_WARMCHAN
    jz   .not_warm
    cmp  byte [rbx + VP_CLASS], VP_CLASS_CLI
    jne  .out
    cmp  edx, VP_DEV_WARMDOMAIN
    jne  .out
    jmp  .deps
.not_warm:
    cmp  byte [rbx + VP_CLASS], VP_CLASS_DESKTOP
    je   .desktop
    test edx, VP_DEV_DISPLAY | VP_DEV_INPUT | VP_DEV_SOUND  ; RCQ-23: only a desktop owns these
    jnz  .out
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rbx + VP_CLASS], VP_CLASS_MEDIA
    je   .thin_devices
%endif
%endif
    cmp  byte [rbx + VP_CLASS], VP_CLASS_THIN_CLI
    jne  .cli
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
.thin_devices:
%endif
%endif
    cmp  edx, VP_DEV_TIMER | VP_DEV_CONSOLE
    jne  .out
    jmp  .deps
.cli:
    test edx, VP_DEV_PADCHAN
    jz   .cli_nopad
    cmp  edx, VP_DEV_PADDOMAIN
    je   .deps
    cmp  edx, VP_DEV_HDADOMAIN              ; RCQ-36 V2: the assigned HDA only under PAD1, alone
    jne  .out
    jmp  .deps
.cli_nopad:
    test edx, VP_DEV_PCIHDA
    jnz  .out
    jmp  .deps
.desktop:
    mov  eax, VP_E_RAM                      ; RCQ-50: the 3 GiB shape is not a DISPLAY shape
    cmp  qword [rbx + VP_RAM], VP_RAM_DISPLAY_MAX
    ja   .out
    mov  eax, VP_E_CLOSURE
    and  edx, ~(VP_DEV_SOUND | VP_DEV_RESTORE) ; explicit optional audio/restore port only
    cmp  edx, VP_DEV_DESKTOP
    jne  .out
.deps:
    mov  eax, VP_E_DEP
    movzx r12d, byte [rbx + VP_NDEPS]
    cmp  r12d, VP_DEP_MAX
    ja   .out
    xor  r13d, r13d                         ; slot index
    xor  r14d, r14d                         ; kernel count (low byte) / initrd (<<8)
    xor  r15d, r15d                         ; kernel+initrd bytes
.slot:
    cmp  r13d, VP_DEP_MAX
    jae  .slots_done
    imul esi, r13d, VP_DEP_BYTES
    lea  rsi, [rbx + VP_DEPS + rsi]
    cmp  r13d, r12d
    jb   .used
    ; Unused slot: every byte zero (no hidden dependency rides along).
    mov  rdx, [rsi]
    or   rdx, [rsi + 8]
    or   rdx, [rsi + 16]
    or   rdx, [rsi + 24]
    or   rdx, [rsi + 32]
    or   rdx, [rsi + 40]
    or   rdx, [rsi + 48]
    mov  eax, VP_E_DEP
    jnz  .out
    jmp  .next_slot
.used:
    mov  eax, VP_E_DEP
    cmp  dword [rsi + VPD_RSVD], 0
    jne  .out
    mov  rdx, [rsi + VPD_SHA]
    or   rdx, [rsi + VPD_SHA + 8]
    or   rdx, [rsi + VPD_SHA + 16]
    or   rdx, [rsi + VPD_SHA + 24]
    jz   .out                               ; an all-zero hash pins nothing
    push rsi
    lea  rdi, [rsi + VPD_NAME]
    call vp_name83_valid
    pop  rsi
    test eax, eax
    mov  eax, VP_E_DEP
    jz   .out
    mov  rdx, [rsi + VPD_SIZE]
    movzx ecx, byte [rsi + VPD_KIND]
    cmp  ecx, VP_DEP_KERNEL
    je   .kernel
    cmp  ecx, VP_DEP_INITRD
    jne  .out
    test rdx, rdx
    jz   .out
    cmp  rdx, VP_INITRD_MAX
    ja   .out
    add  r14d, 0x100
    jmp  .size_add
.kernel:
    cmp  rdx, VP_KERNEL_MIN
    jb   .out
    cmp  rdx, VP_KERNEL_MAX
    ja   .out
    inc  r14d
.size_add:
    ; The initrd starts on a 4 KiB boundary, above the rounded kernel end.
    ; Count each signed file's whole page extent, not just its byte length.
    ; Both lengths were bounded above, so rounding and their sum cannot wrap.
    add  rdx, 0xFFF
    and  rdx, -0x1000
    add  r15, rdx
.dup:
    ; Distinct names: two slots streaming the same file is not a closure.
    xor  ecx, ecx
.dup_scan:
    cmp  ecx, r13d
    jae  .next_slot
    imul edi, ecx, VP_DEP_BYTES
    lea  rdi, [rbx + VP_DEPS + rdi + VPD_NAME]
    mov  rdx, [rdi]
    xor  rdx, [rsi + VPD_NAME]
    mov  r8d, [rdi + 7]
    xor  r8d, [rsi + VPD_NAME + 7]
    or   rdx, r8
    jz   .out                               ; EAX still VP_E_DEP
    inc  ecx
    jmp  .dup_scan
.next_slot:
    inc  r13d
    jmp  .slot
.slots_done:
    mov  eax, VP_E_CLOSURE
    cmp  r14d, 0x101                        ; exactly one kernel and one initrd
    jne  .out
    mov  eax, VP_E_FIT
    add  r15, VP_KERN_GPA
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rbx + VP_CLASS], VP_CLASS_MEDIA
    jne  .fit_ram
    cmp  r15, VP_MEDIA_GPA                 ; initrd lives below the reserved window
    ja   .out
.fit_ram:
%endif
%endif
    cmp  r15, [rbx + VP_RAM]
    ja   .out
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Read-only exact signed two-vCPU tuple. Only this artifact/device/RAM
; closure is supported by START's private two-core implementation.
; RDI record (caller already proved its extent), EAX1 match /0 mismatch.
vm_profile_smp2_match:
    test rdi, rdi
    jz   .bad
    lea  rsi, [rel vp_thin_smp2]
    mov  ecx, VP_BYTES / 8
    cld
    repe cmpsq
    sete al
    movzx eax, al
    ret
.bad:
    xor  eax, eax
    ret

; vp_name83_valid(RDI=11 bytes) -> EAX=1 when the 8.3 form is canonical:
; base 1..8 of [A-Z0-9_-] then spaces, extension 0..3 of the same then spaces.
vm_profile_name83_valid:
vp_name83_valid:
    mov  esi, 8
    mov  edx, 1
    call vp_name83_part
    test eax, eax
    jz   .no
    add  rdi, 8
    mov  esi, 3
    xor  edx, edx
    jmp  vp_name83_part
.no:
    ret

; RDI=part, ESI=length, EDX=minimum characters -> EAX=1/0. Preserves RDI.
vp_name83_part:
    xor  ecx, ecx                           ; index
    xor  r8d, r8d                           ; characters seen
    xor  r9d, r9d                           ; padding seen
.loop:
    cmp  ecx, esi
    jae  .end
    movzx eax, byte [rdi + rcx]
    cmp  al, ' '
    jne  .char
    mov  r9d, 1
    jmp  .next
.char:
    test r9d, r9d
    jnz  .bad                               ; a character after padding
    cmp  al, '_'
    je   .ok
    cmp  al, '-'
    je   .ok
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    jbe  .ok
    cmp  al, 'A'
    jb   .bad
    cmp  al, 'Z'
    ja   .bad
.ok:
    inc  r8d
.next:
    inc  ecx
    jmp  .loop
.end:
    xor  eax, eax
    cmp  r8d, edx
    setae al
    ret
.bad:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; vm_profile_plan_mask(RDI=plan, RSI=RAM bytes, EDX=device mask, ECX=vCPUs).
; The one cost function, shared by the legacy shape and every record.
; ---------------------------------------------------------------------------
vm_profile_plan_mask:
    mov  [rdi + VPP_RAM], rsi
    lea  rax, [rsi + VP_CTRL_BYTES]
    mov  [rdi + VPP_RESERVE], rax
    mov  [rdi + VPP_VCPUS], ecx
    mov  [rdi + VPP_DEVICES], edx
    mov  eax, edx
    not  eax
    and  eax, VP_DEV_PRICED
    mov  [rdi + VPP_OMITTED], eax
    xor  r8d, r8d                           ; MMIO pages
    xor  r9d, r9d                           ; PIC lines
    test edx, VP_DEV_TIMER
    jz   .console
    or   r9d, 1 << 0
.console:
    test edx, VP_DEV_CONSOLE
    jz   .net
    inc  r8d
    or   r9d, 1 << 5
.net:
    test edx, VP_DEV_NET
    jz   .input
    inc  r8d
    or   r9d, 1 << 6
.input:
    test edx, VP_DEV_INPUT
    jz   .entropy
    inc  r8d
    or   r9d, 1 << 1
.entropy:
    test edx, VP_DEV_ENTROPY
    jz   .sound
    inc  r8d
    or   r9d, 1 << 3
.sound:
    test edx, VP_DEV_SOUND
    jz   .restore
    inc  r8d
    or   r9d, 1 << 7
.restore:
    test edx, VP_DEV_RESTORE
    jz   .filesystem
    inc  r8d
    or   r9d, 1 << 5                        ; shares the console's line
.filesystem:
    test edx, VP_DEV_FILESYSTEM
    jz .wifi
    add r8d,2
    or r9d,1<<5
.wifi:
    test edx, VP_DEV_WIFI
    jz .pcihda
    inc r8d
    or r9d,1<<5
.pcihda:
    test edx, VP_DEV_PCIHDA
    jz   .display
    or   r9d, 1 << 6                        ; RCQ-36 V2: polled level line; its BAR is no virtio page
.display:
    xor  r10d, r10d                         ; framebuffer bytes
    test edx, VP_DEV_DISPLAY
    jz   .done
    mov  r10d, VP_FB_BYTES
    add  qword [rdi + VPP_RESERVE], VP_FB_BYTES
.done:
    ; C10b-1a B3 (SEC 107064/107097): the exact driver-domain closure carries the
    ; paos.power register page: one page, one declaration, one leaf. Its IRQ5 is
    ; the console's line, already counted. The closure is never an omittable device.
    cmp  edx, VP_DEV_NICDOMAIN
    je   .closure_power
    cmp  edx, VP_DEV_WIFIDOMAIN
    jne  .counted
.closure_power:
    inc  r8d
.counted:
    mov  [rdi + VPP_MMIO_PAGES], r8d
    mov  [rdi + VPP_IRQ_LINES], r9d
    mov  [rdi + VPP_DECLS], r8d
    mov  [rdi + VPP_FB_BYTES], r10d
    mov  rax, rsi
    shr  rax, 21
    add  eax, r8d
    shr  r10d, 21                           ; display: its 2 MiB leaves
    add  eax, r10d
    mov  [rdi + VPP_EPT_LEAVES], eax
    ret

; vm_profile_plan(RDI=record, RSI=length, RDX=plan) -> EAX=status.
; On refusal the plan is all zero: a refused record is charged nothing.
vm_profile_plan:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  rdi, rdx
    xor  eax, eax
    mov  ecx, VPP_BYTES / 8
    rep  stosq
    mov  rdi, rbx
    mov  rsi, r12
    call vm_profile_validate
    test eax, eax
    jnz  .out
    mov  rdi, r13
    mov  rsi, [rbx + VP_RAM]
    mov  edx, [rbx + VP_DEVICES]
    mov  ecx, [rbx + VP_VCPUS]
    call vm_profile_plan_mask
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; vm_profile_find(RDI=NUL-terminated name plus optional space/CR/LF tail)
; -> RAX=record/0. Reject extra tokens before callers select or request START.
vm_profile_find:
    push rbx
    push r12
    lea  rbx, [rel vp_builtin_table]
    xor  r12d, r12d
.record:
    cmp  r12d, VP_BUILTIN_COUNT
    jae  .none
    xor  ecx, ecx
.cmp:
    movzx eax, byte [rdi + rcx]
    cmp  al, ' '
    je   .text_end
    cmp  al, 13
    je   .text_end
    cmp  al, 10
    je   .text_end
    test al, al
    jz   .text_end
    cmp  ecx, VP_NAME_BYTES - 1
    jae  .next
    cmp  al, [rbx + VP_NAME + rcx]
    jne  .next
    inc  ecx
    jmp  .cmp
.text_end:
    test ecx, ecx
    jz   .next
    cmp  byte [rbx + VP_NAME + rcx], 0
    jne  .next
.tail:
    movzx eax, byte [rdi + rcx]
    test al, al
    jz   .found
    cmp  al, ' '
    je   .tail_space
    cmp  al, 13
    je   .tail_space
    cmp  al, 10
    jne  .none
.tail_space:
    inc  rcx
    jmp  .tail
.found:
    mov  rax, rbx
    jmp  .out
.next:
    add  rbx, VP_BYTES
    inc  r12d
    jmp  .record
.none:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; vp_dep_of_kind(RDI=record, ESI=kind) -> RAX=dependency entry or 0.
vp_dep_of_kind:
    movzx ecx, byte [rdi + VP_NDEPS]
    lea  rax, [rdi + VP_DEPS]
.scan:
    test ecx, ecx
    jz   .none
    cmp  [rax + VPD_KIND], sil
    je   .out
    add  rax, VP_DEP_BYTES
    dec  ecx
    jmp  .scan
.none:
    xor  eax, eax
.out:
    ret

; vm_profile_select(RDI=record) -> EAX=status. Validates and plans before it
; changes any selector; a refusal leaves the current selection untouched.
; The caller binds the selection to its START generation (vm_profile_gen).
vm_profile_select:
%ifdef PAOS_NIC_ASSIGNMENT
    sub rsp,8
    call nd_profile_allowed
    add rsp,8
    test eax,eax
    jnz .nd_allowed
    mov eax,VP_E_BUSY
    ret
.nd_allowed:
%endif
    ; S7: backend/profile/topology stays frozen through full retirement.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    cmp  qword [rel vm_profile_pair_state], 0
    je   vp_select_apply
    push rdi
    call vp_pair_trusted
    pop  rdi
    test eax, eax
    jnz  vp_select_return
    push rdi
    call vp_pair_cancel_idle
    pop  rdi
    test eax, eax
    jnz  vp_select_return
    jmp  vp_select_apply
vp_select_return:
    ret

; Internal non-yielding selector, used only after pair-state admission.
vp_select_apply:
    ; S7: backend/profile/topology stays frozen through full retirement.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    push rbx
    sub  rsp, VPP_BYTES
    mov  rbx, rdi
    mov  esi, VP_BYTES
    mov  rdx, rsp
    call vm_profile_plan
    test eax, eax
    jnz  .out
    lea  rdi, [rel vm_profile_plan_cur]
    mov  rsi, rsp
    mov  ecx, VPP_BYTES / 8
.copy:
    mov  rax, [rsi]
    mov  [rdi], rax
    add  rsi, 8
    add  rdi, 8
    dec  ecx
    jnz  .copy
    mov  rdi, rbx
    mov  esi, VP_DEP_KERNEL
    call vp_dep_of_kind
    mov  [rel vm_profile_kdep], rax
    lea  rcx, [rax + VPD_NAME]
    mov  [rel hv_linux_kernel_name_ptr], rcx
    mov  rdi, rbx
    mov  esi, VP_DEP_INITRD
    call vp_dep_of_kind
    mov  [rel vm_profile_idep], rax
    lea  rcx, [rax + VPD_NAME]
    mov  [rel hv_linux_initrd_name_ptr], rcx
    mov  rax, [rbx + VP_RAM]
    mov  [rel hv_linux_ram_bytes], rax
    mov  eax, [rbx + VP_DEVICES]
    mov  [rel vm_profile_dev_mask], eax
    mov  eax, [rel vm_profile_plan_cur + VPP_FB_BYTES]
    mov  [rel hv_linux_fb_bytes], rax       ; RCQ-23: reserved after guest RAM
    mov  dword [rel vm_profile_gen], 0
    mov  [rel vm_profile_active], rbx
    xor  eax, eax
.out:
    add  rsp, VPP_BYTES
    pop  rbx
    ret

; vm_profile_reset_legacy — no profile: the fixed legacy shape and its plan.
; Leaves artifact names/RAM to the caller's own selector.
vm_profile_reset_legacy:
%ifdef PAOS_NIC_ASSIGNMENT
    sub rsp,8
    call nd_profile_allowed
    add rsp,8
    test eax,eax
    jnz .nd_allowed
    mov eax,VP_E_BUSY
    ret
.nd_allowed:
%endif
    ; S7: backend/profile/topology stays frozen through full retirement.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    sub  rsp, 8
    call vp_pair_cancel_idle
    add  rsp, 8
    test eax, eax
    jnz  vp_select_return
    xor  eax, eax
    mov  [rel vm_profile_active], rax
    mov  [rel vm_profile_kdep], rax
    mov  [rel vm_profile_idep], rax
    mov  [rel vm_profile_gen], eax
    mov  [rel hv_linux_fb_bytes], rax
    mov  dword [rel vm_profile_dev_mask], VP_DEV_LEGACY
    lea  rdi, [rel vm_profile_plan_cur]
    mov  esi, VP_LEGACY_RAM
    mov  edx, VP_DEV_LEGACY
    mov  ecx, 1
    sub  rsp, 8
    call vm_profile_plan_mask
    add  rsp, 8
    xor  eax, eax                         ; reset now exposes explicit admission status
    ret

; vm_profile_bind_launch(EDI=consumed START generation) -> EAX=1 when the
; selected profile governs this launch. A selection made for another
; generation never leaks into it: armed mismatch restores legacy selectors.
; EAX=-1 refuses duplicate/foreign entry while a managed run is already bound.
vm_profile_bind_launch:
    push rdi
    call vp_pair_bind
    pop  rdi
    cmp  eax, VP_E_BUSY
    je   .busy
    test eax, eax
    jnz  .stale
    cmp  qword [rel vm_profile_active], 0
    je   .legacy
    cmp  edi, [rel vm_profile_gen]
    jne  .stale
    mov  eax, 1
    ret
.busy:
    mov  eax, -1                         ; caller must not enter or reset owned run
    ret
.stale:
    call hv_linux_select_default_artifacts  ; also calls vm_profile_reset_legacy
.legacy:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; RC8.1 opt-in native paired selection core. No persistence or health authority
; is inferred from these APIs. Configure once from trusted boot code, BEFORE
; any guest START, using qualified signed built-in good/recovery records.
; No shell/guest/host-receipt route can configure or authorize health here.
; All mutations execute on the serialized guest-control CPU without yielding.
; ---------------------------------------------------------------------------

; RDI must equal a signed table entry, never a copied/untrusted lookalike.
vp_pair_trusted:
    lea  rdx, [rel vp_builtin_table]
    mov  ecx, VP_BUILTIN_COUNT
.scan:
    cmp  rdi, rdx
    je   .found
    add  rdx, VP_BYTES
    loop .scan
    mov  eax, VP_E_AUTHORITY
    ret
.found:
    mov  esi, VP_BYTES
    jmp  vm_profile_validate

; Two valid records may share a native file name only for identical artifact
; kind, length and digest. Otherwise retaining both pairs in the same VFS root
; is impossible. This checks the signed declaration, never rewrites a file.
vp_pair_files_compatible:
    lea  r8, [rdi + VP_DEPS]
    lea  r9, [rsi + VP_DEPS]
    mov  r10d, 2
.outer:
    mov  rsi, r9
    mov  r11d, 2
.inner:
    mov  rax, [r8 + VPD_NAME]
    xor  rax, [rsi + VPD_NAME]
    mov  edx, [r8 + VPD_NAME + 7]
    xor  edx, [rsi + VPD_NAME + 7]
    or   rax, rdx
    jnz  .next
    mov  al, [r8 + VPD_KIND]
    cmp  al, [rsi + VPD_KIND]
    jne  .bad
    mov  rax, [r8 + VPD_SIZE]
    cmp  rax, [rsi + VPD_SIZE]
    jne  .bad
    xor  ecx, ecx
.sha:
    mov  rax, [r8 + VPD_SHA + rcx]
    cmp  rax, [rsi + VPD_SHA + rcx]
    jne  .bad
    add  ecx, 8
    cmp  ecx, 32
    jb   .sha
.next:
    add  rsi, VP_DEP_BYTES
    dec  r11d
    jnz  .inner
    add  r8, VP_DEP_BYTES
    dec  r10d
    jnz  .outer
    xor  eax, eax
    ret
.bad:
    mov  eax, VP_E_PIN
    ret

; vm_profile_pair_configure(RDI=good, RSI=recovery) -> status.
; Signed source adoption supplies these exact records; neither is boot-qualified
; by this function. Recovery is immutable until payload restart. Default OFF.
vm_profile_pair_configure:
    push rbx
    push r12
    sub  rsp, 8
    mov  rbx, rdi
    mov  r12, rsi
    mov  eax, VP_E_BUSY
    cmp  qword [rel vm_profile_pair_state], 0
    jne  .out
    call vp_pair_trusted
    test eax, eax
    jnz  .out
    mov  rdi, r12
    call vp_pair_trusted
    test eax, eax
    jnz  .out
    mov  rdi, rbx
    mov  rsi, r12
    call vp_pair_files_compatible
    test eax, eax
    jnz  .out
    lea  rdi, [rel vp_pair_bank0]
    xor  eax, eax
    mov  ecx, VPS_BYTES / 8
    rep  stosq
    lea  rdi, [rel vp_pair_bank0]
    mov  [rdi + VPS_GOOD], rbx
    mov  [rdi + VPS_RECOVERY], r12
    mov  dword [rel vp_pair_failed_gen], 0
    call vp_pair_publish
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; Copy the current coherent state into the unpublished bank -> RAX=bank.
vp_pair_copy:
    mov  rsi, [rel vm_profile_pair_state]
    lea  rdi, [rel vp_pair_bank0]
    cmp  rdi, rsi
    jne  .copy
    lea  rdi, [rel vp_pair_bank1]
.copy:
    mov  rax, rdi
    mov  ecx, VPS_BYTES / 8
    rep  movsq
    ret

; Only publication boundary. In-memory only, no storage callback or flush.
; Fault controls replace this routine in their inert host fixture, never here.
vp_pair_publish:
    mov  [rel vm_profile_pair_state], rdi
    xor  eax, eax
    ret

; vm_profile_request(RDI=record, ESI=next START gen) -> status.
; Current named START calls this before publishing run_req. Unconfigured legacy
; behavior is unchanged. The staged bank keeps the prior good/recovery intact.
vm_profile_request:
%ifdef PAOS_NIC_ASSIGNMENT
    sub rsp,8
    call nd_profile_allowed
    add rsp,8
    test eax,eax
    jnz .nd_allowed
    mov eax,VP_E_BUSY
    ret
.nd_allowed:
%endif
    cmp  qword [rel vm_profile_pair_state], 0
    je   vm_profile_select
    push rbx
    push r12
    sub  rsp, 8
    mov  rbx, rdi
    mov  r12d, esi
    mov  rdx, [rel vm_profile_pair_state]
    mov  eax, VP_E_BUSY
    cmp  dword [rdx + VPS_PHASE], 0
    jne  .out
    mov  eax, VP_E_GENERATION
    test r12d, r12d
    jz   .out
    cmp  r12d, [rdx + VPS_GEN]
    jbe  .out
    call vp_pair_trusted
    test eax, eax
    jnz  .out
    mov  rdx, [rel vm_profile_pair_state]
    mov  rdi, rbx
    mov  rsi, [rdx + VPS_GOOD]
    call vp_pair_files_compatible
    test eax, eax
    jnz  .out
    mov  rdx, [rel vm_profile_pair_state]
    mov  rdi, rbx
    mov  rsi, [rdx + VPS_RECOVERY]
    call vp_pair_files_compatible
    test eax, eax
    jnz  .out
    call vp_pair_copy
    mov  [rax + VPS_TRIAL], rbx
    mov  [rax + VPS_GEN], r12d
    mov  dword [rax + VPS_PHASE], 1
    mov  dword [rax + VPS_PROOF], 0
    mov  rdi, rax
    call vp_pair_publish
    test eax, eax
    jnz  .interrupted
    mov  rdi, rbx
    call vp_select_apply
    test eax, eax
    jnz  .interrupted
    mov  [rel vm_profile_gen], r12d
    jmp  .out
.interrupted:
    mov  edi, r12d
    call vm_profile_pair_finish
    mov  eax, VP_E_INTERRUPTED
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; Called only from vm_profile_bind_launch. A stale generation or changed
; selector cancels the trial before the caller restores its legacy selectors.
vp_pair_bind:
    push rbx
    mov  ebx, edi
    mov  rdx, [rel vm_profile_pair_state]
    xor  eax, eax
    test rdx, rdx
    jz   .out
    cmp  dword [rdx + VPS_PHASE], 0
    je   .out
    cmp  dword [rdx + VPS_PHASE], 1
    je   .armed
    cmp  dword [rdx + VPS_PHASE], 4
    je   .armed
    mov  eax, VP_E_BUSY
    jmp  .out
.armed:
    cmp  ebx, [rdx + VPS_GEN]
    jne  .stale
    cmp  ebx, [rel vm_profile_gen]
    jne  .stale
    mov  rax, [rdx + VPS_TRIAL]
    cmp  rax, [rel vm_profile_active]
    jne  .stale
    call vp_pair_copy
    mov  ecx, 2
    cmp  dword [rax + VPS_PHASE], 4
    jne  .phase
    mov  ecx, 5
.phase:
    mov  [rax + VPS_PHASE], ecx
    mov  dword [rax + VPS_PROOF], 0
    mov  rdi, rax
    call vp_pair_publish
    test eax, eax
    jz   .out
.stale:
    mov  rdx, [rel vm_profile_pair_state]
    mov  edi, [rdx + VPS_GEN]
    call vm_profile_pair_finish
    mov  eax, VP_E_GENERATION
.out:
    pop  rbx
    ret

; Exact vm_profile_dep_verify consumer. ESI=1 success, 0 failure.
; Only entries of this bound immutable trial can earn the two proof bits.
vp_pair_note_verified:
    push rbx
    mov  rdx, [rel vm_profile_pair_state]
    xor  eax, eax
    test rdx, rdx
    jz   .out
    cmp  dword [rdx + VPS_PHASE], 2
    jne  .out
    mov  rax, [rdx + VPS_TRIAL]
    cmp  rax, [rel vm_profile_active]
    jne  .ignore
    mov  ecx, [rdx + VPS_GEN]
    cmp  ecx, [rel vm_profile_gen]
    jne  .ignore
    mov  ecx, 1
    cmp  rdi, [rel vm_profile_kdep]
    je   .owned
    mov  ecx, 2
    cmp  rdi, [rel vm_profile_idep]
    jne  .ignore
.owned:
    mov  ebx, [rdx + VPS_PROOF]
    or   ebx, ecx
    test esi, esi
    jnz  .copy
    mov  eax, [rdx + VPS_GEN]
    mov  [rel vp_pair_failed_gen], eax    ; sticky even if bank publication is interrupted
    xor  ebx, ebx                         ; failed recheck revokes all proof
.copy:
    call vp_pair_copy
    mov  [rax + VPS_PROOF], ebx
    mov  rdi, rax
    call vp_pair_publish
    jmp  .out
.ignore:
    xor  eax, eax
.out:
    pop  rbx
    ret

; vm_profile_pair_health(RDI=full record SHA256, ESI=consumed gen) -> status.
; This is a native consumer for a future trusted health policy, NOT a host
; receipt/console-token endpoint. Current production authority always refuses.
vm_profile_pair_health:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13, [rel vm_profile_pair_state]
    mov  eax, VP_E_STATE
    test r13, r13
    jz   .out
    cmp  dword [r13 + VPS_PHASE], 2
    jne  .out
    mov  eax, VP_E_GENERATION
    cmp  r12d, [r13 + VPS_GEN]
    jne  .out
    cmp  r12d, [rel vm_profile_gen]
    jne  .out
    mov  eax, VP_E_PIN
    test rbx, rbx
    jz   .out
    mov  rsi, [r13 + VPS_TRIAL]
    cmp  rsi, [rel vm_profile_active]
    jne  .out
    mov  eax, VP_E_HEALTH
    cmp  r12d, [rel vp_pair_failed_gen]
    je   .out
    cmp  dword [r13 + VPS_PROOF], 3
    jne  .out
    lea  rdi, [rel vp_sha_out]
    mov  edx, VP_BYTES
    call sha256_hash
    lea  rsi, [rel vp_sha_out]
    mov  ecx, 4
.cmp:
    mov  rax, [rsi]
    cmp  rax, [rbx]
    jne  .pin
    add  rsi, 8
    add  rbx, 8
    loop .cmp
    mov  rdi, [r13 + VPS_TRIAL]
    mov  esi, r12d
    call vp_pair_health_authorize
    test eax, eax
    jnz  .out
    call vp_pair_copy
    mov  rdx, [rax + VPS_TRIAL]
    mov  [rax + VPS_GOOD], rdx
    mov  qword [rax + VPS_TRIAL], 0
    mov  dword [rax + VPS_PHASE], 3
    mov  dword [rax + VPS_PROOF], 0
    mov  rdi, rax
    call vp_pair_publish
    jmp  .out
.pin:
    mov  eax, VP_E_PIN
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Fixed missing policy, no mutable function pointer or success-bearing command.
; Console init/virtio-ready and Boot-v2 host strong health cannot authorize it.
vp_pair_health_authorize:
    mov  eax, VP_E_HEALTH
    ret

; Terminal loader/VM outcome, or cancellation before run_req. Only this exact
; trial generation is rolled back; a stale completion cannot cancel a new run.
vm_profile_pair_finish:
    push rbx
    mov  rdx, [rel vm_profile_pair_state]
    xor  eax, eax
    test rdx, rdx
    jz   .out
    cmp  dword [rdx + VPS_PHASE], 0
    je   .out
    mov  eax, VP_E_GENERATION
    cmp  edi, [rdx + VPS_GEN]
    jne  .out
    mov  rbx, [rdx + VPS_GOOD]
    call vp_pair_copy
    mov  qword [rax + VPS_TRIAL], 0
    mov  dword [rax + VPS_PHASE], 0
    mov  dword [rax + VPS_PROOF], 0
    mov  rdi, rax
    call vp_pair_publish
    test eax, eax
    jnz  .out
    mov  rdi, rbx
    call vp_select_apply
.out:
    pop  rbx
    ret

; Direct selection/legacy reset can cancel an armed request, not a bound run.
vp_pair_cancel_idle:
    mov  rdx, [rel vm_profile_pair_state]
    xor  eax, eax
    test rdx, rdx
    jz   .out
    cmp  dword [rdx + VPS_PHASE], 0
    je   .out
    mov  eax, VP_E_BUSY
    cmp  dword [rdx + VPS_PHASE], 4
    je   .cancel
    cmp  dword [rdx + VPS_PHASE], 2
    jae  .out
.cancel:
    mov  edi, [rdx + VPS_GEN]
    jmp  vm_profile_pair_finish
.out:
    ret

; vm_profile_pair_recover(EDI=fresh gen, ESI=0 prior good / 1 fixed recovery).
; Selection only; caller must use the existing START publisher/loader. No boot,
; retry, signing, file rewrite or recovery qualification is earned here.
vm_profile_pair_recover:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12d, edi
    mov  rdx, [rel vm_profile_pair_state]
    mov  eax, VP_E_STATE
    test rdx, rdx
    jz   .out
    cmp  esi, 1
    ja   .out
    mov  eax, VP_E_BUSY
    cmp  dword [rdx + VPS_PHASE], 4
    je   .idle
    cmp  dword [rdx + VPS_PHASE], 2
    jae  .out
.idle:
    mov  eax, VP_E_GENERATION
    test r12d, r12d
    jz   .out
    cmp  r12d, [rdx + VPS_GEN]
    jbe  .out
    mov  rbx, [rdx + VPS_GOOD]
    test esi, esi
    jz   .copy
    mov  rbx, [rdx + VPS_RECOVERY]
.copy:
    call vp_pair_copy
    mov  [rax + VPS_TRIAL], rbx
    mov  [rax + VPS_GEN], r12d
    mov  dword [rax + VPS_PHASE], 4
    mov  dword [rax + VPS_PROOF], 0
    mov  rdi, rax
    call vp_pair_publish
    test eax, eax
    jnz  .out
    mov  rdi, rbx
    call vp_select_apply
    mov  [rel vm_profile_gen], r12d
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

vm_profile_pair_durable:
    mov  eax, VP_E_DURABLE
    ret

vm_profile_live_reset:
    xor  eax, eax
    mov  [rel vm_profile_live_devices], eax
    mov  [rel vm_profile_live_mmio], eax
    mov  [rel vm_profile_live_leaves], eax
    mov  [rel vm_profile_live_reserve], rax
    mov  [rel guestpower_live], al          ; C10b-1a: no paos.power page before its map
    ret

; vm_profile_page_selected(EDI=offset from the virtio-mmio window base)
; -> EAX=1 when that page belongs to a selected device.
vm_profile_page_selected:
    mov  edx, VP_DEV_CONSOLE
    cmp  edi, 0x1000
    jb   .test
    mov  edx, VP_DEV_NET
    cmp  edi, 0x2000
    jb   .test
    mov  edx, VP_DEV_INPUT
    cmp  edi, 0x3000
    jb   .test
    mov  edx, VP_DEV_ENTROPY
    cmp  edi, 0x4000
    jb   .test
    mov  edx, VP_DEV_SOUND
    cmp  edi, 0x5000
    jb   .test
    mov  edx, VP_DEV_RESTORE
    cmp  edi, 0x6000
    jb   .test
    mov edx,VP_DEV_FILESYSTEM
    cmp edi,0x8000
    jb .test
    mov edx,VP_DEV_WIFI
    cmp edi,0x9000
    jb .test
    cmp edi,0xA000
    jae .none
    movzx eax, byte [rel guestpower_live]  ; C10b-1a B1/S7: mapped only for the exact closure
    ret
.none:
    xor  eax, eax
    ret
.test:
    xor  eax, eax
    test [rel vm_profile_dev_mask], edx
    setnz al
    ret

; vm_profile_compose_cmdline(RDI=dest, ESI=capacity incl. NUL) -> RAX=length
; or -1. Declares exactly the selected virtio devices, nothing else.
; Capacity is uint32 regardless of RSI's upper bits. A valid nonempty output span
; retains a terminated prefix on failure; zero capacity writes nothing.
vm_profile_compose_cmdline:
    push rbx
    push r12
    mov  rbx, rdi
    mov  esi, esi                          ; the declared uint32 argument
    mov  r12, rdi
    add  r12, rsi                          ; exclusive end
    jc   .fail                             ; invalid wrapping span: no writes
    test esi, esi
    jz   .fail
    lea  rsi, [rel str_vp_cmdline_base]
    test dword [rel vm_profile_dev_mask], VP_DEV_LAPIC
    jnz  .lapic
    test dword [rel vm_profile_dev_mask], VP_DEV_PCIHDA | VP_DEV_NIC
    jz   .base
    lea  rsi, [rel str_vp_cmdline_pci_head] ; RCQ-36 V2: the base line with " pci=off" made
    call vp_append                         ; " pci=conf1 pci=nomsi": its head, then the base on
    jc   .fail
    mov  rax, rdi
    sub  rax, rbx                          ; the head's length (it is the first text)
    lea  rsi, [rel str_vp_cmdline_base]
    lea  rsi, [rsi + rax - 12]             ; - len(" pci=conf1 pci=nomsi") + len(" pci=off")
    jmp  .base
.lapic:
    lea  rsi, [rel str_vp_cmdline_lapic_head] ; RCQ-50 S4: the base line without " nolapic":
    call vp_append                         ; its head, then the base from " noapic" on
    jc   .fail
    mov  rax, rdi
    sub  rax, rbx                          ; the head's length (it is the first text)
    lea  rsi, [rel str_vp_cmdline_base]
    lea  rsi, [rsi + rax + 8]              ; + len(" nolapic")
.base:
    call vp_append
    jc   .fail
    test dword [rel vm_profile_dev_mask], VP_DEV_CONSOLE
    jz   .net
    test dword [rel vm_profile_dev_mask], VP_DEV_PINCHAN
    jnz  .pinchan
    test dword [rel vm_profile_dev_mask], VP_DEV_WARMCHAN
    jnz  .warmchan
    test dword [rel vm_profile_dev_mask], VP_DEV_PADCHAN
    jnz  .padchan
    lea  rsi, [rel str_vp_cmdline_console]
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    mov  rax, [rel vm_profile_active]
    test rax, rax
    jz   .console_selected
    cmp  byte [rax + VP_CLASS], VP_CLASS_MEDIA
    jne  .console_selected
    lea  rsi, [rel str_vp_cmdline_media]     ; paosmedia exclusively owns hvc0
.console_selected:
%endif
%endif
    call vp_append
    jc   .fail
    jmp  .net
.pinchan:
    lea  rsi, [rel str_vp_cmdline_pin]
    call vp_append
    jc   .fail
    jmp  .net
.warmchan:
    lea  rsi, [rel str_vp_cmdline_warm]
    call vp_append
    jc   .fail
    jmp  .net
.padchan:
    ; RCQ-36: the console page without console=hvc0, plus the bound identity.
    call padc_cmdline_text
    test rax, rax
    jz   .fail                             ; never compose an unbound PAD1 port
    mov  rsi, rax
    call vp_append
    jc   .fail
.net:
    test dword [rel vm_profile_dev_mask], VP_DEV_NET
    jz   .input
    lea  rsi, [rel str_vp_cmdline_net]
    call vp_append
    jc   .fail
.input:
    test dword [rel vm_profile_dev_mask], VP_DEV_INPUT
    jz   .entropy
    lea  rsi, [rel str_vp_cmdline_input]
    call vp_append
    jc   .fail
.entropy:
    test dword [rel vm_profile_dev_mask], VP_DEV_ENTROPY
    jz   .sound
    lea  rsi, [rel str_vp_cmdline_entropy]
    call vp_append
    jc   .fail
.sound:
    test dword [rel vm_profile_dev_mask], VP_DEV_SOUND
    jz .restore
    lea rsi, [rel str_vp_cmdline_sound]
    call vp_append
    jc .fail
.restore:
    test dword [rel vm_profile_dev_mask], VP_DEV_RESTORE
    jz   .filesystem
    lea  rsi, [rel str_vp_cmdline_restore]
    call vp_append
    jc   .fail
.filesystem:
    test dword [rel vm_profile_dev_mask],VP_DEV_FILESYSTEM
    jz .wifi
    lea rsi,[rel str_vp_cmdline_filesystem]
    call vp_append
    jc .fail
    push rdi
    call fsg_cmdline
    pop rdi
    test rax,rax
    jz .fail
    mov rsi,rax
    call vp_append
    jc .fail
.wifi:
    test dword [rel vm_profile_dev_mask],VP_DEV_WIFI
    jz .power
    lea rsi,[rel str_vp_cmdline_wifi]
    call vp_append
    jc .fail
.power:
    call guestpower_selected               ; C10b-1a B1: same predicate as the map
    test eax,eax
    jz .done
    lea rsi,[rel str_vp_cmdline_power]
    call vp_append
    jc .fail
.done:
    test dword [rel vm_profile_dev_mask],VP_DEV_NIC
    jz .identity_done
    push rdi
    call nd_cmdline
    pop rdi
    test rax,rax
    jz .fail
    mov rsi,rax
    call vp_append
    jc .fail
.identity_done:
    mov  rax, rdi
    sub  rax, rbx
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

; RDI=cursor, RSI=cstr, R12=exclusive end -> RDI advanced, NUL kept; CF on overflow.
vp_append:
.copy:
    cmp  rdi, r12
    jae  .overflow
    mov  al, [rsi]
    mov  byte [rdi], 0                     ; bounded, terminated prefix on failure
    test al, al
    jz   .done
    lea  rdx, [rdi + 1]
    cmp  rdx, r12
    jae  .overflow                      ; leave room for NUL
    mov  [rdi], al
    inc  rsi
    inc  rdi
    jmp  .copy
.done:
    clc
    ret
.overflow:
    stc
    ret

; vm_profile_dep_verify(RDI=dependency, RSI=part1, RDX=len1, RCX=part2, R8=len2)
; -> EAX=0 or VP_E_PIN. The file is part1||part2 (the kernel's setup sectors
; and its protected-mode payload live at different guest addresses).
vm_profile_dep_verify:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    mov  r15, r8
    mov  rax, r13
    add  rax, r15
    jc   .bad
    cmp  rax, [rbx + VPD_SIZE]
    jne  .bad
    lea  rdi, [rel vp_sha_ctx]
    call sha256_stream_init
    mov  rsi, r12
    mov  rdx, r13
    call vp_sha_update_sliced
    test rax, rax
    jnz  .bad
    test r15, r15
    jz   .final
    mov  rsi, r14
    mov  rdx, r15
    call vp_sha_update_sliced
    test rax, rax
    jnz  .bad
.final:
    lea  rdi, [rel vp_sha_ctx]
    lea  rsi, [rel vp_sha_out]
    call sha256_stream_final
    test rax, rax
    jnz  .bad
    lea  rsi, [rel vp_sha_out]
    mov  rax, [rsi]
    xor  rax, [rbx + VPD_SHA]
    mov  rdx, [rsi + 8]
    xor  rdx, [rbx + VPD_SHA + 8]
    or   rax, rdx
    mov  rdx, [rsi + 16]
    xor  rdx, [rbx + VPD_SHA + 16]
    or   rax, rdx
    mov  rdx, [rsi + 24]
    xor  rdx, [rbx + VPD_SHA + 24]
    or   rax, rdx
    jnz  .bad
    mov  rdi, rbx
    mov  esi, 1
    call vp_pair_note_verified
    jmp  .out
.bad:
    mov  rdi, rbx
    xor  esi, esi
    call vp_pair_note_verified
    mov  eax, VP_E_PIN
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; vp_sha_update_sliced(RSI=data, RDX=len) -> RAX=0/-1: vp_sha_ctx in VP_SHA_SLICE
; slices with the loader's cooperative point (hv_linux_load_yield) after each, so a
; whole-artifact pin hash never holds the BSP silent on START. vp_sha_ctx has no
; other user: only vm_profile_dep_verify touches it, and only the loader calls that.
VP_SHA_SLICE equ 0x100000
vp_sha_update_sliced:
    push rbx
    push r12
    mov  rbx, rsi
    mov  r12, rdx
.slice:
    test r12, r12
    jz   .done
    mov  rdx, r12
    cmp  rdx, VP_SHA_SLICE
    jbe  .update
    mov  rdx, VP_SHA_SLICE
.update:
    lea  rdi, [rel vp_sha_ctx]
    mov  rsi, rbx
    add  rbx, rdx
    sub  r12, rdx
    call sha256_stream_update
    test rax, rax
    jnz  .out
    call hv_linux_load_yield
    jmp  .slice
.done:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Rendering through vmx.asm's staged out-buffer (hv_out_*). Each line stays far
; below hv_out_buf's 1024 bytes: fixed keys, bounded names, decimal u32 values.
; ---------------------------------------------------------------------------

; vp_out_devices(EDI=mask) — "timer,console,net" or "none".
vp_out_devices:
    push rbx
    push r12
    mov  ebx, edi
    xor  r12d, r12d                         ; something written
    test ebx, VP_DEV_TIMER
    jz   .console
    lea  rdi, [rel str_vp_dev_timer]
    call hv_out_str
    mov  r12d, 1
.console:
    test ebx, VP_DEV_CONSOLE
    jz   .net
    test r12d, r12d
    jz   .console_name
    lea  rdi, [rel str_vp_comma]
    call hv_out_str
.console_name:
    lea  rdi, [rel str_vp_dev_console]
    call hv_out_str
    mov  r12d, 1
.net:
    test ebx, VP_DEV_NET
    jz   .display
    test r12d, r12d
    jz   .net_name
    lea  rdi, [rel str_vp_comma]
    call hv_out_str
.net_name:
    lea  rdi, [rel str_vp_dev_net]
    call hv_out_str
    mov  r12d, 1
.display:
    test ebx, VP_DEV_DISPLAY
    jz   .input
    test r12d, r12d
    jz   .display_name
    lea  rdi, [rel str_vp_comma]
    call hv_out_str
.display_name:
    lea  rdi, [rel str_vp_dev_display]
    call hv_out_str
    mov  r12d, 1
.input:
    test ebx, VP_DEV_INPUT
    jz   .entropy
    test r12d, r12d
    jz   .input_name
    lea  rdi, [rel str_vp_comma]
    call hv_out_str
.input_name:
    lea  rdi, [rel str_vp_dev_input]
    call hv_out_str
    mov  r12d, 1
.entropy:
    test ebx, VP_DEV_ENTROPY
    jz   .sound
    test r12d, r12d
    jz   .entropy_name
    lea  rdi, [rel str_vp_comma]
    call hv_out_str
.entropy_name:
    lea  rdi, [rel str_vp_dev_entropy]
    call hv_out_str
    mov  r12d, 1
.sound:
    test ebx, VP_DEV_SOUND
    jz .restore
    test r12d, r12d
    jz .sound_name
    lea rdi, [rel str_vp_comma]
    call hv_out_str
.sound_name:
    lea rdi, [rel str_vp_dev_sound]
    call hv_out_str
    mov r12d, 1
.restore:
    test ebx, VP_DEV_RESTORE
    jz   .filesystem
    test r12d, r12d
    jz   .restore_name
    lea  rdi, [rel str_vp_comma]
    call hv_out_str
.restore_name:
    lea  rdi, [rel str_vp_dev_restore]
    call hv_out_str
    mov  r12d, 1
.filesystem:
    test ebx,VP_DEV_FILESYSTEM
    jz .wifi
    test r12d,r12d
    jz .filesystem_name
    lea rdi,[rel str_vp_comma]
    call hv_out_str
.filesystem_name:
    lea rdi,[rel str_vp_dev_filesystem]
    call hv_out_str
    mov r12d,1
.wifi:
    test ebx,VP_DEV_WIFI
    jz .padchan
    test r12d,r12d
    jz .wifi_name
    lea rdi,[rel str_vp_comma]
    call hv_out_str
.wifi_name:
    lea rdi,[rel str_vp_dev_wifi]
    call hv_out_str
    mov r12d,1
.padchan:
    test ebx, VP_DEV_PINCHAN
    jz   .not_pin_name
    test r12d, r12d
    jz   .pin_name
    lea  rdi, [rel str_vp_comma]
    call hv_out_str
.pin_name:
    lea  rdi, [rel str_vp_dev_pinchan]
    call hv_out_str
    mov  r12d, 1
.not_pin_name:
    test ebx, VP_DEV_PADCHAN
    jz   .lapic
    test r12d, r12d
    jz   .padchan_name
    lea  rdi, [rel str_vp_comma]
    call hv_out_str
.padchan_name:
    lea  rdi, [rel str_vp_dev_padchan]
    call hv_out_str
    mov  r12d, 1
.lapic:
    test ebx, VP_DEV_LAPIC
    jz   .pcihda
    test r12d, r12d
    jz   .lapic_name
    lea  rdi, [rel str_vp_comma]
    call hv_out_str
.lapic_name:
    lea  rdi, [rel str_vp_dev_lapic]
    call hv_out_str
    mov  r12d, 1
.pcihda:
    test ebx, VP_DEV_PCIHDA
    jz   .none
    test r12d, r12d
    jz   .pcihda_name
    lea  rdi, [rel str_vp_comma]
    call hv_out_str
.pcihda_name:
    lea  rdi, [rel str_vp_dev_pcihda]
    call hv_out_str
    mov  r12d, 1
    %ifidn RCQ50_G0_FLR_LAB,1
    test ebx, VP_DEV_PCIFLR
    jz   .none
    lea  rdi, [rel str_vp_dev_pciflr]      ; always after hda: the closure carries both
    call hv_out_str
    %endif
.none:
    test r12d, r12d
    jnz  .out
    lea  rdi, [rel str_vp_dev_none]
    call hv_out_str
.out:
    pop  r12
    pop  rbx
    ret

; vp_out_hex(RDI=bytes, ESI=count) — lowercase hex.
vp_out_hex:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12d, esi
.byte:
    test r12d, r12d
    jz   .out
    movzx eax, byte [rbx]
    lea  rdx, [rel str_vp_hex]
    mov  ecx, eax
    shr  eax, 4
    mov  al, [rdx + rax]
    call hv_out_putc                        ; bounded (hv_out_putc clobbers only RSI)
    and  ecx, 15
    mov  al, [rdx + rcx]
    call hv_out_putc
    inc  rbx
    dec  r12d
    jmp  .byte
.out:
    pop  r12
    pop  rbx
    ret

; vp_out_kv(RDI=key cstr, EAX=u32 value)
vp_out_kv:
    push rax
    call hv_out_str
    pop  rax
    jmp  hv_out_dec

; vp_out_plan_summary(RDI=plan) — bounded list costs; details remain in PLAN.
vp_out_plan_summary:
    push rbx
    mov  rbx, rdi
    lea  rdi, [rel str_vp_k_vcpus]
    mov  eax, [rbx + VPP_VCPUS]
    call vp_out_kv
    lea  rdi, [rel str_vp_k_ram]
    mov  eax, [rbx + VPP_RAM]
    call vp_out_kv
    lea  rdi, [rel str_vp_k_reserve]
    mov  eax, [rbx + VPP_RESERVE]
    call vp_out_kv
    lea  rdi, [rel str_vp_k_devices]
    call hv_out_str
    mov  edi, [rbx + VPP_DEVICES]
    call vp_out_devices
    pop  rbx
    ret

; vp_out_plan(RDI=plan) — full cost line for the single-profile PLAN.
; omitted= stays here only: it is the complement of devices=, and repeating it
; in every PROFILES row would clip the seventh record in the 1024-byte reply.
vp_out_plan:
    push rbx
    mov  rbx, rdi
    call vp_out_plan_summary
    lea  rdi, [rel str_vp_k_omitted]
    call hv_out_str
    mov  edi, [rbx + VPP_OMITTED]
    call vp_out_devices
    lea  rdi, [rel str_vp_k_mmio]
    mov  eax, [rbx + VPP_MMIO_PAGES]
    call vp_out_kv
    lea  rdi, [rel str_vp_k_irq]
    mov  eax, [rbx + VPP_IRQ_LINES]
    call vp_out_kv
    lea  rdi, [rel str_vp_k_leaves]
    mov  eax, [rbx + VPP_EPT_LEAVES]
    call vp_out_kv
    lea  rdi, [rel str_vp_k_decls]
    mov  eax, [rbx + VPP_DECLS]
    call vp_out_kv
    mov  eax, [rbx + VPP_FB_BYTES]          ; RCQ-23: only a display costs framebuffer
    test eax, eax
    jz   .no_fb
    lea  rdi, [rel str_vp_k_fb]
    call vp_out_kv
.no_fb:
    pop  rbx
    ret

; vp_out_record_id(RDI=record) — name, class and compact profile identity.
vp_out_record_id:
    push rbx
    mov  rbx, rdi
    lea  rdi, [rel str_vp_k_name]
    call hv_out_str
    lea  rdi, [rbx + VP_NAME]
    call hv_out_str
    lea  rdi, [rel str_vp_k_class]
    movzx eax, byte [rbx + VP_CLASS]
    call vp_out_kv
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rbx + VP_CLASS], VP_CLASS_MEDIA
    jne  .identity_pin
    lea  rdi, [rel str_vp_k_media_gpa]
    mov  eax, VP_MEDIA_GPA
    call vp_out_kv
.identity_pin:
%endif
%endif
    ; Profile id: SHA-256 of the exact record bytes (first 8 bytes shown).
    lea  rdi, [rel vp_sha_out]
    mov  rsi, rbx
    mov  edx, VP_BYTES
    call sha256_hash
    lea  rdi, [rel str_vp_k_id]
    call hv_out_str
    lea  rdi, [rel vp_sha_out]
    mov  esi, 8
    call vp_out_hex
    pop  rbx
    ret

; vp_out_identity(RDI=record) — single-profile detail includes both file pins.
vp_out_identity:
    push rbx
    mov  rbx, rdi
    call vp_out_record_id
    mov  rdi, rbx
    mov  esi, VP_DEP_KERNEL
    call vp_dep_of_kind
    test rax, rax
    jz   .initrd
    push rax
    lea  rdi, [rel str_vp_k_kernel]
    call hv_out_str
    mov  rdi, [rsp]
    lea  rdi, [rdi + VPD_SHA]
    mov  esi, 8
    call vp_out_hex
    pop  rax
.initrd:
    mov  rdi, rbx
    mov  esi, VP_DEP_INITRD
    call vp_dep_of_kind
    test rax, rax
    jz   .out
    push rax
    lea  rdi, [rel str_vp_k_initrd]
    call hv_out_str
    mov  rdi, [rsp]
    lea  rdi, [rdi + VPD_SHA]
    mov  esi, 8
    call vp_out_hex
    pop  rax
.out:
    pop  rbx
    ret

; vp_out_pair_identity(RDI=record or 0). Full content identity of guest pins
; plus VM shape, matching the compiler's SHA256(profile.bin). The abbreviated
; list stays compact; only single-profile PLAN/STAT append this field.
; A legacy/unresolved selection has no pinned pair and emits no identity.
vp_out_pair_identity:
    test rdi, rdi
    jz   .out
    mov  rsi, rdi
    lea  rdi, [rel vp_sha_out]
    mov  edx, VP_BYTES
    call sha256_hash
    lea  rdi, [rel str_vp_k_pair_sha256]
    call hv_out_str
    lea  rdi, [rel vp_sha_out]
    mov  esi, 32
    jmp  vp_out_hex
.out:
    ret

; vm_profile_render_list — GUESTVM PROFILES: legacy=fixed, then each
; built-in record with its validation status and identity. Costs and omitted
; devices remain in single-profile PLAN; repeating them here clips the ninth
; record in the bounded 1024-byte reply. No row or identity may be truncated.
vm_profile_render_list:
    push rbx
    push r12
    sub  rsp, VPP_BYTES + 8
    call hv_out_reset
    lea  rdi, [rel str_vp_list_head]
    call hv_out_str
    lea  rbx, [rel vp_builtin_table]
    xor  r12d, r12d
.record:
    cmp  r12d, VP_BUILTIN_COUNT
    jae  .done
    lea  rdi, [rel str_vp_sep]
    call hv_out_str
    mov  rdi, rbx
    mov  esi, VP_BYTES
    mov  rdx, rsp
    call vm_profile_plan
    push rax
    lea  rdi, [rel str_vp_k_status]
    call vp_out_kv
    pop  rax
    mov  rdi, rbx
    call vp_out_record_id
    add  rbx, VP_BYTES
    inc  r12d
    jmp  .record
.done:
    add  rsp, VPP_BYTES + 8
    pop  r12
    pop  rbx
    ret

; vm_profile_render_plan(RDI=record or 0 for legacy, ESI=status to report)
vm_profile_render_plan:
    push rbx
    push r12
    sub  rsp, VPP_BYTES + 8
    mov  rbx, rdi
    mov  r12d, esi
    call hv_out_reset
    lea  rdi, [rel str_vp_plan_head]
    call hv_out_str
    lea  rdi, [rel str_vp_k_status]
    mov  eax, r12d
    call vp_out_kv
    test rbx, rbx
    jnz  .record
    test r12d, r12d
    jz   .legacy
    lea  rdi, [rel str_vp_unknown_name]     ; no record resolved: no cost to show
    call hv_out_str
    jmp  .out
.legacy:
    lea  rdi, [rel str_vp_legacy_name]
    call hv_out_str
    mov  rdi, rsp
    mov  esi, VP_LEGACY_RAM
    mov  edx, VP_DEV_LEGACY
    mov  ecx, 1
    call vm_profile_plan_mask
    jmp  .cost
.record:
    mov  rdi, rbx
    mov  esi, VP_BYTES
    mov  rdx, rsp
    call vm_profile_plan
    mov  rdi, rbx
    call vp_out_identity
    mov  rdi, rbx
    call vp_out_pair_identity
.cost:
    mov  rdi, rsp
    call vp_out_plan
.out:
    add  rsp, VPP_BYTES + 8
    pop  r12
    pop  rbx
    ret

; vm_profile_render_live — appended to GUESTVM STAT: the selection in force
; and what the loader actually mapped for the last START.
vm_profile_render_live:
    lea  rdi, [rel str_vp_k_profile]
    call hv_out_str
    mov  rax, [rel vm_profile_active]
    lea  rdi, [rel str_vp_legacy]
    test rax, rax
    jz   .name
    lea  rdi, [rax + VP_NAME]
.name:
    call hv_out_str
    mov  rdi, [rel vm_profile_active]
    call vp_out_pair_identity
    lea  rdi, [rel str_vp_k_live_devices]
    call hv_out_str
    mov  edi, [rel vm_profile_live_devices]
    call vp_out_devices
    lea  rdi, [rel str_vp_k_live_mmio]
    mov  eax, [rel vm_profile_live_mmio]
    call vp_out_kv
    lea  rdi, [rel str_vp_k_live_leaves]
    mov  eax, [rel vm_profile_live_leaves]
    call vp_out_kv
    lea  rdi, [rel str_vp_k_live_reserve]
    mov  eax, [rel vm_profile_live_reserve]
    call vp_out_kv
    cmp  qword [rel vm_profile_pair_state], 0
    je   .out
    lea  rdi, [rel str_vp_pair_limits]
    call hv_out_str
.out:
    ret

; ---------------------------------------------------------------------------
; Built-in profiles (read-only, inside the signed payload). Pins come from
; gauntlet_v2/tools/build_guest_thin_cli.sh (reproducible; MANIFEST.txt).
; ---------------------------------------------------------------------------
VP_THIN_RAM        equ 0x2000000        ; 32 MiB (legacy fixed shape: 64 MiB)
VP_THIN_KERN_SIZE  equ 947200       ; sha256 7bb6e7531c346b2d41d5117e6a38f2cded4a470274a2edeb0ec361fc1f34e991
VP_THIN_INIT_SIZE  equ 1110107      ; sha256 de298fc99c46073409ad4a5b7243c3edd970974ecaaa4371c4fca0dc0a50e8a2

align 8
vp_builtin_table:
; The build imports the actual compiler-produced record. No placeholder pins.
%ifdef PAOS_DRIVER_DOMAIN_PROFILE_INC
vp_driver_domain:
%include PAOS_DRIVER_DOMAIN_PROFILE_INC
.end:
%if vp_driver_domain.end-vp_driver_domain != VP_BYTES
%error "driver-domain profile must be one exact280B record"
%endif
VP_BUILTIN_NIC equ 1
%else
VP_BUILTIN_NIC equ 0
%endif
vp_thin_cli:
    dd 1, VP_BYTES
    db 'thin-cli', 0
    times VP_NAME_BYTES - 9 db 0
    db VP_CLASS_THIN_CLI, 0, 2, 0
    dd 1
    dq VP_THIN_RAM
    dd VP_DEV_TIMER | VP_DEV_CONSOLE, 0
    db VP_DEP_KERNEL, 0, 0, 0, 0
    db 'THINKERN   '
    dq VP_THIN_KERN_SIZE
    db 0x7b, 0xb6, 0xe7, 0x53, 0x1c, 0x34, 0x6b, 0x2d, 0x41, 0xd5, 0x11, 0x7e, 0x6a, 0x38, 0xf2, 0xcd
    db 0xed, 0x4a, 0x47, 0x02, 0x74, 0xa2, 0xed, 0xeb, 0x0e, 0xc3, 0x61, 0xfc, 0x1f, 0x34, 0xe9, 0x91
    db VP_DEP_INITRD, 0, 0, 0, 0
    db 'THININITGZ '
    dq VP_THIN_INIT_SIZE
    db 0xde, 0x29, 0x8f, 0xc9, 0x9c, 0x46, 0x07, 0x34, 0x09, 0xad, 0x4a, 0x5b, 0x72, 0x43, 0xc3, 0xed
    db 0xd9, 0x70, 0x97, 0x4e, 0xca, 0xaa, 0x43, 0x71, 0xc4, 0xfc, 0xa0, 0xdc, 0x0a, 0x50, 0xe8, 0xa2
    times (VP_DEP_MAX - 2) * VP_DEP_BYTES db 0
.end:
%if vp_thin_cli.end - vp_thin_cli != VP_BYTES
    %error "thin-cli profile record must be exactly VP_BYTES"
%endif

; RCQ-23 desktop-linux: pins come from gauntlet_v2/tools/build_guest_desktop_linux.sh.
VP_DESK_RAM        equ 0x4000000        ; 64 MiB; the framebuffer is reserved after it
VP_DESK_KERN_SIZE  equ 902144       ; sha256 b7756660954a50330169330ecb42f957c14edca8e55f51b02feaae1e35040fd3
VP_DESK_INIT_SIZE  equ 1112375      ; sha256 a2e8e38df1f6e5727e00f4d773464d1cff45a2b40e9f0673df42ca4457835c84

vp_desktop_linux:
    dd 1, VP_BYTES
    db 'desktop-linux', 0
    times VP_NAME_BYTES - 14 db 0
    db VP_CLASS_DESKTOP, 0, 2, 0
    dd 1
    dq VP_DESK_RAM
    dd VP_DEV_DESKTOP, 0
    db VP_DEP_KERNEL, 0, 0, 0, 0
    db 'DESKKERN   '
    dq VP_DESK_KERN_SIZE
    db 0xb7, 0x75, 0x66, 0x60, 0x95, 0x4a, 0x50, 0x33, 0x01, 0x69, 0x33, 0x0e, 0xcb, 0x42, 0xf9, 0x57
    db 0xc1, 0x4e, 0xdc, 0xa8, 0xe5, 0x5f, 0x51, 0xb0, 0x2f, 0xea, 0xae, 0x1e, 0x35, 0x04, 0x0f, 0xd3
    db VP_DEP_INITRD, 0, 0, 0, 0
    db 'DESKINITGZ '
    dq VP_DESK_INIT_SIZE
    db 0xa2, 0xe8, 0xe3, 0x8d, 0xf1, 0xf6, 0xe5, 0x72, 0x7e, 0x00, 0xf4, 0xd7, 0x73, 0x46, 0x4d, 0x1c
    db 0xff, 0x45, 0xa2, 0xb4, 0x0e, 0x9f, 0x06, 0x73, 0xdf, 0x42, 0xca, 0x44, 0x57, 0x83, 0x5c, 0x84
    times (VP_DEP_MAX - 2) * VP_DEP_BYTES db 0
.end:
%if vp_desktop_linux.end - vp_desktop_linux != VP_BYTES
    %error "desktop-linux profile record must be exactly VP_BYTES"
%endif
; Explicit opt-in; existing thin/desktop records and artifact pins are unchanged.
vp_entropy_cli:
    dd 1, VP_BYTES
    db 'entropy-cli', 0
    times VP_NAME_BYTES - 12 db 0
    db VP_CLASS_CLI, 0, 2, 0
    dd 1
    dq VP_THIN_RAM
    dd VP_DEV_TIMER | VP_DEV_CONSOLE | VP_DEV_ENTROPY, 0
    db VP_DEP_KERNEL, 0, 0, 0, 0
    db 'THINKERN   '
    dq VP_THIN_KERN_SIZE
    db 0x7b, 0xb6, 0xe7, 0x53, 0x1c, 0x34, 0x6b, 0x2d, 0x41, 0xd5, 0x11, 0x7e, 0x6a, 0x38, 0xf2, 0xcd
    db 0xed, 0x4a, 0x47, 0x02, 0x74, 0xa2, 0xed, 0xeb, 0x0e, 0xc3, 0x61, 0xfc, 0x1f, 0x34, 0xe9, 0x91
    db VP_DEP_INITRD, 0, 0, 0, 0
    db 'THININITGZ '
    dq VP_THIN_INIT_SIZE
    db 0xde, 0x29, 0x8f, 0xc9, 0x9c, 0x46, 0x07, 0x34, 0x09, 0xad, 0x4a, 0x5b, 0x72, 0x43, 0xc3, 0xed
    db 0xd9, 0x70, 0x97, 0x4e, 0xca, 0xaa, 0x43, 0x71, 0xc4, 0xfc, 0xa0, 0xdc, 0x0a, 0x50, 0xe8, 0xa2
    times (VP_DEP_MAX - 2) * VP_DEP_BYTES db 0
.end:
%if vp_entropy_cli.end - vp_entropy_cli != VP_BYTES
    %error "entropy-cli profile record must be exactly VP_BYTES"
%endif

; Separate --sound recipe artifacts: ALSA+SND_VIRTIO, existing desktop pins retained.
vp_desktop_sound:
    dd 1, VP_BYTES
    db 'desktop-sound', 0
    times VP_NAME_BYTES - 14 db 0
    db VP_CLASS_DESKTOP, 0, 2, 0
    dd 1
    dq VP_DESK_RAM
    dd VP_DEV_DESKTOP | VP_DEV_SOUND, 0
    db VP_DEP_KERNEL, 0, 0, 0, 0
    db 'SNDKERN    '
    dq 947200
    db 0xbb, 0xf3, 0x24, 0xf5, 0x3c, 0x0c, 0xb6, 0x66, 0x2f, 0x4e, 0x9f, 0x5b, 0x44, 0x1d, 0x68, 0x62
    db 0xe9, 0x50, 0x09, 0xff, 0x10, 0x96, 0x03, 0xda, 0x30, 0x0c, 0x91, 0x72, 0x83, 0xff, 0x8d, 0x4d
    db VP_DEP_INITRD, 0, 0, 0, 0
    db 'SNDINIT GZ '
    dq VP_DESK_INIT_SIZE
    db 0xa2, 0xe8, 0xe3, 0x8d, 0xf1, 0xf6, 0xe5, 0x72, 0x7e, 0x00, 0xf4, 0xd7, 0x73, 0x46, 0x4d, 0x1c
    db 0xff, 0x45, 0xa2, 0xb4, 0x0e, 0x9f, 0x06, 0x73, 0xdf, 0x42, 0xca, 0x44, 0x57, 0x83, 0x5c, 0x84
    times (VP_DEP_MAX - 2) * VP_DEP_BYTES db 0
.end:
%if vp_desktop_sound.end - vp_desktop_sound != VP_BYTES
    %error "desktop-sound profile record must be exactly VP_BYTES"
%endif

; Common Noble147 CLI, fresh149-package producer (common149_guest.json).
; The whole derived RAM-root hash binds all unchanged common userspace,
; identity startup files, metadata, /init and ACL helper. The initrd is the
; two-stage root staged by stage_linux_ram_root.py: static PID1 bootstrap plus
; the retained single-stage archive (46abaebd..., 248922246 bytes) carried
; byte-identical as ROOTPAY.GZ. The retained archive alone panicked in PID1
; under the ramfs initial root selected above (owned QEMU, 0.0.181), so it is
; no longer admitted here. This is a launchable signed tuple, not a runtime
; RAM/SSH/health or matched-race qualification.
vp_common_ram_cli:
    dd 1, VP_BYTES
    db 'common-ram-cli', 0
    times VP_NAME_BYTES - 15 db 0
    db VP_CLASS_CLI, 0, 2, 0
    dd 1
    dq 768 * 1024 * 1024
    dd VP_DEV_TIMER | VP_DEV_CONSOLE | VP_DEV_NET, 0
    db VP_DEP_KERNEL, 0, 0, 0, 0
    db 'ROOTKERN   '
    dq 15083912
    db 0x41, 0xba, 0x36, 0xd8, 0x60, 0xaa, 0x0b, 0x0c, 0xd9, 0x95, 0xf4, 0xca, 0x88, 0x56, 0xd8, 0x02
    db 0x49, 0xb2, 0x44, 0x57, 0x7e, 0x70, 0x49, 0x29, 0xb5, 0x5b, 0xe1, 0x3f, 0xbd, 0x1e, 0xbd, 0x2f
    db VP_DEP_INITRD, 0, 0, 0, 0
    db 'ROOTINITGZ '
    dq 249789306
    db 0x13, 0x21, 0x4c, 0x84, 0x5a, 0x21, 0xa5, 0xd6, 0xac, 0xcd, 0x40, 0xe8, 0xb3, 0xd1, 0xe2, 0x6f
    db 0xe9, 0xee, 0x81, 0x44, 0x53, 0x6f, 0x65, 0x50, 0x01, 0x70, 0x75, 0xa9, 0x52, 0xce, 0x39, 0x7e
    times (VP_DEP_MAX - 2) * VP_DEP_BYTES db 0
.end:
%if vp_common_ram_cli.end - vp_common_ram_cli != VP_BYTES
    %error "common-ram-cli profile record must be exactly VP_BYTES"
%endif

; RCQ-24 offline CPU mechanics fixture. Whole archive pins include the fixed
; init, runtime and model. No net/display/input/GPU or launch-authority grant.
; Producer: llm_cpu_guest/preflight.py stage() in SOURCE a766fa055.
vp_ai_cpu:
    dd 1, VP_BYTES
    db 'ai-cpu', 0
    times VP_NAME_BYTES - 7 db 0
    db VP_CLASS_THIN_CLI, 0, 2, 0
    dd 1
    dq 512 * 1024 * 1024
    dd VP_DEV_TIMER | VP_DEV_CONSOLE, 0
    db VP_DEP_KERNEL, 0, 0, 0, 0
    db 'THINKERN   '
    dq VP_THIN_KERN_SIZE
    db 0x7b, 0xb6, 0xe7, 0x53, 0x1c, 0x34, 0x6b, 0x2d, 0x41, 0xd5, 0x11, 0x7e, 0x6a, 0x38, 0xf2, 0xcd
    db 0xed, 0x4a, 0x47, 0x02, 0x74, 0xa2, 0xed, 0xeb, 0x0e, 0xc3, 0x61, 0xfc, 0x1f, 0x34, 0xe9, 0x91
    db VP_DEP_INITRD, 0, 0, 0, 0
    db 'AICPUIN GZ '
    dq 141838965
    db 0x66, 0x60, 0x48, 0x5b, 0xfa, 0x42, 0x55, 0xb7, 0xeb, 0xe3, 0xda, 0xa0, 0x17, 0x85, 0x93, 0x5a
    db 0xa6, 0xef, 0xd0, 0xff, 0xac, 0x09, 0x66, 0xcc, 0xe7, 0xe4, 0xb5, 0xe1, 0x89, 0xa2, 0x1a, 0xd9
    times (VP_DEP_MAX - 2) * VP_DEP_BYTES db 0
.end:
%if vp_ai_cpu.end - vp_ai_cpu != VP_BYTES
    %error "ai-cpu profile record must be exactly VP_BYTES"
%endif

; RCQ-24 caller-supplied prompts over the bounded pull console. Separate from
; the fixed ai-cpu journey: stage_interactive.py pins the whole new archive.
vp_ai_chat:
    dd 1, VP_BYTES
    db 'ai-chat', 0
    times VP_NAME_BYTES - 8 db 0
    db VP_CLASS_THIN_CLI, 0, 2, 0
    dd 1
    dq 512 * 1024 * 1024
    dd VP_DEV_TIMER | VP_DEV_CONSOLE, 0
    db VP_DEP_KERNEL, 0, 0, 0, 0
    db 'THINKERN   '
    dq VP_THIN_KERN_SIZE
    db 0x7b, 0xb6, 0xe7, 0x53, 0x1c, 0x34, 0x6b, 0x2d, 0x41, 0xd5, 0x11, 0x7e, 0x6a, 0x38, 0xf2, 0xcd
    db 0xed, 0x4a, 0x47, 0x02, 0x74, 0xa2, 0xed, 0xeb, 0x0e, 0xc3, 0x61, 0xfc, 0x1f, 0x34, 0xe9, 0x91
    db VP_DEP_INITRD, 0, 0, 0, 0
    db 'AICHAT  GZ '
    dq 142536039
    db 0xae, 0xab, 0x55, 0x8e, 0x73, 0x6b, 0x7b, 0x3e, 0x05, 0x72, 0x12, 0xe0, 0x38, 0x5c, 0xc2, 0x74
    db 0x93, 0xd8, 0xe7, 0x66, 0xb6, 0x94, 0x32, 0x70, 0xc0, 0x65, 0xbd, 0xe0, 0x79, 0x03, 0x2b, 0x95
    times (VP_DEP_MAX - 2) * VP_DEP_BYTES db 0
.end:
%if vp_ai_chat.end - vp_ai_chat != VP_BYTES
    %error "ai-chat profile record must be exactly VP_BYTES"
%endif

; Expendable offline CPU worker, private PWR1 only. The native lifecycle must
; admit the real physical kind1 allocation before the guest receives GRANT.
; Producer: llm_cpu_guest/stage_warm.py, no ordinary console or foreground app.
; WARMKERN: build_guest_warm_cpu.sh, local UNIX IPC; no IP stack or netdev.
vp_warm_cpu:
    dd 1, VP_BYTES
    db 'warm-cpu', 0
    times VP_NAME_BYTES - 9 db 0
    db VP_CLASS_CLI, 0, 2, 0
    dd 1
    dq 512 * 1024 * 1024
    dd VP_DEV_TIMER | VP_DEV_CONSOLE | VP_DEV_WARMCHAN, 0
    db VP_DEP_KERNEL, 0, 0, 0, 0
    db 'WARMKERN   '
    dq 1135616
    db 0xab, 0xed, 0x61, 0x5a, 0xce, 0x9f, 0x63, 0x00, 0xb4, 0xc3, 0x7c, 0x47, 0x27, 0x8c, 0x97, 0xf6
    db 0x5a, 0xb9, 0x93, 0x44, 0x32, 0x9c, 0x1e, 0x0b, 0xf0, 0xa7, 0xbc, 0x8c, 0xe9, 0xa1, 0xe5, 0xa7
    db VP_DEP_INITRD, 0, 0, 0, 0
    db 'WARMCPU GZ '
    dq 142830347
    db 0x60, 0x66, 0x22, 0x04, 0x30, 0x48, 0x08, 0x05, 0xbb, 0x77, 0x77, 0x27, 0x59, 0xab, 0x4a, 0x66
    db 0x53, 0xae, 0xc4, 0x67, 0xa7, 0x02, 0x6a, 0x40, 0xf3, 0xca, 0xbb, 0x87, 0x8d, 0xbc, 0x99, 0x6d
    times (VP_DEP_MAX - 2) * VP_DEP_BYTES db 0
.end:
%if vp_warm_cpu.end - vp_warm_cpu != VP_BYTES
    %error "warm-cpu profile record must be exactly VP_BYTES"
%endif

; RCQ-36 audio-domain: the Linux driver domain behind the private PAD1 channel.
; Pins come from gauntlet_v2/tools/build_guest_audio_domain.sh (reproducible;
; MANIFEST.txt). hvc0 belongs to the PAD1 service; the kernel console is ttyS0.
VP_AUD_RAM         equ 0x4000000        ; 64 MiB
VP_AUD_KERN_SIZE   equ 1205248      ; sha256 2b31a29d95cb63fdf7426190873baee0e09c9b8204ecc46031f964fb9dcdda92
VP_AUD_INIT_SIZE   equ 1117342      ; sha256 36f72b5ac0d911001d947bf1e386299a7a8cb0af4ecb567563859f235a9a4b97
VP_AUDH_INIT_SIZE  equ 1119387      ; sha256 b5246fdaa69507146a4aad9e0ab6afb6f502afe8d14a96c4a0b656b853d73646 (--hda: + Line Out /pad-mixer)

vp_audio_domain:
    dd 1, VP_BYTES
    db 'audio-domain', 0
    times VP_NAME_BYTES - 13 db 0
    db VP_CLASS_CLI, 0, 2, 0
    dd 1
    dq VP_AUD_RAM
    dd VP_DEV_PADDOMAIN, 0
    db VP_DEP_KERNEL, 0, 0, 0, 0
    db 'AUDKERN    '
    dq VP_AUD_KERN_SIZE
    db 0x2b, 0x31, 0xa2, 0x9d, 0x95, 0xcb, 0x63, 0xfd, 0xf7, 0x42, 0x61, 0x90, 0x87, 0x3b, 0xae, 0xe0
    db 0xe0, 0x9c, 0x9b, 0x82, 0x04, 0xec, 0xc4, 0x60, 0x31, 0xf9, 0x64, 0xfb, 0x9d, 0xcd, 0xda, 0x92
    db VP_DEP_INITRD, 0, 0, 0, 0
    db 'AUDINIT GZ '
    dq VP_AUD_INIT_SIZE
    db 0x36, 0xf7, 0x2b, 0x5a, 0xc0, 0xd9, 0x11, 0x00, 0x1d, 0x94, 0x7b, 0xf1, 0xe3, 0x86, 0x29, 0x9a
    db 0x7a, 0x8c, 0xb0, 0xaf, 0x4e, 0xcb, 0x56, 0x75, 0x63, 0x85, 0x9f, 0x23, 0x5a, 0x9a, 0x4b, 0x97
    times (VP_DEP_MAX - 2) * VP_DEP_BYTES db 0
.end:
%if vp_audio_domain.end - vp_audio_domain != VP_BYTES
    %error "audio-domain profile record must be exactly VP_BYTES"
%endif

; RCQ-36 V2: the same audio-domain kernel (PCI + snd-hda-intel built in), with the host HDA
; function assigned (VP_DEV_PCIHDA): the PAD1 service plays through it instead of refusing.
; Its initramfs AUDHINIT.GZ (build_guest_audio_domain.sh --hda) adds /pad-mixer, run through
; pad.mixer: snd-hda leaves every mixer-controlled amp muted at volume 0 until userspace writes it.
vp_audio_domain_hda:
    dd 1, VP_BYTES
    db 'audio-hda', 0
    times VP_NAME_BYTES - 10 db 0
    db VP_CLASS_CLI, 0, 2, 0
    dd 1
    dq VP_AUD_RAM
    dd VP_DEV_HDADOMAIN, 0
    db VP_DEP_KERNEL, 0, 0, 0, 0
    db 'AUDKERN    '
    dq VP_AUD_KERN_SIZE
    db 0x2b, 0x31, 0xa2, 0x9d, 0x95, 0xcb, 0x63, 0xfd, 0xf7, 0x42, 0x61, 0x90, 0x87, 0x3b, 0xae, 0xe0
    db 0xe0, 0x9c, 0x9b, 0x82, 0x04, 0xec, 0xc4, 0x60, 0x31, 0xf9, 0x64, 0xfb, 0x9d, 0xcd, 0xda, 0x92
    db VP_DEP_INITRD, 0, 0, 0, 0
    db 'AUDHINITGZ '
    dq VP_AUDH_INIT_SIZE
    db 0xb5, 0x24, 0x6f, 0xda, 0xa6, 0x95, 0x07, 0x14, 0x6a, 0x4a, 0xad, 0x9e, 0x0a, 0xb6, 0xaf, 0xb6
    db 0xf5, 0x02, 0xaf, 0xe8, 0xd1, 0x4a, 0x96, 0xc4, 0xa0, 0xb6, 0x56, 0xb8, 0x53, 0xd7, 0x36, 0x46
    times (VP_DEP_MAX - 2) * VP_DEP_BYTES db 0
.end:
%if vp_audio_domain_hda.end - vp_audio_domain_hda != VP_BYTES
    %error "audio-hda profile record must be exactly VP_BYTES"
%endif

%ifidn RCQ50_G0_FLR_LAB,1
; RCQ-50 G0 (lab only): the audio-domain kernel (PCI conf1 built in) enumerates the assigned
; endpoint; the thin-cli busybox initramfs keeps the guest resident on hvc0. No driver for it.
vp_flr_lab:
    dd 1, VP_BYTES
    db 'flr-lab', 0
    times VP_NAME_BYTES - 8 db 0
    db VP_CLASS_CLI, 0, 2, 0
    dd 1
    dq VP_AUD_RAM
    dd VP_DEV_FLRDOMAIN, 0
    db VP_DEP_KERNEL, 0, 0, 0, 0
    db 'AUDKERN    '
    dq VP_AUD_KERN_SIZE
    db 0x2b, 0x31, 0xa2, 0x9d, 0x95, 0xcb, 0x63, 0xfd, 0xf7, 0x42, 0x61, 0x90, 0x87, 0x3b, 0xae, 0xe0
    db 0xe0, 0x9c, 0x9b, 0x82, 0x04, 0xec, 0xc4, 0x60, 0x31, 0xf9, 0x64, 0xfb, 0x9d, 0xcd, 0xda, 0x92
    db VP_DEP_INITRD, 0, 0, 0, 0
    db 'THININITGZ '
    dq VP_THIN_INIT_SIZE
    db 0xde, 0x29, 0x8f, 0xc9, 0x9c, 0x46, 0x07, 0x34, 0x09, 0xad, 0x4a, 0x5b, 0x72, 0x43, 0xc3, 0xed
    db 0xd9, 0x70, 0x97, 0x4e, 0xca, 0xaa, 0x43, 0x71, 0xc4, 0xfc, 0xa0, 0xdc, 0x0a, 0x50, 0xe8, 0xa2
    times (VP_DEP_MAX - 2) * VP_DEP_BYTES db 0
.end:
%if vp_flr_lab.end - vp_flr_lab != VP_BYTES
    %error "flr-lab profile record must be exactly VP_BYTES"
%endif
VP_BUILTIN_FLR equ 1
%else
VP_BUILTIN_FLR equ 0
%endif

; S7: exact reproducible console-only SMP closure, two physical cores.
vp_thin_smp2:
    dd 1, VP_BYTES
    db 'thin-smp2', 0
    times VP_NAME_BYTES - 10 db 0
    db VP_CLASS_CLI, 0, 2, 0
    dd 2
    dq 64 * 1024 * 1024
    dd VP_DEV_TIMER | VP_DEV_CONSOLE | VP_DEV_LAPIC, 0
    db VP_DEP_KERNEL, 0, 0, 0, 0
    db 'SMPKERN    '
    dq 1070080
    db 0x2b, 0xfb, 0x2c, 0x99, 0x4a, 0x7f, 0xc8, 0x1b, 0xc6, 0x85, 0x54, 0x1e, 0x72, 0x66, 0x44, 0x08
    db 0x9a, 0x45, 0x49, 0x76, 0x88, 0x00, 0x5f, 0x0d, 0xa6, 0xdf, 0x13, 0xd3, 0x2e, 0x10, 0xc7, 0x63
    db VP_DEP_INITRD, 0, 0, 0, 0
    db 'SMPINIT GZ '
    dq 1110108
    db 0x8a, 0x6c, 0xfb, 0xf2, 0x85, 0xdb, 0x70, 0xa9, 0x43, 0x2f, 0xa8, 0x8b, 0x7f, 0xf2, 0xa2, 0x78
    db 0x30, 0xf8, 0x2c, 0x04, 0x54, 0xae, 0xc0, 0x7c, 0xc7, 0x19, 0x69, 0x7f, 0x93, 0x4e, 0xd9, 0x8c
    times (VP_DEP_MAX - 2) * VP_DEP_BYTES db 0
.end:
%if vp_thin_smp2.end - vp_thin_smp2 != VP_BYTES
    %error "thin-smp2 record size drift"
%endif

%ifdef PAOS_FILESYSTEM_PROFILE_INC
vp_filesystem:
%include PAOS_FILESYSTEM_PROFILE_INC
.end:
%if vp_filesystem.end-vp_filesystem != VP_BYTES
 %error "filesystem signed profile record must be exactly VP_BYTES"
%endif
VP_BUILTIN_FILESYSTEM equ 1
%else
VP_BUILTIN_FILESYSTEM equ 0
%endif

%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
; MEDIAKRN: G1 out5. MEDIAINI.GZ: codex-av handoff 09d4b950 (2026-10-17).
vp_media:
    dd 1, VP_BYTES
    db 'media', 0
    times VP_NAME_BYTES - 6 db 0
    db VP_CLASS_MEDIA, 0, 2, 0
    dd 1
    dq VP_MEDIA_RAM
    dd VP_DEV_TIMER | VP_DEV_CONSOLE, 0
    db VP_DEP_KERNEL, 0, 0, 0, 0
    db 'MEDIAKRN   '
    dq 857088
    db 0xe4,0x0c,0xf9,0x61,0x89,0x6a,0x04,0x90,0xc4,0xd2,0xa0,0x15,0xd3,0x7e,0x47,0x58
    db 0x78,0xf0,0x18,0x3d,0xd9,0xeb,0x41,0xe0,0x7e,0xe1,0x64,0x54,0x81,0xbb,0x2e,0xe3
    db VP_DEP_INITRD, 0, 0, 0, 0
    db 'MEDIAINIGZ '
    dq 2306521
    db 0x09,0xd4,0xb9,0x50,0xf9,0xb5,0x83,0xd3,0xf7,0x5c,0xeb,0x82,0x1b,0x02,0xbc,0x10
    db 0xa2,0x4b,0x90,0xbc,0xa7,0xf9,0x3e,0x48,0xe2,0x29,0xcf,0x11,0xd3,0xbd,0x13,0xfe
    times (VP_DEP_MAX - 2) * VP_DEP_BYTES db 0
.end:
%if vp_media.end - vp_media != VP_BYTES
%error "media profile record must be exactly VP_BYTES"
%endif
str_vp_cmdline_media: db " virtio_mmio.device=4K@0xD0000000:5 memmap=4M$0xba00000 paos.media=0xba00000", 0
str_vp_k_media_gpa: db " media_gpa=", 0
VP_BUILTIN_COUNT equ 12 + VP_BUILTIN_FLR + VP_BUILTIN_FILESYSTEM + VP_BUILTIN_NIC
%else
VP_BUILTIN_COUNT equ 11 + VP_BUILTIN_FLR + VP_BUILTIN_FILESYSTEM + VP_BUILTIN_NIC
%endif
%else
VP_BUILTIN_COUNT equ 11 + VP_BUILTIN_FLR + VP_BUILTIN_FILESYSTEM + VP_BUILTIN_NIC
%endif

; Explicit native profile guest marker consumed by guest-only startup units.
; This identifies the guest context; it grants no launch or owner authority.
; Named native profiles unpack their whole root into RAM. Explicit ramfs avoids
; CONFIG_TMPFS default rootfs imposing half of early managed RAM as a file quota.
; Guest physical RAM remains bounded by the validated profile/EPT/NPT mapping.
str_vp_cmdline_base:    db "earlycon=uart8250,io,0x3f8 console=ttyS0 rdinit=/init panic=-1 oops=panic loglevel=8 nolapic noapic no_timer_check lpj=4000000 tsc=reliable idle=halt clearcpuid=124 pci=off nokaslr paos.guest=1 rootfstype=ramfs", 0
; RCQ-50 S4: a guest LAPIC profile (x2APIC kernel) drops only " nolapic"; the head is the base up to it.
str_vp_cmdline_lapic_head: db "earlycon=uart8250,io,0x3f8 console=ttyS0 rdinit=/init panic=-1 oops=panic loglevel=8", 0
; RCQ-36 V2: the assigned-HDA profile's head: the base up to " pci=off", which becomes conf1 without MSI.
str_vp_cmdline_pci_head: db "earlycon=uart8250,io,0x3f8 console=ttyS0 rdinit=/init panic=-1 oops=panic loglevel=8 nolapic noapic no_timer_check lpj=4000000 tsc=reliable idle=halt clearcpuid=124 pci=conf1 pci=nomsi", 0
str_vp_cmdline_console: db " console=hvc0 virtio_mmio.device=4K@0xD0000000:5", 0
str_vp_cmdline_net:     db " virtio_mmio.device=4K@0xD0001000:6", 0
str_vp_cmdline_entropy: db " virtio_mmio.device=4K@0xD0003000:3", 0
str_vp_dev_entropy: db "entropy", 0
str_vp_cmdline_sound: db " virtio_mmio.device=4K@0xD0004000:7", 0
str_vp_dev_sound: db "sound", 0
; The guest restore hook additionally requires paos.snapshot=1 with this port.
str_vp_cmdline_restore: db " virtio_mmio.device=4K@0xD0005000:5 paos.snapshot=1", 0
str_vp_dev_restore: db "restore", 0
str_vp_dev_filesystem: db "filesystem", 0
str_vp_dev_wifi: db "wifi", 0
str_vp_dev_pinchan: db "pinchan",0
str_vp_dev_padchan: db "padchan", 0
str_vp_dev_lapic: db "lapic", 0
str_vp_dev_pcihda: db "hda", 0
%ifidn RCQ50_G0_FLR_LAB,1
str_vp_dev_pciflr: db ",flr", 0
%endif
str_vp_cmdline_input:   db " virtio_mmio.device=4K@0xD0002000:1", 0
str_vp_list_head:       db "VMPROFILES legacy=fixed", 0
str_vp_plan_head:       db "VMPLAN", 0
str_vp_legacy_name:     db " name=legacy", 0
str_vp_unknown_name:    db " name=unknown", 0
str_vp_legacy:          db "legacy", 0
str_vp_sep:             db " |", 0
str_vp_k_status:        db " status=", 0
str_vp_k_name:          db " name=", 0
str_vp_k_class:         db " class=", 0
str_vp_k_id:            db " id=", 0
str_vp_pair_limits:     db " pair_state=volatile pair_durable=unavailable pair_health=unavailable",0
str_vp_k_pair_sha256:   db " pair_sha256=", 0
str_vp_k_kernel:        db " kernel=", 0
str_vp_k_initrd:        db " initrd=", 0
str_vp_k_vcpus:         db " vcpus=", 0
str_vp_k_ram:           db " ram=", 0
str_vp_k_reserve:       db " reserve=", 0
str_vp_k_devices:       db " devices=", 0
str_vp_k_omitted:       db " omitted=", 0
str_vp_k_mmio:          db " mmio_pages=", 0
str_vp_k_irq:           db " irq_lines=", 0
str_vp_k_leaves:        db " ept_leaves=", 0
str_vp_k_decls:         db " decls=", 0
str_vp_k_fb:            db " fb_bytes=", 0
str_vp_k_profile:       db " profile=", 0
str_vp_k_live_devices:  db " live_devices=", 0
str_vp_k_live_mmio:     db " live_mmio=", 0
str_vp_k_live_leaves:   db " live_leaves=", 0
str_vp_k_live_reserve:  db " live_reserve=", 0
str_vp_dev_timer:       db "timer", 0
str_vp_dev_console:     db "console", 0
str_vp_dev_net:         db "net", 0
str_vp_dev_display:     db "display", 0
str_vp_dev_input:       db "input", 0
str_vp_dev_none:        db "none", 0
str_vp_comma:           db ",", 0
str_vp_hex:             db "0123456789abcdef"

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_hv_vm_profile_0 0
align 8
vp_pair_failed_gen:      dd 0           ; monotonic-generation pin failure latch
align 8
vm_profile_pair_state:   dq 0           ; disabled until trusted boot-time config
vp_pair_bank0:          times VPS_BYTES db 0
vp_pair_bank1:          times VPS_BYTES db 0
vm_profile_active:       dq 0           ; selected record, 0 = legacy shape
vm_profile_kdep:         dq 0
vm_profile_idep:         dq 0
vm_profile_live_reserve: dq 0
vm_profile_plan_cur:     times VPP_BYTES db 0
vm_profile_dev_mask:     dd VP_DEV_LEGACY
vm_profile_gen:          dd 0           ; START generation the selection is bound to
vm_profile_live_devices: dd 0
vm_profile_live_mmio:    dd 0
vm_profile_live_leaves:  dd 0
align 8
vp_sha_ctx:              times 112 db 0 ; S256_CTX_SZ
vp_sha_out:              times 32 db 0
%endmacro
WDATA_DEFER WDATA_hv_vm_profile_0

str_vp_cmdline_pin: db " virtio_mmio.device=4K@0xD0000000:5 paos.pin=1", 0
str_vp_cmdline_warm: db " virtio_mmio.device=4K@0xD0000000:5 paos.warm=1", 0

str_vp_cmdline_filesystem: db " virtio_mmio.device=4K@0xD0006000:5 virtio_mmio.device=4K@0xD0007000:5",0

str_vp_cmdline_wifi: db " virtio_mmio.device=4K@0xD0008000:5 paos.wifi=1",0
str_vp_cmdline_power: db " virtio_mmio.device=4K@0xD0009000:5",0 ; C10b-1a: driver-domain closure only
