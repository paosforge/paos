;; MODULE svc/command_compat
;; LAYER 5
;; EXPORTS command_compat_init, cmd_verb_compat, compat_out_ready, compat_out_buf, str_verb_compat
;; IMPORTS boot/serial, boot/gop, bus/pci, fs/blockdev, dev/usb/xhci, hv/vmx, hv/svm, core/lib/fmt, core/lib/str, lib/safe_buffer, svc/command, svc/command_auth, svc/hw_report
;; CAPS
;; OWNER saga:usb_stack
; U7-ENUM: public, read-only native inventory. No firmware calls, rescans,
; device transfers or virtualization enable. Counts describe retained registries;
; zero is absence, unknown Secure Boot stays unknown, invalid bounds are errors.
; Wire: COMPAT nonce=<1..64 alnum/._-> cpu_vendor=intel|amd|unknown
;       virt=vmx|svm|none pci=N secureboot=on|off|unknown gop_modes=N
;       blocks=N xhci=present|absent input=degraded_until_usb_hid
; RCQ-29 hardware report, same verb, no new registry row:
;   COMPAT <nonce> HW [summary|cpu|gpu|nic|storage|usb|input|battery|system|memory]
;   -> COMPAT nonce=<nonce> hw=<class> ... (svc/hw_report; remote requests need
;   their own verified owner envelope; plain COMPAT remains public)

COMPAT_NONCE_MAX equ 64
COMPAT_OUT_CAP   equ 384
COMPAT_HW_CAP    equ 1024             ; the HW sub-form's record (UDP payload is 1408)
; Snapshot layout: vendor:u32, virt:u32, pci:u64, gop:u32, blocks:u32,
;                  secureboot:u32, xhci:u32. IDs: unknown/none=0, intel/vmx=1,
;                  amd/svm=2. This local record owns no subsystem state.

command_compat_init:
    sub  rsp, 40
    lea  rdi, [rel str_verb_compat]
    lea  rsi, [rel cmd_verb_compat]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    xor  r9d, r9d
    call command_register_verb
    call hv_svm_detect_kat
    call compat_report_kat
    ; Live CPUID witness for the independently selected QEMU CPU profiles.
    mov  rdi, rsp
    call compat_snapshot
    call compat_out_reset
    lea  rdi, [rel str_compat_cpu]
    call compat_puts
    mov  edi, [rsp]
    call compat_vendor_string
    call compat_puts
    lea  rdi, [rel str_compat_virt]
    call compat_puts
    mov  edi, [rsp + 4]
    call compat_virt_string
    call compat_puts
    lea  rdi, [rel compat_out_buf]
    call serial_string
    call serial_newline
    call compat_out_reset
    mov  byte [rel compat_out_ready], 0
    add  rsp, 40
    ret

cmd_verb_compat:
    call cmd_handler_prologue
    push rbx
    push r12
    sub  rsp, 40
    mov  rbx, rsi
    mov  r12, [rdi + REQ_ARG]
    mov  byte [rel compat_out_ready], 0
    mov  rdi, r12
    call compat_hw_split                  ; EAX -1 plain / HW class / -2 bad form / -3 bad class
    cmp  eax, -1
    je   .plain
    cmp  eax, -2
    je   .bad_nonce
    cmp  eax, -3
    je   .bad_hw_class
    push rax
    sub  rsp, 8
    ; The HW sub-form is a hardware fingerprint (IDs, drivers, CPU, display): a
    ; remote request needs an owner envelope (AUTH2 VALID/CONSUMED or unrestricted
    ; SSH owner).  Local/in-image callers pass; plain COMPAT stays public.
    cmp  byte [rel command_auth_remote_active], 1
    jne  .hw_owner_ok
    call command_auth_owner_envelope
    test eax, eax
    jnz  .hw_owner_ok
    add  rsp, 16
    lea  r12, [rel str_compat_owner_required]
    jmp  .refuse
.hw_owner_ok:
    lea  rdi, [rel compat_hw_nonce]
    call compat_nonce_valid
    add  rsp, 8
    pop  rdi                              ; EDI = class
    test eax, eax
    jz   .bad_nonce
    call compat_hw_render
    test eax, eax
    jnz  .bad_hw
    mov  qword [rbx + RSP_CODE], CMDE_OK
    mov  qword [rbx + RSP_ACCEPTED], 1
    jmp  .publish
.bad_hw:
    lea  r12, [rel str_compat_bad_hw]
    jmp  .refuse
.bad_hw_class:
    lea  r12, [rel str_compat_bad_hw_class]
    jmp  .refuse
.plain:
    mov  rdi, r12
    call compat_nonce_valid
    test eax, eax
    jz   .bad_nonce
    mov  rdi, rsp
    call compat_snapshot
    mov  rdi, rsp
    mov  rsi, r12
    call compat_render
    test eax, eax
    jnz  .bad_snapshot
    mov  qword [rbx + RSP_CODE], CMDE_OK
    mov  qword [rbx + RSP_ACCEPTED], 1
    jmp  .publish
.bad_nonce:
    lea  r12, [rel str_compat_bad_nonce]
    jmp  .refuse
.bad_snapshot:
    lea  r12, [rel str_compat_bad_snapshot]
.refuse:
    call compat_out_reset                 ; never publish partial success fields
    mov  rdi, r12
    call compat_puts
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    mov  [rbx + RSP_HINT], r12
.publish:
    mov  byte [rel compat_out_ready], 1
    mov  rax, [rbx + RSP_CODE]
    add  rsp, 40
    pop  r12
    pop  rbx
    ret

; compat_hw_split(RDI = argument) -> EAX = -1 when the argument holds no space
;   (plain COMPAT), the HW_C_* class for "<nonce> HW [class]" (no class =
;   summary), -3 for "<nonce> HW <anything but one class name>", or -2 for
;   anything else (the plain grammar's bad nonce).  The nonce token is copied to
;   compat_hw_nonce (NUL-terminated); the caller validates it.
compat_hw_split:
    test rdi, rdi
    jz   .plain
    xor  ecx, ecx
.tok:
    movzx eax, byte [rdi + rcx]
    test al, al
    jz   .plain
    cmp  al, ' '
    je   .space
    cmp  ecx, COMPAT_NONCE_MAX
    jae  .bad
    lea  rdx, [rel compat_hw_nonce]
    mov  [rdx + rcx], al
    inc  ecx
    jmp  .tok
.space:
    lea  rdx, [rel compat_hw_nonce]
    mov  byte [rdx + rcx], 0
    lea  rsi, [rdi + rcx + 1]
    movzx eax, byte [rsi]                 ; exactly "HW", case-insensitive
    or   al, 0x20
    cmp  al, 'h'
    jne  .bad
    movzx eax, byte [rsi + 1]
    or   al, 0x20
    cmp  al, 'w'
    jne  .bad
    movzx eax, byte [rsi + 2]
    test al, al
    jz   .summary
    cmp  al, ' '
    jne  .bad
    lea  rdi, [rsi + 3]
    call hw_report_class_id               ; one more token, exactly a class name
    cmp  eax, -1
    je   .bad_class
    ret
.bad_class:
    mov  eax, -3
    ret
.summary:
    xor  eax, eax                         ; HW_C_SUMMARY
    ret
.plain:
    mov  eax, -1
    ret
.bad:
    mov  eax, -2
    ret

; compat_hw_render(EDI = HW_C_*) -> EAX 0 record staged in compat_out_buf / 1 refused.
compat_hw_render:
    push rbx
    mov  ebx, edi
    call compat_out_reset
    lea  rdi, [rel compat_hw_nonce]
    call compat_nonce_valid
    test eax, eax
    jz   .bad
    lea  rdi, [rel str_compat_head]
    call compat_puts
    lea  rdi, [rel compat_hw_nonce]
    call compat_puts
    cmp  byte [rel compat_out_failed], 0
    jne  .bad
    mov  edi, ebx
    mov  eax, [rel compat_out_len]
    lea  rsi, [rel compat_out_buf]
    add  rsi, rax
    mov  edx, COMPAT_HW_CAP
    sub  edx, eax
    call hw_report_render
    test eax, eax
    jnz  .bad
    xor  eax, eax
    pop  rbx
    ret
.bad:
    call compat_out_reset                 ; never publish partial success fields
    mov  eax, 1
    pop  rbx
    ret

; Snapshot only shipped state. blk_registered_count owns its registry lock;
; other fields are retained boot snapshots. CPUID is safe on every x86-64 CPU.
compat_snapshot:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rdi
    mov  dword [r12], 0
    mov  dword [r12 + 4], 0
    xor  eax, eax
    cpuid
    cmp  ebx, 'Genu'
    jne  .amd
    cmp  edx, 'ineI'
    jne  .cpu_done
    cmp  ecx, 'ntel'
    jne  .cpu_done
    mov  dword [r12], 1
    cmp  eax, 1
    jb   .cpu_done
    call hv_vmx_detect
    mov  [r12 + 4], eax
    jmp  .cpu_done
.amd:
    cmp  ebx, 'Auth'
    jne  .cpu_done
    cmp  edx, 'enti'
    jne  .cpu_done
    cmp  ecx, 'cAMD'
    jne  .cpu_done
    mov  dword [r12], 2
    call hv_svm_detect
    add  eax, eax
    mov  [r12 + 4], eax
.cpu_done:
    mov  rax, [rel pci_dev_count]
    mov  [r12 + 8], rax
    mov  eax, [rel gop_mode_count]
    mov  [r12 + 16], eax
    call blk_registered_count
    mov  [r12 + 20], eax
    movzx eax, byte [rel pbm_sb_secureboot]
    mov  [r12 + 24], eax
    mov  eax, [rel xhci_found]
    mov  [r12 + 28], eax
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; Required nonce. Scan at most 65 readable bytes including NUL; reject whitespace,
; controls, separators and overlong input before any hardware observation.
compat_nonce_valid:
    xor  ecx, ecx
    test rdi, rdi
    jz   .bad
.byte:
    movzx eax, byte [rdi + rcx]
    test al, al
    jz   .end
    cmp  ecx, COMPAT_NONCE_MAX
    jae  .bad
    cmp  al, '.'
    je   .next
    cmp  al, '_'
    je   .next
    cmp  al, '-'
    je   .next
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    jbe  .next
    or   al, 0x20
    cmp  al, 'a'
    jb   .bad
    cmp  al, 'z'
    ja   .bad
.next:
    inc  ecx
    jmp  .byte
.end:
    test ecx, ecx
    setnz al
    movzx eax, al
    ret
.bad:
    xor  eax, eax
    ret

; RDI=snapshot, RSI=nonce -> EAX=0 complete record / 1 invalid.
; Bounds are registry bounds, not formatter truncation. No clamping into success.
compat_render:
    push rbx
    push r12
    sub  rsp, 8
    mov  rbx, rdi
    mov  r12, rsi
    call compat_out_reset
    mov  rdi, r12
    call compat_nonce_valid
    test eax, eax
    jz   .bad
    cmp  dword [rbx], 2
    ja   .bad
    mov  eax, [rbx + 4]
    test eax, eax
    jz   .counts
    cmp  eax, [rbx]                       ; vmx requires Intel; svm requires AMD
    jne  .bad
.counts:
    cmp  qword [rbx + 8], 65536           ; 256 buses * 32 devices * 8 functions
    ja   .bad
    cmp  dword [rbx + 16], 64             ; captured GOP list capacity
    ja   .bad
    cmp  dword [rbx + 20], 64             ; block core registry limit
    ja   .bad
    cmp  dword [rbx + 28], 1
    ja   .bad
    mov  eax, [rbx + 24]
    cmp  eax, 0xFF                       ; unread/failed pre-EBS snapshot
    je   .fields
    cmp  eax, 1
    ja   .bad
.fields:
    lea  rdi, [rel str_compat_head]
    call compat_puts
    mov  rdi, r12
    call compat_puts
    lea  rdi, [rel str_compat_vendor]
    call compat_puts
    mov  edi, [rbx]
    call compat_vendor_string
    call compat_puts
    lea  rdi, [rel str_compat_virt]
    call compat_puts
    mov  edi, [rbx + 4]
    call compat_virt_string
    call compat_puts
    lea  rdi, [rel str_compat_pci]
    call compat_puts
    mov  rdi, [rbx + 8]
    call compat_putdec
    lea  rdi, [rel str_compat_sb]
    call compat_puts
    lea  rdi, [rel str_compat_unknown]
    cmp  dword [rbx + 24], 0xFF
    je   .sb
    lea  rdi, [rel str_compat_off]
    cmp  dword [rbx + 24], 0
    je   .sb
    lea  rdi, [rel str_compat_on]
.sb:
    call compat_puts
    lea  rdi, [rel str_compat_gop]
    call compat_puts
    mov  edi, [rbx + 16]
    call compat_putdec
    lea  rdi, [rel str_compat_blocks]
    call compat_puts
    mov  edi, [rbx + 20]
    call compat_putdec
    lea  rdi, [rel str_compat_xhci]
    call compat_puts
    lea  rdi, [rel str_compat_absent]
    cmp  dword [rbx + 28], 0
    je   .xhci
    lea  rdi, [rel str_compat_present]
.xhci:
    call compat_puts
    lea  rdi, [rel str_compat_input]
    call compat_puts
    movzx eax, byte [rel compat_out_failed]
    jmp  .out
.bad:
    mov  eax, 1
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

compat_vendor_string:
    lea  rax, [rel str_compat_unknown]
    cmp  edi, 1
    jne  .amd
    lea  rax, [rel str_compat_intel]
.amd:
    cmp  edi, 2
    jne  .out
    lea  rax, [rel str_compat_amd]
.out:
    mov  rdi, rax
    ret

compat_virt_string:
    lea  rax, [rel str_compat_none]
    cmp  edi, 1
    jne  .svm
    lea  rax, [rel str_compat_vmx]
.svm:
    cmp  edi, 2
    jne  .out
    lea  rax, [rel str_compat_svm]
.out:
    mov  rdi, rax
    ret

; Bounded append pattern from command_srvstat, using the shared safe primitives.
compat_out_reset:
    mov  dword [rel compat_out_len], 0
    mov  byte [rel compat_out_failed], 0
    mov  byte [rel compat_out_buf], 0
    ret
compat_puts:
    push rbx
    cmp  byte [rel compat_out_failed], 0
    jne  .out
    mov  rbx, rdi
    mov  esi, COMPAT_OUT_CAP
    call safe_capped_len
    test edx, edx
    jnz  .bad
    mov  rcx, rax
    mov  rdx, rbx
    mov  eax, [rel compat_out_len]
    cmp  eax, COMPAT_OUT_CAP
    jae  .bad
    lea  rdi, [rel compat_out_buf]
    add  rdi, rax
    mov  esi, COMPAT_OUT_CAP
    sub  esi, eax
    cmp  rcx, rsi
    jae  .bad
    call safe_copy
    test eax, eax
    jnz  .bad
    add  [rel compat_out_len], edx
    jmp  .out
.bad:
    mov  byte [rel compat_out_failed], 1
.out:
    pop  rbx
    ret
compat_putdec:
    sub  rsp, 8
    lea  rsi, [rel compat_number]
    call fmt_dec
    lea  rdi, [rel compat_number]
    call compat_puts
    add  rsp, 8
    ret

; The production renderer is checked byte-for-byte, including zero/unknown
; subsystems and the exact deliberately degraded input field. Local fixtures
; never replace a live registry or a CPUID result.
compat_report_kat:
    push rbx
    sub  rsp, 32
    lea  rdi, [rel str_verb_compat]
    call command_lookup
    cmp  eax, -1
    je   .fail                            ; a full registry cannot earn the marker
    lea  rdi, [rel compat_kat_full]
    lea  rsi, [rel str_compat_kat_nonce]
    call compat_render
    test eax, eax
    jnz  .fail
    lea  rdi, [rel compat_out_buf]
    lea  rsi, [rel str_compat_kat_full]
    call strcmp
    test eax, eax
    jnz  .fail
    lea  rdi, [rel compat_kat_empty]
    lea  rsi, [rel str_compat_kat_nonce]
    call compat_render
    test eax, eax
    jnz  .fail
    lea  rdi, [rel compat_out_buf]
    lea  rsi, [rel str_compat_kat_empty]
    call strcmp
    test eax, eax
    jnz  .fail
    ; Each corrupted count/enum must fail, not wrap or clamp into a valid field.
    xor  ebx, ebx
.invalid_field:
    mov  qword [rsp], 0
    mov  qword [rsp + 8], 0
    mov  qword [rsp + 16], 0
    mov  qword [rsp + 24], 0
    lea  rax, [rsp]
    mov  dword [rax + rbx*4], -1
    mov  rdi, rsp
    lea  rsi, [rel str_compat_kat_nonce]
    call compat_render
    test eax, eax
    jz   .fail
    inc  ebx
    cmp  ebx, 8
    jb   .invalid_field
    lea  rdi, [rel str_compat_nonce_max]
    call compat_nonce_valid
    cmp  eax, 1
    jne  .fail
    lea  rdi, [rel str_compat_nonce_long]
    call compat_nonce_valid
    test eax, eax
    jnz  .fail
    lea  rdi, [rel str_compat_nonce_inject]
    call compat_nonce_valid
    test eax, eax
    jnz  .fail
    xor  edi, edi
    call compat_nonce_valid
    test eax, eax
    jnz  .fail
    lea  rdi, [rel str_compat_nonce_max + COMPAT_NONCE_MAX]
    call compat_nonce_valid
    test eax, eax
    jnz  .fail
    call compat_out_reset
    mov  dword [rel compat_out_len], COMPAT_OUT_CAP - 1
    lea  rdi, [rel str_compat_kat_nonce]
    call compat_puts
    cmp  byte [rel compat_out_failed], 1
    jne  .fail
    ; Public exact name, with metadata still able to strengthen authorization.
    lea  rdi, [rel str_verb_compat]
    xor  esi, esi
    xor  edx, edx
    call command_auth_required_cap
    test rax, rax
    jnz  .fail
    lea  rdi, [rel str_compat_alias]
    xor  esi, esi
    xor  edx, edx
    call command_auth_required_cap
    test rax, rax
    jz   .fail
    lea  rdi, [rel str_verb_compat]
    xor  esi, esi
    mov  edx, 1
    call command_auth_required_cap
    test rax, rax
    jz   .fail
    lea  rdi, [rel str_verb_compat]
    mov  esi, 1
    xor  edx, edx
    call command_auth_required_cap
    cmp  rax, 1
    jne  .fail
    lea  rdi, [rel str_compat_kat_pass]
    jmp  .emit
.fail:
    lea  rdi, [rel str_compat_kat_fail]
.emit:
    call serial_string
    call compat_out_reset
    add  rsp, 32
    pop  rbx
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_svc_command_compat_0 0
times 33 db 0                  ; compat_out_ready..compat_hw_nonce moved to WDATA_svc_command_compat_0_bss1: keeps the labels below at their offset mod 64
str_verb_compat: db "COMPAT",0
str_compat_alias: db "COMPATX",0
str_compat_head: db "COMPAT nonce=",0
str_compat_cpu: db "COMPATCPU cpu_vendor=",0
str_compat_vendor: db " cpu_vendor=",0
str_compat_virt: db " virt=",0
str_compat_pci: db " pci=",0
str_compat_sb: db " secureboot=",0
str_compat_gop: db " gop_modes=",0
str_compat_blocks: db " blocks=",0
str_compat_xhci: db " xhci=",0
str_compat_input: db " input=degraded_until_usb_hid",0
str_compat_intel: db "intel",0
str_compat_amd: db "amd",0
str_compat_unknown: db "unknown",0
str_compat_vmx: db "vmx",0
str_compat_svm: db "svm",0
str_compat_none: db "none",0
str_compat_on: db "on",0
str_compat_off: db "off",0
str_compat_present: db "present",0
str_compat_absent: db "absent",0
str_compat_bad_nonce: db "COMPAT ERR reason=bad_nonce",0
str_compat_bad_hw: db "COMPAT ERR reason=hw_unavailable",0   ; report busy or record too large
str_compat_bad_hw_class: db "COMPAT ERR reason=bad_hw_class",0
str_compat_owner_required: db "COMPAT ERR reason=owner_required",0   ; HW asked remotely without an owner envelope
str_compat_bad_snapshot: db "COMPAT ERR reason=invalid_snapshot_or_bounds",0
str_compat_kat_nonce: db "kat-29_08.A",0
str_compat_nonce_inject: db "a virt=svm",0
str_compat_nonce_max: times COMPAT_NONCE_MAX db 'a'
    db 0
str_compat_nonce_long: times COMPAT_NONCE_MAX + 1 db 'a'
    db 0
align 8
compat_kat_full: dd 1, 1
    dq 65536
    dd 64, 64, 1, 1
compat_kat_empty: dd 0, 0
    dq 0
    dd 0, 0, 0xFF, 0
str_compat_kat_full: db "COMPAT nonce=kat-29_08.A cpu_vendor=intel virt=vmx pci=65536 secureboot=on gop_modes=64 blocks=64 xhci=present input=degraded_until_usb_hid",0
str_compat_kat_empty: db "COMPAT nonce=kat-29_08.A cpu_vendor=unknown virt=none pci=0 secureboot=unknown gop_modes=0 blocks=0 xhci=absent input=degraded_until_usb_hid",0
str_compat_kat_pass: db "[PAOS64] compat: bounded native enumeration report KAT PASS [compat.native.report.kat]",13,10,0
str_compat_kat_fail: db "[PAOS64] compat: bounded native enumeration report KAT FAIL",13,10,0
%endmacro
WDATA_DEFER WDATA_svc_command_compat_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_svc_command_compat_0_bss1 0
compat_out_ready: resb 1
compat_out_failed: resb 1
alignb 4
compat_out_len: resd 1
compat_number: resb 24
compat_out_buf: resb COMPAT_HW_CAP         ; plain COMPAT stays bounded by COMPAT_OUT_CAP
compat_hw_nonce: resb COMPAT_NONCE_MAX + 1
%endmacro
WDATA_BSS_DEFER WDATA_svc_command_compat_0_bss1
