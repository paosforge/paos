;; MODULE svc/hw_report
;; LAYER 5
;; EXPORTS hw_report_render, hw_report_class_id, hw_report_boot_log, hw_report_kat, hw_report_boot_ready
;; IMPORTS snd/core, snd/uac1_sound, snd/uac1_input_sound, dev/snd/hda_runtime, dev/snd/hda_loopback_native, usb/enum, dev/net/ax88179b, hv/hv_ops, hv/vtd, hv/amdvi, dev/blk/vmd, dev/blk/ahci, dev/blk/nvme, bus/pci, bus/pci_claim, core/smp, core/time, svc/governor, svc/thermal, core/lock, core/lib/fmt, core/memmap, boot/gop, boot/serial, boot/smbios, net/netdev, dev/input/ps2, dev/usb/hid, dev/usb/xhci, dev/blk/usb_msd, dev/net/ax88179, dev/net/cdc_ecm, dev/net/cdc_ncm, dev/power/ec_power, fs/blockdev, svc/idle_probe, core/mca_poll, core/mca_init, core/mca_control, core/mca_cmci, bus/acpi
;; CAPS
;; OWNER saga:live
;; LOCK: hw_lock PROTECTS hw_list, hw_list_n, hw_found, hw_driven, hw_over_driven, hw_scanned, hw_out_ptr, hw_out_len
; ============================================================================
; svc/hw_report.asm — RCQ-29 hardware report (WORKER_LIVE item 2): what this
; machine has and which PaOS driver took it, per class, read-only.
;
; Classes: summary cpu gpu nic storage usb input battery system memory mca,
; mcactl, mcaaux, drivers and retained bindsys/bindvmd/bindusb/bindaud/bindreg/bindcpu.
; Every PCI function of a
; class is listed as BB:DD.F,VVVV:DDDD,CCSSPP,<driver>; the driver is the one that
; recorded a claim for exactly that function (bus/pci_claim), "none" when no
; driver did, with ",unusable" when a driver matched it and could not use it.
; Nothing is inferred from a class code or a vendor list.
;
; Read-only: one CF8/CFC config sweep per boot (class dwords), CPUID, and
; retained driver state.  Device lists are that boot sweep; claims are re-read
; per render but record bind time, so a driver that dies later still shows
; bound (the summary says snapshot=boot). No device transfer, link probe, firmware call or write.
; Remote HW reads require an owner envelope: IDs and CPU/display facts can fingerprint a machine.
; Content includes IDs, driver names, counts and presence; never a disk or
; EDID serial, a MAC address or a battery level.
;
; hw_report_render(EDI=class, RSI=buf, EDX=cap) -> EAX 0 complete / 1 does not
;   fit (buf holds "" then) / 2 busy / 3 bad class.  The text starts with a space
;   (" hw=<class> ...") so a caller can append it to its own reply head.
; ============================================================================

%include "core/abi/mca_poll.inc"
%include "core/abi/mca_bank.inc"
%include "core/abi/mca_enable.inc"

%macro MCA_Q_FIELD 3
    dd %1-$
    db %2,%3,0,0
%endmacro

HW_C_SUMMARY  equ 0
HW_C_CPU      equ 1
HW_C_GPU      equ 2
HW_C_NIC      equ 3
HW_C_STORAGE  equ 4
HW_C_USB      equ 5
HW_C_INPUT    equ 6
HW_C_BATTERY  equ 7
HW_C_SYSTEM   equ 8
HW_C_MEMORY   equ 9
HW_C_MCA      equ 10
HW_C_MCACTL   equ 11
HW_C_MCAAUX   equ 12
HW_C_MCARTE   equ 13
HW_C_MCALOG   equ 14
HW_C_AERQ     equ 15
HW_C_MCGCTL   equ 16
HW_C_DRIVERS  equ 17
HW_C_BINDSYS  equ 18
HW_C_BINDVMD  equ 19
HW_C_BINDUSB  equ 20
HW_C_BINDAUD  equ 21
HW_C_BINDREG  equ 22
HW_C_BINDCPU equ 23
HW_C_DRVOPS   equ 24
HW_C_COUNT    equ 25
HW_C_MCAQ     equ 0x100
HW_C_MCAB     equ 0x200
HW_C_MCAW     equ 0x300
HW_C_SERIALIO equ 10           ; independent scan-only bucket: Intel Serial IO (0C80), shown under input
HW_BUCKETS    equ 11

HW_DEV_MAX    equ 16          ; devices listed per class; the rest are counted (more=)
HW_LIST_MAX   equ 48          ; reported functions kept from one sweep (all classes)
HW_DEV_ENT    equ 16          ; +0 bdf, +4 vendev, +8 class dword, +12 dw driver id,
                              ; +14 db claim state, +15 db bucket
HW_LOG_CAP    equ 1024
HW_TOKEN_MAX  equ 15          ; registry name bytes kept per token (NETCFG MEMBERS' cap)

; hw_report_class_id(RDI = NUL-terminated name) -> EAX = HW_C_* / -1.  Case-insensitive.
hw_report_class_id:
    push rbx
    push r12
    mov  r12, rdi
    xor  ebx, ebx
.next:
    cmp  ebx, HW_C_COUNT
    jae  .none
    lea  rsi, [rel hw_class_names]
    imul eax, ebx, 8
    add  rsi, rax
    mov  rdi, r12
    xor  ecx, ecx
.cmp:
    movzx eax, byte [rdi + rcx]
    movzx edx, byte [rsi + rcx]
    cmp  al, 'A'
    jb   .lower
    cmp  al, 'Z'
    ja   .lower
    or   al, 0x20
.lower:
    cmp  eax, edx
    jne  .miss
    test eax, eax
    jz   .hit
    inc  ecx
    cmp  ecx, 8
    jb   .cmp
.miss:
    inc  ebx
    jmp  .next
.hit:
    mov  eax, ebx
    jmp  .out
.none:
    ; Exact mcabCCP: CPU00..1f, page0..3, eight retained banks/page.
    mov eax,[r12]
    or eax,0x20202020
    mov edx,HW_C_MCAB
    cmp eax,'mcab'
    je .b_name
    mov edx,HW_C_MCAW
    cmp eax,'mcaw'
    jne .try_q
.b_name:
    cmp byte [r12+7],0
    jne .bad_q
    xor ebx,ebx
    mov ecx,4
.b_digit:
    movzx eax,byte [r12+rcx]
    sub eax,'0'
    cmp eax,9
    jbe .b_add
    movzx eax,byte [r12+rcx]
    or eax,32
    sub eax,'a'
    cmp eax,5
    ja .bad_q
    add eax,10
.b_add:
    shl ebx,4
    or ebx,eax
    inc ecx
    cmp ecx,6
    jb .b_digit
    cmp ebx,MCA_POLL_CPUS
    jae .bad_q
    movzx eax,byte [r12+6]
    sub eax,'0'
    cmp eax,3
    ja .bad_q
    lea eax,[rax+rbx*4]
    add eax,edx
    jmp .out
.try_q:
    ; Exact six-character mcaqXX CPU-view selectors; no unchecked suffix.
    mov eax,[r12]
    or eax,0x20202020
    cmp eax,'mcaq'
    jne .bad_q
    cmp byte [r12+6],0
    jne .bad_q
    xor ebx,ebx
    mov ecx,4
.q_digit:
    movzx eax,byte [r12+rcx]
    sub eax,'0'
    cmp eax,9
    jbe .q_add
    movzx eax,byte [r12+rcx]
    or eax,32
    sub eax,'a'
    cmp eax,5
    ja .bad_q
    add eax,10
.q_add:
    shl ebx,4
    or ebx,eax
    inc ecx
    cmp ecx,6
    jb .q_digit
    cmp ebx,MCA_POLL_CPUS
    jae .bad_q
    lea eax,[rbx+HW_C_MCAQ]
    jmp .out
.bad_q:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

hw_report_render:
    push rbx
    push r12
    push r13
    sub  rsp, 8
    mov  ebx, edi
    mov  r12, rsi
    mov  r13d, edx
    mov  eax, 3
    cmp  ebx, HW_C_COUNT
    jb .valid_class
    cmp ebx,HW_C_MCAW
    jae .w_extent
    cmp ebx,HW_C_MCAB
    jb .q_extent
    lea eax,[rbx-HW_C_MCAB]
    cmp eax,128
    mov eax,3
    jae .ret
    jmp .valid_class
.w_extent:
    lea eax,[rbx-HW_C_MCAW]
    cmp eax,128
    mov eax,3
    jae .ret
    jmp .valid_class
.q_extent:
    lea eax,[rbx-HW_C_MCAQ]
    cmp eax,MCA_POLL_CPUS
    mov eax,3
    jae .ret
.valid_class:
    lea  rdi, [rel hw_lock]
    call spin_try_acquire
    test eax, eax
    jnz  .locked
    mov  eax, 2
    jmp  .ret
.locked:
    mov  [rel hw_out_ptr], r12
    mov  [rel hw_out_cap], r13d
    mov  dword [rel hw_out_len], 0
    mov  byte [rel hw_out_failed], 0
    test r13d, r13d
    jz   .overflow
    mov  byte [r12], 0
    cmp  byte [rel hw_scanned], 1         ; one config sweep per boot; renders reuse it
    je   .scanned
    call hw_scan
    mov  byte [rel hw_scanned], 1
.scanned:
    call hw_refresh_claims                ; claims are memory reads, re-taken per render
    lea  rdi, [rel str_hw_head]
    call hw_puts
    cmp ebx,HW_C_MCAQ
    jb .static_class
    cmp ebx,HW_C_MCAW
    jae .write_class
    cmp ebx,HW_C_MCAB
    jae .bank_class
    sub ebx,HW_C_MCAQ
    call hw_r_mcaq
    jmp .rendered
.bank_class:
    sub ebx,HW_C_MCAB
    call hw_r_mcab
    jmp .rendered
.write_class:
    sub ebx,HW_C_MCAW
    call hw_r_mcaw
    jmp .rendered
.static_class:
    lea  rdi, [rel hw_class_names]
    lea  rdi, [rdi + rbx*8]
    call hw_puts
    lea  rax, [rel hw_render_table]
    movsxd rcx, dword [rax + rbx*4]
    add  rax, rcx
    call rax
.rendered:
    cmp  byte [rel hw_out_failed], 0
    jne  .overflow
    xor  ebx, ebx
    jmp  .unlock
.overflow:
    test r13d, r13d
    jz   .ovf_mark
    mov  byte [r12], 0
.ovf_mark:
    mov  ebx, 1
.unlock:
    lea  rdi, [rel hw_lock]
    call spin_release
    mov  eax, ebx
.ret:
    add  rsp, 8
    pop  r13
    pop  r12
    pop  rbx
    ret

; Position-independent dispatch (no absolute pointers in data: the image relocates).
hw_render_table:
    dd hw_r_summary - hw_render_table
    dd hw_r_cpu - hw_render_table
    dd hw_r_gpu - hw_render_table
    dd hw_r_nic - hw_render_table
    dd hw_r_storage - hw_render_table
    dd hw_r_usb - hw_render_table
    dd hw_r_input - hw_render_table
    dd hw_r_battery - hw_render_table
    dd hw_r_system - hw_render_table
    dd hw_r_memory - hw_render_table
    dd hw_r_mca - hw_render_table
    dd hw_r_mcactl - hw_render_table
    dd hw_r_mcaaux - hw_render_table
    dd hw_r_mcarte - hw_render_table
    dd hw_r_mcalog - hw_render_table
    dd hw_r_aerq - hw_render_table
    dd hw_r_mcgctl - hw_render_table
    dd hw_r_drivers - hw_render_table
    dd hw_r_bindsys - hw_render_table
    dd hw_r_bindvmd - hw_render_table
    dd hw_r_bindusb - hw_render_table
    dd hw_r_bindaud - hw_render_table
    dd hw_r_bindreg - hw_render_table
    dd hw_r_bindcpu - hw_render_table
    dd hw_r_drvops - hw_render_table

%include "svc/hw_driver_census.inc"
%include "svc/hw_backend_census.inc"
%include "svc/hw_usb_census.inc"
%include "svc/hw_audio_census.inc"
%include "svc/hw_registry_census.inc"
%include "svc/hw_core_census.inc"
%include "svc/hw_driver_members.inc"

; ---------------------------------------------------------------------------
; The PCI sweep: per bucket found counts, and every reported function (bucket
; tagged) up to HW_LIST_MAX.  hw_put_list picks one bucket.  It runs once per
; boot (hw_scanned): topology is static, there is no hotplug, and a CF8/CFC sweep
; per request would be a CPU lever on the command loop.  Functions past
; HW_LIST_MAX keep their sweep-time claim tally in hw_over_*.
; ---------------------------------------------------------------------------
hw_scan:
    lea  rdi, [rel hw_found]
    xor  eax, eax
    mov  ecx, (HW_BUCKETS * 3 * 4 + 7) / 8
.clr:
    mov  [rdi], rax
    add  rdi, 8
    dec  ecx
    jnz  .clr
    mov  dword [rel hw_list_n], 0
    mov  dword [rel hw_over_unclaimed], 0
    lea  rdi, [rel hw_scan_cb]
    call pci_scan_with_filter
    ret

; hw_refresh_claims: re-read every listed function's claim (bus/pci_claim, no
; config access) and recount hw_driven / hw_unclaimed from the list plus the
; sweep-time tally of the functions past HW_LIST_MAX.  Caller holds hw_lock.
hw_refresh_claims:
    push rbx
    push r12
    sub  rsp, 8
    lea  rsi, [rel hw_over_driven]
    lea  rdi, [rel hw_driven]
    mov  ecx, HW_BUCKETS
.copy:
    mov  eax, [rsi]
    mov  [rdi], eax
    add  rsi, 4
    add  rdi, 4
    dec  ecx
    jnz  .copy
    mov  eax, [rel hw_over_unclaimed]
    mov  [rel hw_unclaimed], eax
    xor  ebx, ebx
.ent:
    cmp  ebx, [rel hw_list_n]
    jae  .out
    mov  r12d, ebx
    shl  r12d, 4
    lea  rax, [rel hw_list]
    add  r12, rax
    mov  edi, [r12]
    call pci_claim_find                     ; EAX driver id (0 none), EDX state
    mov  [r12 + 12], ax
    mov  [r12 + 14], dl
    movzx ecx, byte [r12 + 15]
    test eax, eax
    jnz  .claimed
    inc  dword [rel hw_unclaimed]
    jmp  .next
.claimed:
    cmp  edx, PCI_CLAIM_BOUND
    jne  .next
    lea  rax, [rel hw_driven]
    inc  dword [rax + rcx*4]
.next:
    inc  ebx
    jmp  .ent
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; hw_bucket(EAX = class dword at config 08h) -> EAX = HW_C_* bucket / -1.
hw_bucket:
    mov  ecx, eax
    shr  ecx, 24                            ; base class
    mov  edx, eax
    shr  edx, 16
    and  edx, 0xFF                          ; subclass
    mov  eax, HW_C_STORAGE
    cmp  ecx, 0x01
    je   .out
    mov  eax, HW_C_NIC
    cmp  ecx, 0x02
    je   .out
    mov  eax, HW_C_GPU
    cmp  ecx, 0x03
    je   .out
    mov  eax, -1
    cmp  ecx, 0x0C
    jne  .out
    mov  eax, HW_C_USB
    cmp  edx, 0x03
    je   .out
    mov  eax, HW_C_SERIALIO
    cmp  edx, 0x80
    je   .out
    mov  eax, -1
.out:
    ret

; pci_scan_with_filter callback (EDI=bus, ESI=dev, EDX=fn, ECX=vendev).  Must
; keep RBX, RBP, R12-R15 (the sweep's loop state).
hw_scan_cb:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15d, ecx
    mov  ecx, 0x08
    call pci_cfg_read32                     ; class << 24 | sub << 16 | progif << 8 | rev
    mov  ebx, eax
    call hw_bucket
    cmp  eax, -1
    je   .out
    mov  r8d, eax                           ; bucket (pci_claim_find keeps none of R8)
    push r8
    mov  edi, r12d
    shl  edi, 8
    mov  eax, r13d
    shl  eax, 3
    or   edi, eax
    or   edi, r14d                          ; packed bdf
    push rdi
    call pci_claim_find                     ; EAX driver id (0 none), EDX state
    pop  rdi
    pop  r8
    lea  rcx, [rel hw_found]
    inc  dword [rcx + r8*4]
    mov  ecx, [rel hw_list_n]
    cmp  ecx, HW_LIST_MAX
    jae  .over                              ; still counted in hw_found: shown as more=
    shl  ecx, 4
    lea  r9, [rel hw_list]
    add  r9, rcx
    mov  [r9], edi
    mov  [r9 + 4], r15d
    mov  [r9 + 8], ebx
    mov  [r9 + 12], ax
    mov  [r9 + 14], dl
    mov  [r9 + 15], r8b
    inc  dword [rel hw_list_n]
    jmp  .out
.over:
    test eax, eax
    jnz  .over_claimed
    inc  dword [rel hw_over_unclaimed]
    jmp  .out
.over_claimed:
    cmp  edx, PCI_CLAIM_BOUND
    jne  .out
    lea  rcx, [rel hw_over_driven]
    inc  dword [rcx + r8*4]
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Class bodies.  Each appends to the open output through hw_put*.
; ---------------------------------------------------------------------------
hw_r_summary:
    push rbx
    sub  rsp, 32
    mov  rdi, rsp
    call idle_probe_cpu_ident
    lea  rdi, [rel str_hw_s_cpu]
    call hw_puts
    mov  edi, [rsp + 4]
    call hw_vendor_name
    call hw_puts
    lea  rdi, [rel str_hw_comma]
    call hw_puts
    mov  edi, [rsp + 8]
    call hw_put_hex2
    lea  rdi, [rel str_hw_comma]
    call hw_puts
    mov  edi, [rsp + 12]
    call hw_put_hex2
    lea  rdi, [rel str_hw_s_threads]
    call hw_puts
    mov  edi, [rel smp_topology_online]
    call hw_put_dec
    xor  ebx, ebx
.cls:
    lea  rdi, [rel str_hw_space]
    call hw_puts
    lea  rax, [rel hw_summary_classes]
    movzx eax, byte [rax + rbx]
    push rax
    sub  rsp, 8
    lea  rdi, [rel hw_class_names]
    lea  rdi, [rdi + rax*8]
    call hw_puts
    lea  rdi, [rel str_hw_eq]
    call hw_puts
    mov  rax, [rsp + 8]
    lea  rcx, [rel hw_found]
    mov  edi, [rcx + rax*4]
    call hw_put_dec
    lea  rdi, [rel str_hw_slash]
    call hw_puts
    mov  rax, [rsp + 8]
    lea  rcx, [rel hw_driven]
    mov  edi, [rcx + rax*4]
    call hw_put_dec
    add  rsp, 16
    inc  ebx
    cmp  ebx, 4
    jb   .cls
    lea  rdi, [rel str_hw_s_input]
    call hw_puts
    call hw_put_input_core
    lea  rdi, [rel str_hw_s_battery]
    call hw_puts
    call hw_battery_word
    call hw_puts
    lea  rdi, [rel str_hw_unclaimed]
    call hw_puts
    mov  edi, [rel hw_unclaimed]
    call hw_put_dec
    lea  rdi, [rel str_hw_snapshot]
    call hw_puts
    add  rsp, 32
    pop  rbx
    ret

; Retained sampler slots, not a CPU census or simultaneous snapshot. Each
; qualification byte is read once; qualified CAP is immutable after publication
; and each aligned count is an independent atomic read. Offline/unpolled slots
; remain unchecked. No CPUID/MSR/I/O, scan or state write in this renderer.
; Count aggregation may include shared banks on different CPUs. Saturation
; reports a lower bound; a zero software count makes no hardware health claim.
; mcg_banks retains MCG_CAP.COUNT per slot (two hex digits, -- if unqualified).
; cmci_cap/known are Intel MCG_CAP[10] capability/qualification masks, not
; MCi_CTL2 interrupt-enable readback. AMD SMCA retains its own qualification.
hw_r_mca:
    push rbx
    push r12
    push r13
    sub  rsp, 96
    mov  r13, rsp
    xor  eax, eax
    mov  ecx, 12
.clear:
    mov  [r13 + rcx*8 - 8], rax
    loop .clear
    lea  r12, [rel mca_poll_rows]
    xor  ebx, ebx
.slot:
    movzx eax, byte [r12 + MCA_POLL_QUAL]
    cmp  eax, 4
    jbe  .mask
    mov  eax, 5                       ; invalid retained qualification, unknown
.mask:
    bts  dword [r13 + rax*4], ebx     ; 0..5 classification masks
    cmp  eax, 1
    je   .qualified
    cmp  eax, 4
    jne  .next
.qualified:
    movzx ecx, byte [r12 + MCA_POLL_CAP]
    mov  [r13 + 64 + rbx], cl         ; raw COUNT, not the sampler's 32-bank cap
    cmp  eax, 1
    jne  .bank_count
    bts  dword [r13 + 48], ebx       ; only Intel qualifies CMCI capability
    bt   dword [r12 + MCA_POLL_CAP], 10
    jnc  .bank_count
    bts  dword [r13 + 44], ebx
.bank_count:
    cmp  byte [r12 + MCA_POLL_CAP], MCA_POLL_BANKS
    jbe  .count
    bts  dword [r13 + 24], ebx
.count:
    mov  rax, [r12 + MCA_POLL_COUNT]
    add  rax, [r13 + 32]
    jc   .saturated
    cmp  rax, -1
    jne  .sum
.saturated:
    mov  rax, -1
    mov  dword [r13 + 40], 1
.sum:
    mov  [r13 + 32], rax
.next:
    add  r12, MCA_POLL_STRIDE
    inc  ebx
    cmp  ebx, MCA_POLL_CPUS
    jb   .slot
    lea  rdi, [rel str_hw_mca_head]
    call hw_puts
    xor  ebx, ebx
.field:
    lea  rax, [rel hw_mca_fields]
    movsxd rdi, dword [rax + rbx*4]
    add  rdi, rax
    call hw_puts
    mov  edi, [r13 + rbx*4]
    mov  esi, 8
    call hw_put_hex
    inc  ebx
    cmp  ebx, 7
    jb   .field
    lea  rdi, [rel str_hw_mca_observations]
    call hw_puts
    mov  rdi, [r13 + 32]
    call hw_put_u64
    lea  rdi, [rel str_hw_mca_lower_bound]
    call hw_puts
    mov  edi, [r13 + 40]
    call hw_put_dec
    lea  rdi, [rel str_hw_mca_banks]
    call hw_puts
    xor  ebx, ebx
.bank_field:
    test ebx, ebx
    jz   .bank_value
    lea  rdi, [rel str_hw_slash]
    call hw_puts
.bank_value:
    mov  eax, [r13 + 4]              ; the qualification read made above
    or   eax, [r13 + 16]
    bt   eax, ebx
    jnc  .bank_unknown
    movzx edi, byte [r13 + 64 + rbx]
    mov  esi, 2
    call hw_put_hex
    jmp  .bank_next
.bank_unknown:
    lea  rdi, [rel str_hw_mca_bank_unknown]
    call hw_puts
.bank_next:
    inc  ebx
    cmp  ebx, MCA_POLL_CPUS
    jb   .bank_field
    lea  rdi, [rel str_hw_mca_cmci]
    call hw_puts
    mov  edi, [r13 + 44]
    mov  esi, 8
    call hw_put_hex
    lea  rdi, [rel str_hw_mca_cmci_known]
    call hw_puts
    mov  edi, [r13 + 48]
    mov  esi, 8
    call hw_put_hex
    lea  rdi, [rel str_hw_mca_scope]
    call hw_puts
    add  rsp, 96
    pop  r13
    pop  r12
    pop  rbx
    ret

hw_mca_fields:
    dd str_hw_mca_unchecked - hw_mca_fields
    dd str_hw_mca_intel - hw_mca_fields
    dd str_hw_mca_vendor - hw_mca_fields
    dd str_hw_mca_features - hw_mca_fields
    dd str_hw_mca_smca - hw_mca_fields
    dd str_hw_mca_invalid - hw_mca_fields
    dd str_hw_mca_clipped - hw_mca_fields
str_hw_mca_head: db " snapshot=retained slots=32", 0
str_hw_mca_unchecked: db " unchecked=", 0
str_hw_mca_intel: db " intel=", 0
str_hw_mca_vendor: db " vendor=", 0
str_hw_mca_features: db " features=", 0
str_hw_mca_smca: db " smca=", 0
str_hw_mca_invalid: db " invalid=", 0
str_hw_mca_clipped: db " bank_clipped=", 0
str_hw_mca_observations: db " observations=", 0
str_hw_mca_lower_bound: db " lower_bound=", 0
str_hw_mca_banks: db " mcg_banks=", 0
str_hw_mca_bank_unknown: db "--", 0
str_hw_mca_cmci: db " cmci_cap=", 0
str_hw_mca_cmci_known: db " cmci_known=", 0
str_hw_mca_scope: db " counts=sampled-software shared_banks=may-duplicate freshness=unknown physical=unknown physical_total=unknown irq=unknown containment=unknown", 0

 ; Stable per-CPU control copies. No cross-CPU atomicity or whole-machine extent.
hw_mca_controls_copy:
    sub rsp,MCA_B_COPY_BYTES+8
    xor r14d,r14d
    mov qword [rel hw_mcactl_masks],0
    mov qword [rel hw_mcactl_masks+8],0
.next:
    mov edi,r14d
    mov r15,r14
    shl r15,6
    lea rsi,[rel hw_mcactl_rows]
    add rsi,r15
    mov qword [rsi],0
    call mca_control_copy
    test eax,eax
    jnz .skip
    lea rax,[rel hw_mcactl_rows]
    add rax,r15
    bts dword [rel hw_mcactl_masks],r14d
    bt qword [rax+24],6
    jnc .global
    bts dword [rel hw_mcactl_masks+4],r14d
.global:
    bt qword [rax+16],8
    jnc .skip
    bts dword [rel hw_mcactl_masks+8],r14d
    ; Intel's global enable value is all ones (SDM Vol3, MCG_CTL).
    ; AMD SMCA has one gate per advertised bank; upper reserved bits need
    ; not read as ones (AMD APM Vol2 9.3.1.3; OSRR56255 MSR0000_017B).
    ; Use raw CAP.COUNT, never the first-32 scan bound. Empty or >64 cannot
    ; establish all bank gates in this 64-bit register. No MSR writes here.
    cmp dword [rax+8],4
    je .amd_global
    cmp dword [rax+8],1
    jne .skip
    cmp qword [rax+56],-1
    jne .skip
    jmp .global_all
.amd_global:
    ; OSRR56255 3.4/3.17.2: family17h/model00-2f bank4 is always RAZ/WRIG.
    ; Reuse the stable retained metadata, never infer absence from a zero CTL.
    ; A racing/unknown sample keeps the strict low-COUNT mask below.
    mov edi,r14d
    xor esi,esi
    mov rdx,rsp
    call mca_bank_copy
    mov r8d,eax
    lea rax,[rel hw_mcactl_rows]
    add rax,r15
    movzx ecx,byte [rax+16]
    test ecx,ecx
    jz .skip
    cmp ecx,64
    ja .skip
    mov rdx,-1
    je .amd_mask
    shl rdx,cl
    not rdx
.amd_mask:
    test r8d,r8d
    jnz .amd_compare
    cmp dword [rsp+68],2
    je .amd75
    cmp dword [rsp+64],0x00a70f52
    je .skip                            ; exact75h needs qualified local scope
    mov rcx,[rsp]
    cmp rcx,[rax]                       ; metadata and aggregate are same sample
    jne .amd_compare
    cmp dword [rsp+68],1                ; architecture rule, not a zero-read guess
    jne .amd_compare
    mov ecx,[rsp+64]
    and ecx,0x0ff00f00
    cmp ecx,0x00800f00
    jne .amd_compare
    mov ecx,[rsp+64]
    shr ecx,16
    and ecx,15
    cmp ecx,2
    ja .amd_compare
    btr rdx,4
    jmp .amd_compare
.amd75:
    ; PPR57019 rev3.00 pp120,286-298: COUNT includes RAZ/non-owned
    ; banks. Rule2 is exact75h only. The header masks describe ALL first32
    ; banks under the same aggregate sequence; no query-time MSR accesses.
    cmp dword [rsp+64],0x00a70f52
    jne .skip
    mov rcx,[rsp]
    cmp rcx,[rax]
    jne .skip
    movzx ecx,byte [rax+16]
    cmp ecx,7                           ; mandatory core gates0-3,5,6
    jb .skip
    cmp ecx,32
    ja .skip                            ; never qualify a clipped scope
    cmp ecx,[rax+12]
    jne .skip
    ; Tables32/33 mapped maximum, NOT an ownership mask. A populated
    ; candidate belongs here only after qualified IPID.HardwareID evidence.
    ; IPID invalid (including CONFIG.McaX=0) remains unresolved, even if
    ; raw MCG_CTL happens to contain ones. Never infer from its readback.
    and edx,0x127fffef
    mov ecx,[rsp+72]                     ; CTL read validity
    and ecx,edx
    cmp ecx,edx
    jne .skip
    mov ecx,[rsp+76]                     ; CONFIG read validity
    and ecx,edx
    cmp ecx,edx
    jne .skip
    mov ecx,[rsp+80]                     ; CONFIG.McaX-qualified IPID validity
    and ecx,edx
    cmp ecx,edx
    jne .skip
    mov ecx,[rsp+84]                     ; positive CPU-local bank views
    mov r8d,edx
    not r8d
    test ecx,r8d                        ; contradictory reserved/out-of-scope bank
    jnz .skip
    mov edx,ecx
    or edx,0x6f                         ; mandatory core gates independent of IPID
.amd_compare:
    mov rcx,[rax+56]
    and rcx,rdx
    cmp rcx,rdx
    jne .skip
.global_all:
    bts dword [rel hw_mcactl_masks+12],r14d
.skip:
    inc r14d
    cmp r14d,32
    jb .next
    add rsp,MCA_B_COPY_BYTES+8
    ret

; Raw companion to mcactl: the same stable per-CPU copy and predicate, with
; full MCG_CTL readback. CAP8 absent is unknown, not the internal zero used
; when RDMSR was deliberately skipped. Fits the existing 1024-byte reply.
hw_r_mcgctl:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call hw_mca_controls_copy
    lea rdi,[rel str_hw_mcactl_head]
    call hw_puts
    xor ebx,ebx
.masks:
    lea rax,[rel hw_mcactl_mask_names]
    movsxd rdi,dword [rax+rbx*4]
    add rdi,rax
    call hw_puts
    lea rax,[rel hw_mcactl_masks]
    mov edi,[rax+rbx*4]
    mov esi,8
    call hw_put_hex
    inc ebx
    cmp ebx,4
    jb .masks
    mov r13d,16
    lea rdi,[rel str_hw_mcactl_banks]
    call hw_puts
.array_start:
    xor r14d,r14d
.array:
    mov r15,r14
    shl r15,6
    lea r12,[rel hw_mcactl_rows]
    add r12,r15
    cmp qword [r12],0
    je .unknown
    cmp r13d,56
    jne .byte
    bt qword [r12+16],8
    jnc .unknown
    mov rbx,[r12+56]
    mov rdi,rbx
    shr rdi,32
    mov esi,8
    call hw_put_hex
    mov edi,ebx
    mov esi,8
    call hw_put_hex
    jmp .advance
.byte:
    movzx edi,byte [r12+r13]
    mov esi,2
    call hw_put_hex
    jmp .advance
.unknown:
    lea rdi,[rel str_hw_mca_bank_unknown]
    cmp r13d,56
    jne .put_unknown
    lea rdi,[rel str_hw_mcgctl_unknown]
.put_unknown:
    call hw_puts
.advance:
    inc r14d
    cmp r14d,32
    jae .next_array
    lea rdi,[rel str_hw_mcactl_slash]
    call hw_puts
    jmp .array
.next_array:
    cmp r13d,16
    jne .raw
    mov r13d,8
    lea rdi,[rel str_hw_mcgctl_layout]
    call hw_puts
    jmp .array_start
.raw:
    cmp r13d,8
    jne .done
    mov r13d,56
    lea rdi,[rel str_hw_mcgctl_raw]
    call hw_puts
    jmp .array_start
.done:
    lea rdi,[rel str_hw_mcab_advertise]
    call hw_puts
    lea rdi,[rel str_hw_mcactl_scope]
    call hw_puts
    jmp hw_mca_controls_done

hw_r_mcactl:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call hw_mca_controls_copy
    lea rdi,[rel str_hw_mcactl_head]
    call hw_puts
    xor ebx,ebx
.masks:
    lea rax,[rel hw_mcactl_mask_names]
    movsxd rdi,dword [rax+rbx*4]
    add rdi,rax
    call hw_puts
    lea rax,[rel hw_mcactl_masks]
    mov edi,[rax+rbx*4]
    mov esi,8
    call hw_put_hex
    inc ebx
    cmp ebx,4
    jb .masks
    lea rdi,[rel str_hw_mcactl_banks]
    call hw_puts
    xor r14d,r14d
.banks:
    mov r15,r14
    shl r15,6
    lea r12,[rel hw_mcactl_rows]
    add r12,r15
    cmp qword [r12],0
    je .unknown_bank
    mov edi,[r12+16]                   ; raw MCG_CAP.COUNT, not bounded scan count
    and edi,255
    mov esi,2
    call hw_put_hex
    jmp .bank_next
.unknown_bank:
    lea rdi,[rel str_hw_mca_bank_unknown]
    call hw_puts
.bank_next:
    inc r14d
    cmp r14d,32
    jae .arrays
    lea rdi,[rel str_hw_mcactl_slash]
    call hw_puts
    jmp .banks
.arrays:
    lea rdi,[rel str_hw_mcactl_all]
    call hw_puts
    mov r13d,32
    call hw_mca_controls_array
    lea rdi,[rel str_hw_mcactl_any]
    call hw_puts
    mov r13d,36
    call hw_mca_controls_array
    lea rdi,[rel str_hw_mcactl_scope]
    call hw_puts
    jmp hw_mca_controls_done

hw_r_mcaaux:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call hw_mca_controls_copy
    lea rdi,[rel str_hw_mcaaux_head]
    call hw_puts
    mov edi,[rel hw_mcactl_masks]
    mov esi,8
    call hw_put_hex
    lea rdi,[rel str_hw_mcaaux_present]
    call hw_puts
    mov r13d,40
    call hw_mca_controls_array
    lea rdi,[rel str_hw_mcaaux_enabled]
    call hw_puts
    mov r13d,44
    call hw_mca_controls_array
    lea rdi,[rel str_hw_mcaaux_scope]
    call hw_puts
hw_mca_controls_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; R13D=row field; AMD present is unknown on Intel. Intel CTL2 only with CAP10.
hw_mca_controls_array:
    sub rsp,8
    xor r14d,r14d
.next:
    mov r15,r14
    shl r15,6
    lea r12,[rel hw_mcactl_rows]
    add r12,r15
    cmp qword [r12],0
    je .unknown
    cmp r13d,40
    jb .known
    cmp dword [r12+8],4
    je .known
    cmp r13d,40
    je .unknown
    bt qword [r12+16],10
    jnc .unknown
.known:
    mov edi,[r12+r13]
    mov esi,8
    call hw_put_hex
    jmp .advance
.unknown:
    lea rdi,[rel str_hw_mcactl_unknown]
    call hw_puts
.advance:
    inc r14d
    cmp r14d,32
    jae .done
    lea rdi,[rel str_hw_mcactl_slash]
    call hw_puts
    jmp .next
.done:
    add rsp,8
    ret

; Stable CPU-private read census, never a simultaneous all-CPU snapshot.
; EBX=dense CPU. Copy refusal emits no partial/zero witness.
hw_r_mcaq:
    push rbx
    push r12
    push r13
    sub rsp,400
    mov [rsp+384],ebx
    mov edi,ebx
    mov rsi,rsp
    call mca_poll_coverage_copy
    test eax,eax
    jnz .busy
    lea rdi,[rel str_hw_mcaq]
    call hw_puts
    mov edi,ebx
    mov esi,2
    call hw_put_hex
    lea rdi,[rel str_hw_mcaq_cpu]
    call hw_puts
    mov edi,ebx
    mov esi,2
    call hw_put_hex
    lea r12,[rel hw_mcaq_fields]
    mov r13,rsp
.next:
    movsxd rdi,dword [r12]
    add rdi,r12
    call hw_puts
    movzx eax,byte [r12+4]
    movzx esi,byte [r12+5]
    mov rbx,[r13+rax]
    cmp esi,16
    jne .low
    mov rdi,rbx
    shr rdi,32
    mov esi,8
    call hw_put_hex
    mov esi,8
.low:
    mov edi,ebx
    call hw_put_hex
    add r12,8
    cmp byte [r12+5],0
    jne .next
    lea rdi,[rel str_hw_mcaq_scope]
    call hw_puts
    mov edi,[rsp+384]
    lea rsi,[rsp+64]
    call mca_boot_copy
    test eax,eax
    jnz .done                         ; old/incomplete init supplies no witness
    lea rdi,[rel str_hw_mca_boot]
    call hw_puts
    xor r12d,r12d
.boot:
    mov rbx,[rsp+64+r12*8]
    mov rdi,rbx
    shr rdi,32
    mov esi,8
    call hw_put_hex
    mov edi,ebx
    mov esi,8
    call hw_put_hex
    inc r12d
    cmp r12d,40
    jae .done
    lea rdi,[rel str_hw_mcactl_slash]
    call hw_puts
    jmp .boot
.busy:
    mov byte [rel hw_out_failed],1
.done:
    add rsp,400
    pop r13
    pop r12
    pop rbx
    ret

; Boot postwrite evidence, raw v1 32-qword page. Query only copies native RAM.
hw_r_mcaw:
    push rbx
    push r12
    push r13
    sub rsp,MCA_E_COPY_BYTES
    mov r12d,ebx
    mov edi,ebx
    shr edi,2
    mov esi,ebx
    and esi,3
    mov rdx,rsp
    call mca_enable_copy
    test eax,eax
    jnz .refuse
    lea rdi,[rel str_hw_mcaw]
    call hw_puts
    mov edi,r12d
    shr edi,2
    mov esi,2
    call hw_put_hex
    mov edi,r12d
    and edi,3
    mov esi,1
    call hw_put_hex
    lea rdi,[rel str_hw_mcab_cpu]
    call hw_puts
    mov edi,r12d
    shr edi,2
    mov esi,2
    call hw_put_hex
    lea rdi,[rel str_hw_mcaw_page]
    call hw_puts
    mov edi,r12d
    and edi,3
    mov esi,1
    call hw_put_hex
    lea rdi,[rel str_hw_mcaw_raw]
    call hw_puts
    xor r12d,r12d
.next:
    mov rbx,[rsp+r12*8]
    mov rdi,rbx
    shr rdi,32
    mov esi,8
    call hw_put_hex
    mov edi,ebx
    mov esi,8
    call hw_put_hex
    inc r12d
    cmp r12d,MCA_E_COPY_BYTES/8
    jae .done
    lea rdi,[rel str_hw_mcactl_slash]
    call hw_puts
    jmp .next
.refuse:
    mov byte [rel hw_out_failed],1
.done:
    add rsp,MCA_E_COPY_BYTES
    pop r13
    pop r12
    pop rbx
    ret
str_hw_mcaw: db 'mcaw',0
str_hw_mcaw_page: db ' page=',0
str_hw_mcaw_raw: db ' raw=',0

; CPU/page selector only. Copy retained scan data; never issues an MSR read.
; Local mask is positive architectural bank visibility, not interrupt ownership.
hw_r_mcab:
    push rbx
    push r12
    push r13
    sub rsp,MCA_B_COPY_BYTES
    mov r12d,ebx
    mov edi,ebx
    shr edi,2
    mov esi,ebx
    and esi,3
    mov rdx,rsp
    call mca_bank_copy
    test eax,eax
    jnz .refuse
    lea rdi,[rel str_hw_mcab]
    call hw_puts
    mov edi,r12d
    shr edi,2
    mov esi,2
    call hw_put_hex
    mov edi,r12d
    and edi,3
    mov esi,1
    call hw_put_hex
    lea rdi,[rel str_hw_mcab_cpu]
    call hw_puts
    mov edi,r12d
    shr edi,2
    mov esi,2
    call hw_put_hex
    lea r12,[rel hw_mcab_fields]
    mov r13,rsp
.field:
    movsxd rdi,dword [r12]
    add rdi,r12
    call hw_puts
    movzx eax,byte [r12+4]
    movzx esi,byte [r12+5]
    mov rbx,[r13+rax]
    cmp esi,16
    jne .low
    mov rdi,rbx
    shr rdi,32
    mov esi,8
    call hw_put_hex
    mov esi,8
.low:
    mov edi,ebx
    call hw_put_hex
    add r12,8
    cmp byte [r12+5],0
    jne .field
    xor r12d,r12d                       ; CTL/CONFIG/IPID field0..2
.array_head:
    lea rax,[rel hw_mcab_array_names]
    movsxd rdi,dword [rax+r12*4]
    add rdi,rax
    call hw_puts
    xor ebx,ebx
.array:
    mov ecx,ebx
    add ecx,[r13+88]                    ; actual bank index (0..31)
    mov eax,[r13+72+r12*4]              ; full CPU read-valid bitmap
    bt eax,ecx
    jnc .unknown
    imul eax,ebx,MCA_B_ENTRY
    lea rax,[r13+rax+96]
    mov rdi,[rax+r12*8]
    shr rdi,32
    mov esi,8
    call hw_put_hex
    imul eax,ebx,MCA_B_ENTRY
    lea rax,[r13+rax+96]
    mov edi,[rax+r12*8]
    mov esi,8
    call hw_put_hex
    jmp .advance
.unknown:
    lea rdi,[rel str_hw_mcgctl_unknown]
    call hw_puts
.advance:
    inc ebx
    cmp ebx,8
    jae .array_done
    lea rdi,[rel str_hw_slash]
    call hw_puts
    jmp .array
.array_done:
    inc r12d
    cmp r12d,3
    jb .array_head
    lea rdi,[rel str_hw_mcab_scope]
    call hw_puts
    jmp .done
.refuse:
    mov byte [rel hw_out_failed],1
.done:
    add rsp,MCA_B_COPY_BYTES
    pop r13
    pop r12
    pop rbx
    ret

hw_mcab_fields:
    MCA_Q_FIELD str_hw_mcab_qual,8,2
    MCA_Q_FIELD str_hw_mcab_banks,16,2
    MCA_Q_FIELD str_hw_mcab_first,88,2
    MCA_Q_FIELD str_hw_mcab_signature,64,8
    MCA_Q_FIELD str_hw_mcab_rule,68,2
    MCA_Q_FIELD str_hw_mcab_cap,16,16
    MCA_Q_FIELD str_hw_mcab_seq,0,16
    MCA_Q_FIELD str_hw_mcab_time,48,16
    MCA_Q_FIELD str_hw_mcab_ctlvalid,72,8
    MCA_Q_FIELD str_hw_mcab_cfgvalid,76,8
    MCA_Q_FIELD str_hw_mcab_ipidvalid,80,8
    MCA_Q_FIELD str_hw_mcab_local,84,8
    dq 0
hw_mcab_array_names:
    dd str_hw_mcab_ctl-hw_mcab_array_names
    dd str_hw_mcab_config-hw_mcab_array_names
    dd str_hw_mcab_ipid-hw_mcab_array_names
str_hw_mcab_advertise: db ' bank_v1=1',0
str_hw_mcab: db 'mcab',0
str_hw_mcab_cpu: db ' v=1 cpu=',0
str_hw_mcab_qual: db ' qual=',0
str_hw_mcab_banks: db ' banks=',0
str_hw_mcab_first: db ' first=',0
str_hw_mcab_signature: db ' signature=',0
str_hw_mcab_rule: db ' rule=',0
str_hw_mcab_cap: db ' cap=',0
str_hw_mcab_seq: db ' seq=',0
str_hw_mcab_time: db ' sampled_us=',0
str_hw_mcab_ctlvalid: db ' ctl_valid=',0
str_hw_mcab_cfgvalid: db ' config_valid=',0
str_hw_mcab_ipidvalid: db ' ipid_valid=',0
str_hw_mcab_local: db ' local=',0
str_hw_mcab_ctl: db ' ctl=',0
str_hw_mcab_config: db ' config=',0
str_hw_mcab_ipid: db ' ipid=',0
str_hw_mcab_scope: db ' snapshot=per-cpu-retained local_meaning=positive-view absent=unknown irq_ownership=unknown physical=unknown',0

; Raw ACPI MCFG qualification, exposing segments outside our segment0 reader.
hw_r_aerq:
    push rbx
    push r12
    push r13
    lea rdi,[rel str_hw_aerq_state]
    call hw_puts
    movzx edi,byte [rel acpi_table_state+1]
    mov esi,1
    call hw_put_hex
    lea rdi,[rel str_hw_aerq_n]
    call hw_puts
    mov edi,[rel acpi_mcfg_count]
    mov esi,1
    call hw_put_hex
    lea rdi,[rel str_hw_aerq_entries]
    call hw_puts
    mov r13d,[rel acpi_mcfg_count]
    test r13d,r13d
    jz .unknown
    cmp r13d,4
    ja .unknown
    lea r12,[rel acpi_mcfg_entries]
    xor ebx,ebx
.next:
    movzx edi,word [r12+8]
    mov esi,4
    call hw_put_hex
    lea rdi,[rel str_hw_colon]
    call hw_puts
    movzx edi,byte [r12+10]
    mov esi,2
    call hw_put_hex
    lea rdi,[rel str_hw_dash]
    call hw_puts
    movzx edi,byte [r12+11]
    mov esi,2
    call hw_put_hex
    inc ebx
    cmp ebx,r13d
    jae .scope
    lea rdi,[rel str_hw_slash]
    call hw_puts
    add r12,16
    jmp .next
.unknown:
    lea rdi,[rel str_hw_dash]
    call hw_puts
.scope:
    lea rdi,[rel str_hw_aerq_limits]
    call hw_puts
    pop r13
    pop r12
    pop rbx
    ret

; Descriptor-relative strings keep the image relocatable. Width0 terminates.
hw_mcaq_fields:
    MCA_Q_FIELD str_hw_mcaq_qual,MCA_Q_QUAL,1
    MCA_Q_FIELD str_hw_mcaq_banks,MCA_Q_BANKS,2
    MCA_Q_FIELD str_hw_mcaq_cap,MCA_Q_CAP,16
    MCA_Q_FIELD str_hw_mcaq_polls,MCA_Q_POLLS,16
    MCA_Q_FIELD str_hw_mcaq_first,MCA_Q_FIRST,16
    MCA_Q_FIELD str_hw_mcaq_last,MCA_Q_LAST,16
    MCA_Q_FIELD str_hw_mcaq_nonzero,MCA_Q_NONZERO,8
    MCA_Q_FIELD str_hw_mcaq_scanned,MCA_Q_SCANNED,8
    MCA_Q_FIELD str_hw_mcaq_seq,MCA_Q_SEQ,16
    MCA_Q_FIELD str_hw_mcaq_changed,MCA_Q_CHANGED,8
    dq 0
str_hw_mcaq: db 'mcaq',0
str_hw_mcaq_cpu: db ' v=1 cpu=',0
str_hw_mcaq_qual: db ' qual=',0
str_hw_mcaq_banks: db ' banks=',0
str_hw_mcaq_cap: db ' cap=',0
str_hw_mcaq_polls: db ' polls=',0
str_hw_mcaq_first: db ' first=',0
str_hw_mcaq_last: db ' last=',0
str_hw_mcaq_nonzero: db ' nonzero=',0
str_hw_mcaq_scanned: db ' scanned=',0
str_hw_mcaq_seq: db ' seq=',0
str_hw_mcaq_changed: db ' changed=',0
str_hw_mcaq_scope: db ' scope=cpu-view',0
str_hw_mca_boot: db ' boot_v1=',0
str_hw_aerq_state: db ' v=1 mcfg_state=',0
str_hw_aerq_n: db ' allocations=',0
str_hw_aerq_entries: db ' entries=',0
str_hw_aerq_limits: db ' cpu_limit=20 bank_limit=20 aer_limit=20',0

; Per-CPU aligned atomic counts, never a simultaneous all-CPU snapshot.
hw_r_mcalog:
    push rbx
    push r12
    push r13
    push r14
    push r15
    xor r13d,r13d
    lea rdi,[rel str_hw_mcalog_head]
    call hw_puts
    xor r14d,r14d
.cpu:
    imul r15,r14,MCA_POLL_STRIDE
    lea r12,[rel mca_poll_rows]
    add r12,r15
    movzx eax,byte [r12+MCA_POLL_QUAL]
    cmp eax,1
    je .known
    cmp eax,4
    jne .unknown
.known:
    bts r13d,r14d
    mov rbx,[r12+MCA_POLL_COUNT]
    mov rdi,rbx
    shr rdi,32
    mov esi,8
    call hw_put_hex
    mov edi,ebx
    mov esi,8
    call hw_put_hex
    jmp .next
.unknown:
    lea rdi,[rel str_hw_mcalog_unknown]
    call hw_puts
.next:
    inc r14d
    cmp r14d,32
    jae .finish
    lea rdi,[rel str_hw_mcactl_slash]
    call hw_puts
    jmp .cpu
.finish:
    lea rdi,[rel str_hw_mcactl_ready]
    call hw_puts
    mov edi,r13d
    mov esi,8
    call hw_put_hex
    lea rdi,[rel str_hw_mcalog_scope]
    call hw_puts
    ; Separate one-attempt stable CPU samples; a busy/uninitialized CPU is
    ; excluded by other_ready, never represented as a qualified zero.
    sub rsp,64                         ; private copy32, aggregate24, alignment8
    xor eax,eax
    mov [rsp+32],rax
    mov [rsp+40],rax
    mov [rsp+48],rax
    mov r15d,r13d                       ; original corrected-array scope
    xor r13d,r13d
    xor r14d,r14d
.other_cpu:
    bt r15d,r14d
    jnc .other_next
    mov edi,r14d
    mov rsi,rsp
    call mca_poll_observed_copy
    test eax,eax
    jnz .other_next
    bts r13d,r14d
    xor ebx,ebx
.other_sum:
    mov rax,[rsp+rbx*8]
    add rax,[rsp+rbx*8+32]
    jnc .other_store
    mov rax,-1
.other_store:
    mov [rsp+rbx*8+32],rax
    inc ebx
    cmp ebx,3
    jb .other_sum
.other_next:
    inc r14d
    cmp r14d,32
    jb .other_cpu
    lea rdi,[rel str_hw_mcalog_other_ready]
    call hw_puts
    mov edi,r13d
    mov esi,8
    call hw_put_hex
    xor r14d,r14d
    lea r12,[rel hw_mcalog_other_names]
.other_field:
    movsxd rdi,dword [r12]
    add rdi,r12
    call hw_puts
    mov rbx,[rsp+r14*8+32]
    mov rdi,rbx
    shr rdi,32
    mov esi,8
    call hw_put_hex
    mov edi,ebx
    mov esi,8
    call hw_put_hex
    add r12,4
    inc r14d
    cmp r14d,3
    jb .other_field
    add rsp,64
    jmp hw_mca_controls_done
str_hw_mcalog_head: db " slots=32 observations=",0
str_hw_mcalog_unknown: db "----------------",0
str_hw_mcalog_scope: db " snapshot=per-cpu-retained counts=sampled-software physical=unknown",0

hw_mcalog_other_names:
    dd str_hw_mcalog_other_seen-$
    dd str_hw_mcalog_other_logged-$
    dd str_hw_mcalog_other_dropped-$
str_hw_mcalog_other_ready: db ' other_ready=',0
str_hw_mcalog_other_seen: db ' other_seen=',0
str_hw_mcalog_other_logged: db ' other_logged=',0
str_hw_mcalog_other_dropped: db ' other_dropped=',0

; Read-only route evidence from per-CPU native readbacks. No CMCI write here.
hw_r_mcarte:
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea rdi,[rel hw_mcarte_masks]
    xor eax,eax
    mov ecx,9
    rep stosd
    mov qword [rel hw_mcarte_irqs],0
    xor r14d,r14d
.copy:
    mov edi,r14d
    mov r15,r14
    shl r15,6
    lea r12,[rel hw_mcactl_rows]
    add r12,r15
    mov qword [r12],0
    mov rsi,r12
    call mca_cmci_copy
    test eax,eax
    jnz .advance
    bts dword [rel hw_mcarte_masks],r14d
    bt dword [r12+44],0
    jnc .cmci_gate
    bts dword [rel hw_mcarte_masks+4],r14d
.cmci_gate:
    bt dword [r12+44],1
    jnc .states
    bts dword [rel hw_mcarte_masks+8],r14d
    test dword [r12+44],1
    jz .states
    cmp dword [r12+8],4
    jne .states
    cmp dword [r12+12],0
    je .states
    mov eax,[r12+20]
    and eax,0x107ff
    cmp eax,0xed
    jne .states
    bts dword [rel hw_mcarte_masks+12],r14d
.states:
    cmp dword [r12+8],6
    jne .irq
    bts dword [rel hw_mcarte_masks+16],r14d
.irq:
    mov rax,[r12+32]
    test rax,rax
    jz .pending
    bts dword [rel hw_mcarte_masks+20],r14d
    add rax,[rel hw_mcarte_irqs]
    jnc .sum
    mov rax,-1
.sum:
    mov [rel hw_mcarte_irqs],rax
.pending:
    cmp dword [r12+40],0
    je .foreign
    bts dword [rel hw_mcarte_masks+24],r14d
.foreign:
    cmp dword [r12+8],7
    jne .polled
    bts dword [rel hw_mcarte_masks+28],r14d
.polled:
    cmp dword [r12+8],5
    jne .advance
    bts dword [rel hw_mcarte_masks+32],r14d
.advance:
    inc r14d
    cmp r14d,32
    jb .copy
    lea rdi,[rel str_hw_mcarte_head]
    call hw_puts
    mov edi,[rel mca_cmci_policy]
    mov esi,1
    call hw_put_hex
    xor ebx,ebx
.masks:
    lea rax,[rel hw_mcarte_names]
    movsxd rdi,dword [rax+rbx*4]
    add rdi,rax
    call hw_puts
    lea rax,[rel hw_mcarte_masks]
    mov edi,[rax+rbx*4]
    mov esi,8
    call hw_put_hex
    inc ebx
    cmp ebx,9
    jb .masks
    lea rdi,[rel str_hw_mcarte_owned]
    call hw_puts
    mov r13d,12
    call hw_mca_controls_array
    lea rdi,[rel str_hw_mcarte_external]
    call hw_puts
    mov r13d,16
    call hw_mca_controls_array
    lea rdi,[rel str_hw_mcarte_irqs]
    call hw_puts
    mov rbx,[rel hw_mcarte_irqs]
    mov rdi,rbx
    shr rdi,32
    mov esi,8
    call hw_put_hex
    mov edi,ebx
    mov esi,8
    call hw_put_hex
    lea rdi,[rel str_hw_mcactl_scope]
    call hw_puts
    jmp hw_mca_controls_done
hw_mcarte_names:
    dd str_hw_mcactl_ready-hw_mcarte_names
    dd str_hw_mcarte_mc-hw_mcarte_names
    dd str_hw_mcarte_gate-hw_mcarte_names
    dd str_hw_mcarte_route-hw_mcarte_names
    dd str_hw_mcarte_storm-hw_mcarte_names
    dd str_hw_mcarte_seen-hw_mcarte_names
    dd str_hw_mcarte_pending-hw_mcarte_names
    dd str_hw_mcarte_foreign-hw_mcarte_names
    dd str_hw_mcarte_polled-hw_mcarte_names
str_hw_mcarte_head: db " slots=32 policy=",0
str_hw_mcarte_mc: db " mc_gate=",0
str_hw_mcarte_gate: db " cmci_gate=",0
str_hw_mcarte_route: db " route=",0
str_hw_mcarte_storm: db " storm=",0
str_hw_mcarte_seen: db " irq_seen=",0
str_hw_mcarte_pending: db " pending=",0
str_hw_mcarte_foreign: db " foreign=",0
str_hw_mcarte_polled: db " polled=",0
str_hw_mcarte_owned: db " owned=",0
str_hw_mcarte_external: db " external=",0
str_hw_mcarte_irqs: db " irq_total=",0

hw_mcactl_mask_names:
    dd str_hw_mcactl_ready-hw_mcactl_mask_names
    dd str_hw_mcactl_mce-hw_mcactl_mask_names
    dd str_hw_mcactl_global-hw_mcactl_mask_names
    dd str_hw_mcactl_global_all-hw_mcactl_mask_names
str_hw_mcactl_head: db " slots=32",0
str_hw_mcactl_ready: db " ready=",0
str_hw_mcactl_mce: db " cr4_mce=",0
str_hw_mcactl_global: db " global_present=",0
str_hw_mcactl_global_all: db " global_all=",0
str_hw_mcactl_banks: db " banks=",0
str_hw_mcactl_all: db " ctl_all=",0
str_hw_mcactl_any: db " ctl_any=",0
str_hw_mcactl_scope: db " snapshot=per-cpu-retained physical=unknown",0
str_hw_mcactl_unknown: db "--------",0
str_hw_mcactl_slash: db "/",0
str_hw_mcgctl_layout: db " layout=",0
str_hw_mcgctl_raw: db " raw=",0
str_hw_mcgctl_unknown: db "----------------",0
str_hw_mcaaux_head: db " slots=32 ready=",0
str_hw_mcaaux_present: db " smca_present=",0
str_hw_mcaaux_enabled: db " enable_bit=",0
str_hw_mcaaux_scope: db " snapshot=per-cpu-retained intel=ctl2-bit30 amd=config-bit40 irq_route=unknown",0

hw_r_cpu:
    push rbx
    sub  rsp, 32
    mov  rdi, rsp
    call idle_probe_cpu_ident               ; ECX = CPUID.01H:ECX
    mov  ebx, ecx
    lea  rdi, [rel str_hw_c_vendor]
    call hw_puts
    mov  edi, [rsp + 4]
    call hw_vendor_name
    call hw_puts
    lea  rdi, [rel str_hw_c_family]
    call hw_puts
    mov  edi, [rsp + 8]
    call hw_put_hex2
    lea  rdi, [rel str_hw_c_model]
    call hw_puts
    mov  edi, [rsp + 12]
    call hw_put_hex2
    lea  rdi, [rel str_hw_c_stepping]
    call hw_puts
    mov  edi, [rsp + 16]
    call hw_put_dec
    lea  rdi, [rel str_hw_c_brand]
    call hw_puts
    call hw_put_brand
    lea  rdi, [rel str_hw_c_packages]
    call hw_puts
    mov  edi, [rel smp_package_count]
    call hw_put_dec
    lea  rdi, [rel str_hw_c_cores]
    call hw_puts
    mov  edi, [rel smp_physical_core_count]
    call hw_put_dec
    lea  rdi, [rel str_hw_c_tpc]
    call hw_puts
    mov  edi, [rel smp_threads_per_core]
    call hw_put_dec
    lea  rdi, [rel str_hw_c_online]
    call hw_puts
    mov  edi, [rel smp_topology_online]
    call hw_put_dec
    lea  rdi, [rel str_hw_c_hv]
    call hw_puts
    mov  edi, ebx
    shr  edi, 31
    call hw_put_dec
    add  rsp, 32
    pop  rbx
    ret

hw_r_gpu:
    mov  edi, HW_C_GPU
    call hw_put_list
    lea  rdi, [rel str_hw_g_native]
    call hw_puts
    lea  rdi, [rel str_hw_g_display]
    call hw_puts
    cmp  dword [rel fb_width], 0
    je   .nogop
    lea  rdi, [rel str_hw_g_gop]
    call hw_puts
    mov  edi, [rel fb_width]
    call hw_put_dec
    lea  rdi, [rel str_hw_x]
    call hw_puts
    mov  edi, [rel fb_height]
    call hw_put_dec
    ret
.nogop:
    lea  rdi, [rel str_hw_none]
    call hw_puts
    ret

hw_r_nic:
    push rbx
    sub  rsp, 64                            ; one struc netdev_minfo
    mov  edi, HW_C_NIC
    call hw_put_list
    lea  rdi, [rel str_hw_n_usb]
    call hw_puts
    xor  ebx, ebx
    cmp  byte [rel ax_present], 0
    je   .axb
    lea  rdi, [rel str_hw_ax88179]
    call hw_put_item
.axb:
    cmp  byte [rel axb_registered], 1       ; newer AX (0200) bound and registered (ROOT109541 (a))
    jne  .ecm
    lea  rdi, [rel str_hw_ax88179b]
    call hw_put_item
.ecm:
    cmp  byte [rel cdc_ecm_present], 0
    je   .ncm
    lea  rdi, [rel str_hw_cdc_ecm]
    call hw_put_item
.ncm:
    cmp  byte [rel cdc_ncm_present], 0
    je   .usb_done
    lea  rdi, [rel str_hw_cdc_ncm]
    call hw_put_item
.usb_done:
    test ebx, ebx
    jnz  .members
    lea  rdi, [rel str_hw_none]
    call hw_puts
.members:
    ; Registered network members (registry only: netdev_member_brief does no driver IO).
    xor  ebx, ebx
.member:
    cmp  ebx, NETDEV_MAX_SLOTS
    jae  .done
    mov  edi, ebx
    mov  rsi, rsp
    call netdev_member_brief
    test rax, rax
    jnz  .next
    test dword [rsp + netdev_minfo.flags], NETDEV_F_ABSENT
    jnz  .next
    lea  rdi, [rel str_hw_n_if]
    call hw_puts
    mov  rdi, [rsp + netdev_minfo.name]
    call hw_put_token
    lea  rdi, [rel str_hw_colon]
    call hw_puts
    mov  rdi, [rsp + netdev_minfo.driver]
    call hw_put_token
    lea  rdi, [rel str_hw_colon]
    call hw_puts
    mov  eax, [rsp + netdev_minfo.health]
    lea  rdi, [rel str_hw_ok]
    cmp  eax, HEALTH_OK
    je   .health
    lea  rdi, [rel str_hw_degraded]
    cmp  eax, HEALTH_DEGRADED
    je   .health
    lea  rdi, [rel str_hw_dead]
.health:
    call hw_puts
.next:
    inc  ebx
    jmp  .member
.done:
    add  rsp, 64
    pop  rbx
    ret

hw_r_storage:
    mov  edi, HW_C_STORAGE
    call hw_put_list
    lea  rdi, [rel str_hw_st_usb]
    call hw_puts
    movzx edi, byte [rel msd_bound]
    call hw_put_dec
    lea  rdi, [rel str_hw_st_blocks]
    call hw_puts
    call blk_registered_count
    mov  edi, eax
    call hw_put_dec
    ret

hw_r_usb:
    mov  edi, HW_C_USB
    call hw_put_list
    ret

hw_r_input:
    lea  rdi, [rel str_hw_s_input]
    call hw_puts
    call hw_put_input_core
    lea  rdi, [rel str_hw_i_i2c]
    call hw_puts
    mov  edi, HW_C_SERIALIO                 ; Serial IO functions (I2C hosts of touchpads)
    call hw_put_list
    ret

hw_r_battery:
    lea  rdi, [rel str_hw_b_driver]
    call hw_puts
    call hw_battery_word
    call hw_puts
    cmp  byte [rel ecp_active], 0
    je   .out
    lea  rdi, [rel str_hw_b_present]
    call hw_puts
    movzx eax, byte [rel ecp_bat_present]
    lea  rdi, [rel str_hw_unknown]
    cmp  eax, ECP_UNKNOWN8
    je   .p
    lea  rdi, [rel str_hw_zero]
    test eax, eax
    jz   .p
    lea  rdi, [rel str_hw_one]
.p:
    call hw_puts
.out:
    ret

; Retained SMBIOS DIMMs and published EFI map, using the existing owner HW
; transport. DIMM entry ABI is boot/smbios: stride144, cap4; +0 handle:u16,
; +2 name-clips:u8, +3 size-state:u8, +8 bytes:u64, +16/+80 strings[64].
; Installed total needs a complete walk, at least one type17, no unknown/overflow.
; Row clipping never truncates that aggregate; locator31/bank15 are hex encoded.
hw_r_memory:
    push rbx
    push r12
    push r13
    sub  rsp, 32                           ; private memmap_inventory output[24]
    lea  rdi, [rel str_hw_sys_state]
    call hw_puts
    mov  edi, [rel smbios_identity_state]
    call hw_put_dec
    lea  rdi, [rel str_hw_m_state]
    call hw_puts
    xor  ebx, ebx                          ; installed total not yet known
    lea  rdi, [rel str_hw_m_partial]
    cmp  byte [rel smbios_mem_complete], 1
    jne  .state
    lea  rdi, [rel str_hw_m_absent]
    cmp  dword [rel smbios_mem_seen], 0
    je   .state
    lea  rdi, [rel str_hw_m_partial]
    cmp  dword [rel smbios_mem_unknown], 0
    jne  .state
    cmp  byte [rel smbios_mem_overflow], 0
    jne  .state
    mov  ebx, 1
    lea  rdi, [rel str_hw_ok]
    mov  eax, [rel smbios_mem_seen]
    cmp  eax, [rel smbios_mem_stored]
    ja   .clipped
    lea  r12, [rel smbios_mem_entries]
    xor  r13d, r13d
.check_names:
    cmp  r13d, [rel smbios_mem_stored]
    jae  .state
    cmp  r13d, 4
    jae  .state
    cmp  byte [r12 + 2], 0
    jne  .clipped
    add  r12, 144
    inc  r13d
    jmp  .check_names
.clipped:
    lea  rdi, [rel str_hw_m_clip_state]
.state:
    call hw_puts
    lea  rdi, [rel str_hw_m_complete]
    call hw_puts
    movzx edi, byte [rel smbios_mem_complete]
    call hw_put_dec
    lea  rdi, [rel str_hw_m_seen]
    call hw_puts
    mov  edi, [rel smbios_mem_seen]
    call hw_put_dec
    lea  rdi, [rel str_hw_m_stored]
    call hw_puts
    mov  edi, [rel smbios_mem_stored]
    call hw_put_dec
    lea  rdi, [rel str_hw_m_unknown]
    call hw_puts
    mov  edi, [rel smbios_mem_unknown]
    call hw_put_dec
    lea  rdi, [rel str_hw_m_clipped]
    call hw_puts
    mov  edi, [rel smbios_mem_seen]
    sub  edi, [rel smbios_mem_stored]
    call hw_put_dec
    lea  rdi, [rel str_hw_m_installed]
    call hw_puts
    test ebx, ebx
    jz   .unknown_total
    mov  rdi, [rel smbios_mem_bytes]
    call hw_put_u64
    jmp  .rows
.unknown_total:
    lea  rdi, [rel str_hw_unknown]
    call hw_puts
.rows:
    lea  r12, [rel smbios_mem_entries]
    xor  r13d, r13d
.row:
    cmp  r13d, [rel smbios_mem_stored]
    jae  .map
    cmp  r13d, 4
    jae  .map
    lea  rdi, [rel str_hw_m_dimm]
    call hw_puts
    movzx edi, word [r12]
    mov  esi, 4
    call hw_put_hex
    lea  rdi, [rel str_hw_comma]
    call hw_puts
    cmp  byte [r12 + 3], 0
    je   .empty
    cmp  byte [r12 + 3], 1
    jne  .unknown_size
    mov  rdi, [r12 + 8]
    call hw_put_u64
    jmp  .names
.empty:
    lea  rdi, [rel str_hw_m_empty]
    call hw_puts
    jmp  .names
.unknown_size:
    lea  rdi, [rel str_hw_unknown]
    call hw_puts
.names:
    lea  rdi, [rel str_hw_comma]
    call hw_puts
    lea  rdi, [r12 + 16]
    call hw_put_bios_hex
    lea  rdi, [rel str_hw_comma]
    call hw_puts
    lea  rdi, [r12 + 80]
    call hw_put_bios_hex
    lea  rdi, [rel str_hw_comma]
    call hw_puts
    movzx edi, byte [r12 + 2]
    call hw_put_dec
    add  r12, 144
    inc  r13d
    jmp  .row
.map:
    mov  rdi, rsp
    call memmap_inventory
    lea  rdi, [rel str_hw_m_map_state]
    call hw_puts
    lea  rdi, [rel str_hw_m_absent]
    cmp  dword [rsp], 0
    je   .map_state
    lea  rdi, [rel str_hw_ok]
    cmp  dword [rsp], 1
    je   .map_state
    lea  rdi, [rel str_hw_m_invalid]
.map_state:
    call hw_puts
    lea  rdi, [rel str_hw_m_map_desc]
    call hw_puts
    mov  edi, [rsp + 4]
    call hw_put_dec
    lea  rdi, [rel str_hw_m_conventional]
    call hw_puts
    cmp  dword [rsp], 1
    jne  .unknown_conventional
    mov  rdi, [rsp + 8]
    call hw_put_u64
    jmp  .boot_bytes
.unknown_conventional:
    lea  rdi, [rel str_hw_unknown]
    call hw_puts
.boot_bytes:
    lea  rdi, [rel str_hw_m_loader_boot]
    call hw_puts
    cmp  dword [rsp], 1
    jne  .unknown_boot
    mov  rdi, [rsp + 16]
    call hw_put_u64
    jmp  .scope
.unknown_boot:
    lea  rdi, [rel str_hw_unknown]
    call hw_puts
.scope:
    lea  rdi, [rel str_hw_m_scope]
    call hw_puts
    add  rsp, 32
    pop  r13
    pop  r12
    pop  rbx
    ret

; First missing T1-2 platform sampler: retained type0 BIOS facts only. This
; record deliberately makes no DIMM/installed-RAM/UEFI-map claim. Empty/missing
; string indices are '-', never a guessed firmware version. BIOS text is the
; existing printable-ASCII sanitization, max63; the per-field clip mask exposes
; loss. Raw SMBIOS state accompanies even a previously retained partial record.
hw_r_system:
    sub  rsp, 8
    lea  rdi, [rel str_hw_sys_state]
    call hw_puts
    mov  edi, [rel smbios_identity_state]
    call hw_put_dec
    lea  rdi, [rel str_hw_sys_present]
    call hw_puts
    movzx edi, byte [rel smbios_have_t0]
    call hw_put_dec
    lea  rdi, [rel str_hw_sys_vendor]
    call hw_puts
    lea  rdi, [rel smbios_bios_vendor]
    call hw_put_bios_hex
    lea  rdi, [rel str_hw_sys_version]
    call hw_puts
    lea  rdi, [rel smbios_bios_version]
    call hw_put_bios_hex
    lea  rdi, [rel str_hw_sys_date]
    call hw_puts
    lea  rdi, [rel smbios_bios_date]
    call hw_put_bios_hex
    lea  rdi, [rel str_hw_sys_clipped]
    call hw_puts
    movzx edi, byte [rel smbios_bios_clipped]
    call hw_put_dec
    lea  rdi, [rel str_hw_sys_scope]
    call hw_puts
    ; Last field: the answer every HP quirk caller gets (T1-2 clause 6), read only
    ; after a pre-EBS reader resolved the table, so a reply never walks firmware tables.
    lea  rdi, [rel str_hw_sys_hpq]
    call hw_puts
    cmp  byte [rel smbios_identity_resolved], 0
    jne  .hpq
    lea  rdi, [rel str_hw_dash]
    call hw_puts
    jmp  .out
.hpq:
    call smbios_hp_quirk_identity
    mov  edi, eax
    call hw_put_dec
.out:
    add  rsp, 8
    ret

; RDI = retained 64-byte BIOS string. Hex preserves spaces/punctuation without
; introducing reply tokens or delimiters; bound independently of its terminator.
hw_put_bios_hex:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rdi
    xor  ebx, ebx
    cmp  byte [r12], 0
    jne  .next
    lea  rdi, [rel str_hw_dash]
    call hw_puts
    jmp  .out
.next:
    movzx edi, byte [r12 + rbx]
    test edi, edi
    jz   .out
    mov  esi, 2
    call hw_put_hex
    inc  ebx
    cmp  ebx, 63
    jb   .next
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; "kbd:<0|1>,mouse:<0|1>,usb_hid:<n>,usb_host:<driven xhci>" (after " input=").
hw_put_input_core:
    lea  rdi, [rel str_hw_i_kbd]
    call hw_puts
    movzx edi, byte [rel ps2_kbd_armed]
    call hw_put_dec
    lea  rdi, [rel str_hw_i_mouse]
    call hw_puts
    movzx edi, byte [rel ps2_mouse_acked]
    call hw_put_dec
    lea  rdi, [rel str_hw_i_hid]
    call hw_puts
    movzx edi, byte [rel usb_hid_active_count]
    call hw_put_dec
    lea  rdi, [rel str_hw_i_host]
    call hw_puts
    mov  edi, [rel hw_driven + HW_C_USB * 4]
    call hw_put_dec
    ret

; -> RDI = "ec_power" when an EC battery descriptor matched this machine, else "none".
hw_battery_word:
    lea  rdi, [rel str_hw_none]
    cmp  byte [rel ecp_active], 0
    je   .out
    lea  rdi, [rel str_hw_ec_power]
.out:
    ret

; hw_put_list(EDI = bucket): " n=<found> dev=BB:DD.F,VVVV:DDDD,CCSSPP,<driver|none>
;   [,unusable] ... [more=<m>]"; at most HW_DEV_MAX devices, the rest counted.
hw_put_list:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r14d, edi                          ; bucket
    xor  r15d, r15d                         ; listed so far
    lea  rdi, [rel str_hw_n]
    call hw_puts
    lea  rax, [rel hw_found]
    mov  edi, [rax + r14*4]
    call hw_put_dec
    xor  ebx, ebx
.dev:
    cmp  ebx, [rel hw_list_n]
    jae  .more
    cmp  r15d, HW_DEV_MAX
    jae  .more
    mov  r12d, ebx
    shl  r12d, 4
    lea  rax, [rel hw_list]
    add  r12, rax
    movzx eax, byte [r12 + 15]
    cmp  eax, r14d
    jne  .next
    inc  r15d
    lea  rdi, [rel str_hw_dev]
    call hw_puts
    mov  r13d, [r12]
    mov  edi, r13d
    shr  edi, 8
    mov  esi, 2
    call hw_put_hex
    lea  rdi, [rel str_hw_colon]
    call hw_puts
    mov  edi, r13d
    shr  edi, 3
    and  edi, 0x1F
    mov  esi, 2
    call hw_put_hex
    lea  rdi, [rel str_hw_dot]
    call hw_puts
    mov  edi, r13d
    and  edi, 7
    mov  esi, 1
    call hw_put_hex
    lea  rdi, [rel str_hw_comma]
    call hw_puts
    movzx edi, word [r12 + 4]               ; vendor
    mov  esi, 4
    call hw_put_hex
    lea  rdi, [rel str_hw_colon]
    call hw_puts
    movzx edi, word [r12 + 6]               ; device
    mov  esi, 4
    call hw_put_hex
    lea  rdi, [rel str_hw_comma]
    call hw_puts
    mov  edi, [r12 + 8]
    shr  edi, 8                             ; class, subclass, progif
    mov  esi, 6
    call hw_put_hex
    lea  rdi, [rel str_hw_comma]
    call hw_puts
    movzx edi, word [r12 + 12]              ; driver id
    test edi, edi
    jnz  .named
    lea  rdi, [rel str_hw_none]
    call hw_puts
    jmp  .next
.named:
    call pci_claim_drv_name
    mov  rdi, rax
    call hw_puts
    cmp  byte [r12 + 14], PCI_CLAIM_BOUND
    je   .next
    lea  rdi, [rel str_hw_unusable]
    call hw_puts
.next:
    inc  ebx
    jmp  .dev
.more:
    lea  rax, [rel hw_found]
    mov  edi, [rax + r14*4]
    sub  edi, r15d
    jz   .out
    push rdi
    lea  rdi, [rel str_hw_more]
    call hw_puts
    pop  rdi
    call hw_put_dec
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI = item, EBX = items so far (incremented): "a" then ",b".
hw_put_item:
    push rdi
    test ebx, ebx
    jz   .first
    lea  rdi, [rel str_hw_comma]
    call hw_puts
.first:
    pop  rdi
    call hw_puts
    inc  ebx
    ret

; The CPUID brand string (80000002h..80000004h) as one token: leading and
; trailing blanks dropped, inner runs of blanks -> "_", anything outside
; [0-9A-Za-z.()@-] -> "_".  "unknown" when the leaf is absent.
hw_put_brand:
    push rbx
    push r12
    sub  rsp, 72
    mov  eax, 0x80000000
    xor  ecx, ecx
    cpuid
    cmp  eax, 0x80000004
    jb   .unknown
    xor  r12d, r12d
.leaf:
    lea  eax, [r12d + 0x80000002]
    xor  ecx, ecx
    cpuid
    imul r8d, r12d, 16
    mov  [rsp + r8], eax
    mov  [rsp + r8 + 4], ebx
    mov  [rsp + r8 + 8], ecx
    mov  [rsp + r8 + 12], edx
    inc  r12d
    cmp  r12d, 3
    jb   .leaf
    mov  byte [rsp + 48], 0
    lea  rdi, [rsp]
    call hw_brand_token                     ; in place: the token never grows
    cmp  byte [rsp], 0
    je   .unknown
    lea  rdi, [rsp]
    call hw_puts
    jmp  .out
.unknown:
    lea  rdi, [rel str_hw_unknown]
    call hw_puts
.out:
    add  rsp, 72
    pop  r12
    pop  rbx
    ret

; hw_brand_token(RDI = NUL-terminated text) -> rewrites it in place as one token.
hw_brand_token:
    mov  rsi, rdi                           ; read cursor
    mov  rdx, rdi                           ; write cursor
    xor  ecx, ecx                           ; 1 = a blank run is pending
.skip_lead:
    movzx eax, byte [rsi]
    cmp  al, ' '
    jne  .loop
    inc  rsi
    jmp  .skip_lead
.loop:
    movzx eax, byte [rsi]
    test al, al
    jz   .end
    inc  rsi
    cmp  al, ' '
    jne  .char
    mov  ecx, 1
    jmp  .loop
.char:
    test ecx, ecx
    jz   .keep
    mov  byte [rdx], '_'
    inc  rdx
    xor  ecx, ecx
.keep:
    call hw_brand_char_ok
    mov  [rdx], al
    inc  rdx
    jmp  .loop
.end:
    mov  byte [rdx], 0                      ; a trailing blank run is dropped
    ret

; AL = byte -> AL unchanged if [0-9A-Za-z.()@-], else '_'.  Keeps RCX/RDX/RSI.
hw_brand_char_ok:
    cmp  al, '0'
    jb   .punct
    cmp  al, '9'
    jbe  .ok
    cmp  al, 'A'
    jb   .punct
    cmp  al, 'Z'
    jbe  .ok
    cmp  al, 'a'
    jb   .bad
    cmp  al, 'z'
    jbe  .ok
    jmp  .bad
.punct:
    cmp  al, '.'
    je   .ok
    cmp  al, '('
    je   .ok
    cmp  al, ')'
    je   .ok
    cmp  al, '-'
    je   .ok
    cmp  al, '@'
    je   .ok
.bad:
    mov  al, '_'
.ok:
    ret

; hw_vendor_name(EDI = IDLE_V_*) -> RDI = "intel" | "amd" | "other".
hw_vendor_name:
    mov  eax, edi
    lea  rdi, [rel str_hw_intel]
    cmp  eax, IDLE_V_INTEL
    je   .out
    lea  rdi, [rel str_hw_amd]
    cmp  eax, IDLE_V_AMD
    je   .out
    lea  rdi, [rel str_hw_other]
.out:
    ret

; hw_put_token(RDI = name or 0): a registry name as one token: at most
; HW_TOKEN_MAX bytes of [A-Za-z0-9._-], any other byte as '_', "-" when absent
; or empty. The name is not trusted to be a short printable string: a static
; netdev_info.name in the org 0 image is an unrelocated offset (rc-sec
; SEC-netdev-info-unrelocated-name), and the record goes to the inventory.
hw_put_token:
    lea  rsi, [rel hw_num]
    xor  ecx, ecx
    test rdi, rdi
    jz   .end
.ch:
    cmp  ecx, HW_TOKEN_MAX
    jae  .end
    movzx eax, byte [rdi + rcx]
    test al, al
    jz   .end
    mov  edx, eax
    or   dl, 0x20
    cmp  dl, 'a'
    jb   .digit
    cmp  dl, 'z'
    jbe  .keep
.digit:
    cmp  al, '0'
    jb   .punct
    cmp  al, '9'
    jbe  .keep
.punct:
    cmp  al, '-'
    je   .keep
    cmp  al, '.'
    je   .keep
    cmp  al, '_'
    je   .keep
    mov  al, '_'
.keep:
    mov  [rsi + rcx], al
    inc  ecx
    jmp  .ch
.end:
    mov  byte [rsi + rcx], 0
    mov  rdi, rsi
    test ecx, ecx
    jnz  hw_puts
    lea  rdi, [rel str_hw_dash]
    jmp  hw_puts

; ---------------------------------------------------------------------------
; Bounded output.  Overflow latches hw_out_failed; the caller then returns 1 and
; never publishes a truncated record.
; ---------------------------------------------------------------------------
hw_puts:
    cmp  byte [rel hw_out_failed], 0
    jne  .out
    mov  r8, [rel hw_out_ptr]
    mov  ecx, [rel hw_out_len]
    mov  edx, [rel hw_out_cap]
.copy:
    movzx eax, byte [rdi]
    test al, al
    jz   .done
    lea  r9d, [ecx + 1]
    cmp  r9d, edx                           ; keep room for the NUL
    jae  .full
    mov  [r8 + rcx], al
    inc  ecx
    inc  rdi
    jmp  .copy
.done:
    mov  byte [r8 + rcx], 0
    mov  [rel hw_out_len], ecx
.out:
    ret
.full:
    mov  byte [rel hw_out_failed], 1
    ret

hw_put_dec:
    mov  edi, edi
hw_put_u64:                              ; capacity bytes must retain all64 bits
    sub  rsp, 8
    lea  rsi, [rel hw_num]
    call fmt_dec
    lea  rdi, [rel hw_num]
    call hw_puts
    add  rsp, 8
    ret

; "0x" + two hex digits (family/model are < 0x100).
hw_put_hex2:
    push rdi
    lea  rdi, [rel str_hw_0x]
    call hw_puts
    pop  rdi
    mov  esi, 2
    jmp  hw_put_hex

; hw_put_hex(EDI = value, ESI = digits 1..8): fixed-width lowercase hex.
hw_put_hex:
    sub  rsp, 24
    mov  ecx, esi
    mov  byte [rsp + rcx], 0
.dig:
    dec  ecx
    mov  eax, edi
    and  eax, 0xF
    lea  rdx, [rel str_hw_hexdig]
    movzx eax, byte [rdx + rax]
    mov  [rsp + rcx], al
    shr  edi, 4
    test ecx, ecx
    jnz  .dig
    mov  rdi, rsp
    call hw_puts
    add  rsp, 24
    ret

; ---------------------------------------------------------------------------
; hw_report_boot_log — one serial line per class, "[hw.report] hw=<class> ...",
;   once per boot after the drivers have run (boot/header P7).  Evidence for
;   QEMU and serial targets; the same text COMPAT HW returns.
; ---------------------------------------------------------------------------
; A local presentation must wait for the deferred driver census, rather than
; freezing an earlier PCI sweep before the network drivers have bound.
hw_report_boot_ready:
    movzx eax, byte [rel hw_boot_complete]
    ret

hw_report_boot_log:
    push rbx
    push r12
    sub  rsp, 8
    call hw_report_kat
    lea  rdi, [rel str_hw_kat_pass]
    test eax, eax
    jz   .kat
    lea  rdi, [rel str_hw_kat_fail]
.kat:
    call serial_string
    xor  ebx, ebx
.cls:
    cmp  ebx, HW_C_COUNT
    jae  .out
    mov  edi, ebx
    lea  rsi, [rel hw_log_buf]
    mov  edx, HW_LOG_CAP
    call hw_report_render                 ; the first class sweeps; the rest reuse it
    mov  r12d, eax
    lea  rdi, [rel str_hw_log_head]
    call serial_string
    lea  rdi, [rel hw_log_buf]
    test r12d, r12d
    jz   .line
    lea  rdi, [rel str_hw_log_fail]
.line:
    call serial_string
    call serial_newline
    inc  ebx
    jmp  .cls
.out:
    mov  byte [rel hw_boot_complete], 1
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; hw_report_kat -> EAX 0 pass / 1 fail.  Known answers for the pure helpers the
;   renderer is made of (class names, buckets, brand token, hex, overflow).
hw_report_kat:
    push rbx
    sub  rsp, 64
    lea  rdi, [rel hw_lock]                 ; the writer state below is shared with renders
    call spin_acquire
    lea  rdi, [rel str_hw_kat_nic_upper]
    call hw_report_class_id
    cmp  eax, HW_C_NIC
    jne  .fail
    lea  rdi, [rel str_hw_kat_bogus]
    call hw_report_class_id
    cmp  eax, -1
    jne  .fail
    mov  eax, 0x0C033000                    ; xHCI
    call hw_bucket
    cmp  eax, HW_C_USB
    jne  .fail
    mov  eax, 0x0C800000                    ; Serial IO
    call hw_bucket
    cmp  eax, HW_C_SERIALIO
    jne  .fail
    mov  eax, 0x0C050000                    ; SMBus: not reported
    call hw_bucket
    cmp  eax, -1
    jne  .fail
    mov  eax, 0x06040000                    ; bridge: not reported
    call hw_bucket
    cmp  eax, -1
    jne  .fail
    lea  rsi, [rel str_hw_kat_brand_in]
    mov  rdi, rsp
    xor  ecx, ecx
.cp:
    mov  al, [rsi + rcx]
    mov  [rdi + rcx], al
    inc  ecx
    test al, al
    jnz  .cp
    mov  rdi, rsp
    call hw_brand_token
    mov  rdi, rsp
    lea  rsi, [rel str_hw_kat_brand_out]
    call hw_kat_streq
    test eax, eax
    jz   .fail
    ; bounded writer: 4 bytes of room never hold "hw=x" + NUL
    mov  [rel hw_out_ptr], rsp
    mov  dword [rel hw_out_cap], 4
    mov  dword [rel hw_out_len], 0
    mov  byte [rel hw_out_failed], 0
    lea  rdi, [rel str_hw_kat_long]
    call hw_puts
    cmp  byte [rel hw_out_failed], 1
    jne  .fail
    mov  dword [rel hw_out_cap], 64
    mov  dword [rel hw_out_len], 0
    mov  byte [rel hw_out_failed], 0
    mov  edi, 0x8086
    mov  esi, 4
    call hw_put_hex
    mov  edi, 0x1d
    mov  esi, 2
    call hw_put_hex
    mov  rdi, rsp
    lea  rsi, [rel str_hw_kat_hex]
    call hw_kat_streq
    test eax, eax
    jz   .fail
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, 1
.out:
    mov  ebx, eax
    lea  rdi, [rel hw_lock]
    call spin_release
    mov  eax, ebx
    add  rsp, 64
    pop  rbx
    ret

; RDI, RSI NUL-terminated -> EAX 1 equal / 0.
hw_kat_streq:
    xor  ecx, ecx
.c:
    movzx eax, byte [rdi + rcx]
    cmp  al, [rsi + rcx]
    jne  .ne
    test al, al
    jz   .eq
    inc  ecx
    jmp  .c
.eq:
    mov  eax, 1
    ret
.ne:
    xor  eax, eax
    ret

; --- svc/hw_report data ---
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
%macro WDATA_svc_hw_report_0 0
; hw_lock..hw_log_buf moved to WDATA_svc_hw_report_0_bss1 (zero-fill tail)
%endmacro
WDATA_DEFER WDATA_svc_hw_report_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_svc_hw_report_0_bss1 0
hw_mcactl_rows: resb 32*64
hw_mcactl_masks: resd 4
hw_mcarte_masks: resd 9
alignb 8
hw_mcarte_irqs: resq 1
hw_lock:       resb 1
hw_out_failed: resb 1
alignb 8
hw_out_ptr:    resq 1
hw_out_len:    resd 1
hw_out_cap:    resd 1
hw_scanned:    resb 1
alignb 4
hw_list_n:     resd 1
hw_unclaimed:  resd 1
hw_over_unclaimed: resd 1
hw_found:      resd HW_BUCKETS            ; hw_found, hw_driven, hw_over_driven:
hw_driven:     resd HW_BUCKETS            ; contiguous, hw_scan clears all three
hw_over_driven: resd HW_BUCKETS
alignb 8
hw_list:       resb HW_LIST_MAX * HW_DEV_ENT
hw_num:        resb 24
hw_log_buf:    resb HW_LOG_CAP
hw_boot_complete: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_svc_hw_report_0_bss1

hw_class_names:                       ; HW_C_* order, 8 bytes each
    db "summary", 0
    db "cpu", 0, 0, 0, 0, 0
    db "gpu", 0, 0, 0, 0, 0
    db "nic", 0, 0, 0, 0, 0
    db "storage", 0
    db "usb", 0, 0, 0, 0, 0
    db "input", 0, 0, 0
    db "battery", 0
    db "system", 0, 0
    db "memory", 0, 0
    db "mca", 0, 0, 0, 0, 0
    db "mcactl", 0, 0
    db "mcaaux", 0, 0
    db "mcarte", 0, 0
    db "mcalog", 0, 0
    db "aerq", 0, 0, 0, 0
    db "mcgctl", 0, 0
    db "drivers", 0
    db "bindsys", 0
    db "bindvmd", 0
    db "bindusb", 0
    db "bindaud", 0
    db "bindreg", 0
    db "bindcpu", 0
    db "drvops", 0, 0
hw_summary_classes: db HW_C_GPU, HW_C_NIC, HW_C_STORAGE, HW_C_USB
str_hw_head:       db " hw=", 0
str_hw_space:      db " ", 0
str_hw_comma:      db ",", 0
str_hw_colon:      db ":", 0
str_hw_dot:        db ".", 0
str_hw_eq:         db "=", 0
str_hw_slash:      db "/", 0
str_hw_x:          db "x", 0
str_hw_dash:       db "-", 0
str_hw_0x:         db "0x", 0
str_hw_zero:       db "0", 0
str_hw_one:        db "1", 0
str_hw_none:       db "none", 0
str_hw_unknown:    db "unknown", 0
str_hw_other:      db "other", 0
str_hw_intel:      db "intel", 0
str_hw_amd:        db "amd", 0
str_hw_ok:         db "ok", 0
str_hw_degraded:   db "degraded", 0
str_hw_dead:       db "dead", 0
str_hw_hexdig:     db "0123456789abcdef"
str_hw_n:          db " n=", 0
str_hw_dev:        db " dev=", 0
str_hw_unusable:   db ",unusable", 0
str_hw_more:       db " more=", 0
str_hw_unclaimed:  db " unclaimed_pci=", 0
str_hw_snapshot:   db " snapshot=boot", 0   ; devices: the boot sweep; claims: bind time
str_hw_sys_state:   db " smbios_state=", 0
str_hw_sys_present: db " bios_present=", 0
str_hw_sys_vendor:  db " bios_vendor_hex=", 0
str_hw_sys_version: db " bios_version_hex=", 0
str_hw_sys_date:    db " bios_date_hex=", 0
str_hw_sys_clipped: db " bios_clipped=", 0
str_hw_sys_hpq:     db " hp_quirk_identity=", 0
str_hw_sys_scope:   db " bios_encoding=ascii_sanitized_hex bios_cap=63 snapshot=pre_ebs", 0
str_hw_m_state: db " dimm_state=", 0
str_hw_m_clip_state: db "clipped", 0
str_hw_m_partial: db "partial", 0
str_hw_m_absent: db "absent", 0
str_hw_m_invalid: db "invalid", 0
str_hw_m_empty: db "empty", 0
str_hw_m_complete: db " dimm_complete=", 0
str_hw_m_seen: db " dimm_seen=", 0
str_hw_m_stored: db " dimm_stored=", 0
str_hw_m_unknown: db " dimm_unknown=", 0
str_hw_m_clipped: db " dimm_clipped=", 0
str_hw_m_installed: db " installed_bytes=", 0
str_hw_m_dimm: db " dimm=", 0
str_hw_m_map_state: db " map_state=", 0
str_hw_m_map_desc: db " map_desc=", 0
str_hw_m_conventional: db " map_conventional_bytes=", 0
str_hw_m_loader_boot: db " map_loader_boot_bytes=", 0
str_hw_m_scope: db " dimm_encoding=ascii_sanitized_hex dimm_name_cap=31 dimm_bank_cap=15 dimm_cap=4 snapshot=pre_ebs map_scope=saved_efi_types allocator_free=unknown", 0
str_hw_s_cpu:      db " cpu=", 0
str_hw_s_threads:  db " threads=", 0
str_hw_s_input:    db " input=", 0
str_hw_s_battery:  db " battery=", 0
str_hw_c_vendor:   db " vendor=", 0
str_hw_c_family:   db " family=", 0
str_hw_c_model:    db " model=", 0
str_hw_c_stepping: db " stepping=", 0
str_hw_c_brand:    db " brand=", 0
str_hw_c_packages: db " packages=", 0
str_hw_c_cores:    db " cores=", 0
str_hw_c_tpc:      db " threads_per_core=", 0
str_hw_c_online:   db " online=", 0
str_hw_c_hv:       db " hypervisor=", 0
str_hw_g_native:   db " native_driver=none", 0
str_hw_g_display:  db " display=", 0
str_hw_g_gop:      db "gop:", 0
str_hw_n_usb:      db " usb_nic=", 0
str_hw_n_if:       db " if=", 0
str_hw_ax88179:    db "ax88179", 0
str_hw_ax88179b:   db "ax88179b", 0
str_hw_cdc_ecm:    db "cdc_ecm", 0
str_hw_cdc_ncm:    db "cdc_ncm", 0
str_hw_st_usb:     db " usb_storage=", 0
str_hw_st_blocks:  db " blocks=", 0
str_hw_i_kbd:      db "kbd:", 0
str_hw_i_mouse:    db ",mouse:", 0
str_hw_i_hid:      db ",usb_hid:", 0
str_hw_i_host:     db ",usb_host:", 0
str_hw_i_i2c:      db " i2c_hid=none serial_io", 0
str_hw_b_driver:   db " driver=", 0
str_hw_b_present:  db " present=", 0
str_hw_ec_power:   db "ec_power", 0
str_hw_log_head:   db "[hw.report]", 0
str_hw_kat_pass:   db "[hw.report.kat] pass", 13, 10, 0
str_hw_kat_fail:   db "[hw.report.kat] FAIL", 13, 10, 0
str_hw_log_fail:   db " hw=? err=does_not_fit", 0
str_hw_kat_nic_upper:  db "NIC", 0
str_hw_kat_bogus:      db "nics", 0
str_hw_kat_brand_in:   db "  Intel(R) Core(TM)  i7-8700T CPU @ 2.40GHz  ", 0
str_hw_kat_brand_out:  db "Intel(R)_Core(TM)_i7-8700T_CPU_@_2.40GHz", 0
str_hw_kat_long:       db " hw=x", 0
str_hw_kat_hex:        db "80861d", 0
