;; MODULE boot/paging
;; LAYER 0
;; EXPORTS exit_boot_and_page, preebs_wdt_arm, preebs_wdt_status, wx_test_page, heap_base, heap_size, model_heap_base, model_heap_size, model_heap_alloc_base, model_heap_alloc_size, mmap_buffer, mmap_size, mmap_desc_size, diag_ring_base, crash_identity_base, filmstrip_ring_base, pmod_region_base, pmod_region_phys, pmod_pt_addr, pmod_sandbox_pml4, vmd_ecam_phys, vmd_window_gb, vmd_root_bdf_boot, fb_shadow_region_base, fb_shadow_region_size, paging_xhci_bar_mapped, paging_nvme_bar_mapped, paging_pd_entry_ptr, inv_top_of_ram, paging_fb_unmapped, paging_fb_gop_base, pbm_runtime_read_mapped, paging_hda_count, paging_hda_overflow, paging_hda_bars, paging_hda_bdfs, hp_mapping_reserve, hp_mapping_probe, hp_mapping_page
;; IMPORTS boot/model_preload, boot/boot_menu, boot/serial, boot/header, boot/boot_v2_handoff, boot/boot_v2_health, boot/gop, core/reset_wipe
;; CAPS
;; OWNER saga:boot
; ============================================================================
; boot/paging.asm — leave UEFI Boot Services + install our own page tables.
;
; A REWRITE block (BLOCKS.md), not a port — but the EBS + identity-map MECHANISM
; is ported from the old tree's proven exit_boot_services (the AllocatePool /
; GetMemoryMap / EBS-with-retry / CR3 sequence works on OVMF + bare metal). The
; old tree's later-feature cruft (EFI crash counter, CMOS phase-D/E recovery,
; chainload) is intentionally dropped — those are M5 boot-canon, not M1.
;
; STEP 1 (this file, now): EBS + identity map (0-16 GiB, 2 MiB pages) + load CR3.
;   Pages are RW+X for now (0x83) — NOT yet W^X.
; STEP 2 (next): W^X marking — EFER.NXE + CR0.WP, image code+rodata R+X, a fixed
;   BSS region + heap/dma/stacks RW+NX, MMIO RW+NX+UC, + a W^X self-test
;   (MEMORY_MAP §3.1 realized model). Left as the next increment so STEP 1 is
;   independently verifiable.
;
; EFI_BOOT_SERVICES offsets: AllocatePool +0x40, GetMemoryMap +0x38,
;   ExitBootServices +0xE8 (UEFI spec).
; ============================================================================

; ===========================================================================
; 1249 goal 2 — exact-range framebuffer cache policy in PaOS's own tables.
; ===========================================================================
; fb_pat_program — IA32_PAT with PA1 = WC (Linux layout for PA0-3: WB WC UC- UC;
;   the upper half keeps the architectural default). Full SDM sequence: CD=1,
;   WBINVD, TLB flush, WRMSR, WBINVD, CD=0. Runs on the BSP just before the CR3
;   load; core/smp mirrors the same value in the AP trampoline. No PAT -> no-op.
fb_pat_program:
    push rbx
    mov  eax, 1
    cpuid
    bt   edx, 16                        ; CPUID.01H:EDX.PAT
    jnc  .done
    mov  rax, cr0
    or   rax, (1 << 30)                 ; CD
    and  rax, ~(1 << 29)                ; NW = 0
    mov  cr0, rax
    wbinvd
    mov  rax, cr3
    mov  cr3, rax
    mov  ecx, 0x277
    mov  eax, 0x00070106                ; PA0 WB, PA1 WC, PA2 UC-, PA3 UC
    mov  edx, 0x00070406                ; PA4 WB, PA5 WT, PA6 UC-, PA7 UC
    wrmsr
    wbinvd
    mov  rax, cr0
    and  rax, ~(1 << 30)
    mov  cr0, rax
    mov  byte [rel fb_pat_programmed], 1
.done:
    pop  rbx
    ret

; fb_apply_cache_policy — pre-EBS, after gop_revalidate_record: give the exact
;   page-rounded framebuffer range its own cache policy in the tables about to
;   go live. Fully covered 2 MiB identity entries get the attribute; a partially
;   covered 2 MiB entry is split into a 4 KiB table (two spare pages) so no
;   adjacent RAM/MMIO/heap page inherits the framebuffer policy. WC = PAT index 1
;   (PWT) once fb_pat_program runs; without PAT the range is UC- (PCD). Ranges
;   this map does not cover are left untouched and reported as memtype 0.
fb_apply_cache_policy:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  dword [rel gop_fb_memtype], 0
    mov  dword [rel gop_fb_pages_2m], 0
    mov  dword [rel gop_fb_pages_4k], 0
    mov  dword [rel gop_fb_range_exact], 0
    mov  rax, [rel fb_base]
    test rax, rax
    jz   .out
    mov  rcx, [rel fb_size]
    test rcx, rcx
    jz   .out
    mov  r12, rax
    and  r12, ~0xFFF                    ; page-rounded start
    lea  r13, [rax + rcx + 0xFFF]
    and  r13, ~0xFFF                    ; page-rounded exclusive end
    mov  eax, 1
    cpuid
    mov  r15d, (1 << 3)                 ; PWT -> PAT index 1 (WC after fb_pat_program)
    mov  dword [rel gop_fb_memtype], 1
    bt   edx, 16
    jc   .have_attr
    mov  r15d, (1 << 4)                 ; no PAT: PCD -> UC-
    mov  dword [rel gop_fb_memtype], 2
.have_attr:
    mov  r14, r12
    and  r14, ~0x1FFFFF                 ; first 2 MiB entry touched
.big:
    cmp  r14, r13
    jae  .done
    mov  rax, r14
    shr  rax, 39
    jnz  .abort                         ; only the low 512 GiB are this map's
    mov  rbx, [rel pml4_addr]
    mov  rbx, [rbx]
    test bl, 1
    jz   .abort
    mov  r11, 0x000FFFFFFFFFF000
    and  rbx, r11                       ; PDPT
    mov  rax, r14
    shr  rax, 30
    and  eax, 511
    mov  rbx, [rbx + rax*8]
    test bl, 1
    jz   .abort                         ; not identity-mapped here: leave it alone
    test bl, 0x80
    jnz  .abort                         ; a 1 GiB page is not this map's shape
    and  rbx, r11                       ; PD
    mov  rax, r14
    shr  rax, 21
    and  eax, 511
    lea  rbx, [rbx + rax*8]             ; rbx = &PD[idx]
    mov  rdx, [rbx]
    test dl, 1
    jz   .abort
    cmp  r14, r12
    jb   .partial
    lea  rax, [r14 + 0x200000]
    cmp  rax, r13
    ja   .partial
    ; --- fully covered 2 MiB entry ---
    test dl, 0x80
    jz   .full_pt
    or   rdx, r15
    mov  [rbx], rdx
    inc  dword [rel gop_fb_pages_2m]
    jmp  .next
.full_pt:
    and  rdx, r11                       ; an existing 4 KiB table: attribute every PTE
    xor  ecx, ecx
.fpt:
    cmp  ecx, 512
    jae  .next
    or   [rdx + rcx*8], r15
    inc  ecx
    jmp  .fpt
.partial:
    test dl, 0x80
    jz   .have_pt                       ; already a 4 KiB table (e.g. the image split)
    mov  eax, [rel fb_pt_used]
    cmp  eax, 2
    jae  .abort                         ; two spare tables only: never steal another page
    inc  dword [rel fb_pt_used]
    mov  r8, [rel pml4_addr]
    add  r8, 0x14000                    ; spare PT pages after PML4, PDPT, 16 PDs, 2 fb PDs
    shl  rax, 12
    add  r8, rax                        ; r8 = the new PT (zeroed with the pool)
    mov  r9, rdx
    mov  rax, 0x000FFFFFFFE00000
    and  r9, rax                        ; 2 MiB physical base
    mov  r10, rdx
    mov  rax, 0xFFF0000000000FFF
    and  r10, rax                       ; flag bits of the huge entry (P, RW, NX, ...)
    and  r10, ~0x80                     ; PS is not a PTE flag
    and  r10, ~(1 << 12)                ; the 2 MiB PAT bit position is address in a PTE
    xor  ecx, ecx
.split:
    cmp  ecx, 512
    jae  .split_done
    mov  rax, rcx
    shl  rax, 12
    add  rax, r9
    or   rax, r10
    mov  [r8 + rcx*8], rax
    inc  ecx
    jmp  .split
.split_done:
    mov  rax, r8
    or   rax, 0x03                      ; Present | RW table pointer (no PS)
    mov  [rbx], rax
    mov  rdx, rax
.have_pt:
    and  rdx, r11                       ; rdx = PT
    xor  ecx, ecx
.ppt:
    cmp  ecx, 512
    jae  .next
    mov  rax, rcx
    shl  rax, 12
    add  rax, r14                       ; page address
    cmp  rax, r12
    jb   .ppt_next
    cmp  rax, r13
    jae  .ppt_next
    or   [rdx + rcx*8], r15
    inc  dword [rel gop_fb_pages_4k]
.ppt_next:
    inc  ecx
    jmp  .ppt
.next:
    add  r14, 0x200000
    jmp  .big
.done:
    mov  dword [rel gop_fb_range_exact], 1
    jmp  .report
.abort:
    mov  dword [rel gop_fb_memtype], 0
.report:
    lea  rdi, [rel str_fb_policy]
    call serial_string
    mov  edi, [rel gop_fb_memtype]
    call serial_hex64
    lea  rdi, [rel str_fb_policy_2m]
    call serial_string
    mov  edi, [rel gop_fb_pages_2m]
    call serial_hex64
    lea  rdi, [rel str_fb_policy_4k]
    call serial_string
    mov  edi, [rel gop_fb_pages_4k]
    call serial_hex64
    lea  rdi, [rel str_fb_nl]
    call serial_string
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; --- pre-ExitBootServices watchdog (MSI spoke handoff 6a, admin 2026-10-01 12:25) ---
; UEFI SetWatchdogTimer (EFI_BOOT_SERVICES +0x100): Timeout seconds (0 disarms),
; WatchdogCode (0x0000-0xFFFF are the firmware's; PaOS uses 0x10001), DataSize 0,
; WatchdogData NULL. On expiry the firmware resets the platform. Both helpers
; align their own frame (callable from any residue) and preserve everything but
; the UEFI volatile registers.
%ifndef PREEBS_WDT_S
PREEBS_WDT_S        equ 300             ; = the spec's boot-manager default, now owned by PaOS
%endif
PREEBS_WDT_CODE     equ 0x10001
preebs_wdt_arm:
    mov  ecx, PREEBS_WDT_S
preebs_wdt_set:
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    sub  rsp, 32
    mov  rax, [rel boot_services]
    test rax, rax
    jz   .out
    mov  edx, PREEBS_WDT_CODE
    xor  r8d, r8d                       ; DataSize
    xor  r9d, r9d                       ; WatchdogData
    call [rax + 0x100]                  ; SetWatchdogTimer
    mov  [rel preebs_wdt_status], rax
.out:
    mov  rsp, rbp
    pop  rbp
    ret

exit_boot_and_page:
    push rbx
    push r12
    push r13
    sub rsp, 40                         ; shadow space (32) + 1 stack arg slot, 16-aligned

    ; Size the identity map from the firmware's RAM/runtime inventory. The
    ; historical 16 GiB map remains the floor; systems whose RAM crosses that
    ; boundary receive one additional PD per GiB, capped at one 512 GiB PDPT.
    ; Proven on the Dell 5490, whose top of RAM is about 16.73 GiB.
    call paging_inventory_extent

    ; --- allocate page-table memory while Boot Services are still up ---
    ; Keep the fixed 25-page layout unchanged, then append one PD per GiB over
    ; the 16 GiB floor and PAGING_XHCI_PDS xHCI MMIO PDs (RCQ-09 slice 2). Allocate below 4 GiB because
    ; the AP trampoline patches
    ; only the low 32 bits of CR3 (core/smp.asm). Append two private NVMe
    ; pages (PDPT + PD) AFTER the existing allocation; no fixed offset moves.
    ; One final original PT splits the low
    ; 2 MiB so the SIPI code at 0x8000 stays executable after image relocation.
    mov rax, [rel ident_gib]
    sub rax, 16
    add rax, 26 + PAGING_XHCI_PDS + 2
    mov [rel pt_alloc_pages], rax
    mov rax, 0xFFFFFFFF
    mov [rel pt_alloc_buf], rax
    mov rax, [rel boot_services]
    mov ecx, 1                          ; AllocateMaxAddress
    mov edx, 2                          ; EfiLoaderData
    mov r8, [rel pt_alloc_pages]
    lea r9, [rel pt_alloc_buf]
    call [rax + 0x28]                   ; AllocatePages(type, memtype, pages, &addr)
    test rax, rax
    jnz exit_boot_and_page_fail

    mov rax, [rel pt_alloc_buf]         ; page-aligned by construction
    mov [rel pml4_addr], rax
    mov r12, rax                        ; r12 = PML4 base

    mov rdi, r12                        ; zero fixed tables plus appended RS-1 PDs
    mov rcx, [rel pt_alloc_pages]
    shl rcx, 9                          ; pages * 4096 / 8 qwords
    xor eax, eax
    rep stosq

    ; PML4[0] -> PDPT (+0x1000)
    lea rax, [r12 + 0x1000]
    or  rax, 0x03                       ; Present | RW
    mov [r12], rax

    ; PDPT[0..15] -> PD0..PD15 (each PD at +0x2000 + i*0x1000)
    lea rbx, [r12 + 0x1000]
    xor ecx, ecx
.pdpt:
    cmp ecx, 16
    jge .pdpt_done
    mov eax, ecx
    shl rax, 12
    add rax, r12
    add rax, 0x2000
    or  rax, 0x03                       ; Present | RW
    mov [rbx + rcx*8], rax
    inc ecx
    jmp .pdpt
.pdpt_done:

    ; PD0..PD15: 8192 * 2 MiB pages = 16 GiB identity.
    ; W^X (STEP 2): every page gets NX (bit 63) EXCEPT the 2 MiB page(s) that
    ; overlap the image range reported by EFI_LOADED_IMAGE.  Direct firmware
    ; launches normally use the preferred 1 MiB base, but a child StartImage is
    ; routinely relocated because the standalone Manager already occupies it.
    ; Assuming entry zero is executable makes such a child triple-fault at CR3.
    ; The "code is read-only" half still needs a 4 KiB split of the image pages.
    lea rbx, [r12 + 0x2000]
    xor ecx, ecx                        ; entry index
    xor r13, r13                        ; phys addr
.pd:
    cmp ecx, 8192
    jge .pd_done
    mov rax, r13
    or  rax, 0x83                       ; Present | RW | PS (2 MiB)
    mov rdx, [rel pbm_image_size]
    test rdx, rdx
    jz  .pd_legacy_image
    mov rdx, [rel pbm_image_base]
    and rdx, ~0x1FFFFF                  ; first executable 2 MiB page
    cmp r13, rdx
    jb  .pd_nx
    mov rdx, [rel pbm_image_base]
    add rdx, [rel pbm_image_size]
    add rdx, 0x1FFFFF
    and rdx, ~0x1FFFFF                  ; exclusive end page
    cmp r13, rdx
    jb  .pd_x
.pd_nx:
    bts rax, 63                         ; NX — data/heap/stack/mmio not executable
    jmp .pd_x
.pd_legacy_image:
    test ecx, ecx
    jz  .pd_x                           ; defensive fallback for no LoadedImage
    bts rax, 63
.pd_x:
    mov [rbx + rcx*8], rax
    add r13, 0x200000
    inc ecx
    jmp .pd
.pd_done:

    ; The AP enables this CR3 while still executing its SIPI trampoline at
    ; 0x8000. A relocated image can make PDE0 NX, so split that PDE using the
    ; final allocated PT. Preserve its existing permissions on all 512 pages;
    ; only the actual trampoline page gains execute permission. The BSP copies
    ; and patches this page immediately before INIT/SIPI (core/smp.asm).
    mov rdx, [rel pt_alloc_pages]
    dec rdx
    shl rdx, 12
    add rdx, r12                        ; final PT; fixed/RS-1/xHCI offsets unchanged
    mov r8, [r12 + 0x2000]
    and r8, ~0x80                       ; clear huge-page PS (not a 4 KiB flag)
    xor ecx, ecx
.sipi_pt:
    mov rax, rcx
    shl rax, 12
    or  rax, r8
    mov [rdx + rcx*8], rax
    inc ecx
    cmp ecx, 512
    jb .sipi_pt
    btr qword [rdx + (0x8000 >> 12)*8], 63
    mov rax, rdx
    or  rax, 3
    mov [r12 + 0x2000], rax             ; parent NX clear; leaves own execution

    ; GiB 16 .. ident_gib-1. Extra PDs live after the fixed block at +0x19000,
    ; preserving every historical framebuffer/VMD table offset. Data is NX;
    ; only pages overlapping the loaded image remain executable.
    mov r13, 16
.rs1_gib:
    cmp r13, [rel ident_gib]
    jae .rs1_done
    mov rax, r13
    sub rax, 16
    shl rax, 12
    lea rbx, [r12 + 0x19000]
    add rbx, rax
    lea rax, [r12 + 0x1000]
    mov rdx, rbx
    or  rdx, 0x03
    mov [rax + r13*8], rdx
    mov rdx, r13
    shl rdx, 30
    xor ecx, ecx
.rs1_pd:
    cmp ecx, 512
    jge .rs1_next
    mov rax, rdx
    or  rax, 0x83
    push rcx
    mov rcx, [rel pbm_image_size]
    test rcx, rcx
    jz  .rs1_nx
    mov rcx, [rel pbm_image_base]
    and rcx, ~0x1FFFFF
    cmp rdx, rcx
    jb  .rs1_nx
    mov rcx, [rel pbm_image_base]
    add rcx, [rel pbm_image_size]
    add rcx, 0x1FFFFF
    and rcx, ~0x1FFFFF
    cmp rdx, rcx
    jb  .rs1_x
.rs1_nx:
    bts rax, 63
.rs1_x:
    pop rcx
    mov [rbx + rcx*8], rax
    add rdx, 0x200000
    inc ecx
    jmp .rs1_pd
.rs1_next:
    inc r13
    jmp .rs1_gib
.rs1_done:

    ; --- map the GOP framebuffer's region if it lands outside the 16 GiB map ---
    ; OVMF can place the fb's 64-bit PCI BAR high (observed ~16.75 GiB on QEMU).
    ; Map the 2 GiB window containing fb_base with NX 2 MiB pages (fb is data/MMIO,
    ; never executed), using the 2 spare PDs (pages 18-19). gop_query already ran.
    ; (WB for now; a real fb wants WC — TODO. fb<16GiB is already mapped → skip.)
    mov rax, [rel fb_base]
    ; DISPLAY (disp_gop): the GOP base as adopted, recorded BEFORE the revalidation
    ; below and any headless zeroing, so disp_gop may differ from disp_fb (the base
    ; actually used) when revalidation moves or drops the framebuffer.
    mov [rel paging_fb_gop_base], rax
    test rax, rax
    jz  .fb_done
    mov r13, rax
    shr r13, 30                         ; r13 = GiB index of fb_base
    cmp r13, [rel ident_gib]
    jb  .fb_done                        ; already covered by the inventory-sized map
    ; The 2 GiB window takes PDPT[gb] and PDPT[gb+1] of the one low PDPT. At GiB
    ; 511 or above that would write past the PDPT page into PD0 (the low identity
    ; map) and leave the framebuffer unmapped. Map nothing; run headless: fb_base and
    ; the geometry go to 0 as without a GOP (every consumer checks fb_base first;
    ; fb_bpp/format/output flags keep their values). Large discrete-GPU BARs sit there.
    cmp r13, 511
    jae .fb_unmappable
    lea rbx, [r12 + 0x1000]             ; PDPT
    lea rax, [r12 + 0x12000]            ; fb_pd_0 (page 18)
    or  rax, 0x03
    mov [rbx + r13*8], rax              ; PDPT[gb] -> fb_pd_0
    lea rax, [r12 + 0x13000]            ; fb_pd_1 (page 19)
    or  rax, 0x03
    mov [rbx + r13*8 + 8], rax          ; PDPT[gb+1] -> fb_pd_1
    mov rdx, r13
    shl rdx, 30                         ; phys base = gb << 30
    lea rbx, [r12 + 0x12000]            ; fb_pd_0 (fb_pd_1 is contiguous at +0x1000)
    xor ecx, ecx
.fbpd:
    cmp ecx, 1024                       ; 2 PDs * 512 = 2 GiB of 2 MiB pages
    jge .fb_done
    mov rax, rdx
    or  rax, 0x83                       ; Present | RW | PS
    bts rax, 63                         ; NX
    mov [rbx + rcx*8], rax
    add rdx, 0x200000
    inc ecx
    jmp .fbpd
.fb_unmappable:
    xor eax, eax
    mov [rel fb_base], rax
    mov [rel fb_width], eax
    mov [rel fb_height], eax
    mov [rel fb_stride], eax
    mov [rel fb_size], rax
    mov byte [rel paging_fb_unmapped], 1
.fb_done:

    ; --- Intel VMD (2026-09-08): map the 2 GiB window holding the VMD root's
    ;     CFGBAR (child ECAM) and MEMBAR2 when firmware placed them above the
    ;     16 GiB identity map (MSI Z890: CFGBAR 0x7020000000, MEMBAR2
    ;     0x7022000000). Bus 0 only (a VMD root is a Root Complex Integrated
    ;     Endpoint), inline CF8/CFC reads (layer 1 imports no bus/pci), loose
    ;     class 0104 / vendor 8086 match; dev/blk/vmd does the strict device-ID
    ;     match post-EBS and refuses an unmapped ECAM loudly. Uses the 2 spare
    ;     VMD PDs (pages 22-23); PCD set so config/device MMIO is uncached.
    xor r13d, r13d                      ; r13 = bus-0 device 0..31, fn 0
.vmd_scan:
    cmp r13d, 32
    jae .vmd_done
    mov eax, r13d
    shl eax, 11
    or  eax, 0x80000000                 ; CONFIG_ADDRESS: bus 0, dev, fn 0, offset 0
    mov edx, 0xCF8
    out dx, eax
    mov edx, 0xCFC
    in  eax, dx                         ; vendor | device
    cmp ax, 0x8086
    jne .vmd_next
    mov eax, r13d
    shl eax, 11
    or  eax, 0x80000008                 ; offset 8 = class
    mov edx, 0xCF8
    out dx, eax
    mov edx, 0xCFC
    in  eax, dx
    shr eax, 8
    cmp eax, 0x010400                   ; class 01 / subclass 04 / progIF 00
    jne .vmd_next
    mov eax, r13d
    shl eax, 11
    or  eax, 0x80000010                 ; BAR0 low
    mov edx, 0xCF8
    out dx, eax
    mov edx, 0xCFC
    in  eax, dx
    mov ebx, eax
    test bl, 0x01
    jnz .vmd_next                       ; I/O BAR: not a CFGBAR
    mov eax, r13d
    shl eax, 11
    or  eax, 0x80000014                 ; BAR0 high (64-bit type only)
    mov edx, 0xCF8
    out dx, eax
    mov edx, 0xCFC
    in  eax, dx
    mov ecx, ebx
    and ecx, 0x06
    cmp ecx, 0x04                       ; 10b = 64-bit memory BAR
    je  .vmd_64
    xor eax, eax
.vmd_64:
    shl rax, 32
    and ebx, 0xFFFFFFF0
    or  rax, rbx                        ; rax = CFGBAR physical base
    mov [rel vmd_ecam_phys], rax
    mov edx, r13d
    shl edx, 8                          ; bdf = bus 0 << 16 | dev << 8 | fn 0
    mov [rel vmd_root_bdf_boot], edx
    mov r13, rax
    shr r13, 30                         ; GiB index
    cmp r13, [rel ident_gib]
    jb  .vmd_done                       ; already inside the inventory-sized map
    cmp r13, 511
    jae .vmd_done                       ; PDPT[gb+1] must stay in the low PDPT; vmd.asm refuses on window 0
    lea rbx, [r12 + 0x1000]             ; PDPT
    cmp qword [rbx + r13*8], 0
    jne .vmd_done                       ; an existing entry (fb window): leave it
    cmp qword [rbx + r13*8 + 8], 0
    jne .vmd_done
    lea rax, [r12 + 0x16000]            ; vmd_pd_0 (page 22)
    or  rax, 0x03
    mov [rbx + r13*8], rax
    lea rax, [r12 + 0x17000]            ; vmd_pd_1 (page 23)
    or  rax, 0x03
    mov [rbx + r13*8 + 8], rax
    mov [rel vmd_window_gb], r13
    mov rdx, r13
    shl rdx, 30                         ; phys base = gb << 30
    lea rbx, [r12 + 0x16000]            ; vmd_pd_0 (vmd_pd_1 is contiguous at +0x1000)
    xor ecx, ecx
.vmdpd:
    cmp ecx, 1024                       ; 2 PDs * 512 = 2 GiB of 2 MiB pages
    jge .vmd_done
    mov rax, rdx
    or  rax, 0x93                       ; Present | RW | PCD (uncached MMIO) | PS
    bts rax, 63                         ; NX
    mov [rbx + rcx*8], rax
    add rdx, 0x200000
    inc ecx
    jmp .vmdpd
.vmd_next:
    inc r13d
    jmp .vmd_scan
.vmd_done:
    call paging_xhci_map_high_bar

; Define here for paging ownership, emit after GOP's layout-sensitive mode list.
%macro PAGING_XHCI_HIGH_MAP 0
; paging_xhci_map_high_bar — identity-map every xHCI MMIO BAR the 16 GiB / RAM
;   map does not cover (RCQ-09 slice 2: AMD boxes such as the Reatan expose four
;   xHCIs behind root-port bridges on buses other than 0; the Beelink PCH 51ED
;   sits at 0x607e180000). Each BAR's 2 MiB page is mapped UC+NX through up to
;   PAGING_XHCI_PDS PD pages appended after the high-RAM PDs (every historical
;   fixed paging-table offset is unchanged). A PDPT entry someone else owns
;   (framebuffer, VMD, RAM) is never overwritten; a BAR that needs a fifth PD,
;   lies at or above 512 GiB (QEMU's ~768 GiB) or whose 256 KiB aperture crosses
;   its 2 MiB page stays unmapped: the bring-up then skips that controller or,
;   for the first one only, uses its guarded low-RAM relocation. Buses are
;   walked up to the highest subordinate bus any bridge reports, with the same
;   function-0 / multi-function rule as pci_scan_with_filter. Reads only.
;   In: R12 = PML4 base. Preserves RBX, RBP, R12-R15.
; RCQ-36 extends this walk with Intel/AMD class 040300/040380: retain up to 32 BARs,
; then retag eligible identity PDEs or use spare high-MMIO pool pages after
; xHCI ownership is known. Up to 64 xHCI aperture endpoints; either list's
; exhaustion refuses all HDA mappings. No allocation/split or xHCI map_one change.
paging_xhci_map_high_bar:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    xor  r14d, r14d                      ; xHCI PD pages used
    xor  r15d, r15d                      ; bus << 8 | dev << 3 | fn
    xor  ebp, ebp                        ; highest bus to walk (bridges raise it)
    mov  dword [rel paging_nvme_found], 0
    mov  qword [rel paging_nvme_bar], 0
    mov  qword [rel paging_nvme_proven], 0
    mov  dword [rel paging_hda_pd_used], 0
    mov  dword [rel paging_hda_count], 0
    mov  dword [rel paging_hda_xhci_count], 0
    mov  dword [rel paging_hda_overflow], 0
    mov  dword [rel paging_hda_high_proven], 0
    %ifidn RCQ50_G0_FLR_LAB,1
    mov  dword [rel paging_flr_count], 0
    mov  dword [rel paging_flr_bar], 0
    %endif
.scan:
    mov  eax, r15d
    shr  eax, 8
    cmp  eax, ebp
    ja   .done
    cmp  r15d, 0x10000
    jae  .done
    mov  eax, r15d
    shl  eax, 8
    or   eax, 0x80000000
    mov  edx, 0xCF8
    out  dx, eax
    mov  edx, 0xCFC
    in   eax, dx
    cmp  ax, 0xFFFF
    jne  .present
    test r15d, 7
    jnz  .next_fn
    add  r15d, 8                         ; no function 0: no device
    jmp  .scan
.present:
    mov  eax, r15d                       ; header type (0x0C byte 2)
    shl  eax, 8
    or   eax, 0x8000000C
    mov  edx, 0xCF8
    out  dx, eax
    mov  edx, 0xCFC
    in   eax, dx
    shr  eax, 16
    mov  ebx, eax                        ; BL = header type (bit 7 multi-function)
    mov  ecx, ebx
    and  ecx, 0x7F
    cmp  ecx, 1                          ; PCI-to-PCI bridge: walk its buses
    jne  .class
    mov  eax, r15d
    shl  eax, 8
    or   eax, 0x80000018
    mov  edx, 0xCF8
    out  dx, eax
    mov  edx, 0xCFC
    in   eax, dx
    shr  eax, 16
    and  eax, 0xFF                       ; subordinate bus number
    cmp  eax, ebp
    jbe  .class
    mov  ebp, eax
.class:
    mov  eax, r15d
    shl  eax, 8
    or   eax, 0x80000008
    mov  edx, 0xCF8
    out  dx, eax
    mov  edx, 0xCFC
    in   eax, dx
    shr  eax, 8
    mov  r8d, eax                        ; class survives config reads
    cmp  eax, 0x010802                   ; same first legacy NVMe as native detect
    je   .nvme_class
    %ifidn RCQ50_G0_FLR_LAB,1
    ; RCQ-50 G0 (lab only): pci_assign's pinned FLR endpoint (PCIA_FLR_VENDEV, class
    ; 020000) gets the same UC+NX retag and whole-page non-RAM proof as an HDA BAR,
    ; after the walk; never the HDA list (hda_boot_handoff reads it). Every match is
    ; counted: more than one, or a BAR0 that is not 32-bit non-prefetchable memory,
    ; maps nothing, and pci_assign then refuses the attach (err 6).
    cmp  eax, 0x020000
    jne  .flr_skip
    mov  eax, r15d
    shl  eax, 8
    or   eax, 0x80000000
    mov  edx, 0xCF8
    out  dx, eax
    mov  edx, 0xCFC
    in   eax, dx
    cmp  eax, 0x10C98086                 ; == PCIA_FLR_VENDEV (hv/pci_assign)
    jne  .flr_class
    inc  dword [rel paging_flr_count]
    mov  dword [rel paging_flr_bar], 0
    mov  eax, r15d
    shl  eax, 8
    or   eax, 0x80000010
    mov  edx, 0xCF8
    out  dx, eax
    mov  edx, 0xCFC
    in   eax, dx
    test al, 0x0F                        ; memory, 32-bit, non-prefetchable
    jnz  .advance
    mov  [rel paging_flr_bar], eax
    jmp  .advance
.flr_class:
    mov  eax, r8d
.flr_skip:
    %endif
    and  eax, 0xFFFF7F                   ; HDA progIF00 or observed progIF80 only
    cmp  eax, 0x040300                   ; HDA shares this SAME PCI walk
    je   .hda_class
    mov  eax, r8d                       ; xHCI retains its exact raw progIF
    cmp  eax, 0x0C0330                   ; real xHCI class/subclass/progIF
    jne  .advance
    jmp  .read_bar
.nvme_class:
    cmp  dword [rel paging_nvme_found], 0
    jne  .advance                       ; native selects the FIRST matching function
    mov  dword [rel paging_nvme_found], 1
    mov  [rel paging_nvme_bdf], r15d     ; retain identity even if its BAR is refused
    jmp  .read_bar
.hda_class:
    mov  r8d, 0x040300                   ; logical HDA tag after exact 00/80 admission
    mov  eax, r15d
    shl  eax, 8
    or   eax, 0x80000000
    mov  edx, 0xCF8
    out  dx, eax
    mov  edx, 0xCFC
    in   eax, dx
    cmp  ax, 0x8086
    je   .read_bar
    cmp  ax, 0x1022
    jne  .advance
.read_bar:
    mov  eax, r15d
    shl  eax, 8
    or   eax, 0x80000010
    mov  edx, 0xCF8
    out  dx, eax
    mov  edx, 0xCFC
    in   eax, dx
    mov  r13d, eax                       ; BAR0
    cmp  r8d, 0x010802
    je   .nonprefetch
    cmp  r8d, 0x040300
    jne  .bar_type
.nonprefetch:
    test r13b, 8                        ; HDA prefetchable BAR is refused
    jnz  .advance
.bar_type:
    test r13b, 1
    jnz  .advance                        ; I/O BAR is not MMIO
    xor  r10d, r10d
    and  eax, 0x06
    jz   .bar32
    cmp  eax, 0x04
    jne  .advance
    mov  eax, r15d
    shl  eax, 8
    or   eax, 0x80000014
    mov  edx, 0xCF8
    out  dx, eax
    mov  edx, 0xCFC
    in   eax, dx
    mov  r10d, eax
.bar32:
    shl  r10, 32
    and  r13d, 0xFFFFFFF0
    or   r10, r13
    test r10, r10
    jz   .advance
    cmp  r8d, 0x010802
    jne  .not_nvme
    mov  [rel paging_nvme_bar], r10
    jmp  .advance
.not_nvme:
    cmp  r8d, 0x040300
    je   .remember_hda
    ; Remember xHCI ownership even for low BARs the original mapper leaves
    ; unchanged. Defer HDA retags until the complete walk, so BDF order cannot
    ; allow an HDA page to steal a later xHCI's aperture. No second PCI scan.
    mov  ecx, [rel paging_hda_xhci_count]
    cmp  ecx, PAGING_HDA_XHCI_PAGES - 2
    ja   .owner_overflow
    mov  rdx, r10
    add  rdx, 0x3FFFF                   ; xHCI owns its complete 256 KiB aperture
    jc   .owner_overflow
    and  rdx, ~0x1FFFFF
    mov  rax, r10
    and  rax, ~0x1FFFFF
    lea  r9, [rel paging_hda_xhci_pages]
    mov  [r9 + rcx*8], rax
    mov  [r9 + rcx*8 + 8], rdx          ; both ends, even a crossing refused BAR
    add  dword [rel paging_hda_xhci_count], 2
    jmp  .xhci_map
.owner_overflow:
    mov  dword [rel paging_hda_overflow], 1
.xhci_map:
    call .map_one
    jmp  .advance
.remember_hda:
    mov  ecx, [rel paging_hda_count]
    cmp  ecx, PAGING_HDA_BARS
    jae  .hda_overflow
    lea  rax, [rel paging_hda_bars]
    mov  [rax + rcx*8], r10
    lea  rax, [rel paging_hda_bdfs]
    mov  [rax + rcx*4], r15d           ; exact boot function paired with BAR
    inc  dword [rel paging_hda_count]
    jmp  .advance
.hda_overflow:
    mov  dword [rel paging_hda_overflow], 1
.advance:
    test r15d, 7
    jnz  .next_fn
    test bl, 0x80
    jnz  .next_fn                        ; multi-function: walk functions 1..7
    add  r15d, 8
    jmp  .scan
.next_fn:
    inc  r15d
    jmp  .scan
.done:
    cmp  dword [rel paging_hda_overflow], 0
    jne  .restore
    mov  [rel paging_hda_pd_used], r14d ; xHCI gets first use of the fixed pool
    xor  ebp, ebp
.hda_pending:
    cmp  ebp, [rel paging_hda_count]
    %ifidn RCQ50_G0_FLR_LAB,1
    jae  .flr_map
    %else
    jae  .restore
    %endif
    lea  rax, [rel paging_hda_bars]
    mov  r10, [rax + rbp*8]
    call .hda_map_one
    inc  ebp
    jmp  .hda_pending
    %ifidn RCQ50_G0_FLR_LAB,1
.flr_map:
    cmp  dword [rel paging_flr_count], 1
    jne  .restore                        ; none, or more than one: never guess
    mov  r10d, [rel paging_flr_bar]      ; zero-extends a 32-bit BAR
    test r10, r10
    jz   .restore
    call .hda_map_one
    %endif
.restore:
    call .nvme_map                      ; independent finite mapping after other owners
    pop  r15
    pop  r14
    pop  r13
    pop  rbp
    pop  rbx
    ret

; R10 = BAR base. Clobbers RAX, RCX, RDX, R9, R11, R13.
.map_one:
    mov  r13, r10
    shr  r13, 30                        ; GiB index in this PDPT
    cmp  r13, [rel ident_gib]
    jb   .map_ret                       ; existing identity map
    cmp  r13, 512
    jae  .map_ret                       ; outside the low PML4 entry
    mov  rax, r10
    and  eax, 0x1FFFFF
    cmp  eax, 0x1C0000                  ; full 256 KiB aperture in one 2 MiB PDE
    ja   .map_ret
    mov  r9, [rel ident_gib]
    sub  r9, 16
    shl  r9, 12
    lea  r9, [r12 + r9 + 0x19000]       ; first appended xHCI PD page
    lea  r11, [r12 + 0x1000]            ; PDPT
    mov  rax, [r11 + r13*8]
    test rax, rax
    jz   .new_pd
    and  rax, ~0xFFF
    cmp  rax, r9
    jb   .map_ret                       ; never overwrite framebuffer/VMD/RAM
    lea  rdx, [r9 + PAGING_XHCI_PDS * 0x1000]
    cmp  rax, rdx
    jae  .map_ret
    mov  rdx, rax                       ; one of ours: add this BAR's PDE to it
    jmp  .pde
.new_pd:
    cmp  r14d, PAGING_XHCI_PDS
    jae  .map_ret                       ; out of PD pages: this BAR stays unmapped
    mov  edx, r14d
    shl  edx, 12
    add  rdx, r9
    inc  r14d
    mov  rax, rdx
    or   rax, 0x03
    mov  [r11 + r13*8], rax
.pde:
    mov  rax, r10
    shr  rax, 21
    and  eax, 511
    mov  rcx, r10
    and  rcx, ~0x1FFFFF
    or   rcx, 0x93                      ; P | RW | PCD | PS, uncached MMIO
    bts  rcx, 63                        ; NX
    mov  [rdx + rax*8], rcx
.map_ret:
    ret

; RCQ-36: pre-EBS HDA mapping with whole-page non-RAM inventory proof.
; The inventory buffer stays live; later UEFI allocations only change RAM's
; subtype, never its RAM/non-RAM partition (paging-owner guidance 20:49).
; Classic's native hda_init uses a 16 KiB controller aperture. No BAR sizing
; writes, new allocations, runtime retag or split. High BARs use only spare
; pages from the existing bounded xHCI MMIO PD pool, after the xHCI scan.
; The future CR3 install flushes these not-yet-active tables. Every refusal
; leaves their bytes intact; runtime's PCD+NX guard keeps HDA dormant.
.hda_map_one:
    push rbx
    push r13
    push r14
    push r15
    push rsi
    test r10, 0xFFF
    jnz  .hda_ret
    mov  eax, r10d
    and  eax, 0x1FFFFF
    cmp  eax, 0x1FC000                  ; full 16 KiB stays within this PDE
    ja   .hda_ret
    cmp  word [rel inv_flags], 0         ; neither fallback nor truncation
    jne  .hda_ret
    mov  r13, r10
    and  r13, ~0x1FFFFF                 ; candidate whole-page start/end
    lea  r14, [r13 + 0x200000]
    mov  rax, r10
    shr  rax, 30
    cmp  rax, 512
    jae  .hda_ret                       ; only the low PML4 entry is owned
    cmp  rax, 1
    je   .hda_ret                       ; PMOD owns the virtual 1..2 GiB window
    ; Reject VMD's complete owned two-GiB window, not just its root BAR.
    mov  rcx, [rel vmd_window_gb]
    test rcx, rcx
    jz   .hda_fb
    cmp  rax, rcx
    jb   .hda_fb
    add  rcx, 2
    cmp  rax, rcx
    jb   .hda_ret
.hda_fb:
    ; This snapshot precedes GOP revalidation. If a later mode change moved
    ; the framebuffer here, fb_apply_cache_policy's WC/PWT OR keeps PCD|PWT
    ; (UC): potentially slower rendering, never a WB alias of this MMIO page.
    mov  rax, [rel fb_base]
    mov  rcx, [rel fb_size]
    test rcx, rcx
    jz   .hda_xhci
    add  rcx, rax
    jc   .hda_ret
    cmp  rax, r14
    jae  .hda_xhci
    cmp  rcx, r13
    ja   .hda_ret
.hda_xhci:
    ; An xHCI aperture can share this page with HDA (Lenovo b1320000 /
    ; b1330000). Low xHCI discovery leaves the canonical identity leaf WB.
    ; Sharing UC policy changes neither physical translation nor driver
    ; custody. Both shared and unshared pages must pass the exact untouched
    ; PDPT/PDE and whole-page non-RAM proof below; owned leaves still refuse.
    xor  ecx, ecx
    lea  rdx, [rel paging_hda_xhci_pages]
.hda_owner:
    cmp  ecx, [rel paging_hda_xhci_count]
    jae  .hda_pd
    cmp  [rdx + rcx*8], r13
    je   .hda_pd                        ; shared low MMIO can use the same UC leaf
    inc  ecx
    jmp  .hda_owner
.hda_pd:
    ; Verify the PDPT still names the canonical identity PD. Never follow or
    ; overwrite a framebuffer/VMD/xHCI/foreign owner, even if it looks valid.
    mov  rax, r10
    shr  rax, 30
    cmp  rax, [rel ident_gib]
    jae  .hda_inventory                ; high mappings get the same non-RAM proof
    mov  rcx, rax
    cmp  rax, 16
    jb   .hda_low_pd
    sub  rax, 16
    shl  rax, 12
    lea  r15, [r12 + rax + 0x19000]
    jmp  .hda_have_pd
.hda_low_pd:
    shl  rax, 12
    lea  r15, [r12 + rax + 0x2000]
.hda_have_pd:
    mov  rax, r15
    or   rax, 3
    cmp  [r12 + rcx*8 + 0x1000], rax
    jne  .hda_ret
    mov  rax, r10
    shr  rax, 21
    and  eax, 511
    lea  r15, [r15 + rax*8]
    mov  rax, r13
    or   rax, 0x83
    bts  rax, 63
    cmp  [r15], rax                    ; exact untouched identity RW+NX+PS
    jne  .hda_ret                      ; includes split, alias, X or owned cache policy
.hda_inventory:
    ; Validate inventory shape as well as its success flag. Malformed entries
    ; anywhere in the bounded snapshot make the whole proof unavailable.
    mov  rsi, [rel inv_map_buffer]
    test rsi, rsi
    jz   .hda_ret
    mov  r11, [rel inv_map_desc_size]
    cmp  r11, 40
    jb   .hda_ret
    cmp  r11, 256
    ja   .hda_ret
    mov  rax, [rel inv_map_size]
    test rax, rax
    jz   .hda_ret
    cmp  rax, INV_MAP_BYTES
    ja   .hda_ret
    xor  edx, edx
    div  r11
    test rdx, rdx
    jnz  .hda_ret
    mov  r9, rsi
    add  r9, [rel inv_map_size]
    jc   .hda_ret
.hda_desc:
    cmp  rsi, r9
    jae  .hda_retag
    mov  rax, [rsi + 24]
    test rax, rax
    jz   .hda_next                      ; an empty descriptor owns no page
    mov  rdx, rax
    shr  rdx, 52
    jnz  .hda_ret
    shl  rax, 12
    mov  rbx, [rsi + 8]
    test rbx, 0xFFF
    jnz  .hda_ret
    add  rax, rbx
    jc   .hda_ret
    cmp  rbx, r14
    jae  .hda_next
    cmp  rax, r13
    jbe  .hda_next
    bt   qword [rsi + 32], 63           ; runtime-backed is never eligible
    jc   .hda_ret
    mov  edx, [rsi]
    test edx, edx
    jz   .hda_reserved                  ; reserved non-RAM hole only
    cmp  edx, 11
    je   .hda_next                      ; EfiMemoryMappedIO
    cmp  edx, 12
    jne  .hda_ret                       ; all other/unknown types treated as RAM
    jmp  .hda_next
.hda_reserved:
    test dword [rsi + 32], 0x0E         ; reserved WB/WT/WC could still be RAM
    jnz  .hda_ret
.hda_next:
    add  rsi, r11
    jmp  .hda_desc
.hda_retag:
    mov  rax, r10
    shr  rax, 30
    cmp  rax, [rel ident_gib]
    jae  .hda_map_high
    or   qword [r15], 0x18              ; PCD|PWT => PAT index3 UC, preserve NX
    jmp  .hda_ret
.hda_map_high:
    ; No table bytes change until both the inventory proof and exact table
    ; ownership/leaf checks pass. Never follow a foreign or unallocated PD.
    mov  rbx, rax                       ; GiB index (<512 checked above)
    mov  rcx, [rel ident_gib]
    sub  rcx, 16
    shl  rcx, 12
    lea  rsi, [r12 + rcx + 0x19000]     ; fixed preallocated MMIO pool
    lea  r11, [r12 + rbx*8 + 0x1000]    ; candidate PDPT entry
    mov  rdx, [r11]
    test rdx, rdx
    jz   .hda_new_pd
    mov  eax, edx
    and  eax, 0xFFF
    cmp  eax, 3                        ; exact pre-CR3 P|RW, never a 1GiB leaf
    jne  .hda_ret
    and  rdx, ~0xFFF
    cmp  rdx, rsi
    jb   .hda_ret
    mov  eax, [rel paging_hda_pd_used]
    shl  rax, 12
    add  rax, rsi
    cmp  rdx, rax
    jae  .hda_ret                       ; only already allocated pool pages
    xor  r9d, r9d
    jmp  .hda_high_leaf
.hda_new_pd:
    mov  eax, [rel paging_hda_pd_used]
    cmp  eax, PAGING_XHCI_PDS
    jae  .hda_ret                       ; exhausted: remain unmapped, no stealing
    shl  rax, 12
    lea  rdx, [rsi + rax]
    mov  r9d, 1
.hda_high_leaf:
    mov  rax, r10
    shr  rax, 21
    and  eax, 511
    lea  r15, [rdx + rax*8]
    mov  rax, r13
    or   rax, 0x93
    bts  rax, 63                       ; identity UC+NX large leaf
    mov  rcx, [r15]
    test rcx, rcx
    jz   .hda_high_publish
    test r9d, r9d
    jnz  .hda_ret                       ; a fresh pool page must be empty here
    cmp  rcx, rax
    je   .hda_high_publish              ; xHCI shares this exact UC+NX leaf
    or   rax, 0x08
    cmp  rcx, rax
    jne  .hda_ret                       ; never replace aliases or owned policy
.hda_high_publish:
    test r9d, r9d
    jz   .hda_high_retag
    or   rdx, 3
    mov  [r11], rdx
    inc  dword [rel paging_hda_pd_used]
.hda_high_retag:
    or   rax, 0x08                      ; match low HDA PAT index3 UC
    mov  [r15], rax
    bts  dword [rel paging_hda_high_proven], ebp ; exact pending BAR passed proof
.hda_ret:
    pop  rsi
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; First legacy NVMe only. Read-only PCI discovery above supplies its actual BAR.
; Map a whole 2MiB non-RAM page before EBS, never move it into RAM. The existing
; low identity/guarded relocation and VMD child path remain native-owned.
; Two additional pages, after the original allocation, cover one PDPT + PD.
; Lower canonical physical MMIO (<2^47) may be above the original512GiB PDPT.
; No page-table byte changes until inventory AND exact ownership checks pass.
.nvme_map:
    push rbx
    push rsi
    push rdi
    mov  r10, [rel paging_nvme_bar]
    mov  rax, r10
    shr  rax, 34
    jz   .nvme_ret                      ; low BAR behavior stays unchanged
    mov  rax, r10
    shr  rax, 47
    jnz  .nvme_ret                      ; cannot identity-map noncanonical addresses
    test r10, 0xFFF
    jnz  .nvme_ret
    cmp  word [rel inv_flags], 0
    jne  .nvme_ret
    mov  r13, r10
    and  r13, ~0x1FFFFF
    lea  r14, [r13 + 0x200000]
    mov  rax, r10
    shr  rax, 30
    cmp  rax, [rel ident_gib]
    jb   .nvme_ret                      ; do not retag RAM identity PDs
    mov  rcx, [rel vmd_window_gb]
    test rcx, rcx
    jz   .nvme_fb
    cmp  rax, rcx
    jb   .nvme_fb
    add  rcx, 2
    cmp  rax, rcx
    jb   .nvme_ret
.nvme_fb:
    mov  rax, [rel fb_base]
    mov  rcx, [rel fb_size]
    test rcx, rcx
    jz   .nvme_inventory
    add  rcx, rax
    jc   .nvme_ret
    cmp  rax, r14
    jae  .nvme_inventory
    cmp  rcx, r13
    ja   .nvme_ret
.nvme_inventory:
    mov  rsi, [rel inv_map_buffer]
    test rsi, rsi
    jz   .nvme_ret
    mov  r11, [rel inv_map_desc_size]
    cmp  r11, 40
    jb   .nvme_ret
    cmp  r11, 256
    ja   .nvme_ret
    mov  rax, [rel inv_map_size]
    test rax, rax
    jz   .nvme_ret
    cmp  rax, INV_MAP_BYTES
    ja   .nvme_ret
    xor  edx, edx
    div  r11
    test rdx, rdx
    jnz  .nvme_ret
    mov  r9, rsi
    add  r9, [rel inv_map_size]
    jc   .nvme_ret
.nvme_desc:
    cmp  rsi, r9
    jae  .nvme_publish
    mov  rax, [rsi + 24]
    test rax, rax
    jz   .nvme_next                      ; an empty descriptor owns no page
    mov  rdx, rax
    shr  rdx, 52
    jnz  .nvme_ret
    shl  rax, 12
    mov  rbx, [rsi + 8]
    test rbx, 0xFFF
    jnz  .nvme_ret
    add  rax, rbx
    jc   .nvme_ret
    cmp  rbx, r14
    jae  .nvme_next
    cmp  rax, r13
    jbe  .nvme_next
    bt   qword [rsi + 32], 63           ; runtime-backed is never eligible
    jc   .nvme_ret
    mov  edx, [rsi]
    test edx, edx
    jz   .nvme_reserved                  ; reserved non-RAM hole only
    cmp  edx, 11
    je   .nvme_next                      ; EfiMemoryMappedIO
    cmp  edx, 12
    jne  .nvme_ret                       ; all other/unknown types treated as RAM
    jmp  .nvme_next
.nvme_reserved:
    test dword [rsi + 32], 0x0E         ; reserved WB/WT/WC could still be RAM
    jnz  .nvme_ret
.nvme_next:
    add  rsi, r11
    jmp  .nvme_desc
.nvme_publish:
    mov  rax, [rel ident_gib]
    sub  rax, 16
    shl  rax, 12
    lea  rsi, [r12 + rax + (26 + PAGING_XHCI_PDS) * 0x1000] ; private PDPT
    mov  rax, r10
    shr  rax, 39
    lea  r8, [r12 + rax*8]              ; PML4 entry
    xor  r11d, r11d                    ; pending parents, not yet published
    test eax, eax
    jnz  .nvme_high_pml4
    mov  rax, [r8]
    and  rax, ~0x20                    ; hardware Accessed is harmless
    lea  rdx, [r12 + 0x1000]
    or   rdx, 3
    cmp  rax, rdx
    jne  .nvme_ret
    lea  r9, [r12 + 0x1000]            ; canonical low PDPT
    jmp  .nvme_pdpt
.nvme_high_pml4:
    cmp  qword [r8], 0
    jne  .nvme_ret                     ; never follow/replace a foreign PML4 slot
    mov  r11d, 2
    mov  r9, rsi                       ; use only our private PDPT
.nvme_pdpt:
    mov  rax, r10
    shr  rax, 30
    and  eax, 511
    lea  r9, [r9 + rax*8]
    mov  rdx, [r9]
    test rdx, rdx
    jz   .nvme_new_pd
    ; Existing low-PML4 shared xHCI/HDA PDs may carry this exact UC page.
    ; No other table is followed, including RAM/framebuffer/VMD/split tables.
    test r11d, 2
    jnz  .nvme_ret
    mov  eax, edx
    and  eax, 0xFFF
    and  eax, ~0x20
    cmp  eax, 3
    jne  .nvme_ret
    and  rdx, ~0xFFF
    lea  rcx, [rsi - (1 + PAGING_XHCI_PDS) * 0x1000] ; shared pool starts at25
    cmp  rdx, rcx
    jb   .nvme_ret
    mov  eax, [rel paging_hda_pd_used]
    shl  rax, 12
    add  rcx, rax
    cmp  rdx, rcx
    jae  .nvme_ret
    jmp  .nvme_leaf
.nvme_new_pd:
    lea  rdx, [rsi + 0x1000]            ; private PD, one fixed allocation
    or   r11d, 1
.nvme_leaf:
    mov  rax, r10
    shr  rax, 21
    and  eax, 511
    lea  rdi, [rdx + rax*8]
    mov  rax, r13
    or   rax, 0x9B                     ; identity P|RW|PCD|PWT|PS + NX (PAT UC)
    bts  rax, 63
    mov  rcx, [rdi]
    test rcx, rcx
    jz   .nvme_install
    test r11d, 1
    jnz  .nvme_ret                     ; a fresh private PD must be empty
    and  rcx, ~0x68                    ; A/D and PWT: existing xHCI UC allowed
    mov  rbx, rax
    and  rbx, ~0x08
    cmp  rcx, rbx
    jne  .nvme_ret                     ; no cache/translation/permission replacement
.nvme_install:
    mov  [rdi], rax
    test r11d, 1
    jz   .nvme_install_pml4
    or   rdx, 3
    mov  [r9], rdx
.nvme_install_pml4:
    test r11d, 2
    jz   .nvme_prove
    or   rsi, 3
    mov  [r8], rsi
.nvme_prove:
    mov  [rel paging_nvme_leaf], rdi
    mov  [rel paging_nvme_pdpt_entry], r9
    mov  [rel paging_nvme_pml4_entry], r8
    mov  rax, [r9]
    mov  [rel paging_nvme_pdpt_value], rax
    mov  rax, [r8]
    mov  [rel paging_nvme_pml4_value], rax
    mov  [rel paging_nvme_proven], r10
.nvme_ret:
    pop  rdi
    pop  rsi
    pop  rbx
    ret

; RDI=actual BAR, RSI=required aperture bytes, EDX=actual BDF.
; Return EAX=1 only for the precise boot-proven function/BAR AND live owned
; identity UC+NX parents/leaf, covering the ENTIRE required access span.
; No arbitrary table pointer is followed; only boot-proven entry addresses.
paging_nvme_bar_mapped:
    xor  eax, eax
    test rdi, rdi
    jz   .no
    cmp  rdi, [rel paging_nvme_proven]
    jne  .no
    cmp  edx, [rel paging_nvme_bdf]
    jne  .no
    test rsi, rsi
    jz   .no
    mov  rcx, rdi
    and  ecx, 0x1FFFFF
    add  rcx, rsi
    jc   .no
    cmp  rcx, 0x200000
    ja   .no
    mov  r8, [rel paging_nvme_pml4_entry]
    mov  rcx, [r8]
    and  rcx, ~0x20
    mov  rdx, [rel paging_nvme_pml4_value]
    and  rdx, ~0x20
    cmp  rcx, rdx
    jne  .no
    mov  r8, [rel paging_nvme_pdpt_entry]
    mov  rcx, [r8]
    and  rcx, ~0x20
    mov  rdx, [rel paging_nvme_pdpt_value]
    and  rdx, ~0x20
    cmp  rcx, rdx
    jne  .no
    mov  r8, [rel paging_nvme_leaf]
    mov  rcx, [r8]
    and  rcx, ~0x60                    ; hardware A/D only
    mov  rdx, rdi
    and  rdx, ~0x1FFFFF
    or   rdx, 0x9B
    bts  rdx, 63
    cmp  rcx, rdx
    jne  .no
    mov  eax, 1
.no:
    ret
%endmacro

    ; Allocate one owned 4 KiB page for the W^X destructive self-test (core/idt).
    ; If it lands >=2 MiB it falls in an NX 2 MiB page in our map, so executing
    ; from it must #PF — the proof that NX is enforced. (Owned page => safe to
    ; write/jump; the test guards on the >=2 MiB check.)
    ; A relocated image may span more than the first 2 MiB window. Retry a
    ; bounded number of times if firmware puts this page inside any executable
    ; image window; otherwise the planted RET executes instead of faulting.
    mov r13d, 8
.wx_page_alloc:
    mov rax, [rel boot_services]
    mov ecx, 2
    mov edx, 4096
    lea r8, [rel wx_test_page]
    call [rax + 0x40]                   ; AllocatePool
    test rax, rax
    jnz exit_boot_and_page_fail
    mov rax, [rel wx_test_page]
    mov rdx, [rel pbm_image_base]
    add rdx, [rel pbm_image_size]
    add rdx, 0x1FFFFF
    and rdx, ~0x1FFFFF
    cmp rax, rdx
    jae .wx_page_ok
    cmp rax, 0x200000
    jb  .wx_page_ok                     ; self-test already skips below 2 MiB
    dec r13d
    jnz .wx_page_alloc
    mov qword [rel wx_test_page], 0     ; skip honestly rather than misfire
.wx_page_ok:

    ; --- Contract 1020 PMOD address-space window. The 1 GiB virtual window
    ; starts at the MEMORY_MAP anchor 0x40000000; this first seam commits only
    ; 16 physical pages (64 KiB) and leaves the rest unmapped. The backing pages
    ; are allocated anywhere: 0x40000000 is a virtual ABI, not a claim that this
    ; exact physical range is free in every firmware memory map. A 4 KiB PT is
    ; mandatory: code/data need distinct RX/RW+NX pages and unmapped guards.
    ; Failure disables PMOD loading but must never prevent the keep from booting.
    mov  qword [rel pmod_region_base], 0x40000000
    mov  qword [rel pmod_region_phys], 0
    mov  rax, [rel boot_services]
    xor  ecx, ecx                        ; AllocateAnyPages
    mov  edx, 2                          ; EfiLoaderData
    mov  r8d, 16                         ; 64 KiB committed in 1 GiB window
    lea  r9, [rel pmod_region_phys]
    call [rax + 0x28]                    ; AllocatePages
    test rax, rax
    jz   .pmod_region_ok
    mov  qword [rel pmod_region_base], 0
    mov  qword [rel pmod_region_phys], 0
    jmp  .pmod_alloc_done
.pmod_region_ok:
    ; Do not expose stale firmware/conventional-memory contents to a loaded
    ; cell. Zero the owned physical allocation before guard PTEs hide pages.
    mov  rdi, [rel pmod_region_phys]
    mov  ecx, (16 * 4096) / 8
    xor  eax, eax
    rep  stosq
    mov  rax, [rel boot_services]
    mov  ecx, 2
    mov  edx, 8192                       ; PT + alignment slack
    lea  r8, [rel pmod_pt_alloc]
    call [rax + 0x40]
    test rax, rax
    jnz  .pmod_disable
    mov  rax, [rel pmod_pt_alloc]
    add  rax, 0xFFF
    and  rax, ~0xFFF
    mov  [rel pmod_pt_addr], rax

    mov  rax, [rel boot_services]
    mov  ecx, 2
    mov  edx, 16384                      ; PML4 + PDPT + PD + alignment slack
    lea  r8, [rel pmod_sandbox_alloc]
    call [rax + 0x40]
    test rax, rax
    jnz  .pmod_disable
    mov  rax, [rel pmod_sandbox_alloc]
    add  rax, 0xFFF
    and  rax, ~0xFFF
    mov  [rel pmod_sandbox_pml4], rax
    lea  rdx, [rax + 0x1000]
    mov  [rel pmod_sandbox_pdpt], rdx
    lea  rdx, [rax + 0x2000]
    mov  [rel pmod_sandbox_pd], rdx

    ; Sparse layout: guard | m1 code | m1 data | guard | m2 code | m2 data |
    ; guard | watchdog code | fault-test code | guard | sandbox stack | guard.
    ; Code begins RW+NX for the copy; the loader seals it RO+X only after
    ; Merkle+signature+format verification. The stack stays RW+NX.
    mov  rdi, [rel pmod_pt_addr]
    mov  ecx, 4096 / 8
    xor  eax, eax
    rep  stosq
    xor  ecx, ecx
.pmod_pte:
    cmp  ecx, 11
    jae  .pmod_pte_done
    cmp  ecx, 0
    je   .pmod_pte_next
    cmp  ecx, 3
    je   .pmod_pte_next
    cmp  ecx, 6
    je   .pmod_pte_next
    cmp  ecx, 9
    je   .pmod_pte_next
    mov  rax, [rel pmod_region_phys]
    mov  edx, ecx
    shl  rdx, 12
    add  rax, rdx
    or   rax, 0x03                      ; Present | RW while loading
    bts  rax, 63                        ; NX until sealed
    mov  rdi, [rel pmod_pt_addr]
    mov  [rdi + rcx*8], rax
.pmod_pte_next:
    inc  ecx
    jmp  .pmod_pte
.pmod_pte_done:
    ; A distinct sandbox CR3 reuses the proven host mappings except for the
    ; first 2 MiB of the 1 GiB module window: private PDPT/PD pages copy the
    ; host's 1-2 GiB PD and only entry 0 reaches the sparse PT above. The
    ; sandbox call runs host code on host stacks with the host IDT, so it must
    ; still find them there: hiding the whole 1-2 GiB range reset the CPU on
    ; the first call whenever firmware or the Manager loaded PaOS there (QEMU
    ; 2 GiB guests, 2026-10-17). A host image overlapping the window's own
    ; 2 MiB cannot be kept visible, so PMOD is disabled instead.
    ; The host deliberately retains its original huge-page identity map so
    ; unrelated physical allocations elsewhere in that 2 MiB are not hidden.
    mov  rax, [rel pbm_image_size]
    test rax, rax
    jz   .pmod_image_clear
    mov  rdx, [rel pbm_image_base]
    cmp  rdx, 0x40200000                 ; end of the sparse 2 MiB
    jae  .pmod_image_clear
    add  rax, rdx
    cmp  rax, 0x40000000
    ja   .pmod_disable                  ; image shares the sparse 2 MiB
.pmod_image_clear:
    mov  rax, [r12 + 0x1000 + 8]        ; host PDPT[1]
    test al, 1
    jz   .pmod_disable
    test al, 0x80
    jnz  .pmod_disable                  ; a 1 GiB page has no PD to copy
    mov  rdi, [rel pmod_sandbox_pml4]
    mov  rsi, r12
    mov  ecx, 4096 / 8
    rep  movsq
    mov  rdi, [rel pmod_sandbox_pdpt]
    lea  rsi, [r12 + 0x1000]
    mov  ecx, 4096 / 8
    rep  movsq
    mov  rax, [rel pmod_sandbox_pdpt]
    or   rax, 0x03
    mov  rdi, [rel pmod_sandbox_pml4]
    mov  [rdi], rax                     ; private low-half PDPT
    mov  rsi, [r12 + 0x1000 + 8]
    mov  rax, 0x000FFFFFFFFFF000
    and  rsi, rax                       ; host 1-2 GiB PD
    mov  rdi, [rel pmod_sandbox_pd]
    mov  ecx, 4096 / 8
    rep  movsq
    mov  rax, [rel pmod_pt_addr]
    or   rax, 0x03
    mov  rdi, [rel pmod_sandbox_pd]
    mov  [rdi], rax                     ; only the first 2 MiB has sparse 4 KiB PTEs
    mov  rax, [rel pmod_sandbox_pd]
    or   rax, 0x03
    mov  rdi, [rel pmod_sandbox_pdpt]
    mov  [rdi + 8], rax                 ; PDPT[1] = private module-window PD
    jmp  .pmod_alloc_done
.pmod_disable:
    mov  qword [rel pmod_region_base], 0
    mov  qword [rel pmod_region_phys], 0
    mov  qword [rel pmod_pt_addr], 0
    mov  qword [rel pmod_sandbox_pml4], 0
.pmod_alloc_done:

    ; --- reserve the PERSISTENT diag ring (MEMORY_MAP §1): a FIXED 64 KiB region
    ;     that survives a warm reboot. AllocatePages(AllocateAddress) pins it at
    ;     DIAG_RING_BASE so it (a) never overlaps the heap/DMA pool the next allocs
    ;     hand out and (b) is the same physical address every boot — the substrate
    ;     core/diag reads a prior boot's crash/phase forensics back from. Failure is
    ;     NON-FATAL: fall back to a pooled 64 KiB region (persistence degrades to
    ;     same-boot; the gate still runs), and if even that fails, 0 => diag disables
    ;     itself. The 64 KiB region is data — it lands in an NX 2 MiB page (RW+NX),
    ;     identity-mapped (<16 GiB), so core/diag can read/write it post-CR3. ---
    mov  qword [rel diag_ring_base], DIAG_RING_BASE   ; desired addr (in/out for AllocateAddress)
    mov  rax, [rel boot_services]
    mov  ecx, 2                          ; AllocateAddress
    mov  edx, 2                          ; EfiLoaderData (survives EBS)
    mov  r8d, DIAG_RING_PAGES            ; 16 pages = 64 KiB
    lea  r9, [rel diag_ring_base]
    call [rax + 0x28]                    ; AllocatePages(type, memtype, pages, &addr)
    test rax, rax
    jz   .diag_ring_ok
    mov  rax, [rel boot_services]        ; fixed address refused -> pooled fallback
    mov  ecx, 2                          ; EfiLoaderData
    mov  edx, DIAG_RING_SIZE
    lea  r8, [rel diag_ring_base]
    call [rax + 0x40]                    ; AllocatePool(type, size, &buf)
    test rax, rax
    jz   .diag_ring_ok
    mov  qword [rel diag_ring_base], 0   ; no ring at all -> core/diag disables itself
.diag_ring_ok:

    ; Additive fatal identity page: keep existing v3 diag geometry byte exact.
    ; No pooled fallback: never treat a different address as retained evidence.
    mov qword [rel crash_identity_base],CRID_BASE
    mov rax,[rel boot_services]
    mov ecx,2
    mov edx,2
    mov r8d,CRID_PAGES
    lea r9,[rel crash_identity_base]
    call [rax+0x28]
    test rax,rax
    jz .crash_identity_ok
    mov qword [rel crash_identity_base],0
.crash_identity_ok:

    ; Task2302 boot filmstrip: reserve its exact fixed-address evidence arena.
    ; Unlike the persistent diag ring there is no pooled fallback: a different
    ; address would violate the documented ABI and make stale pointer evidence
    ; possible. Failure is non-fatal and leaves a zero pointer; capture then
    ; reports all slots invalid and boot continues. No allocation occurs at
    ; any checkpoint and no filmstrip byte is ever written to the ESP.
    mov  qword [rel filmstrip_ring_base], FILMSTRIP_RING_BASE
    mov  rax, [rel boot_services]
    mov  ecx, 2                          ; AllocateAddress
    mov  edx, 2                          ; EfiLoaderData (survives EBS)
    mov  r8d, FILMSTRIP_RING_PAGES
    lea  r9, [rel filmstrip_ring_base]
    call [rax + 0x28]
    test rax, rax
    jz   .filmstrip_ring_ok
    mov  qword [rel filmstrip_ring_base], 0
.filmstrip_ring_ok:

    ; Allocate the kernel/DMA heap below 4 GiB. e1000e programs 32-bit ring base
    ; registers with BAH=0, so a top-of-RAM allocation would truncate DMA on
    ; machines such as the Dell whose RAM extends beyond 16 GiB.
    mov rax, 0xFFFFFFFF
    mov [rel heap_base], rax
    mov rax, [rel boot_services]
    mov ecx, 1                          ; AllocateMaxAddress
    mov edx, 2                          ; EfiLoaderData
    mov r8d, 0x1000                     ; 16 MiB / 4 KiB
    lea r9, [rel heap_base]
    call [rax + 0x28]                   ; AllocatePages
    test rax, rax
    jnz exit_boot_and_page_fail
    mov qword [rel heap_size], 0x1000000

    ; Reserve and map permanent CPU stacks before the final firmware map/EBS.
    call percpu_stack_reserve
    jc   exit_boot_and_page_fail

    ; Contract 1061b: keep the 327 MiB cognition model out of both BSS and the
    ; 16 MiB general heap.  Secure the mandatory general heap first, then use
    ; AllocateMaxAddress for one contiguous high region inside the established
    ; 0..16 GiB identity map.  Machines without 384 MiB available still boot:
    ; cognition reports present=0 instead of making the model a boot dependency.
    ; If that region is unavailable, retain a smaller arena for the image cache
    ; and other model-heap users.  Its actual size still excludes cognition.
    mov  rax, 0x3FFFFFFFF              ; qword store has no imm64 encoding
    mov  [rel model_heap_alloc_base], rax
    mov  rax, [rel boot_services]
    mov  ecx, 1                         ; AllocateMaxAddress
    mov  edx, 2                         ; EfiLoaderData
    mov  r8d, 0x18000                   ; 384 MiB / 4 KiB
    lea  r9, [rel model_heap_alloc_base]
    call [rax + 0x28]                   ; AllocatePages
    test rax, rax
    jz   .model_heap_ok
    ; A failed AllocatePages may dirty its in/out address.  Restart every
    ; firmware operand for the bounded 64 MiB fallback inside the same map.
    mov  rax, 0x3FFFFFFFF
    mov  [rel model_heap_alloc_base], rax
    mov  rax, [rel boot_services]
    mov  ecx, 1                         ; AllocateMaxAddress
    mov  edx, 2                         ; EfiLoaderData
    mov  r8d, 0x4000                    ; 64 MiB / 4 KiB
    lea  r9, [rel model_heap_alloc_base]
    call [rax + 0x28]                   ; AllocatePages
    test rax, rax
    jz   .model_heap_small_ok
    mov  qword [rel model_heap_alloc_base], 0
    mov  qword [rel model_heap_alloc_size], 0
    mov  qword [rel model_heap_base], 0
    mov  qword [rel model_heap_size], 0
    jmp  .model_heap_done
.model_heap_ok:
    mov  rax, [rel model_heap_alloc_base]
    mov  [rel model_heap_base], rax
    mov  qword [rel model_heap_alloc_size], 0x18000000
    mov  qword [rel model_heap_size], 0x18000000
    jmp  .model_heap_done
.model_heap_small_ok:
    mov  rax, [rel model_heap_alloc_base]
    mov  [rel model_heap_base], rax
    mov  qword [rel model_heap_alloc_size], 0x4000000
    mov  qword [rel model_heap_size], 0x4000000
.model_heap_done:
    call hp_mapping_reserve            ; dedicated high-RAM preservation page
    call boot_model_preload             ; verified boot-volume file, before final memory map

    ; --- 1249 §12 rung 3: re-validate the GOP mode record as the LAST act before
    ;     GetMemoryMap/ExitBootServices (ConSplitter may have re-modeset since the
    ;     capture), then give the exact page-rounded framebuffer range its own
    ;     cache policy (WC through PAT PA1 when PAT exists, else UC-). ---
    ; A framebuffer left unmapped above GiB 511 stays retired: revalidation would read
    ; the zeroed record as firmware drift, SetMode and re-adopt the unmapped base.
    cmp byte [rel paging_fb_unmapped], 0
    jne .fb_reval_skip
    call gop_revalidate_record
    call bm_face_refresh               ; redraw any adopted/reset GOP surface
.fb_reval_skip:
    call fb_apply_cache_policy

    ; --- 2026-09-08: full-screen back buffer RAM for gui/window (fb_shadow_attach): one
    ;     contiguous EfiLoaderData block BELOW 4 GiB sized from the revalidated GOP record
    ;     (stride * height * 4), so the compositor never composes into a top-of-RAM MTRR
    ;     hole (the cognition region at <=16 GiB measured ~860 MB/s). Absent -> the GUI
    ;     falls back to kmalloc, then kmalloc_model. ---
    mov  eax, [rel fb_stride]
    imul eax, [rel fb_height]
    shl  rax, 2
    test rax, rax
    jz   .shadow_region_done
    add  rax, 0xFFF
    shr  rax, 12                        ; pages
    mov  r8, rax
    ; AllocatePages may clobber R8 under the UEFI Microsoft x64 ABI. Record
    ; the requested capacity before the call; failure clears it below.
    shl  rax, 12
    mov  [rel fb_shadow_region_size], rax
    mov  rax, 0xFFFFFFFF
    mov  [rel fb_shadow_region_base], rax  ; AllocateMaxAddress: in = ceiling, out = base
    mov  rax, [rel boot_services]
    mov  ecx, 1                         ; AllocateMaxAddress
    mov  edx, 2                         ; EfiLoaderData
    lea  r9, [rel fb_shadow_region_base]
    call [rax + 0x28]                   ; AllocatePages
    test rax, rax
    jz   .shadow_region_ok
    mov  qword [rel fb_shadow_region_base], 0
    mov  qword [rel fb_shadow_region_size], 0
    jmp  .shadow_region_done
.shadow_region_ok:
.shadow_region_done:

MMAP_BUFFER_BYTES equ 65536             ; final UEFI memory-map buffer (was 8192)
    ; --- final memory map + ExitBootServices ---
    ; Allocate a fresh map buffer (our AllocatePool above changed the map/key).
    ; 64 KiB (~1300 descriptors): a fixed 8 KiB was too small for large firmware
    ; maps (MSI/AMI desktop; OVMF right after MokManager) and returned
    ; EFI_BUFFER_TOO_SMALL here -> "FAILED (EBS/alloc)" (desktop rehearsal r12).
    call mmap_final_clear
    mov qword [rel mmap_owned_buffer], 0
    mov qword [rel mmap_capacity], 0
    mov rax, [rel boot_services]
    mov ecx, 2
    mov edx, MMAP_BUFFER_BYTES
    lea r8, [rel mmap_owned_buffer]      ; ownership is separate from published map
    call [rax + 0x40]                   ; AllocatePool
    test rax, rax
    jnz exit_boot_and_page_fail
    mov qword [rel mmap_capacity], MMAP_BUFFER_BYTES

    ; The pre-EBS watchdog (header.asm arms it at entry) stays ARMED through the
    ; final GetMemoryMap/ExitBootServices and the retry (root 2026-10-08 20:09:57
    ; (2)(a)): UEFI 2.10 sec. 7.5.1 SetWatchdogTimer(): "The watchdog timer is only
    ; used during boot services. On successful completion of
    ; EFI_BOOT_SERVICES.ExitBootServices() the watchdog timer is disabled." A
    ; firmware wedge inside these calls is reset; a failure resets at once
    ; (exit_boot_and_page_fail).
    call mmap_final_read                ; fresh outputs + complete structural admission
    test rax, rax
    jnz exit_boot_and_page_fail

    mov rax, [rel boot_services]
    mov rcx, [rel image_handle]
    mov rdx, [rel mmap_pending_key]
%ifdef PAOS_LAB_EBS_FAIL
    not rdx                             ; QEMU lab: a stale key, so both EBS calls fail
%endif
    ; An attempted EBS can partially shut firmware down even on failure.
    ; No later face/menu ConOut call is legal, including the retry window.
    mov byte [rel bm_face_boot_services_live], 0
    call [rax + 0xE8]                   ; ExitBootServices(handle, key)
    test rax, rax
    jz  .ebs_ok

    ; EBS failed once: ONLY GetMemoryMap + EBS are legal now (no AllocatePool).
    call mmap_final_read                ; failure cannot fall through with an old key
    test rax, rax
    jnz exit_boot_and_page_fail
    mov rax, [rel boot_services]
    mov rcx, [rel image_handle]
    mov rdx, [rel mmap_pending_key]
%ifdef PAOS_LAB_EBS_FAIL
    not rdx
%endif
    call [rax + 0xE8]                   ; ExitBootServices again
    test rax, rax
    jnz exit_boot_and_page_fail

.ebs_ok:
    cli                                 ; we own the CPU now — no firmware, no IRQs yet
    rdtsc                               ; RCQ-32 BG4: Boot Services exited (raw TSC; svc/boot_gates converts)
    shl rdx, 32
    or  rax, rdx
    mov [rel boot_bg4_ebs_tsc], rax
    call mmap_final_publish             ; only the EBS-success map becomes current
    call map_pbm_runtime_code_and_reset_guard ; same-size call; guard code lives after GOP layout boundary

    ; Enable NX interpretation + supervisor write-protect BEFORE installing tables
    ; that carry NX bits (a set NX bit with EFER.NXE=0 is a reserved-bit fault).
    mov ecx, 0xC0000080                 ; IA32_EFER
    rdmsr
    or  eax, (1 << 11)                  ; EFER.NXE
    wrmsr
    mov rax, cr0
    or  rax, (1 << 16)                  ; CR0.WP (makes future RO code pages real in ring 0)
    mov cr0, rax

    ; --- 1249: IA32_PAT PA1 = WC before the tables that use index 1 go live ---
    call fb_pat_program

    mov rax, [rel pml4_addr]
    mov cr3, rax                        ; install our page tables (also flushes TLB)

    ; Reaching here proves the W^X tables are valid + we're running on them (a bad
    ; NX/reserved-bit setup would have #GP/#PF'd → triple fault → reboot, no marker).
    lea rdi, [rel str_paging_ok]
    call serial_string
    lea rdi, [rel str_wx_ok]
    call serial_string
    cmp byte [rel paging_fb_unmapped], 0
    je  .fb_marker_done
    lea rdi, [rel str_fb_unmapped]
    call serial_string
.fb_marker_done:
    call paging_extent_report
    add rsp, 40
    pop r13
    pop r12
    pop rbx
    ret

; Final-map ownership and publication are distinct. These helpers allocate,
; free, print and poll NOTHING; after an attempted EBS only GetMemoryMap is
; invoked here. The existing caller owns at most two EBS attempts and reset.
mmap_final_clear:
    mov qword [rel mmap_buffer], 0
    mov qword [rel mmap_size], 0
    mov qword [rel mmap_key], 0
    mov qword [rel mmap_desc_size], 0
    mov qword [rel mmap_desc_ver], 0
    ret

; Owned EfiLoaderData must remain addressable after CR3 installation. Full
; allocation span (not just the returned map) is checked; pool alignment is8.
mmap_final_buffer:
    mov dword [rel mmap_admit_reason], 1
    mov rdx, [rel mmap_owned_buffer]
    test rdx, rdx
    jz .bad
    test dl, 7
    jnz .bad
    mov rcx, [rel mmap_capacity]
    cmp rcx, MMAP_BUFFER_BYTES
    jne .bad
    add rdx, rcx
    jc .bad
    cmp rdx, [rel ident_bytes]
    ja .bad
    xor eax, eax
    ret
.bad:
    mov eax, 1
    ret

; RAX=0 means an admitted pending map. Raw GetMemoryMap status is retained
; separately; local refusal returns1 and a bounded diagnostic reason.
; Preserve caller flags/DF and full64 nonvolatile GPR ownership.
mmap_final_read:
    pushfq
    cld
    push rbp
    mov rbp, rsp
    and rsp, -16
    sub rsp, 64                       ; shadow + fifth arg + owner/capacity snapshots
    call mmap_final_clear
    mov qword [rel mmap_final_status], -1
    mov qword [rel mmap_pending_size], 0
    mov qword [rel mmap_pending_key], 0
    mov qword [rel mmap_pending_desc_size], 0
    mov qword [rel mmap_pending_desc_ver], 0
    call mmap_final_buffer
    test rax, rax
    jnz .out
    call mmap_interval_check            ; refuse private scratch alias/busy before firmware writes
    test rax, rax
    jnz .out
    mov rdx, [rel mmap_owned_buffer]
    mov [rsp + 48], rdx
    mov rax, [rel mmap_capacity]
    mov [rsp + 56], rax
    mov [rel mmap_pending_size], rax
    lea rcx, [rel mmap_pending_size]
    lea r8, [rel mmap_pending_key]
    lea r9, [rel mmap_pending_desc_size]
    lea rax, [rel mmap_pending_desc_ver]
    mov [rsp + 32], rax
    mov rax, [rel boot_services]
    call [rax + 0x38]                  ; GetMemoryMap, on first AND retry acquisition
    mov [rel mmap_final_status], rax
    test rax, rax                      ; never overwrite/ignore failed EFI status
    jnz .read_failed
    mov rax, [rsp + 48]
    cmp rax, [rel mmap_owned_buffer]
    jne .owner_changed
    mov rax, [rsp + 56]
    cmp rax, [rel mmap_capacity]
    jne .owner_changed
    call mmap_final_validate
    jmp .out
.read_failed:
    mov dword [rel mmap_admit_reason], 8
    jmp .out
.owner_changed:
    mov dword [rel mmap_admit_reason], 7
    mov rax, [rsp + 48]
    mov [rel mmap_owned_buffer], rax
    mov rax, [rsp + 56]
    mov [rel mmap_capacity], rax
    mov eax, 1
.out:
    mov rsp, rbp
    pop rbp
    popfq
    ret

; Admission facts required by memmap_total, acpi_range and runtime map walks:
; complete aligned v1 descriptors, finite extent/stride, page-aligned nonempty
; nonwrapping physical/virtual spans and nonoverlapping physical records.
; Firmware order/bytes are preserved. Collect only validated start/end pairs
; into fixed private BSS, heapsort in O(n log n), then check adjacent intervals.
; Scratch is never allocated during acquisition/retry or published as the map.
mmap_final_validate:
    push rbp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    xor ebp, ebp                      ; owns private scratch only after successful claim
    call mmap_final_buffer
    test rax, rax
    jnz .bad
    mov rsi, [rel mmap_owned_buffer]
    mov rdx, [rel mmap_pending_size]
    mov dword [rel mmap_admit_reason], 2
    test rdx, rdx
    jz .bad
    cmp rdx, [rel mmap_capacity]
    ja .bad
    mov dword [rel mmap_admit_reason], 3
    mov rbx, [rel mmap_pending_desc_size]
    cmp rbx, 40
    jb .bad
    cmp rbx, 256
    ja .bad
    test bl, 7
    jnz .bad
    cmp qword [rel mmap_pending_desc_ver], 1
    jne .bad
    mov rax, rdx
    mov r12, rsi
    add r12, rdx                       ; buffer+capacity already checked; size<=capacity
    xor edx, edx
    div rbx
    test rdx, rdx
    jnz .bad                          ; never accept a trailing partial descriptor
    mov dword [rel mmap_admit_reason], 9
    cmp rax, MMAP_INTERVAL_CAP
    ja .bad
    call mmap_interval_check
    test rax, rax
    jnz .bad
    xor eax, eax
    mov edx, 1
    lock cmpxchg [rel mmap_interval_busy], rdx
    jnz .bad                          ; changed owner/lifetime, never clear another claim
    mov ebp, 1
    mov qword [rel mmap_interval_count], 0
    xor r13d, r13d                    ; conventional bytes (protect memmap_total's sum)
.row:
    cmp rsi, r12
    jae .order
    mov dword [rel mmap_admit_reason], 4
    mov r14, [rsi + 8]
    test r14d, 4095
    jnz .bad
    mov r10, [rsi + 16]
    test r10d, 4095
    jnz .bad
    mov r8, [rsi + 24]
    test r8, r8
    jz .bad
    mov rax, r8
    shr rax, 52
    jnz .bad
    shl r8, 12
    mov r15, r14
    add r15, r8
    jc .bad
    add r10, r8
    jc .bad
    cmp dword [rsi], 7
    jne .append
    mov dword [rel mmap_admit_reason], 6
    add r13, r8
    jc .bad
.append:
    mov dword [rel mmap_admit_reason], 9
    mov rax, [rel mmap_interval_count]
    cmp rax, MMAP_INTERVAL_CAP
    jae .bad                          ; explicit capacity guard on every private write
    shl rax, 4
    lea rdi, [rel mmap_interval_index]
    mov [rdi + rax], r14
    mov [rdi + rax + 8], r15
    inc qword [rel mmap_interval_count]
    add rsi, rbx
    jmp .row
.order:
    mov dword [rel mmap_admit_reason], 9
    mov rcx, [rel mmap_interval_count]
    mov rax, [rel mmap_pending_size]
    xor edx, edx
    div rbx
    cmp rax, rcx
    jne .bad                          ; never sort/use a stale or corrupted private count
    lea rdi, [rel mmap_interval_index]
    call mmap_interval_sort
    mov dword [rel mmap_admit_reason], 5
    mov rcx, [rel mmap_interval_count]
    cmp rcx, 2
    jb .good
    lea rdi, [rel mmap_interval_index]
    mov rax, [rdi + 8]                 ; exclusive end of prior sorted interval
    dec rcx
.adjacent:
    add rdi, 16
    cmp [rdi], rax
    jb .bad                           ; equality is valid adjacency; strict less overlaps
    mov rax, [rdi + 8]
    dec rcx
    jnz .adjacent
.good:
    mov dword [rel mmap_admit_reason], 0
    xor eax, eax
    jmp .out
.bad:
    test ebp, ebp
    jz .not_owned
    mov qword [rel mmap_interval_count], 0
.not_owned:
    mov eax, 1
.out:
    test ebp, ebp
    jz .release_done
    mov qword [rel mmap_interval_busy], 0
.release_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

MMAP_INTERVAL_CAP equ MMAP_BUFFER_BYTES / 40
MMAP_INTERVAL_BYTES equ MMAP_INTERVAL_CAP * 16

; Fixed private workspace: full64 extent/capacity, alignment, identity coverage,
; alias and lifetime admission before any use (including before GetMemoryMap).
; No external scratch pointer/capacity is accepted. RAX=0 available, else1.
mmap_interval_check:
    push rdi
    mov dword [rel mmap_admit_reason], 9
    lea rdi, [rel mmap_interval_workspace]
    test dil, 15
    jnz .bad
    lea rax, [rel mmap_interval_workspace_end]
    mov rcx, rax
    sub rcx, rdi
    jc .bad
    cmp rcx, MMAP_INTERVAL_BYTES + 16
    jne .bad
    cmp rax, [rel ident_bytes]
    ja .bad
    lea r8, [rel mmap_interval_index]
    test r8b, 15
    jnz .bad
    lea r9, [rdi + 16]
    cmp r8, r9
    jne .bad
    lea rcx, [rel mmap_interval_index_end]
    sub rcx, r8
    jc .bad
    cmp rcx, MMAP_INTERVAL_BYTES
    jne .bad
    mov rcx, [rel mmap_owned_buffer]
    mov rdx, rcx
    add rdx, [rel mmap_capacity]
    jc .bad
    cmp rdi, rdx
    jae .separate
    cmp rcx, rax
    jb .bad                           ; reject overlap with metadata OR interval storage
.separate:
    cmp qword [rel mmap_interval_busy], 0
    jne .bad                          ; uncertain/other claim is never reset/reused
    xor eax, eax
    jmp .out
.bad:
    mov eax, 1
.out:
    pop rdi
    ret

; RDI=index, RCX=count (1..1638), validated by sole caller. Unsigned-start
; max-heap ordering. In-place private pairs; firmware descriptors stay untouched.
; Worst case O(n log n), constant stack; all64 bits of endpoints move together.
mmap_interval_sort:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rcx
    cmp r12, 2
    jb .out
    mov r13, r12
    shr r13, 1
.heapify:
    dec r13
    mov rdi, rbx
    mov rcx, r12
    mov rdx, r13
    call mmap_interval_sift
    test r13, r13
    jnz .heapify
    mov r13, r12
.extract:
    dec r13
    mov rax, r13
    shl rax, 4
    mov r8, [rbx]
    mov r9, [rbx + 8]
    mov r10, [rbx + rax]
    mov r11, [rbx + rax + 8]
    mov [rbx], r10
    mov [rbx + 8], r11
    mov [rbx + rax], r8
    mov [rbx + rax + 8], r9
    mov rdi, rbx
    mov rcx, r13                       ; extracted maximum is outside shrinking heap
    xor edx, edx
    call mmap_interval_sift
    cmp r13, 1
    ja .extract
.out:
    pop r13
    pop r12
    pop rbx
    ret

; RDI=index, RCX=heap count, RDX=root. Promote the larger child until saved
; pair fits; children are checked before reads. No recursion/allocator/callback.
mmap_interval_sift:
    push rsi
    mov rax, rdx
    shl rax, 4
    mov r8, [rdi + rax]
    mov r9, [rdi + rax + 8]
.child:
    lea r10, [rdx * 2 + 1]
    cmp r10, rcx
    jae .place
    mov rax, r10
    shl rax, 4
    lea r11, [r10 + 1]
    cmp r11, rcx
    jae .larger
    mov r11, [rdi + rax + 16]
    cmp r11, [rdi + rax]
    jbe .larger
    inc r10
    add rax, 16
.larger:
    cmp r8, [rdi + rax]
    jae .place
    mov r11, [rdi + rax]
    mov rsi, [rdi + rax + 8]
    mov rax, rdx
    shl rax, 4
    mov [rdi + rax], r11
    mov [rdi + rax + 8], rsi
    mov rdx, r10
    jmp .child
.place:
    mov rax, rdx
    shl rax, 4
    mov [rdi + rax], r8
    mov [rdi + rax + 8], r9
    pop rsi
    ret

; Called only after successful EBS and the existing immediate success TSC.
; All consumers retain their existing fields; no failed/pending map is visible.
mmap_final_publish:
    mov rax, [rel mmap_owned_buffer]
    mov [rel mmap_buffer], rax
    mov rax, [rel mmap_pending_size]
    mov [rel mmap_size], rax
    mov rax, [rel mmap_pending_key]
    mov [rel mmap_key], rax
    mov rax, [rel mmap_pending_desc_size]
    mov [rel mmap_desc_size], rax
    mov rax, [rel mmap_pending_desc_ver]
    mov [rel mmap_desc_ver], rax
    ret

; Preserve the executable half of UEFI Runtime Services inside our otherwise-NX
; identity map. A validated Manager Try handoff gains read availability only;
; mutable availability remains restricted to the nonce-bound mutable handoff.
; Every EfiRuntimeServicesCode descriptor must be nonempty and
; wholly covered; otherwise the publisher stays disabled rather than jumping
; into an NX or unmapped firmware page after EBS.
map_pbm_runtime_code:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  byte [rel pbm_runtime_code_mapped], 0
    mov  byte [rel pbm_runtime_read_mapped], 0
    cmp  byte [rel pbm_manager_launch], 1
    jne  .out
    cmp  byte [rel pbm_try_media], 1   ; read-only Try, never a writer grant
    je   .read_map
    test byte [rel pbm_flags], PBM_HF_MUTABLE_ATTEMPT
    jz   .out
.read_map:
    mov  rsi, [rel mmap_buffer]
    mov  r12, [rel mmap_size]
    mov  r13, [rel mmap_desc_size]
    test rsi, rsi
    jz   .out
    cmp  r13, 40
    jb   .out
    cmp  r13, 256
    ja   .out
    mov  r15, rsi
    add  r15, r12
    jc   .out
    xor  r14d, r14d                    ; executable runtime descriptors covered
.descriptor:
    cmp  rsi, r15
    jae  .done
    mov  rax, rsi
    add  rax, r13
    jc   .out
    cmp  rax, r15
    ja   .out
    ; Every EFI_MEMORY_RUNTIME range must be identity-mapped for the firmware
    ; call graph. Data/MMIO remains NX; only RuntimeServicesCode becomes X.
    bt   qword [rsi + 32], 63
    jnc  .next
    mov  rbx, [rsi + 24]              ; NumberOfPages
    test rbx, rbx
    jz   .out
    mov  rax, rbx
    shr  rax, 52                      ; page count << 12 must fit in u64
    jnz  .out
    shl  rbx, 12
    mov  rdx, [rsi + 8]               ; PhysicalStart
    add  rbx, rdx                     ; exclusive byte end
    jc   .out
    cmp  rbx, [rel ident_bytes]       ; every runtime byte must be mapped
    ja   .out
    cmp  dword [rsi], 5               ; EfiRuntimeServicesCode
    jne  .next
    and  rdx, ~0xFFF                  ; first covering 4 KiB page
.runtime_page:
    cmp  rdx, rbx
    jae  .runtime_done
    mov  rdi, rdx
    call paging_pd_entry_ptr          ; live PD entry, including RS-1 PDs
    test rax, rax
    jz   .out
    test qword [rax], 1               ; never publish coverage of an absent leaf
    jz   .out
    bt   qword [rax], 7
    jc   .runtime_large
    ; PDE0 is split for the SIPI code page. Clear NX only on runtime-code
    ; PTEs actually covered by this descriptor; adjacent data retains NX.
    mov  rdi, [rax]
    mov  rcx, 0x000FFFFFFFFFF000
    and  rdi, rcx
    mov  rcx, rdx
    shr  rcx, 12
    and  ecx, 511
    lea  rdi, [rdi + rcx*8]
    test qword [rdi], 1
    jz   .out
    btr  qword [rax], 63              ; parent permission must also permit X
    btr  qword [rdi], 63
    add  rdx, 0x1000
    jc   .out
    jmp  .runtime_page
.runtime_large:
    btr  qword [rax], 63
    and  rdx, ~0x1FFFFF
    add  rdx, 0x200000
    jc   .out
    jmp  .runtime_page
.runtime_done:
    inc  r14d
.next:
    add  rsi, r13
    jmp  .descriptor
.done:
    test r14d, r14d
    jz   .out
    mov  byte [rel pbm_runtime_read_mapped], 1
    cmp  byte [rel pbm_try_media], 1
    je   .out                        ; every existing writer gate remains closed
    mov  byte [rel pbm_runtime_code_mapped], 1
    lea  rdi, [rel str_pbm_runtime_mapped]
    call serial_string
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Every caller runs before a successful ExitBootServices, on the firmware's page
; tables, so the platform is never left dark (root 2026-10-08 20:09:57 (2)(a)):
; after the failure marker, UEFI 2.10 sec. 8.5.1 ResetSystem(EfiResetCold). It is a
; runtime service, legal both while boot services are live and after a failed
; ExitBootServices (sec. 7.4.6 then bars the BOOT services other than memory
; allocation; runtime services are not among them). The watchdog is not relied on
; here: a partial shutdown in a failed ExitBootServices may already have stopped
; the firmware timer that drives it. If it returns, the in-band CF9 reset
; (chainload_linux_reset_warm's fallback); only if both return, HLT.
EFI_RESET_COLD equ 0
exit_boot_and_page_fail:
    ; SYSTEM Y is cached before EBS (sec/system_secret). The hook uses RIP-relative
    ; image buffers and skips zero heap pointers: safe under the firmware CR3.
    ; All failure edges precede our CR3 switch; no return/reload follows the wipe.
    call reset_wipe_all
    lea rdi, [rel str_paging_fail]
    call serial_string
    lea rdi, [rel str_paging_fail_reset]
    call serial_string
    mov ecx, 0x100000                   ; serial is synchronous here: let the UART drain
.drain:
    pause
    dec ecx
    jnz .drain
    and rsp, -16
    sub rsp, 32
    mov rax, [rel runtime_services]
    test rax, rax
    jz  .cf9
    mov ecx, EFI_RESET_COLD
    mov rdx, 0x8000000000000015         ; EFI_ABORTED
    xor r8d, r8d                        ; DataSize
    xor r9d, r9d                        ; ResetData
    call [rax + 0x68]                   ; ResetSystem; never returns on success
.cf9:
    mov al, 0x06
    mov dx, 0x0CF9
    out dx, al
.hang:
    hlt
    jmp .hang

; Inventory buffer for the preliminary map walk. The final EBS map is still
; acquired independently after all allocations.
INV_MAP_BYTES equ 65536

; Derive identity-map extent from RAM-backed and EFI_MEMORY_RUNTIME descriptors.
; Result is clamped to 16..512 GiB; a failed inventory keeps the safe 16 GiB
; floor and emits an explicit degraded health fact later.
paging_inventory_extent:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    and  rsp, -16
    sub  rsp, 48
    mov  qword [rel ident_gib], 16
    mov  rax, 0x400000000
    mov  [rel ident_bytes], rax
    mov  qword [rel inv_top_of_ram], 0
    mov  qword [rel inv_rt_end], 0
    mov  word [rel inv_flags], 0
    mov  rax, [rel boot_services]
    mov  ecx, 2                          ; EfiLoaderData
    mov  edx, INV_MAP_BYTES
    lea  r8, [rel inv_map_buffer]
    call [rax + 0x40]                   ; AllocatePool
    test rax, rax
    jnz  .fallback
    mov  qword [rel inv_map_size], INV_MAP_BYTES
    lea  rcx, [rel inv_map_size]
    mov  rdx, [rel inv_map_buffer]
    lea  r8, [rel inv_map_key]
    lea  r9, [rel inv_map_desc_size]
    lea  rax, [rel inv_map_desc_ver]
    mov  [rsp + 32], rax
    mov  rax, [rel boot_services]
    call [rax + 0x38]                   ; GetMemoryMap
    test rax, rax
    jnz  .fallback
    mov  rsi, [rel inv_map_buffer]
    mov  r13, [rel inv_map_desc_size]
    cmp  r13, 40
    jb   .fallback
    cmp  r13, 256
    ja   .fallback
    mov  r15, rsi
    add  r15, [rel inv_map_size]
    xor  r12d, r12d                     ; top of RAM-backed/runtime memory
    xor  r14d, r14d                     ; top of runtime memory
.desc:
    cmp  rsi, r15
    jae  .walked
    mov  rbx, [rsi + 24]                ; NumberOfPages
    mov  rax, rbx
    shr  rax, 52
    jnz  .next
    shl  rbx, 12
    add  rbx, [rsi + 8]
    jc   .next
    bt   qword [rsi + 32], 63           ; EFI_MEMORY_RUNTIME
    jnc  .not_rt
    cmp  rbx, r14
    cmova r14, rbx
    jmp  .ram
.not_rt:
    mov  eax, [rsi]
    cmp  eax, 14
    ja   .next
    cmp  eax, 11
    jb   .low_type
    cmp  eax, 14                        ; persistent memory is RAM-backed
    jne  .next                          ; MMIO/MMIO-port/PAL do not widen map
    jmp  .ram
.low_type:
    test eax, eax
    jz   .next                          ; reserved
    cmp  eax, 8
    je   .next                          ; unusable
.ram:
    cmp  rbx, r12
    cmova r12, rbx
.next:
    add  rsi, r13
    jmp  .desc
.walked:
    mov  [rel inv_top_of_ram], r12
    mov  [rel inv_rt_end], r14
    mov  rax, r12
    add  rax, 0x3FFFFFFF
    shr  rax, 30                        ; ceil(top / 1 GiB)
    cmp  rax, 16
    jae  .above_floor
    mov  eax, 16
.above_floor:
    cmp  rax, 512
    jbe  .fits
    mov  eax, 512
    or   word [rel inv_flags], 1        ; truncated
.fits:
    mov  [rel ident_gib], rax
    shl  rax, 30
    mov  [rel ident_bytes], rax
    jmp  .out
.fallback:
    or   word [rel inv_flags], 2        ; inventory unavailable
.out:
    lea  rsp, [rbp - 40]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; RDI physical address -> RAX pointer to its live 2 MiB PD entry, or zero.
; Above the RAM identity extent, expose only an HDA-proven page in the owned
; MMIO pool. An xHCI UC leaf alone cannot substitute for HDA's inventory proof.
paging_pd_entry_ptr:
    mov  rax, rdi
    shr  rax, 30
    cmp  rax, [rel ident_gib]
    jae  .mmio
    cmp  rax, 16
    jae  .high
    shl  rax, 12
    add  rax, 0x2000
    jmp  .have
.high:
    sub  rax, 16
    shl  rax, 12
    add  rax, 0x19000
.have:
    add  rax, [rel pml4_addr]
.leaf:
    mov  rcx, rdi
    shr  rcx, 21
    and  rcx, 511
    lea  rax, [rax + rcx*8]
    ret
.mmio:
    cmp  rax, 512
    jae  .none
    ; Preserve the existing RDX ABI (UEFI runtime-code walk keeps its cursor
    ; there). Only our four appended MMIO PD pages may be followed here.
    push rdx
    mov  rdx, rdi
    and  rdx, ~0x1FFFFF
    xor  ecx, ecx
.mmio_proof:
    cmp  ecx, PAGING_HDA_BARS
    jae  .mmio_none
    cmp  ecx, [rel paging_hda_count]
    jae  .mmio_none
    bt   dword [rel paging_hda_high_proven], ecx
    jnc  .mmio_next
    lea  rax, [rel paging_hda_bars]
    mov  rax, [rax + rcx*8]
    and  rax, ~0x1FFFFF
    cmp  rax, rdx
    je   .mmio_owned
.mmio_next:
    inc  ecx
    jmp  .mmio_proof
.mmio_owned:
    mov  rax, rdi
    shr  rax, 30
    mov  rdx, [rel pml4_addr]
    mov  rax, [rdx + rax*8 + 0x1000]
    mov  ecx, eax
    and  ecx, 0xFFF
    and  ecx, ~0x20                    ; the hardware may have set Accessed
    cmp  ecx, 3                        ; P|RW, not PS or another owner/policy
    jne  .mmio_none
    and  rax, ~0xFFF
    mov  rcx, [rel ident_gib]
    sub  rcx, 16
    shl  rcx, 12
    lea  rdx, [rdx + rcx + 0x19000]
    cmp  rax, rdx
    jb   .mmio_none
    add  rdx, PAGING_XHCI_PDS * 0x1000
    cmp  rax, rdx
    jae  .mmio_none
    pop  rdx
    jmp  .leaf                         ; consumer still validates the live PDE
.mmio_none:
    pop  rdx
.none:
    xor  eax, eax
    ret

; RDI=firmware xHCI BAR. Return EAX=1 only for an identity-mapped UC+NX
; 2 MiB PDE covering the driver's entire 256 KiB aperture. No PCI writes.
%macro PAGING_XHCI_BAR_CHECK 0
paging_xhci_bar_mapped:
    xor  eax, eax
    mov  rcx, rdi
    and  ecx, 0x1FFFFF
    cmp  ecx, 0x1C0000
    ja   .not_mapped
    mov  rcx, rdi
    shr  rcx, 30
    cmp  rcx, 512
    jae  .not_mapped
    mov  rdx, [rel pml4_addr]
    add  rdx, 0x1000
    mov  rdx, [rdx + rcx*8]
    test dl, 1
    jz   .not_mapped
    test dl, 0x80
    jnz  .not_mapped
    mov  rcx, 0x000FFFFFFFFFF000
    and  rdx, rcx
    mov  rcx, rdi
    shr  rcx, 21
    and  ecx, 511
    mov  rdx, [rdx + rcx*8]
    mov  ecx, edx
    and  ecx, 0x93
    cmp  ecx, 0x93                     ; P | RW | PCD | PS
    jne  .not_mapped
    bt   rdx, 63                       ; NX required
    jnc  .not_mapped
    mov  rcx, 0x000FFFFFFFE00000
    and  rdx, rcx
    and  rdi, rcx
    cmp  rdx, rdi                      ; identity, not an alias
    jne  .not_mapped
    mov  eax, 1
.not_mapped:
    ret
%endmacro

paging_extent_report:
    lea  rdi, [rel str_extent_pre]
    call serial_string
    mov  rdi, [rel ident_gib]
    call serial_hex64
    lea  rdi, [rel str_extent_top]
    call serial_string
    mov  rdi, [rel inv_top_of_ram]
    call serial_hex64
    lea  rdi, [rel str_extent_flags]
    call serial_string
    movzx edi, word [rel inv_flags]
    call serial_hex64
    lea  rdi, [rel str_extent_ok]
    cmp  word [rel inv_flags], 0
    jne  .bad
    mov  rax, [rel inv_top_of_ram]
    cmp  rax, [rel ident_bytes]
    jbe  .emit
.bad:
    lea  rdi, [rel str_extent_trunc]
.emit:
    call serial_string
    ret

; --- boot/paging data (in-image for now; pre-W^X) ---
pt_alloc_buf:   dq 0                    ; AllocatePages base (below 4 GiB)
vmd_ecam_phys:  dq 0                    ; Intel VMD CFGBAR (child ECAM) seen on bus 0 pre-EBS, 0 = none
vmd_window_gb:  dq 0                    ; GiB index of the 2 GiB VMD window mapped above 16 GiB, 0 = none
vmd_root_bdf_boot: dd -1                ; bus<<16|dev<<8|fn of that root, -1 = none
wx_test_page:   dq 0                    ; owned NX-test page (core/idt wx_selftest)
heap_base:      dq 0                    ; kernel heap region (core/heap.asm)
heap_size:      dq 0
model_heap_base: dq 0                   ; dedicated large-model streaming region
model_heap_size: dq 0
; Immutable full LoaderData allocation, including any retained model prefix.
; The ownership census uses these, while the allocator uses the available tail.
model_heap_alloc_base: dq 0
model_heap_alloc_size: dq 0
fb_shadow_region_base: dq 0             ; 2026-09-08: back buffer RAM below 4 GiB (gui/window fb_shadow_attach)
fb_shadow_region_size: dq 0
crash_identity_base: dq 0               ; fixed page after v3 diag ring, no fallback
diag_ring_base: dq 0                    ; fixed persistent diag ring (core/diag.asm)
filmstrip_ring_base: dq 0               ; fixed same-boot filmstrip arena (svc/command_filmstrip.asm)
pmod_region_base: dq 0                  ; fixed 1 GiB PMOD virtual ABI anchor
pmod_region_phys: dq 0                  ; firmware-selected 64 KiB backing allocation
pmod_pt_alloc: dq 0                     ; raw PT allocation (alignment owner)
pmod_pt_addr: dq 0                      ; sparse module 4 KiB page table
pmod_sandbox_alloc: dq 0                ; raw CR3 allocation (alignment owner)
pmod_sandbox_pml4: dq 0                 ; distinct Tier-1 CR3 root
pmod_sandbox_pdpt: dq 0                 ; private low-half PDPT for module window
pmod_sandbox_pd: dq 0                   ; private 1-2 GiB module-window PD
pml4_addr:      dq 0
mmap_owned_buffer:      dq 0           ; retained allocation, never a failed OUT map
mmap_capacity:          dq 0           ; independent of firmware's returned/required size
mmap_pending_size:      dq 0
mmap_pending_key:       dq 0
mmap_pending_desc_size: dq 0
mmap_pending_desc_ver:  dq 0           ; UINT32 output, upper half cleared before every read
mmap_final_status:      dq -1          ; raw last GetMemoryMap status, -1 before any call
mmap_admit_reason:      dd 0           ;0=admitted,1=buffer,2=size,3=shape,4=range,
                                      ;5=overlap,6=sum,7=owner drift,8=GetMemoryMap failed,9=private index refused
align 8
mmap_buffer:    dq 0
mmap_size:      dq 0
mmap_key:       dq 0
mmap_desc_size: dq 0
mmap_desc_ver:  dq 0
%include "core/abi/wdata.inc"
; Loader-owned zero-fill tail, inside PE VirtualSize and RW+NX after paging.
; Boot writes occur pre-EBS; retry rebuilds only the current admitted prefix. After
; boot only the T1-4.8 refusal KAT (core/mmap_refusal.asm) claims it, on private input.
%macro WDATA_boot_mmap_intervals 0
alignb 16
mmap_interval_workspace:
mmap_interval_busy: resq 1
mmap_interval_count: resq 1
mmap_interval_index: resq MMAP_INTERVAL_CAP * 2
mmap_interval_index_end:
mmap_interval_workspace_end:
%endmacro
WDATA_BSS_DEFER WDATA_boot_mmap_intervals
PAGING_XHCI_PDS equ 4                   ; shared MMIO PD pool, xHCI has first use
PAGING_HDA_BARS equ 32                  ; private bounded pending list; no allocations
PAGING_HDA_XHCI_PAGES equ 64
; Emit data with the helpers AFTER gop_mode_list, preserving the known-safe
; pre-GOP addresses and historical table-allocation layout.
%macro PAGING_HDA_DATA 0
; First legacy NVMe, public boot observations; never mutated after CR3 install.
align 8
paging_nvme_bar: dq 0
paging_nvme_proven: dq 0
paging_nvme_leaf: dq 0
paging_nvme_pdpt_entry: dq 0
paging_nvme_pml4_entry: dq 0
paging_nvme_pdpt_value: dq 0
paging_nvme_pml4_value: dq 0
paging_nvme_found: dd 0
paging_nvme_bdf: dd 0
paging_hda_count: dd 0
paging_hda_xhci_count: dd 0
paging_hda_overflow: dd 0              ; exhaustion refuses ALL HDA retags
paging_hda_pd_used: dd 0               ; high MMIO pages used by xHCI then HDA
paging_hda_high_proven: dd 0           ; bits for pending BARs admitted by full proof
%ifidn RCQ50_G0_FLR_LAB,1
paging_flr_count: dd 0                 ; RCQ-50 G0 lab: pinned FLR endpoints the walk saw
paging_flr_bar: dd 0                   ; its 32-bit BAR0 (0: none or unsupported)
%endif
align 8
paging_hda_bars: times PAGING_HDA_BARS dq 0
paging_hda_bdfs: times PAGING_HDA_BARS dd 0
paging_hda_xhci_pages: times PAGING_HDA_XHCI_PAGES dq 0
%endmacro
ident_gib:      dq 16                   ; identity-map extent, GiB
ident_bytes:    dq 0x400000000          ; identity-map extent, bytes
inv_top_of_ram: dq 0
inv_rt_end:     dq 0
inv_flags:      dw 0                    ; bit0 truncated, bit1 inventory unavailable
pt_alloc_pages: dq 0
inv_map_buffer: dq 0
inv_map_size:   dq 0
inv_map_key:    dq 0
inv_map_desc_size: dq 0
inv_map_desc_ver:  dq 0
str_paging_ok:   db "[PAOS64] M1 paging: EBS done, CR3 loaded (16GiB identity)", 13, 10, 0
str_pbm_runtime_mapped: db "[PAOS64] Boot v2 UEFI runtime-code descriptors executable in owned identity map [boot.v2.runtime.mapped]",13,10,0
str_wx_ok:       db "[PAOS64] M1 W^X: NXE+WP on, data pages NX (image X)", 13, 10, 0
str_paging_fail: db "[PAOS64] M1 paging: FAILED (EBS/alloc)", 13, 10, 0
str_paging_fail_reset: db "[PAOS64] M1 paging: cold reset, not a dark halt [boot.ebs.fail.reset]", 13, 10, 0
str_extent_pre:  db "[PAOS64] M1 paging: identity extent_gib=", 0
str_extent_top:  db " inventory_top=", 0
str_extent_flags: db " flags=", 0
str_extent_ok:   db " covers inventory [memory.map.inventory.ok]", 13, 10, 0
str_extent_trunc: db " TRUNCATED or inventory unavailable [memory.map.inventory.truncated]", 13, 10, 0

; --- 1249 framebuffer cache policy facts (paging-owned) ---
fb_pt_used:       dd 0                  ; spare 4 KiB tables consumed by the exact-range split (max 2)
fb_pat_programmed: db 0
paging_fb_unmapped: db 0             ; 1: fb at GiB >= 511, outside the low PDPT; display disabled
align 8
paging_fb_gop_base: dq 0           ; DISPLAY (msi-b70): GOP fb base at the fb map step (0 = no GOP)
str_fb_unmapped:  db "[PAOS64] M1 paging: framebuffer at GiB >= 511 is outside the low PDPT; display disabled (headless) [paging.fb.unmapped]", 13, 10, 0
str_fb_policy:    db "[PAOS64] P1 paging: framebuffer cache policy memtype=", 0
str_fb_policy_2m: db " pages_2m=", 0
str_fb_policy_4k: db " pages_4k=", 0
str_fb_nl:        db 13, 10, 0
preebs_wdt_status:  dq -1               ; the last SetWatchdogTimer status (0 = armed/disarmed)
%ifdef PAOS_LAB_EBS_FAIL
%if PAOS_PUBLIC_BUILD
%error "PAOS_LAB_EBS_FAIL is a QEMU-lab define; never in a public build"
%endif
%endif
%ifdef PAOS_LAB_PREEBS_HANG
str_lab_preebs_hang: db '[PAOS64] lab.preebs.hang (QEMU lab: deliberate pre-EBS wedge)',13,10,0
%endif

%include "boot/hp_usb_mapping.inc"

%include "core/abi/wdata.inc"
%macro WDATA_BSS_boot_runtime_read 0
pbm_runtime_read_mapped: resb 1 ; coverage only, never authorizes persistent writes
%endmacro
WDATA_BSS_DEFER WDATA_BSS_boot_runtime_read
