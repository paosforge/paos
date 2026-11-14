;; MODULE bus/pci_bdf
;; LAYER 2
;; EXPORTS pci_ecam_cfg_snapshot, pci_ecam_acs_snapshot, pci_ecam_acs_enable, pci_ecam_aer_control_snapshot, pci_ecam_aer_coverage_snapshot, pci_bdf_read, pci_bdf_write, pci_find_cap, mmio_mark_uc, pci_ecam_aer_snapshot, pci_mmio_resource_page, pci_mmio_resource_page_diagnostic, pci_mmio_nonram_chunk
;; IMPORTS bus/pci_aer_control, bus/pci, boot/paging, bus/acpi
;; CAPS CAP_MMIO
;; OWNER saga:bus
; ============================================================================
; Vendor-neutral PCI helpers over a packed BDF (bus:8, dev:5, fn:3), plus the
; MMIO UC marking every IOMMU and MMIO-owning driver needs before its first
; register access. Moved byte-for-byte from hv/vtd.asm (RCQ-18-AMDVI-S3a
; D-pci) so hv/amdvi and dev/input/i2c_hid do not depend on the Intel module.
; ============================================================================

; EDI=packed BDF, ESI=config offset -> EAX=config dword. ESI is preserved.
pci_bdf_read:
    push rbx
    mov  ebx, esi                         ; preserve caller's config offset
    mov  ecx, esi
    mov  edx, edi
    and  edx, 7
    mov  esi, edi
    shr  esi, 3
    and  esi, 0x1F
    shr  edi, 8
    call pci_cfg_read32
    mov  esi, ebx
    pop  rbx
    ret

; EDI=packed BDF, ESI=config offset, EDX=value -> pci_cfg_write32.
pci_bdf_write:
    mov  r8d, edx
    mov  ecx, esi
    mov  edx, edi
    and  edx, 7
    mov  esi, edi
    shr  esi, 3
    and  esi, 0x1F
    shr  edi, 8
    jmp  pci_cfg_write32

; EDI=packed BDF, ESI=capability ID -> EAX=capability offset or zero.
pci_find_cap:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, esi
    mov  esi, 4
    call pci_bdf_read
    test eax, 0x00100000                 ; PCI Status.Capabilities List
    jz   .none
    mov  edi, r12d
    mov  esi, 0x34
    call pci_bdf_read
    and  eax, 0xFC
    mov  ebx, eax
    mov  ecx, 32                         ; malformed/cyclic lists stay bounded
.next:
    test ebx, ebx
    jz   .none
    cmp  ebx, 0xFC
    ja   .none
    mov  edi, r12d
    mov  esi, ebx
    push rcx
    call pci_bdf_read
    pop  rcx
    movzx edx, al
    cmp  edx, r13d
    je   .found
    shr  eax, 8
    and  eax, 0xFC
    mov  ebx, eax
    dec  ecx
    jnz  .next
.none:
    xor  eax, eax
    jmp  .out
.found:
    mov  eax, ebx
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Mark the 2 MiB identity-map page containing RDI as true UC (PCD+PWT).
; This is Classic's proven mark_mmio_uncacheable sequence adapted locally so
; an IOMMU seam does not invent a second page-table layout.
mmio_mark_uc:
    push rbx
    mov  rax, rdi
    shr  rax, 21
    cmp  rax, 8192                       ; rework maps exactly 0..16 GiB
    jae  .bad
    mov  rbx, [rel pml4_addr]
    test rbx, rbx
    jz   .bad
    lea  rbx, [rbx + 0x2000]
    test byte [rbx + rax*8], 1
    jz   .bad
    or   qword [rbx + rax*8], 0x18       ; PCD|PWT = UC regardless of MTRR
    mov  rax, rdi
    and  rax, -0x200000
    invlpg [rax]
    mfence
    mov  eax, 1
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret

; pci_ecam_aer_snapshot(RDI=segment-0 packed BDF0..65535, RSI=private64B)
; -> EAX: pci_aer_snapshot status0..5, 6 unavailable mapping/MCFG,
; 7 absent device, 8 identity changed, 9 resource not admitted.
; For pci_ecam_aer_snapshot, admitted calls propagate pci_aer_snapshot R8..R11
; diagnostics; pre-reader transport refusal returns an all-zero tuple.
; BSP command context only. No device write, reporting enable, ack, isolation or
; event-count claim. Refusal preserves output. Low16GiB identity leaves only:
; a whole2MiB leaf must be inside one validated MCFG allocation AND a saved
; firmware Reserved/MMIO descriptor. RAM/partial/unmapped/split/nonidentity/PAT
; leaves refuse. Reuse mmio_mark_uc before the first ECAM load; this changes
; owned page-table cache bits, never device configuration. No new mappings.
; CF8 and ECAM vendor/device must agree; each reader call rechecks identity.
; These checks cannot make PCI hot removal or a physical bus fault recoverable.
pci_ecam_aer_snapshot:
    lea rdx,[rel pci_aer_snapshot]
    jmp pci_ecam_aer_snapshot_common

pci_ecam_aer_coverage_snapshot:
    lea rdx,[rel pci_aer_coverage_snapshot]
    jmp pci_ecam_aer_snapshot_common

pci_ecam_aer_control_snapshot:
    lea rdx,[rel pci_aer_control_snapshot]
    jmp pci_ecam_aer_snapshot_common

; U3a: pci_ecam_acs_snapshot(RDI=segment-0 packed BDF, RSI=private64B) -> EAX:
; pci_acs_snapshot status 0..5 over exactly the same admitted ECAM transport, CF8/ECAM
; identity rechecks and Linux extended-config applicability (12 not applicable) as
; the AER readers above; 6..9 are the same transport refusals. Read-only.
pci_ecam_acs_snapshot:
    lea rdx,[rel pci_acs_snapshot]
    jmp pci_ecam_aer_snapshot_common

pci_ecam_aer_snapshot_common:
    cmp rdi, 65535
    ja .bad_request
    test rsi, rsi
    jz .bad_request
    mov rax, rsi
    add rax, 63
    jc .bad_request
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 168                    ; snapshot64, context16, callback8, admission80
    mov [rsp+80],rdx
    mov ebx, edi
    mov r12, rsi
    mov edi, ebx
    lea rsi, [rsp+88]               ; private admission witness, not AER output
    call pci_ecam_admit
    test edx, edx
    jnz .admission_refused
    mov r13, rax
    mov edi, ebx
    xor esi, esi
    call pci_bdf_read
    mov ebp, eax
    cmp ax, 0xffff
    je .absent
    test ax, ax
    jz .absent
    cmp eax, [r13]
    jne .identity
    mov [rsp+64], r13
    mov [rsp+72], ebp
    mov rdi,r13
    call pci_ecam_aer_applicability
    cmp ebp,[r13]
    jne .identity
    test eax,eax
    jnz .done
    lea rdi, [rel pci_ecam_aer_read32]
    lea rsi, [rsp+64]
    mov rdx, rsp
    mov ecx, 64
    call qword [rsp+80]
    test eax, eax
    jnz .done
    cmp ebp, [r13]
    jne .identity
    mov rdi, r12
    mov rsi, rsp
    mov ecx, 8
    rep movsq
    xor eax, eax
    jmp .done
.admission_refused:
    mov eax, edx
    jmp .done
.absent:
    mov eax, 7
    jmp .done
.identity:
    mov eax, 8
    jmp .done
.done:
    ; R8..R11 diagnostic tuple is meaningful only for the admitted AER callback.
    ; Transport refusals never expose volatile helper contents or stale samples.
    cmp eax, 12
    je .diagnostic_ready
    cmp eax, 6
    jb .diagnostic_ready
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
.diagnostic_ready:
    add rsp, 168
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.bad_request:
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    mov eax, 4
    ret

; W3 (ROOT 109394, SEC 109421 C1-C5): pci_ecam_acs_enable(EDI=segment-0 packed BDF)
; -> EAX status, EDX ACS Capability|Control<<16 before (0 if unread), ECX after
; (0 unless resampled). Takes no offset and no value: the ACS capability comes
; from pci_ecam_acs_snapshot, and the only store is its Control halfword (cap+6)
; = Control_before | SV|RR|CR|UF through the admitted UC ECAM leaf. The store is
; made only when Capability holds all four and Control lacks one, right after a
; fresh CF8/ECAM identity recheck and an unchanged ACS header and Cap|Control.
; It never clears a bit (DT/TB/EC/egress untouched). Success requires a fresh
; stable resample with the same offset, header and Capability and Control
; exactly Control_before|0x1D. Status: 0 enabled (or already enabled; no store),
; 1-9/12 snapshot or transport refusal (no store), 10 Capability lacks a required
; bit (no store), 11 resample refused or differs after the store. The isolation
; gate never trusts this result: pcia_iso_cb reads ACS fresh at every gate.
; 0x1D = SV(0) | RR(2) | CR(3) | UF(4), the gate's PCIA_ACS_REQUIRED.
pci_ecam_acs_enable:
    cmp rdi, 65535
    ja .bad_request
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 160                       ; sample64 @0, admission80 @64, aligned calls
    mov ebx, edi
    mov edi, ebx
    mov rsi, rsp
    call pci_ecam_acs_snapshot
    xor edx, edx
    xor ecx, ecx
    test eax, eax
    jnz .done
    mov r12d, [rsp]                    ; ACS capability offset
    mov r13d, [rsp+4]                  ; ACS header
    mov r14d, [rsp+8]                  ; Capability low16, Control high16
    mov edx, r14d
    mov eax, r14d
    and eax, 0x1D
    cmp eax, 0x1D
    jne .incapable
    mov eax, r14d
    shr eax, 16
    and eax, 0x1D
    cmp eax, 0x1D
    je .resample                       ; already enabled: no store
    mov edi, ebx
    lea rsi, [rsp+64]
    call pci_ecam_admit
    test edx, edx
    jnz .admission_refused
    mov r15, rax                       ; admitted function address
    mov edi, ebx
    xor esi, esi
    call pci_bdf_read                  ; CF8 identity under pci_cfg_io_lock
    cmp ax, 0xffff
    je .absent
    test ax, ax
    jz .absent
    cmp eax, [r15]
    jne .identity
    cmp r12d, 0xff8
    ja .malformed
    cmp r13d, [r15+r12]
    jne .changed
    cmp r14d, [r15+r12+4]
    jne .changed
    mov eax, r14d
    shr eax, 16
    or eax, 0x1D
    mov [r15+r12+6], ax                ; the single ECAM store (SEC C1)
.resample:
    mov edi, ebx
    mov rsi, rsp
    call pci_ecam_acs_snapshot
    mov edx, r14d
    xor ecx, ecx
    test eax, eax
    jnz .readback
    mov ecx, [rsp+8]
    cmp [rsp], r12d
    jne .readback
    cmp [rsp+4], r13d
    jne .readback
    mov eax, r14d
    or eax, 0x1D << 16
    cmp ecx, eax                       ; SEC C2: exactly before | 0x1D
    jne .readback
    xor eax, eax
    jmp .done
.incapable:
    mov eax, 10
    jmp .done
.readback:
    mov eax, 11
    jmp .done
.admission_refused:
    mov eax, edx
    jmp .refused
.absent:
    mov eax, 7
    jmp .refused
.identity:
    mov eax, 8
    jmp .refused
.malformed:
    mov eax, 2
    jmp .refused
.changed:
    mov eax, 5
.refused:                              ; before any store: no after value
    mov edx, r14d
    xor ecx, ecx
.done:
    add rsp, 160
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.bad_request:
    xor edx, edx
    xor ecx, ecx
    mov eax, 4
    ret

; Private shared admission, RDI=validated packed BDF, RSI=private80B.
; Returns RAX=function address, EDX=0/6/9; zeroes record then retains finite
; admission witnesses even on refusal. NO device load or CF8 identity read.
; Existing validated MCFG allocation, whole Reserved/MMIO leaf, exact identity
; RW/large/PAT0 and UC guards are shared by AER and the independent diagnostic.
pci_ecam_admit:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov ebx, edi
    mov r12, rsi
    mov rdi, rsi
    xor eax, eax
    mov ecx, 10
    rep stosq
    lea rdi, [rel acpi_mcfg_entries]
    mov esi, [rel acpi_mcfg_count]
    xor edx, edx                    ; segment0 only
    mov ecx, ebx
    shr ecx, 8
    mov r8d, ebx
    shr r8d, 3
    and r8d, 31
    mov r9d, ebx
    and r9d, 7
    call pci_ecam_resolve_span
    test edx, edx
    jnz .unavailable
    mov r13, rax
    mov [r12+8], rax
    shr rax, 34                     ; existing mmio_mark_uc covers low16GiB
    jnz .unavailable
    mov r14, r13
    and r14, -0x200000
    mov [r12+16], r14
    ; Resolver validated all <=4 allocations. Admit the entire cache leaf,
    ; including the bus immediately before an odd start bus, or refuse it.
    lea r10, [rel acpi_mcfg_entries]
    mov r11d, [rel acpi_mcfg_count]
.allocation:
    test r11d, r11d
    jz .resource_refused
    cmp word [r10+8], 0
    jne .next_allocation
    movzx eax, byte [r10+10]
    shl rax, 20
    add rax, [r10]
    cmp r14, rax
    jb .next_allocation
    movzx eax, byte [r10+11]
    inc eax
    shl rax, 20
    add rax, [r10]
    lea rdx, [r14+0x200000]
    cmp rdx, rax
    jbe .resource
.next_allocation:
    add r10, 16
    dec r11d
    jmp .allocation
.resource:
    mov rax, [r10]
    mov [r12], rax
    mov eax, [r10+8]
    mov [r12+48], eax
    mov rdi, r14
    call pci_ecam_resource_page
    test eax, eax
    jz .resource_refused
    ; On success resource_page retains its covering descriptor in R8, end RCX.
    mov rax, [r8+8]
    mov [r12+24], rax
    mov [r12+32], rcx
    mov eax, [r8]
    mov [r12+52], eax
    mov rdi, r14
    call paging_pd_entry_ptr
    test rax, rax
    jz .unavailable
    mov rbp, rax
    mov r15, [rax]
    mov [r12+40], r15
    mov eax, r15d
    and eax, 0x1083                  ; present/RW/large, PAT must be0
    cmp eax, 0x83
    jne .unavailable
    mov rax, 0x000fffffffe00000
    and r15, rax
    cmp r15, r14                    ; exact physical identity, not just present
    jne .unavailable
    mov rdi, r14
    call mmio_mark_uc
    test eax, eax
    jz .unavailable
    mov rax, [rbp]
    mov [r12+40], rax               ; actual post-UC PDE, not an invented value
    mov rax, r13
    xor edx, edx
    jmp .done
.unavailable:
    mov edx, 6
    jmp .done
.resource_refused:
    mov edx, 9
.done:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Independent ECAM header observation, NEVER an AER acceptance path.
; RDI=segment0 packed BDF, RSI=private80B, EDX=1(ID only) or7(00/08/0c).
; EAX=0 raw read,4 bad request,6 mapping unavailable,9 resource refused.
; Valid requests zero80B and retain partial admission witnesses on refusal;
; invalid requests preserve output. Layout: six QWORDs MCFGbase/function/leaf/
; FWstart/FWend/PDE; DWORDs MCFG(segment16/start8/end8),FWtype; six raw DWORDs
; first00/08/0c,repeat00/08/0c. Unrequested raw DWORDs stay zero.
; Exactly2 or6 UC DWORD loads, no CF8 prerequisite, no config writes, no
; capabilities walk. Raw zero/ffff/mismatch is evidence, never absence or PASS.
pci_ecam_cfg_snapshot:
    cmp rdi, 65535
    ja .bad
    test rsi, rsi
    jz .bad
    mov rax, rsi
    add rax, 79
    jc .bad
    cmp edx, 1
    je .valid
    cmp edx, 7
    jne .bad
.valid:
    push rbx
    push r12
    push r13
    mov ebx, edx
    mov r12, rsi
    call pci_ecam_admit
    test edx, edx
    jnz .refused
    mov r13, rax
    mov eax, [r13]
    mov [r12+56], eax
    cmp ebx, 1
    je .repeat
    mov eax, [r13+8]
    mov [r12+60], eax
    mov eax, [r13+12]
    mov [r12+64], eax
.repeat:
    lfence
    mov eax, [r13]
    mov [r12+68], eax
    cmp ebx, 1
    je .ok
    mov eax, [r13+8]
    mov [r12+72], eax
    mov eax, [r13+12]
    mov [r12+76], eax
.ok:
    xor eax, eax
    jmp .done
.refused:
    mov eax, edx
.done:
    pop r13
    pop r12
    pop rbx
    ret
.bad:
    mov eax, 4
    ret

 ; RDI=admitted, identity-checked UC function page. No config writes.
; Return0=extended config accessible;12=not applicable;2=malformed legacy
; capability chain. Linux drivers/pci/probe.c pci_cfg_space_size[_ext] rules:
; host bridge, PCIe, or PCI-X2 may have extended config; ordinary PCI does not.
; All-ones100 qualifies only256B; alias requires ALL15 potential aliases.
; Bounded48 conventional entries,15 alias reads. Refusals preserve sample.
; diag reason15=legacy256,16=allones100,17=full alias,18=bad legacy list.
pci_ecam_aer_applicability:
    xor r8d,r8d
    xor r9d,r9d
    xor r10d,r10d
    xor r11d,r11d
    mov eax,[rdi+8]
    shr eax,16
    cmp ax,0x0600                       ; host bridge exception in Linux
    je .extended
    test dword [rdi+4],0x100000          ; PCI_STATUS_CAP_LIST
    jz .legacy
    movzx eax,byte [rdi+0x0e]
    and eax,0x7f
    cmp eax,2
    ja .malformed
    mov ecx,0x34
    cmp eax,2
    jne .pointer
    mov ecx,0x14                       ; CardBus header
.pointer:
    movzx ecx,byte [rdi+rcx]
    and ecx,0xfc
    mov edx,48
.cap:
    test ecx,ecx
    jz .legacy
    cmp ecx,0x40
    jb .malformed
    cmp ecx,0xfc
    ja .malformed
    test edx,edx
    jz .malformed
    dec edx
    mov eax,[rdi+rcx]
    cmp al,0x10                       ; PCI Express capability
    je .extended
    cmp al,7                          ; PCI-X capability
    jne .next_cap
    cmp ecx,0xf8
    ja .malformed
    test dword [rdi+rcx+4],0xc0000000  ; PCI_X_STATUS_266MHZ|533MHZ
    jnz .extended
.next_cap:
    movzx ecx,ah
    and ecx,0xfc
    jmp .cap
.extended:
    mov eax,[rdi+0x100]
    mov r9d,eax
    mov rcx,0x100
    shl rcx,32
    or r9,rcx                         ; header at100
    mov r10,0x100000000                ; EDX0, available1
    mov r11d,1
    cmp eax,-1
    je .all_ones
    cmp eax,[rdi]
    jne .yes
    mov ecx,0x200
.alias:
    inc r11d
    mov edx,[rdi+rcx]
    cmp edx,eax
    jne .yes
    add ecx,0x100
    cmp ecx,0x1000
    jb .alias
    mov r8,0x10000000011                 ; reason17 at100
    mov eax,12
    ret
.all_ones:
    mov r8,0x10000000010                 ; reason16 at100
    mov eax,12
    ret
.legacy:
    mov r8d,15
    mov eax,12
    ret
.malformed:
    mov r8d,18
    mov eax,2
    ret
.yes:
    xor eax,eax
    ret

; Trusted private context {Q admitted function base, D vendor/device}. Full-width
; bounds precede every load; offset0..0xffc, aligned. No legacy offset alias.
pci_ecam_aer_read32:
    cmp rsi, 0xffc
    ja .bad
    test sil, 3
    jnz .bad
    mov rax, [rdi]
    mov edx, [rax]
    cmp edx, [rdi+8]
    jne .bad
    mov eax, [rax+rsi]
    xor edx, edx
    ret
.bad:
    xor eax, eax
    mov edx, 1
    ret

; NIC BAR admission (VM 106805, ROOT 106811). RDI = 2 MiB-aligned chunk whose end
; is at or below 16 GiB -> EAX 1 admit, 0 refuse. Same saved final map and shape
; checks as the whole-leaf walk below, with boot/paging.asm .hda_inventory's
; non-RAM rule: every descriptor overlapping the chunk must be MMIO (11), MMIO
; port (12) or UC-only reserved (0 without WC/WT/WB), never runtime-backed; any
; other or unknown type is RAM. A chunk no descriptor overlaps is an undescribed
; non-RAM gap (OVMF's PCI aperture): firmware describes all RAM. Read-only: no
; descriptor, device or table write and no retained pointer. Leaf; clobbers only
; RAX, RCX, RDX, R8-R11.
pci_mmio_nonram_chunk:
    test rdi, 0x1FFFFF
    jnz .no
    mov r11, rdi
    add r11, 0x200000
    jc .no
    mov rax, 0x400000000
    cmp r11, rax
    ja .no
    mov r8, [rel mmap_buffer]
    test r8, r8
    jz .no
    mov r9, [rel mmap_desc_size]
    cmp r9, 40
    jb .no
    cmp r9, 256
    ja .no
    test r9b, 7
    jnz .no
    mov rax, [rel mmap_size]
    xor edx, edx
    div r9
    test rdx, rdx
    jnz .no
    test rax, rax
    jz .no
    cmp rax, 4096
    ja .no
    mov r10, rax
.row:
    mov rcx, [r8+24]                    ; pages
    test rcx, rcx
    jz .next                            ; an empty descriptor owns no page
    mov rdx, rcx
    shr rdx, 52
    jnz .no
    mov rax, [r8+8]                     ; physical start
    test rax, 0xFFF
    jnz .no
    shl rcx, 12
    add rcx, rax
    jc .no                              ; RCX = exclusive end
    cmp rax, r11
    jae .next                           ; starts at or after the chunk end
    cmp rcx, rdi
    jbe .next                           ; ends at or before the chunk start
    bt qword [r8+32], 63                ; runtime-backed is never eligible
    jc .no
    mov edx, [r8]
    test edx, edx
    jz .reserved
    cmp edx, 11                         ; EfiMemoryMappedIO
    je .next
    cmp edx, 12                         ; EfiMemoryMappedIOPortSpace
    je .next
    jmp .no                             ; all other or unknown types are RAM
.reserved:
    test dword [r8+32], 0x0E            ; reserved WC/WT/WB could still be RAM
    jnz .no
.next:
    add r8, r9
    dec r10
    jnz .row
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; RDI=aligned low16GiB page. Saved final UEFI map was fully validated at EBS;
; retain bounded shape checks here and require the whole leaf in one reserved
; (type0) or MMIO(type11) descriptor. Missing firmware description is unavailable,
; never an invitation to change RAM cacheability. No descriptor or device write.
; Same admission walk, optional fixed128B caller-owned diagnostic.
; RDI=leaf, RSI=diagnostic; only called by the fixed EDU prepare path.
; No pointer retained, no extra scan, no descriptor or device writes.
pci_mmio_resource_page_diagnostic:
    push rbx
    mov rbx,rsi
    jmp pci_ecam_resource_page.start

pci_mmio_resource_page:
; Shared read-only whole-leaf resource admission for the fixed EDU probe.
pci_ecam_resource_page:
    push rbx
    xor ebx,ebx                         ; legacy ECAM callers observe no new state
.start:
    test rbx,rbx
    jz .shape_saved
    mov rax,[rel mmap_size]
    mov [rbx+32],rax
    mov rax,[rel mmap_desc_size]
    mov [rbx+40],rax
.shape_saved:
    mov r8, [rel mmap_buffer]
    test r8, r8
    jz .no_map
    mov r9, [rel mmap_desc_size]
    cmp r9, 40
    jb .no_short
    cmp r9, 256
    ja .no_long
    test r9b, 7
    jnz .no_stride
    mov rax, [rel mmap_size]
    xor edx, edx
    div r9
    test rdx, rdx
    jnz .no_tail
    test rax, rax
    jz .no_empty
    cmp rax, 4096
    ja .no_count
    mov r10, rax
    lea r11, [rdi+0x200000]
.row:
    test rbx,rbx
    jz .counted
    inc dword [rbx+52]
.counted:
    mov rax, [r8+8]
    cmp rdi, rax
    jb .next
    mov rcx, [r8+24]
    shr rcx, 52
    jnz .no_pages
    mov rcx, [r8+24]
    shl rcx, 12
    add rcx, rax
    jc .no_overflow
    call .candidate                     ; raw row covering leaf start, if any
    cmp r11, rcx
    ja .next
    cmp dword [r8], 0
    je .yes
    cmp dword [r8], 11
    jne .no_type
.yes:
    test rbx,rbx
    jz .accepted
    mov dword [rbx+48],12
.accepted:
    mov eax, 1
    pop rbx
    ret
.next:
    add r8, r9
    dec r10
    jnz .row
    mov eax,11
    jmp .reject
.no_map: mov eax,1
    jmp .reject
.no_short: mov eax,2
    jmp .reject
.no_long: mov eax,3
    jmp .reject
.no_stride: mov eax,4
    jmp .reject
.no_tail: mov eax,5
    jmp .reject
.no_empty: mov eax,6
    jmp .reject
.no_count: mov eax,7
    jmp .reject
.no_pages: mov eax,8
    jmp .malformed
.no_overflow: mov eax,9
.malformed:
    test rbx,rbx
    jz .reject
    mov dword [rbx+60],2
    call .copy_row
    jmp .reject
.no_type: mov eax,10
.reject:
    test rbx,rbx
    jz .rejected
    mov [rbx+48],eax
.rejected:
    xor eax,eax
    pop rbx
    ret
.candidate:
    test rbx,rbx
    jz .no_copy
    cmp rcx,rdi                         ; prior start<=leaf; end must exceed it
    jbe .no_copy
    mov dword [rbx+60],1
.copy_row:
    mov edx,[rbx+52]
    dec edx
    mov [rbx+56],edx
    mov rdx,[r8]
    mov [rbx+64],rdx
    mov rdx,[r8+8]
    mov [rbx+72],rdx
    mov rdx,[r8+16]
    mov [rbx+80],rdx
    mov rdx,[r8+24]
    mov [rbx+88],rdx
    mov rdx,[r8+32]
    mov [rbx+96],rdx
.no_copy:
    ret
