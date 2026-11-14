;; MODULE core/dma
;; LAYER 1
;; EXPORTS dma_init, dma_alloc, dma_alloc_domain, dma_virt_to_phys, dma_selftest, dma_iommu_map, dma_iommu_unmap, dma_iommu_lookup, dma_iommu_record, dma_iommu_bind, dma_domain_bind, dma_domain_attach, dma_domain_receipt, dma_domain_live_bind, dma_domain_live_receipt
;; IMPORTS boot/serial, core/heap
;; CAPS
;; OWNER saga:core
; ============================================================================
; core/dma.asm — page-aligned, identity-mapped DMA buffer allocator.
;
; Device descriptor rings (e1000e TX/RX, AHCI command list, NVMe queues) hand a
; PHYSICAL address to hardware, then the driver reads/writes the same memory by
; VIRTUAL address. With our identity map (boot/paging.asm: 4 KiB and 2 MiB leaves)
; phys==virt for everything below 16 GiB, so a buffer carved from the kernel heap
; (a UEFI conventional-memory region <16 GiB, RW+NX) is already identity-mapped.
; This module makes that guarantee explicit + page-aligned: rings must not strad-
; dle a page in a way the device's DMA engine cares about, and many HW descriptor
; bases require 4 KiB (or larger) alignment.
;
; M2 = bump only (no free), same rationale as core/heap: ring buffers live for the
; life of the device and are never freed (the old tree's dma_pool was bump-only
; too). A reserved pool is grabbed from the heap once, page-aligned; dma_alloc
; bump-allocates page-aligned, page-rounded buffers from it. Returns 0 on OOM.
;
; dma_alloc returns ONE value used as BOTH phys and virt (they are equal). The
; self-test proves equality the hard way: it walks the live page tables (CR3 ->
; PML4 -> PDPT -> PD -> optional PT) and asserts the translated physical address
; equals the virtual address it started from.
;
; IOMMU-map SEAM (1112): every device address is produced by dma_iommu_map,
; which starts as a degenerate identity map (iova == phys == virt) but RECORDS
; each live mapping's [base,len]. VT-d enforcement (1111) binds the real map
; implementation here and turns those records into the native domain valid-set.
; The signature and every dma_alloc call site remain byte-identical. The same
; numeric identity address remains both the CPU pointer and device IOVA; the
; restrictive VT-d leaf, rather than a different number, provides enforcement.
; The table is NOT cleared by dma_init: mappings track device lifetime, not
; pool lifetime (e1000e re-calls dma_init for a fresh pool while earlier rings
; stay live).
;
; DOMAIN TAGS (RCQ-36 S5b DID 3): every record carries a tag naming the device
; domain its pages belong to. Tag 0 (DMA_DOM_NATIVE) is the DID-2 native domain
; every dma_alloc site uses; tag 1 (DMA_DOM_HDA) is the HDA-only DID 3. Any other
; tag is refused before the pool moves. The tag is written in the same commit
; step as base/len (before len publishes the slot) and cleared with them; the
; unmap hook receives the RECORDED tag, so a caller cannot choose another
; domain at retire. Pool spans are page-rounded and never overlap, so two tags
; never share a 4 KiB page. The domain attach/receipt seam lets a layer-3 owner
; (HDA) ask the bound IOMMU owner to move its function into the tag's domain
; and read back the receipt; with nothing bound the answer is no_enforcement.
; ============================================================================

DMA_PAGE        equ 4096
DMA_POOL_SIZE   equ 0x100000                ; 1 MiB reserved DMA region
DMA_IOMMU_SLOTS equ 128                     ; live-mapping record table capacity
DMA_DOM_NATIVE  equ 0                       ; record tag: native DID 2 (every dma_alloc site)
DMA_DOM_HDA     equ 1                       ; record tag: HDA-only DID 3 (RCQ-36 S5b)
DMA_DOM_R_UNBOUND equ 3                     ; dma_domain_attach reason: no IOMMU owner bound
DMA_ADVERSE_TABLE_BYTES equ DMA_IOMMU_SLOTS * 16
DMA_ADVERSE_TAG_BYTES equ DMA_IOMMU_SLOTS
DMA_ADVERSE_NEXT equ DMA_ADVERSE_TABLE_BYTES + DMA_ADVERSE_TAG_BYTES
DMA_ADVERSE_END equ DMA_ADVERSE_NEXT + 8
DMA_ADVERSE_LATCH equ DMA_ADVERSE_END + 8
DMA_ADVERSE_STACK equ DMA_ADVERSE_LATCH + 16

; address field masks for the 4-level walk (clears P/RW/US/NX + reserved bits)
DMA_PHYS_MASK   equ 0x000FFFFFFFFFF000      ; 4 KiB-frame address field (bits 51:12)
DMA_2M_MASK     equ 0x000FFFFFFFE00000      ; 2 MiB-frame address field (bits 51:21)

; dma_init — reserve the DMA pool from the heap, page-align its base.
dma_init:
    push rbx
    mov  edi, DMA_POOL_SIZE + DMA_PAGE      ; +1 page of slack to absorb alignment
    call kmalloc
    test rax, rax
    jz   .fail
    add  rax, DMA_PAGE - 1                  ; round base up to a page boundary
    jc   .fail                             ; keep the old pool if alignment wraps
    and  rax, ~(DMA_PAGE - 1)
    mov  rdx, rax
    add  rax, DMA_POOL_SIZE
    jc   .fail                             ; no partial replacement on bad extent
    mov  [rel dma_base], rdx                ; retain the reservation, not just cursor
    mov  [rel dma_next], rdx
    mov  [rel dma_end], rax
.fail:
    pop  rbx
    ret

; dma_alloc(RDI=size) -> RAX = phys==virt buffer (page-aligned), or 0 on OOM.
; The returned device address is produced by the dma_iommu_map seam (identity
; today) — callers are unchanged; only the seam's internals gain the hook.
; Native domain (tag 0); RSI and RCX are preserved for the driver sites.
dma_alloc:
    push rsi
    xor  esi, esi                           ; DMA_DOM_NATIVE
    call dma_alloc_domain
    pop  rsi
    ret

; dma_alloc_domain(RDI=size, ESI=tag) -> RAX = phys==virt buffer, or 0 on OOM,
; a failed map, or a tag other than DMA_DOM_NATIVE/DMA_DOM_HDA (refused before
; the pool moves). The first HDA map refusal latches until reboot; later HDA
; attempts allocate nothing (srcreview L1). Never reclaim a failed map's span:
; its best-effort rollback may leave cached translations after a timeout.
; Native allocations use the same mapping path. RSI and RCX are preserved.
; Empty sizes, rounding overflow and inconsistent/uninitialized pool state refuse
; before the pool, mapping table or HDA map-failure latch can change. The retained
; base and fixed extent bound the cursor; equality of mutable fields is not a
; memory-corruption or concurrency proof. Successful dma_init replaces the pool
; without retiring earlier device mappings, as before.
dma_alloc_domain:
    cmp  esi, DMA_DOM_HDA
    ja   .oom
    jne  .allocate
    cmp  byte [rel dma_hda_map_refused], 0
    jne  .oom
.allocate:
    test rdi, rdi
    jz   .oom
    cmp  rdi, -DMA_PAGE                     ; largest size whose round-up fits
    ja   .oom
    add  rdi, DMA_PAGE - 1                  ; round size up to whole pages
    and  rdi, ~(DMA_PAGE - 1)
    mov  rax, [rel dma_base]
    test rax, rax
    jz   .oom                              ; no reservation has been established
    test rax, DMA_PAGE - 1
    jnz  .oom
    mov  rdx, rax
    add  rdx, DMA_POOL_SIZE
    jc   .oom
    cmp  rdx, [rel dma_end]
    jne  .oom                              ; limit must still name this reservation
    mov  rax, [rel dma_next]
    test rax, DMA_PAGE - 1
    jnz  .oom
    cmp  rax, [rel dma_base]
    jb   .oom                              ; never publish a page below the pool
    mov  rdx, rax
    add  rdx, rdi
    jc   .oom
    cmp  rdx, [rel dma_end]
    ja   .oom
    mov  [rel dma_next], rdx
    push rsi                                ; keep dma_alloc's visible clobbers
    push rcx                                ; unchanged for the 28 driver sites
    mov  edx, esi                           ; tag
    mov  rsi, rdi                           ; len (page-rounded)
    mov  rdi, rax                           ; virt
    call dma_iommu_map                      ; RAX = identity-valued IOVA
    pop  rcx
    pop  rsi
    test rax, rax
    jnz  .out
    cmp  esi, DMA_DOM_HDA
    jne  .out
    mov  byte [rel dma_hda_map_refused], 1
.out:
    ret
.oom:
    xor  eax, eax
    ret

; dma_iommu_map(RDI=virt, RSI=len, EDX=tag) -> RAX = iova the device may use.
; Records the live [base,len,tag]. Before dma_iommu_bind this is the 1112
; identity seam. Once bound, the hook map(RDI=virt, RSI=len, EDX=tag) must
; install the same numeric address as a real IOVA in the tag's domain before
; the record becomes visible. An unknown tag is refused, and a full table
; never admits an untracked non-native buffer. Clobbers rcx, rdx, r10, r11.
dma_iommu_map:
    mov  r10d, edx                          ; tag
    cmp  r10d, DMA_DOM_HDA
    ja   .fail
    lea  rdx, [rel dma_iommu_table]
    xor  ecx, ecx
.scan:
    cmp  ecx, DMA_IOMMU_SLOTS
    jae  .full
    cmp  qword [rdx + 8], 0                 ; len==0 => free slot
    je   .record
    add  rdx, 16
    inc  ecx
    jmp  .scan
.record:
    mov  r11, [rel dma_iommu_map_hook]
    test r11, r11
    jz   .commit                            ; pre-VT-d: record identity seam
    push rdx
    push rdi
    push rsi
    push r10
    mov  edx, r10d
    call r11                                ; real map(virt,len,tag) -> iova
    pop  r10
    pop  rsi
    pop  rdi
    pop  rdx
    test rax, rax
    jz   .fail                              ; enforcement active: fail closed
    cmp  rax, rdi                           ; one-value ABI uses identity IOVA
    jne  .fail
.commit:
    lea  r11, [rel dma_iommu_table]
    mov  rcx, rdx
    sub  rcx, r11
    shr  ecx, 4                             ; slot index
    lea  r11, [rel dma_iommu_dom]
    mov  [r11 + rcx], r10b                  ; tag first: len publishes the slot
    mov  [rdx], rdi                         ; base
    mov  [rdx + 8], rsi                     ; len
    mov  rax, rdi
    ret
.full:
    cmp  qword [rel dma_iommu_map_hook], 0
    jne  .fail                              ; active domain cannot admit untracked DMA
    test r10d, r10d
    jnz  .fail                              ; a non-native buffer is never untracked
    mov  rax, rdi                           ; 1112 pre-bind compatibility
    ret
.fail:
    xor  eax, eax
    ret

; dma_iommu_unmap(RDI=iova, RSI=len) -> RAX=1 removed, 0 not found.
; Under enforcement, clear hardware first and retire the valid-set record only
; after the VT-d unmap succeeds. The hook unmap(RDI, RSI, EDX=tag) gets the
; recorded tag. Clobbers rcx, rdx, r10, r11.
dma_iommu_unmap:
    lea  rdx, [rel dma_iommu_table]
    xor  ecx, ecx
.scan:
    cmp  ecx, DMA_IOMMU_SLOTS
    jae  .notfound
    cmp  qword [rdx + 8], 0                 ; skip free slots
    je   .next
    cmp  [rdx], rdi
    jne  .next
    cmp  [rdx + 8], rsi
    jne  .next
    mov  r11, [rel dma_iommu_unmap_hook]
    test r11, r11
    jz   .clear
    push rcx
    push rdx
    push rdi
    push rsi
    lea  r10, [rel dma_iommu_dom]
    movzx edx, byte [r10 + rcx]             ; the recorded tag, never the caller's
    call r11
    pop  rsi
    pop  rdi
    pop  rdx
    pop  rcx
    test rax, rax
    jz   .notfound
.clear:
    xor  eax, eax
    mov  [rdx], rax                         ; clear the record
    mov  [rdx + 8], rax
    lea  r10, [rel dma_iommu_dom]
    mov  [r10 + rcx], al                    ; and its tag (rc-sec C2)
    mov  eax, 1
    ret
.next:
    add  rdx, 16
    inc  ecx
    jmp  .scan
.notfound:
    xor  eax, eax
    ret

; dma_iommu_lookup(RDI=iova) -> RAX = recorded len (0 if not a live mapping).
; Clobbers rcx, rdx.
dma_iommu_lookup:
    lea  rdx, [rel dma_iommu_table]
    xor  ecx, ecx
.scan:
    cmp  ecx, DMA_IOMMU_SLOTS
    jae  .absent
    cmp  qword [rdx + 8], 0
    je   .next
    cmp  [rdx], rdi
    je   .hit
.next:
    add  rdx, 16
    inc  ecx
    jmp  .scan
.hit:
    mov  rax, [rdx + 8]
    ret
.absent:
    xor  eax, eax
    ret

; dma_iommu_record(RDI=index) -> RAX=base, RDX=len, ECX=tag (all zero if
; absent). Read-only enumeration for the IOMMU owners; the table remains private.
dma_iommu_record:
    cmp  rdi, DMA_IOMMU_SLOTS
    jae  .absent
    lea  rax, [rel dma_iommu_dom]
    movzx ecx, byte [rax + rdi]
    shl  rdi, 4
    lea  rax, [rel dma_iommu_table]
    add  rax, rdi
    mov  rdx, [rax + 8]
    test rdx, rdx
    jz   .absent
    mov  rax, [rax]
    ret
.absent:
    xor  eax, eax
    xor  edx, edx
    xor  ecx, ecx
    ret

; dma_iommu_bind(RDI=map_fn, RSI=unmap_fn) -> RAX=1 bound, 0 refused.
; Publish map last so an allocator cannot see mapping active without unmap.
; Passing two zeroes cleanly unbinds during a failed VT-d initialization.
dma_iommu_bind:
    test rdi, rdi
    jz   .unbind
    test rsi, rsi
    jz   .bad
    mov  [rel dma_iommu_unmap_hook], rsi
    mfence
    mov  [rel dma_iommu_map_hook], rdi
    mov  eax, 1
    ret
.unbind:
    test rsi, rsi
    jnz  .bad
    mov  qword [rel dma_iommu_map_hook], 0
    mfence
    mov  qword [rel dma_iommu_unmap_hook], 0
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; dma_domain_bind(RDI=attach_fn, RSI=receipt_fn) -> RAX=1 bound, 0 refused.
; The IOMMU owner publishes its domain attach/receipt pair; two zeroes unbind.
; attach(EDI=packed BDF, RSI=controller MMIO, EDX=tag) -> EAX 0 attached or a
; nonzero refusal; receipt(EDI=tag) -> EAX 1 ok / 0, RDX=map serial,
; RSI=NUL-terminated receipt line. Receipt is published last.
dma_domain_bind:
    test rdi, rdi
    jz   .unbind
    test rsi, rsi
    jz   .bad
    mov  qword [rel dma_domain_live_receipt_hook], 0
    mfence
    mov  [rel dma_domain_attach_hook], rdi
    mfence
    mov  [rel dma_domain_receipt_hook], rsi
    mov  eax, 1
    ret
.unbind:
    test rsi, rsi
    jnz  .bad
    mov  qword [rel dma_domain_live_receipt_hook], 0
    mfence
    mov  qword [rel dma_domain_receipt_hook], 0
    mfence
    mov  qword [rel dma_domain_attach_hook], 0
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; dma_domain_attach(EDI=packed BDF, RSI=controller MMIO, EDX=tag) -> EAX = 0
; attached, else a nonzero refusal: DMA_DOM_R_UNBOUND when no owner is bound or
; the tag is not a separate domain (only DMA_DOM_HDA is). Clobbers like a call.
dma_domain_attach:
    cmp  edx, DMA_DOM_HDA
    jne  .unbound
    mov  rax, [rel dma_domain_attach_hook]
    test rax, rax
    jz   .unbound
    jmp  rax
.unbound:
    mov  eax, DMA_DOM_R_UNBOUND
    ret

; dma_domain_live_bind(RDI=live_receipt_fn) -> EAX 1 bound/unbound, 0 refused.
; The strict attach/receipt pair must already exist. Rebinding that pair clears
; this hook, so a replacement owner cannot inherit an old live receipt.
dma_domain_live_bind:
    test rdi, rdi
    jz   .publish
    cmp  qword [rel dma_domain_attach_hook], 0
    je   .bad
    cmp  qword [rel dma_domain_receipt_hook], 0
    je   .bad
.publish:
    mfence
    mov  [rel dma_domain_live_receipt_hook], rdi
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; dma_domain_receipt(EDI=tag) -> EAX 1 ok / 0, RDX=map serial (0 if none),
; RSI=receipt line. With nothing bound: EAX 0, RDX 0, RSI = the unbound line.
dma_domain_receipt:
    cmp  edi, DMA_DOM_HDA
    jne  .unbound
    mov  rax, [rel dma_domain_receipt_hook]
    test rax, rax
    jz   .unbound
    jmp  rax
.unbound:
    xor  eax, eax
    xor  edx, edx
    lea  rsi, [rel str_dma_dom_unbound]
    ret

; dma_domain_live_receipt(EDI=tag) -> same registers as the strict receipt.
; Valid only after a strict attach; permits the owner's active DMA lifecycle.
dma_domain_live_receipt:
    cmp  edi, DMA_DOM_HDA
    jne  .unbound
    mov  rax, [rel dma_domain_live_receipt_hook]
    test rax, rax
    jz   .unbound
    jmp  rax
.unbound:
    xor  eax, eax
    xor  edx, edx
    lea  rsi, [rel str_dma_dom_unbound]
    ret

; dma_virt_to_phys(RDI=virt) -> RAX=phys, or zero for an unsupported/absent map.
; Four-level walk with 2 MiB PDE or 4 KiB PTE leaves, including split PDE0.
; Our map has no 1 GiB leaves. Proof tool, not a fast path; preserves R8.
dma_virt_to_phys:
    push r8
    mov  rax, rdi
    shl  rax, 16
    sar  rax, 16
    cmp  rax, rdi                           ; canonical under the four-level map?
    jne  .unmapped
    mov  r8, DMA_PHYS_MASK                  ; 64-bit mask must live in a reg (no imm64 AND)
    mov  rax, cr3
    and  rax, r8                            ; PML4 base
    mov  rcx, rdi                           ; PML4 index = va[47:39]
    shr  rcx, 39
    and  rcx, 0x1FF
    mov  rax, [rax + rcx*8]                 ; PML4E
    test al, 1
    jz   .unmapped
    and  rax, r8                            ; PDPT base
    mov  rcx, rdi                           ; PDPT index = va[38:30]
    shr  rcx, 30
    and  rcx, 0x1FF
    mov  rax, [rax + rcx*8]                 ; PDPTE
    test al, 1
    jz   .unmapped
    test al, 0x80                          ; 1 GiB leaves are outside our map
    jnz  .unmapped
    and  rax, r8                            ; PD base (our map: PDPTE -> PD, no 1G pages)
    mov  rcx, rdi                           ; PD index = va[29:21]
    shr  rcx, 21
    and  rcx, 0x1FF
    mov  rax, [rax + rcx*8]                 ; PDE: either 2 MiB leaf or PT pointer
    test al, 1
    jz   .unmapped
    test al, 0x80
    jnz  .large
    and  rax, r8                            ; PT base
    mov  rcx, rdi
    shr  rcx, 12
    and  rcx, 0x1FF
    mov  rax, [rax + rcx*8]                 ; 4 KiB PTE (bit 7 is PAT, not PS)
    test al, 1
    jz   .unmapped
    and  rax, r8                            ; 4 KiB frame base
    mov  rcx, rdi
    and  rcx, 0xFFF
    jmp  .offset
.large:
    mov  r8, DMA_2M_MASK
    and  rax, r8                            ; 2 MiB frame base
    mov  rcx, rdi
    and  rcx, 0x1FFFFF                      ; + offset within the 2 MiB page
.offset:
    add  rax, rcx
    pop  r8
    ret
.unmapped:
    xor  eax, eax
    pop  r8
    ret

; dma_selftest — two buffers: page-aligned, non-overlapping, writable, phys==virt.
dma_selftest:
    push rbx
    push r12
    push r13
    call dma_init
    ; --- buffer 1 ---
    mov  edi, DMA_PAGE
    call dma_alloc
    test rax, rax
    jz   .fail
    mov  rbx, rax                           ; buf1
    mov  r13, rax                           ; retain original live control for adverse checks
    test rax, DMA_PAGE - 1                  ; page-aligned?
    jnz  .fail
    mov  qword [rbx], 0x5AFED00D            ; writable
    ; --- buffer 2 ---
    mov  edi, DMA_PAGE
    call dma_alloc
    test rax, rax
    jz   .fail
    mov  r12, rax                           ; buf2
    test rax, DMA_PAGE - 1
    jnz  .fail
    mov  qword [r12], 0x0BADCAFE            ; writable
    ; non-overlapping: buf2 must start at/after buf1 + its page
    lea  rcx, [rbx + DMA_PAGE]
    cmp  r12, rcx
    jb   .fail
    cmp  qword [rbx], 0x5AFED00D            ; buf1 intact (buf2 write didn't alias it)
    jne  .fail
    ; identity map: phys==virt for both buffers (real page-table walk)
    mov  rdi, rbx
    call dma_virt_to_phys
    cmp  rax, rbx
    jne  .fail
    mov  rdi, r12
    call dma_virt_to_phys
    cmp  rax, r12
    jne  .fail
    ; --- 1112 IOMMU-map seam, scale-1 KAT (checks first, print only on pass) ---
    mov  edi, DMA_PAGE
    call dma_alloc                          ; routes through dma_iommu_map
    test rax, rax
    jz   .fail
    mov  rbx, rax                           ; buf3 = map_iova (buf1 checks done)
    mov  rdi, rax                           ; identity_ok: iova == page-walk phys
    call dma_virt_to_phys
    cmp  rax, rbx
    jne  .fail
    mov  rdi, rbx                           ; recorded: [base,len] tracked
    call dma_iommu_lookup
    cmp  rax, DMA_PAGE
    jne  .fail
    mov  rdi, rbx                           ; unmap round-trip
    mov  rsi, DMA_PAGE
    call dma_iommu_unmap
    cmp  rax, 1
    jne  .fail
    mov  rdi, rbx                           ; removed: no longer a live mapping
    call dma_iommu_lookup
    test rax, rax
    jnz  .fail
    mov  rdi, r13                          ; original two live, owned buffers
    mov  rsi, r12
    call dma_adverse_selftest
    test eax, eax
    jz   .fail
    lea  rdi, [rel str_dma_refusal_ok]
    call serial_string
    lea  rdi, [rel str_dma_seam1]
    call serial_string
    mov  rdi, rbx
    call serial_hex64
    lea  rdi, [rel str_dma_seam2]
    call serial_string
    mov  rdi, rbx
    call serial_hex64
    lea  rdi, [rel str_dma_seam3]
    call serial_string
    lea  rdi, [rel str_dma_ok]
    call serial_string
    pop  r13
    pop  r12
    pop  rbx
    ret
.fail:
    lea  rdi, [rel str_dma_fail]
    call serial_string
    pop  r13
    pop  r12
    pop  rbx
    ret

; Boot-only bounded adverse checks after the original allocation/page-walk and
; unmap control. RDI/RSI are the original two live pages, never device-owned.
; Use actual allocator inputs, without rewriting pool bounds, mapping hooks,
; tags or failure latches. No new allocation can succeed in these seven cases.
; Snapshot the entire mapping/tag state; verify it and both complete canary
; pages after EACH refusal. The ordinary third-page unmap stays unchanged.
; EAX=1 only after every check. A pre-existing HDA latch cannot masquerade as
; exercising its OOM/size checks, so it refuses this diagnostic unchanged.

dma_adverse_selftest:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, DMA_ADVERSE_STACK
    mov  r14, rsp
    mov  r12, rdi
    mov  r13, rsi
    cmp  byte [rel dma_hda_map_refused], 0
    jne  .fail
    ; Fill only the two already-owned success-control pages.
    mov  rdi, r12
    mov  eax, 0x5AFED00D
    mov  ecx, DMA_PAGE / 8
    cld
    rep  stosq
    mov  rdi, r13
    mov  eax, 0x0BADCAFE
    mov  ecx, DMA_PAGE / 8
    rep  stosq
    mov  rdi, r14
    lea  rsi, [rel dma_iommu_table]
    mov  ecx, DMA_ADVERSE_TABLE_BYTES / 8
    rep  movsq
    lea  rsi, [rel dma_iommu_dom]
    mov  ecx, DMA_ADVERSE_TAG_BYTES / 8
    rep  movsq
    mov  rax, [rel dma_next]
    mov  [r14 + DMA_ADVERSE_NEXT], rax
    mov  rax, [rel dma_end]
    mov  [r14 + DMA_ADVERSE_END], rax
    movzx eax, byte [rel dma_hda_map_refused]
    mov  [r14 + DMA_ADVERSE_LATCH], rax
    mov  ebx, 1
    ; Valid sizes larger than CURRENT remaining capacity: real pool OOM,
    ; including HDA, which must not set its map-failure latch on size refusal.
    mov  rdi, [rel dma_end]
    sub  rdi, [rel dma_next]
    add  rdi, DMA_PAGE
    xor  esi, esi
    call dma_alloc_domain
    call .unchanged
    and  ebx, eax
    mov  rdi, [rel dma_end]
    sub  rdi, [rel dma_next]
    add  rdi, DMA_PAGE
    mov  esi, DMA_DOM_HDA
    call dma_alloc_domain
    call .unchanged
    and  ebx, eax
    xor  edi, edi
    xor  esi, esi
    call dma_alloc_domain
    call .unchanged
    and  ebx, eax
    xor  edi, edi
    mov  esi, DMA_DOM_HDA
    call dma_alloc_domain
    call .unchanged
    and  ebx, eax
    mov  rdi, -1
    xor  esi, esi
    call dma_alloc_domain
    call .unchanged
    and  ebx, eax
    mov  rdi, -1
    mov  esi, DMA_DOM_HDA
    call dma_alloc_domain
    call .unchanged
    and  ebx, eax
    mov  edi, DMA_PAGE
    mov  esi, DMA_DOM_HDA + 1
    call dma_alloc_domain
    call .unchanged
    and  ebx, eax
    mov  eax, ebx
    jmp  .out
.fail:
    xor  eax, eax
.out:
    add  rsp, DMA_ADVERSE_STACK
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.unchanged:
    test rax, rax
    jnz  .bad
    mov  rax, [r14 + DMA_ADVERSE_NEXT]
    cmp  rax, [rel dma_next]
    jne  .bad
    mov  rax, [r14 + DMA_ADVERSE_END]
    cmp  rax, [rel dma_end]
    jne  .bad
    movzx eax, byte [rel dma_hda_map_refused]
    cmp  rax, [r14 + DMA_ADVERSE_LATCH]
    jne  .bad
    mov  rdi, r14
    lea  rsi, [rel dma_iommu_table]
    mov  ecx, DMA_ADVERSE_TABLE_BYTES / 8
    cld
    repe cmpsq
    jne  .bad
    lea  rdi, [r14 + DMA_ADVERSE_TABLE_BYTES]
    lea  rsi, [rel dma_iommu_dom]
    mov  ecx, DMA_ADVERSE_TAG_BYTES / 8
    repe cmpsq
    jne  .bad
    mov  rdi, r12
    mov  eax, 0x5AFED00D
    mov  ecx, DMA_PAGE / 8
    repe scasq
    jne  .bad
    mov  rdi, r13
    mov  eax, 0x0BADCAFE
    mov  ecx, DMA_PAGE / 8
    repe scasq
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

dma_base:      dq 0                        ; established only by successful dma_init
dma_next:      dq 0
dma_end:       dq 0
dma_iommu_map_hook:   dq 0
dma_iommu_unmap_hook: dq 0
dma_domain_attach_hook:  dq 0
dma_domain_receipt_hook: dq 0
dma_domain_live_receipt_hook: dq 0
; live-mapping record table: DMA_IOMMU_SLOTS x {base dq, len dq}; len==0 = free
dma_iommu_table: times DMA_IOMMU_SLOTS * 2 dq 0
str_dma_refusal_ok: db "[PAOS64] memory.dma adverse oom=2 zero=2 wrap=2 tag=1 cursor=unchanged mappings=unchanged tags=unchanged latch=unchanged buffers=intact [memory.dma.adverse.ok]", 13, 10, 0
str_dma_ok:    db "[PAOS64] M2 dma: alloc/identity-mapped buffer OK", 13, 10, 0
str_dma_fail:  db "[PAOS64] M2 dma: FAILED", 13, 10, 0
; fields are literal 1s because the line prints only after each is asserted
str_dma_seam1: db "[PAOS64] dma.iommu.seam map_iova=", 0
str_dma_seam2: db " base=", 0
str_dma_seam3: db " recorded=1 identity_ok=1 unmapped=1", 13, 10, 0
str_dma_dom_unbound: db "dma.domain state=refused reason=no_enforcement", 0

%include "core/abi/wdata.inc" ; WDATA_BSS_DEFER; standalone assemblies expand blocks in place
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER).
%macro WDATA_core_dma_0_bss1 0
alignb 64
dma_iommu_dom: resb DMA_IOMMU_SLOTS          ; per-record domain tag, parallel to dma_iommu_table
dma_hda_map_refused: resb 1                 ; sticky for this boot; dma_init does not clear it
%endmacro
WDATA_BSS_DEFER WDATA_core_dma_0_bss1
