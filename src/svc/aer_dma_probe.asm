;; MODULE svc/aer_dma_probe
;; LAYER 5
;; EXPORTS aer_dma_prepare, aer_dma_tick, aer_dma_before_stop, aer_dma_page
;; IMPORTS bus/pci_bdf, bus/pci_contain, bus/hal, boot/paging, core/dma, core/time
;; CAPS CAP_MMIO
;; OWNER saga:resilience
; Fixed QEMU EDU proof fixture, owner-mutating prepare, one attempt per boot.
; Never used to enable reporting or stop a device. The independent AER path
; stops the subtree even if this witness refuses. No post-stop MMIO/config write.
; EDU v8.2.2: 64B transfers, 100ms virtual timer, 32-bit register accesses >=0x80
; zero-extend the 64-bit DMA fields. Owned identity DMA page must fit below4GiB.
; No mapping/IOMMU bypass, arbitrary address/BDF, interrupt or recovery command.
; States0 untouched,1 loading,2 positive pending,3 ready,4 negative pending,
; 5 postguard observed,6 refused/failed. State5 alone is NOT H3 proof: the host
; must join raw buffers, exact native stop, native times and actual fault input.

; Fixed retained diagnostic, offsets and guard IDs: T1_7_DMA_DIAGNOSTIC.md.
; MOV-only instrumentation preserves the original guard flags/branches.
%macro DMA_GUARD 1
    mov dword [rel aer_dma_diagnostic+4],%1
    mov qword [rel aer_dma_diagnostic+8],0
    mov qword [rel aer_dma_diagnostic+16],0
%endmacro
%macro DMA_OBS 1
    mov [rel aer_dma_diagnostic+8],%1
%endmacro

aer_dma_prepare:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    cmp dword [rel aer_dma_record],0
    jne .out
    mov dword [rel aer_dma_record],6        ; latch BEFORE any qualification/I/O
    mov dword [rel aer_dma_record+4],0x20
    mov dword [rel aer_dma_record+60],1
    mov dword [rel aer_dma_diagnostic],2
    DMA_GUARD 1
    call aer_dma_hypervisor
    DMA_OBS rax
    test eax,eax
    jz .out
    DMA_GUARD 2
    mov edi,0x20
    call pci_contain_lookup
    test rax,rax
    jnz .out                              ; quarantine is never undone
    mov edi,0x20
    xor esi,esi
    DMA_GUARD 3
    call pci_bdf_read
    DMA_OBS rax
    cmp eax,0x000c1b36                     ; fixed QEMU pcie-root-port
    jne .out
    mov edi,0x20
    mov esi,8
    DMA_GUARD 4
    call pci_bdf_read
    DMA_OBS rax
    shr eax,16
    cmp ax,0x0604
    jne .out
    mov edi,0x20
    mov esi,12
    DMA_GUARD 5
    call pci_bdf_read
    DMA_OBS rax
    shr eax,16
    and eax,0x7f
    cmp eax,1
    jne .out
    mov edi,0x20
    mov esi,0x10
    DMA_GUARD 6
    call pci_find_cap
    DMA_OBS rax
    test eax,eax
    jz .out
    mov edi,0x20
    mov esi,eax
    DMA_GUARD 7
    call pci_bdf_read
    DMA_OBS rax
    shr eax,20
    and eax,15
    cmp eax,4
    jne .out
    mov edi,0x20
    mov esi,24
    DMA_GUARD 8
    call pci_bdf_read
    DMA_OBS rax
    test al,al                            ; primary bus0 only
    jnz .out
    movzx ebx,ah
    DMA_GUARD 9
    DMA_OBS rbx
    test ebx,ebx
    jz .out
    shr eax,16
    and eax,255
    DMA_GUARD 10
    DMA_OBS rax
    cmp eax,ebx
    jb .out
    inc eax
    shl eax,8
    mov r13d,eax                          ; exclusive BDF end <=65536
    shl ebx,8
    xor r12d,r12d                         ; unique endpoint count
.scan:
    mov edi,ebx
    xor esi,esi
    call pci_bdf_read
    cmp eax,0x11e81234
    jne .next
    inc r12d
    DMA_GUARD 11
    DMA_OBS r12
    cmp r12d,1
    jne .out
    mov [rel aer_dma_record+8],ebx
    mov [rel aer_dma_record+12],eax
.next:
    inc ebx
    cmp ebx,r13d
    jb .scan
    DMA_GUARD 12
    DMA_OBS r12
    cmp r12d,1
    jne .out
    mov ebx,[rel aer_dma_record+8]
    mov edi,ebx
    mov esi,8
    DMA_GUARD 13
    call pci_bdf_read
    DMA_OBS rax
    cmp al,0x10                           ; known EDU register contract revision
    jne .out
    mov edi,ebx
    mov esi,12
    DMA_GUARD 14
    call pci_bdf_read
    DMA_OBS rax
    test eax,0x007f0000                   ; ordinary endpoint header
    jnz .out
    mov edi,ebx
    mov esi,16
    DMA_GUARD 15
    call pci_bdf_read
    DMA_OBS rax
    test eax,0x000fffff                   ; 32-bit nonprefetch,1MiB-aligned BAR0
    jnz .out
    DMA_GUARD 16
    DMA_OBS rax
    test eax,eax
    jz .out
    mov [rel aer_dma_record+16],eax
    mov [rel aer_dma_region],rax
    mov qword [rel aer_dma_region+8],0x100000
    mov r14,rax
    and r14,-0x200000
    mov [rel aer_dma_diagnostic+24],r14
    DMA_GUARD 17
    mov rdi,r14
    lea rsi,[rel aer_dma_diagnostic]
    call aer_dma_resource_page
    DMA_OBS rax           ; whole cache leaf firmware or qualified PCI MMIO
    test eax,eax
    jz .out
    mov rdi,r14
    DMA_GUARD 18
    call paging_pd_entry_ptr
    test rax,rax
    jz .out
    mov r15,[rax]
    DMA_GUARD 19
    DMA_OBS r15
    mov eax,r15d
    and eax,0x1083
    cmp eax,0x83                          ; present,RW,large, PAT0
    jne .out
    DMA_GUARD 20
    DMA_OBS r15
    mov rax,0x000fffffffe00000
    and r15,rax
    cmp r15,r14                           ; existing identity leaf only
    jne .out
    mov rdi,r14
    DMA_GUARD 21
    call mmio_mark_uc
    DMA_OBS rax
    test eax,eax
    jz .out
    mov edi,4096
    DMA_GUARD 22
    call dma_alloc
    test rax,rax
    jz .out
    mov r12,rax
    DMA_GUARD 23
    DMA_OBS r12
    lea rdx,[rax+4095]
    shr rdx,32
    jnz .out                              ; HAL32 EDU address fields: no truncation
    DMA_GUARD 24
    DMA_OBS r12
    test eax,4095
    jnz .out
    mov rdi,r12
    DMA_GUARD 25
    call dma_virt_to_phys
    DMA_OBS rax
    mov [rel aer_dma_diagnostic+16],r12
    cmp rax,r12
    jne .out
    lea rdi,[r12+4095]
    DMA_GUARD 26
    call dma_virt_to_phys
    DMA_OBS rax
    lea rdx,[r12+4095]
    mov [rel aer_dma_diagnostic+16],rdx
    cmp rax,rdx
    jne .out
    mov [rel aer_dma_buffer],r12
    mov rdi,r12
    mov eax,0xcccccccc
    mov ecx,1024
    rep stosd
    mov rdi,r12
    mov eax,0x5a5a5a5a
    mov ecx,16
    rep stosd
    lea rdi,[r12+128]
    mov eax,0xa5a5a5a5
    mov ecx,16
    rep stosd
    lea rdi,[r12+256]
    mov ecx,16
    rep stosd
    lea rsi,[r12+128]
    lea rdi,[rel aer_dma_initial_positive]
    mov ecx,8
    rep movsq
    mfence
    DMA_GUARD 27
    mov edi,0x20
    call pci_contain_lookup
    test rax,rax
    jnz .out
    mov edi,ebx
    mov esi,4
    call pci_bdf_read
    mov [rel aer_dma_record+20],eax
    movzx edx,ax                          ; zero upper RW1C status half
    or edx,6
    mov edi,ebx
    mov esi,4
    call pci_bdf_write
    mov edi,ebx
    mov esi,4
    DMA_GUARD 28
    call pci_bdf_read
    DMA_OBS rax
    and eax,6
    cmp eax,6
    jne .out
    lea rdi,[rel aer_dma_region]
    xor esi,esi
    DMA_GUARD 29
    call hal_mmio_read32
    DMA_OBS rax
    jc .out
    DMA_GUARD 30
    DMA_OBS rax
    cmp eax,0x010000ed
    jne .out
    mov esi,0x98
    DMA_GUARD 31
    call hal_mmio_read32
    DMA_OBS rax
    jc .out
    DMA_GUARD 32
    DMA_OBS rax
    test eax,1
    jnz .out                              ; never replace an active EDU operation
    DMA_GUARD 33
    call time_monotonic_now_us
    DMA_OBS rax
    test rax,rax
    jz .out
    DMA_GUARD 34
    mov [rel aer_dma_diagnostic+16],rax
    add rax,5000000
    DMA_OBS rax
    jc .out
    mov [rel aer_dma_deadline],rax
    mov rax,[rel timer_ticks]
    mov [rel aer_dma_record+32],eax
    mov rdi,r12
    mov esi,0x40000
    mov edx,1                             ; load owned source -> device buffer
    DMA_GUARD 35
    call aer_dma_queue
    DMA_OBS rax
    mov [rel aer_dma_diagnostic+16],rdx
    cmp eax,1
    jne .out
    mov dword [rel aer_dma_diagnostic+4],255
    mov dword [rel aer_dma_record+60],0
    mov dword [rel aer_dma_record],1
.out:
    mov eax,[rel aer_dma_record]
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; EDU-only resource qualification. GetMemoryMap need not list ordinary PCI
; MMIO (EDKII CoreGetMemoryMap emits only reserved/runtime GCD MMIO). Keep
; legacy whole-leaf firmware admission; ONLY a missing-cover result can use
; the positively decoded, enabled fixed root-port memory window instead.
; A second bounded saved-map walk then rejects ANY protected/RAM intersection,
; including a descriptor starting inside the leaf. Absence alone never admits.
; RDI=aligned leaf, RSI=fixed128B observation; no hardware/descriptor writes.
; At most2 fixed CF8 reads and4096 additional saved descriptors, prepare only.
aer_dma_resource_page:
    push rbx
    push rbp
    push r12
    mov rbx,rsi
    mov r12,rdi
    call pci_mmio_resource_page_diagnostic
    test eax,eax
    jnz .out
    cmp dword [rbx+48],11
    jne .out
    mov edi,0x20                         ; already qualified fixed QEMU root port
    mov esi,32                           ; Type1 Memory Base/Limit, never BAR-size write
    call pci_bdf_read
    mov [rbx+104],eax                     ; retain raw qualification across later guards
    mov dword [rbx+48],14
    cmp eax,-1
    je .no
    test eax,0x000f000f                   ; reserved base/limit bits must be zero
    jnz .no
    mov ebp,eax
    mov edi,0x20
    mov esi,4
    call pci_bdf_read
    mov [rbx+108],eax
    cmp eax,-1
    je .no
    test eax,2                           ; upstream Memory Space Enable is already set
    jz .no
    mov dword [rbx+48],15
    mov eax,ebp
    and eax,0xfff0
    shl rax,16
    cmp r12,rax
    jb .no
    mov eax,ebp
    and eax,0xfff00000
    add rax,0x100000                     ; inclusive1MiB limit -> exclusive end
    lea r11,[r12+0x200000]
    cmp r11,rax
    ja .no
    ; Prior shared walk established the valid bounded map shape. The fixed
    ; CF8 reads do not allocate or mutate that immutable final boot map.
    mov r8,[rel mmap_buffer]
    mov r9,[rel mmap_desc_size]
    mov rax,[rel mmap_size]
    xor edx,edx
    div r9
    mov r10,rax
    mov dword [rbx+52],0
    mov dword [rbx+56],0
    mov dword [rbx+60],0
    mov qword [rbx+64],0
    mov qword [rbx+72],0
    mov qword [rbx+80],0
    mov qword [rbx+88],0
    mov qword [rbx+96],0
.row:
    inc dword [rbx+52]
    mov rax,[r8+8]
    test eax,4095
    jnz .malformed
    mov rcx,[r8+24]
    test rcx,rcx
    jz .malformed
    shr rcx,52
    jnz .malformed
    mov rcx,[r8+24]
    shl rcx,12
    add rcx,rax
    jc .malformed
    cmp rax,r11                          ; half-open disjoint ranges are safe
    jae .next
    cmp rcx,r12
    jbe .next
    cmp dword [r8],0
    je .next
    cmp dword [r8],11
    je .next
    mov dword [rbx+48],16                ; protected/RAM overlap anywhere in leaf
    mov dword [rbx+60],1
    jmp .row_refused
.malformed:
    mov dword [rbx+48],17
    mov dword [rbx+60],2
.row_refused:
    mov eax,[rbx+52]
    dec eax
    mov [rbx+56],eax
    mov rax,[r8]
    mov [rbx+64],rax
    mov rax,[r8+8]
    mov [rbx+72],rax
    mov rax,[r8+16]
    mov [rbx+80],rax
    mov rax,[r8+24]
    mov [rbx+88],rax
    mov rax,[r8+32]
    mov [rbx+96],rax
    jmp .no
.next:
    add r8,r9
    dec r10
    jnz .row
    mov dword [rbx+48],13                ; positive PCI window + no protected overlap
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    pop r12
    pop rbp
    pop rbx
    ret

; aer_dma_v2 binds all retained tick words to core/time timer_ticks.
; Only the BSP PIT or calibrated BSP LAPIC handover advances that counter;
; AP interrupts never do. IRQ0 alone is masked after a healthy handover.
; Called only from serialized BSP AER pump, no interrupt or AP entry.
aer_dma_tick:
    push rbx
    mov ebx,[rel aer_dma_record]
    cmp ebx,1
    jb .out
    cmp ebx,2
    jbe .pre
    cmp ebx,4
    jne .out
    call time_monotonic_now_us
    mov rdx,[rel aer_dma_stop_us]
    sub rax,rdx
    jc .fail
    cmp rax,1000000
    jb .out
    mov rax,[rel timer_ticks]
    sub rax,[rel aer_dma_stop_tick]
    jc .fail
    cmp rax,1024                          ; BSP PIT/LAPIC~1kHz; EDU100ms had opportunity
    jb .out
    mov edi,0x20
    call pci_contain_lookup
    test rax,rax
    jz .fail
    cmp dword [rax],1                     ; independent actual config-stop result
    jne .fail
    mov rdi,[rel aer_dma_buffer]
    add rdi,256
    mov eax,0xa5a5a5a5
    mov ecx,16
    repe scasd
    jne .fail
    mov rdi,[rel aer_dma_buffer]
    add rdi,384
    mov eax,0xcccccccc
    mov ecx,16
    repe scasd
    jne .fail
    call time_monotonic_now_us
    mov [rel aer_dma_record+52],rax        ; DWORD13/14 post us
    mov rax,[rel timer_ticks]
    mov [rel aer_dma_record+40],eax
    mov dword [rel aer_dma_record],5
    jmp .out
.pre:
    ; AER may contain the subtree while the positive control is still loading.
    ; Any retained stop attempt ends preparation before touching the device;
    ; partial/refused/busy containment is not permission to rearm the probe.
    mov edi,0x20
    call pci_contain_lookup
    test rax,rax
    jnz .fail
    call time_monotonic_now_us
    test rax,rax
    jz .fail
    cmp rax,[rel aer_dma_deadline]
    jae .fail
    lea rdi,[rel aer_dma_region]
    mov esi,0x98
    call hal_mmio_read32
    jc .fail
    test eax,1
    jnz .out
    cmp ebx,2
    je .positive
    mov edi,0x40000
    mov rsi,[rel aer_dma_buffer]
    add rsi,128
    mov edx,3                             ; positive control: actual device->RAM
    call aer_dma_queue
    mov [rel aer_dma_record+24],eax
    cmp eax,3
    jne .fail
    mov dword [rel aer_dma_record],2
    jmp .out
.positive:
    mfence
    mov rdi,[rel aer_dma_buffer]
    add rdi,128
    mov eax,0x5a5a5a5a
    mov ecx,16
    repe scasd
    jne .fail
    mov dword [rel aer_dma_record],3
    jmp .out
.fail:
    mov dword [rel aer_dma_record+60],2
    mov dword [rel aer_dma_record],6
.out:
    pop rbx
    ret

; RDI=root BDF, immediately before the independent containment call. Queue only
; when positive control completed. A refusal NEVER prevents the native stop.
aer_dma_before_stop:
    cmp rdi,0x20
    jne .return
    cmp dword [rel aer_dma_record],3
    jne .return
    push rbx
    mov ebx,[rel aer_dma_record+8]
    mov edi,ebx
    xor esi,esi
    call pci_bdf_read
    cmp eax,[rel aer_dma_record+12]
    jne .fail
    mov edi,ebx
    mov esi,4
    call pci_bdf_read
    and eax,6
    cmp eax,6
    jne .fail
    call time_monotonic_now_us
    test rax,rax
    jz .fail
    mov [rel aer_dma_stop_us],rax
    mov [rel aer_dma_record+44],rax        ; DWORD11/12 stop us
    mov rax,[rel timer_ticks]
    mov [rel aer_dma_stop_tick],rax
    mov [rel aer_dma_record+36],eax
    mov edi,0x40000
    mov rsi,[rel aer_dma_buffer]
    add rsi,256
    mov edx,3
    call aer_dma_queue
    mov [rel aer_dma_record+28],eax
    cmp eax,3
    jne .fail
    mov dword [rel aer_dma_record],4
    pop rbx
.return:
    ret
.fail:
    mov dword [rel aer_dma_record+60],3
    mov dword [rel aer_dma_record],6
    pop rbx
    ret

; RDI=source32, RSI=dest32, EDX=command1/3. Each field is a fresh32-bit EDU
; store (zero-extends the complete 64-bit register). No IRQ bit, length64 only.
aer_dma_queue:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13,rsi
    mov ebx,edx
    lea rdi,[rel aer_dma_region]
    mov esi,0x80
    mov edx,r12d
    call hal_mmio_write32
    jc .bad_source
    mov esi,0x88
    mov edx,r13d
    call hal_mmio_write32
    jc .bad_destination
    mov esi,0x90
    mov edx,64
    call hal_mmio_write32
    jc .bad_length
    mfence
    mov esi,0x98
    mov edx,ebx
    call hal_mmio_write32
    jc .bad_command
    call hal_mmio_read32
    jc .bad_read
    xor edx,edx
    jmp .out
.bad_source:
    mov edx,1
    jmp .bad
.bad_destination:
    mov edx,2
    jmp .bad
.bad_length:
    mov edx,3
    jmp .bad
.bad_command:
    mov edx,4
    jmp .bad
.bad_read:
    mov edx,5
    jmp .bad
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; One read-only64B RAM page. No device I/O or tick from the read verb.
; 0record,1source,2positive,3negative,4guard,5initial-positive,
; 6prepare diagnostic,7retained descriptor. Never exposes arbitrary RAM.
aer_dma_page:
    cmp rdi,6
    jb .old
    cmp rdi,7
    ja .none
    sub edi,6
    shl edi,6
    lea rax,[rel aer_dma_diagnostic]
    add rax,rdi
    ret
.old:
    cmp rdi,5
    ja .none
    jne .normal
    lea rax,[rel aer_dma_initial_positive]
    cmp qword [rel aer_dma_buffer],0
    je .none
    ret
.normal:
    lea rax,[rel aer_dma_record]
    test edi,edi
    jz .out
    mov rax,[rel aer_dma_buffer]
    test rax,rax
    jz .none
    dec edi
    shl edi,7
    add rax,rdi
.out:
    ret
.none:
    xor eax,eax
    ret

; Explicitly QEMU-only. Hypervisor leaf plus exact KVM/TCG vendor, no metal
; inference from a matching device ID. Qualification is not a security boundary.
aer_dma_hypervisor:
    push rbx
    mov eax,1
    cpuid
    test ecx,0x80000000
    jz .no
    mov eax,0x40000000
    cpuid
    cmp eax,0x40000000
    jbe .no
    cmp ebx,0x4b4d564b
    jne .tcg
    cmp ecx,0x564b4d56
    jne .no
    cmp edx,0x0000004d
    jne .no
    jmp .yes
.tcg:
    cmp ebx,0x54474354
    jne .no
    cmp ecx,0x43544743
    jne .no
    cmp edx,0x47435447
    jne .no
.yes:
    mov eax,1
    pop rbx
    ret
.no:
    xor eax,eax
    pop rbx
    ret

%include "core/abi/wdata.inc"
%macro WDATA_aer_dma_probe 0
alignb 8
aer_dma_diagnostic: resb 128
aer_dma_record:   resd 16
aer_dma_initial_positive: resb 64
aer_dma_buffer:   resq 1
aer_dma_region:   resq 2
aer_dma_deadline: resq 1
aer_dma_stop_us:  resq 1
aer_dma_stop_tick: resq 1
%endmacro
WDATA_BSS_DEFER WDATA_aer_dma_probe
