;; MODULE sec/cpu_microcode
;; LAYER 2
;; EXPORTS cpu_microcode_select, cpu_microcode_apply
;; IMPORTS core/smp, sec/cpu_security, core/idt
;; CAPS
;; OWNER saga:security
; RCQ-42 early microcode. cpu_microcode_select validates an update image and
; SELECTS the newest update for one sampled CPU: pure, no CPUID, MSR, write,
; allocation or global state. cpu_microcode_apply (slice 2a) hands a selected
; update to the calling CPU and reads its revision back, through the
; cpu_security hardware adapters plus cpu_microcode_write, whose one WRMSR
; core/idt's one-shot #GP slot contains (slice 2b). Early placement, AP
; coverage and the image's signed update file are boot wiring with their own
; review.
; The CPU verifies the vendor signature; this code checks only structure, so a
; caller must only ever pass bytes from PaOS's own signed image.
;
; Intel (SDM vol. 3 "Microcode Update Facilities"): 48-byte header, version 1,
; loader 1; data size 0 means 2000 data / 2048 total; data size a multiple of
; 4; total a multiple of 1024, >= header + data and inside the blob; the dword
; sum of header + data is 0. An extended signature table fills the rest: 20-
; byte header (count, checksum) + count x 12-byte entries, exact size, dword
; sum 0, and every entry's signature + flags + checksum equals the header's.
; A match is CPUID(1).EAX equal to a signature whose processor flags contain
; bit (platform id, MSR 17h bits 52:50, supplied by the caller 0..7).
; A blob is any number of concatenated updates; any malformed update refuses
; the whole blob.
;
; AMD (container format read by Linux amd.c): magic "DMA\0", equivalence table
; (type 0, size a non-zero multiple of 16 inside the blob, 16-byte entries
; ending at installed_cpu 0); then patch sections (type 1, size >= 64 inside
; the blob), until the blob ends or the next container magic. A patch header
; naming a northbridge or southbridge device (chipset-specific code, which the
; sample cannot judge) refuses the whole blob, as Linux verify_patch does.
; A patch applies only when 0Fh + (processor_rev_id >> 12) is the CPU family.
; Before family 17h it matches when processor_rev_id equals the CPU's
; equivalence id: the first entry whose installed_cpu equals CPUID(1).EAX.
; From family 17h (Zen) the patch_id encodes the CPUID(1).EAX it fits
; (Linux mc_patch_matches/ucode_rev_to_cpuid) and must equal it exactly; the
; equivalence table is not consulted. The patch_id is the revision.
;
; Newer means update revision > the sampled current revision, unsigned. No
; selection without a valid sampled revision, on a hypervisor, or for an
; unknown vendor: an equal or unknown revision never selects anything.
;
; cpu_microcode_select(RDI=blob, RSI=length, RDX=CSS sample (cpu_security),
;   RCX=Intel platform id 0..7, full width (ignored for AMD), R8=MCS record)
;   -> RAX = MC_* (also stored in MCS_STATUS). The record is zeroed first.
;   SELECTED: OFFSET/LENGTH name the update (Intel: header start; the data a
;   loader passes starts 48 bytes later. AMD: patch header start). NONE: the
;   blob is well-formed and nothing newer matches; REV keeps the best matching
;   revision found (0 if none). Refusals leave OFFSET/LENGTH zero.
;   A null record returns MC_E_ARGS with nothing written. Callee-save kept.
;   Diagnostics: VENDOR is set once the sample is read, CURRENT once a valid
;   revision is accepted, SEEN counts well-formed updates (Intel) / patch
;   sections (AMD) walked, including those before a malformed one.

MC_MAX_BLOB      equ 4 * 1024 * 1024
MC_INTEL_HEADER  equ 48

MCS_STATUS       equ 0
MCS_VENDOR       equ 4
MCS_OFFSET       equ 8
MCS_LENGTH       equ 16
MCS_REV          equ 24
MCS_CURRENT      equ 28
MCS_SEEN         equ 32                 ; well-formed updates / patch sections walked
MCS_AFTER        equ 36                 ; cpu_microcode_apply: revision read back
MCS_SIZE         equ 40

MC_SELECTED      equ 0
MC_NONE          equ 1
MC_E_ARGS        equ -1
MC_E_VENDOR      equ -2
MC_E_GUEST       equ -3
MC_E_REVISION    equ -4
MC_E_MALFORMED   equ -5
MC_E_PLATFORM    equ -6
MC_E_UNSUPPORTED equ -7                 ; AMD chipset-specific patch
MC_E_STATE       equ -8                 ; apply: record not SELECTED, outside blob, vendor differs
MC_E_ALIGN       equ -9                 ; apply: Intel update data not 16-byte aligned
MC_E_NOT_APPLIED equ -10                ; apply: revision read back is not the selected one
MC_E_FAULT       equ -11                ; apply: the CPU refused the load with #GP (contained)
MC_E_BUSY        equ -12                ; apply: the #GP slot was held; nothing written

cpu_microcode_select:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  rbp, rcx
    mov  r15, r8
    mov  rax, MC_E_ARGS
    test r15, r15
    jz   .out                           ; nowhere to report: touch nothing
    xor  ecx, ecx
    mov  [r15], rcx
    mov  [r15 + 8], rcx
    mov  [r15 + 16], rcx
    mov  [r15 + 24], rcx
    mov  [r15 + 32], rcx
    test r12, r12
    jz   .status
    test r14, r14
    jz   .status
    test r13, r13
    jz   .status
    cmp  r13, MC_MAX_BLOB
    ja   .status
    mov  eax, [r14 + CSS_VENDOR]
    mov  [r15 + MCS_VENDOR], eax
    mov  rax, MC_E_VENDOR
    mov  ecx, [r14 + CSS_VENDOR]
    cmp  ecx, 1
    je   .known
    cmp  ecx, 2
    jne  .status
.known:
    mov  rax, MC_E_GUEST
    cmp  dword [r14 + CSS_HV], 0
    jne  .status                        ; never update microcode from a guest
    mov  rax, MC_E_REVISION
    cmp  dword [r14 + CSS_REV_VALID], 1
    jne  .status
    mov  eax, [r14 + CSS_REV]
    mov  [r15 + MCS_CURRENT], eax
    cmp  ecx, 1
    jne  .amd
    call mc_intel_walk
    jmp  .walked
.amd:
    call mc_amd_walk
.walked:
    test eax, eax
    jz   .judge
    movsxd rax, eax                     ; the walk's MC_E_* refusal
    xor  ecx, ecx
    mov  [r15 + MCS_OFFSET], rcx
    mov  [r15 + MCS_LENGTH], rcx
    mov  [r15 + MCS_REV], ecx
    jmp  .status
.judge:
    mov  eax, MC_NONE
    cmp  qword [r15 + MCS_LENGTH], 0
    je   .status
    mov  ecx, [r15 + MCS_REV]
    cmp  ecx, [r15 + MCS_CURRENT]
    ja   .selected
    xor  ecx, ecx                       ; best match is not newer: report it only
    mov  [r15 + MCS_OFFSET], rcx
    mov  [r15 + MCS_LENGTH], rcx
    jmp  .status
.selected:
    mov  eax, MC_SELECTED
.status:
    mov  [r15 + MCS_STATUS], eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Intel walk (R12 blob, R13 length, R14 sample, R15 record, RBP platform id).
;   -> EAX 0 walked (best match recorded), MC_E_MALFORMED, MC_E_PLATFORM (id > 7).
mc_intel_walk:
    cmp  rbp, 7
    ja   .platform
    mov  ecx, ebp
    mov  ebp, 1
    shl  ebp, cl                        ; processor-flags bit for this platform
    xor  ebx, ebx                       ; offset of the current update
.next:
    cmp  rbx, r13
    jae  .done
    mov  rax, r13
    sub  rax, rbx                       ; bytes left
    cmp  rax, MC_INTEL_HEADER
    jb   .bad
    lea  rsi, [r12 + rbx]
    cmp  dword [rsi], 1                 ; header version
    jne  .bad
    cmp  dword [rsi + 20], 1            ; loader revision
    jne  .bad
    mov  ecx, [rsi + 28]                ; data size
    mov  edx, [rsi + 32]                ; total size
    test ecx, ecx
    jnz  .sized
    mov  ecx, 2000
    mov  edx, 2048
.sized:
    test ecx, 3
    jnz  .bad
    test edx, 1023
    jnz  .bad
    lea  r8, [rcx + MC_INTEL_HEADER]    ; header + data
    cmp  r8, rdx
    ja   .bad
    cmp  rdx, rax
    ja   .bad                           ; the whole update lies inside the blob
    mov  r9, rsi
    mov  r10, r8
    shr  r10, 2
    xor  r11d, r11d
.sum:
    add  r11d, [r9]
    add  r9, 4
    dec  r10
    jnz  .sum
    test r11d, r11d
    jnz  .bad
    mov  r10, rdx
    sub  r10, r8                        ; extended table bytes
    jz   .walked
    cmp  r10, 20
    jb   .bad
    lea  r9, [rsi + r8]                 ; extended table header
    mov  eax, [r9]
    imul rax, rax, 12
    add  rax, 20
    cmp  rax, r10
    jne  .bad                           ; exact size, so every entry is inside
    mov  rdi, r9
    shr  r10, 2
    xor  r11d, r11d
.esum:
    add  r11d, [rdi]
    add  rdi, 4
    dec  r10
    jnz  .esum
    test r11d, r11d
    jnz  .bad
    mov  r11d, [rsi + 12]               ; header signature + flags + checksum
    add  r11d, [rsi + 24]
    add  r11d, [rsi + 16]
    mov  r10d, [r9]
    lea  rdi, [r9 + 20]
.entry:
    test r10d, r10d
    jz   .walked
    mov  eax, [rdi]
    add  eax, [rdi + 4]
    add  eax, [rdi + 8]
    cmp  eax, r11d
    jne  .bad
    add  rdi, 12
    dec  r10d
    jmp  .entry
.walked:
    inc  dword [r15 + MCS_SEEN]
    mov  eax, [r14 + CSS_SIG]
    cmp  eax, [rsi + 12]
    jne  .ext_match
    test ebp, [rsi + 24]
    jnz  .candidate
.ext_match:
    mov  r10, rdx
    sub  r10, r8
    jz   .advance
    lea  r9, [rsi + r8]
    mov  r10d, [r9]
    lea  rdi, [r9 + 20]
.ext_entry:
    test r10d, r10d
    jz   .advance
    cmp  eax, [rdi]
    jne  .ext_skip
    test ebp, [rdi + 4]
    jnz  .candidate
.ext_skip:
    add  rdi, 12
    dec  r10d
    jmp  .ext_entry
.candidate:
    mov  eax, [rsi + 4]                 ; update revision
    cmp  qword [r15 + MCS_LENGTH], 0
    je   .take
    cmp  eax, [r15 + MCS_REV]
    jbe  .advance                       ; the first of equal revisions is kept
.take:
    mov  [r15 + MCS_REV], eax
    mov  [r15 + MCS_OFFSET], rbx
    mov  [r15 + MCS_LENGTH], rdx
.advance:
    add  rbx, rdx
    jmp  .next
.done:
    xor  eax, eax
    ret
.bad:
    mov  eax, MC_E_MALFORMED
    ret
.platform:
    mov  eax, MC_E_PLATFORM
    ret

; AMD walk (R12 blob, R13 length, R14 sample, R15 record).
;   -> EAX 0 walked, MC_E_MALFORMED, MC_E_UNSUPPORTED (chipset-specific patch),
;   MC_E_PLATFORM (the CPU is not family 0Fh-based).
mc_amd_walk:
    mov  eax, [r14 + CSS_SIG]
    mov  edx, eax
    shr  eax, 8
    and  eax, 15
    cmp  eax, 15
    jne  .platform
    shr  edx, 20
    and  edx, 255
    lea  ebp, [rax + rdx]               ; CPU family
    xor  ebx, ebx
.container:
    cmp  rbx, r13
    jae  .done
    mov  rax, r13
    sub  rax, rbx
    cmp  rax, 12
    jb   .bad
    lea  rsi, [r12 + rbx]
    cmp  dword [rsi], 0x00414D44        ; "DMA\0"
    jne  .bad
    cmp  dword [rsi + 4], 0             ; equivalence table section
    jne  .bad
    mov  ecx, [rsi + 8]
    test ecx, ecx
    jz   .bad
    test ecx, 15
    jnz  .bad
    sub  rax, 12
    cmp  rcx, rax
    ja   .bad
    xor  r11d, r11d                     ; equivalence id, 0 = none in this container
    lea  rdi, [rsi + 12]
    mov  r8, rcx
    shr  r8, 4
.equiv:
    mov  eax, [rdi]
    test eax, eax
    jz   .equiv_end
    test r11d, r11d
    jnz  .equiv_next                    ; the first matching entry wins
    cmp  eax, [r14 + CSS_SIG]
    jne  .equiv_next
    movzx r11d, word [rdi + 12]
.equiv_next:
    add  rdi, 16
    dec  r8
    jnz  .equiv
.equiv_end:
    lea  rbx, [rbx + rcx + 12]
.section:
    cmp  rbx, r13
    jae  .done
    mov  rax, r13
    sub  rax, rbx
    cmp  rax, 4
    jb   .bad
    cmp  dword [r12 + rbx], 0x00414D44
    je   .container
    cmp  rax, 8
    jb   .bad
    lea  rsi, [r12 + rbx]
    cmp  dword [rsi], 1                 ; patch section
    jne  .bad
    mov  ecx, [rsi + 4]
    cmp  ecx, 64
    jb   .bad                           ; holds at least the patch header
    sub  rax, 8
    cmp  rcx, rax
    ja   .bad
    inc  dword [r15 + MCS_SEEN]
    lea  rdi, [rsi + 8]                 ; patch header
    mov  eax, [rdi + 16]                ; nb_dev_id
    or   eax, [rdi + 20]                ; sb_dev_id
    jnz  .chipset
    movzx eax, word [rdi + 24]          ; processor_rev_id
    mov  edx, eax
    shr  edx, 12
    add  edx, 15
    cmp  edx, ebp
    jne  .skip                          ; another family's patch
    cmp  ebp, 0x17
    jae  .zen
    test r11d, r11d
    jz   .skip
    cmp  eax, r11d
    jne  .skip
    jmp  .match
.zen:                                   ; patch_id 31:24 ext family, 23:20 ext model,
    mov  eax, [rdi + 4]                 ; 15:12 model, 11:8 stepping -> CPUID(1).EAX
    mov  edx, eax
    shr  edx, 4
    and  edx, 0x0FF00000
    mov  r8d, eax
    shr  r8d, 4
    and  r8d, 0x000F0000
    or   edx, r8d
    mov  r8d, eax
    shr  r8d, 8
    and  r8d, 0xFF
    or   edx, r8d
    or   edx, 0x00000F00
    cmp  edx, [r14 + CSS_SIG]
    jne  .skip
.match:
    mov  eax, [rdi + 4]                 ; patch_id
    cmp  qword [r15 + MCS_LENGTH], 0
    je   .take
    cmp  eax, [r15 + MCS_REV]
    jbe  .skip
.take:
    mov  [r15 + MCS_REV], eax
    lea  rdx, [rbx + 8]
    mov  [r15 + MCS_OFFSET], rdx
    mov  [r15 + MCS_LENGTH], rcx
.skip:
    lea  rbx, [rbx + rcx + 8]
    jmp  .section
.done:
    xor  eax, eax
    ret
.bad:
    mov  eax, MC_E_MALFORMED
    ret
.platform:
    mov  eax, MC_E_PLATFORM
    ret
.chipset:
    mov  eax, MC_E_UNSUPPORTED
    ret

; cpu_microcode_apply(RDI=blob, RSI=length, RDX=CSS sample of THIS logical
;   CPU, R8=MCS record that cpu_microcode_select filled from this same blob)
;   -> RAX = MC_APPLIED (0) or MC_*. Intel: WRMSR 79h with the update data
;   (header + 48, which must be 16-byte aligned), then clear 8Bh, CPUID(1),
;   read 8Bh high dword. AMD: WRMSR C001_0020h with the patch header, then
;   read 8Bh low dword. MCS_AFTER keeps the revision read back; only a
;   revision equal to the selected REV is APPLIED. Nothing is written unless
;   the record is SELECTED with its update inside [blob, blob + length), the
;   sample is not a guest, and its vendor is the record's. A load the CPU
;   refuses with #GP returns MC_E_FAULT (core/idt resumed it; nothing read
;   back); MC_E_BUSY when the #GP slot was held (nothing written). The caller
;   keeps the blob unchanged since selection and runs this once per logical
;   CPU with interrupts off. Callee-save kept.
MC_APPLIED       equ 0
MC_AMD_PATCH_LOADER equ 0xC0010020
MC_INTEL_UPDATE_TRIGGER equ 0x79

cpu_microcode_apply:
    mov  rax, MC_E_ARGS
    test r8, r8
    jz   .noargs
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  rbx, rsi                       ; length, dead before CPUID
    mov  r14, rdx
    mov  r13, r8
    mov  dword [r13 + MCS_AFTER], 0
    test r12, r12
    jz   .out
    test r14, r14
    jz   .out
    mov  rax, MC_E_STATE
    cmp  dword [r13 + MCS_STATUS], MC_SELECTED
    jne  .out
    mov  rcx, [r13 + MCS_OFFSET]
    mov  rdx, [r13 + MCS_LENGTH]
    test rdx, rdx
    jz   .out
    cmp  rcx, rbx
    jae  .out
    mov  rsi, rbx
    sub  rsi, rcx
    cmp  rdx, rsi
    ja   .out                           ; the selected update lies inside the blob
    mov  esi, [r14 + CSS_VENDOR]
    cmp  esi, [r13 + MCS_VENDOR]
    jne  .out
    mov  rax, MC_E_GUEST
    cmp  dword [r14 + CSS_HV], 0
    jne  .out                           ; never write an update MSR from a guest
    lea  rdi, [r12 + rcx]
    cmp  esi, 1
    je   .intel
    mov  rax, MC_E_STATE
    cmp  esi, 2
    jne  .out
    mov  ecx, MC_AMD_PATCH_LOADER       ; patch header address
    mov  eax, edi
    mov  rdx, rdi
    shr  rdx, 32
    call cpu_microcode_write
    test rax, rax
    jnz  .out                           ; MC_E_FAULT / MC_E_BUSY: nothing to read back
    mov  ecx, 0x8B
    call cpu_security_rdmsr
    jmp  .readback
.intel:
    add  rdi, MC_INTEL_HEADER           ; update data address
    mov  rax, MC_E_ALIGN
    test edi, 15
    jnz  .out
    mov  ecx, MC_INTEL_UPDATE_TRIGGER
    mov  eax, edi
    mov  rdx, rdi
    shr  rdx, 32
    call cpu_microcode_write
    test rax, rax
    jnz  .out
    mov  ecx, 0x8B
    xor  eax, eax
    xor  edx, edx
    call cpu_security_revision_clear
    mov  eax, 1
    xor  ecx, ecx
    call cpu_security_cpuid             ; latches the new revision into 8Bh
    mov  ecx, 0x8B
    call cpu_security_rdmsr
    mov  eax, edx
.readback:
    mov  [r13 + MCS_AFTER], eax
    cmp  eax, [r13 + MCS_REV]
    mov  rax, MC_E_NOT_APPLIED
    jne  .out
    mov  eax, MC_APPLIED
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
.noargs:
    ret

; cpu_microcode_write(ECX=MSR, EDX:EAX=value) -> RAX 0 written, MC_E_FAULT
; (the CPU refused it with #GP; core/idt resumed it), MC_E_BUSY (another CPU
; holds the one-shot slot; nothing written). The slot is armed for exactly the
; adapter's WRMSR on this CPU and disarmed after it, faulted or not. Keeps
; RBX, RBP, RDI, RSI, R8-R15.
cpu_microcode_write:
    cmp  dword [rel smp_core_custody_gate], 0
    je   .custody_free
    mov  rax, MC_E_BUSY
    ret
.custody_free:
    push rdi
    push rsi
    push rax
    push rcx
    push rdx
    lea  rdi, [rel cpu_microcode_wrmsr]
    lea  rsi, [rel cpu_microcode_wrmsr_ret]
    call idt_gp_fixup_arm               ; EAX 1 armed / 0 busy
    mov  esi, eax
    pop  rdx
    pop  rcx
    pop  rax
    test esi, esi
    jz   .busy
    call cpu_microcode_wrmsr            ; a refused load #GPs and resumes at its ret
    call idt_gp_fixup_disarm            ; EAX 1 = it faulted
    neg  rax
    and  rax, MC_E_FAULT                ; 0 or MC_E_FAULT
    jmp  .out
.busy:
    mov  rax, MC_E_BUSY
.out:
    pop  rsi
    pop  rdi
    ret

; Hardware adapter: tests replace only this body. core/idt's #GP slot names
; the WRMSR and resumes at the ret.
cpu_microcode_wrmsr:
    wrmsr
cpu_microcode_wrmsr_ret:
    ret
