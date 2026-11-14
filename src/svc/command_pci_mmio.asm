;; MODULE svc/command_pci_mmio
;; LAYER 5
;; EXPORTS command_pci_mmio_init, pci_mmio_out_ready, pci_mmio_out_buf, pci_mmio_scan_ready, pci_mmio_scan_arg, str_verb_pciscan
;; IMPORTS core/lib/fmt, lib/safe_buffer, svc/command, bus/pci, bus/pci_bdf, bus/irq
;; CAPS
;; OWNER saga:pci_mmio_iommu_baremetal

; 1117b is an observability/proof projection only. It reuses the established PCI
; and CAP_MMIO primitives and does not import or modify VT-d state. DMAVIOL and
; DMAVIOL_CHECK remain owned by hv/vtd.asm (the prerequisite 1111 path).

PCI_MMIO_OUT_CAP equ 1050
PCISCAN_PAGE_ROWS equ 24
PCISCAN_CFG_ROWS equ 12
PCISCAN_ARG_CAP equ 96
PCISCAN_END equ 65536
; 27 bytes per compact row plus bounded decimal metadata and NUL.
%if PCISCAN_PAGE_ROWS * 27 + 160 > PCI_MMIO_OUT_CAP
    %error PCISCAN_page_exceeds_staging
%endif
; CFG keeps the existing <=306B metadata plus the <=192B ECAM tuple.
; At12 rows, even counting the removed old ECAM marker twice stays <=905B.
; Ordinary PAGE remains24 rows. No truncation at these fixed field bounds.
%if PCISCAN_CFG_ROWS * 27 + 80 + 500 + 1 > PCI_MMIO_OUT_CAP
    %error PCISCAN_CFG_page_exceeds_staging
%endif

; Register three verbs through the canonical command registry.
command_pci_mmio_init:
    lea  rdi, [rel str_verb_pciscan]
    lea  rsi, [rel cmd_verb_pciscan]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                         ; read-only live enumeration
    call command_register_verb

    lea  rdi, [rel str_verb_pcicfg_safe]
    lea  rsi, [rel cmd_verb_pcicfg_safe]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                          ; idempotent same-value BAR write
    call command_register_verb

    lea  rdi, [rel str_verb_mmiocap]
    lea  rsi, [rel cmd_verb_mmiocap]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                         ; side-effect-free LAPIC-ID reads only
    call command_register_verb
    ret

; ---------------------------------------------------------------------------
; Bounded staged-reply helpers.
; ---------------------------------------------------------------------------
pci_mmio_out_reset:
    lea  rax, [rel pci_mmio_out_buf]
    mov  [rel pci_mmio_out_cur], rax
    mov  byte [rel pci_mmio_out_buf], 0
    mov  byte [rel pci_mmio_out_ready], 0
    mov  byte [rel pci_mmio_scan_ready], 0
    mov  byte [rel pci_inventory_diag_active], 0
    ret

; pci_mmio_out_str(RDI=cstr). Truncates at the final reserved NUL byte.
pci_mmio_out_str:
    mov  rsi, [rel pci_mmio_out_cur]
    lea  rcx, [rel pci_mmio_out_buf + PCI_MMIO_OUT_CAP - 1]
.copy:
    cmp  rsi, rcx
    jae  .done
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .copy
.done:
    mov  byte [rsi], 0
    mov  [rel pci_mmio_out_cur], rsi
    ret

; pci_mmio_out_hex(RDI=value, EDX=minimum digits).
pci_mmio_out_hex:
    lea  rsi, [rel pci_mmio_num_buf]
    call fmt_hex
    lea  rdi, [rel pci_mmio_num_buf]
    jmp  pci_mmio_out_str

; pci_mmio_out_dec(RDI=value).
pci_mmio_out_dec:
    lea  rsi, [rel pci_mmio_num_buf]
    call fmt_dec
    lea  rdi, [rel pci_mmio_num_buf]
    jmp  pci_mmio_out_str

; pci_mmio_out_char(DIL=byte).
pci_mmio_out_char:
    mov  rsi, [rel pci_mmio_out_cur]
    lea  rax, [rel pci_mmio_out_buf + PCI_MMIO_OUT_CAP - 1]
    cmp  rsi, rax
    jae  .done
    mov  [rsi], dil
    inc  rsi
    mov  byte [rsi], 0
    mov  [rel pci_mmio_out_cur], rsi
.done:
    ret

; ---------------------------------------------------------------------------
; PCISCAN [nonce [PAGE decimal-BDF-cursor]] — a bounded LIVE page.
; No argument / nonce alone starts at zero. Cursor=(bus<<8)|(dev<<3)|fn,
; range 0..65536. Rows retain the legacy BB:DD.F=VVVV:DDDD/CC:SS:PI grammar.
; The canonical full walk counts ALL devices; next is the first unreturned BDF,
; or 65536 at completion. Pages are separate live scans, not a frozen snapshot.
; Callers collect strictly increasing cursors and must reject topology changes.
cmd_verb_pciscan:
    call cmd_handler_prologue
    push r12
    push r13
    mov  r12, rsi
    mov  r13, [rdi + REQ_ARG]
    call pci_mmio_out_reset
    mov  byte [rel pci_mmio_scan_cfg], 255
    mov  qword [rel pci_mmio_scan_start], 0
    mov  qword [rel pci_mmio_scan_count], 0
    mov  qword [rel pci_mmio_scan_returned], 0
    mov  qword [rel pci_mmio_scan_next], PCISCAN_END
    mov  byte [rel pci_mmio_scan_error], 0
    mov  byte [rel pci_mmio_scan_arg], 0
    test r13, r13
    jz   .parsed
    mov  rdi, r13
    mov  esi, PCISCAN_ARG_CAP
    call safe_capped_len
    test edx, edx
    jnz  .bad
    mov  rcx, rax
    mov  rdx, r13
    lea  rdi, [rel pci_mmio_scan_arg]
    mov  esi, PCISCAN_ARG_CAP
    call safe_copy
    test eax, eax
    jnz  .bad
    lea  rdi, [rel pci_mmio_scan_arg]
    call pci_mmio_scan_parse
    test eax, eax
    jnz  .bad
.parsed:
    cmp byte [rel pci_mmio_scan_cfg], 255
    je .no_cfg_begin
    call pci_inventory_diag_begin
.no_cfg_begin:
    lea  rdi, [rel str_pciscan_head]
    call pci_mmio_out_str
    lea  rdi, [rel pci_mmio_scan_cb]
    call pci_scan_with_filter
    cmp  byte [rel pci_mmio_scan_error], 0
    jne  .bad
    lea  rdi, [rel str_pciscan_count]
    call pci_mmio_out_str
    mov  rdi, [rel pci_mmio_scan_count]
    call pci_mmio_out_dec
    lea  rdi, [rel str_pciscan_start]
    call pci_mmio_out_str
    mov  rdi, [rel pci_mmio_scan_start]
    call pci_mmio_out_dec
    lea  rdi, [rel str_pciscan_returned]
    call pci_mmio_out_str
    mov  rdi, [rel pci_mmio_scan_returned]
    call pci_mmio_out_dec
    lea  rdi, [rel str_pciscan_next]
    call pci_mmio_out_str
    mov  rdi, [rel pci_mmio_scan_next]
    call pci_mmio_out_dec
    lea  rdi, [rel str_pciscan_complete]
    call pci_mmio_out_str
    xor  edi, edi
    cmp  qword [rel pci_mmio_scan_next], PCISCAN_END
    sete dil
    call pci_mmio_out_dec
    lea  rdi, [rel str_pciscan_live]
    call pci_mmio_out_str
    cmp byte [rel pci_mmio_scan_cfg], 255
    je .no_cfg_emit
    cmp byte [rel pci_inventory_diag_done], 1
    jne .bad
    call pci_mmio_scan_cfg_emit
.no_cfg_emit:
    mov  qword [r12 + RSP_CODE], CMDE_OK
    mov  byte [rel pci_mmio_out_ready], 1
    mov  byte [rel pci_mmio_scan_ready], 1
    jmp  .done
.bad:
    ; Refuse atomically: no partial inventory survives a malformed request or
    ; an impossible/saturated enumerator input.
    call pci_mmio_out_reset
    mov  qword [r12 + RSP_CODE], CMDE_BADARG
.done:
    pop  r13
    pop  r12
    ret

; Bounded copied C string. Nonce is 1..64 printable non-space ASCII bytes.
; Optional PAGE is exact, decimal, no signs/trailing tokens. Reject before IO.
pci_mmio_scan_parse:
    xor  ecx, ecx
    cmp  byte [rdi], 0
    je   .ok
.nonce:
    movzx eax, byte [rdi + rcx]
    test eax, eax
    jz   .ok
    cmp  al, ' '
    je   .page
    cmp  al, 33
    jb   .bad
    cmp  al, 126
    ja   .bad
    inc  ecx
    cmp  ecx, 64
    ja   .bad
    jmp  .nonce
.page:
    test ecx, ecx
    jz   .bad
    lea  rdi, [rdi + rcx]
    cmp  dword [rdi], ' CFG'
    je .cfg
    cmp  dword [rdi], ' PAG'
    jne  .bad
    cmp  word [rdi + 4], 'E '
    jne  .bad
    add  rdi, 6
    xor  eax, eax
    xor  ecx, ecx
.digits:
    movzx edx, byte [rdi]
    test edx, edx
    jz   .end
    sub  edx, '0'
    cmp  edx, 9
    ja   .bad
    imul eax, eax, 10
    add  eax, edx
    cmp  eax, PCISCAN_END
    ja   .bad
    inc  ecx
    inc  rdi
    jmp  .digits
.end:
    test ecx, ecx
    jz   .bad
    mov  [rel pci_mmio_scan_start], rax
.ok:
    xor  eax, eax
    ret
.cfg:
    ; Exact one-digit page; no signs, trailing tokens or IO on refusal.
    cmp byte [rdi+4], ' '
    jne .bad
    movzx eax, byte [rdi+5]
    sub eax, '0'
    cmp eax, 7
    ja .bad
    cmp byte [rdi+6], 0
    jne .bad
    mov [rel pci_mmio_scan_cfg], al
    jmp .ok
.bad:
    mov  eax, 1
    ret

; Diagnostic CFG pages return at most12 inventory rows, including zero IDs.
; Normal PAGE still returns24. Each CFG page is a NEW live walk,
; never presented as one cached multi-page snapshot. Whole UDP budget checked by
; existing PCISCAN one-take framer before publishing any success body.
pci_mmio_scan_cfg_emit:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    movzx r12d, byte [rel pci_mmio_scan_cfg]
    lea rdi, [rel str_pciscan_cfg_page]
    call pci_mmio_out_str
    mov edi, r12d
    call pci_mmio_out_dec
    lea rdi, [rel str_pciscan_cfg_next]
    call pci_mmio_out_str
    lea rdi, [r12+1]
    call pci_mmio_out_dec
    lea rdi, [rel str_pciscan_cfg_complete]
    call pci_mmio_out_str
    xor edi, edi
    cmp r12d, 7
    sete dil
    call pci_mmio_out_dec
    lea rdi, [rel str_pciscan_cfg_bdf]
    call pci_mmio_out_str
    mov edi, r12d
    call pci_mmio_out_dec
    lea rdi, [rel str_pciscan_cfg_scope]
    call pci_mmio_out_str
    imul ebx, r12d, 3
    mov rdi, [rel pci_inventory_diag_original]
    mov ecx, ebx
    shr rdi, cl
    and edi, 7
    call pci_mmio_out_dec
    lea rdi, [rel str_pciscan_cfg_first]
    call pci_mmio_out_str
    lea r13, [rel pci_inventory_diag_first]
    call pci_mmio_scan_cfg_triple
    lea rdi, [rel str_pciscan_cfg_repeat]
    call pci_mmio_out_str
    lea r13, [rel pci_inventory_diag_repeat]
    call pci_mmio_scan_cfg_triple
    call pci_mmio_scan_ecam_emit
    lea rdi, [rel str_pciscan_cfg_equal]
    call pci_mmio_out_str
    xor ebp, ebp
    xor r14d, r14d
.equal:
    lea rax, [rel pci_inventory_diag_first]
    mov edx, [rax+rbx*4]
    lea rax, [rel pci_inventory_diag_repeat]
    cmp edx, [rax+rbx*4]
    jne .different
    bts ebp, r14d
.different:
    inc ebx
    inc r14d
    cmp r14d, 3
    jb .equal
    mov edi, ebp
    call pci_mmio_out_dec
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Compact versioned ECAM admission witness, independent of CF8 and AER.
; CFG0 reads only the observed same-bus control ID twice; CFG2/3/4 read the
; unknown functions'00/08/0c twice. Other CFG pages do NO ECAM read. Across
; these four commands this is at most20 DWORD loads, never a second scan.
; Each command is live independently; no cross-page stability/absence claim.
; v1,status2,mask1,MCFGbase16,MCFGmeta8,function16,leaf16,FWtype8,FWstart16,
; FWend16,PDE16,first00/08/0c8,repeat00/08/0c8 (all hex, no 0x).
; status0 means admitted raw loads only; status10 means not requested. Zeros
; in an unobserved sample are placeholders; only status0+mask marks reads.
pci_mmio_scan_ecam_emit:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 80
    mov r12, rsp
    mov rdi, rsp
    xor eax, eax
    mov ecx, 10
    rep stosq
    mov r13d, 10                    ; not requested, not unavailable
    xor r14d, r14d
    movzx edi, byte [rel pci_mmio_scan_cfg]
    test edi, edi
    jz .control
    cmp edi, 2
    jb .emit
    cmp edi, 4
    ja .emit
    mov r14d, 7
    jmp .read
.control:
    mov r14d, 1
.read:
    add edi, 24                    ; bus0 device3 function=CFGpage
    mov rsi, rsp
    mov edx, r14d
    call pci_ecam_cfg_snapshot
    mov r13d, eax
.emit:
    lea rdi, [rel str_pciscan_cfg_ecam]
    call pci_mmio_out_str
    mov edi, r13d
    mov edx, 2
    call pci_mmio_out_hex
    mov dil, ','
    call pci_mmio_out_char
    mov edi, r14d
    mov edx, 1
    call pci_mmio_out_hex
    xor ebx, ebx
.field:
    mov dil, ','
    call pci_mmio_out_char
    lea r15, [rel pci_mmio_ecam_fields]
    movzx ecx, byte [r15+rbx*2]
    movzx edx, byte [r15+rbx*2+1]
    mov edi, [r12+rcx]
    cmp edx, 16
    jne .value
    mov rdi, [r12+rcx]
.value:
    call pci_mmio_out_hex
    inc ebx
    cmp ebx, 14
    jb .field
    add rsp, 80
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; R13=array, EBX=fn*3, preserve EBX for the next triple and equality mask.
pci_mmio_scan_cfg_triple:
    push rbx
    push r14
    sub rsp, 8
    xor r14d, r14d
.next:
    mov edi, [r13+rbx*4]
    mov edx, 8
    call pci_mmio_out_hex
    inc r14d
    inc ebx
    cmp r14d, 3
    je .done
    mov dil, ','
    call pci_mmio_out_char
    jmp .next
.done:
    add rsp, 8
    pop r14
    pop rbx
    ret

; Callback inputs: EDI=bus, ESI=dev, EDX=fn, ECX=vendor/device.
; Preserve every callee-saved scan-loop register.
pci_mmio_scan_cb:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15d, ecx
    cmp  edi, 255
    ja   .invalid
    cmp  esi, 31
    ja   .invalid
    cmp  edx, 7
    ja   .invalid
    cmp  qword [rel pci_mmio_scan_count], PCISCAN_END
    jae  .invalid
    inc  qword [rel pci_mmio_scan_count]
    mov  eax, edi
    shl  eax, 8
    mov  r8d, esi
    shl  r8d, 3
    or   eax, r8d
    or   eax, edx
    cmp  rax, [rel pci_mmio_scan_start]
    jb   .done
    mov  r8d, PCISCAN_PAGE_ROWS
    cmp  byte [rel pci_mmio_scan_cfg], 255
    je   .row_limit
    mov  r8d, PCISCAN_CFG_ROWS
.row_limit:
    cmp  qword [rel pci_mmio_scan_returned], r8
    jb   .emit
    cmp  qword [rel pci_mmio_scan_next], PCISCAN_END
    jne  .done
    mov  [rel pci_mmio_scan_next], rax
    jmp  .done
.invalid:
    mov  byte [rel pci_mmio_scan_error], 1
    jmp  .done
.emit:
    inc  qword [rel pci_mmio_scan_returned]
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, r14d
    mov  ecx, 0x08
    call pci_inventory_read32
    mov  ebx, eax                         ; class/subclass/prog-if register

    mov  dil, ' '
    call pci_mmio_out_char
    movzx edi, r12b
    mov  edx, 2
    call pci_mmio_out_hex
    mov  dil, ':'
    call pci_mmio_out_char
    movzx edi, r13b
    mov  edx, 2
    call pci_mmio_out_hex
    mov  dil, '.'
    call pci_mmio_out_char
    movzx edi, r14b
    mov  edx, 1
    call pci_mmio_out_hex
    mov  dil, '='
    call pci_mmio_out_char
    movzx edi, r15w
    mov  edx, 4
    call pci_mmio_out_hex
    mov  dil, ':'
    call pci_mmio_out_char
    mov  eax, r15d
    shr  eax, 16
    movzx edi, ax
    mov  edx, 4
    call pci_mmio_out_hex
    mov  dil, '/'
    call pci_mmio_out_char
    mov  eax, ebx
    shr  eax, 24
    movzx edi, al
    mov  edx, 2
    call pci_mmio_out_hex
    mov  dil, ':'
    call pci_mmio_out_char
    mov  eax, ebx
    shr  eax, 16
    movzx edi, al
    mov  edx, 2
    call pci_mmio_out_hex
    mov  dil, ':'
    call pci_mmio_out_char
    mov  eax, ebx
    shr  eax, 8
    movzx edi, al
    mov  edx, 2
    call pci_mmio_out_hex
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; PCICFG_SAFE <nonce> — exact BAR0 read / same-value write / independent read.
; ---------------------------------------------------------------------------
cmd_verb_pcicfg_safe:
    call cmd_handler_prologue
    push r12
    call pci_mmio_out_reset
    call pci_cfg_same_bar_roundtrip
    jc   .failed
    lea  rdi, [rel str_pcicfg_head]
    call pci_mmio_out_str
    mov  rax, [rel pci_safe_bar_bdf]
    mov  r12, rax
    shr  rax, 16
    movzx edi, al
    mov  edx, 2
    call pci_mmio_out_hex
    mov  dil, ':'
    call pci_mmio_out_char
    mov  rax, r12
    shr  rax, 8
    movzx edi, al
    mov  edx, 2
    call pci_mmio_out_hex
    mov  dil, '.'
    call pci_mmio_out_char
    movzx edi, r12b
    mov  edx, 1
    call pci_mmio_out_hex
    lea  rdi, [rel str_pcicfg_before]
    call pci_mmio_out_str
    mov  edi, [rel pci_safe_bar_before]
    mov  edx, 8
    call pci_mmio_out_hex
    lea  rdi, [rel str_pcicfg_after]
    call pci_mmio_out_str
    mov  edi, [rel pci_safe_bar_after]
    mov  edx, 8
    call pci_mmio_out_hex
    lea  rdi, [rel str_pcicfg_ok]
    call pci_mmio_out_str
    jmp  .ready
.failed:
    lea  rdi, [rel str_pcicfg_fail]
    call pci_mmio_out_str
.ready:
    mov  byte [rel pci_mmio_out_ready], 1
    pop  r12
    ret

; ---------------------------------------------------------------------------
; MMIOCAP <nonce> — side-effect-free LAPIC-ID positive/negative access proof.
; The access counter increments only AFTER CAP_MMIO authorization. Therefore an
; unchanged counter around the denied attempt proves refusal happened before the
; HAL or hardware read.
; ---------------------------------------------------------------------------
cmd_verb_mmiocap:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    call pci_mmio_out_reset
    xor  ebx, ebx                         ; bit0=allowed, bit1=denied, bit2=pre-access
    mov  r15, [rel cap_current]           ; restore caller principal exactly

    mov  qword [rel cap_current], CAP_MMIO | CAP_IRQ
    mov  r12, [rel cap_mmio_access_count]
    lea  rdi, [rel apic_region]
    mov  esi, APIC_ID
    call cap_mmio_read32
    mov  r14d, eax                        ; LAPIC ID read-back (side-effect-free)
    jc   .allowed_done
    mov  rax, [rel cap_mmio_access_count]
    lea  rcx, [r12 + 1]
    cmp  rax, rcx
    jne  .allowed_done
    or   ebx, 1
.allowed_done:
    mov  qword [rel cap_current], 0
    mov  r13, [rel cap_mmio_access_count]
    lea  rdi, [rel apic_region]
    mov  esi, APIC_ID
    call cap_mmio_read32
    jnc  .denied_done
    or   ebx, 2
.denied_done:
    cmp  qword [rel cap_mmio_access_count], r13
    jne  .restore
    or   ebx, 4
.restore:
    mov  [rel cap_current], r15

    lea  rdi, [rel str_mmiocap_allowed]
    call pci_mmio_out_str
    mov  edi, ebx
    and  edi, 1
    call pci_mmio_out_dec
    lea  rdi, [rel str_mmiocap_denied]
    call pci_mmio_out_str
    mov  edi, ebx
    shr  edi, 1
    and  edi, 1
    call pci_mmio_out_dec
    lea  rdi, [rel str_mmiocap_pre]
    call pci_mmio_out_str
    mov  edi, ebx
    shr  edi, 2
    and  edi, 1
    call pci_mmio_out_dec
    lea  rdi, [rel str_mmiocap_access_before]
    call pci_mmio_out_str
    mov  rdi, r13
    call pci_mmio_out_dec
    lea  rdi, [rel str_mmiocap_access_after]
    call pci_mmio_out_str
    mov  rdi, [rel cap_mmio_access_count]
    call pci_mmio_out_dec
    lea  rdi, [rel str_mmiocap_source]
    call pci_mmio_out_str
    mov  edi, r14d
    mov  edx, 8
    call pci_mmio_out_hex
    mov  byte [rel pci_mmio_out_ready], 1

    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

align 8
pci_mmio_out_cur:    dq 0
pci_mmio_scan_count: dq 0
pci_mmio_scan_start: dq 0
pci_mmio_scan_returned: dq 0
pci_mmio_scan_next: dq PCISCAN_END
pci_mmio_scan_cfg: db 255
pci_mmio_scan_error: db 0
pci_mmio_scan_ready: db 0
pci_mmio_scan_arg: times PCISCAN_ARG_CAP db 0
pci_mmio_out_ready:  db 0
pci_mmio_num_buf:    times 24 db 0
pci_mmio_out_buf:    times PCI_MMIO_OUT_CAP db 0

str_verb_pciscan:       db "PCISCAN", 0
str_verb_pcicfg_safe:   db "PCICFG_SAFE", 0
str_verb_mmiocap:       db "MMIOCAP", 0
str_pciscan_head:       db " PCISCAN", 0
str_pciscan_count:      db " devices=", 0
str_pciscan_start:      db " start=", 0
str_pciscan_returned:   db " returned=", 0
str_pciscan_next:       db " next=", 0
str_pciscan_complete:   db " complete=", 0
str_pciscan_live:       db " scan=live", 0
str_pcicfg_head:        db " PCICFG_SAFE kind=bar offset=0x10 bdf=", 0
str_pcicfg_before:      db " before=0x", 0
str_pcicfg_after:       db " after=0x", 0
str_pcicfg_ok:          db " same_value=1", 0
str_pcicfg_fail:        db " PCICFG_SAFE ERR no_known_bar_or_readback_mismatch", 0
str_mmiocap_allowed:    db " MMIOCAP allowed_read=", 0
str_mmiocap_denied:     db " denied=", 0
str_mmiocap_pre:        db " denied_before_access=", 0
str_mmiocap_access_before: db " access_before=", 0
str_mmiocap_access_after:  db " access_after=", 0
str_mmiocap_source:     db " source=lapic_id lapic_id=0x", 0

str_pciscan_cfg_page: db " cfg_page=",0
str_pciscan_cfg_next: db " cfg_next=",0
str_pciscan_cfg_complete: db " cfg_complete=",0
str_pciscan_cfg_bdf: db " cfg_bdf=00:03.",0
str_pciscan_cfg_scope: db " cfg_scope=live_per_request cfg_mech=cf8_cfc cfg_status=unknown cfg_offsets=00,08,0c cfg_original_mask=",0
str_pciscan_cfg_first: db " cfg_first=",0
str_pciscan_cfg_repeat: db " cfg_repeat=",0
str_pciscan_cfg_equal: db " cfg_equal_mask=",0

; record offset, exact maximum hexadecimal width; no arbitrary formatter input.
pci_mmio_ecam_fields: db 0,16,48,8,8,16,16,16,52,8,24,16,32,16,40,16,56,8,60,8,64,8,68,8,72,8,76,8
str_pciscan_cfg_ecam: db " cfg_ecam=v1,",0
