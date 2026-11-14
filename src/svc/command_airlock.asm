;; MODULE svc/command_airlock
;; LAYER 5
;; EXPORTS airlock_declare, airlock_faultinj_xhci, cmd_verb_airlockstatus, cmd_verb_airlockfile, airlock_out_buf, airlock_out_cur, airlock_out_ready
;; IMPORTS svc/command, core/lib/fmt, core/lib/str, dev/usb/xhci, fs/vfs
;; CAPS mmio dma
;; OWNER task:1316
; ============================================================================
; Pillar-4 hardware-airlock demo. The e1000e control NIC is never targeted:
; FAULTINJ xhci stops the non-lifeline xHCI controller, requires a live HCHalted
; readback, and reuses the shipped reset/program/run path. AIRLOCKFILE performs
; a real temp-then-swap FAT/VFS write and byte-exact readback in the running OS.
; ============================================================================

airlock_declare:
    lea  rdi, [rel str_verb_airlockstatus]
    lea  rsi, [rel cmd_verb_airlockstatus]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_airlockfile]
    lea  rsi, [rel cmd_verb_airlockfile]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    ret

; Called by the existing FAULTINJ registry handler for its exact xhci token.
; Returns the xhci_airlock_fault result and stages the hardware receipt.
airlock_faultinj_xhci:
    push rbx
    call xhci_airlock_fault
    mov  rbx, rax
    call airlock_out_reset
    lea  rdi, [rel str_al_inj_pre]
    call airlock_out_str
    movzx edi, byte [rel xhci_airlock_last_halted]
    call airlock_out_dec
    lea  rdi, [rel str_al_inj_cont]
    call airlock_out_str
    xor  edi, edi
    test rbx, rbx
    setz dil
    call airlock_out_dec
    lea  rdi, [rel str_al_inj_reinit]
    call airlock_out_str
    test rbx, rbx
    jnz  .failed
    lea  rdi, [rel str_al_ok]
    jmp  .verdict
.failed:
    lea  rdi, [rel str_al_fail]
.verdict:
    call airlock_out_str
    lea  rdi, [rel str_al_code]
    call airlock_out_str
    mov  rdi, rbx
    call airlock_out_dec
    call airlock_append_status
    mov  byte [rel airlock_out_ready], 1
    mov  rax, rbx
    pop  rbx
    ret

cmd_verb_airlockstatus:
    call cmd_handler_prologue
    call airlock_out_reset
    lea  rdi, [rel str_al_status]
    call airlock_out_str
    call airlock_append_status
    mov  byte [rel airlock_out_ready], 1
    ret

; AIRLOCKFILE SET <nonce> | GET. The file is a FAT 8.3 entry in the shipped
; RAM-backed VFS, so the proof crosses the filesystem implementation rather
; than reading a command-module variable back directly.
cmd_verb_airlockfile:
    call cmd_handler_prologue
    push rbx
    mov  rdi, [rdi + REQ_ARG]
    call airlock_tokenize
    call airlock_out_reset
    lea  rax, [rel airlock_tok]
    mov  rdi, [rax]
    lea  rsi, [rel str_al_set]
    call airlock_tok_is
    je   .set
    lea  rax, [rel airlock_tok]
    mov  rdi, [rax]
    lea  rsi, [rel str_al_get]
    call airlock_tok_is
    je   .get
    lea  rdi, [rel str_al_file_badarg]
    call airlock_out_str
    jmp  .done
.set:
    lea  rax, [rel airlock_tok]
    mov  rsi, [rax + 8]
    test rsi, rsi
    jz   .badarg
    lea  rdi, [rel airlock_file_buf]
    xor  ecx, ecx
.copy_nonce:
    cmp  ecx, 63
    jae  .copy_done
    mov  al, [rsi + rcx]
    mov  [rdi + rcx], al
    test al, al
    jz   .have_len
    inc  ecx
    jmp  .copy_nonce
.copy_done:
    mov  byte [rdi + rcx], 0
.have_len:
    test ecx, ecx
    jz   .badarg
    mov  edi, [rel vfs_ram_handle]
    lea  rsi, [rel airlock_filename]
    lea  rdx, [rel airlock_file_buf]
    call vfs_writefile
    cmp  rax, -1
    je   .ioerr
    lea  rdi, [rel str_al_file_pre]
    call airlock_out_str
    lea  rdi, [rel airlock_file_buf]
    call airlock_out_str
    lea  rdi, [rel str_al_file_setok]
    call airlock_out_str
    jmp  .done
.get:
    mov  edi, [rel vfs_ram_handle]
    lea  rsi, [rel airlock_filename]
    lea  rdx, [rel airlock_file_buf]
    mov  rcx, 63
    call vfs_readfile
    cmp  rax, -1
    je   .ioerr
    cmp  rax, 63
    jbe  .size_ok
    mov  eax, 63
.size_ok:
    lea  rdx, [rel airlock_file_buf]
    mov  byte [rdx + rax], 0
    mov  rbx, rax
    lea  rdi, [rel str_al_file_pre]
    call airlock_out_str
    lea  rdi, [rel airlock_file_buf]
    call airlock_out_str
    lea  rdi, [rel str_al_file_size]
    call airlock_out_str
    mov  rdi, rbx
    call airlock_out_dec
    lea  rdi, [rel str_al_file_getok]
    call airlock_out_str
    jmp  .done
.badarg:
    lea  rdi, [rel str_al_file_badarg]
    call airlock_out_str
    jmp  .done
.ioerr:
    lea  rdi, [rel str_al_file_ioerr]
    call airlock_out_str
.done:
    mov  byte [rel airlock_out_ready], 1
    pop  rbx
    ret

; Put critical live hardware fields first so they cannot be lost behind PaOS's
; long earned-marker tail. Counters follow the independent current USBSTS read.
airlock_append_status:
    push rbx
    push r12
    call xhci_airlock_status
    mov  ebx, eax
    mov  r12d, edx
    lea  rdi, [rel str_al_live]
    call airlock_out_str
    mov  edi, ebx
    call airlock_out_dec
    lea  rdi, [rel str_al_hch]
    call airlock_out_str
    mov  edi, r12d
    call airlock_out_dec
    lea  rdi, [rel str_al_usbsts]
    call airlock_out_str
    mov  edi, [rel xhci_airlock_last_usbsts]
    call airlock_out_hex
    lea  rdi, [rel str_al_bdf_bus]
    call airlock_out_str
    mov  edi, [rel xhci_bus]
    call airlock_out_dec
    lea  rdi, [rel str_al_bdf_dev]
    call airlock_out_str
    mov  edi, [rel xhci_dev]
    call airlock_out_dec
    lea  rdi, [rel str_al_bdf_fn]
    call airlock_out_str
    mov  edi, [rel xhci_fn]
    call airlock_out_dec
    lea  rdi, [rel str_al_attempts]
    call airlock_out_str
    mov  rdi, [rel xhci_airlock_attempts]
    call airlock_out_dec
    lea  rdi, [rel str_al_injected]
    call airlock_out_str
    mov  rdi, [rel xhci_airlock_injected]
    call airlock_out_dec
    lea  rdi, [rel str_al_contained]
    call airlock_out_str
    mov  rdi, [rel xhci_airlock_contained]
    call airlock_out_dec
    lea  rdi, [rel str_al_uncontained]
    call airlock_out_str
    mov  rdi, [rel xhci_airlock_uncontained]
    call airlock_out_dec
    lea  rdi, [rel str_al_metric]
    call airlock_out_str
    mov  rdi, [rel xhci_airlock_contained]
    call airlock_out_dec
    pop  r12
    pop  rbx
    ret

airlock_tokenize:
    lea  rsi, [rel airlock_argbuf]
    xor  ecx, ecx
.cp:
    cmp  ecx, 95
    jae  .cap
    mov  al, [rdi + rcx]
    mov  [rsi + rcx], al
    test al, al
    jz   .copied
    inc  ecx
    jmp  .cp
.cap:
    mov  byte [rsi + rcx], 0
.copied:
    mov  qword [rel airlock_tok], 0
    mov  qword [rel airlock_tok + 8], 0
    lea  rsi, [rel airlock_argbuf]
    xor  ecx, ecx
.scan:
    cmp  byte [rsi], ' '
    jne  .start
    inc  rsi
    jmp  .scan
.start:
    cmp  byte [rsi], 0
    je   .done
    cmp  ecx, 2
    jae  .done
    lea  rax, [rel airlock_tok]
    mov  [rax + rcx*8], rsi
    inc  ecx
.word:
    cmp  byte [rsi], 0
    je   .done
    cmp  byte [rsi], ' '
    je   .split
    inc  rsi
    jmp  .word
.split:
    mov  byte [rsi], 0
    inc  rsi
    jmp  .scan
.done:
    ret

airlock_tok_is:
    test rdi, rdi
    jz   .ne
    call strcmp
    test rax, rax
    ret
.ne:
    or   eax, 1
    ret

airlock_out_reset:
    lea  rax, [rel airlock_out_buf]
    mov  [rel airlock_out_cur], rax
    mov  byte [rax], 0
    ret

airlock_out_str:
    mov  rsi, [rel airlock_out_cur]
    lea  rdx, [rel airlock_out_buf + 511]
.cp:
    cmp  rsi, rdx
    jae  .done
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .cp
.done:
    mov  byte [rsi], 0
    mov  [rel airlock_out_cur], rsi
    ret

airlock_out_dec:
    mov  rsi, [rel airlock_out_cur]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel airlock_out_cur], rsi
    ret

airlock_out_hex:
    mov  rsi, [rel airlock_out_cur]
    push rsi
    xor  edx, edx
    call fmt_hex
    pop  rsi
    add  rsi, rax
    mov  [rel airlock_out_cur], rsi
    ret

align 8
airlock_out_cur:   dq 0
airlock_out_ready: db 0
align 8
airlock_tok:       dq 0, 0
airlock_argbuf:    times 96 db 0
airlock_file_buf:  times 64 db 0
airlock_out_buf:   times 512 db 0

str_verb_airlockstatus: db "AIRLOCKSTATUS", 0
str_verb_airlockfile:   db "AIRLOCKFILE", 0
str_al_set:             db "SET", 0
str_al_get:             db "GET", 0
airlock_filename:       db "AIRLOCK TXT"       ; exact FAT 8.3 name AIRLOCK.TXT

str_al_inj_pre:       db " AIRLOCK fault_path=xhci_stop_reset target=xhci hardware_halt=", 0
str_al_inj_cont:      db " contained=", 0
str_al_inj_reinit:    db " reinit=", 0
str_al_ok:            db "ok", 0
str_al_fail:          db "fail", 0
str_al_code:          db " code=", 0
str_al_status:        db " AIRLOCK driver=xhci", 0
str_al_live:          db " live=", 0
str_al_hch:           db " hch=", 0
str_al_usbsts:        db " usbsts=0x", 0
str_al_bdf_bus:       db " bdf=", 0
str_al_bdf_dev:       db ":", 0
str_al_bdf_fn:        db ".", 0
str_al_attempts:      db " attempts=", 0
str_al_injected:      db " injected=", 0
str_al_contained:     db " faults_contained=", 0
str_al_uncontained:   db " faults_uncontained=", 0
str_al_metric:        db " stab.contained_faults=", 0
str_al_file_pre:      db " AIRLOCKFILE file=AIRLOCK.TXT nonce=", 0
str_al_file_setok:    db " write=ok", 0
str_al_file_size:     db " size=", 0
str_al_file_getok:    db " readback=ok", 0
str_al_file_badarg:   db " AIRLOCKFILE ERR usage=SET_<nonce>|GET", 0
str_al_file_ioerr:    db " AIRLOCKFILE ERR vfs_io", 0
