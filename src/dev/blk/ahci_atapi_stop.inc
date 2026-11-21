; dev/blk/ahci_atapi_stop.inc - T4-4 328 (ROOT 121217(2), SEC 121222 A1-A3/A6).
; PaOS never drives an ATAPI drive (.pscan skips it). Until 328 the firmware's FIS
; receive engine on that port kept running all session: DMA rights into the
; firmware-chosen PxFB. At the original .pscan, once per skipped port, this ends
; that right with exactly one PxCMD write and records what it saw. It never issues
; a command, never resets the link and never writes CLB/FB/IS/SERR/IE/SCTL.
;
; Legacy HBA only (A1). A VMD child is recorded state 5 with no further access:
; MSI's VMD estate is untouched (SR-12).
;
; A2b (SEC 121230 S-1..S-4, ROOT 122179): once FR is observed 0, a firmware-latched PxIS
; of only DHRS and/or PSS with PxIE==0 gets exactly one W1C of the latched value (intent
; recorded first, the fresh IS must still equal it) and must then read 0. At most 2
; writes per port: CMD, IS.
;
; Row (AAS_ROW bytes per physical port, u32 words, zero = unseen):
;  0 state  1 polls  2 SIG  3 SSTS  4 CMD before  5 CMD written (0 none)  6 CMD last
;  7 IS  8 IE  9 SERR  10 CI  11 SACT  12/13 CLB lo/hi  14/15 FB lo/hi (original, A6)
;  16 IS fresh before W1C  17 IS written (0 none)  18 IS after  19 IE fresh before W1C
; Header (AAS_HDR): bus, dev, fn, selected vendor/device, ABAR (u64), scans.
; The terminal admits DET=3 on an unregistered port only against this boot's row
; for the same HBA identity and port (ahci_atapi_terminal_admit).

AAS_ROW      equ 80
AAS_HDR      equ 32
AAS_POLLS    equ 500                  ; x tsc_delay_us(1000): the 500 ms bound
AAS_OFF      equ 1                    ; FRE and FR already 0: no write
AAS_STOPPED  equ 2                    ; one write, FR observed 0
AAS_STUCK    equ 3                    ; one write, FR still 1 at the bound: no second write
AAS_RUNNING  equ 4                    ; ST or CR set: a command engine PaOS does not own; no write
AAS_VMD      equ 5                    ; VMD child: not attempted (SR-12)
AAS_IS_REFUSED equ 6                  ; FR 0 but the latched IS is not clearable stale receive status: no IS write
AAS_IS_STUCK equ 7                    ; the one IS W1C, IS still non-zero after it: no retry
AAS_IS_DHRS  equ AEO_IS_STALE         ; FS F4's shared empty-port mask (ahci_empty_owner.inc), DHRS
AAS_IS_PSS   equ 0x2                  ; PxIS.PSS: PIO Setup FIS (firmware PIO-in ATAPI, e.g. IDENTIFY PACKET)
; S-1, ROOT 122179 (Lenovo twin leg 2, IS 0x3 under OVMF): ATAPI ports only, and only after
; FR is observed 0, when no FIS can arrive, so these receive-status bits are stale.
; AEO_IS_STALE stays DHRS only for FS's empty ports.
AAS_IS_STALE equ AAS_IS_DHRS | AAS_IS_PSS
AAS_SIG_ATAPI equ 0xEB140101
AAS_PX_IE     equ 0x14               ; PxIE (no AHCI_PORT_ equ exists)
AAS_PX_SACT   equ 0x34               ; PxSACT
AAS_CMD_KEEP  equ 0x0FFFFFE7           ; clear FRE (bit4), CLO (bit3) and ICC (31:28); ST stays as read (0)

; EDI = physical port, RBX = ABAR (.pscan's identity-mapped MMIO).
; Called only from ahci_blk_create .pscan for a DET=3 port whose SIG is ATAPI.
; Preserves RBX, RBP, R12-R15.
ahci_atapi_fre_stop:
    push r12
    push r13
    push r14
    mov  r13d, edi
    cmp  r13d, 32
    jae  .out
    ; A1 identity: the HBA these rows belong to, as .pscan sees it.
    mov  eax, [rel ahci_busno]
    mov  [rel ahci_atapi_stop_hdr], eax
    mov  eax, [rel ahci_devno]
    mov  [rel ahci_atapi_stop_hdr+4], eax
    mov  eax, [rel ahci_fn]
    mov  [rel ahci_atapi_stop_hdr+8], eax
    mov  eax, [rel ahci_terminal_selected_id]
    mov  [rel ahci_atapi_stop_hdr+12], eax
    mov  rax, [rel ahci_bar5]
    mov  [rel ahci_atapi_stop_hdr+16], rax
    inc  dword [rel ahci_atapi_stop_hdr+24]
    imul eax, r13d, AAS_ROW
    lea  r12, [rel ahci_atapi_stop_rows]
    add  r12, rax
    mov  rdi, r12
    mov  ecx, AAS_ROW/8
    xor  eax, eax
    rep  stosq
    cmp  byte [rel ahci_vmd_child], 0
    je   .legacy
    mov  dword [r12], AAS_VMD
    jmp  .emit
.legacy:
    mov  r14d, r13d
    shl  r14d, 7
    add  r14d, AHCI_PORT_BASE
    add  r14, rbx                         ; port base, identity-mapped
    mov  eax, [r14 + AHCI_PORT_SIG]
    mov  [r12+8], eax
    mov  eax, [r14 + AHCI_PORT_SSTS]
    mov  [r12+12], eax
    mov  eax, [r14 + AHCI_PORT_IS]
    mov  [r12+28], eax
    mov  eax, [r14 + AAS_PX_IE]
    mov  [r12+32], eax
    mov  eax, [r14 + AHCI_PORT_SERR]
    mov  [r12+36], eax
    mov  eax, [r14 + AHCI_PORT_CI]
    mov  [r12+40], eax
    mov  eax, [r14 + AAS_PX_SACT]
    mov  [r12+44], eax
    mov  eax, [r14 + AHCI_PORT_CLB]
    mov  [r12+48], eax
    mov  eax, [r14 + AHCI_PORT_CLBU]
    mov  [r12+52], eax
    mov  eax, [r14 + AHCI_PORT_FB]
    mov  [r12+56], eax
    mov  eax, [r14 + AHCI_PORT_FBU]
    mov  [r12+60], eax
    mov  eax, [r14 + AHCI_PORT_CMD]       ; the read the single write derives from (A2)
    mov  [r12+16], eax
    mov  [r12+24], eax
    test eax, AHCI_PXCMD_ST | AHCI_PXCMD_CR
    jz   .not_running
    mov  dword [r12], AAS_RUNNING
    jmp  .emit
.not_running:
    test eax, AHCI_PXCMD_FRE | AHCI_PXCMD_FR
    jnz  .stop
    mov  dword [r12], AAS_OFF
    jmp  .is_clear
.stop:
    and  eax, AAS_CMD_KEEP                ; ST stays 0 (read above), FRE/CLO/ICC 0
    mov  [r12+20], eax
    mov  [r14 + AHCI_PORT_CMD], eax       ; the one write
.poll:
    inc  dword [r12+4]
    mov  eax, [r14 + AHCI_PORT_CMD]
    mov  [r12+24], eax
    test eax, AHCI_PXCMD_FR
    jz   .stopped
    cmp  dword [r12+4], AAS_POLLS
    jae  .stuck
    mov  edi, 1000
    call tsc_delay_us
    jmp  .poll
.stuck:
    mov  dword [r12], AAS_STUCK           ; no second write, no retry
    jmp  .emit
.stopped:
    mov  dword [r12], AAS_STOPPED
.is_clear:                                ; A2b: only here, after FR observed 0 with ST=CR=0
    mov  eax, [r12+28]                    ; the latched original IS
    test eax, eax
    jz   .emit
    mov  eax, [r14 + AAS_PX_IE]           ; the fresh read right before the write
    mov  [r12+76], eax
    mov  eax, [r14 + AHCI_PORT_IS]
    mov  [r12+64], eax
    mov  eax, [r12+28]
    cmp  dword [r12+32], 0                ; S-2 original and fresh IE both 0
    jne  .is_refused
    cmp  dword [r12+76], 0
    jne  .is_refused
    test eax, ~AAS_IS_STALE               ; S-1 DHRS|PSS only: any other bit refuses
    jnz  .is_refused
    cmp  eax, [r12+64]                    ; S-3 unchanged since latched, else no write
    jne  .is_refused
    mov  [r12+68], eax                    ; intent before effect
    mov  [r14 + AHCI_PORT_IS], eax        ; the one W1C of exactly the latched bits
    mov  eax, [r14 + AHCI_PORT_IS]        ; S-4 stale admission off: must read 0
    mov  [r12+72], eax
    test eax, eax
    jz   .emit
    mov  dword [r12], AAS_IS_STUCK
    jmp  .emit
.is_refused:
    mov  dword [r12], AAS_IS_REFUSED
.emit:
    call ahci_atapi_stop_emit
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

; R12 = row, R13D = port. One serial line (A6: original CLB/FB for the host's
; memory-map grade). Straight-line: no pointer tables (org-0 image).
ahci_atapi_stop_emit:
%macro AAS_FIELD 2
    lea  rdi, [rel %1]
    call serial_string
    mov  edi, %2
    call serial_hex64
%endmacro
%macro AAS_ROWF 2
    lea  rdi, [rel %1]
    call serial_string
    mov  edi, [r12+%2]
    call serial_hex64
%endmacro
    lea  rdi, [rel str_aas_head]
    call serial_string
    mov  edi, [rel ahci_atapi_stop_hdr]
    call serial_hex64
    AAS_FIELD str_aas_dev, [rel ahci_atapi_stop_hdr+4]
    AAS_FIELD str_aas_fn, [rel ahci_atapi_stop_hdr+8]
    AAS_FIELD str_aas_id, [rel ahci_atapi_stop_hdr+12]
    lea  rdi, [rel str_aas_bar]
    call serial_string
    mov  rdi, [rel ahci_atapi_stop_hdr+16]
    call serial_hex64
    AAS_FIELD str_aas_port, r13d
    AAS_ROWF str_aas_state, 0
    AAS_ROWF str_aas_polls, 4
    AAS_ROWF str_aas_sig, 8
    AAS_ROWF str_aas_ssts, 12
    AAS_ROWF str_aas_cmd0, 16
    AAS_ROWF str_aas_cmdw, 20
    AAS_ROWF str_aas_cmd1, 24
    AAS_ROWF str_aas_is, 28
    AAS_ROWF str_aas_ie, 32
    AAS_ROWF str_aas_serr, 36
    AAS_ROWF str_aas_ci, 40
    AAS_ROWF str_aas_sact, 44
    lea  rdi, [rel str_aas_clb]
    call serial_string
    mov  rdi, [r12+48]
    call serial_hex64
    lea  rdi, [rel str_aas_fb]
    call serial_string
    mov  rdi, [r12+56]
    call serial_hex64
    AAS_ROWF str_aas_isp, 64
    AAS_ROWF str_aas_isw, 68
    AAS_ROWF str_aas_isa, 72
    AAS_ROWF str_aas_iep, 76
    call serial_newline
    ret
%unmacro AAS_FIELD 2
%unmacro AAS_ROWF 2

; A3: called by ahci_terminal_quiesce .port_check for an UNREGISTERED port whose
; fresh SSTS.DET != 0. R13 = terminal observations (identity words at +44/+48/+52,
; ABAR +64, selected id +136), R12 = that port's terminal row (fresh SSTS +76,
; SIG +80), R14D = physical port. CF clear only for DET==3 with this boot's state
; 1/2 row (FR 0; IS cleared or never set) for the same HBA and port and SIG ATAPI
; both then and now; the caller
; still applies every engine/queue/IE/IS predicate. RAM only; no MMIO. On
; admission the row's state goes to terminal word 27 (reserved0 otherwise).
ahci_atapi_terminal_admit:
    mov  eax, [r12+76]
    and  eax, 15
    cmp  eax, 3
    jne  .no
    cmp  dword [r12+80], AAS_SIG_ATAPI
    jne  .no
    cmp  r14d, 32
    jae  .no
    cmp  dword [rel ahci_atapi_stop_hdr+24], 0
    je   .no
    mov  eax, [rel ahci_atapi_stop_hdr]
    cmp  eax, [r13+44]
    jne  .no
    mov  eax, [rel ahci_atapi_stop_hdr+4]
    cmp  eax, [r13+48]
    jne  .no
    mov  eax, [rel ahci_atapi_stop_hdr+8]
    cmp  eax, [r13+52]
    jne  .no
    mov  eax, [rel ahci_atapi_stop_hdr+12]
    cmp  eax, [r13+136]
    jne  .no
    mov  rax, [rel ahci_atapi_stop_hdr+16]
    cmp  rax, [r13+64]
    jne  .no
    imul eax, r14d, AAS_ROW
    lea  rdx, [rel ahci_atapi_stop_rows]
    add  rdx, rax
    cmp  dword [rdx+8], AAS_SIG_ATAPI
    jne  .no
    mov  eax, [rdx]
    cmp  eax, AAS_OFF
    je   .yes
    cmp  eax, AAS_STOPPED
    jne  .no
.yes:
    mov  [r12+108], eax                   ; terminal word 27: the admitting row state
    clc
    ret
.no:
    stc
    ret

str_aas_head:  db "[PAOS64] AHCIATAPI1 bus=", 0
str_aas_dev:   db " dev=", 0
str_aas_fn:    db " fn=", 0
str_aas_id:    db " id=", 0
str_aas_bar:   db " bar=", 0
str_aas_port:  db " port=", 0
str_aas_state: db " state=", 0
str_aas_polls: db " polls=", 0
str_aas_sig:   db " sig=", 0
str_aas_ssts:  db " ssts=", 0
str_aas_cmd0:  db " cmd0=", 0
str_aas_cmdw:  db " cmdw=", 0
str_aas_cmd1:  db " cmd1=", 0
str_aas_is:    db " is=", 0
str_aas_ie:    db " ie=", 0
str_aas_serr:  db " serr=", 0
str_aas_ci:    db " ci=", 0
str_aas_sact:  db " sact=", 0
str_aas_clb:   db " clb=", 0
str_aas_fb:    db " fb=", 0
str_aas_isp:   db " isp=", 0
str_aas_isw:   db " isw=", 0
str_aas_isa:   db " isa=", 0
str_aas_iep:   db " iep=", 0

; Zero state: its own block (pinned WDATA_dev_blk_ahci_0* layouts stay unchanged).
%macro WDATA_BSS_dev_blk_ahci_atapi_stop 0
alignb 8
ahci_atapi_stop_hdr:  resb AAS_HDR
ahci_atapi_stop_rows: resb 32*AAS_ROW
%endmacro
WDATA_BSS_DEFER WDATA_BSS_dev_blk_ahci_atapi_stop
