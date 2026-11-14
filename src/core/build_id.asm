;; MODULE core/build_id
;; LAYER 1
;; EXPORTS build_id_measure, build_id_report, build_id_state_text, paos_build_measured, paos_build_hex, paos_build_state
;; IMPORTS core/lib/sha256, boot/serial
;; CAPS
;; OWNER rc-boot-claude
;; CONTEXT: bsp_only
; core/build_id.asm — SEC-pbh1-acceptance-identity (root 06:20:51): the
; running image MEASURES its own identity instead of echoing the CRC-only
; Manager handoff claim (pbm_payload_sha).
;
; build_id = SHA-256 over D = [code_start, wdata_region): code, rodata and the
; legacy in-line data, up to the page-isolated WDATA region. PaOS needs no
; runtime pointer relocation, so these bytes equal the file's bytes at
; file offset 0x200 for any load base. The image pages are still writable
; (pre-W^X), so D is pristine only before PaOS stores anything: efi_entry
; calls build_id_measure FIRST. sha256_hash writes only its WDATA scratch.
;
; The post-link stamp (tools/build_identity.py, run by `make build` before any
; signing) writes SHA-256 of the file's D bytes into paos_build_stamp, which
; is WDATA and therefore outside D. The self-check compares stamp and
; measurement: match | unstamped (a direct nasm assembly) | mismatch (the bytes
; that ran are not the bytes the build stamped). Consumers print the MEASURED
; value only; a tool recomputes SHA-256(D) from the staged artefact and trusts
; neither the stamp nor the claim. The id names what was LOADED; later writes
; into D (pre-W^X) do not change it, so it is not a runtime-integrity claim.

BID_ST_UNMEASURED   equ 0
BID_ST_MATCH        equ 1
BID_ST_UNSTAMPED    equ 2
BID_ST_MISMATCH     equ 3
BID_STAMP_MAGIC     equ 0                ; 'PAOSBID1'
BID_STAMP_DOM_LEN   equ 8                ; u32 bytes of D
BID_STAMP_RSVD      equ 12               ; u32 zero
BID_STAMP_DIGEST    equ 16               ; 32 bytes, zero until stamped
BID_STAMP_SIZE      equ 48

; build_id_measure -> nothing. The first call of efi_entry: no store into D
; before it. Clobbers the SysV scratch registers (the caller keeps RCX/RDX).
build_id_measure:
    push rbx
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  rbx, rax
    lea  rdi, [rel paos_build_measured]
    lea  rsi, [rel code_start]
    mov  edx, wdata_region - code_start
    call sha256_hash
    test rax, rax
    jnz  .out                            ; stays UNMEASURED, no text
    lea  rsi, [rel paos_build_measured]
    lea  rdi, [rel paos_build_hex]
    lea  r8, [rel bid_hex_digits]
    mov  ecx, 32
.hex:
    movzx eax, byte [rsi]
    mov  edx, eax
    shr  eax, 4
    mov  al, [r8 + rax]
    mov  [rdi], al
    and  edx, 0x0F
    mov  dl, [r8 + rdx]
    mov  [rdi + 1], dl
    inc  rsi
    add  rdi, 2
    dec  ecx
    jnz  .hex
    mov  byte [rdi], 0
    mov  byte [rel paos_build_state], BID_ST_UNSTAMPED
    lea  rsi, [rel paos_build_stamp + BID_STAMP_DIGEST]
    mov  rax, [rsi]
    or   rax, [rsi + 8]
    or   rax, [rsi + 16]
    or   rax, [rsi + 24]
    jz   .timed                          ; never stamped: a direct assembly
    mov  byte [rel paos_build_state], BID_ST_MISMATCH
    lea  rdi, [rel paos_build_measured]
    xor  ecx, ecx
.cmp:
    mov  rax, [rsi + rcx*8]
    cmp  rax, [rdi + rcx*8]
    jne  .timed
    inc  ecx
    cmp  ecx, 4
    jb   .cmp
    mov  byte [rel paos_build_state], BID_ST_MATCH
.timed:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, rbx
    mov  [rel paos_build_measure_tsc], rax
.out:
    pop  rbx
    ret

; build_id_state_text -> RDI the state word (NUL-terminated). Clobbers RAX only.
; RIP-relative only: the image has no runtime pointer relocation.
build_id_state_text:
    movzx eax, byte [rel paos_build_state]
    lea  rdi, [rel str_bid_match]
    cmp  eax, BID_ST_MATCH
    je   .out
    lea  rdi, [rel str_bid_unstamped]
    cmp  eax, BID_ST_UNSTAMPED
    je   .out
    lea  rdi, [rel str_bid_mismatch]
    cmp  eax, BID_ST_MISMATCH
    je   .out
    lea  rdi, [rel str_bid_unmeasured]
.out:
    ret

; build_id_report -> nothing. One serial line once serial is up:
; [PAOS64] build id: <64 hex> bid=<state> measure_tsc=0x.. [boot.build_id]
build_id_report:
    sub  rsp, 8
    lea  rdi, [rel str_bid_line]
    call serial_string
    lea  rdi, [rel paos_build_hex]
    call serial_string
    lea  rdi, [rel str_bid_state]
    call serial_string
    call build_id_state_text
    call serial_string
    lea  rdi, [rel str_bid_tsc]
    call serial_string
    mov  rdi, [rel paos_build_measure_tsc]
    call serial_hex64
    lea  rdi, [rel str_bid_marker]
    call serial_string
    add  rsp, 8
    ret

bid_hex_digits:   db "0123456789abcdef"
str_bid_line:     db "[PAOS64] build id: ",0
str_bid_state:    db " bid=",0
str_bid_tsc:      db " measure_tsc=",0
str_bid_marker:   db " [boot.build_id]",13,10,0
str_bid_unmeasured: db "unmeasured",0
str_bid_match:    db "match",0
str_bid_unstamped: db "unstamped",0
str_bid_mismatch: db "mismatch",0

%include "core/abi/wdata.inc"
%macro WDATA_core_build_id 0
align 8, db 0
paos_build_measured:    times 32 db 0
paos_build_measure_tsc: dq 0
paos_build_hex:         times 65 db 0
paos_build_state:       db BID_ST_UNMEASURED
align 8, db 0
; The post-link stamp: outside D, never written at runtime.
paos_build_stamp:
    db 'PAOSBID1'
    dd wdata_region - code_start
    dd 0
    times 32 db 0
%endmacro
WDATA_DEFER WDATA_core_build_id
