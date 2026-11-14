;; MODULE sec/owner_stage_key
;; LAYER 5
;; EXPORTS owner_stage_key_preebs, owner_stage_key_hkdf, owner_stage_key_discard, osk_state, osk_flags
;; IMPORTS boot/header, boot/serial, boot/nvram_access, boot/boot_v2_handoff, sec/principal, core/lib/hkdf_sha256, core/lib/mem
;; CAPS
;; OWNER saga:sec
;; CONTEXT: bsp_only
; ============================================================================
; sec/owner_stage_key.asm — owner identity S1b-2c-0: the owner STAGE KEY Z
; (srcreview c-1 M1, rc-sec 11:22:50, root 11:25:44 with srcreview Z1-Z6).
;
; The owner store authenticated its stages with HKDF(Y), but every Y spends at
; least one boot in the NV|BS|RT PaOSPrincipalCred (system_secret: Y is made
; after EBS and migrated on the next boot), so a runtime OS could hold Y and
; forge a stage. Z replaces Y as the stage MAC and stage name root. It is born
; HERE, before ExitBootServices, from fresh entropy, and lives only in
; PaOSOwnerStageKey with attributes NV|BS (0x3): a runtime OS never sees it
; (runtime GetVariable hides it, runtime SetVariable refuses BS-only attrs).
;
; owner_stage_key_preebs (boot/header, after system_secret_preebs, BEFORE
; owner_store_preebs and EBS):
;   1. reads PaOSOwnerStageKey. Exactly ours (attrs NV|BS, 64 B, magic, version,
;      size, CRC, an acceptable key): Z is loaded (LOADED);
;   2. anything else under the name (an RT-visible plant, a wrong size, a torn
;      or degenerate copy) is DELETED, never trusted (flags bit 2), and a new Z
;      is born. One the firmware will not delete leaves NO Z this boot (STUCK);
;   3. birth (Z1): EFI_RNG_PROTOCOL GetRNG with the default algorithm, and
;      RDSEED (else RDRAND) with a bounded carry retry (10 per word each).
;      Each source's 32 bytes are refused when a word is 0 or all ones or any
;      two words repeat (the
;      known all-ones RDRAND failure); accepted sources are XORed, so either
;      alone suffices and neither alone decides. Never Y, the TSC or any value
;      a runtime OS can see. No accepted source: NO_ENTROPY, no Z;
;   4. a new Z is written NV|BS and read back byte-exact before first use
;      (BORN); any firmware error leaves no Z (FAILED);
;   5. reports one marker line with the step's TSC delta.
; Without Z the owner store derives no stage name and judges no stage (UNNAMED):
; no stage is accepted and the local password authority stays RT (Z1 residual).
;
; Z leaves this module only as HKDF output (owner_stage_key_hkdf). In S1b-2c-0
; owner_store is its only user and discards it before EBS; the c-2a writer will
; keep it after EBS (srcreview Z5: X then holds it in RAM).
;
; Residuals: pre-EBS code (a UEFI shell, any db-trusted loader) and an SPI dump
; read and can rewrite Z, as for Y and the owner record itself. An NVRAM reset
; deletes Z: the next boot makes a new one, and a stage MACed under the old Z
; is refused (the owner re-stages).
; ============================================================================

OSK_NONE          equ 0                 ; not run: no runtime services
OSK_LOADED        equ 1                 ; our PaOSOwnerStageKey was valid
OSK_BORN          equ 2                 ; made this boot, stored NV|BS, read back exact
OSK_FAILED        equ 3                 ; a firmware error: no Z this boot
OSK_NO_ENTROPY    equ 4                 ; no source gave acceptable bytes: no Z this boot
OSK_STUCK         equ 5                 ; a variable not ours holds the name and will not delete: no Z

OSK_FL_RNG        equ 1                 ; EFI_RNG_PROTOCOL contributed to a new Z
OSK_FL_CPU        equ 2                 ; RDSEED/RDRAND contributed to a new Z
OSK_FL_REPLACED   equ 4                 ; something not ours under the name was deleted
OSK_FL_RNG_BAD    equ 8                 ; the RNG protocol was present but failed or gave refused bytes
OSK_FL_CPU_BAD    equ 16                ; the CPU source was absent, failed or gave refused bytes

OSK_ATTRS         equ 0x00000003        ; NV | BOOTSERVICE_ACCESS, never RUNTIME_ACCESS
OSK_MAGIC         equ 0x315A4F50        ; "POZ1"
OSK_VERSION       equ 1
OSK_SIZE          equ 64
OSK_OFF_MAGIC     equ 0
OSK_OFF_VERSION   equ 4
OSK_OFF_SIZE      equ 6
OSK_OFF_KEY       equ 16
OSK_OFF_CRC       equ 60                ; CRC32 (pbm_crc32) over [0, 60)
OSK_EFI_NOT_FOUND        equ 0x800000000000000E
OSK_EFI_BUFFER_TOO_SMALL equ 0x8000000000000005
OSK_RT_GETVAR     equ 0x48
OSK_BS_LOCATE     equ 0x140             ; EFI_BOOT_SERVICES.LocateProtocol
OSK_CPU_RETRIES   equ 10                ; per word and instruction (SDM: 10 for RDRAND): bounded under the pre-EBS watchdog

%if OSK_OFF_KEY + 32 > OSK_OFF_CRC || OSK_OFF_CRC + 4 != OSK_SIZE
    %error owner_stage_key_layout_mismatch
%endif

; owner_stage_key_preebs — PRE-EBS only (boot services and the firmware's
;   runtime services live). No return value: the outcome is osk_state and
;   osk_flags. Preserves the callee-saved registers.
owner_stage_key_preebs:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    and  rsp, -16
    sub  rsp, 48
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  r14, rax
    mov  byte [rel osk_state], OSK_NONE
    mov  byte [rel osk_flags], 0
    call owner_stage_key_discard
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .report
    ; ---- 1. our copy ----
    mov  qword [rel osk_io_size], OSK_SIZE
    mov  dword [rel osk_io_attrs], 0
    lea  rcx, [rel osk_name]
    lea  rdx, [rel prin_record_guid]
    lea  r8, [rel osk_io_attrs]
    lea  r9, [rel osk_io_size]
    lea  rax, [rel osk_blob]
    mov  [rsp + 32], rax
    call [r12 + OSK_RT_GETVAR]
    test rax, rax
    jz   .found
    mov  rdx, OSK_EFI_NOT_FOUND
    cmp  rax, rdx
    je   .birth
    mov  rdx, OSK_EFI_BUFFER_TOO_SMALL
    cmp  rax, rdx
    je   .replace                       ; oversized: not ours
    jmp  .failed                        ; a device error decides nothing
.found:
    cmp  dword [rel osk_io_attrs], OSK_ATTRS
    jne  .replace                       ; RT-visible (or otherwise foreign): never trusted
    cmp  qword [rel osk_io_size], OSK_SIZE
    jne  .replace
    lea  rdi, [rel osk_blob]
    call osk_blob_valid
    test eax, eax
    jz   .replace
    lea  rsi, [rel osk_blob + OSK_OFF_KEY]
    call osk_take_key
    mov  byte [rel osk_state], OSK_LOADED
    jmp  .wipe
    ; ---- 2. not ours: delete, then a new Z ----
.replace:
    or   byte [rel osk_flags], OSK_FL_REPLACED
    call osk_delete
    test eax, eax
    jz   .birth
    mov  byte [rel osk_state], OSK_STUCK
    jmp  .wipe
    ; ---- 3./4. birth ----
.birth:
    cld
    lea  rdi, [rel osk_blob]
    xor  eax, eax
    mov  ecx, OSK_SIZE
    rep  stosb
    lea  rdi, [rel osk_blob + OSK_OFF_KEY]
    call osk_gather
    test eax, eax
    jz   .no_entropy
    mov  dword [rel osk_blob + OSK_OFF_MAGIC], OSK_MAGIC
    mov  word [rel osk_blob + OSK_OFF_VERSION], OSK_VERSION
    mov  word [rel osk_blob + OSK_OFF_SIZE], OSK_SIZE
    lea  rdi, [rel osk_blob]
    mov  esi, OSK_OFF_CRC
    call pbm_crc32
    mov  [rel osk_blob + OSK_OFF_CRC], eax
    call osk_write
    test eax, eax
    jnz  .failed
    ; byte-exact read-back with exactly our attributes before first use
    mov  qword [rel osk_io_size], OSK_SIZE
    mov  dword [rel osk_io_attrs], 0
    lea  rcx, [rel osk_name]
    lea  rdx, [rel prin_record_guid]
    lea  r8, [rel osk_io_attrs]
    lea  r9, [rel osk_io_size]
    lea  rax, [rel osk_verify]
    mov  [rsp + 32], rax
    call [r12 + OSK_RT_GETVAR]
    test rax, rax
    jnz  .failed
    cmp  dword [rel osk_io_attrs], OSK_ATTRS
    jne  .failed
    cmp  qword [rel osk_io_size], OSK_SIZE
    jne  .failed
    lea  rsi, [rel osk_blob]
    lea  rdi, [rel osk_verify]
    mov  ecx, OSK_SIZE
    cld
    repe cmpsb
    jne  .failed
    lea  rsi, [rel osk_blob + OSK_OFF_KEY]
    call osk_take_key
    mov  byte [rel osk_state], OSK_BORN
    jmp  .wipe
.no_entropy:
    mov  byte [rel osk_state], OSK_NO_ENTROPY
    jmp  .wipe
.failed:
    mov  byte [rel osk_state], OSK_FAILED
    call owner_stage_key_discard
.wipe:
    ; the read, write and entropy buffers held Z: only osk_key keeps it
    cld
    xor  eax, eax
    lea  rdi, [rel osk_blob]
    mov  ecx, OSK_SIZE
    rep  stosb
    lea  rdi, [rel osk_verify]
    mov  ecx, OSK_SIZE
    rep  stosb
    lea  rdi, [rel osk_tmp]
    mov  ecx, 32
    rep  stosb
.report:
    lea  rdi, [rel str_osk_state]
    call serial_string
    movzx edi, byte [rel osk_state]
    call serial_hex64
    lea  rdi, [rel str_osk_flags]
    call serial_string
    movzx edi, byte [rel osk_flags]
    call serial_hex64
    lea  rdi, [rel str_osk_tsc]
    call serial_string
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, r14
    mov  rdi, rax
    call serial_hex64
    lea  rdi, [rel str_osk_marker]
    call serial_string
    lea  rsp, [rbp - 32]
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; osk_take_key(RSI = 32 bytes) — copies Z into osk_key and marks it ready.
osk_take_key:
    cld
    lea  rdi, [rel osk_key]
    mov  ecx, 32
    rep  movsb
    mov  byte [rel osk_key_ready], 1
    ret

; osk_blob_valid(RDI = 64-byte copy) -> EAX 1 when magic, version, size, CRC
;   are exactly ours and the key passes osk_quality.
osk_blob_valid:
    push rbx
    mov  rbx, rdi
    xor  eax, eax
    cmp  dword [rbx + OSK_OFF_MAGIC], OSK_MAGIC
    jne  .out
    cmp  word [rbx + OSK_OFF_VERSION], OSK_VERSION
    jne  .out
    cmp  word [rbx + OSK_OFF_SIZE], OSK_SIZE
    jne  .out
    mov  esi, OSK_OFF_CRC
    call pbm_crc32
    cmp  eax, [rbx + OSK_OFF_CRC]
    jne  .bad
    lea  rdi, [rbx + OSK_OFF_KEY]
    call osk_quality
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  rbx
    ret

; osk_quality(RDI = 32 bytes) -> EAX 1 when no 8-byte word is 0 or all ones and
;   no two words are equal (Z1). Clobbers RCX, RDX, R8-R10.
osk_quality:
    xor  eax, eax
    mov  r8, [rdi]
    mov  r9, [rdi + 8]
    mov  r10, [rdi + 16]
    mov  rdx, [rdi + 24]
    cmp  r8, r9
    je   .out
    cmp  r8, r10
    je   .out
    cmp  r8, rdx
    je   .out
    cmp  r9, r10
    je   .out
    cmp  r9, rdx
    je   .out
    cmp  r10, rdx
    je   .out
    xor  ecx, ecx
.word:
    mov  rdx, [rdi + rcx*8]
    test rdx, rdx
    jz   .out
    cmp  rdx, -1
    je   .out
    inc  ecx
    cmp  ecx, 4
    jb   .word
    mov  eax, 1
.out:
    xor  edx, edx
    xor  r8d, r8d
    xor  r9d, r9d
    xor  r10d, r10d
    ret

; osk_gather(RDI = 32 zeroed bytes) -> EAX 1 and the bytes = the XOR of every
;   accepted source, or EAX 0 and the bytes zeroed. Sets the source bits of
;   osk_flags. Preserves the callee-saved registers.
osk_gather:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    and  rsp, -16
    sub  rsp, 48
    mov  rbx, rdi
    xor  r13d, r13d                     ; the sources that contributed
    ; ---- EFI_RNG_PROTOCOL, the default algorithm ----
    mov  rax, [rel boot_services]
    test rax, rax
    jz   .cpu
    mov  qword [rel osk_rng], 0
    lea  rcx, [rel osk_rng_guid]
    xor  edx, edx                       ; Registration = NULL
    lea  r8, [rel osk_rng]
    call [rax + OSK_BS_LOCATE]
    test rax, rax
    jnz  .cpu                           ; no RNG protocol: the CPU source may still serve
    mov  rcx, [rel osk_rng]
    test rcx, rcx
    jz   .cpu
    xor  edx, edx                       ; RNGAlgorithm = NULL: the default
    mov  r8d, 32
    lea  r9, [rel osk_tmp]
    call [rcx + 8]                      ; EFI_RNG_PROTOCOL.GetRNG
    test rax, rax
    jnz  .rng_bad
    lea  rdi, [rel osk_tmp]
    call osk_quality
    test eax, eax
    jz   .rng_bad
    call osk_mix
    or   r13d, OSK_FL_RNG
    jmp  .cpu
.rng_bad:
    or   byte [rel osk_flags], OSK_FL_RNG_BAD
    ; ---- RDSEED / RDRAND ----
.cpu:
    call osk_wipe_tmp
    lea  rdi, [rel osk_tmp]
    call osk_cpu_entropy
    test eax, eax
    jnz  .cpu_bad
    lea  rdi, [rel osk_tmp]
    call osk_quality
    test eax, eax
    jz   .cpu_bad
    call osk_mix
    or   r13d, OSK_FL_CPU
    jmp  .judge
.cpu_bad:
    or   byte [rel osk_flags], OSK_FL_CPU_BAD
.judge:
    call osk_wipe_tmp
    or   [rel osk_flags], r13b
    xor  eax, eax
    test r13d, r13d
    jz   .none
    mov  rdi, rbx
    call osk_quality                    ; the XOR itself must pass too
    test eax, eax
    jnz  .out
.none:
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, 32
    call memset
    xor  eax, eax
.out:
    lea  rsp, [rbp - 24]
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; osk_mix — XOR osk_tmp into the 32 bytes at RBX (osk_gather's destination). Clobbers RAX, RCX, RDX.
osk_mix:
    lea  rdx, [rel osk_tmp]             ; [rel X + rcx*8] is not RIP-relative: base first
    xor  ecx, ecx
.word:
    mov  rax, [rdx + rcx*8]
    xor  [rbx + rcx*8], rax
    inc  ecx
    cmp  ecx, 4
    jb   .word
    xor  eax, eax
    ret

; osk_wipe_tmp — zeroes osk_tmp. Preserves every register but flags.
osk_wipe_tmp:
    push rdi
    push rcx
    push rax
    cld
    lea  rdi, [rel osk_tmp]
    xor  eax, eax
    mov  ecx, 32
    rep  stosb
    pop  rax
    pop  rcx
    pop  rdi
    ret

; osk_cpu_entropy(RDI = 32 bytes) -> EAX 0 and four words from RDSEED (else
;   RDRAND), each with a bounded carry retry; EAX -1 and the bytes zeroed when
;   neither instruction exists or a word cannot be had. The one CPU seam: host
;   rows script it. Preserves the callee-saved registers.
osk_cpu_entropy:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    xor  r13d, r13d                     ; bit 0 RDRAND, bit 1 RDSEED
    xor  eax, eax
    cpuid
    mov  r8d, eax
    cmp  r8d, 1
    jb   .fail
    mov  eax, 1
    cpuid
    bt   ecx, 30
    jnc  .no_rdrand
    or   r13d, 1
.no_rdrand:
    cmp  r8d, 7
    jb   .have
    mov  eax, 7
    xor  ecx, ecx
    cpuid
    bt   ebx, 18
    jnc  .have
    or   r13d, 2
.have:
    test r13d, r13d
    jz   .fail
    xor  r9d, r9d                       ; byte offset
.word:
    test r13d, 2
    jz   .rdrand
    mov  ecx, OSK_CPU_RETRIES
.seed:
    rdseed rax
    jc   .got
    pause
    dec  ecx
    jnz  .seed
.rdrand:
    test r13d, 1
    jz   .fail
    mov  ecx, OSK_CPU_RETRIES
.rand:
    rdrand rax
    jc   .got
    pause
    dec  ecx
    jnz  .rand
    jmp  .fail
.got:
    mov  [r12 + r9], rax
    add  r9d, 8
    cmp  r9d, 32
    jb   .word
    xor  eax, eax
    jmp  .out
.fail:
    xor  eax, eax
    mov  [r12], rax
    mov  [r12 + 8], rax
    mov  [r12 + 16], rax
    mov  [r12 + 24], rax
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; osk_write -> EAX 0 when the firmware stored osk_blob as PaOSOwnerStageKey
;   (NV|BS). PaOS-namespace GUID: the storage gate's NORMAL class.
osk_write:
    push rbp
    mov  rbp, rsp
    push r12
    and  rsp, -16
    sub  rsp, 48
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .bad
    lea  rdi, [rel prin_record_guid]
    lea  rsi, [rel osk_name]
    xor  edx, edx                       ; SA_INTENT_IMPLICIT: PaOS-namespace -> NORMAL
    lea  rcx, [rel str_osk_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    lea  rcx, [rel osk_name]
    lea  rdx, [rel prin_record_guid]
    mov  r8d, OSK_ATTRS
    mov  r9d, OSK_SIZE
    lea  rax, [rel osk_blob]
    mov  [rsp + 32], rax
    call [r12 + 0x58]                   ; SetVariable (literal: test_nvram_setvariable_sites scans it)
    test rax, rax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    lea  rsp, [rbp - 8]
    pop  r12
    pop  rbp
    ret

; osk_delete -> EAX 0 when the variable under our name is gone (DataSize 0
;   deletes whatever attributes it had; pre-EBS that includes an RT-visible one).
osk_delete:
    push rbp
    mov  rbp, rsp
    push r12
    and  rsp, -16
    sub  rsp, 48
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .bad
    lea  rdi, [rel prin_record_guid]
    lea  rsi, [rel osk_name]
    xor  edx, edx
    lea  rcx, [rel str_osk_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    lea  rcx, [rel osk_name]
    lea  rdx, [rel prin_record_guid]
    xor  r8d, r8d
    xor  r9d, r9d
    mov  qword [rsp + 32], 0
    call [r12 + 0x58]                   ; SetVariable (literal: test_nvram_setvariable_sites scans it)
    test rax, rax
    jz   .ok
    mov  rdx, OSK_EFI_NOT_FOUND
    cmp  rax, rdx
    jne  .bad
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    lea  rsp, [rbp - 8]
    pop  r12
    pop  rbp
    ret

; owner_stage_key_hkdf(RDI = info, ESI = info length, RDX = 32-byte destination)
;   -> EAX 1 and destination = HKDF-SHA256(IKM = Z, no salt, info) while this
;   boot holds Z (pre-EBS: sec/owner_store's stage key and stage names).
;   EAX 0 with the destination zeroed otherwise. Z itself never leaves here.
owner_stage_key_hkdf:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    and  rsp, -16
    sub  rsp, 16
    mov  rbx, rdx
    cmp  byte [rel osk_key_ready], 1
    jne  .none
    mov  r8, rdi
    mov  r9d, esi
    lea  rdi, [rel osk_key]
    mov  esi, 32
    xor  edx, edx
    xor  ecx, ecx
    mov  [rsp], rbx
    mov  qword [rsp + 8], 32
    call hkdf_sha256_derive
    test rax, rax
    jnz  .none
    mov  eax, 1
    jmp  .out
.none:
    mov  rdi, rbx                       ; a failed derive leaves no partial key
    xor  esi, esi
    mov  edx, 32
    call memset
    xor  eax, eax
.out:
    lea  rsp, [rbp - 16]
    pop  r12
    pop  rbx
    pop  rbp
    ret

; owner_stage_key_discard — wipes Z (owner_store_preebs calls it when its pass
;   ends; S1b-2c-0 has no user after EBS). Preserves every register but flags.
owner_stage_key_discard:
    push rdi
    push rcx
    push rax
    cld
    lea  rdi, [rel osk_key]
    xor  eax, eax
    mov  ecx, 32
    rep  stosb
    mov  byte [rel osk_key_ready], 0
    pop  rax
    pop  rcx
    pop  rdi
    ret

%include "core/abi/wdata.inc" ; WDATA_BSS_DEFER; standalone assemblies expand blocks in place
; Zero-initialised state with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER):
; owner_stage_key_preebs sets every field at entry, and its consumers key on
; osk_key_ready (0 = no Z), so the zero image value is never trusted.
%macro WDATA_BSS_sec_owner_stage_key 0
alignb 8
osk_io_size:      resq 1
osk_rng:          resq 1                ; the located EFI_RNG_PROTOCOL interface (pre-EBS only)
osk_io_attrs:     resd 1
osk_state:        resb 1
osk_flags:        resb 1
osk_key_ready:    resb 1                ; osk_key holds Z this boot
alignb 16
osk_key:          resb 32               ; Z from pre-EBS until owner_store's pass ends (reset_wipe covers it)
osk_blob:         resb OSK_SIZE         ; PaOSOwnerStageKey image (holds Z while in use)
osk_verify:       resb OSK_SIZE         ; its read-back
osk_tmp:          resb 32               ; one source's entropy before it is mixed
%endmacro
WDATA_BSS_DEFER WDATA_BSS_sec_owner_stage_key
align 4, db 0
osk_rng_guid:                           ; EFI_RNG_PROTOCOL_GUID 3152bca5-eade-433d-862e-c01cdc291f44
    dd 0x3152BCA5
    dw 0xEADE, 0x433D
    db 0x86,0x2E,0xC0,0x1C,0xDC,0x29,0x1F,0x44
align 2, db 0                           ; CHAR16 variable names (char16_align_check)
osk_name:
    dw 'P','a','O','S','O','w','n','e','r','S','t','a','g','e','K','e','y',0
str_osk_nvg_tag:  db "owner_stage_key_preebs",0
str_osk_state:    db "[PAOS64] owner stage key: state=",0
str_osk_flags:    db " flags=",0
str_osk_tsc:      db " tsc=",0
str_osk_marker:   db " [sec.osk.preebs]",13,10,0
