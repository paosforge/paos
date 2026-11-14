;; MODULE core/csprng
;; LAYER 1
;; EXPORTS csprng_selftest, csprng_service_init, csprng_generate, csprng_reseed, csprng_source_fault_once, csprng_status_snapshot
;; IMPORTS core/lib/hmac_sha256, core/lib/mem, core/lock, boot/serial
;; CAPS
;; OWNER saga:crypto
;; LOCK: csprng_lock PROTECTS csprng_k, csprng_v, csprng_health, csprng_initialized, csprng_kat_ok, csprng_reseed_counter, csprng_entropy_last, csprng_entropy_last_valid, csprng_source_fault_injected, csprng_source_failures, csprng_entropy, csprng_tmp, csprng_update_input, csprng_kat_output
; ============================================================================
; The one keep-owned cryptographic random-byte service (contract 1236).
;
; Construction: HMAC_DRBG with SHA-256, SP 800-90A Rev.1 section 10.1.2.
; K and V are private to this module. RDSEED/RDRAND occur only in the bounded,
; health-tested provider below. Provider failure degrades the service and all
; Generate calls fail closed after wiping the caller's requested output span.
; Only a successful provider-backed reseed restores READY.
;
; The deterministic KAT is NIST CAVP HMAC_DRBG SHA-256 COUNT=0,
; PredictionResistance=False, EntropyInputLen=256, NonceLen=128,
; ReturnedBitsLen=1024, with no personalization or additional input. CAVP
; reseeds once, then invokes Generate twice; ReturnedBits are from the second
; invocation. The reseed step is part of the published COUNT=0 transcript.
; ============================================================================

CSPRNG_READY       equ 1
CSPRNG_DEGRADED    equ 2
CSPRNG_SEED_BYTES  equ 48
CSPRNG_MAX_REQUEST equ 1024
CSPRNG_MAX_RESEED  equ 0x0000FFFFFFFFFFFF
CSPRNG_UPD_MAX     equ 64

; Named wrappers make the declared lock site mechanically auditable while all
; lock mechanics remain in the one canonical core/lock primitive.
csprng_lock_acquire:
    lea  rdi, [rel csprng_lock]
    call spin_acquire
    ret

csprng_lock_release:
    lea  rdi, [rel csprng_lock]
    call spin_release
    ret

; csprng_drbg_update(RDI=provided_data, RSI=len<=64), caller holds lock.
; SP 800-90A 10.1.2.2: K=HMAC(K,V||sep||data), V=HMAC(K,V), with a
; second sep=1 round iff provided_data is non-empty.
csprng_drbg_update:
    push rbx
    push r12
    push r13
    cld
    mov  r12, rdi
    mov  r13, rsi
    cmp  r13, CSPRNG_UPD_MAX
    ja   .fail
    xor  ebx, ebx
.round:
    lea  rdi, [rel csprng_update_input]
    lea  rsi, [rel csprng_v]
    mov  ecx, 32
    rep  movsb
    mov  byte [rdi], bl
    inc  rdi
    test r13, r13
    jz   .input_ready
    mov  rsi, r12
    mov  rcx, r13
    rep  movsb
.input_ready:
    lea  rdi, [rel csprng_tmp]
    lea  rsi, [rel csprng_k]
    mov  edx, 32
    lea  rcx, [rel csprng_update_input]
    lea  r8, [r13 + 33]
    call hmac_sha256
    test rax, rax
    jnz  .fail
    lea  rdi, [rel csprng_k]
    lea  rsi, [rel csprng_tmp]
    mov  ecx, 32
    rep  movsb

    lea  rdi, [rel csprng_tmp]
    lea  rsi, [rel csprng_k]
    mov  edx, 32
    lea  rcx, [rel csprng_v]
    mov  r8d, 32
    call hmac_sha256
    test rax, rax
    jnz  .fail
    lea  rdi, [rel csprng_v]
    lea  rsi, [rel csprng_tmp]
    mov  ecx, 32
    rep  movsb

    test r13, r13
    jz   .ok
    test bl, bl
    jnz  .ok
    mov  bl, 1
    jmp  .round
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; csprng_drbg_instantiate(RDI=seed_material,RSI=len), caller holds lock.
csprng_drbg_instantiate:
    push r12
    push r13
    cld
    mov  r12, rdi
    mov  r13, rsi
    lea  rdi, [rel csprng_k]
    xor  eax, eax
    mov  ecx, 4
    rep  stosq
    lea  rdi, [rel csprng_v]
    mov  rax, 0x0101010101010101
    mov  ecx, 4
    rep  stosq
    mov  rdi, r12
    mov  rsi, r13
    call csprng_drbg_update
    pop  r13
    pop  r12
    ret

; csprng_drbg_generate(RDI=out,RSI=len), caller holds lock.
csprng_drbg_generate:
    push rbx
    push r12
    push r13
    push r14
    cld
    mov  r12, rdi
    mov  r13, rsi
.block:
    test r13, r13
    jz   .update
    lea  rdi, [rel csprng_tmp]
    lea  rsi, [rel csprng_k]
    mov  edx, 32
    lea  rcx, [rel csprng_v]
    mov  r8d, 32
    call hmac_sha256
    test rax, rax
    jnz  .fail
    lea  rdi, [rel csprng_v]
    lea  rsi, [rel csprng_tmp]
    mov  ecx, 32
    rep  movsb
    mov  r14, r13
    cmp  r14, 32
    jbe  .copy
    mov  r14d, 32
.copy:
    mov  rdi, r12
    lea  rsi, [rel csprng_v]
    mov  rcx, r14
    rep  movsb
    add  r12, r14
    sub  r13, r14
    jmp  .block
.update:
    xor  edi, edi
    xor  esi, esi
    call csprng_drbg_update
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; csprng_entropy_get(RDI=out,RSI=len), internal provider only, lock held.
; Returns 0/-1. Every failure wipes the destination and degrades health.
csprng_entropy_get:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cld
    mov  r12, rdi
    mov  r13, rsi
    mov  r10, rdi
    mov  r11, rsi
    test r12, r12
    jz   .fail_no_wipe
    test r13, r13
    jz   .fail
    test r13, 7
    jnz  .fail
    cmp  byte [rel csprng_source_fault_injected], 1
    jne  .discover
    mov  byte [rel csprng_source_fault_injected], 0
    jmp  .fail

.discover:
    xor  r14d, r14d                       ; bit0 RDRAND, bit1 RDSEED
    xor  eax, eax
    cpuid
    mov  r15d, eax
    cmp  r15d, 1
    jb   .fail
    mov  eax, 1
    cpuid
    bt   ecx, 30
    jnc  .no_rdrand
    or   r14d, 1
.no_rdrand:
    cmp  r15d, 7
    jb   .features_done
    mov  eax, 7
    xor  ecx, ecx
    cpuid
    bt   ebx, 18
    jnc  .features_done
    or   r14d, 2
.features_done:
    test r14d, r14d
    jz   .fail

.word:
    test r13, r13
    jz   .success
    mov  ecx, 64
.retry:
    test r14d, 2
    jz   .try_rdrand
    rdseed rax
    jc   .sample
    jmp  .retry_next
.try_rdrand:
    rdrand rax
    jc   .sample
.retry_next:
    dec  ecx
    jnz  .retry
    jmp  .fail
.sample:
    cmp  byte [rel csprng_entropy_last_valid], 1
    jne  .store
    cmp  rax, [rel csprng_entropy_last]
    je   .fail
.store:
    mov  [rel csprng_entropy_last], rax
    mov  byte [rel csprng_entropy_last_valid], 1
    mov  [r12], rax
    add  r12, 8
    sub  r13, 8
    jmp  .word
.success:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rdi, r10
    mov  rcx, r11
    xor  eax, eax
    rep  stosb
.fail_no_wipe:
    inc  qword [rel csprng_source_failures]
    mov  byte [rel csprng_health], CSPRNG_DEGRADED
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

csprng_wipe_entropy:
    lea  rdi, [rel csprng_entropy]
    xor  eax, eax
    mov  ecx, CSPRNG_SEED_BYTES
    rep  stosb
    ret

; Initialize the live service exclusively from the health-tested provider.
csprng_service_init:
    call csprng_lock_acquire
    cmp  byte [rel csprng_kat_ok], 1
    jne  .failed
    lea  rdi, [rel csprng_entropy]
    mov  esi, CSPRNG_SEED_BYTES
    call csprng_entropy_get
    test rax, rax
    jnz  .failed
    lea  rdi, [rel csprng_entropy]
    mov  esi, CSPRNG_SEED_BYTES
    call csprng_drbg_instantiate
    test rax, rax
    jnz  .failed
    mov  qword [rel csprng_reseed_counter], 1
    mov  byte [rel csprng_initialized], 1
    mov  byte [rel csprng_health], CSPRNG_READY
    call csprng_wipe_entropy
    call csprng_lock_release
    lea  rdi, [rel str_csprng_ready]
    call serial_string
    xor  eax, eax
    ret
.failed:
    call csprng_wipe_entropy
    mov  byte [rel csprng_initialized], 0
    mov  byte [rel csprng_health], CSPRNG_DEGRADED
    call csprng_lock_release
    lea  rdi, [rel str_csprng_degraded]
    call serial_string
    mov  eax, -1
    ret

; csprng_generate(RDI=out,RSI=len) -> 0/-1.
csprng_generate:
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    test r12, r12
    jz   .invalid
    test r13, r13
    jz   .invalid
    cmp  r13, CSPRNG_MAX_REQUEST
    ja   .invalid
    call csprng_lock_acquire
    cmp  byte [rel csprng_initialized], 1
    jne  .refuse
    cmp  byte [rel csprng_health], CSPRNG_READY
    jne  .refuse
    mov  rax, [rel csprng_reseed_counter]
    mov  rcx, CSPRNG_MAX_RESEED
    cmp  rax, rcx
    ja   .refuse_degrade
    mov  rdi, r12
    mov  rsi, r13
    call csprng_drbg_generate
    test rax, rax
    jnz  .refuse_degrade
    inc  qword [rel csprng_reseed_counter]
    call csprng_lock_release
    xor  eax, eax
    jmp  .out
.refuse_degrade:
    mov  byte [rel csprng_health], CSPRNG_DEGRADED
.refuse:
    mov  rdi, r12
    mov  rcx, r13
    xor  eax, eax
    rep  stosb
    call csprng_lock_release
.invalid:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    ret

; Fresh provider entropy is mandatory on every reseed.
csprng_reseed:
    call csprng_lock_acquire
    cmp  byte [rel csprng_kat_ok], 1
    jne  .fail
    lea  rdi, [rel csprng_entropy]
    mov  esi, CSPRNG_SEED_BYTES
    call csprng_entropy_get
    test rax, rax
    jnz  .fail
    cmp  byte [rel csprng_initialized], 1
    jne  .instantiate
    lea  rdi, [rel csprng_entropy]
    mov  esi, CSPRNG_SEED_BYTES
    call csprng_drbg_update
    jmp  .checked
.instantiate:
    lea  rdi, [rel csprng_entropy]
    mov  esi, CSPRNG_SEED_BYTES
    call csprng_drbg_instantiate
.checked:
    test rax, rax
    jnz  .fail
    mov  qword [rel csprng_reseed_counter], 1
    mov  byte [rel csprng_initialized], 1
    mov  byte [rel csprng_health], CSPRNG_READY
    call csprng_wipe_entropy
    call csprng_lock_release
    xor  eax, eax
    ret
.fail:
    call csprng_wipe_entropy
    mov  byte [rel csprng_health], CSPRNG_DEGRADED
    call csprng_lock_release
    mov  eax, -1
    ret

; Force the real provider failure branch. The injection is one-shot but the
; resulting degraded health persists until provider-backed reseed succeeds.
csprng_source_fault_once:
    call csprng_lock_acquire
    mov  byte [rel csprng_source_fault_injected], 1
    lea  rdi, [rel csprng_entropy]
    mov  esi, CSPRNG_SEED_BYTES
    call csprng_entropy_get               ; consumes injection via real fail path
    call csprng_wipe_entropy
    call csprng_lock_release
    mov  eax, -1                          ; injected provider failure was expected
    ret

; Atomic status snapshot: EAX=health, RDX=source failures, RCX=reseed counter,
; R8=initialized, R9=KAT status.
csprng_status_snapshot:
    call csprng_lock_acquire
    movzx eax, byte [rel csprng_health]
    mov  rdx, [rel csprng_source_failures]
    mov  rcx, [rel csprng_reseed_counter]
    movzx r8d, byte [rel csprng_initialized]
    movzx r9d, byte [rel csprng_kat_ok]
    call csprng_lock_release
    ret

; NIST CAVP deterministic KAT over the DRBG core, independent of live entropy.
csprng_selftest:
    call hmac_sha256_selftest
    test rax, rax
    jnz  .fail_unlocked
    call csprng_lock_acquire
    lea  rdi, [rel csprng_kat_seed]
    mov  esi, CSPRNG_SEED_BYTES
    call csprng_drbg_instantiate
    test rax, rax
    jnz  .fail_locked
    lea  rdi, [rel csprng_kat_reseed]
    mov  esi, 32
    call csprng_drbg_update              ; CAVP EntropyInputReseed, no addl input
    test rax, rax
    jnz  .fail_locked
    lea  rdi, [rel csprng_kat_output]
    mov  esi, 128
    call csprng_drbg_generate
    test rax, rax
    jnz  .fail_locked
    lea  rdi, [rel csprng_kat_output]
    mov  esi, 128
    call csprng_drbg_generate
    test rax, rax
    jnz  .fail_locked
    lea  rdi, [rel csprng_kat_output]
    lea  rsi, [rel csprng_kat_expected]
    mov  edx, 128
    call memcmp
    test rax, rax
    jnz  .fail_locked
    mov  byte [rel csprng_kat_ok], 1
    call csprng_lock_release
    lea  rdi, [rel str_csprng_kat_vector]
    call serial_string
    lea  rdi, [rel str_csprng_kat_ok]
    call serial_string
    xor  eax, eax
    ret
.fail_locked:
    mov  byte [rel csprng_kat_ok], 0
    call csprng_lock_release
.fail_unlocked:
    lea  rdi, [rel str_csprng_kat_fail]
    call serial_string
    mov  eax, -1
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_core_csprng_0 0
align 16
csprng_lock:                  db 0
csprng_health:                db 0
csprng_initialized:           db 0
csprng_kat_ok:                db 0
csprng_source_fault_injected: db 0
csprng_entropy_last_valid:    db 0
align 8
csprng_reseed_counter:        dq 0
csprng_source_failures:       dq 0
csprng_entropy_last:          dq 0
align 16
csprng_k:            times 32 db 0
csprng_v:            times 32 db 0
csprng_tmp:          times 32 db 0
csprng_entropy:      times CSPRNG_SEED_BYTES db 0
csprng_update_input: times (33 + CSPRNG_UPD_MAX) db 0
csprng_kat_output:  times 128 db 0

; NIST CAVP HMAC_DRBG SHA-256 COUNT=0 seed_material = EntropyInput || Nonce.
csprng_kat_seed:
    db 0x06,0x03,0x2c,0xd5,0xee,0xd3,0x3f,0x39
    db 0x26,0x5f,0x49,0xec,0xb1,0x42,0xc5,0x11
    db 0xda,0x9a,0xff,0x2a,0xf7,0x12,0x03,0xbf
    db 0xfa,0xf3,0x4a,0x9c,0xa5,0xbd,0x9c,0x0d
    db 0x0e,0x66,0xf7,0x1e,0xdc,0x43,0xe4,0x2a
    db 0x45,0xad,0x3c,0x6f,0xc6,0xcd,0xc4,0xdf
; EntropyInputReseed from the same NIST CAVP COUNT=0 transcript.
csprng_kat_reseed:
    db 0x01,0x92,0x0a,0x4e,0x66,0x9e,0xd3,0xa8
    db 0x5a,0xe8,0xa3,0x3b,0x35,0xa7,0x4a,0xd7
    db 0xfb,0x2a,0x6b,0xb4,0xcf,0x39,0x5c,0xe0
    db 0x03,0x34,0xa9,0xc9,0xa5,0xa5,0xd5,0x52
csprng_kat_expected:
    db 0x76,0xfc,0x79,0xfe,0x9b,0x50,0xbe,0xcc
    db 0xc9,0x91,0xa1,0x1b,0x56,0x35,0x78,0x3a
    db 0x83,0x53,0x6a,0xdd,0x03,0xc1,0x57,0xfb
    db 0x30,0x64,0x5e,0x61,0x1c,0x28,0x98,0xbb
    db 0x2b,0x1b,0xc2,0x15,0x00,0x02,0x09,0x20
    db 0x8c,0xd5,0x06,0xcb,0x28,0xda,0x2a,0x51
    db 0xbd,0xb0,0x38,0x26,0xaa,0xf2,0xbd,0x23
    db 0x35,0xd5,0x76,0xd5,0x19,0x16,0x08,0x42
    db 0xe7,0x15,0x8a,0xd0,0x94,0x9d,0x1a,0x9e
    db 0xc3,0xe6,0x6e,0xa1,0xb1,0xa0,0x64,0xb0
    db 0x05,0xde,0x91,0x4e,0xac,0x2e,0x9d,0x4f
    db 0x2d,0x72,0xa8,0x61,0x6a,0x80,0x22,0x54
    db 0x22,0x91,0x82,0x50,0xff,0x66,0xa4,0x1b
    db 0xd2,0xf8,0x64,0xa6,0xa3,0x8c,0xc5,0xb6
    db 0x49,0x9d,0xc4,0x3f,0x7f,0x2b,0xd0,0x9e
    db 0x1e,0x0f,0x8f,0x58,0x85,0x93,0x51,0x24

str_csprng_kat_vector: db "[PAOS64] P2 crypto: HMAC_DRBG NIST CAVP COUNT=0 returnedbits[0..1023]=76fc79fe9b50beccc991a11b5635783a83536add03c157fb30645e611c2898bb2b1bc215000209208cd506cb28da2a51bdb03826aaf2bd2335d576d519160842e7158ad0949d1a9ec3e66ea1b1a064b005de914eac2e9d4f2d72a8616a80225422918250ff66a41bd2f864a6a38cc5b6499dc43f7f2bd09e1e0f8f5885935124",13,10,0
str_csprng_kat_ok:     db "[PAOS64] P2 crypto: CSPRNG published KAT PASS [crypto.csprng.kat]",13,10,0
str_csprng_kat_fail:   db "[PAOS64] P2 crypto: CSPRNG published KAT FAIL (marker withheld)",13,10,0
str_csprng_ready:      db "[PAOS64] P2 crypto: keep CSPRNG service ready [crypto.csprng.ready]",13,10,0
str_csprng_degraded:   db "[PAOS64] P2 crypto: keep CSPRNG service DEGRADED (entropy provider refused)",13,10,0
%endmacro
WDATA_DEFER WDATA_core_csprng_0
