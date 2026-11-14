;; MODULE sec/owner_record
;; LAYER 5
;; EXPORTS owner_record_validate, owner_record_select, owner_stage_validate, owner_change_needs_confirmation
;; IMPORTS boot/boot_v2_handoff, core/lib/sha256, core/lib/hmac_sha256, core/lib/mem
;; CAPS
;; OWNER saga:sec
;; CONTEXT: bsp_only
; Per-install owner S1 foundation: pure validation and policy, no firmware
; access here. sec/owner_store (S1b-1) is the pre-EBS caller; password
; migration and the runtime consumer follow in S1b-2. Root D5 (2026-10-09)
; requires typed firmware confirmation for remote-authority additions/replacements.
;
; A record is exactly 512 bytes, NV|BS. A stage is 608 bytes, NV|BS|RT,
; authenticated with the caller's domain-separated HKDF(Z) stage key. Neither
; a CRC nor a valid stage MAC grants permission to apply an authority change.
; Validation is separate from confirmation: owner_change_needs_confirmation
; (root D5, below, unwired) classifies a change; the apply transaction is S1b.

OWR_SIZE             equ 512
OWR_ATTRS            equ 3
OWR_MAGIC            equ 0x31574f50       ; POW1
OWR_VERSION          equ 1               ; a record whose LOCAL verifier predates the stage key Z
OWR_VERSION_Z        equ 2               ; S1b-2c-0 (root 11:25:44): any LOCAL verifier came from a Z-verified stage
OWR_GEN              equ 8               ; u64 LE, nonzero, never wraps
OWR_FLAGS            equ 16
OWR_LOCAL            equ 1
OWR_KEY              equ 2
OWR_FLEET            equ 4
OWR_FLOOR_SEEDED     equ 8               ; sec/replay_floor §9.4: PaOSReplayFloor existed when written
OWR_KNOWN_FLAGS      equ 15
OWR_SSH_GEN          equ 20              ; u32 LE HKDF identity generation
OWR_SUMMARY          equ 24              ; non-secret applied change kind 0..7
OWR_MODULUS          equ 32
OWR_KEY_ID           equ 288
OWR_ITERATIONS       equ 320
OWR_SALT             equ 324             ; 16 bytes
OWR_VERIFIER         equ 340             ; 32 bytes
OWR_PW_BLOCK_LEN     equ 52              ; ITERATIONS + SALT + VERIFIER
OWR_FLEET_BLOCK      equ 384             ; 124 bytes
OWR_DISK_LEN         equ 424
OWR_SYSTEM_LEN       equ 425
OWR_DISK_SERIAL      equ 428             ; cap40, zero-padded, no truncation
OWR_SYSTEM_SERIAL    equ 468             ; cap32, zero-padded, no truncation
OWR_CRC              equ 508

OWS_SIZE             equ 608
OWS_ATTRS            equ 7
OWS_MAGIC            equ 0x31545350       ; PST1
OWS_VERSION          equ 1
OWS_BASE_GEN         equ 8
OWS_NEW_GEN          equ 16
OWS_PREV_HASH        equ 24
OWS_KIND             equ 56              ; 1..7, apply policy is separate
OWS_KIND_LOCAL       equ 2               ; c2a LOCAL first setup/replace: D1 protected-field delta
OWS_BODY             equ 64
OWS_MAC              equ 576

%if OWR_ITERATIONS + OWR_PW_BLOCK_LEN != OWR_VERIFIER + 32
    %error owner_record_pw_block_mismatch
%endif
%if OWR_CRC + 4 != OWR_SIZE || OWS_BODY + OWR_SIZE != OWS_MAC || OWS_MAC + 32 != OWS_SIZE
    %error owner_record_layout_mismatch
%endif

; RDI=record, RSI=exact available size, EDX=firmware attributes -> EAX=0/-1.
; The bounded length and attributes are checked before the first record read.
owner_record_validate:
    push rbx
    push r12
    push r13
    sub rsp, 144                         ; digest32 + SHA256 stream context112
    mov r12, rdi
    test rdi, rdi
    jz .bad
    cmp rsi, OWR_SIZE
    jne .bad
    cmp edx, OWR_ATTRS
    jne .bad
    cmp dword [r12], OWR_MAGIC
    jne .bad
    cmp word [r12 + 4], OWR_VERSION
    je .version
    cmp word [r12 + 4], OWR_VERSION_Z    ; an image before S1b-2c-0 refuses it: fail-safe
    jne .bad
.version:
    cmp word [r12 + 6], OWR_SIZE
    jne .bad
    cmp qword [r12 + OWR_GEN], 0
    je .bad
    mov ebx, [r12 + OWR_FLAGS]
    test ebx, ~OWR_KNOWN_FLAGS
    jnz .bad
    cmp dword [r12 + OWR_SUMMARY], 7
    ja .bad
    cmp dword [r12 + 28], 0
    jne .bad
    lea rdi, [r12 + 372]
    mov ecx, 12
    call owner_zero_range
    test eax, eax
    jnz .bad
    mov rdi, r12
    mov esi, OWR_CRC
    call pbm_crc32
    cmp eax, [r12 + OWR_CRC]
    jne .bad

    test ebx, OWR_LOCAL
    jz .no_password
    cmp dword [r12 + OWR_ITERATIONS], 600000
    jne .bad
    lea rdi, [r12 + OWR_SALT]
    mov ecx, 16
    call owner_zero_range
    test eax, eax
    jz .bad
    lea rdi, [r12 + OWR_VERIFIER]
    mov ecx, 32
    call owner_zero_range
    test eax, eax
    jz .bad
    jmp .key
.no_password:
    lea rdi, [r12 + OWR_ITERATIONS]
    mov ecx, 64
    call owner_zero_range
    test eax, eax
    jnz .bad
.key:
    test ebx, OWR_KEY
    jz .no_key
    test byte [r12 + OWR_MODULUS], 0x80 ; 2048-bit, big-endian RSA modulus
    jz .bad
    test byte [r12 + OWR_MODULUS + 255], 1
    jz .bad
    ; Match boot_v2_manifest.key_id exactly: SHA256(DER SubjectPublicKeyInfo),
    ; RSA-2048 with exponent65537. Hash the canonical public DER in three parts;
    ; modulus-only hashes would drift from AUTH2 replay/enrollment fingerprints.
    lea rdi, [rsp + 32]
    call sha256_stream_init
    lea rdi, [rsp + 32]
    lea rsi, [rel owner_spki_prefix]
    mov edx, owner_spki_prefix_len
    call sha256_stream_update
    test eax, eax
    jnz .bad
    lea rdi, [rsp + 32]
    lea rsi, [r12 + OWR_MODULUS]
    mov edx, 256
    call sha256_stream_update
    test eax, eax
    jnz .bad
    lea rdi, [rsp + 32]
    lea rsi, [rel owner_spki_suffix]
    mov edx, owner_spki_suffix_len
    call sha256_stream_update
    test eax, eax
    jnz .bad
    lea rdi, [rsp + 32]
    mov rsi, rsp
    call sha256_stream_final
    test eax, eax
    jnz .bad
    mov rdi, rsp
    lea rsi, [r12 + OWR_KEY_ID]
    call owner_digest_diff
    test eax, eax
    jnz .bad
    jmp .fleet
.no_key:
    lea rdi, [r12 + OWR_MODULUS]
    mov ecx, 288
    call owner_zero_range
    test eax, eax
    jnz .bad
.fleet:
    test ebx, OWR_FLEET
    jz .no_fleet
    test ebx, OWR_KEY                   ; fleet cannot have an absent verifier
    jz .bad
    cmp dword [r12 + OWR_FLEET_BLOCK], 1 ; one current, explicit fleet profile
    jne .bad
    cmp word [r12 + 394], 0
    jne .bad
    cmp word [r12 + 426], 0
    jne .bad
    cmp qword [r12 + 500], 0
    jne .bad
    movzx ecx, byte [r12 + OWR_DISK_LEN]
    cmp ecx, 40
    ja .bad
    lea rdi, [r12 + OWR_DISK_SERIAL + rcx]
    neg ecx
    add ecx, 40
    call owner_zero_range
    test eax, eax
    jnz .bad
    movzx ecx, byte [r12 + OWR_SYSTEM_LEN]
    cmp ecx, 32
    ja .bad
    lea rdi, [r12 + OWR_SYSTEM_SERIAL + rcx]
    neg ecx
    add ecx, 32
    call owner_zero_range
    test eax, eax
    jnz .bad
    jmp .ok
.no_fleet:
    lea rdi, [r12 + OWR_FLEET_BLOCK]
    mov ecx, 124
    call owner_zero_range
    test eax, eax
    jnz .bad
.ok:
    xor r13d, r13d
    jmp .out
.bad:
    mov r13d, -1
.out:
    ; Local digest scratch is always cleared, including malformed-input exits.
    mov rdi, rsp
    xor esi, esi
    mov edx, 144
    call memset
    mov eax, r13d
    add rsp, 144
    pop r13
    pop r12
    pop rbx
    ret

; Two (pointer,length,attributes) triples in RDI/RSI/EDX and RCX/R8/R9D.
; Returns 0/1 for selected slot, -1 only for BOTH genuinely absent triples
; (NULL,0,0), -2 when no valid slot or equal-generation divergent records.
; A firmware read error must be handled before this API, never as absence.
owner_record_select:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 32
    mov r12, rdi
    mov r13, rcx
    mov [rsp], rsi
    mov [rsp + 8], edx
    mov [rsp + 16], r8
    mov [rsp + 24], r9d
    call owner_record_validate
    mov r14d, eax
    mov rdi, r13
    mov rsi, [rsp + 16]
    mov edx, [rsp + 24]
    call owner_record_validate
    test r14d, r14d
    jz .zero_valid
    test eax, eax
    jz .one
    mov eax, -2
    mov rdx, r12
    or rdx, r13
    or rdx, [rsp]
    or rdx, [rsp + 16]
    mov ecx, [rsp + 8]
    or ecx, [rsp + 24]
    or rdx, rcx
    jnz .out
    mov eax, -1
    jmp .out
.zero_valid:
    test eax, eax
    jnz .zero
    mov rax, [r12 + OWR_GEN]
    cmp rax, [r13 + OWR_GEN]
    ja .zero
    jb .one
    mov rdi, r12
    mov rsi, r13
    mov edx, OWR_SIZE
    call memcmp
    test eax, eax
    jz .zero
    mov eax, -2                         ; ambiguous equal-generation authority
    jmp .out
.zero:
    xor eax, eax
    jmp .out
.one:
    mov eax, 1
.out:
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI=stage, RSI=size, EDX=attrs, RCX=validated base, R8=base size,
; R9=32-byte derived stage key -> EAX=0/-1. NULL/0 base means genuine absence;
; caller must never map a corrupt/read-error estate to that representation.
; A valid result proves integrity/base lineage only, never permission to apply.
owner_stage_validate:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 64
    mov r12, rdi
    mov r13, rcx
    mov r14, r8
    mov r15, r9
    test rdi, rdi
    jz .bad
    test r15, r15
    jz .bad
    cmp rsi, OWS_SIZE
    jne .bad
    cmp edx, OWS_ATTRS
    jne .bad
    cmp dword [r12], OWS_MAGIC
    jne .bad
    cmp word [r12 + 4], OWS_VERSION
    jne .bad
    cmp word [r12 + 6], OWS_SIZE
    jne .bad
    cmp dword [r12 + OWS_KIND], 1
    jb .bad
    cmp dword [r12 + OWS_KIND], 7
    ja .bad
    cmp dword [r12 + 60], 0
    jne .bad
    test r13, r13
    jz .absent
    mov rdi, r13
    mov rsi, r14
    mov edx, OWR_ATTRS
    call owner_record_validate
    test eax, eax
    jnz .bad
    mov rbx, [r13 + OWR_GEN]
    mov rdi, rsp
    mov rsi, r13
    mov edx, OWR_SIZE
    call sha256_hash
    test eax, eax
    jnz .bad
    jmp .chain
.absent:
    test r14, r14
    jnz .bad
    xor ebx, ebx
    mov rdi, rsp
    lea rsi, [rel owner_absent_domain]
    mov edx, owner_absent_domain_len
    call sha256_hash
    test eax, eax
    jnz .bad
.chain:
    cmp rbx, [r12 + OWS_BASE_GEN]
    jne .bad
    add rbx, 1
    jc .bad                             ; no wrap to a fresh generation
    cmp rbx, [r12 + OWS_NEW_GEN]
    jne .bad
    cmp rbx, [r12 + OWS_BODY + OWR_GEN]
    jne .bad
    mov eax, [r12 + OWS_KIND]
    cmp eax, [r12 + OWS_BODY + OWR_SUMMARY]
    jne .bad
    mov rdi, rsp
    lea rsi, [r12 + OWS_PREV_HASH]
    call owner_digest_diff
    test eax, eax
    jnz .bad
    lea rdi, [r12 + OWS_BODY]
    mov esi, OWR_SIZE
    mov edx, OWR_ATTRS
    call owner_record_validate
    test eax, eax
    jnz .bad
    mov rdi, rsp
    mov rsi, r15
    mov edx, 32
    mov rcx, r12
    mov r8d, OWS_MAC
    call hmac_sha256
    test eax, eax
    jnz .bad
    mov rdi, rsp
    lea rsi, [r12 + OWS_MAC]
    call owner_digest_diff
    test eax, eax
    jnz .bad
    ; c2a D1: judge the LOCAL writer's delta against the REAL validated
    ; pre-EBS base, never the zeroed post-EBS public copy. A valid MAC is
    ; insufficient to change KEY, SSH identity, FLEET, serials or flags.
    cmp dword [r12 + OWS_KIND], OWS_KIND_LOCAL
    jne .valid
    mov rdi, r13
    lea rsi, [r12 + OWS_BODY]
    call owner_stage_local_delta
    test eax, eax
    jnz .delta_bad
.valid:
    xor ebx, ebx
    jmp .out
.delta_bad:
    mov ebx, -3                         ; stable protected-field-delta refusal
    jmp .out
.bad:
    mov ebx, -1
.out:
    mov rdi, rsp
    xor esi, esi
    mov edx, 64
    call memset
    mov eax, ebx
    add rsp, 64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; D1, called only after record, lineage and MAC validation. RDI=real base
; or genuine absence, RSI=validated LOCAL body. Version/CRC are canonicalized
; by the pre-EBS applier; gen/summary/header were already checked above.
; Only LOCAL flag and ITERATIONS/SALT/VERIFIER may change in the body.
owner_stage_local_delta:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
    test dword [r12 + OWR_FLAGS], OWR_LOCAL
    jz .bad                             ; this entry cannot remove LOCAL
    test rbx, rbx
    jz .absent
    mov eax, [rbx + OWR_FLAGS]
    xor eax, [r12 + OWR_FLAGS]
    test eax, ~OWR_LOCAL
    jnz .bad
    lea rdi, [rbx + OWR_SSH_GEN]
    lea rsi, [r12 + OWR_SSH_GEN]
    mov edx, 4
    call memcmp
    test eax, eax
    jnz .bad
    lea rdi, [rbx + 28]
    lea rsi, [r12 + 28]
    mov edx, OWR_ITERATIONS - 28         ; reserved header + KEY modulus/id
    call memcmp
    test eax, eax
    jnz .bad
    lea rdi, [rbx + 372]
    lea rsi, [r12 + 372]
    mov edx, OWR_CRC - 372              ; reserved tail + entire FLEET/serials
    call memcmp
    test eax, eax
    jnz .bad
    jmp .ok
.absent:
    cmp dword [r12 + OWR_FLAGS], OWR_LOCAL
    jne .bad
    cmp dword [r12 + OWR_SSH_GEN], 0
    jne .bad
    lea rdi, [r12 + 28]
    mov ecx, OWR_ITERATIONS - 28
    call owner_zero_range
    test eax, eax
    jnz .bad
    lea rdi, [r12 + 372]
    mov ecx, OWR_CRC - 372
    call owner_zero_range
    test eax, eax
    jnz .bad
.ok:
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    pop r12
    pop rbx
    ret

; Root D5 policy, still unwired. RDI=base512 (NULL only for proven absence),
; RSI=new512, both caller-owned bounded buffers -> EAX=-1 malformed, 0 no
; EXTRA firmware confirmation, 1 default-NO typed firmware ConIn required.
; A zero result does not authorize an operation: ordinary owner authentication,
; HUMAN keys AND pointer, stage MAC/lineage and transaction checks still apply.
; This compares actual authority content, never the stage's declared kind.
; KEY additions/replacements and any FLEET additions/replacements require1.
; Removing authority, LOCAL password changes and SSH generation changes do not
; add a ConIn prompt. An absent/corrupt firmware read is distinguished by the
; future caller; a corrupt base must NEVER be mapped to NULL.
owner_change_needs_confirmation:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    mov rdi, r13
    mov esi, OWR_SIZE
    mov edx, OWR_ATTRS
    call owner_record_validate
    test eax, eax
    jnz .bad
    xor ebx, ebx
    test r12, r12
    jz .key
    mov rdi, r12
    mov esi, OWR_SIZE
    mov edx, OWR_ATTRS
    call owner_record_validate
    test eax, eax
    jnz .bad
    mov ebx, [r12 + OWR_FLAGS]
.key:
    test dword [r13 + OWR_FLAGS], OWR_KEY
    jz .fleet
    test ebx, OWR_KEY
    jz .confirm
    lea rdi, [r12 + OWR_MODULUS]
    lea rsi, [r13 + OWR_MODULUS]
    mov edx, 256
    call memcmp
    test eax, eax
    jnz .confirm
.fleet:
    test dword [r13 + OWR_FLAGS], OWR_FLEET
    jz .no_extra
    test ebx, OWR_FLEET
    jz .confirm
    lea rdi, [r12 + OWR_FLEET_BLOCK]
    lea rsi, [r13 + OWR_FLEET_BLOCK]
    mov edx, OWR_CRC - OWR_FLEET_BLOCK
    call memcmp
    test eax, eax
    jnz .confirm
.no_extra:
    xor eax, eax
    jmp .out
.confirm:
    mov eax, 1
    jmp .out
.bad:
    mov eax, -1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Fixed-size digest comparison: all32 bytes are read regardless of mismatch.
owner_digest_diff:
    xor eax, eax
    xor ecx, ecx
.byte:
    mov dl, [rdi + rcx]
    xor dl, [rsi + rcx]
    or al, dl
    inc ecx
    cmp ecx, 32
    jb .byte
    ret

; OR reduction for reserved/absent-field canonicalization, bounded by constants
; or previously checked serial lengths. Returns zero exactly for an empty range.
owner_zero_range:
    xor eax, eax
    test ecx, ecx
    jz .out
.byte:
    or al, [rdi]
    inc rdi
    dec ecx
    jnz .byte
.out:
    ret

owner_absent_domain: db "PaOS/owner/absent/v1"
owner_absent_domain_len equ $ - owner_absent_domain
owner_spki_prefix:
    db 0x30,0x82,0x01,0x22,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48
    db 0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x82,0x01
    db 0x0f,0x00,0x30,0x82,0x01,0x0a,0x02,0x82,0x01,0x01,0x00
owner_spki_prefix_len equ $ - owner_spki_prefix
owner_spki_suffix: db 0x02,0x03,0x01,0x00,0x01
owner_spki_suffix_len equ $ - owner_spki_suffix
%if owner_spki_prefix_len + 256 + owner_spki_suffix_len != 294
    %error owner_spki_layout_mismatch
%endif
