;; MODULE dev/snd/nullsnd
;; LAYER 3
;; EXPORTS nullsnd_create, nullsnd_create_fixture
;; IMPORTS snd/core, boot/serial
;; CAPS
;; OWNER saga:audio
; ============================================================================
; dev/snd/nullsnd.asm — the FAKE/discard sound backend, and by charter the
; REFERENCE implementation of the ABI-v2 snd_ops vtable (DRIVER_MODEL §7). BOTH
; (a) the QEMU-no-hardware regression target — always present, zero silicon —
; AND (b) the ops-contract documentation the hda backend must match byte-for-
; byte. Write the fake first; it defines the semantics (Task3201).
;
; It is a DISCARD / ACCOUNTING sink: submit() consumes bytes without touching
; any device, accounting exact frames = bytes / frame_bytes. It NEVER claims
; sample content (bit-exact PCM is a later real-backend task). A stream handle
; is core-owned and opaque: (backend_id<<32)|(generation<<16)|(slot+1). close()
; clears the slot so the old handle is stale; reopen() gets a fresh slot at
; frame 0. A handle whose backend_id/slot/generation does not resolve to a live
; slot is rejected (return -1) — that is stale/cross-backend rejection.
;
; The `call snd_register` is the ONE sanctioned L3->L4 upward edge (DRIVER_MODEL
; §5) — modlint whitelists it for dev/snd backends.
; ============================================================================

NULLSND_MAX_STREAMS  equ 4
NULLSND_BACKEND_A    equ 0xA1         ; primary backend id
NULLSND_BACKEND_B    equ 0xB2         ; lower-prio fixture backend id
NULLSND_SUPP_FORMATS equ SNDFMT_S16LE ; nullsnd accepts S16LE only (KAT)
NULLSND_S16_BYTES    equ 2            ; bytes per sample for S16LE
NULLSND_FIXTURE_PRIO equ 5            ; below PRIO_DOMAIN(10): loses selection to primary

struc nullsnd_stream
  .in_use:      resd 1
  .generation:  resd 1                ; unique per open (stale-handle discriminator)
  .frame_bytes: resd 1                ; channels * bytes/sample
  .state:       resd 1                ; SND_STATE_*
  .xruns:       resd 1
  .volume:      resd 1                ; q15
  .frames:      resq 1                ; accumulated frames
  .session:     resq 1                ; caller session_group envelope
endstruc

struc nullsnd_priv
  .backend_id:  resd 1
  .gen_next:    resd 1                ; monotonic generation source
  .streams:     resb nullsnd_stream_size * NULLSND_MAX_STREAMS
endstruc

; --- runtime vtable build (lea+mov: pointers MUST be runtime VAs; a static
;     `dq nullsnd_read` bakes the org-0 RVA, and the PE ImageBase is not applied
;     to baked dq symbols on the flat-bin load) -------------------------------
nullsnd_build_ops:
    push rbx
    lea  rbx, [rel nullsnd_ops]
    lea  rax, [rel nullsnd_open]
    mov  [rbx + snd_ops.open], rax
    lea  rax, [rel nullsnd_submit]
    mov  [rbx + snd_ops.submit], rax
    lea  rax, [rel nullsnd_position]
    mov  [rbx + snd_ops.position], rax
    lea  rax, [rel nullsnd_status]
    mov  [rbx + snd_ops.status], rax
    lea  rax, [rel nullsnd_set_volume]
    mov  [rbx + snd_ops.set_volume], rax
    lea  rax, [rel nullsnd_close]
    mov  [rbx + snd_ops.close], rax
    lea  rax, [rel nullsnd_recover]
    mov  [rbx + snd_ops.recover], rax
    pop  rbx
    ret

; nullsnd_resolve(RDI=self, RSI=handle) -> RAX = live stream ptr, or 0.
; Resolves the opaque handle by backend_id + slot + generation against the live
; slot table — never trusts the handle as a pointer. Clobbers RAX, R8, R9.
nullsnd_resolve:
    mov  r8, [rdi + dev.priv]
    ; backend id = (handle >> 32) & 0xFFFF
    mov  rax, rsi
    shr  rax, 32
    movzx eax, ax
    cmp  eax, [r8 + nullsnd_priv.backend_id]
    jne  .bad
    ; slot = (handle & 0xFFFF) - 1
    mov  eax, esi
    and  eax, 0xFFFF
    test eax, eax
    jz   .bad
    dec  eax
    cmp  eax, NULLSND_MAX_STREAMS
    jae  .bad
    imul eax, eax, nullsnd_stream_size
    lea  r9, [r8 + nullsnd_priv.streams]
    add  r9, rax                        ; r9 = stream
    cmp  dword [r9 + nullsnd_stream.in_use], 0
    je   .bad
    ; generation = (handle >> 16) & 0xFFFF
    mov  rax, rsi
    shr  rax, 16
    movzx eax, ax
    cmp  eax, [r9 + nullsnd_stream.generation]
    jne  .bad
    mov  rax, r9
    ret
.bad:
    xor  eax, eax
    ret

; nullsnd_open(self, RSI=snd_stream_params*, RDX=out_handle*) -> RAX 0/-1.
; Only S16LE is supported; any other format (or no free slot) returns -1.
nullsnd_open:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, [rdi + dev.priv]
    mov  r13, rsi                       ; params
    mov  r14, rdx                       ; out_handle
    ; format must be exactly the supported set
    mov  eax, [r13 + snd_stream_params.format]
    cmp  eax, NULLSND_SUPP_FORMATS
    jne  .fail
    mov  eax, [r13 + snd_stream_params.channels]
    test eax, eax
    jz   .fail
    ; find a free slot
    xor  ebx, ebx
.find:
    cmp  ebx, NULLSND_MAX_STREAMS
    jae  .fail
    mov  eax, ebx
    imul eax, eax, nullsnd_stream_size
    lea  r9, [r12 + nullsnd_priv.streams]
    add  r9, rax                        ; r9 = candidate stream
    cmp  dword [r9 + nullsnd_stream.in_use], 0
    je   .got
    inc  ebx
    jmp  .find
.got:
    ; frame_bytes = channels * bytes/sample
    mov  ecx, [r13 + snd_stream_params.channels]
    imul ecx, ecx, NULLSND_S16_BYTES    ; ecx = frame_bytes
    ; fresh generation
    mov  eax, [r12 + nullsnd_priv.gen_next]
    inc  eax
    mov  [r12 + nullsnd_priv.gen_next], eax
    mov  [r9 + nullsnd_stream.generation], eax
    mov  dword [r9 + nullsnd_stream.in_use], 1
    mov  [r9 + nullsnd_stream.frame_bytes], ecx
    mov  dword [r9 + nullsnd_stream.state], SND_STATE_RUNNING
    mov  dword [r9 + nullsnd_stream.xruns], 0
    mov  dword [r9 + nullsnd_stream.volume], 0x7FFF
    mov  qword [r9 + nullsnd_stream.frames], 0
    mov  rax, [r13 + snd_stream_params.session_group]
    mov  [r9 + nullsnd_stream.session], rax
    ; handle = (backend_id << 32) | (generation << 16) | (slot + 1)
    mov  eax, [r12 + nullsnd_priv.backend_id]
    shl  rax, 16
    mov  ecx, [r9 + nullsnd_stream.generation]
    or   rax, rcx
    shl  rax, 16
    lea  ecx, [rbx + 1]
    or   rax, rcx
    mov  [r14], rax                     ; *out_handle = handle
    xor  eax, eax                       ; RAX = 0 ok
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; nullsnd_submit(self, RSI=handle, RDX=buf, RCX=len) -> RAX bytes-accepted / -1.
; Discard sink: accepts the whole buffer, accounts frames = len / frame_bytes.
nullsnd_submit:
    push rcx                            ; len
    call nullsnd_resolve                ; RAX = stream or 0
    pop  rcx
    test rax, rax
    jz   .bad
    mov  r9, rax                        ; stream
    mov  r8d, [r9 + nullsnd_stream.frame_bytes]
    test r8d, r8d
    jz   .bad
    mov  rax, rcx                       ; len
    xor  edx, edx
    div  r8                             ; rax = len / frame_bytes
    add  [r9 + nullsnd_stream.frames], rax
    mov  rax, rcx                       ; return bytes-accepted = len
    ret
.bad:
    mov  rax, -1
    ret

; nullsnd_position(self, RSI=handle) -> RAX frames / -1.
nullsnd_position:
    call nullsnd_resolve
    test rax, rax
    jz   .bad
    mov  rax, [rax + nullsnd_stream.frames]
    ret
.bad:
    mov  rax, -1
    ret

; nullsnd_status(self, RSI=handle, RDX=snd_status*) -> RAX 0/-1.
; pts == frames for a discard sink (no device buffering latency modelled).
nullsnd_status:
    push rdx
    call nullsnd_resolve
    pop  rdx
    test rax, rax
    jz   .bad
    mov  r9, rax
    mov  rcx, [r9 + nullsnd_stream.frames]
    mov  [rdx + snd_status.frames], rcx
    mov  [rdx + snd_status.timestamp], rcx
    mov  ecx, [r9 + nullsnd_stream.state]
    mov  [rdx + snd_status.state], ecx
    mov  ecx, [r9 + nullsnd_stream.xruns]
    mov  [rdx + snd_status.xruns], ecx
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

; nullsnd_set_volume(self, RSI=handle, RDX=vol_q15) -> RAX 0/-1.
nullsnd_set_volume:
    push rdx
    call nullsnd_resolve
    pop  rdx
    test rax, rax
    jz   .bad
    mov  [rax + nullsnd_stream.volume], edx
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

; nullsnd_close(self, RSI=handle) -> RAX 0/-1. Clears the slot; the old handle
; is henceforth stale (in_use=0 fails resolve).
nullsnd_close:
    call nullsnd_resolve
    test rax, rax
    jz   .bad
    mov  dword [rax + nullsnd_stream.in_use], 0
    mov  dword [rax + nullsnd_stream.state], SND_STATE_CLOSED
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

; nullsnd_recover(self) -> RAX 0. Backend/controller-scoped; a discard sink is
; never wedged, so recovery is a successful no-op.
nullsnd_recover:
    xor  eax, eax
    ret

; nullsnd_create_one(RDI=dev, RSI=info, RDX=priv, RCX=name, R8D=prio,
;                    R9D=backend_id) -> RAX = REG_OK/REG_REJECT.
nullsnd_create_one:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  ebx, r8d                       ; prio
    mov  ebp, r9d                       ; backend id
    ; --- fill priv (streams array is zero-initialised in-image) ------------
    mov  dword [r14 + nullsnd_priv.backend_id], ebp
    mov  dword [r14 + nullsnd_priv.gen_next], 0
    ; --- fill snd_info -----------------------------------------------------
    mov  [r13 + snd_info.name], r15
    mov  dword [r13 + snd_info.formats], NULLSND_SUPP_FORMATS
    mov  dword [r13 + snd_info.max_chan], 2
    mov  dword [r13 + snd_info.rates], 0
    ; --- fill the uniform struct dev header --------------------------------
    lea  rax, [rel nullsnd_ops]
    mov  [r12 + dev.ops], rax
    mov  [r12 + dev.info], r13
    mov  [r12 + dev.priv], r14
    mov  dword [r12 + dev.prio], ebx
    mov  dword [r12 + dev.health], HEALTH_OK
    mov  dword [r12 + dev.class], CLASS_SOUND
    mov  dword [r12 + dev.flags], 0
    mov  qword [r12 + dev.next], 0
    mov  [r12 + dev.name], r15
    ; --- register (the sanctioned L3->L4 upward edge) ----------------------
    mov  rdi, r12
    call snd_register
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; nullsnd_create() -> RAX. Primary discard backend, PRIO_DOMAIN, HEALTH_OK.
nullsnd_create:
    call nullsnd_build_ops
    lea  rdi, [rel nullsnd_dev]
    lea  rsi, [rel nullsnd_info]
    lea  rdx, [rel nullsnd_privd]
    lea  rcx, [rel str_nullsnd_name]
    mov  r8d, PRIO_DOMAIN
    mov  r9d, NULLSND_BACKEND_A
    jmp  nullsnd_create_one

; nullsnd_create_fixture() -> RAX. A second, LOWER-prio healthy node so the KAT
; can prove select() returns the highest-prio node (prio-desc ordering).
nullsnd_create_fixture:
    call nullsnd_build_ops
    lea  rdi, [rel nullsnd_fx_dev]
    lea  rsi, [rel nullsnd_fx_info]
    lea  rdx, [rel nullsnd_fx_privd]
    lea  rcx, [rel str_nullfx_name]
    mov  r8d, NULLSND_FIXTURE_PRIO
    mov  r9d, NULLSND_BACKEND_B
    jmp  nullsnd_create_one

; --- nullsnd data (in-image writable; migrates to BSS under full W^X) --------
align 8
nullsnd_ops:      times snd_ops_size db 0        ; runtime-populated vtable (storage only)
nullsnd_dev:      times dev_size db 0
nullsnd_info:     times snd_info_size db 0
nullsnd_privd:    times nullsnd_priv_size db 0
nullsnd_fx_dev:   times dev_size db 0
nullsnd_fx_info:  times snd_info_size db 0
nullsnd_fx_privd: times nullsnd_priv_size db 0
str_nullsnd_name: db "nullsnd", 0
str_nullfx_name:  db "nullfx", 0
