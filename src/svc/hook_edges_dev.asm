;; MODULE svc/hook_edges_dev
;; LAYER 5
;; EXPORTS hook_uac_status_plan, hook_uac_status_post, hook_hda_plan, hook_hda_post, hook_dev_edges_declare, hook_usb_plan, hook_usb_post, hook_aer_plan, hook_aer_post, hook_pci_plan, hook_pci_post, hook_backlight_plan, hook_backlight_post, hook_session_plan, hook_power_plan, hook_power_post, hook_reinitinfo_plan, hook_reinitinfo_post, hook_dpower_plan, hook_dpower_post
;; IMPORTS svc/command_uac1_input_probe, svc/command_uac1_capture, svc/command_hda_loopback, core/build_id, core/lib/fmt, svc/command, svc/command_hook, svc/command_auth, svc/command_usb, svc/resilience, svc/command_pci_mmio, sec/session, dev/power/ec_power, svc/command_reinit, svc/command_wav_playback, dev/snd/hda_loopback_native
;; CAPS
;; OWNER saga:command
; ============================================================================
; svc/hook_edges_dev.asm -- RCQ-15 slice 3: device, power and session HOOK edges.
;
;   uac  (device)   owner saved input/capture scalar status; no PCM or IO
;   audio      (device)   owner HDA saved diagnostics (explicit epoch/row)
;   usb        (device)   the enumerated USB devices   native USBLIST / USBDESC <slot> / USBPORTS
;   aer        (device)   PCIe error capture           native AERLOG last / PCIECTO status
;   pci        (device)   one live page of PCI functions; explicit cursor 0..65536
;   backlight  (power)    the panel backlight          native BACKLIGHT [pct]
;   session    (session)  the console session          native SESSIONINFO <nonce>
;   reinitinfo (device)  declared driver metadata     native REINITINFO (no driver IO)
;   dpower     (device)  passive RAM/loopnet lifecycle native DPOWER status 0
;   power      (power)    battery and AC observation   native STATUS + owner envelope
;
; As in slices 1 and 2, an edge only PLANS a native verb and argument;
; svc/command_hook dispatches it with the caller's own source, principal,
; capability and idempotency key, so the native gate decides. Nothing here
; lowers a native class: BACKLIGHT is registered destructive as a whole, so a
; hook READ of the level needs the same authority as the native read form
; (BACKLIGHT with no argument), and the hook says so in its schema.
;
; OBSERVE is planned as GET by svc/command_hook (the witness is over the GET
; reply), so a planner sees only LIST, GET, SET, INPUT and CANCEL.
; Typed rules the edges add (stricter only):
;   * usb: GET usb:<slot> takes canonical decimal 1..16; GET usb ports is the
;     root-hub PORTSC dump; LIST/GET usb are the device list;
;   * aer: GET aer is the last captured record, GET aer cto the completion
;     timeout configuration; the injects (AERINJECT, PCIECTOINJECT) are not typed;
;   * pci: LIST/GET pci[:cursor] returns one 24-row live page, default 0;
;     OBSERVE labels and witnesses only that page. PCICFG_SAFE (a BAR
;     write, even a same-value one) and MMIOCAP (an access-proof primitive
;     that moves a counter) are not typed;
;   * backlight: GET reads the level; SET takes exactly 0..100
;     (decimal, no sign, at most 3 digits). The native reports the PWM duty
;     (device units, not percent) in RSP_VAL only, and its SET programs
;     duty = clamp(max * pct / 100, min, max); so a post stages
;     "pct=<p> duty=<d> max=<m>": p is the nearest whole percent of duty/max
;     (it reads back as the SET pct whenever the clamp did not apply and max is
;     at least 198), or "na" when the PWM is unusable or max is 0;
;   * session: GET is SESSIONINFO (locked, principal id, key_handle
;     bound|none, restore and workspace fields; no credential is in that reply);
;     SESSIONLOCK/UNLOCK, SLEEP and the boot rail are not typed.
;   * power: owner-envelope-only GET/OBSERVE of the native battery/AC software
;     groups. STATUS runs through normal dispatch first; the post applies the
;     SAME command_auth_owner_envelope as UDP STATUS before even reading backend
;     availability. Local/internal/AI/injected frames gain no envelope authority.
;     No new registry verb, ticket, EC IO, sample/refresh job or power mutation.
;     The existing ecp_status_format revalidates age/clock and projects coherent
;     BSP-serialized published groups; reads can retire stale software validity.
;     Only battery/AC fields are copied. Ages are since last successful groups;
;     failures keep timestamps but invalidate values, never cached-as-current.
;     Clock loss makes age unknown; validity stays retired until real sampling.
;     Unsupported backends have explicit unknown values/unsupported freshness.
;     The keyed witness excludes age and attempt times: same state at a later
;     time or repeated read/attempt is stable; value/validity/backend changes move
;     it. Default GET keeps that battery/AC schema. Explicit lid/button selectors
;     read a passive native saved-software snapshot, with unknown age; counters
;     do not infer physical state or resulting power actions. No PWM escapes.
; REINITINFO is declaration metadata, never runtime liveness or recovery proof.
; Only its read-only native handler is planned; no REINIT/CANARY/WORK route.
; The complete bounded publication is validated before copying; fresh staging
; is required and retired after both success and refusal. BSP command dispatch
; serializes this shared buffer exactly as for the existing device edges.
; Every unsupported op answers "hook na". PCISCAN and SESSIONINFO take a
; request nonce; the edge supplies it from one module-wide counter shared by
; the pci and session edges (a correlation token, never authority; it starts
; at 1 each boot). PCISCAN binds it in the one-use native argument stage
; without echoing it in the page; SESSIONINFO echoes it as " nonce=<n>"
; in its reply, so a GET session shows how many pci + session hook reads ran
; since boot, and the session OBSERVE witness is keyed (the nonce is not a
; key) so it hashes only the observed state.
; Identities: usb, usb:<slot>, aer, pci:<cursor>, backlight, session, power, reinitinfo.
; ============================================================================

HDE_SLOT_DIGITS_MAX equ 2
HDE_PCT_MAX         equ 100
HDE_PCT_DIGITS_MAX  equ 3

; hook_dev_edges_declare -- bind the device descriptors (lea at init, ESSENCE S10)
;   and register them after the slice-2 edges. clobbers: caller-saved.
hook_dev_edges_declare:
    push rbx
    lea  rbx, [rel hook_edge_audio]
    lea  rax, [rel str_hhd_audio]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hde_kind_device]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hhd_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_hda_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_hda_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0 ; complete validated typed diagnostic
    mov  rdi, rbx
    call command_hook_edge_register

    ; Separate descriptor preserves the existing audio diagnostic schema.
    lea  rbx, [rel hook_edge_uac_status]
    lea  rax, [rel huas_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hde_kind_device]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel huas_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_uac_status_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_uac_status_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0 ; every selected scalar field and selector
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_usb]
    lea  rax, [rel str_hde_usb]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hde_kind_device]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hde_usb_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_usb_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_usb_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0      ; the whole listing
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_aer]
    lea  rax, [rel str_hde_aer]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hde_kind_device]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hde_aer_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_aer_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_aer_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0      ; the whole record
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_pci]
    lea  rax, [rel str_hde_pci]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hde_kind_device]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hde_pci_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_pci_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_pci_post]
    mov  [rbx + HE_POST], rax
    lea  rax, [rel pci_mmio_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel pci_mmio_out_ready]
    mov  [rbx + HE_OREADY], rax
    mov  qword [rbx + HE_WITNESS], 0      ; the complete validated live page; no nonce in its native body
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_backlight]
    lea  rax, [rel str_hde_backlight]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hde_kind_power]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hde_backlight_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_backlight_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_backlight_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0         ; the native verb stages no text; the post does
    mov  qword [rbx + HE_OREADY], 0
    lea  rax, [rel str_hde_backlight_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_session]
    lea  rax, [rel str_hde_session]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hde_kind_session]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hde_session_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_session_plan]
    mov  [rbx + HE_PLAN], rax
    mov  qword [rbx + HE_POST], 0
    lea  rax, [rel session_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel session_out_ready]
    mov  [rbx + HE_OREADY], rax
    lea  rax, [rel str_hde_session_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_power]
    lea  rax, [rel str_hde_power]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hde_kind_power]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hde_power_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_power_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_power_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    lea  rax, [rel str_hde_power_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register
    lea  rbx, [rel hook_edge_reinitinfo]
    lea  rax, [rel str_hde_reinitinfo]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hde_kind_device]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hde_reinitinfo_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_reinitinfo_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_reinitinfo_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    lea  rax, [rel str_hde_reinitinfo_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register
    lea  rbx, [rel hook_edge_dpower]
    lea  rax, [rel str_hde_dpower]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hde_kind_device]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hde_dpower_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_dpower_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_dpower_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0      ; every complete software status field
    mov  rdi, rbx
    call command_hook_edge_register
    pop  rbx
    ret

; hde_arg_nonce -- append the edge's next 16-hex request nonce to the planned
;   argument. clobbers: caller-saved
hde_arg_nonce:
    mov  rdi, [rel hde_nonce_ctr]
    inc  rdi
    mov  [rel hde_nonce_ctr], rdi
    lea  rsi, [rel hde_nonce_buf]
    mov  edx, 16
    call fmt_hex
    lea  rdi, [rel hde_nonce_buf]
    jmp  command_hook_arg_str

; hde_read_op(EDI op) -> EAX 1 for LIST or GET (the read ops), else 0
hde_read_op:
    xor  eax, eax
    cmp  edi, HOP_LIST
    je   .yes
    cmp  edi, HOP_GET
    jne  .out
.yes:
    mov  eax, 1
.out:
    ret

; ---------------------------------------------------------------------------
; usb edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   LIST|GET usb                  USBLIST
;   GET usb ports                 USBPORTS
;   GET usb:<slot>                USBDESC <slot>      (canonical 1..16)
; ---------------------------------------------------------------------------
hook_usb_plan:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12, rsi
    mov  r13, rdx
    call hus_retire
    call hde_read_op
    test eax, eax
    jz   .na
    cmp  byte [r12], 0
    jne  .slot
    cmp  byte [r13], 0
    je   .list
    cmp  ebx, HOP_GET
    jne  .bad
    mov  rdi, r13
    lea  rsi, [rel str_hde_word_ports]
    call command_hook_word_eq
    test eax, eax
    jz   .bad
    call command_hook_arg_reset           ; USBPORTS takes no argument
    mov byte [rel hus_pending], 3
    lea  rax, [rel str_hde_verb_usbports]
    jmp  .out
.list:
    call command_hook_arg_reset           ; USBLIST takes no argument
    mov byte [rel hus_pending], 1
    lea  rax, [rel str_hde_verb_usblist]
    jmp  .out
.slot:
    cmp  ebx, HOP_GET
    jne  .bad
    cmp  byte [r13], 0
    jne  .bad
    cmp byte [r12], '0'
    je .bad
    xor r8d,r8d
    xor  ecx, ecx
.digit:
    movzx eax, byte [r12 + rcx]
    test eax, eax
    jz   .digits_end
    cmp  ecx, HDE_SLOT_DIGITS_MAX
    jae  .bad
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    ja   .bad
    sub al,'0'
    movzx eax,al
    imul r8d,r8d,10
    add r8d,eax
    inc  ecx
    jmp  .digit
.digits_end:
    cmp r8d,16
    ja .bad
    mov [rel hus_slot],r8d
    mov byte [rel hus_pending],2
    call command_hook_arg_reset
    mov  rdi, r12
    call command_hook_arg_str
    lea  rax, [rel str_hde_verb_usbdesc]
    jmp  .out
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; aer edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   GET aer                       AERLOG last
;   GET aer cto                   PCIECTO status
; ---------------------------------------------------------------------------
hook_aer_plan:
    push rbx
    push r12
    mov  ebx, edi
    mov  r12, rdx
    cmp  ebx, HOP_GET
    jne  .na                              ; one record, nothing to enumerate
    cmp  byte [rsi], 0
    jne  .bad                             ; one instance
    cmp  byte [r12], 0
    je   .log
    cmp  ebx, HOP_GET
    jne  .bad
    mov  rdi, r12
    lea  rsi, [rel str_hde_word_cto]
    call command_hook_word_eq
    test eax, eax
    jz   .bad
    call command_hook_arg_reset
    lea  rdi, [rel str_hde_arg_status]
    call command_hook_arg_str
    mov  byte [rel har_pending], 2
    call har_retire_selected
    lea  rax, [rel str_hde_verb_pciecto]
    jmp  .out
.log:
    call command_hook_arg_reset
    lea  rdi, [rel str_hde_arg_last]
    call command_hook_arg_str
    mov  byte [rel har_pending], 1
    call har_retire_selected
    lea  rax, [rel str_hde_verb_aerlog]
    jmp  .out
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; pci edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   LIST|GET pci[:cursor]        PCISCAN <fresh-nonce> PAGE <0..65536>
; ---------------------------------------------------------------------------
hook_pci_plan:
    push rbx
    push r12
    mov  r12, rsi
    mov  rbx, rdx
    call hpc_retire
    call hde_read_op
    test eax, eax
    jz   .na
    cmp  byte [rbx], 0
    jne  .bad
    mov  qword [rel hpc_cursor], 0
    cmp  byte [r12], 0
    je   .parsed
    mov  rdi, r12
    call hpc_dec
    test eax, eax
    jz   .bad
    cmp  byte [rdi], 0
    jne  .bad
    mov  [rel hpc_cursor], rdx
.parsed:
    call command_hook_arg_reset
    call hde_arg_nonce
    lea  rdi, [rel str_hpc_page]
    call command_hook_arg_str
    mov  rdi, [rel hpc_cursor]
    call command_hook_arg_dec
    lea  rdi, [rel str_hpc_zero]
    call command_hook_default_instance
    mov  byte [rel hpc_pending], 1
    lea  rax, [rel str_hde_verb_pciscan]
    jmp  .out
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; backlight edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   GET backlight                 BACKLIGHT              (destructive class kept: the native read form)
;   SET backlight <0..100>        BACKLIGHT <pct>
; ---------------------------------------------------------------------------
hook_backlight_plan:
    push rbx
    push r12
    mov  ebx, edi
    mov  r12, rdx
    cmp  byte [rsi], 0
    jne  .bad                             ; one instance: the panel
    cmp  ebx, HOP_GET
    je   .read
    cmp  ebx, HOP_SET
    je   .set
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    jmp  .out
.read:
    cmp  byte [r12], 0
    jne  .bad
    call command_hook_arg_reset           ; no argument: the native read form
    lea  rax, [rel str_hde_verb_backlight]
    jmp  .out
.set:
    mov  rdi, r12
    call command_hook_parse_dec           ; RAX value, RDX digit count
    test edx, edx
    jz   .bad
    cmp  edx, HDE_PCT_DIGITS_MAX
    ja   .bad
    cmp  byte [r12 + rdx], 0
    jne  .bad                             ; digits only, nothing after them
    cmp  rax, HDE_PCT_MAX
    ja   .bad
    mov  rbx, rax
    call command_hook_arg_reset
    mov  rdi, rbx
    call command_hook_arg_dec             ; canonical decimal (no leading zeros)
    lea  rax, [rel str_hde_verb_backlight]
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; hook_backlight_post(EDI op, RSI inst, RDX rest, RCX rsp) -> EAX 1 = "pct=<p> duty=<d> max=<m>" staged
;   The native verb reports the PWM duty only in RSP_VAL; a refusal passes through.
;   p = (duty * 100 + max / 2) / max, the nearest whole percent; "na" when the
;   PWM is not usable or max is 0 (never a #DE, as in ecp_status_format).
hook_backlight_post:
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .none
    push rbx
    push r12
    sub  rsp, 8
    mov  rbx, [rcx + RSP_VAL]             ; the duty, in device units
    mov  r12d, [rel ecp_bl_max]
    call command_hook_out_reset
    lea  rdi, [rel str_hde_pct]
    call command_hook_out_str
    cmp  byte [rel ecp_bl_ok], 1
    jne  .pct_na
    test r12d, r12d
    jz   .pct_na
    imul rax, rbx, 100
    mov  rdx, r12
    shr  rdx, 1
    add  rax, rdx
    xor  edx, edx
    div  r12
    mov  rdi, rax
    call command_hook_out_dec
    jmp  .duty
.pct_na:
    lea  rdi, [rel str_hde_na]
    call command_hook_out_str
.duty:
    lea  rdi, [rel str_hde_duty]
    call command_hook_out_str
    mov  rdi, rbx
    call command_hook_out_dec
    lea  rdi, [rel str_hde_max]
    call command_hook_out_str
    mov  rdi, r12
    call command_hook_out_dec
    add  rsp, 8
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.none:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; session edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   GET session                   SESSIONINFO <nonce>
; ---------------------------------------------------------------------------
hook_session_plan:
    cmp  edi, HOP_GET
    je   .read
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.read:
    cmp  byte [rsi], 0
    jne  .bad                             ; one instance: the console session
    cmp  byte [rdx], 0
    jne  .bad
    call command_hook_arg_reset
    call hde_arg_nonce
    lea  rax, [rel str_hde_verb_sessioninfo]
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; power: GET only (OBSERVE is planned as GET). Default battery/AC snapshot;
; exact lid/button subselectors are passive saved observations. No instance
; and no native job selector: STATUS(0) is plain liveness.
hook_power_plan:
    mov  byte [rel hlb_pending], 0
    lea  rax, [rel str_hde_power_witness]
    mov  [rel hook_edge_power + HE_WITNESS], rax
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad                             ; one coherent battery/AC observation
    cmp  byte [rdx], 0
    je   .native
    cmp  dword [rdx], 'lid'
    je   .lid
    cmp  dword [rdx], 'butt'
    jne  .bad
    cmp  word [rdx + 4], 'on'
    jne  .bad
    cmp  byte [rdx + 6], 0
    jne  .bad
    mov  byte [rel hlb_pending], 2
    jmp  .selected
.lid:
    mov  byte [rel hlb_pending], 1
.selected:
    mov  qword [rel hook_edge_power + HE_WITNESS], 0 ; whole finite saved observation
.native:
    call command_hook_arg_reset
    lea  rax, [rel str_hde_verb_status]
    ret
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

HDE_POWER_RAW_MAX equ 512                 ; native ECP_LINE_MAX, pinned by host control
; Post only after successful native dispatch. The local stack snapshot is bounded
; and cleared on both success/error. Native projection has no EC IO; it shares
; the existing BSP command/idle-loop serialization, never an AP/IRQ entry point.
hook_power_post:
    cmp  byte [rel hlb_pending], 0
    jne  hook_lid_button_post
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .none                            ; native/session refusal stays authoritative
    push rbx
    push r12
    push r13
    mov  rbx, rcx
    call command_auth_owner_envelope
    test eax, eax
    jz   .denied
    call command_hook_out_reset
    cmp  byte [rel ecp_active], 1
    jne  .unsupported
    sub  rsp, HDE_POWER_RAW_MAX
    mov  r12, rsp
    mov  rdi, r12
    mov  esi, HDE_POWER_RAW_MAX
    call ecp_status_format
    test rax, rax
    jz   .bad_reply
    cmp  rax, HDE_POWER_RAW_MAX
    jae  .bad_reply
    cmp  byte [r12 + rax], 0
    jne  .bad_reply
    lea  rdi, [rel str_hde_power_head]
    call command_hook_out_str
    lea  r13, [rel str_hde_power_keys]
.field:
    mov  rdi, r12
    mov  rsi, r13
    call hde_power_field
    test rax, rax
    jz   .bad_reply                       ; refuse incomplete native schema, no partial success
    mov  rdi, rax
    mov  esi, ecx
    call command_hook_out_strn
.next_key:
    inc  r13
    cmp  byte [r13 - 1], 0
    jne  .next_key
    cmp  byte [r13], 0
    jne  .field
.clear:
    mov  rdi, r12
    xor  esi, esi
    mov  edx, HDE_POWER_RAW_MAX
    call memset
    add  rsp, HDE_POWER_RAW_MAX
    jmp  .staged
.bad_reply:
    call command_hook_out_reset
    lea  rdi, [rel str_hde_power_bad_reply]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    lea  rax, [rel str_hde_power_bad_reply]
    mov  [rbx + RSP_HINT], rax
    jmp  .clear
.unsupported:
    lea  rdi, [rel str_hde_power_unsupported]
    call command_hook_out_str
    jmp  .staged
.denied:
    call command_hook_out_reset
    lea  rdi, [rel str_hde_power_denied]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_AUTHDENY
    lea  rax, [rel str_hde_power_denied]
    mov  [rbx + RSP_HINT], rax
.staged:
    pop  r13
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.none:
    xor  eax, eax
    ret

; Owned local snapshot and full admitted request are captured once. Native
; STATUS admission is authoritative; envelope precedes even backend disclosure.
; No asynchronous producer/ready flag: lifetime is this serialized post call.
hook_lid_button_post:
    movzx eax, byte [rel hlb_pending]
    mov  byte [rel hlb_pending], 0          ; retire on every outcome
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .none                            ; native STATUS refusal stays authoritative
    push rbx
    push r12
    push r13
    mov  rbx, rcx
    mov  r13d, eax
    call command_auth_owner_envelope
    cmp  eax, 1
    jne  .denied
    sub  rsp, 128                         ; 64 snapshot + REQ_SZ(56) + padding
    mov  r12, rsp
    lea  rdi, [r12 + 64]
    call command_hook_request_copy
    mov  rdi, r12
    mov  esi, 64
    mov  edx, r13d
    call ecp_lid_button_snapshot
    cmp  rax, 64
    jne  .bad
    lea  rdi, [r12 + 64]
    call command_hook_request_matches
    cmp  eax, 1
    jne  .bad
    cmp  qword [r12], 0x31424c
    jne  .bad
    cmp  [r12 + 8], r13
    jne  .bad
    cmp  qword [r12 + 16], 1
    ja   .bad
    cmp  qword [r12 + 24], 1
    ja   .bad
    cmp  qword [r12 + 48], 0
    jne  .bad
    cmp  qword [r12 + 56], 0
    jne  .bad
    mov  rax, [r12 + 40]
    shr  rax, 32
    jnz  .bad
    cmp  qword [r12 + 16], 0
    jne  .backend_ok
    cmp  qword [r12 + 24], 0
    jne  .bad
.backend_ok:
    cmp  qword [r12 + 24], 1
    je   .supported
    cmp  qword [r12 + 32], 255
    jne  .bad
    cmp  qword [r12 + 40], 0
    jne  .bad
    jmp  .valid
.supported:
    cmp  r13d, 2
    je   .button_value
    cmp  qword [r12 + 32], 1
    jbe  .valid
.button_value:
    cmp  qword [r12 + 32], 255
    jne  .bad
.valid:
    call command_hook_out_reset
    lea  rdi, [rel str_hlb_lid]
    cmp  r13d, 1
    je   .head
    lea  rdi, [rel str_hlb_button]
.head:
    call command_hook_out_str
    lea  rdi, [rel str_hlb_ec]
    cmp  qword [r12 + 16], 1
    je   .backend
    lea  rdi, [rel str_hlb_unsupported_backend]
.backend:
    call command_hook_out_str
    lea  rdi, [rel str_hlb_support]
    call command_hook_out_str
    mov  rdi, [r12 + 24]
    call command_hook_out_dec
    cmp  r13d, 2
    je   .presses
    lea  rdi, [rel str_hlb_state]
    call command_hook_out_str
    lea  rdi, [rel str_hlb_unknown]
    cmp  qword [r12 + 24], 1
    jne  .state
    cmp  qword [r12 + 32], 255
    je   .state
    lea  rdi, [rel str_hlb_closed]
    cmp  qword [r12 + 32], 0
    je   .state
    lea  rdi, [rel str_hlb_open]
.state:
    call command_hook_out_str
    lea  rdi, [rel str_hlb_events]
    jmp  .count_key
.presses:
    lea  rdi, [rel str_hlb_presses]
.count_key:
    call command_hook_out_str
    cmp  qword [r12 + 24], 1
    jne  .unknown_count
    mov  rdi, [r12 + 40]
    call command_hook_out_dec
    jmp  .freshness
.unknown_count:
    lea  rdi, [rel str_hlb_unknown]
    call command_hook_out_str
.freshness:
    lea  rdi, [rel str_hlb_untracked]
    cmp  qword [r12 + 24], 1
    je   .age
    lea  rdi, [rel str_hlb_unsupported]
.age:
    call command_hook_out_str
    lea  rdi, [rel str_hlb_lid_tail]
    cmp  r13d, 1
    je   .tail
    lea  rdi, [rel str_hlb_button_tail]
.tail:
    call command_hook_out_str
    jmp  .clear
.bad:
    call command_hook_out_reset
    lea  rdi, [rel str_hde_power_bad_reply]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    lea  rax, [rel str_hde_power_bad_reply]
    mov  [rbx + RSP_HINT], rax
.clear:
    mov  rdi, r12
    xor  esi, esi
    mov  edx, 128
    call memset
    add  rsp, 128
    jmp  .out
.denied:
    call command_hook_out_reset
    lea  rdi, [rel str_hde_power_denied]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_AUTHDENY
    lea  rax, [rel str_hde_power_denied]
    mov  [rbx + RSP_HINT], rax
.out:
    pop  r13
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.none:
    xor  eax, eax
    ret

; hde_power_field(RDI raw512, RSI key beginning with space and ending '=')
; -> RAX token start / 0, ECX length. Both match and value scans bound to raw512;
; only complete nonempty whitespace-delimited native fields are copied. The
; whitelist is fixed, never request-controlled, and never exposes other fields.
hde_power_field:
    xor  r8d, r8d
.scan:
    cmp  r8d, HDE_POWER_RAW_MAX
    jae  .no
    cmp  byte [rdi + r8], 0
    je   .no
    xor  ecx, ecx
.match:
    mov  r10b, [rsi + rcx]
    test r10b, r10b
    jz   .value
    lea  r9d, [r8d + ecx]
    cmp  r9d, HDE_POWER_RAW_MAX
    jae  .no
    cmp  r10b, [rdi + r9]
    jne  .next
    inc  ecx
    jmp  .match
.next:
    inc  r8d
    jmp  .scan
.value:
    lea  r9d, [r8d + ecx]
    mov  edx, r9d
.val:
    cmp  edx, HDE_POWER_RAW_MAX
    jae  .no
    mov  al, [rdi + rdx]
    test al, al
    jz   .end
    cmp  al, ' '
    je   .end
    cmp  al, 13
    je   .end
    cmp  al, 10
    je   .end
    inc  edx
    jmp  .val
.end:
    cmp  edx, r9d
    je   .no
    mov  ecx, edx
    sub  ecx, r8d
    lea  rax, [rdi + r8]
    ret
.no:
    xor  eax, eax
    ret

; REINITINFO declares a contract; it does not sample a driver. GET only,
; OBSERVE uses the same native admission and hashes declaration fields only.
hook_reinitinfo_plan:
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    jne  .bad
    mov  byte [rel reinit_out_ready], 0
    mov  byte [rel reinit_out_buf], 0
    call command_hook_arg_reset
    lea  rax, [rel str_hde_verb_reinitinfo]
    ret
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

HDE_REINIT_RAW_MAX equ 256                ; native reinit_out_buf capacity
hook_reinitinfo_post:
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .refused
    push rbx
    push r12
    sub  rsp, 8
    mov  rbx, rcx
    cmp  byte [rel reinit_out_ready], 1
    jne  .bad_reply
    lea  rdi, [rel reinit_out_buf]
    lea  rsi, [rdi + HDE_REINIT_RAW_MAX]
    call hde_reinit_record
    test eax, eax
    jz   .bad_reply
    lea  rax, [rel reinit_out_buf + 11]    ; strip only the native command label
    sub  rdi, rax
    mov  r12, rdi
    call command_hook_out_reset
    lea  rdi, [rel str_hde_reinitinfo_head]
    call command_hook_out_str
    lea  rdi, [rel reinit_out_buf + 11]
    mov  rsi, r12
    call command_hook_out_strn
    jmp  .done
.bad_reply:
    call command_hook_out_reset
    lea  rdi, [rel str_hde_reinitinfo_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hde_reinitinfo_bad]
    mov  [rbx + RSP_HINT], rax
.done:
    mov  byte [rel reinit_out_ready], 0
    mov  byte [rel reinit_out_buf], 0
    add  rsp, 8
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.refused:
    mov  byte [rel reinit_out_ready], 0
    mov  byte [rel reinit_out_buf], 0
    xor  eax, eax                        ; native code/hint remain authoritative
    ret

; RDI raw, RSI exclusive end -> EAX complete canonical record; RDI final NUL.
; Exact ordered public fields; no extra fields, partial lists, newline or nonce.
; Metadata values may change without implying runtime success. Every byte read
; (including the terminator) is below the producer's actual 256-byte capacity.
hde_reinit_record:
    mov  r11, rsi
    lea  rsi, [rel str_hde_ri_drv]
    call hde_reinit_literal
    test eax, eax
    jz   .no
    call hde_reinit_word
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hde_ri_idempotent]
    call hde_reinit_literal
    test eax, eax
    jz   .no
    call hde_reinit_bool
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hde_ri_preserved]
    call hde_reinit_literal
    test eax, eax
    jz   .no
    call hde_reinit_list
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hde_ri_resettable]
    call hde_reinit_literal
    test eax, eax
    jz   .no
    call hde_reinit_list
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hde_ri_quiesce]
    call hde_reinit_literal
    test eax, eax
    jz   .no
    call hde_reinit_bool
    test eax, eax
    jz   .no
    cmp  rdi, r11
    jae  .no
    cmp  byte [rdi], 0
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

hde_reinit_literal:
.next:
    mov  al, [rsi]
    test al, al
    jz   .yes
    cmp  rdi, r11
    jae  .no
    cmp  al, [rdi]
    jne  .no
    inc  rdi
    inc  rsi
    jmp  .next
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

hde_reinit_bool:
    cmp  rdi, r11
    jae  .no
    mov  al, [rdi]
    sub  al, '0'
    cmp  al, 1
    ja   .no
    inc  rdi
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

hde_reinit_list:
.next:
    call hde_reinit_word
    test eax, eax
    jz   .no
    cmp  rdi, r11
    jae  .no
    cmp  byte [rdi], ','
    jne  .yes
    inc  rdi
    jmp  .next
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Nonempty lowercase identifier, then lowercase/digits/underscore/hyphen.
hde_reinit_word:
    cmp  rdi, r11
    jae  .no
    mov  al, [rdi]
    cmp  al, 'a'
    jb   .no
    cmp  al, 'z'
    ja   .no
.next:
    inc  rdi
    cmp  rdi, r11
    jae  .no
    mov  al, [rdi]
    cmp  al, 'a'
    jb   .other
    cmp  al, 'z'
    jbe  .next
.other:
    cmp  al, '0'
    jb   .symbol
    cmp  al, '9'
    jbe  .next
.symbol:
    cmp  al, '_'
    je   .next
    cmp  al, '-'
    je   .next
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

str_hde_reinitinfo: db "reinitinfo", 0
str_hde_verb_reinitinfo: db "REINITINFO", 0
str_hde_reinitinfo_schema: db "v=1 inst=none get=REINITINFO{evidence=declaration,runtime=unobserved,drv=<identifier>,idempotent=0|1,preserved=<identifier-list>,resettable=<identifier-list>,quiesce=0|1} observe=declaration-fields-only not-runtime-liveness-or-recovery-success authority=native list=na set=na input=na cancel=na", 0
str_hde_reinitinfo_head: db " reinitinfo v=1 evidence=declaration runtime=unobserved", 0
str_hde_reinitinfo_bad: db " hook err=reinitinfo_reply_incomplete", 0
str_hde_reinitinfo_witness: db " evidence=",0," runtime=",0," drv=",0," idempotent=",0," preserved=",0," resettable=",0," quiesce=",0,0
str_hde_ri_drv: db " REINITINFO drv=", 0
str_hde_ri_idempotent: db " idempotent=", 0
str_hde_ri_preserved: db " preserved=", 0
str_hde_ri_resettable: db " resettable=", 0
str_hde_ri_quiesce: db " quiesce=", 0
align 8
hook_edge_reinitinfo: times (HE_SZ / 8) dq 0

; ---------------------------------------------------------------------------
str_hde_usb:              db "usb", 0
str_hde_aer:              db "aer", 0
str_hde_pci:              db "pci", 0
str_hde_backlight:        db "backlight", 0
str_hde_session:          db "session", 0
str_hde_kind_device:      db "device", 0
str_hde_kind_power:       db "power", 0
str_hde_kind_session:     db "session", 0
str_hde_usb_schema:       db "v=1 inst=none|<slot 1..16 canonical> list=USBLIST{SLOT,VID:PID,CLASS,PORT;empty=none;truncated=shown,total;rows=atomic} get=USBLIST|ports:USBPORTS{native diagnostic,not-inventory}|<slot>:USBDESC{slot,18-byte hex length=18 type=1|none} observe=whole-native-data-and-completeness authority=native current=one-use-selector-and-extent no-live-enumeration-or-health-proof set=na input=na cancel=na", 0
str_hde_aer_schema:       db "v=1 inst=none get=AERLOG last{saved-software,captured,class,BDF,tag,count}|cto:PCIECTO status{configured-timeout-us,rootports,applied-any,coverage-unknown} observe=selected-state authority=native no-live-health-or-physical-containment-proof list=na set=na input=na cancel=na", 0
str_hde_pci_schema: db "v=2 inst=decimal-page-cursor:0..65536 default=0 list=PCISCAN{BB:DD.F=VVVV:DDDD/CC:SS:PI,devices,start,returned,next,complete,scan=live} get=same rows<=24 complete=page-stream-end next=first-unreturned-BDF|65536 live-not-atomic observe=one-page-with-cursor nonce=excluded no-inventory-or-hardware-proof authority=native set=na input=na cancel=na", 0
str_hde_backlight_schema: db "inst=none get=BACKLIGHT{pct=<nearest duty*100/max>|na,duty,max (PWM units)} set=<0..100>:BACKLIGHT <pct> observe=duty,pct,max (BACKLIGHT is destructive: reads need the same authority) list=na input=na cancel=na", 0
str_hde_session_schema:   db "inst=none get=SESSIONINFO{locked,principal,key_handle=bound|none,restore_class,restore_source,workspace_principal,gate_kat,boot_policy} observe=locked,principal,key_handle,workspace_principal,restore_source,gate_kat,boot_policy nonce=excluded saved-diagnostics-only list=na set=na input=na cancel=na", 0
str_hde_backlight_witness: db "duty=",0,"pct=",0," max=",0,0
str_hde_session_witness:  db "locked=",0," principal=",0," key_handle=",0," workspace_principal=",0," restore_source=",0," gate_kat=",0," boot_policy=",0,0
str_hde_pct:              db "pct=", 0
str_hde_na:               db "na", 0
str_hde_duty:             db " duty=", 0
str_hde_max:              db " max=", 0
str_hde_word_ports:       db "PORTS", 0
str_hde_word_cto:         db "CTO", 0
str_hde_arg_last:         db "last", 0
str_hde_arg_status:       db "status", 0
str_hde_verb_usblist:     db "USBLIST", 0
str_hde_verb_usbdesc:     db "USBDESC", 0
str_hde_verb_usbports:    db "USBPORTS", 0
str_hde_verb_aerlog:      db "AERLOG", 0
str_hde_verb_pciecto:     db "PCIECTO", 0
str_hde_verb_pciscan:     db "PCISCAN", 0
str_hde_verb_backlight:   db "BACKLIGHT", 0
str_hde_verb_sessioninfo: db "SESSIONINFO", 0

str_hde_power: db "power", 0
str_hde_verb_status: db "STATUS", 0
str_hde_power_schema: db "v=1 inst=none get=STATUS(0)+owner-envelope{backend=ec|unsupported,AC=0|1|unknown,BAT=0|1|unknown,BAT_PCT=0..100|unknown,BAT_STATE=idle|discharging|charging|unknown,BAT_REM,BAT_FULL,BAT_DESIGN (mAh),BAT_MV (mV),BAT_RATE (mA),BAT_UNIT,BAT_WARN=none|low|critical|unknown,AC_FRESH/BAT_FRESH=never|valid|absent|failed|expired|clock|unsupported,AC_AGE_MS/BAT_AGE_MS=last-success group age|unknown,AC_ATTEMPT_MS/BAT_ATTEMPT_MS=last-attempt time|unknown} selectors=lid|button lid={state=open|closed|unknown,events=u32|unknown} button={presses=u32|unknown,action=unobserved} support=software-configured:0|1 freshness=untracked|unsupported age_ms=unknown counters=wrapping-u32 current=valid-only absent=BAT_FRESH:absent last-good-values=not-retained observe=values+validity+backend (age/attempt excluded) authority=native-owner-envelope-only list=na set=na input=na cancel=na", 0
str_hde_power_head: db " power v=1 backend=ec", 0
str_hde_power_denied: db " hook err=owner_envelope_required", 0
str_hde_power_bad_reply: db " hook err=power_reply_incomplete", 0
str_hde_power_unsupported: db " power v=1 backend=unsupported AC=unknown BAT=unknown BAT_PCT=unknown BAT_STATE=unknown BAT_REM=unknown BAT_FULL=unknown BAT_DESIGN=unknown BAT_MV=unknown BAT_RATE=unknown BAT_UNIT=unknown BAT_WARN=unknown AC_FRESH=unsupported AC_AGE_MS=unknown BAT_FRESH=unsupported BAT_AGE_MS=unknown AC_ATTEMPT_MS=unknown BAT_ATTEMPT_MS=unknown", 0
str_hde_power_keys: db " AC=",0," BAT=",0," BAT_PCT=",0," BAT_STATE=",0," BAT_REM=",0," BAT_FULL=",0," BAT_DESIGN=",0," BAT_MV=",0," BAT_RATE=",0," BAT_UNIT=",0," BAT_WARN=",0," AC_FRESH=",0," AC_AGE_MS=",0," BAT_FRESH=",0," BAT_AGE_MS=",0," AC_ATTEMPT_MS=",0," BAT_ATTEMPT_MS=",0,0
str_hde_power_witness: db " backend=",0," AC=",0," BAT=",0," BAT_PCT=",0," BAT_STATE=",0," BAT_REM=",0," BAT_FULL=",0," BAT_DESIGN=",0," BAT_MV=",0," BAT_RATE=",0," BAT_UNIT=",0," BAT_WARN=",0," AC_FRESH=",0," BAT_FRESH=",0,0

align 8
hook_edge_usb:            times (HE_SZ / 8) dq 0
hook_edge_aer:            times (HE_SZ / 8) dq 0
hook_edge_pci:            times (HE_SZ / 8) dq 0
hook_edge_backlight:      times (HE_SZ / 8) dq 0
hook_edge_session:        times (HE_SZ / 8) dq 0
hook_edge_power:          times (HE_SZ / 8) dq 0
hde_nonce_ctr:            dq 0
hde_nonce_buf:            times 24 db 0

; DPOWER status is passive software evidence, not physical POWER success.
; Only GET (also OBSERVE's planned op) delegates exact "status 0". The normal
; native destructive row retains owner MUTATE admission for every transport.
; No class/custody/probe/transaction call is made here. Native rc and error are
; data, independent of transport OK: unsupported/unattached/degraded/busy and
; every transitional state remain observable without inferred consistency rules.
; The whole normalized reply is witnessed: state, custody, token, generations,
; phase, acknowledgements AND software frame/work progress. There are no clock
; or read-attempt counters to omit. All fields move the witness intentionally.
; Typed publication additionally requires the exact request owner, checked with
; command_auth_ticket_owner through the common nested-request accessor. Trusted
; internal/SYSTEM native admission alone cannot expose this owner-only surface.
; Fresh publication is consumed and retired on success/malformed/native refusal.
hook_dpower_plan:
    mov  byte [rel reinit_out_ready], 0
    mov  byte [rel reinit_out_buf], 0
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    jne  .bad
    call command_hook_arg_reset
    lea  rdi, [rel str_hde_dpower_arg]
    call command_hook_arg_str
    lea  rax, [rel str_hde_verb_dpower]
    ret
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

HDE_DPOWER_RAW_MAX equ 384                ; native reinit_out_buf capacity
hook_dpower_post:
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .refused
    push rbx
    push r12
    sub  rsp, 8
    mov  rbx, rcx
    call command_hook_request_owner
    test eax, eax
    jz   .owner_required
    cmp  byte [rel reinit_out_ready], 1
    jne  .bad_reply
    lea  rdi, [rel reinit_out_buf]
    lea  rsi, [rdi + HDE_DPOWER_RAW_MAX]
    call hde_dpower_record
    test eax, eax
    jz   .bad_reply
    mov  [rsp], edx                      ; parsed optional guest suffix, not global state
    lea  rax, [rel reinit_out_buf + 7]    ; strip only the native command label
    sub  rdi, rax
    mov  r12, rdi
    call command_hook_out_reset
    lea  rdi, [rel str_hde_dpower_head]
    cmp  dword [rsp], 0
    je   .head
    lea  rdi, [rel str_hde_dpower_guest_head]
.head:
    call command_hook_out_str
    lea  rdi, [rel reinit_out_buf + 7]
    mov  rsi, r12
    call command_hook_out_strn
    jmp  .done
.owner_required:
    call command_hook_out_reset
    lea  rdi, [rel str_hde_dpower_denied]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_AUTHDENY
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hde_dpower_denied]
    mov  [rbx + RSP_HINT], rax
    jmp  .done
.bad_reply:
    call command_hook_out_reset
    lea  rdi, [rel str_hde_dpower_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hde_dpower_bad]
    mov  [rbx + RSP_HINT], rax
.done:
    mov  byte [rel reinit_out_ready], 0
    mov  byte [rel reinit_out_buf], 0
    add  rsp, 8
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.refused:
    mov  byte [rel reinit_out_ready], 0
    mov  byte [rel reinit_out_buf], 0
    xor  eax, eax                        ; native code/hint remain authoritative
    ret

hde_dpower_record:
    mov  r11, rsi
    lea  rsi, [rel str_hde_dp_rc]
    call hde_reinit_literal
    test eax, eax
    jz   .no
    mov  rdx, 9223372036854775807
    call hde_dpower_signed
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hde_dp_state]
    call hde_reinit_literal
    test eax, eax
    jz   .no
    mov  rdx, 4294967295
    call hde_dpower_unsigned
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hde_dp_count]
    call hde_reinit_literal
    test eax, eax
    jz   .no
    mov  rdx, 4294967295
    call hde_dpower_unsigned
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hde_dp_members]
    call hde_reinit_literal
    test eax, eax
    jz   .no
    mov  rdx, 4294967295
    call hde_dpower_unsigned
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hde_dp_token]
    call hde_reinit_literal
    test eax, eax
    jz   .no
    mov  rdx, 18446744073709551615
    call hde_dpower_unsigned
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hde_dp_phase]
    call hde_reinit_literal
    test eax, eax
    jz   .no
    mov  rdx, 4294967295
    call hde_dpower_unsigned
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hde_dp_error]
    call hde_reinit_literal
    test eax, eax
    jz   .no
    mov  rdx, 2147483647
    call hde_dpower_signed
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hde_dp_ramgen]
    call hde_reinit_literal
    test eax, eax
    jz   .no
    mov  rdx, 18446744073709551615
    call hde_dpower_unsigned
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hde_dp_netgen]
    call hde_reinit_literal
    test eax, eax
    jz   .no
    mov  rdx, 18446744073709551615
    call hde_dpower_unsigned
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hde_dp_frames]
    call hde_reinit_literal
    test eax, eax
    jz   .no
    mov  rdx, 18446744073709551615
    call hde_dpower_unsigned
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hde_dp_done]
    call hde_reinit_literal
    test eax, eax
    jz   .no
    mov  rdx, 255
    call hde_dpower_unsigned
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hde_dp_ramack]
    call hde_reinit_literal
    test eax, eax
    jz   .no
    mov  rdx, 4294967295
    call hde_dpower_unsigned
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hde_dp_netack]
    call hde_reinit_literal
    test eax, eax
    jz   .no
    mov  rdx, 4294967295
    call hde_dpower_unsigned
    test eax, eax
    jz   .no
    cmp  rdi, r11
    jae  .no
    cmp  byte [rdi], 0
    jne  .guest
    xor  edx, edx
    mov  eax, 1
    ret
.guest:
    lea  rsi, [rel str_hde_dp_guestgen]
    call hde_reinit_literal
    test eax, eax
    jz   .no
    mov  rdx, 18446744073709551615
    call hde_dpower_unsigned
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hde_dp_guestack]
    call hde_reinit_literal
    test eax, eax
    jz   .no
    mov  rdx, 4294967295
    call hde_dpower_unsigned
    test eax, eax
    jz   .no
    cmp  rdi, r11
    jae  .no
    cmp  byte [rdi], 0
    jne  .no
    mov  edx, 1
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Native signed decimal: i64 rc, sign-extended i32 error. Negative zero,
; plus signs, leading zeroes and overflows are not native formatter output.
hde_dpower_signed:
    xor  esi, esi
    cmp  rdi, r11
    jae  .no
    cmp  byte [rdi], '-'
    jne  .number
    inc  rdi
    inc  rdx                            ; abs(INT_MIN) is max+1
    inc  esi
.number:
    call hde_dpower_unsigned
    test eax, eax
    jz   .no
    test esi, esi
    jz   .yes
    test r8, r8
    jz   .no
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; RDI cursor, R11 exclusive end, RDX unsigned limit. Leaves R8 value.
; Canonical 1..20 decimal digits; no out-of-buffer terminator access.
hde_dpower_unsigned:
    mov  r10, rdx
    xor  r8d, r8d
    xor  ecx, ecx
.next:
    cmp  rdi, r11
    jae  .no
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 9
    ja   .end
    test ecx, ecx
    jz   .first
    test r8, r8
    jz   .no                            ; no leading zeroes
.first:
    mov  r9, 1844674407370955161
    cmp  r8, r9
    ja   .no
    jb   .add
    cmp  eax, 5
    ja   .no
.add:
    imul r8, r8, 10
    add  r8, rax
    cmp  r8, r10
    ja   .no
    inc  rdi
    inc  ecx
    jmp  .next
.end:
    test ecx, ecx
    jz   .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

str_hde_dpower: db "dpower", 0
str_hde_verb_dpower: db "DPOWER", 0
str_hde_dpower_arg: db "status 0", 0
str_hde_dpower_schema: db "v=1 inst=none get=DPOWER(status 0) evidence=software scope=ram-loopnet[+guest] rc=i64 state=u32 count=u32 members=u32 token=u64 phase=u32 error=i32 ramgen=u64 netgen=u64 frames=u64 done=u8 ramack=u32 netack=u32 optional-pair=guestgen:u64,guestack:u32 observe=all-fields(including-progress) authority=native-owner-MUTATE unsupported/unattached/transitional/degraded=raw-native-state no-physical-success-inference list=na set=na input=na cancel=na", 0
str_hde_dpower_head: db " dpower v=1 evidence=software scope=ram-loopnet", 0
str_hde_dpower_guest_head: db " dpower v=1 evidence=software scope=ram-loopnet-guest", 0
str_hde_dpower_bad: db " hook err=dpower_reply_incomplete", 0
str_hde_dp_rc: db " DPOWER rc=", 0
str_hde_dp_state: db " state=", 0
str_hde_dp_count: db " count=", 0
str_hde_dp_members: db " members=", 0
str_hde_dp_token: db " token=", 0
str_hde_dp_phase: db " phase=", 0
str_hde_dp_error: db " error=", 0
str_hde_dp_ramgen: db " ramgen=", 0
str_hde_dp_netgen: db " netgen=", 0
str_hde_dp_frames: db " frames=", 0
str_hde_dp_done: db " done=", 0
str_hde_dp_ramack: db " ramack=", 0
str_hde_dp_netack: db " netack=", 0
str_hde_dp_guestgen: db " guestgen=", 0
str_hde_dp_guestack: db " guestack=", 0
align 8
hook_edge_dpower: times (HE_SZ / 8) dq 0
str_hde_dpower_denied: db " hook err=dpower_owner_required", 0

; A PCI page is a one-use response to this exact planned nonce/cursor. The native
; read gate has already run. Reject a whole malformed/incomplete record rather
; than relaying a prefix or hashing stale bytes. No topology snapshot is kept.
HPC_NATIVE_CAP equ 1050
HPC_BODY_CAP equ 1024
hook_pci_post:
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .native_refused
    push rbx
    push r12
    mov  rbx, rcx
    cmp  byte [rel hpc_pending], 1
    jne  .bad
    cmp  byte [rel pci_mmio_out_ready], 1
    jne  .bad
    cmp  byte [rel pci_mmio_scan_ready], 1
    jne  .bad
    lea  rdi, [rel pci_mmio_scan_arg]
    lea  rsi, [rel command_hook_arg]
    xor  ecx, ecx
.arg:
    cmp  ecx, 96
    jae  .bad
    mov  al, [rdi + rcx]
    cmp  al, [rsi + rcx]
    jne  .bad
    test al, al
    jz   .arg_ok
    inc  ecx
    jmp  .arg
.arg_ok:
    test ecx, ecx
    jz   .bad
    lea  rdi, [rel pci_mmio_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HPC_NATIVE_CAP
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    cmp  ecx, HPC_BODY_CAP
    jae  .bad
    mov  r12d, ecx
    call hpc_record
    test eax, eax
    jz   .bad
    call command_hook_out_reset
    lea  rdi, [rel pci_mmio_out_buf]
    mov  esi, r12d
    call command_hook_out_strn
    jmp  .out
.bad:
    call command_hook_out_reset
    lea  rdi, [rel str_hpc_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hpc_bad]
    mov  [rbx + RSP_HINT], rax
.out:
    call hpc_retire
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.native_refused:
    call hpc_retire
    xor  eax, eax
    ret

hpc_retire:
    mov  byte [rel hpc_pending], 0
    mov  byte [rel pci_mmio_out_ready], 0
    mov  byte [rel pci_mmio_scan_ready], 0
    mov  byte [rel pci_mmio_scan_arg], 0
    mov  byte [rel pci_mmio_out_buf], 0
    ret

; After the bounded NUL scan, every parser stops at that NUL. Rows are exact,
; lowercase fixed-width native hex. Only existing PCI vendor IDs may be rows.
hpc_record:
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  rsi, [rel str_hpc_head]
    call hpc_literal
    test eax, eax
    jz   .no
    xor  r12d, r12d                      ; actual row count
    mov  r13, -1                        ; previous packed BDF
.rows:
    cmp  byte [rdi], ' '
    jne  .no
    cmp  byte [rdi + 1], 'd'             ; devices= marks metadata, never a row
    jne  .row
    cmp  byte [rdi + 2], 'e'
    jne  .row
    cmp  byte [rdi + 3], 'v'             ; bus de: is a row, not devices=
    je   .metadata
.row:
    inc  rdi
    cmp  r12d, 24
    jae  .no
    mov  ecx, 2
    call hpc_hex
    test eax, eax
    jz   .no
    mov  ebx, edx
    shl  ebx, 8
    cmp  byte [rdi], ':'
    jne  .no
    inc  rdi
    mov  ecx, 2
    call hpc_hex
    test eax, eax
    jz   .no
    cmp  edx, 31
    ja   .no
    shl  edx, 3
    or   ebx, edx
    cmp  byte [rdi], '.'
    jne  .no
    inc  rdi
    mov  ecx, 1
    call hpc_hex
    test eax, eax
    jz   .no
    cmp  edx, 7
    ja   .no
    or   ebx, edx
    cmp  rbx, [rel hpc_cursor]
    jb   .no
    test r12d, r12d
    jz   .first
    cmp  rbx, r13
    jbe  .no
.first:
    mov  r13, rbx
    cmp  byte [rdi], '='
    jne  .no
    inc  rdi
    mov  ecx, 4
    call hpc_hex
    test eax, eax
    jz   .no
    cmp  edx, 65535
    je   .no                            ; enumerator never emits vendor NONE
    cmp  byte [rdi], ':'
    jne  .no
    inc  rdi
    mov  ecx, 4
    call hpc_hex
    test eax, eax
    jz   .no
    cmp  byte [rdi], '/'
    jne  .no
    inc  rdi
    mov  ecx, 2
    call hpc_hex
    test eax, eax
    jz   .no
    cmp  byte [rdi], ':'
    jne  .no
    inc  rdi
    mov  ecx, 2
    call hpc_hex
    test eax, eax
    jz   .no
    cmp  byte [rdi], ':'
    jne  .no
    inc  rdi
    mov  ecx, 2
    call hpc_hex
    test eax, eax
    jz   .no
    inc  r12d
    jmp  .rows
.metadata:
    lea  rsi, [rel str_hpc_total]
    call hpc_literal
    test eax, eax
    jz   .no
    call hpc_dec
    test eax, eax
    jz   .no
    mov  r14d, edx
    cmp  r14, r12
    jb   .no
    lea  rsi, [rel str_hpc_start]
    call hpc_literal
    test eax, eax
    jz   .no
    call hpc_dec
    test eax, eax
    jz   .no
    cmp  rdx, [rel hpc_cursor]
    jne  .no
    lea  rsi, [rel str_hpc_returned]
    call hpc_literal
    test eax, eax
    jz   .no
    call hpc_dec
    test eax, eax
    jz   .no
    cmp  rdx, r12
    jne  .no
    lea  rsi, [rel str_hpc_next]
    call hpc_literal
    test eax, eax
    jz   .no
    call hpc_dec
    test eax, eax
    jz   .no
    mov  r15d, edx
    lea  rsi, [rel str_hpc_complete]
    call hpc_literal
    test eax, eax
    jz   .no
    call hpc_dec
    test eax, eax
    jz   .no
    cmp  edx, 1
    ja   .no
    test edx, edx
    jz   .more
    cmp  r15d, 65536
    jne  .no
    ; At completion every function is either a row or before start; with start
    ; zero, total must equal row count. There are at most start earlier BDFs.
    mov  rax, r14
    sub  rax, r12
    cmp  rax, [rel hpc_cursor]
    ja   .no
    jmp  .live
.more:
    cmp  r12d, 24
    jne  .no
    cmp  r15d, 65536
    jae  .no
    cmp  r15, r13
    jbe  .no
    cmp  r14, r12
    jbe  .no
    ; Physical coordinate capacity bounds all functions before/within/after.
    mov  rax, 65536
    sub  rax, r15
    add  rax, r12
    add  rax, [rel hpc_cursor]
    cmp  r14, rax
    ja   .no
.live:
    lea  rsi, [rel str_hpc_live]
    call hpc_literal
    test eax, eax
    jz   .no
    cmp  byte [rdi], 0
    jne  .no
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

hpc_literal:
    mov  al, [rsi]
    test al, al
    jz   .yes
    cmp  al, [rdi]
    jne  .no
    inc  rsi
    inc  rdi
    jmp  hpc_literal
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Canonical natural decimal 0..65536. No overflow, sign, leading zero or prefix.
; EDX=value; RDI advances to the delimiter, EAX=1 iff at least one valid digit.
hpc_dec:
    xor  edx, edx
    cmp  byte [rdi], '0'
    jne  .digits
    inc  rdi
    mov  eax, 1
    ret
.digits:
    xor  ecx, ecx
.next:
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 9
    ja   .end
    imul rdx, rdx, 10
    add  rdx, rax
    cmp  rdx, 65536
    ja   .no
    inc  rdi
    inc  ecx
    jmp  .next
.end:
    xor  eax, eax
    test ecx, ecx
    setnz al
    ret
.no:
    xor  eax, eax
    ret

; ECX fixed digits, lowercase only, EDX=value. Never reads past source NUL.
hpc_hex:
    xor  edx, edx
.next:
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 9
    jbe  .digit
    sub  eax, 'a' - '0'
    cmp  eax, 5
    ja   .no
    add  eax, 10
.digit:
    shl  edx, 4
    or   edx, eax
    inc  rdi
    dec  ecx
    jnz  .next
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

str_hpc_page: db " PAGE ", 0
str_hpc_zero: db "0", 0
str_hpc_bad: db " hook err=pci_page_incomplete", 0
str_hpc_head: db " PCISCAN", 0
str_hpc_total: db " devices=", 0
str_hpc_start: db " start=", 0
str_hpc_returned: db " returned=", 0
str_hpc_next: db " next=", 0
str_hpc_complete: db " complete=", 0
str_hpc_live: db " scan=live", 0
align 8
hpc_cursor: dq 0
hpc_pending: db 0

; Typed USB post: validate the complete native publication before owned copying.
; Dispatch is serialized. Selector/extent cells are correlation, never authority.
; Ports retains its native diagnostic bytes; it is explicitly not inventory.
hook_usb_post:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx,rcx
    cmp qword [rbx+RSP_CODE],CMDE_OK
    jne .refused
    movzx eax,byte [rel hus_pending]
    test eax,eax
    jz .bad
    cmp al,[rel usb_out_kind]
    jne .bad
    cmp byte [rel usb_out_ready],1
    jne .bad
    mov edx,[rel hus_slot]
    cmp edx,[rel usb_out_slot]
    jne .bad
    lea rdi,[rel usb_out_buf]
    xor ecx,ecx
.measure:
    cmp ecx,512                       ; actual native USB_OUT_CAP
    jae .bad
    cmp byte [rdi+rcx],0
    je .bounded
    inc ecx
    jmp .measure
.bounded:
    lea rax,[rdi+rcx]
    cmp rax,[rel usb_out_cur]
    jne .bad
    mov r12d,ecx
    cmp ecx,HOOK_OUT_MAX-1
    ja .bad
    cmp byte [rel hus_pending],1
    je .list
    cmp byte [rel hus_pending],2
    je .desc
    cmp byte [rel hus_pending],3
    jne .bad
    lea rsi,[rel str_hus_ports]
    call hus_literal
    test eax,eax
    jz .bad
    cmp byte [rdi],0
    je .bad
    jmp .copy
.list:
    call hus_list
    test eax,eax
    jz .bad
    jmp .copy
.desc:
    call hus_desc
    test eax,eax
    jz .bad
.copy:
    call command_hook_out_reset
    lea rdi,[rel usb_out_buf]
    mov esi,r12d
    call command_hook_out_strn
    jmp .retire
.bad:
    call command_hook_out_reset
    lea rdi,[rel str_hus_bad]
    call command_hook_out_str
    mov qword [rbx+RSP_CODE],CMDE_BADARG
    mov qword [rbx+RSP_ACCEPTED],0
    lea rax,[rel str_hus_bad]
    mov [rbx+RSP_HINT],rax
.retire:
    call hus_retire
    mov eax,1
    jmp .out
.refused:
    call hus_retire
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
hus_retire:
    mov byte [rel hus_pending],0
    mov dword [rel hus_slot],0
    mov byte [rel usb_out_ready],0
    mov byte [rel usb_out_buf],0
    mov byte [rel usb_out_kind],0
    mov dword [rel usb_out_slot],0
    mov qword [rel usb_out_cur],0
    ret

; Sequential native slots, exact fixed-width lowercase hex, byte-sized port,
; CRLF per whole row. Truncation is a final record, never a successful full list.
hus_list:
    push rdi
    lea rsi,[rel str_hus_empty]
    call hus_literal
    test eax,eax
    pop rax
    jz .rows
    cmp byte [rdi],0
    je .yes
.rows:
    mov rdi,rax
    xor r14d,r14d
.row:
    lea rsi,[rel str_hus_slot]
    call hus_literal
    test eax,eax
    jz .no
    call hus_uint
    test eax,eax
    jz .no
    inc r14d
    cmp r14d,16
    ja .no
    cmp edx,r14d
    jne .no
    lea rsi,[rel str_hus_vidpid]
    call hus_literal
    test eax,eax
    jz .no
    call hus_hexword
    test eax,eax
    jz .no
    lea rsi,[rel str_hus_colon]
    call hus_literal
    test eax,eax
    jz .no
    call hus_hexword
    test eax,eax
    jz .no
    lea rsi,[rel str_hus_class]
    call hus_literal
    test eax,eax
    jz .no
    call hus_hexbyte
    test eax,eax
    jz .no
    lea rsi,[rel str_hus_port]
    call hus_literal
    test eax,eax
    jz .no
    call hus_uint
    test eax,eax
    jz .no
    cmp edx,255
    ja .no
    lea rsi,[rel str_hus_crlf]
    call hus_literal
    test eax,eax
    jz .no
    cmp byte [rdi],0
    je .yes
    cmp byte [rdi],'S'
    je .row
    mov r15,rdi                         ; producer bytes before truncation line
    lea rsi,[rel str_hus_trunc]
    call hus_literal
    test eax,eax
    jz .no
    call hus_uint
    test eax,eax
    jz .no
    cmp edx,r14d
    jne .no
    lea rsi,[rel str_hus_total]
    call hus_literal
    test eax,eax
    jz .no
    call hus_uint
    test eax,eax
    jz .no
    cmp edx,16
    ja .no
    cmp edx,r14d
    jbe .no
    cmp byte [rdi],0
    jne .no
    ; Mirror only the native bounded-publication rule: the next worst-case row
    ; cannot fit. Reject a fabricated early truncation (no separate enum read).
    lea rax,[rel usb_out_buf]
    sub r15,rax
    add r15,54                          ; USB_ROW_MAX + NUL
    lea eax,[r14d+1]
    cmp eax,edx
    jae .last
    add r15,51                          ; USB_TRUNC_MAX
.last:
    cmp r15,512
    jbe .no
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

hus_desc:
    lea rsi,[rel str_hus_desc]
    call hus_literal
    test eax,eax
    jz .no
    call hus_uint
    test eax,eax
    jz .no
    cmp edx,[rel hus_slot]
    jne .no
    push rdi
    lea rsi,[rel str_hus_none]
    call hus_literal
    test eax,eax
    pop rax
    jz .bytes
    cmp byte [rdi],0
    je .yes
.bytes:
    mov rdi,rax
    lea rsi,[rel str_hus_bytes]
    call hus_literal
    test eax,eax
    jz .no
    xor r14d,r14d
.hex:
    call hus_hexbyte
    test eax,eax
    jz .no
    lea rax,[rel hus_descriptor]
    mov [rax+r14],dl
    inc r14d
    cmp r14d,18
    jb .hex
    cmp byte [rdi],0
    jne .no
    ; Same advertised DEVICE geometry that enum validates: 18 bytes, type1.
    ; Other bytes are preserved metadata, not endpoint/configuration validation.
    cmp byte [rel hus_descriptor],18
    jne .no
    cmp byte [rel hus_descriptor+1],1
    jne .no
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

hus_literal:
    mov al,[rsi]
    test al,al
    jz .yes
    cmp al,[rdi]
    jne .no
    inc rdi
    inc rsi
    jmp hus_literal
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret
; All USB decimal schema fields fit 3 digits. A zero is canonical on its own.
hus_uint:
    xor edx,edx
    cmp byte [rdi],'0'
    jne .digits
    inc rdi
    mov eax,1
    ret
.digits:
    xor r9d,r9d
.next:
    movzx eax,byte [rdi]
    sub eax,'0'
    cmp eax,9
    ja .end
    cmp r9d,3
    jae .no
    imul edx,edx,10
    add edx,eax
    inc rdi
    inc r9d
    jmp .next
.end:
    xor eax,eax
    test r9d,r9d
    setnz al
    ret
.no:
    xor eax,eax
    ret
hus_hexword:
    call hus_hexbyte
    test eax,eax
    jz .out
    call hus_hexbyte
.out:
    ret
hus_hexbyte:
    xor ecx,ecx
    xor edx,edx
.next:
    movzx eax,byte [rdi]
    sub eax,'0'
    cmp eax,9
    jbe .digit
    movzx eax,byte [rdi]
    sub eax,'a'
    cmp eax,5
    ja .no
    add eax,10
.digit:
    shl edx,4
    or edx,eax
    inc rdi
    inc ecx
    cmp ecx,2
    jb .next
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

hus_pending: db 0
align 4
hus_slot: dd 0
hus_descriptor: times 18 db 0
str_hus_bad: db " hook err=usb_reply_incomplete",0
str_hus_empty: db "USBLIST none",0
str_hus_slot: db "SLOT=",0
str_hus_vidpid: db " VID:PID=",0
str_hus_colon: db ":",0
str_hus_class: db " CLASS=",0
str_hus_port: db " PORT=",0
str_hus_crlf: db 13,10,0
str_hus_trunc: db "USBLIST truncated shown=",0
str_hus_total: db " total=",0
str_hus_desc: db "USBDESC slot=",0
str_hus_none: db " none",0
str_hus_bytes: db " bytes=",0
str_hus_ports: db "USBPORTS maxports=",0

; Saved AER/CTO reads share a native staging area with unrelated publishers.
; Never copy or retire another selector's publication. Admission is native.
hook_aer_post:
    push rbx
    push r12
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    mov  al, [rel har_pending]
    test al, al
    jz   .bad
    cmp  al, [rel res_out_kind]
    jne  .bad
    cmp  byte [rel res_out_ready], 1
    jne  .bad
    cmp  byte [rel res_out_error], 0
    jne  .bad
    lea  rdi, [rel res_read_req]
    call command_hook_request_matches
    test eax, eax
    jz   .bad
    lea  rdi, [rel res_read_arg]
    lea  rsi, [rel command_hook_arg]
    xor  ecx, ecx
.arg:
    cmp  ecx, 64
    jae  .bad
    mov  al, [rdi + rcx]
    cmp  al, [rsi + rcx]
    jne  .bad
    test al, al
    jz   .extent
    inc  ecx
    jmp  .arg
.extent:
    test ecx, ecx
    jz   .bad
    lea  rdi, [rel res_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, 256
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel res_out_cur]
    jne  .bad
    mov  r12d, ecx
    cmp  byte [rel har_pending], 1
    jne  .cto
    call har_aer_record
    test eax, eax
    jz   .bad
    call command_hook_out_reset
    cmp  qword [rel har_count], 0
    je   .empty
    lea  rdi, [rel str_har_saved]
    call command_hook_out_str
    lea  rdi, [rel res_out_buf]
    mov  esi, r12d
    call command_hook_out_strn
    jmp  .out
.empty:
    lea  rdi, [rel str_har_empty]
    call command_hook_out_str
    jmp  .out
.cto:
    call har_cto_record
    test eax, eax
    jz   .bad
    call command_hook_out_reset
    lea  rdi, [rel str_har_cto]
    call command_hook_out_str
    mov  rdi, [rel har_timeout]
    call command_hook_out_dec
    lea  rdi, [rel str_har_ports]
    call command_hook_out_str
    mov  rdi, [rel har_ports]
    call command_hook_out_dec
    lea  rdi, [rel str_har_applied]
    call command_hook_out_str
    mov  rdi, [rel har_applied]
    call command_hook_out_dec
    lea  rdi, [rel str_har_coverage]
    call command_hook_out_str
    jmp  .out
.bad:
    call command_hook_out_reset
    lea  rdi, [rel str_har_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_har_bad]
    mov  [rbx + RSP_HINT], rax
.out:
    call har_retire_selected
    mov  byte [rel har_pending], 0
    mov  eax, 1
    jmp  .done
.refused:
    call har_retire_selected
    mov  byte [rel har_pending], 0
    xor  eax, eax
.done:
    pop  r12
    pop  rbx
    ret

har_retire_selected:
    mov  al, [rel har_pending]
    test al, al
    jz   .done
    cmp  al, [rel res_out_kind]
    jne  .done
    mov  byte [rel res_out_ready], 0
    mov  byte [rel res_out_kind], 0
    mov  byte [rel res_out_error], 0
    mov  byte [rel res_out_buf], 0
    mov  byte [rel res_read_arg], 0
    mov  qword [rel res_out_cur], 0
    mov  qword [rel res_read_req + 0], 0
    mov  qword [rel res_read_req + 8], 0
    mov  qword [rel res_read_req + 16], 0
    mov  qword [rel res_read_req + 24], 0
    mov  qword [rel res_read_req + 32], 0
    mov  qword [rel res_read_req + 40], 0
    mov  qword [rel res_read_req + 48], 0
.done:
    ret

; Canonical u64 decimal; rejects overflow, empty and leading-zero forms. RDX
; value, RDI delimiter, EAX success. Bounded by the earlier native NUL extent.
har_dec:
    xor  edx, edx
    cmp  byte [rdi], '0'
    jne  .digits
    inc  rdi
    mov  eax, 1
    ret
.digits:
    xor  ecx, ecx
.next:
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 9
    ja   .end
    mov  r8, 1844674407370955161
    cmp  rdx, r8
    ja   .no
    jne  .add
    cmp  eax, 5
    ja   .no
.add:
    imul rdx, rdx, 10
    add  rdx, rax
    inc  rdi
    inc  ecx
    jmp  .next
.end:
    xor  eax, eax
    test ecx, ecx
    setnz al
    ret
.no:
    xor  eax, eax
    ret

har_aer_record:
    push rbx
    push r13
    lea  rsi, [rel str_har_head]
    call hpc_literal
    test eax, eax
    jz   .no
    mov  r13, rdi
    lea  rbx, [rel har_classes]
.class:
    mov  rdi, r13
    mov  rsi, [rbx]
    add  rsi, rbx                       ; row-relative label at the live image base
    call hpc_literal
    test eax, eax
    jnz  .bdf
    add  rbx, 8
    cmp  qword [rbx], 0
    jne  .class
    jmp  .no
.bdf:
    lea  rsi, [rel str_har_bdf]
    call hpc_literal
    test eax, eax
    jz   .no
    xor  edx, edx
    xor  ecx, ecx
    mov  r13, rdi
.hex:
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 9
    jbe  .digit
    sub  eax, 'a' - '0'
    cmp  eax, 5
    ja   .hex_end
    add  eax, 10
.digit:
    cmp  ecx, 16
    jae  .no
    shl  rdx, 4
    or   rdx, rax
    inc  rdi
    inc  ecx
    jmp  .hex
.hex_end:
    test ecx, ecx
    jz   .no
    cmp  ecx, 1
    je   .bdf_value
    cmp  byte [r13], '0'
    je   .no
.bdf_value:
    cmp  rdx, -1
    je   .tag
    mov  rax, rdx
    and  rax, 0xffffffffff00e0f8       ; only bus8/dev5/fn3 in separate bytes
    jnz  .no
.tag:
    lea  rsi, [rel str_har_tag]
    call hpc_literal
    test eax, eax
    jz   .no
    ; Last count separator permits printable tags containing ' count='.
    mov  r13, rdi
    xor  ebx, ebx
.scan:
    movzx eax, byte [rdi]
    test al, al
    jz   .tag_end
    cmp  al, 32
    jb   .no
    cmp  al, 126
    ja   .no
    lea  rdx, [rdi + 7]
    cmp  rdx, [rel res_out_cur]
    ja   .next
    cmp  dword [rdi], ' cou'
    jne  .next
    cmp  word [rdi + 4], 'nt'
    jne  .next
    cmp  byte [rdi + 6], '='
    jne  .next
    mov  rbx, rdi
.next:
    inc  rdi
    jmp  .scan
.tag_end:
    test rbx, rbx
    jz   .no
    mov  rax, rbx
    sub  rax, r13
    cmp  rax, 31
    ja   .no
    lea  rdi, [rbx + 7]
    call har_dec
    test eax, eax
    jz   .no
    mov  rbx, rdx
    lea  rsi, [rel str_har_count_q]
    call hpc_literal
    test eax, eax
    jz   .no
    lea  rsi, [rel str_har_exact]
    cmp  rbx, -1
    jne  .quality
    lea  rsi, [rel str_har_lower]
.quality:
    call hpc_literal
    test eax, eax
    jz   .no
    cmp  byte [rdi], 0
    jne  .no
    mov  [rel har_count], rbx
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r13
    pop  rbx
    ret

har_cto_record:
    lea  rsi, [rel str_har_native_cto]
    call hpc_literal
    test eax, eax
    jz   .no
    call har_dec
    test eax, eax
    jz   .no
    cmp  rdx, 10000
    je   .timeout
    cmp  rdx, 50000
    je   .timeout
    cmp  rdx, 210000
    jne  .no
.timeout:
    mov  [rel har_timeout], rdx
    lea  rsi, [rel str_har_ports]
    call hpc_literal
    test eax, eax
    jz   .no
    call har_dec
    test eax, eax
    jz   .no
    cmp  rdx, 256                    ; actual producer scans bus0, 32*8 functions
    ja   .no
    mov  [rel har_ports], rdx
    lea  rsi, [rel str_har_native_applied]
    call hpc_literal
    test eax, eax
    jz   .no
    call har_dec
    test eax, eax
    jz   .no
    cmp  rdx, 1
    ja   .no
    cmp  byte [rdi], 0
    jne  .no
    mov  [rel har_applied], rdx
    test edx, edx
    jz   .yes
    cmp  qword [rel har_ports], 0
    je   .no
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

str_har_count_q: db " count_q=", 0
str_har_exact: db "exact", 0
str_har_lower: db "lower_bound", 0
str_har_head: db "aer_last class=", 0
str_har_bdf: db " bdf=0x", 0
str_har_tag: db " tag=", 0
str_har_native_cto: db "cto=on timeout_us=", 0
str_har_native_applied: db " applied=", 0
str_har_ports: db " rootports=", 0
str_har_applied: db " applied_any=", 0
str_har_coverage: db " coverage=unknown", 0
str_har_empty: db " aer v=1 scope=saved-software captured=0 count=0 count_q=exact", 0
str_har_saved: db " aer v=1 scope=saved-software captured=1 ", 0
str_har_cto: db " aer v=1 scope=configured-software timeout_us=", 0
str_har_bad: db " hook err=aer_reply_incomplete", 0
str_har_class_corr: db "correctable", 0
str_har_class_uncorr: db "uncorr-nonfatal", 0
str_har_class_cto: db "completion-timeout", 0
str_har_class_fatal: db "fatal", 0
align 8
; Each class entry is relative to its own qword; flat org0 images have no
; runtime relocation for an absolute dq label. The zero sentinel stays zero.
har_classes:
    dq str_har_class_corr - $
    dq str_har_class_uncorr - $
    dq str_har_class_cto - $
    dq str_har_class_fatal - $
    dq 0
har_count: dq 0
har_timeout: dq 0
har_ports: dq 0
har_applied: dq 0
har_pending: db 0

; Passive lid/button selector state; no publication survives the post lifetime.
hlb_pending: db 0
str_hlb_lid: db " power v=1 observation=lid backend=",0
str_hlb_button: db " power v=1 observation=button backend=",0
str_hlb_ec: db "ec",0
str_hlb_unsupported_backend: db "unsupported",0
str_hlb_support: db " support=",0
str_hlb_state: db " state=",0
str_hlb_unknown: db "unknown",0
str_hlb_open: db "open",0
str_hlb_closed: db "closed",0
str_hlb_events: db " events=",0
str_hlb_presses: db " presses=",0
str_hlb_untracked: db " freshness=untracked age_ms=unknown",0
str_hlb_unsupported: db " freshness=unsupported age_ms=unknown",0
str_hlb_lid_tail: db " scope=saved-software",0
str_hlb_button_tail: db " scope=latched-software-counter action=unobserved",0

; audio:<explicit-u16-epoch> stat | pin <u16-row> | node <u16-row> | edge <u16-row>.
; GET never acquires/selects/runs/reads/releases an owner or performs hardware IO.
; CANCEL delegates owned WAV cancellation. SET play admits an existing-owner
; WAV job only; no file read, producer tick, implicit owner or acoustic claim.
hook_hda_plan:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12, rsi
    mov  r13, rdx
    call hlc_diagnostic_retire
    call hook_wav_info_retire
    mov  byte [rel hhd_pending], 0
    cmp  ebx, HOP_CANCEL
    je   .cancel
    cmp  ebx, HOP_SET
    je   .play
    cmp  ebx, HOP_GET
    jne  .na
    cmp  byte [r12], 0
    jne  .hda
    mov  rdi, r13
    call hook_wav_info_plan
    jmp  .out
.play:
    cmp  byte [r12], 0
    jne  .bad
    mov  rdi, r13
    call hook_wav_play_plan
    jmp  .out
.cancel:
    cmp  byte [r12], 0
    jne  .bad
    cmp  byte [r13], 0
    jne  .bad
    call command_hook_arg_reset
    lea  rdi, [rel hwp_cancel]
    call command_hook_arg_str
    mov  byte [rel hwp_pending], 2
    lea  rax, [rel hwp_verb]
    jmp  .out
.hda:
    mov  rdi, r12
    call har_dec
    test eax, eax
    jz   .bad
    cmp  rdx, 65535
    ja   .bad
    cmp  byte [rdi], 0
    jne  .bad
    mov  [rel hhd_epoch], rdx
    xor  ebx, ebx
    lea  r12, [rel hhd_selectors]
.selector:
    mov  rdi, r13
    movsxd rsi, dword [r12 + rbx*4]
    add  rsi, r12
    call command_hook_after_word
    test rax, rax
    jnz  .found
    inc  ebx
    cmp  ebx, 4
    jb   .selector
    jmp  .bad
.found:
    mov  qword [rel hhd_row], 0
    test ebx, ebx
    jz   .stat
    mov  rdi, rax
    call har_dec
    test eax, eax
    jz   .bad
    cmp  rdx, 65535
    ja   .bad
    cmp  byte [rdi], 0
    jne  .bad
    mov  [rel hhd_row], rdx
    jmp  .args
.stat:
    cmp  byte [rax], 0
    jne  .bad
.args:
    mov  [rel hhd_selected], ebx
    lea  rax, [rel hhd_opcodes]
    mov  eax, [rax + rbx*4]
    mov  [rel hhd_opcode], eax
    call command_hook_arg_reset
    lea  rax, [rel hhd_native_names]
    movsxd rdi, dword [rax + rbx*4]
    add  rdi, rax
    call command_hook_arg_str
    lea  rdi, [rel str_hhd_space]
    call command_hook_arg_str
    mov  rdi, [rel hhd_epoch]
    call command_hook_arg_dec
    test ebx, ebx
    jz   .planned
    lea  rdi, [rel str_hhd_space]
    call command_hook_arg_str
    mov  rdi, [rel hhd_row]
    call command_hook_arg_dec
.planned:
    mov  byte [rel hhd_pending], 1
    lea  rax, [rel str_hhd_verb]
    jmp  .out
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

hook_hda_post:
    cmp  byte [rel hwp_pending], 1
    je   hook_wav_info_post
    cmp  byte [rel hwp_pending], 2
    je   hook_wav_cancel_post
    cmp  byte [rel hwp_pending], 3
    je   hook_wav_play_post
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov  rbx, rcx
    cmp  byte [rel hhd_pending], 1
    jne  .bad
    ; Registry denial may not have entered the producer. Preserve its refusal.
    cmp  byte [rel hlc_diag_valid], 1
    jne  .no_producer
    cmp  byte [rel hdaloop_out_ready], 1
    jne  .bad
    lea  rdi, [rel hlc_diag_req]
    call command_hook_request_matches
    test eax, eax
    jz   .bad
    lea  rsi, [rel command_hook_arg]
    lea  rdi, [rel hlc_diag_arg]
    xor  ecx, ecx
.arg:
    cmp  ecx, 32
    jae  .bad
    mov  al, [rdi + rcx]
    cmp  al, [rsi + rcx]
    jne  .bad
    test al, al
    jz   .extent
    inc  ecx
    jmp  .arg
.extent:
    lea  rdi, [rel hdaloop_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, 1050
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel hlc_diag_end]
    jne  .bad
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  qword [rbx + RSP_ACCEPTED], 1
    jne  .bad
    cmp  dword [rdi], 'HL1 '
    jne  .bad
    add  rdi, 4
    xor  r12d, r12d
.number:
    call har_dec
    test eax, eax
    jz   .bad
    cmp  byte [rdi], ' '
    jne  .bad
    ; Only epoch, serial and frame counters are native qwords.
    cmp  r12d, 5
    je   .width_ok
    cmp  r12d, 7
    je   .width_ok
    cmp  r12d, 9
    je   .width_ok
    cmp  r12d, 10
    je   .width_ok
    mov  rax, rdx
    shr  rax, 32
    jnz  .bad
.width_ok:
    lea  rax, [rel hhd_values]
    mov  [rax + r12*8], rdx
    inc  rdi
    inc  r12d
    cmp  r12d, 15
    jne  .after_build
    lea  rsi, [rel paos_build_hex]
    xor  ecx, ecx
.build:
    mov  al, [rdi + rcx]
    cmp  al, [rsi + rcx]
    jne  .bad
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    jbe  .hex
    cmp  al, 'a'
    jb   .bad
    cmp  al, 'f'
    ja   .bad
.hex:
    inc  ecx
    cmp  ecx, 64
    jb   .build
    cmp  byte [rsi + 64], 0
    jne  .bad
    cmp  byte [rdi + 64], ' '
    jne  .bad
    add  rdi, 65
.after_build:
    mov  eax, [rel hhd_selected]
    lea  rdx, [rel hhd_counts]
    cmp  r12d, [rdx + rax*4]
    jb   .number
    cmp  byte [rdi], 0
    jne  .bad
    mov  eax, [rel hhd_opcode]
    cmp  [rel hhd_values], rax
    jne  .bad
    mov  rax, [rel hhd_epoch]
    cmp  [rel hhd_values + 5*8], rax
    jne  .bad
    mov  eax, [rel boot_nonce]
    cmp  [rel hhd_values + 14*8], rax
    jne  .bad
    cmp  qword [rel hhd_values + 13*8], 1
    jne  .bad
    cmp  qword [rel hhd_values + 12*8], 44100
    jne  .bad
    cmp  dword [rel hhd_selected], 3
    jne  .format
    mov  rax, [rel hhd_row]
    cmp  [rel hhd_values + 24*8], rax ; EDGE alone echoes its row index
    jne  .bad
.format:
    call command_hook_out_reset
    lea  rdi, [rel str_hhd_head]
    call command_hook_out_str
    lea  rdi, [rel str_hhd_epoch]
    call command_hook_out_str
    mov  rdi, [rel hhd_epoch]
    call command_hook_out_dec
    lea  rdi, [rel str_hhd_row]
    call command_hook_out_str
    mov  rdi, [rel hhd_row]
    call command_hook_out_dec
    lea  r13, [rel hhd_keys]
    xor  r14d, r14d
.fields:
    movsxd rdi, dword [r13 + r14*4]
    add  rdi, r13
    call command_hook_out_str
    lea  rax, [rel hhd_values]
    mov  rdi, [rax + r14*8]
    call command_hook_out_dec
    inc  r14d
    cmp  r14d, 23
    jb   .fields
    lea  rdi, [rel str_hhd_build]
    call command_hook_out_str
    lea  rdi, [rel paos_build_hex]
    call command_hook_out_str
    mov  eax, [rel hhd_selected]
    mov  ecx, eax
    lea  r13, [rel hhd_row_keys]
    movsxd rax, dword [r13 + rax*4]
    add  r13, rax
    lea  rdx, [rel hhd_counts]
    mov  ebp, [rdx + rcx*4]
.row_fields:
    cmp  r14d, ebp
    jae  .success
    movsxd rdi, dword [r13]
    lea  rax, [rel hhd_keys]
    add  rdi, rax
    call command_hook_out_str
    lea  rax, [rel hhd_values]
    mov  rdi, [rax + r14*8]
    call command_hook_out_dec
    add  r13, 4
    inc  r14d
    jmp  .row_fields
.success:
    mov  ebp, 1
    jmp  .clear
.refused:
    ; Complete distinct HLR1 refusal, bound to the same request and extent.
    cmp  ecx, 8
    jne  .bad
    cmp  dword [rdi], 'HLR1'
    jne  .bad
    cmp  byte [rdi + 4], ' '
    jne  .bad
    movzx eax, byte [rdi + 5]
    sub  eax, '0'
    cmp  eax, CMDE_BADARG
    je   .refusal_code
    cmp  eax, CMDE_AUTHDENY
    jne  .bad
.refusal_code:
    cmp  [rbx + RSP_CODE], rax
    jne  .bad
    cmp  word [rdi + 6], ' 0'
    jne  .bad
    cmp  qword [rbx + RSP_ACCEPTED], 0
    jne  .bad
    call command_hook_out_reset
    lea  rdi, [rel str_hhd_refused]
    call command_hook_out_str
    mov  rdi, [rbx + RSP_CODE]
    call command_hook_out_dec
    mov  ebp, 1
    jmp  .clear
.no_producer:
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    je   .bad
    xor  ebp, ebp                         ; original registry refusal owns reply
    jmp  .clear
.bad:
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    mov  qword [rbx + RSP_VAL], 0
    lea  rax, [rel str_hhd_bad]
    mov  [rbx + RSP_HINT], rax
    call command_hook_out_reset
    lea  rdi, [rel str_hhd_bad]
    call command_hook_out_str
    mov  ebp, 1
.clear:
    call hlc_diagnostic_retire
    call hook_wav_info_retire
    mov  byte [rel hhd_pending], 0
    lea  rdi, [rel hhd_values]
    xor  esi, esi
    mov  edx, 32*8
    call memset
    mov  eax, ebp
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

str_hhd_audio: db "audio",0
str_hhd_verb: db "HDALOOP",0
str_hhd_schema: db "v=1 common=op,owner_phase,owner_error,loop_phase,loop_error,native_epoch,bdf,serial,pin_count,played,captured,channels,rate,format,boot,route0..7,build pin=codec,group,nid,caps,pin_caps,config,sense,known,query node=node_count,codec,group,nid,caps,pin_caps,config,conn_len,reserved edge=edge_count,edge_index,codec,group,nid,connection_index,target,reserved route=codec,AFG,outpin,DAC,inpin,ADC,input_channels,VRef inst=explicit-u16-epoch get=stat|pin row|node row|edge row row=u16+native-count authority=HDALOOP-owner+MUTATE native-phase-epoch-row-gates=decisive record=complete-HL1 fields=u32-except-epoch-serial-played-captured:u64 observe=whole-selected-diagnostic scope=saved-software acoustic-evidence=no playback=get:playback+16lowerhexnonce,WPI1,v2,software-only list=na set=WAVPLAY-play(1|2,absolute-path;native-owner;admission-only) input=na cancel=WAVPLAY-CANCEL(inst=none,args=none;native-bound-owner;state=cleanup|retired;software-only)",0
str_hhd_head: db " audio v=1 scope=saved-software acoustic_evidence=0",0
str_hhd_space: db " ",0
str_hhd_epoch: db " epoch=",0
str_hhd_row: db " row=",0
str_hhd_build: db " build=",0
str_hhd_bad: db " hook err=audio_reply_incomplete",0
str_hhd_refused: db " audio v=1 accepted=0 refused=1 code=",0
hhd_STAT: db "STAT",0
hhd_PIN: db "PIN",0
hhd_NODE: db "NODE",0
hhd_EDGE: db "EDGE",0
align 8
hhd_selectors: dd hhd_STAT-hhd_selectors,hhd_PIN-hhd_selectors,hhd_NODE-hhd_selectors,hhd_EDGE-hhd_selectors
hhd_native_names: dd hhd_STAT-hhd_native_names,hhd_PIN-hhd_native_names,hhd_NODE-hhd_native_names,hhd_EDGE-hhd_native_names
hhd_opcodes: dd 2,3,9,10
hhd_counts: dd 23,32,32,31
hhd_key_op: db " op=",0
hhd_key_owner_phase: db " owner_phase=",0
hhd_key_owner_error: db " owner_error=",0
hhd_key_loop_phase: db " loop_phase=",0
hhd_key_loop_error: db " loop_error=",0
hhd_key_native_epoch: db " native_epoch=",0
hhd_key_bdf: db " bdf=",0
hhd_key_serial: db " serial=",0
hhd_key_pin_count: db " pin_count=",0
hhd_key_played: db " played=",0
hhd_key_captured: db " captured=",0
hhd_key_channels: db " channels=",0
hhd_key_rate: db " rate=",0
hhd_key_format: db " format=",0
hhd_key_boot: db " boot=",0
hhd_key_route0: db " route0=",0
hhd_key_route1: db " route1=",0
hhd_key_route2: db " route2=",0
hhd_key_route3: db " route3=",0
hhd_key_route4: db " route4=",0
hhd_key_route5: db " route5=",0
hhd_key_route6: db " route6=",0
hhd_key_route7: db " route7=",0
hhd_key_codec: db " codec=",0
hhd_key_group: db " group=",0
hhd_key_nid: db " nid=",0
hhd_key_caps: db " caps=",0
hhd_key_pin_caps: db " pin_caps=",0
hhd_key_config: db " config=",0
hhd_key_sense: db " sense=",0
hhd_key_known: db " known=",0
hhd_key_query: db " query=",0
hhd_key_node_count: db " node_count=",0
hhd_key_conn_len: db " conn_len=",0
hhd_key_reserved: db " reserved=",0
hhd_key_edge_count: db " edge_count=",0
hhd_key_edge_index: db " edge_index=",0
hhd_key_connection_index: db " connection_index=",0
hhd_key_target: db " target=",0
align 4
hhd_keys: dd hhd_key_op-hhd_keys,hhd_key_owner_phase-hhd_keys,hhd_key_owner_error-hhd_keys,hhd_key_loop_phase-hhd_keys,hhd_key_loop_error-hhd_keys,hhd_key_native_epoch-hhd_keys,hhd_key_bdf-hhd_keys,hhd_key_serial-hhd_keys,hhd_key_pin_count-hhd_keys,hhd_key_played-hhd_keys,hhd_key_captured-hhd_keys,hhd_key_channels-hhd_keys,hhd_key_rate-hhd_keys,hhd_key_format-hhd_keys,hhd_key_boot-hhd_keys,hhd_key_route0-hhd_keys,hhd_key_route1-hhd_keys,hhd_key_route2-hhd_keys,hhd_key_route3-hhd_keys,hhd_key_route4-hhd_keys,hhd_key_route5-hhd_keys,hhd_key_route6-hhd_keys,hhd_key_route7-hhd_keys
hhd_row_keys: dd hhd_row0-hhd_row_keys,hhd_row1-hhd_row_keys,hhd_row2-hhd_row_keys,hhd_row3-hhd_row_keys
hhd_row0: dd 0
hhd_row1: dd hhd_key_codec-hhd_keys,hhd_key_group-hhd_keys,hhd_key_nid-hhd_keys,hhd_key_caps-hhd_keys,hhd_key_pin_caps-hhd_keys,hhd_key_config-hhd_keys,hhd_key_sense-hhd_keys,hhd_key_known-hhd_keys,hhd_key_query-hhd_keys
hhd_row2: dd hhd_key_node_count-hhd_keys,hhd_key_codec-hhd_keys,hhd_key_group-hhd_keys,hhd_key_nid-hhd_keys,hhd_key_caps-hhd_keys,hhd_key_pin_caps-hhd_keys,hhd_key_config-hhd_keys,hhd_key_conn_len-hhd_keys,hhd_key_reserved-hhd_keys
hhd_row3: dd hhd_key_edge_count-hhd_keys,hhd_key_edge_index-hhd_keys,hhd_key_codec-hhd_keys,hhd_key_group-hhd_keys,hhd_key_nid-hhd_keys,hhd_key_connection_index-hhd_keys,hhd_key_target-hhd_keys,hhd_key_reserved-hhd_keys
%macro WDATA_hhd 0
hook_edge_audio: times (HE_SZ/8) dq 0
hhd_pending: db 0
align 8
hhd_epoch: dq 0
hhd_row: dq 0
hhd_opcode: dd 0
hhd_selected: dd 0
hhd_values: times 32 dq 0
%endmacro
WDATA_DEFER WDATA_hhd

; Exact SET audio play <1|2> <absolute, non-space ASCII path>. The
; native argument is at most223 bytes plus NUL, matching the common bound.
; Native VFS/stat, selected owner and session decide admission; no owner setup.
hook_wav_play_plan:
    push rbx
    lea  rsi, [rel hwp_play_selector]
    call hpc_literal
    test eax, eax
    jz   .bad
    mov  rbx, rdi
    movzx eax, byte [rbx]
    sub  eax, '1'
    cmp  eax, 1
    ja   .bad
    cmp  byte [rbx + 1], ' '
    jne  .bad
    cmp  byte [rbx + 2], '/'
    jne  .bad
    mov  ecx, 2
.path:
    cmp  ecx, 224
    jae  .bad
    movzx eax, byte [rbx + rcx]
    test al, al
    jz   .planned
    cmp  al, 33
    jb   .bad
    cmp  al, 126
    ja   .bad
    inc  ecx
    jmp  .path
.planned:
    call command_hook_arg_reset
    mov  rdi, rbx
    call command_hook_arg_str
    mov  byte [rel hwp_pending], 3
    lea  rax, [rel hwp_verb]
    pop  rbx
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    pop  rbx
    ret

; A synchronous native acceptance denotes job admission only. Bind its full
; scalar epoch to the current native owner; never infer playback or sound.
; Refusals keep their code and use constants, never a native hint pointer.
hook_wav_play_post:
    push rbx
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  qword [rbx + RSP_ACCEPTED], 1
    jne  .bad
    mov  rax, [rel hln_epoch]
    cmp  [rbx + RSP_VAL], rax
    jne  .bad
    call command_hook_out_reset
    lea  rdi, [rel hwp_play_accepted]
    call command_hook_out_str
    mov  rdi, [rbx + RSP_VAL]
    call command_hook_out_dec
    jmp  .tail
.bad:
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    lea  rax, [rel hwp_play_bad]
    mov  [rbx + RSP_HINT], rax
.refused:
    mov  qword [rbx + RSP_ACCEPTED], 0
    call command_hook_out_reset
    lea  rdi, [rel hwp_play_refused]
    call command_hook_out_str
    mov  rdi, [rbx + RSP_CODE]
    call command_hook_out_dec
.tail:
    lea  rdi, [rel hwp_tail]
    call command_hook_out_str
    call hook_wav_info_retire
    mov  qword [rbx + RSP_VAL], 0
    mov  eax, 1
    pop  rbx
    ret

; Current synchronous cancellation result from the SAME common native dispatch.
; No new native owner lookup, step or INFO operation: WAVPLAY itself decides
; admitted session/epoch/hook identity and verified backend retirement. Scalar6
; means cleanup requested; scalar4 means retired, never playback/acoustic success.
hook_wav_cancel_post:
    push rbx
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  qword [rbx + RSP_ACCEPTED], 1
    jne  .bad
    cmp  qword [rbx + RSP_VAL], 6
    je   .cleanup
    cmp  qword [rbx + RSP_VAL], 4
    jne  .bad
    lea  rdi, [rel hwp_cancel_retired]
    jmp  .copy
.cleanup:
    lea  rdi, [rel hwp_cancel_cleanup]
.copy:
    push rdi
    sub  rsp, 8
    call command_hook_out_reset
    add  rsp, 8
    pop  rdi
    call command_hook_out_str
    call hook_wav_info_retire
    mov  qword [rbx + RSP_VAL], 0
    mov  eax, 1
    pop  rbx
    ret
.bad:
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel hwp_cancel_bad]
    mov  [rbx + RSP_HINT], rax
.refused:
    ; Keep the actual registry/native refusal; never claim cleanup/retirement.
    call hook_wav_info_retire
    mov  qword [rbx + RSP_VAL], 0
    xor  eax, eax
    pop  rbx
    ret

; Owned WAV observation on the SAME audio descriptor. The sole common nested
; dispatcher calls registered WAVPLAY INFO under original owner/MUTATE/session
; authority. INFO, unlike STAT, never advances work or detaches its callback.
; Empty instance only; explicit epoch diagnostics above retain their contract.
hook_wav_info_plan:
    push rbx
    lea  rsi, [rel hwp_selector]
    call hpc_literal
    test eax, eax
    jz   .bad
    mov  rbx, rdi
    xor  ecx, ecx
.hex:
    mov  al, [rbx + rcx]
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    jbe  .digit
    cmp  al, 'a'
    jb   .bad
    cmp  al, 'f'
    ja   .bad
.digit:
    inc  ecx
    cmp  ecx, 16
    jb   .hex
    cmp  byte [rbx + 16], 0
    jne  .bad
    lea  rdi, [rel hwp_nonce]
    mov  rsi, rbx
    mov  ecx, 17
    rep movsb
    call command_hook_arg_reset
    lea  rdi, [rel hwp_info]
    call command_hook_arg_str
    lea  rdi, [rel hwp_nonce]
    call command_hook_arg_str
    mov  byte [rel hwp_pending], 1
    lea  rax, [rel hwp_verb]
    pop  rbx
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    pop  rbx
    ret

; Retire request text only, never the WAV allocation/native owner/media state.
hook_wav_info_retire:
    push rbx
    call command_wav_info_retire
    mov  byte [rel hwp_pending], 0
    mov  qword [rel hwp_body], 0
    lea  rdi, [rel hwp_nonce]
    xor  esi, esi
    mov  edx, 17
    call memset
    lea  rdi, [rel hwp_values]
    xor  esi, esi
    mov  edx, 18*8
    call memset
    pop  rbx
    ret

hook_wav_info_post:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov  rbx, rcx
    cmp  byte [rel hwp_pending], 1
    jne  .bad
    ; Consume the REAL native one-use boundary on every outcome, including a
    ; dispatcher refusal that did not enter the producer. Native code decides
    ; original session/full64 epoch/controller/map identity before publication.
    lea  rdi, [rel command_hook_arg]
    mov  rsi, rbx
    call command_wav_info_take
    mov  r12, rax
    mov  [rel hwp_body], rax
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    test r12, r12
    jz   .bad
    mov  rdi, r12
    lea  rsi, [rel hwp_head]
    call hpc_literal
    test eax, eax
    jz   .bad
    xor  ecx, ecx
.nonce:
    lea  rdx, [rel hwp_nonce]
    mov  al, [rdx + rcx]
    cmp  al, [rdi + rcx]
    jne  .bad
    inc  ecx
    cmp  ecx, 16
    jb   .nonce
    add  rdi, 16
    lea  r13, [rel hwp_keys]
    xor  r14d, r14d
.field:
    cmp  r14d, 3
    jne  .number
    lea  rsi, [rel hwp_stage]
    call hpc_literal
    test eax, eax
    jz   .bad
    ; Enum is bounded and tied to the exact response scalar below.
    xor  ebp, ebp
    mov  r12, rdi
.enum:
    lea  rax, [rel hwp_stages]
    movsxd rsi, dword [rax + rbp*4]
    add  rsi, rax
    mov  rdi, r12
    call hpc_literal
    test eax, eax
    jz   .next_enum
    cmp  byte [rdi], ' '
    je   .number
.next_enum:
    inc  ebp
    cmp  ebp, 7
    jb   .enum
    jmp  .bad
.number:
    movsxd rsi, dword [r13 + r14*4]
    add  rsi, r13
    call hpc_literal
    test eax, eax
    jz   .bad
    call har_dec
    test eax, eax
    jz   .bad
    cmp  byte [rdi], ' '
    jne  .bad
    lea  rax, [rel hwp_values]
    mov  [rax + r14*8], rdx
    inc  r14d
    cmp  r14d, 18
    jb   .field
    lea  rsi, [rel hwp_tail]
    call hpc_literal
    test eax, eax
    jz   .bad
    cmp  byte [rdi], 0
    jne  .bad
    ; Native u32 fields retain their declared width, all others full u64.
    lea  rdx, [rel hwp_values]
    lea  rsi, [rel hwp_u32]
    mov  ecx, 6
.width:
    movzx eax, byte [rsi]
    mov  rax, [rdx + rax*8]
    shr  rax, 32
    jnz  .bad
    inc  rsi
    loop .width
    mov  rax, [rdx + 3*8]
    cmp  rax, 7
    ja   .bad
    cmp  rax, [rbx + RSP_VAL]
    jne  .bad
    ; Retained native identity also binds the complete parsed record. These
    ; comparisons add no authority: the actual INFO gate has already accepted.
    mov  rcx, [rel hln_epoch]
    cmp  [rdx], rcx
    jne  .bad
    mov  ecx, [rel hln_bdf]
    cmp  [rdx + 8], rcx
    jne  .bad
    mov  rcx, [rel hln_serial]
    cmp  [rdx + 2*8], rcx
    jne  .bad
    ; accepted=0; preparing=0..3; playing=3; terminal names exact stage IDs.
    cmp  ebp, 1
    jne  .fixed_stage
    cmp  eax, 3
    ja   .bad
    jmp  .flags
.fixed_stage:
    lea  rcx, [rel hwp_stage_ids]
    movzx ecx, byte [rcx + rbp]
    cmp  eax, ecx
    jne  .bad
.flags:
    xor  ecx, ecx
    cmp  qword [rdx + 8*8], 0
    setne cl
    cmp  [rdx + 7*8], rcx
    jne  .bad
    xor  ecx, ecx
    cmp  eax, 6
    sete cl
    cmp  [rdx + 15*8], rcx
    jne  .bad
    xor  ecx, ecx
    cmp  eax, 4
    sete cl
    cmp  [rdx + 16*8], rcx
    jne  .bad
    xor  ecx, ecx
    cmp  eax, 7
    sete cl
    cmp  [rdx + 17*8], rcx
    jne  .bad
    ; Complete native grammar has been validated. Copy to caller-owned typed
    ; bytes before retirement; whole reply witnesses retain nonce/full identity.
    call command_hook_out_reset
    lea  rdi, [rel hwp_typed]
    call command_hook_out_str
    mov  rdi, [rel hwp_body]
    add  rdi, 5                    ; validated nonce=... through exact suffix
    call command_hook_out_str
    mov  ebp, 1
    jmp  .clear
.refused:
    xor  ebp, ebp                  ; retain native/registry error code and hint
    jmp  .clear
.bad:
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hhd_bad]
    mov  [rbx + RSP_HINT], rax
    call command_hook_out_reset
    lea  rdi, [rel str_hhd_bad]
    call command_hook_out_str
    mov  ebp, 1
.clear:
    mov  qword [rbx + RSP_VAL], 0
    call hook_wav_info_retire
    mov  eax, ebp
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

hwp_selector: db "playback ",0
hwp_info: db "INFO ",0
hwp_play_selector: db "play ",0
hwp_play_accepted: db " audio v=4 view=play state=accepted epoch=",0
hwp_play_refused: db " audio v=4 view=play state=refused code=",0
hwp_play_bad: db "audio invalid_native_play",0
hwp_cancel: db "CANCEL",0
hwp_cancel_cleanup: db " audio v=3 view=cancel state=cleanup scope=software acoustic=unverified",0
hwp_cancel_retired: db " audio v=3 view=cancel state=retired scope=software acoustic=unverified",0
hwp_cancel_bad: db "audio invalid_native_cancel",0
hwp_verb: db "WAVPLAY",0
hwp_head: db "WPI1 nonce=",0
hwp_stage: db " stage=",0
hwp_tail: db " scope=software acoustic=unverified",0
hwp_typed: db " audio v=2 view=playback ",0
hwp_accepted: db "accepted",0
hwp_preparing: db "preparing",0
hwp_playing: db "playing",0
hwp_retired: db "retired",0
hwp_fault: db "fault",0
hwp_cleanup: db "cleanup",0
hwp_uncertain: db "uncertain",0
align 4
hwp_stages: dd hwp_accepted-hwp_stages,hwp_preparing-hwp_stages,hwp_playing-hwp_stages,hwp_retired-hwp_stages,hwp_fault-hwp_stages,hwp_cleanup-hwp_stages,hwp_uncertain-hwp_stages
hwp_stage_ids: db 0,0,3,4,5,6,7
hwp_u32: db 1,3,4,9,13,14
hwp_key_epoch: db " epoch=",0
hwp_key_controller: db " controller=",0
hwp_key_serial: db " serial=",0
hwp_key_stage_id: db " stage_id=",0
hwp_key_error: db " error=",0
hwp_key_loaded: db " loaded=",0
hwp_key_size: db " size=",0
hwp_key_frames_known: db " frames_known=",0
hwp_key_frames: db " frames=",0
hwp_key_producer_phase: db " producer_phase=",0
hwp_key_decoded_bytes: db " decoded_bytes=",0
hwp_key_prepared: db " prepared=",0
hwp_key_submitted: db " submitted=",0
hwp_key_loop: db " loop=",0
hwp_key_backend: db " backend=",0
hwp_key_cleanup: db " cleanup=",0
hwp_key_retired: db " retired=",0
hwp_key_uncertain: db " uncertain=",0
align 4
hwp_keys: dd hwp_key_epoch-hwp_keys,hwp_key_controller-hwp_keys,hwp_key_serial-hwp_keys,hwp_key_stage_id-hwp_keys,hwp_key_error-hwp_keys,hwp_key_loaded-hwp_keys,hwp_key_size-hwp_keys,hwp_key_frames_known-hwp_keys,hwp_key_frames-hwp_keys,hwp_key_producer_phase-hwp_keys,hwp_key_decoded_bytes-hwp_keys,hwp_key_prepared-hwp_keys,hwp_key_submitted-hwp_keys,hwp_key_loop-hwp_keys,hwp_key_backend-hwp_keys,hwp_key_cleanup-hwp_keys,hwp_key_retired-hwp_keys,hwp_key_uncertain-hwp_keys
%macro WDATA_wav_hook 0
hwp_pending: db 0
hwp_nonce: times 17 db 0
align 8
hwp_body: dq 0
hwp_values: times 18 dq 0
%endmacro
WDATA_DEFER WDATA_wav_hook

; Owner-only scalar snapshots. All native wrappers take exactly numeric zero,
; run through normal registry/auth dispatch and perform their own owner check.
; Native RSP_VAL is synchronous, not a shared producer buffer; no stale text is
; consulted. One pending selector survives only until that dispatch's post.
; No collector start/read/info/diagnostic-subselector or hardware path is typed.
hook_uac_status_plan:
    push rbx
    push r12
    push r13
    mov  r12, rsi
    mov  r13, rdx
    mov  byte [rel huas_pending], 0
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [r12], 0
    jne  .bad
    mov  ebx, 1
    mov  rdi, r13
    lea  rsi, [rel huas_input]
    call strcmp
    test eax, eax
    jz   .selected
    inc  ebx
    mov  rdi, r13
    lea  rsi, [rel huas_capture]
    call strcmp
    test eax, eax
    jz   .selected
    inc  ebx
    mov  rdi, r13
    lea  rsi, [rel huas_playback]
    call strcmp
    test eax, eax
    jnz  .bad
.selected:
    call command_hook_arg_reset
    xor  edi, edi
    call command_hook_arg_dec
    mov  [rel huas_pending], bl
    lea  rax, [rel huas_istat]
    cmp  ebx, 1
    je   .out
    lea  rax, [rel huas_cstat]
    cmp  ebx, 2
    je   .out
    lea  rax, [rel huas_sstat]
    jmp  .out
.bad:
    xor  eax, eax
    mov  edx, HOOK_PLAN_BADARG
    jmp  .out
.na:
    xor  eax, eax
    mov  edx, HOOK_PLAN_NA
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

hook_uac_status_post:
    push rbx
    push rbp
    push r12
    mov  rbx, rcx
    movzx ebp, byte [rel huas_pending]
    mov  byte [rel huas_pending], 0
    cmp  ebp, 1
    jb   .bad
    cmp  ebp, 3
    ja   .bad
    ; Native admission owns refusals; never turn one into a typed observation.
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    ; SSTAT is a read-only native verb: its OK envelope retains accepted=0.
    ; ISTAT/CSTAT explicitly publish accepted=1. Preserve each exact contract.
    xor  eax, eax
    cmp  ebp, 3
    setne al
    cmp  qword [rbx + RSP_ACCEPTED], rax
    jne  .bad
    mov  r12, [rbx + RSP_VAL]
    cmp  ebp, 1
    jne  .format
    mov  rax, r12
    shr  rax, 40                        ; ISTAT reserved high bits must be zero
    jnz  .bad
.format:
    call command_hook_out_reset
    lea  rdi, [rel huas_head]
    call command_hook_out_str
    lea  rdi, [rel huas_input]
    cmp  ebp, 1
    je   .selector
    lea  rdi, [rel huas_capture]
    cmp  ebp, 2
    je   .selector
    lea  rdi, [rel huas_playback]
.selector:
    call command_hook_out_str
    lea  rdi, [rel huas_phase]
    call command_hook_out_str
    movzx edi, r12b
    call command_hook_out_dec
    shr  r12, 8
    lea  rdi, [rel huas_error]
    call command_hook_out_str
    movzx edi, r12b
    call command_hook_out_dec
    shr  r12, 8
    lea  rdi, [rel huas_accepted_bytes]
    cmp  ebp, 3
    je   .count
    lea  rdi, [rel huas_sent]
    cmp  ebp, 1
    jne  .count
    lea  rdi, [rel huas_bytes]
.count:
    call command_hook_out_str
    movzx edi, r12w
    call command_hook_out_dec
    shr  r12, 16
    cmp  ebp, 1
    je   .flags
    cmp  ebp, 3
    je   .playback_tail
    lea  rdi, [rel huas_completed]
    call command_hook_out_str
    movzx edi, r12w
    call command_hook_out_dec
    shr  r12, 16
    lea  rdi, [rel huas_stage]
    jmp  .last
.playback_tail:
    lea  rdi, [rel huas_abi_state]
    call command_hook_out_str
    movzx edi, r12b
    call command_hook_out_dec
    shr  r12, 8
    lea  rdi, [rel huas_flags]
    call command_hook_out_str
    movzx edi, r12b
    call command_hook_out_dec
    shr  r12, 8
    lea  rdi, [rel huas_ticks]
    jmp  .last
.flags:
    lea  rdi, [rel huas_flags]
.last:
    call command_hook_out_str
    mov  rdi, r12
    call command_hook_out_dec
    mov  eax, 1
    jmp  .out
.refused:
    xor  eax, eax
    jmp  .out
.bad:
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    mov  qword [rbx + RSP_VAL], 0
    lea  rax, [rel huas_bad]
    mov  [rbx + RSP_HINT], rax
    call command_hook_out_reset
    lea  rdi, [rel huas_bad]
    call command_hook_out_str
    mov  eax, 1
.out:
    pop  r12
    pop  rbp
    pop  rbx
    ret

huas_name: db "uac",0
huas_schema: db "v=1 inst=none get=input-status:UAC1_ISTAT(0){phase:u8,error:u8,bytes:u16,flags:u8}|capture-status:UAC1_CSTAT(0){phase:u8,error:u8,sent:u16,completed:u16,stage:u16}|playback-status:UAC1_SSTAT(0){phase:u8,error:u8,accepted_bytes:u16,abi_state:u8,flags:u8,ticks:u16} authority=native-owner+registry observe=whole-selected-scalar scope=saved-software acoustic-evidence=no flags=opened:1,sealed:2,drained:4,closed:8,unavailable-clock-observed:16 playback-flags=opened:1,drained:2,closed:4,unavailable-presentation:8 pcm=none start=na list=na set=na input=na cancel=na",0
huas_input: db "input-status",0
huas_capture: db "capture-status",0
huas_playback: db "playback-status",0
huas_istat: db "UAC1_ISTAT",0
huas_cstat: db "UAC1_CSTAT",0
huas_sstat: db "UAC1_SSTAT",0
huas_head: db " uac v=1 scope=saved-software acoustic_evidence=0 selector=",0
huas_phase: db " phase=",0
huas_error: db " error=",0
huas_bytes: db " bytes=",0
huas_flags: db " flags=",0
huas_sent: db " sent=",0
huas_completed: db " completed=",0
huas_stage: db " stage=",0
huas_accepted_bytes: db " accepted_bytes=",0
huas_abi_state: db " abi_state=",0
huas_ticks: db " ticks=",0
huas_bad: db " hook err=uac_reply_incomplete",0
%macro WDATA_uac_status_hook 0
huas_pending: db 0
align 8
hook_edge_uac_status: times (HE_SZ/8) dq 0
%endmacro
WDATA_DEFER WDATA_uac_status_hook
