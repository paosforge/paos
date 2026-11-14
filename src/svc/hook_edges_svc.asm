;; MODULE svc/hook_edges_svc
%include "core/abi/build_profile.inc"
;; LAYER 5
;; EXPORTS hse_arg_nonce, hook_svc_edges_declare, hook_fs_plan, hook_fsjob_plan, hook_fsjob_post, hook_net_plan, hook_net_post, hook_guest_plan, hook_guest_post, hook_job_plan, hook_guestnet_plan, hook_guestnet_post, hook_block_plan, hook_block_post, hook_scheduler_plan, hook_scheduler_post, hook_rtadmit_plan, hook_rtadmit_post, hook_guestcpu_plan, hook_guestcpu_post, hook_recovery_plan, hook_recovery_post, hook_watchdog_plan, hook_watchdog_post, hook_health_plan, hook_health_post, hook_blackbox_plan, hook_blackbox_post, hook_backup_plan, hook_backup_post, hook_artifact_plan, hook_artifact_post, hook_airlock_plan, hook_airlock_post, hook_owner_plan, hook_owner_post
;; IMPORTS core/lib/fmt, svc/command, svc/command_hook, svc/command_fs, svc/command_blk, svc/command_sched, svc/command_rt, svc/command_guestcpu, svc/command_smp, svc/command_udp, hv/vmx, hv/guestnet, sec/job_receipt, svc/command_recovery_state, svc/command_software_stop, svc/command_health_verdict, svc/command_boot_blackbox, svc/command_backup, svc/command_guestfile, svc/command_airlock, svc/command_owner_stat
;; CAPS
;; OWNER saga:command
; ============================================================================
; svc/hook_edges_svc.asm -- RCQ-15 slice 2: service-layer HOOK edges.
;
;   fs      (storage)  the selected FS volume      native FSINFO / FSLS / FSSTAT / FSHASH / FSREN / FSMKDIR / FSRMDIR
;   fsjob   (job)      one FS copy job             native FSCOPY / FSJOB / FSCANCEL
;   net     (network)  the netdev members          native NETCFG MEMBERS / DHCP ONCE / STATIC
;   guest   (vm)       the Linux guest appliance   native GUESTVM STAT / EXITSTAT / PROFILES / PLAN / START / STOP / INPUT
;   job     (job)      the signed-receipt job seam native JOBPUB / JOBRUN CAP_COMPUTE <nonce>
;
; As in slice 1, an edge only PLANS a native verb and argument; svc/command_hook
; dispatches it with the caller's own source, principal, capability and
; idempotency key, so the native gate decides (the FS reads are owner MUT on
; the shipped floor, the copy-job verbs are destructive) and the FS handler's
; own admission (fs_armed_mount, the scratch classifier, the backend allowlist)
; runs unchanged. FSJOB LIST additionally validates and consumes the complete
; native discovery stage, then fits its copied facts into the bounded hook reply.
;
; Typed rules the edges add (stricter only):
;   * an fs instance is one absolute path without spaces. SET supports native
;     rename, mkdir, rmdir, create/delete/write/write_at with fresh nonce.
;     GET read <offset> <length> plans bounded FSREAD. FSFORMAT stays untyped.
;     Native owner/MUTATE,
;     armed-backend checks and canonical path bounds remain authoritative.
;   * fsjob SET takes exactly "<src> <dst>", both absolute; GET and CANCEL take
;     a decimal job id instance. LIST takes no instance/arguments and delegates
;     FSJOBS with a fresh nonce; INPUT remains unavailable;
;   * net has one instance; GET/LIST/OBSERVE are the owner's NETCFG MEMBERS
;     listing (staged by the native verb only for an owner-signed UDP request,
;     which the nested request still is), SET takes exactly dhcp | static;
;   * guest has one instance; GET/OBSERVE are GUESTVM STAT; explicit GET exitstat
;     reads retained exit counters/sample without guest work. GET guest profiles
;     and GET guest plan [<profile>] the profile reads (S4), SET takes exactly
;     start or stop, INPUT takes exactly key <1..127> or ptr <x> <y> <buttons> (S5b,
;     rc-sec 2026-10-12 11:17:34: it inherits GUESTVM's native gate, owner MUTATE remotely);
;     the diagnostic sub-verbs (VALIDATE, LAUNCH, PANIC) are not typed.
;     Its post filter (S3b) relays GUESTVM's staged hv_out_buf as the hook reply:
;     see hook_guest_post;
;   * job has one instance and no job id to read back: JOBRUN runs one metered
;     compute job synchronously and its reply is the signed receipt. SET takes
;     exactly compute (the CAP_BLOCK_WRITE negative barrier is the native KAT's,
;     not an AI operation); GET/OBSERVE are the node's receipt key (JOBPUB).
; The FS verbs echo a 16-hex request nonce. The edge supplies it from its own
; counter (a correlation token, never authority: the FS layer only echoes it),
; and the OBSERVE witness keys leave NONCE= out, so a witness changes only when
; the observed state does.
; Identities: fs (the volume FSSEL selected), fs:<abs path>, fsjob:<job id>, net, guest, job.
; ============================================================================

HSE_ID_DIGITS_MAX equ 19
HSE_HV_OUT_CAP    equ 1024                ; hv_out_buf's size (hv/vmx "hv_out_buf: resb HV_OUT_BYTES", 1024; the host suite pins it)
%define HSE_GUEST_TRUNC " hook truncated=1"
%strlen HSE_GUEST_TRUNC_LEN HSE_GUEST_TRUNC
HSE_GUEST_BODY_MAX equ HOOK_OUT_MAX - 1 - HSE_GUEST_TRUNC_LEN   ; a cut text's bound: the flag still fits
; S5b: GUESTVM INPUT's own bounds (hv/guestinput GI_KEY_MAX, hv/vm_profile VP_FB_WIDTH/HEIGHT - 1, buttons 0..7;
; the host suite pins each one to its source)
HSE_GI_DIGITS     equ 3
HSE_GI_KEY_MAX    equ 127
HSE_GI_X_MAX      equ 799
HSE_GI_Y_MAX      equ 599
HSE_GI_BTN_MAX    equ 7

; hook_svc_edges_declare -- bind the two descriptors (lea at init, ESSENCE S10)
;   and register them after the slice-1 edges. clobbers: caller-saved.
hook_svc_edges_declare:
    push rbx
    lea  rbx, [rel hook_edge_fs]
    lea  rax, [rel str_hse_fs]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hse_kind_storage]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hse_fs_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_fs_plan]
    mov  [rbx + HE_PLAN], rax
    mov  qword [rbx + HE_POST], 0
    lea  rax, [rel fs_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel fs_out_ready]
    mov  [rbx + HE_OREADY], rax
    lea  rax, [rel str_hse_fs_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_fsjob]
    lea  rax, [rel str_hse_fsjob]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hse_kind_job]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hse_fsjob_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_fsjob_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_fsjob_post]
    mov  [rbx + HE_POST], rax
    lea  rax, [rel fs_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel fs_out_ready]
    mov  [rbx + HE_OREADY], rax
    lea  rax, [rel str_hse_fsjob_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_net]
    lea  rax, [rel str_hse_net]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hse_kind_network]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hse_net_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_net_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_net_post]
    mov  [rbx + HE_POST], rax
    lea  rax, [rel netlist_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel netlist_ready]
    mov  [rbx + HE_OREADY], rax
    mov  qword [rbx + HE_WITNESS], 0      ; the whole listing (it carries no counter)
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_guest]
    lea  rax, [rel str_hse_guest]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hse_kind_vm]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hse_guest_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_guest_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_guest_post]
    mov  [rbx + HE_POST], rax
    lea  rax, [rel hv_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel hv_out_ready]
    mov  [rbx + HE_OREADY], rax
    lea  rax, [rel str_hse_guest_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_guestnet]
    lea  rax, [rel str_hgn_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hse_kind_network]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hgn_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_guestnet_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_guestnet_post]
    mov  [rbx + HE_POST], rax
    lea  rax, [rel guestnet_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel guestnet_out_ready]
    mov  [rbx + HE_OREADY], rax
    mov  qword [rbx + HE_WITNESS], 0      ; STAT advances no counters; hash the complete validated record
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_job]
    lea  rax, [rel str_hse_job]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hse_kind_job]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hse_job_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_job_plan]
    mov  [rbx + HE_PLAN], rax
    mov  qword [rbx + HE_POST], 0
    lea  rax, [rel job_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel job_out_ready]
    mov  [rbx + HE_OREADY], rax
    lea  rax, [rel str_hse_job_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register
    ; Backend identity is explicit; this adds no enumeration or storage IO verb.
    lea  rbx, [rel hook_edge_block]
    lea  rax, [rel str_hbi_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hse_kind_storage]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hbi_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_block_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_block_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0      ; whole validated inventory, no correlation field
    mov  rdi, rbx
    call command_hook_edge_register
    ; Read-only projection of cached native placement counters. No work route.
    lea  rbx, [rel hook_edge_scheduler]
    lea  rax, [rel str_hsched_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hsched_kind]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hsched_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_scheduler_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_scheduler_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0      ; complete validated snapshot only
    mov  rdi, rbx
    call command_hook_edge_register
    lea  rbx, [rel hook_edge_rtadmit]
    lea  rax, [rel str_hrt_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hrt_kind]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hrt_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_rtadmit_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_rtadmit_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0      ; whole validated reply, fixed correlation token
    mov  rdi, rbx
    call command_hook_edge_register
    lea  rbx, [rel hook_edge_guestcpu]
    lea  rax, [rel str_hgc_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hgc_kind]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hgc_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_guestcpu_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_guestcpu_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0      ; complete native fields; nonce excluded
    mov  rdi, rbx
    call command_hook_edge_register
    lea  rbx, [rel hook_edge_recovery]
    lea  rax, [rel str_hrc_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hrc_kind]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hrc_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_recovery_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_recovery_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0 ; complete cached native reply
    mov  rdi, rbx
    call command_hook_edge_register
    lea  rbx, [rel hook_edge_watchdog]
    lea  rax, [rel str_hcw_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hcw_kind]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hcw_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_watchdog_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_watchdog_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0 ; complete cached native reply
    mov  rdi, rbx
    call command_hook_edge_register
    lea  rbx, [rel hook_edge_health]
    lea  rax, [rel str_hch_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hch_kind]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hch_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_health_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_health_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0 ; complete cached native reply
    mov  rdi, rbx
    call command_hook_edge_register
    lea  rbx, [rel hook_edge_blackbox]
    lea  rax, [rel str_hbb_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hbb_kind]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hbb_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_blackbox_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_blackbox_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0 ; complete cached native reply
    mov  rdi, rbx
    call command_hook_edge_register
    ; Native-authorized BACKUP status and generation-bound cancellation.
    lea  rbx, [rel hook_edge_backup]
    lea  rax, [rel str_hbk_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hbb_kind]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hbk_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_backup_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_backup_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0 ; whole validated receipt, correlation excluded
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_artifact]
    lea  rax, [rel str_hga_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hga_kind]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hga_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_artifact_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_artifact_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0 ; complete current native reply
    mov  rdi, rbx
    call command_hook_edge_register
%if !PAOS_PUBLIC_BUILD
    lea  rbx, [rel hook_edge_airlock]
    lea  rax, [rel str_hal_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hal_kind]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hal_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_airlock_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_airlock_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0 ; complete cached native reply
    mov  rdi, rbx
    call command_hook_edge_register
%endif
    lea  rbx, [rel hook_edge_owner]
    lea  rax, [rel str_how_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_how_kind]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_how_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_owner_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_owner_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0 ; whole validated native scalar record
    mov  rdi, rbx
    call command_hook_edge_register
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; shared planner helpers
; ---------------------------------------------------------------------------

; hse_abs_path(RDI = cstr) -> EAX 1 when it is "/" followed by no space, else 0
;   (the hook line already bounds its length). clobbers: RAX, RDI
hse_abs_path:
    cmp  byte [rdi], '/'
    jne  .no
.l:
    mov  al, [rdi]
    test al, al
    jz   .yes
    cmp  al, ' '
    je   .no
    inc  rdi
    jmp  .l
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; hse_job_id(RDI = cstr) -> EAX 1 when the WHOLE string is a nonzero decimal of
;   at most HSE_ID_DIGITS_MAX digits (the FS layer parses it again). clobbers: RAX, RCX
hse_job_id:
    xor  ecx, ecx
    cmp  byte [rdi], '0'
    je   .no                              ; no leading zero, and never job 0
.l:
    mov  al, [rdi + rcx]
    test al, al
    jz   .end
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    ja   .no
    inc  ecx
    cmp  ecx, HSE_ID_DIGITS_MAX
    ja   .no
    jmp  .l
.end:
    test ecx, ecx
    jz   .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; hse_arg_nonce(EDI = 1 for a leading space) -- append the edge's next 16-hex
;   request nonce to the planned argument. clobbers: caller-saved
hse_arg_nonce:
    test edi, edi
    jz   .hex
    lea  rdi, [rel str_hse_sp]
    call command_hook_arg_str
.hex:
    mov  rdi, [rel hse_nonce_ctr]
    inc  rdi
    mov  [rel hse_nonce_ctr], rdi
    lea  rsi, [rel hse_nonce_buf]
    mov  edx, 16
    call fmt_hex
    lea  rdi, [rel hse_nonce_buf]
    jmp  command_hook_arg_str

; ---------------------------------------------------------------------------
; fs edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   LIST fs[:<dir>]          FSLS <dir or /> <nonce>
;   GET  fs                  FSINFO <nonce>
;   GET  fs:<path>           FSSTAT <path> <nonce>
;   GET  fs:<path> hash      FSHASH <path> <nonce>
;   SET  fs:<src> rename <dst> FSREN <src> <dst> <nonce> (native gates decide)
;   SET  fs:<path> mkdir     FSMKDIR <path> <nonce>
;   SET  fs:<path> rmdir     FSRMDIR <path> <nonce>
;   GET  fs:<path> read <offset> <length>  FSREAD <path> <offset> <length> <nonce>
; ---------------------------------------------------------------------------
hook_fs_plan:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12, rsi
    mov  r13, rdx
    cmp  byte [r12], 0
    je   .inst_ok
    mov  rdi, r12
    call hse_abs_path
    test eax, eax
    jz   .bad
.inst_ok:
    cmp  ebx, HOP_SET
    jne  .read_ops
    mov  rdi, r13
    lea  rsi, [rel str_hse_word_mkdir]
    call command_hook_word_eq
    test eax, eax
    jnz  .mkdir
    mov  rdi, r13
    lea  rsi, [rel str_hse_word_rmdir]
    call command_hook_word_eq
    test eax, eax
    jnz  .rmdir
    mov  rdi, r13
    lea  rsi, [rel str_hse_word_rename]
    call command_hook_after_word
    test rax, rax
    jnz  .rename
    mov  rsi, r12
    mov  rdx, r13
    call hse_content_plan
    jmp  .out
.read_ops:
    cmp  ebx, HOP_LIST
    je   .list
    cmp  ebx, HOP_GET
    je   .get
    cmp  ebx, HOP_SET
    je   .rename
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    jmp  .out
.list:
    cmp  byte [r13], 0
    jne  .bad
    call command_hook_arg_reset
    mov  rdi, r12
    cmp  byte [rdi], 0
    jne  .list_dir
    lea  rdi, [rel str_hse_root]
.list_dir:
    call command_hook_arg_str
    mov  edi, 1
    call hse_arg_nonce
    lea  rax, [rel str_hse_verb_fsls]
    jmp  .out
.get:
    cmp  byte [r12], 0
    jne  .get_path
    cmp  byte [r13], 0
    jne  .bad
    call command_hook_arg_reset
    xor  edi, edi
    call hse_arg_nonce
    lea  rax, [rel str_hse_verb_fsinfo]
    jmp  .out
.get_path:
    lea  rbx, [rel str_hse_verb_fsstat]
    cmp  byte [r13], 0
    je   .path_arg
    mov  rdi, r13
    lea  rsi, [rel str_hse_field_hash]
    call command_hook_word_eq
    test eax, eax
    jnz  .hash
    mov  rdi, r13
    lea  rsi, [rel str_hse_word_read]
    call command_hook_after_word
    test rax, rax
    jz   .bad
    mov  rdx, rax
    mov  rsi, r12
    call hse_read_plan
    jmp  .out
.hash:
    lea  rbx, [rel str_hse_verb_fshash]
.path_arg:
    call command_hook_arg_reset
    mov  rdi, r12
    call command_hook_arg_str
    mov  edi, 1
    call hse_arg_nonce
    mov  rax, rbx
    jmp  .out
.rename:
    mov  rdi, r13
    lea  rsi, [rel str_hse_word_rename]
    call command_hook_after_word
    test rax, rax
    jz   .bad
    mov  r13, rax                        ; exact one destination, no extra words
    mov  rdi, r12
    call hse_rename_path
    test eax, eax
    jz   .bad
    mov  ebx, ecx                        ; source byte length
    mov  rdi, r13
    call hse_rename_path
    test eax, eax
    jz   .bad
    add  ecx, ebx
    cmp  ecx, HOOK_ARG_MAX - 19          ; two spaces + 16 hex + NUL
    ja   .bad                            ; never truncate a planned mutation
    call command_hook_arg_reset
    mov  rdi, r12
    call command_hook_arg_str
    lea  rdi, [rel str_hse_sp]
    call command_hook_arg_str
    mov  rdi, r13
    call command_hook_arg_str
    mov  edi, 1
    call hse_arg_nonce
    lea  rax, [rel str_hse_verb_fsren]
    jmp  .out
.mkdir:
    lea  rbx, [rel str_hse_verb_fsmkdir]
    jmp  .directory
.rmdir:
    lea  rbx, [rel str_hse_verb_fsrmdir]
.directory:
    mov  rdi, r12
    call hse_directory_path
    test eax, eax
    jz   .bad
    ; Path <=191 + space +16 hex +NUL fits HOOK_ARG_MAX=224.
    call command_hook_arg_reset
    mov  rdi, r12
    call command_hook_arg_str
    mov  edi, 1
    call hse_arg_nonce
    mov  rax, rbx
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; SET fs:<path> create <hex> | delete | write <hex> | write_at <offset> <hex>
; Only plans existing native verbs. All input is validated before constructing
; the argument; the common overflow latch is an additional final fence.
hse_content_plan:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rsi
    mov  r13, rdx
    mov  rdi, r12
    call hse_content_path
    test eax, eax
    jz   .bad
    mov  r14d, ecx
    mov  rdi, r13
    lea  rsi, [rel str_hse_word_delete]
    call command_hook_word_eq
    test eax, eax
    jnz  .delete
    mov  rdi, r13
    lea  rsi, [rel str_hse_word_create]
    call command_hook_after_word
    lea  rbx, [rel str_hse_verb_fsnew]
    test rax, rax
    jnz  .hex
    mov  rdi, r13
    lea  rsi, [rel str_hse_word_write]
    call command_hook_after_word
    lea  rbx, [rel str_hse_verb_fswrite]
    test rax, rax
    jnz  .hex
    mov  rdi, r13
    lea  rsi, [rel str_hse_word_write_at]
    call command_hook_after_word
    test rax, rax
    jz   .na
    mov  r13, rax                       ; original offset + space + hex
    mov  rdi, rax
    call hse_content_offset
    test edx, edx
    jnz  .bad
    mov  r15, rax                       ; full-width offset, never dword
    mov  rdi, rsi                       ; hex after exactly one space
    call hse_content_hex
    test eax, eax
    jz   .bad
    shr  ecx, 1
    add  r15, rcx
    jc   .bad                          ; offset + byte count must not wrap
    ; Legacy range dispatch has backend-specific fences, no namespace gate.
    ; Keep typed range paths within the existing native scratch grammar too.
    mov  rdi, r12
    mov  esi, r14d
    call hse_content_scratch
    test eax, eax
    jz   .bad
    jmp  .emit
.hex:
    mov  r13, rax
    mov  rdi, rax
    call hse_content_hex
    test eax, eax
    jz   .bad
.emit:
    xor  ecx, ecx
.suffix_len:
    cmp  byte [r13 + rcx], 0
    je   .size
    inc  ecx
    cmp  ecx, 533                      ; 20 decimal + space + 512 hex
    ja   .bad
    jmp  .suffix_len
.size:
    lea  eax, [r14 + rcx + 18]         ; path + space + suffix + space + nonce
    cmp  eax, HOOK_ARG_MAX - 1
    ja   .bad
    call command_hook_arg_reset
    mov  rdi, r12
    call command_hook_arg_str
    lea  rdi, [rel str_hse_sp]
    call command_hook_arg_str
    mov  rdi, r13
    call command_hook_arg_str
    jmp  .nonce
.delete:
    lea  rbx, [rel str_hse_verb_fsdel]
    ; canonical path <=191, plus space +16-hex nonce fits 224 bytes.
    call command_hook_arg_reset
    mov  rdi, r12
    call command_hook_arg_str
.nonce:
    mov  edi, 1
    call hse_arg_nonce
    mov  rax, rbx
    jmp  .out
.bad:
    xor  eax, eax
    mov  edx, HOOK_PLAN_BADARG
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.na:
    xor  eax, eax
    mov  edx, HOOK_PLAN_NA
    jmp  .out

; Nonempty, even hex, at most 256 bytes (the native whole-file cap). No spaces,
; signs, trailing arguments or silent truncation. ECX = hex character count.
hse_content_hex:
    xor  ecx, ecx
.loop:
    movzx eax, byte [rdi + rcx]
    test al, al
    jz   .end
    cmp  ecx, 512
    jae  .no
    sub  eax, '0'
    cmp  eax, 9
    jbe  .digit
    movzx eax, byte [rdi + rcx]
    or   al, 0x20
    sub  eax, 'a'
    cmp  eax, 5
    ja   .no
.digit:
    inc  ecx
    jmp  .loop
.end:
    test ecx, ecx
    jz   .no
    test ecx, 1
    jnz  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Mirror native fs_parse_u64's FULL-WIDTH imul/jo + add/jc acceptance,
; with a 20-digit token bound and exactly one separating space. Native's signed
; multiply rejects some uint64 spellings: do not promise an expanded range.
; RAX=value, RSI=hex suffix, EDX=0 success/-1 failure.
hse_content_offset:
    xor  eax, eax
    xor  r8d, r8d
.loop:
    movzx ecx, byte [rdi + r8]
    cmp  cl, ' '
    je   .end
    sub  ecx, '0'
    cmp  ecx, 9
    ja   .no
    cmp  r8d, 20
    jae  .no
    imul rax, rax, 10
    jo   .no
    add  rax, rcx
    jc   .no
    inc  r8d
    jmp  .loop
.end:
    test r8d, r8d
    jz   .no
    lea  rsi, [rdi + r8 + 1]
    xor  edx, edx
    ret
.no:
    mov  edx, -1
    ret

; The native raw scratch classifier, used as a stricter range planner fence.
; This pure path grammar grants no authority and cannot arm a mount.
hse_content_scratch:
    ; Canonical validation already excludes dot components and aliases.
    ; Retain the native /FSW*.TST or /FSWDIR[0..2 chars]/... shape.
    cmp  esi, 7
    jb   .root
    cmp  byte [rdi], '/'
    jne  .no
    mov  eax, [rdi + 1]
    or   eax, 0x20202020
    cmp  eax, 'fswd'
    jne  .root
    mov  ax, [rdi + 5]
    or   ax, 0x2020
    cmp  ax, 'ir'
    jne  .root
    mov  ecx, 7
.dir_component:
    cmp  ecx, esi
    jae  .directory
    cmp  byte [rdi + rcx], '/'
    je   .directory
    cmp  ecx, 9
    jae  .no
    cmp  byte [rdi + rcx], '.'
    je   .no
    inc  ecx
    jmp  .dir_component
.directory:
    mov  eax, 1
    ret
.root:
    cmp  esi, 8                            ; /FSW.TST
    jb   .no
    cmp  esi, 13                           ; /FSWxxxxx.TST
    ja   .no
    cmp  byte [rdi], '/'
    jne  .no
    mov  al, [rdi + 1]
    or   al, 0x20
    cmp  al, 'f'
    jne  .no
    mov  al, [rdi + 2]
    or   al, 0x20
    cmp  al, 's'
    jne  .no
    mov  al, [rdi + 3]
    or   al, 0x20
    cmp  al, 'w'
    jne  .no
    mov  ecx, esi
    sub  ecx, 4
    cmp  byte [rdi + rcx], '.'
    jne  .no
    mov  al, [rdi + rcx + 1]
    or   al, 0x20
    cmp  al, 't'
    jne  .no
    mov  al, [rdi + rcx + 2]
    or   al, 0x20
    cmp  al, 's'
    jne  .no
    mov  al, [rdi + rcx + 3]
    or   al, 0x20
    cmp  al, 't'
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret


; Canonical non-root printable path; native backend rules remain decisive.
hse_rename_path:
hse_directory_path:
hse_content_path:
    cmp  byte [rdi], '/'
    jne  .no
    mov  ecx, 1
    mov  r8d, 1                         ; current component start
.next:
    cmp  ecx, HOOK_LINE_MAX - 1
    ja   .no
    movzx eax, byte [rdi + rcx]
    test al, al
    jz   .component
    cmp  al, 33
    jb   .no
    cmp  al, 126
    ja   .no
    cmp  al, 92                         ; backslash is not a separator here
    je   .no
    cmp  al, '/'
    je   .component
    inc  ecx
    jmp  .next
.component:
    mov  edx, ecx
    sub  edx, r8d
    jz   .no
    cmp  byte [rdi + r8], '.'
    jne  .valid_component
    cmp  edx, 1
    je   .no
    cmp  edx, 2
    jne  .valid_component
    cmp  byte [rdi + r8 + 1], '.'
    je   .no
.valid_component:
    test al, al
    jz   .yes
    inc  ecx
    mov  r8d, ecx
    jmp  .next
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; GET fs:<path> read <offset> <length> -> existing FSREAD, no direct VFS entry.
; The native full-width decimal rules and exact 1..256-byte range are retained.
; Native path/backend policy remains decisive; no arm/select or path-policy grant.
hse_read_plan:
    push r12
    push r13
    push r14
    mov  r12, rsi
    mov  r13, rdx
    xor  r14d, r14d
.path_len:
    cmp  r14d, HOOK_LINE_MAX - 1
    ja   .bad
    cmp  byte [r12 + r14], 0
    je   .numbers
    inc  r14d
    jmp  .path_len
.numbers:
    mov  rdi, r13
    call hse_read_number
    test edx, edx
    jnz  .bad
    cmp  byte [rsi], ' '
    jne  .bad
    lea  rdi, [rsi + 1]
    call hse_read_number
    test edx, edx
    jnz  .bad
    cmp  byte [rsi], 0
    jne  .bad
    test rax, rax
    jz   .bad
    cmp  rax, 256
    ja   .bad
    sub  rsi, r13                       ; complete original decimal suffix
    lea  rax, [r14 + rsi + 18]          ; path + space + suffix + space + nonce
    cmp  rax, HOOK_ARG_MAX - 1
    ja   .bad
    call command_hook_arg_reset
    mov  rdi, r12
    call command_hook_arg_str
    lea  rdi, [rel str_hse_sp]
    call command_hook_arg_str
    mov  rdi, r13
    call command_hook_arg_str
    mov  edi, 1
    call hse_arg_nonce
    lea  rax, [rel str_hse_verb_fsread]
    jmp  .out
.bad:
    xor  eax, eax
    mov  edx, HOOK_PLAN_BADARG
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

; RDI decimal token -> RAX value, RSI terminator (space/NUL), EDX=0/-1.
; Mirrors native fs_parse_u64's imul/jo + add/jc, including its upper-range
; refusals. Preserve leading zeros: native accepts them, including >20 digits.
; Each token is bounded by the common line cap even for direct planner calls.
hse_read_number:
    xor  eax, eax
    xor  r8d, r8d
.loop:
    movzx ecx, byte [rdi + r8]
    test cl, cl
    jz   .end
    cmp  cl, ' '
    je   .end
    cmp  r8d, HOOK_LINE_MAX - 1
    jae  .no
    sub  ecx, '0'
    cmp  ecx, 9
    ja   .no
    imul rax, rax, 10
    jo   .no
    add  rax, rcx
    jc   .no
    inc  r8d
    jmp  .loop
.end:
    test r8d, r8d
    jz   .no
    lea  rsi, [rdi + r8]
    xor  edx, edx
    ret
.no:
    mov  edx, -1
    ret

; ---------------------------------------------------------------------------
; fsjob edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   SET    fsjob <src> <dst>   FSCOPY <src> <dst> <nonce>  (the reply names JOB=<id>)
;   GET    fsjob check <src> <dst> [MODE=...] [TREE=1] -> read-only FSCHECK
;   GET    fsjob issue <0..15>  FSCHECK ITEM=<i> <nonce> (latest check)
;   GET    fsjob:<id>          FSJOB <id> <nonce>
;   CANCEL fsjob:<id>          FSCANCEL <id> <nonce>
; ---------------------------------------------------------------------------
hook_fsjob_plan:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12, rsi
    mov  r13, rdx
    call hfj_retire                     ; stale LIST stage cannot survive any plan
    cmp  ebx, HOP_LIST
    je   .list
    cmp  ebx, HOP_SET
    je   .set
    cmp  ebx, HOP_GET
    je   .get
    cmp  ebx, HOP_CANCEL
    je   .by_id
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    jmp  .out
.list:
    cmp  byte [r12], 0
    jne  .bad
    cmp  byte [r13], 0
    jne  .bad
    call command_hook_arg_reset
    xor  edi, edi
    call hse_arg_nonce
    lea  rsi, [rel hse_nonce_buf]
    lea  rdi, [rel hfj_nonce]
    mov  ecx, 16
    rep movsb
    mov  byte [rel hfj_pending], 1
    lea  rax, [rel str_hfj_verb]
    jmp  .out
.get:
    cmp  byte [r12], 0
    jne  .by_id
    mov  rdi, r13
    lea  rsi, [rel str_hse_word_check]
    call command_hook_after_word
    test rax, rax
    jz   .issue
    mov  rdi, rax
    call hse_copy_check_args
    test eax, eax
    jz   .bad
    lea  rax, [rel str_hse_verb_fscheck]
    jmp  .out
.issue:
    mov  rdi, r13
    lea  rsi, [rel str_hse_word_issue]
    call command_hook_after_word
    test rax, rax
    jz   .bad
    mov  r12, rax
    mov  rdi, rax
    call command_hook_parse_dec
    test edx, edx
    jz   .bad
    cmp  edx, 2
    ja   .bad
    cmp  byte [r12 + rdx], 0
    jne  .bad
    cmp  rax, 15                         ; native's bounded latest-check issue list
    ja   .bad
    cmp  edx, 1
    je   .issue_valid
    cmp  byte [r12], '0'
    je   .bad
.issue_valid:
    call command_hook_arg_reset
    lea  rdi, [rel str_hse_item_eq]
    call command_hook_arg_str
    mov  rdi, r12
    call command_hook_arg_str
    mov  edi, 1
    call hse_arg_nonce
    lea  rax, [rel str_hse_verb_fscheck]
    jmp  .out
.set:
    cmp  byte [r12], 0
    jne  .bad                             ; a new job has no instance yet
    ; exactly "<abs> <abs>": one space, both absolute
    mov  rdi, r13
    cmp  byte [rdi], '/'
    jne  .bad
.src:
    mov  al, [rdi]
    test al, al
    jz   .bad                             ; no destination
    cmp  al, ' '
    je   .dst
    inc  rdi
    jmp  .src
.dst:
    inc  rdi
    call hse_abs_path
    test eax, eax
    jz   .bad
    call command_hook_arg_reset
    mov  rdi, r13
    call command_hook_arg_str
    mov  edi, 1
    call hse_arg_nonce
    lea  rax, [rel str_hse_verb_fscopy]
    jmp  .out
.by_id:
    cmp  byte [r13], 0
    jne  .bad
    mov  rdi, r12
    call hse_job_id
    test eax, eax
    jz   .bad
    call command_hook_arg_reset
    mov  rdi, r12
    call command_hook_arg_str
    mov  edi, 1
    call hse_arg_nonce
    lea  rax, [rel str_hse_verb_fsjob]
    cmp  ebx, HOP_GET
    je   .out
    lea  rax, [rel str_hse_verb_fscancel]
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Read-only FSCHECK grammar, bounded by HOOK_LINE_MAX. Does not allocate a
; request identity or start a job. Native authorization and path checks run later.
; RDI = src/dst/options, EAX = 1 with staged argument, else 0. Preserves nonvolatiles.
hse_copy_check_args:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    cmp  byte [rdi], '/'
    jne  .bad
.src:
    mov  al, [rdi]
    cmp  al, ' '
    je   .dst
    cmp  al, 32
    jbe  .bad
    cmp  al, 127
    je   .bad
    inc  rdi
    jmp  .src
.dst:
    inc  rdi
    cmp  byte [rdi], '/'
    jne  .bad
.dst_loop:
    mov  al, [rdi]
    test al, al
    jz   .paths_end
    cmp  al, ' '
    je   .paths_end
    cmp  al, 32
    jbe  .bad
    cmp  al, 127
    je   .bad
    inc  rdi
    jmp  .dst_loop
.paths_end:
    mov  r14, rdi
    sub  r14, r12                       ; exact src + space + dst span
    mov  r15, rdi
    cmp  byte [rdi], 0
    je   .valid
    inc  r15
    cmp  byte [r15], 0
    je   .bad                           ; a trailing space is not an option
    lea  r13, [rel str_hse_check_options]
.options:
    mov  rdi, r15
    mov  rsi, r13
    call strcmp
    test eax, eax
    jz   .valid
.next:
    cmp  byte [r13], 0
    je   .next_end
    inc  r13
    jmp  .next
.next_end:
    inc  r13
    cmp  byte [r13], 0
    jne  .options
    jmp  .bad
.valid:
    call command_hook_arg_reset
    mov  rdi, r12
    mov  rsi, r14
    call command_hook_arg_strn
    mov  edi, 1
    call hse_arg_nonce                  ; preview correlation only, never a copy request key
    cmp  byte [r15], 0
    je   .yes
    lea  rdi, [rel str_hse_sp]
    call command_hook_arg_str
    mov  rdi, r15
    call command_hook_arg_str
.yes:
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; net edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   GET|LIST net         NETCFG MEMBERS
;   SET net dhcp         NETCFG DHCP ONCE <nonce>   (live only; reboot restores the static address)
;   SET net static       NETCFG STATIC <nonce>
; ---------------------------------------------------------------------------
hook_net_plan:
    push rbx
    push r12
    mov  ebx, edi
    mov  r12, rdx
    call hnm_retire                     ; only this request may publish MEMBERS
    cmp  byte [rsi], 0
    jne  .bad                             ; one instance
    cmp  ebx, HOP_GET
    je   .members
    cmp  ebx, HOP_LIST
    je   .members
    cmp  ebx, HOP_SET
    je   .set
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    jmp  .out
.members:
    cmp  byte [r12], 0
    jne  .bad
    call command_hook_arg_reset
    lea  rdi, [rel str_hse_net_members]
    call command_hook_arg_str
    mov  byte [rel hnm_pending], 1
    lea  rax, [rel str_hse_verb_netcfg]
    jmp  .out
.set:
    lea  rbx, [rel str_hse_net_dhcp_once]
    mov  rdi, r12
    lea  rsi, [rel str_hse_word_dhcp]
    call command_hook_word_eq
    test eax, eax
    jnz  .transition
    lea  rbx, [rel str_hse_net_static]
    mov  rdi, r12
    lea  rsi, [rel str_hse_word_static]
    call command_hook_word_eq
    test eax, eax
    jz   .bad
.transition:
    call command_hook_arg_reset
    mov  rdi, rbx
    call command_hook_arg_str
    xor  edi, edi
    call hse_arg_nonce
    lea  rax, [rel str_hse_verb_netcfg]
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; NETCFG MEMBERS remains owner-signed UDP only. The native producer decides
; publication; no hook can make a console/AI/SYSTEM listing visible. Validate a
; whole bounded native record before copying it, then consume its staging on
; success, malformed output and native refusal. SET keeps its native result.
HNM_REPLY_CAP equ 832                    ; native 64 + 8 * 96; pinned by host check
hook_net_post:
    push rbx
    push r12
    mov  rbx, rcx
    cmp  edi, HOP_SET
    je   .none
    cmp  edi, HOP_GET
    je   .read
    cmp  edi, HOP_LIST
    jne  .bad
.read:
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .none
    cmp  qword [rbx + RSP_ACCEPTED], 1
    jne  .bad
    cmp  byte [rel hnm_pending], 1
    jne  .bad
    cmp  byte [rel netlist_ready], 1
    jne  .bad
    lea  rdi, [rel netlist_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HNM_REPLY_CAP
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel netlist_cur]
    jne  .bad
    mov  r12d, ecx
    call hnm_record
    test eax, eax
    jz   .bad
    cmp  rdx, [rbx + RSP_VAL]
    jne  .bad
    call command_hook_out_reset
    lea  rdi, [rel netlist_buf]
    mov  esi, r12d
    call command_hook_out_strn
    call hnm_retire
    mov  eax, 1
    jmp  .out
.bad:
    call command_hook_out_reset
    lea  rdi, [rel str_hnm_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hnm_bad]
    mov  [rbx + RSP_HINT], rax
    call hnm_retire
    mov  eax, 1
    jmp  .out
.none:
    call hnm_retire
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret
hnm_retire:
    mov  byte [rel hnm_pending], 0
    mov  byte [rel netlist_ready], 0
    mov  byte [rel netlist_buf], 0
    mov  qword [rel netlist_cur], 0
    ret

%macro HNM_LITERAL 1
    lea  rsi, [rel %1]
    call hbi_literal
    test eax, eax
    jz   .no
%endmacro
%macro HNM_COLON 0
    cmp  byte [rdi], ':'
    jne  .no
    inc  rdi
%endmacro
; The producer's 8-slot table is ordered; count, selected identity, every row,
; native widths and exact end must agree. Empty/unprobed/absent are real states.
hnm_record:
    push rbx
    push r12
    push r13
    push r14
    push r15
    HNM_LITERAL str_hnm_head
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  rdx, 8
    ja   .no
    mov  r14, rdx
    HNM_LITERAL str_hnm_sel
    mov  r15, -1
    cmp  byte [rdi], '-'
    jne  .selected
    inc  rdi
    jmp  .rows
.selected:
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  rdx, 7
    ja   .no
    mov  r15, rdx
.rows:
    xor  r12d, r12d                     ; seen slots
    xor  r13d, r13d                     ; actual rows
    mov  ebx, -1                       ; previous slot
.row:
    cmp  byte [rdi], 0
    je   .end
    cmp  r13, r14
    jae  .no
    HNM_LITERAL str_hnm_row
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  rdx, 7
    ja   .no
    cmp  ebx, -1
    je   .slot
    cmp  edx, ebx
    jbe  .no
.slot:
    mov  ebx, edx
    bts  r12, rdx
    HNM_COLON
    call hnm_name
    test eax, eax
    jz   .no
    HNM_COLON
    call hnm_name
    test eax, eax
    jz   .no
    HNM_COLON
    cmp  byte [rdi], '-'
    jne  .mac
    inc  rdi
    jmp  .priority
.mac:
    mov  ecx, 12
.hex:
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 9
    jbe  .hex_ok
    movzx eax, byte [rdi]
    sub  eax, 'a'
    cmp  eax, 5
    ja   .no
.hex_ok:
    inc  rdi
    dec  ecx
    jnz  .hex
.priority:
    HNM_COLON
    call hnm_u32
    test eax, eax
    jz   .no
    HNM_COLON
    mov  r10, rdi
    lea  rsi, [rel str_hnm_ok]
    call hbi_literal
    test eax, eax
    jnz  .health
    mov  rdi, r10
    lea  rsi, [rel str_hnm_degraded]
    call hbi_literal
    test eax, eax
    jnz  .health
    mov  rdi, r10
    lea  rsi, [rel str_hnm_absent]
    call hbi_literal
    test eax, eax
    jnz  .health
    mov  rdi, r10
    lea  rsi, [rel str_hnm_dead]
    call hbi_literal
    test eax, eax
    jnz  .health
    mov  rdi, r10
    cmp  byte [rdi], 'h'
    jne  .no
    inc  rdi
    call hnm_u32
    test eax, eax
    jz   .no
    cmp  rdx, 2                         ; known enum values have their own spelling
    jbe  .no
.health:
    HNM_COLON
    xor  eax, eax
    cmp  rbx, r15
    sete al
    add  al, '0'
    cmp  al, [rdi]
    jne  .no
    inc  rdi
    HNM_COLON
    mov  r10, rdi
    lea  rsi, [rel str_hnm_dash]
    call hbi_literal
    test eax, eax
    jnz  .next
    mov  rdi, r10
    lea  rsi, [rel str_hnm_down]
    call hbi_literal
    test eax, eax
    jnz  .next
    mov  rdi, r10
    lea  rsi, [rel str_hnm_err]
    call hbi_literal
    test eax, eax
    jnz  .next
    mov  rdi, r10
    HNM_LITERAL str_hnm_up
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  rdx, 0xffffff                  ; native u32 link >> 8
    ja   .no
.next:
    inc  r13
    jmp  .row
.end:
    cmp  r13, r14
    jne  .no
    cmp  r15, -1
    je   .yes
    bt   r12, r15
    jnc  .no
.yes:
    mov  rdx, r14
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
hnm_u32:
    call hbi_decimal
    test eax, eax
    jz   .out
    mov  ecx, 0xffffffff
    cmp  rdx, rcx
    seta cl
    movzx ecx, cl
    sub  eax, ecx
.out:
    ret
hnm_name:
    cmp  byte [rdi], '?'
    jne  .name
    inc  rdi
    mov  eax, 1
    ret
.name:
    xor  ecx, ecx
.char:
    movzx eax, byte [rdi]
    cmp  al, ':'
    je   .end
    cmp  ecx, 15
    jae  .no
    cmp  al, '-'
    je   .keep
    cmp  al, '.'
    je   .keep
    cmp  al, '_'
    je   .keep
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .keep
    or   al, 0x20
    cmp  al, 'a'
    jb   .no
    cmp  al, 'z'
    ja   .no
.keep:
    inc  rdi
    inc  ecx
    jmp  .char
.end:
    xor  eax, eax
    test ecx, ecx
    setnz al
    ret
.no:
    xor  eax, eax
    ret

str_hnm_head: db "NETCFG MEMBERS n=",0
str_hnm_sel: db " sel=",0
str_hnm_row: db " M=",0
str_hnm_ok: db "ok",0
str_hnm_degraded: db "degraded",0
str_hnm_absent: db "absent",0
str_hnm_dead: db "dead",0
str_hnm_dash: db "-",0
str_hnm_down: db "down",0
str_hnm_err: db "err",0
str_hnm_up: db "up",0
str_hnm_bad: db " hook err=net_members_reply_unavailable",0
hnm_pending: db 0

; ---------------------------------------------------------------------------
; guest edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   GET guest                     GUESTVM STAT
;   GET guest exitstat            GUESTVM EXITSTAT (retained, no VMCS read/yield)
;   GET guest profiles            GUESTVM PROFILES
;   GET guest plan [<profile>]    GUESTVM PLAN [<profile>]     (S4)
;   SET guest start [<profile>]   GUESTVM START [<profile>]
;   SET guest stop                GUESTVM STOP                 (S4)
;   CANCEL guest                  GUESTVM STOP (request; OBSERVE completion)
; A profile name is the record's own grammar, [a-z0-9-]{1,23} (hv/vm_profile
; VP_NAME). INPUT uses the existing injection gate and lock check (S5b).
; EXITSTAT is explicit GET only; ordinary OBSERVE still reads the STAT keys.
; ---------------------------------------------------------------------------
HSE_PROFILE_MAX equ 23

hook_guest_plan:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12, rdx
    xor  r13d, r13d                       ; a PLAN/START profile, or 0
    cmp  byte [rsi], 0
    jne  .bad                             ; one instance
    cmp  ebx, HOP_GET
    je   .get
    cmp  ebx, HOP_SET
    je   .set
    cmp  ebx, HOP_INPUT
    je   .input
    cmp  ebx, HOP_CANCEL
    je   .cancel
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    jmp  .out
.input:
    ; S5b: key <1..127> | ptr <x> <y> <buttons>, one space apart, each value one decimal spelling
    mov  rdi, r12
    lea  rsi, [rel str_hse_guest_key]
    call command_hook_after_word
    test rax, rax
    jz   .input_ptr
    mov  r13, rax                         ; the key code's text
    mov  rdi, rax
    mov  edx, HSE_GI_KEY_MAX
    call hse_dec_tok
    test eax, eax
    jz   .bad
    test ecx, ecx
    jz   .bad                             ; key codes start at 1
    cmp  byte [rsi], 0
    jne  .bad
    lea  rbx, [rel str_hse_guest_in_key]
    jmp  .plan
.input_ptr:
    mov  rdi, r12
    lea  rsi, [rel str_hse_guest_ptr]
    call command_hook_after_word
    test rax, rax
    jz   .bad
    mov  r13, rax                         ; "<x> <y> <buttons>"
    mov  rdi, rax
    mov  edx, HSE_GI_X_MAX
    call hse_dec_tok
    test eax, eax
    jz   .bad
    cmp  byte [rsi], ' '
    jne  .bad
    lea  rdi, [rsi + 1]
    mov  edx, HSE_GI_Y_MAX
    call hse_dec_tok
    test eax, eax
    jz   .bad
    cmp  byte [rsi], ' '
    jne  .bad
    lea  rdi, [rsi + 1]
    mov  edx, HSE_GI_BTN_MAX
    call hse_dec_tok
    test eax, eax
    jz   .bad
    cmp  byte [rsi], 0
    jne  .bad
    lea  rbx, [rel str_hse_guest_in_ptr]
    jmp  .plan
.get:
    lea  rbx, [rel str_hse_guest_stat]
    cmp  byte [r12], 0
    je   .plan
    lea  rbx, [rel str_hse_guest_exitstat]
    mov  rdi, r12
    mov  rsi, rbx
    call command_hook_word_eq
    test eax, eax
    jnz  .plan
    lea  rbx, [rel str_hse_guest_profiles]
    mov  rdi, r12
    mov  rsi, rbx
    call command_hook_word_eq
    test eax, eax
    jnz  .plan
    mov  rdi, r12
    lea  rsi, [rel str_hse_guest_plan]
    call command_hook_after_word
    test rax, rax
    jz   .bad
    lea  rbx, [rel str_hse_guest_plan]
.profile:
    cmp  byte [rax], 0
    je   .plan                            ; PLAN/START alone: native default selection
    mov  r13, rax
    xor  ecx, ecx
.pname:
    movzx eax, byte [r13 + rcx]
    test eax, eax
    jz   .plan
    cmp  ecx, HSE_PROFILE_MAX
    jae  .bad
    cmp  eax, '-'
    je   .pname_ok
    cmp  eax, '0'
    jb   .bad
    cmp  eax, '9'
    jbe  .pname_ok
    cmp  eax, 'a'
    jb   .bad
    cmp  eax, 'z'
    ja   .bad
.pname_ok:
    inc  ecx
    jmp  .pname
.cancel:
    cmp  byte [r12], 0
    jne  .bad
    lea  rbx, [rel str_hse_guest_stop]
    jmp  .plan                            ; native owns generation and lifecycle
.set:
    lea  rbx, [rel str_hse_guest_start]
    mov  rdi, r12
    mov  rsi, rbx
    call command_hook_after_word
    test rax, rax
    jnz  .profile                         ; only syntax here; native owns profile admission
    lea  rbx, [rel str_hse_guest_stop]
    mov  rdi, r12
    mov  rsi, rbx
    call command_hook_word_eq
    test eax, eax
    jz   .bad
.plan:
    call command_hook_arg_reset
    mov  rdi, rbx
    call command_hook_arg_str
    test r13, r13
    jz   .planned
    lea  rdi, [rel str_hse_sp]
    call command_hook_arg_str
    mov  rdi, r13
    call command_hook_arg_str
.planned:
    lea  rax, [rel str_hse_verb_guestvm]
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; hse_dec_tok(RDI = text, EDX = largest value) -> EAX 1 = one decimal token of 1..HSE_GI_DIGITS digits,
;   no leading zero, value <= EDX, ending at a NUL or a space; ECX = its value, RSI = the byte that ended it.
;   EAX 0 otherwise. clobbers: RAX, RCX, RSI, R8
hse_dec_tok:
    xor  ecx, ecx
    mov  rsi, rdi
.d:
    movzx eax, byte [rsi]
    test eax, eax
    jz   .end
    cmp  eax, ' '
    je   .end
    sub  eax, '0'
    cmp  eax, 9
    ja   .no
    mov  r8, rsi
    sub  r8, rdi
    cmp  r8d, HSE_GI_DIGITS
    jae  .no
    imul ecx, ecx, 10
    add  ecx, eax
    inc  rsi
    jmp  .d
.end:
    mov  r8, rsi
    sub  r8, rdi
    jz   .no                              ; no digits
    cmp  r8d, 1
    je   .range
    cmp  byte [rdi], '0'
    je   .no                              ; one spelling per value
.range:
    cmp  ecx, edx
    ja   .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; hook_guest_post(EDI op, RSI inst, RDX rest, RCX rsp) -> EAX 1 = a hook reply staged, 0 = nothing staged.
;   RCQ-15 S3b (root 2026-10-09 12:56:23). GUESTVM stages its reply in hv_out_buf (hv/vmx), which the UDP
;   reply chain sends only from the marker tail, past the 1472 B cap under HOOK, so a delegated GET guest
;   answered without the GUESTVM STAT body. The post filter relays that text as the hook reply (for every
;   planned sub-verb; INPUT's is the GUESTINPUT line, S5b):
;   * a native refusal passes through untouched, and nothing is relayed unless GUESTVM staged a reply;
;   * the text is measured only within hv_out_buf (HSE_HV_OUT_CAP bytes). With no NUL inside the buffer,
;     nothing is copied: the reply is " hook err=guest_reply_unterminated" and hv_out_ready stays set;
;   * bound = min(the text's length, HOOK_OUT_MAX - 1): a text that fits is copied whole; one that does not
;     (only if hv_out_buf ever outgrows the hook buffer) is cut at HSE_GUEST_BODY_MAX and flagged
;     " hook truncated=1", which then still fits; command_hook_out_buf is never overrun;
;   * hv_out_ready is cleared only after the copy, so the marker tail never sends the text a second time.
;   Authority is unchanged: this runs after the native gate, on GUESTVM's own reply to this caller.
;   clobbers: caller-saved.
hook_guest_post:
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .none                            ; a refusal passes through unchanged
    cmp  byte [rel hv_out_ready], 1
    jne  .none
    lea  rdi, [rel hv_out_buf]
    xor  ecx, ecx
.len:
    cmp  ecx, HSE_HV_OUT_CAP
    jae  .unterminated
    cmp  byte [rdi + rcx], 0
    je   .measured
    inc  ecx
    jmp  .len
.measured:
    call command_hook_out_reset           ; clobbers RAX only
    lea  rdi, [rel hv_out_buf]
    mov  esi, HOOK_OUT_MAX - 1            ; the whole text fits
    cmp  ecx, esi
    jbe  .copy
    mov  esi, HSE_GUEST_BODY_MAX          ; cut where the flag still fits
.copy:
    push rcx                              ; the native text's length (< HSE_HV_OUT_CAP)
    call command_hook_out_strn
    pop  rcx
    cmp  ecx, HOOK_OUT_MAX - 1
    jbe  .copied
    lea  rdi, [rel str_hse_guest_trunc]
    call command_hook_out_str
.copied:
    mov  byte [rel hv_out_ready], 0       ; consumed: the hook reply carries it
    mov  eax, 1
    ret
.unterminated:
    call command_hook_out_reset
    lea  rdi, [rel str_hse_guest_unterm]
    call command_hook_out_str
    mov  eax, 1
    ret
.none:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; job edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   GET job              JOBPUB                       (the node's receipt public key)
;   SET job compute <n>  JOBRUN CAP_COMPUTE <n>       (one metered job; the reply is its signed receipt)
; The receipt nonce is the caller's own freshness token (the receipt body signs
; it), never one the hook makes up: 1..HSE_JOB_NONCE_MAX of [A-Za-z0-9._-].
; ---------------------------------------------------------------------------
HSE_JOB_NONCE_MAX equ 64
hook_job_plan:
    push rbx
    push r12
    mov  ebx, edi
    mov  r12, rdx
    cmp  byte [rsi], 0
    jne  .bad                             ; one instance
    cmp  ebx, HOP_GET
    je   .pub
    cmp  ebx, HOP_SET
    je   .set
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    jmp  .out
.pub:
    cmp  byte [r12], 0
    jne  .bad
    call command_hook_arg_reset           ; JOBPUB takes no argument
    lea  rax, [rel str_hse_verb_jobpub]
    jmp  .out
.set:
    lea  rsi, [rel str_hse_word_compute]
    xor  ecx, ecx
.kw:
    mov  al, [rsi + rcx]
    test al, al
    jz   .kw_end
    mov  dl, [r12 + rcx]
    and  dl, 0xDF                         ; ASCII letters fold to upper case
    cmp  dl, al
    jne  .bad
    inc  ecx
    jmp  .kw
.kw_end:
    cmp  byte [r12 + rcx], ' '
    jne  .bad
    lea  r12, [r12 + rcx + 1]             ; the caller's nonce
    xor  ecx, ecx
.nonce:
    movzx eax, byte [r12 + rcx]
    test eax, eax
    jz   .nonce_end
    cmp  ecx, HSE_JOB_NONCE_MAX
    jae  .bad
    inc  ecx
    cmp  al, '.'
    je   .nonce
    cmp  al, '_'
    je   .nonce
    cmp  al, '-'
    je   .nonce
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    jbe  .nonce
    or   al, 0x20
    cmp  al, 'a'
    jb   .bad
    cmp  al, 'z'
    jbe  .nonce
    jmp  .bad
.nonce_end:
    test ecx, ecx
    jz   .bad
    call command_hook_arg_reset
    lea  rdi, [rel str_hse_job_scope]
    call command_hook_arg_str
    mov  rdi, r12
    call command_hook_arg_str
    lea  rax, [rel str_hse_verb_jobrun]
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
str_hse_fs:            db "fs", 0
str_hse_fsjob:         db "fsjob", 0
str_hse_kind_storage:  db "storage", 0
str_hse_kind_job:      db "job", 0
str_hse_fs_schema:     db "inst=none|<abs path, no spaces> list=FSLS(<dir>|/) get=FSINFO{VOL,BACKEND,CLUSTER,TOTAL,FREE,ORPHANS,DEV,PART_START,PART_SECTORS,SCHEME}|FSSTAT{NAME,SIZE,DIR}|hash:FSHASH{SIZE,SHA256}|read:<offset>:<length>:FSREAD{NONCE,OFF,LEN,SHA256,DATA}(length=1..256;native-u64-parser;owner-MUTATE) observe=SIZE,DIR,SHA256,FREE,ORPHANS,ERR,OFF,LEN,DATA,VOL,BACKEND,CLUSTER,TOTAL,DEV,PART_START,PART_SECTORS,SCHEME set=rename <canonical-abs-dst>:FSREN <inst-src> <dst> <nonce>(native-owner-MUTATE;native-armed-backend;no-auto-arm)|create:<hex>:FSNEW|delete:FSDEL|write:<hex>:FSWRITE|write_at:<offset>:<hex>:FSWRITE(native-supported-range;canonical-scratch;no-auto-arm;nonempty-even-hex;native-u64-parser)|mkdir:FSMKDIR|rmdir:FSRMDIR <inst-path> <nonce> input=na cancel=na", 0
str_hse_fsjob_schema:  db "inst=<job id> set=<src> <dst>:FSCOPY(owner; reply JOB=<id>) get=FSJOB{STATE,DONE,TOTAL,PHASE,ELAPSED_MS,RATE_BPS,DURABLE,PRESERVED,KEPT,POS,ERR,FILES_DONE,SKIPPED,RESULT}|check:<src> <dst> [MODE=refuse|keepboth|skipsame|skipsame+keepboth] [TREE=1]:FSCHECK(owner,read-only,COMPLETE,REASON,FILES,DIRS,BYTES,NEED,FREE,FITS,ISSUES,LISTED,SAME;incomplete totals are lower bounds)|issue:<0..15>:FSCHECK_ITEM(latest check) cancel=FSCANCEL observe=STATE,DONE,TOTAL,PHASE,DURABLE,PRESERVED,KEPT,POS,ERR,FILES_DONE,SKIPPED,RESULT,CHECK,COMPLETE,REASON,FILES,DIRS,BYTES,NEED,FREE,FITS,ISSUES,LISTED,SAME,I,KIND,PATHHEX list=FSJOBS(inst=none,args=none;current-session;bounded;J=id:state:done:total:durable:cancel:record:pos:error:files:skipped;unknown-history-explicit;one-use) input=na", 0
; FSREAD range identity matters even when equal bytes hash alike. NONCE is per-call.
str_hse_fs_witness:    db " SIZE=",0," DIR=",0," SHA256=",0," FREE=",0," ORPHANS=",0," ERR ",0," OFF=",0," LEN=",0," DATA=",0," VOL=",0," BACKEND=",0," CLUSTER=",0," TOTAL=",0," DEV=",0," PART_START=",0," PART_SECTORS=",0," SCHEME=",0,0
; Job outcomes, preservation and queue/tree progress are state. NONCE, elapsed time and rate are not.
; Keep both native error spellings: a job's ERR=<reason> and a request's ERR <reason>.
str_hse_fsjob_witness: db " STATE=",0," DONE=",0," TOTAL=",0," PHASE=",0," DURABLE=",0," ERR ",0," PRESERVED=",0," KEPT=",0," POS=",0," ERR=",0," FILES_DONE=",0," SKIPPED=",0," RESULT=",0," CHECK=",0," COMPLETE=",0," REASON=",0," FILES=",0," DIRS=",0," BYTES=",0," NEED=",0," FREE=",0," FITS=",0," ISSUES=",0," LISTED=",0," SAME=",0," I=",0," KIND=",0," PATHHEX=",0,0
str_hse_net:           db "net", 0
str_hse_guest:         db "guest", 0
str_hse_kind_network:  db "network", 0
str_hse_kind_vm:       db "vm", 0
str_hse_net_schema:    db "inst=none get=NETCFG MEMBERS(owner-signed UDP;authority=native){n:0..8,sel:slot|-,M=<slot:0..7>:<name:safe15|?>:<driver:safe15|?>:<mac:hex12|->:<prio:u32>:<health:ok|degraded|absent|dead|h-u32>:<selected:bool>:<link:up-Mbps-u24|down|err|->} complete=ordered-unique-slots,count,selection,extent;one-use list=same observe=whole-validated-listing set=dhcp:NETCFG DHCP ONCE|static:NETCFG STATIC(owner; live only) input=na cancel=na", 0
str_hse_guest_schema:  db "inst=none get=GUESTVM STAT{running,launches,kboot,load_err,vmexit_reason}|exitstat:GUESTVM EXITSTAT{rev=1,gen:u32,total/pio/timer/intr/other/sync/n/rsn/rip/qual/ilen/rax/rdx/an/asn/arsn/arip/arfl/ablk/aent:u64hex16,retained-after-STOP}|profiles:GUESTVM PROFILES|plan [<profile [a-z0-9-]{1,23}>]:GUESTVM PLAN set=start [<profile [a-z0-9-]{1,23}>]:GUESTVM START(native-profile-admission)|stop:GUESTVM STOP input=key <1..127>:GUESTVM INPUT KEY|ptr <x 0..799> <y 0..599> <buttons 0..7>:GUESTVM INPUT PTR observe=running,launches,kboot,load_err,vmexit_reason,profile,pair_sha256,live_devices,live_mmio,live_leaves,live_reserve;exitstat:rev,gen,total,pio,timer,intr,other,sync,n,rsn,rip,qual,ilen,rax,rdx,an,asn,arsn,arip,arfl,ablk,aent list=na cancel=GUESTVM STOP(args=none;completion=observe)", 0
str_hse_guest_witness: db " running=",0," launches=",0," kboot=",0," load_err=",0," vmexit_reason=",0," rev=",0," gen=",0," total=",0," pio=",0," timer=",0," intr=",0," other=",0," sync=",0," n=",0," rsn=",0," rip=",0," qual=",0," ilen=",0," rax=",0," rdx=",0," profile=",0," pair_sha256=",0," live_devices=",0," live_mmio=",0," live_leaves=",0," live_reserve=",0," an=",0," asn=",0," arsn=",0," arip=",0," arfl=",0," ablk=",0," aent=",0,0
str_hse_net_members:   db "MEMBERS", 0
str_hse_net_dhcp_once: db "DHCP ONCE ", 0
str_hse_net_static:    db "STATIC ", 0
str_hse_word_dhcp:     db "DHCP", 0
str_hse_word_static:   db "STATIC", 0
str_hse_guest_exitstat: db "EXITSTAT", 0
str_hse_guest_stat:    db "STAT", 0
str_hse_guest_start:   db "START", 0
str_hse_guest_stop:    db "STOP", 0
str_hse_guest_profiles: db "PROFILES", 0
str_hse_guest_plan:    db "PLAN", 0
str_hse_guest_key:     db "KEY", 0
str_hse_guest_ptr:     db "PTR", 0
str_hse_guest_in_key:  db "INPUT KEY", 0
str_hse_guest_in_ptr:  db "INPUT PTR", 0
str_hse_guest_trunc:   db HSE_GUEST_TRUNC, 0
str_hse_guest_unterm:  db " hook err=guest_reply_unterminated", 0
str_hse_job:           db "job", 0
str_hse_job_schema:    db "inst=none get=JOBPUB{PUB,ALG} set=compute <nonce [A-Za-z0-9._-]{1,64}>:JOBRUN CAP_COMPUTE <nonce>(one metered job; reply BODY=<receipt> SIG=<ed25519>) observe=PUB list=na input=na cancel=na", 0
str_hse_job_witness:   db "PUB=",0,0
str_hse_word_compute:  db "COMPUTE", 0
str_hse_job_scope:     db "CAP_COMPUTE ", 0
str_hse_verb_jobpub:   db "JOBPUB", 0
str_hse_verb_jobrun:   db "JOBRUN", 0
str_hse_verb_netcfg:   db "NETCFG", 0
str_hse_verb_guestvm:  db "GUESTVM", 0
str_hse_field_hash:    db "HASH", 0
str_hse_root:          db "/", 0
str_hse_sp:            db " ", 0
str_hse_verb_fsinfo:   db "FSINFO", 0
str_hse_verb_fsls:     db "FSLS", 0
str_hse_verb_fsstat:   db "FSSTAT", 0
str_hse_verb_fshash:   db "FSHASH", 0
str_hse_verb_fscopy:   db "FSCOPY", 0
str_hse_verb_fsjob:    db "FSJOB", 0
str_hse_verb_fscancel: db "FSCANCEL", 0

align 8
hook_edge_fs:          times (HE_SZ / 8) dq 0
hook_edge_fsjob:       times (HE_SZ / 8) dq 0
hook_edge_net:         times (HE_SZ / 8) dq 0
hook_edge_guest:       times (HE_SZ / 8) dq 0
hook_edge_job:         times (HE_SZ / 8) dq 0
hse_nonce_ctr:         dq 0
hse_nonce_buf:         times 24 db 0

str_hse_word_rename: db "RENAME", 0
str_hse_verb_fsren: db "FSREN", 0
str_hse_word_mkdir: db "MKDIR",0
str_hse_word_rmdir: db "RMDIR",0
str_hse_verb_fsmkdir: db "FSMKDIR",0
str_hse_verb_fsrmdir: db "FSRMDIR",0
str_hse_verb_fsnew: db "FSNEW",0
str_hse_verb_fsdel: db "FSDEL",0
str_hse_verb_fswrite: db "FSWRITE",0
str_hse_word_create: db "CREATE",0
str_hse_word_delete: db "DELETE",0
str_hse_word_write: db "WRITE",0
str_hse_word_write_at: db "WRITE_AT",0
str_hse_verb_fsread: db "FSREAD",0
str_hse_word_read: db "READ",0
; Passive singleton: only the fixed native STAT literal can be planned. Native
; dispatch owns authority and caller context, including its MUTATE floor. STAT
; may refresh retained launch disposition through its existing power guard;
; this edge never launches, stops, probes or sends. All counters remain semantic:
; observation itself advances none. Flags are retained diagnostics, not proof.
; BSP command serialization owns staging (the existing outer request boundary
; retires native/hook ready flags even before parse/auth refusal). Clear native
; staging before dispatch and consume on every post; only complete records relay.
HGN_REPLY_MAX equ 512                   ; actual guestnet_out_buf, silently clipped at 511
hook_guestnet_plan:
    mov  byte [rel guestnet_out_ready], 0
    mov  byte [rel guestnet_out_buf], 0
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    jne  .bad
    lea  rdi, [rel str_hgn_stat]
    call command_hook_arg_str
    lea  rax, [rel str_hgn_verb]
    ret
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

hook_guestnet_post:
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .native_refused
    push rbx
    push r12
    mov  rbx, rcx
    cmp  byte [rel guestnet_out_ready], 1
    jne  .bad_reply
    lea  rdi, [rel guestnet_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HGN_REPLY_MAX
    jae  .bad_reply
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    mov  r12d, ecx
    call hgn_record
    test eax, eax
    jz   .bad_reply
    call command_hook_out_reset
    lea  rdi, [rel guestnet_out_buf]
    mov  esi, r12d
    call command_hook_out_strn
    jmp  .retire
.bad_reply:
    call command_hook_out_reset
    lea  rdi, [rel str_hgn_bad_reply]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hgn_bad_reply]
    mov  [rbx + RSP_HINT], rax
.retire:
    mov  byte [rel guestnet_out_ready], 0
    mov  byte [rel guestnet_out_buf], 0
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.native_refused:
    mov  byte [rel guestnet_out_ready], 0
    mov  byte [rel guestnet_out_buf], 0
    xor  eax, eax                       ; preserve the native refusal envelope
    ret

; Called only after the capacity-bounded NUL scan. Exact field order, canonical
; natural decimal widths, enum spellings, complete final boolean and NUL. No
; prefix/truncated record is a snapshot. Native error-to-reason mapping is exact.
hgn_record:
    push rbx
    push r12
    lea  rsi, [rel str_hgn_head]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 255
    call hgn_number
    test eax, eax
    jz   .no
    cmp  byte [rdi], '.'
    jne  .no
    inc  rdi
    mov  r8d, 255
    call hgn_number
    test eax, eax
    jz   .no
    cmp  byte [rdi], '.'
    jne  .no
    inc  rdi
    mov  r8d, 255
    call hgn_number
    test eax, eax
    jz   .no
    cmp  byte [rdi], '.'
    jne  .no
    inc  rdi
    mov  r8d, 255
    call hgn_number
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_nat]
    call hgn_literal
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_nat_values]
    call hgn_choice
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_launch]
    call hgn_literal
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_launch_values]
    call hgn_choice
    test eax, eax
    jz   .no
    mov  ebx, edx
    lea  rsi, [rel str_hgn_err]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 255
    call hgn_number
    test eax, eax
    jz   .no
    mov  r12d, edx
    lea  rsi, [rel str_hgn_reason]
    call hgn_literal
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_reason_values]
    call hgn_choice
    test eax, eax
    jz   .no
    ; reason indices: native errors 1..9, unknown=10, then pending=11,
    ; none=12, owner_changed=13, request_not_published=14. Error zero
    ; otherwise means not_requested (including refused).
    test r12d, r12d
    jz   .zero_error
    cmp  r12d, 9
    jbe  .reason_check
    cmp  r12d, 254
    je   .owner_changed
    cmp  r12d, 253
    je   .unpublished
    mov  r12d, 10
    jmp  .reason_check
.owner_changed:
    mov  r12d, 13
    jmp  .reason_check
.unpublished:
    mov  r12d, 14
    jmp  .reason_check
.zero_error:
    cmp  ebx, 1
    jne  .not_requested
    mov  r12d, 11
    jmp  .reason_check
.not_requested:
    cmp  ebx, 2
    jne  .reason_check
    mov  r12d, 12
.reason_check:
    cmp  edx, r12d
    jne  .no
    lea  rsi, [rel str_hgn_shell]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 1
    call hgn_number
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_probes]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 255
    call hgn_number
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_dhcp_injected]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 1
    call hgn_number
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_guest_tx_packets]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 4294967295
    call hgn_number
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_nat_forwarded]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 4294967295
    call hgn_number
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_nat_returned]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 4294967295
    call hgn_number
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_ipv4]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 4294967295
    call hgn_number
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_udp]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 4294967295
    call hgn_number
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_dhcp]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 4294967295
    call hgn_number
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_discover]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 4294967295
    call hgn_number
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_request]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 4294967295
    call hgn_number
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_tagged]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 4294967295
    call hgn_number
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_replies]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 4294967295
    call hgn_number
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_reply_attempts]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 4294967295
    call hgn_number
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_rx_nobuf]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 4294967295
    call hgn_number
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_frame_len]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 4294967295
    call hgn_number
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_l2_at_10]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 4294967295
    call hgn_number
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_l2_at_12]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 4294967295
    call hgn_number
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgn_running]
    call hgn_literal
    test eax, eax
    jz   .no
    mov  r8d, 1
    call hgn_number
    test eax, eax
    jz   .no
    cmp  byte [rdi], 0
    jne  .no
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; Exact literal including leading delimiters; never advances past a source NUL.
hgn_literal:
    mov  al, [rsi]
    test al, al
    jz   .yes
    cmp  al, [rdi]
    jne  .no
    inc  rsi
    inc  rdi
    jmp  hgn_literal
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Natural decimal <= R8D (up to UINT32_MAX). The zero form is a single byte;
; the caller must validate the next delimiter. RDI advances, EDX is the value.
hgn_number:
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
    cmp  rdx, r8
    ja   .no
    inc  ecx
    inc  rdi
    jmp  .next
.end:
    xor  eax, eax
    test ecx, ecx
    setnz al
    ret
.no:
    xor  eax, eax
    ret

; A NUL-separated enum table, terminated by an empty entry. Exact single token;
; RDI advances, EDX is index. No prefix may match or run beyond source NUL.
hgn_choice:
    xor  edx, edx
.option:
    cmp  byte [rsi], 0
    je   .no
    xor  ecx, ecx
.match:
    mov  al, [rsi + rcx]
    test al, al
    jz   .end
    cmp  al, [rdi + rcx]
    jne  .skip
    inc  ecx
    jmp  .match
.end:
    cmp  byte [rdi + rcx], ' '
    je   .yes
    cmp  byte [rdi + rcx], 0
    je   .yes
.skip:
    cmp  byte [rsi], 0
    lea  rsi, [rsi + 1]
    jne  .skip
    inc  edx
    jmp  .option
.yes:
    add  rdi, rcx
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

str_hgn_name: db "guestnet", 0
str_hgn_verb: db "GUESTNET", 0
str_hgn_stat: db "STAT", 0
str_hgn_bad_reply: db " hook err=guestnet_reply_incomplete", 0
str_hgn_schema: db "v=1 inst=none get=GUESTNET STAT{lease=IPv4,nat=up|down,launch=none|requested|achieved|refused,load_err=u8,load_reason=native,shell_ready=bool,shell_probes=u8,dhcp_injected=bool,guest_tx_packets=u32,nat_forwarded=u32,nat_returned=u32,ipv4=u32,udp=u32,dhcp=u32,discover=u32,request=u32,tagged=u32,replies=u32,reply_attempts=u32,rx_nobuf=u32,frame_len=u32,l2_at_10=u32,l2_at_12=u32,running=bool} observe=all-fields counters=retained-not-poll-counts flags=native-diagnostics no-reachability-proof no-shell-success-proof launch=retained-native-refresh incomplete=refused authority=native list=na set=na input=na cancel=na", 0
str_hgn_nat_values: db "down",0,"up",0,0
str_hgn_launch_values: db "none",0,"requested",0,"achieved",0,"refused",0,0
str_hgn_reason_values: db "not_requested",0,"host_state_or_vmx_refused",0,"guest_memory_region_unavailable",0,"BZIMAGE2_missing_or_malformed",0,"BZIMAGE2_read_failed",0,"INITRD2.GZ_missing_malformed_or_read_failed",0,"vmlaunch_failed",0,"vmexit_or_vmwrite_failed",0,"boot_budget_exceeded",0,"guest_task_spawn_failed",0,"unknown",0,"pending",0,"none",0,"owner_changed",0,"request_not_published",0,0
str_hgn_head: db " GUESTNET lease=", 0
str_hgn_nat: db " nat=", 0
str_hgn_launch: db " launch=", 0
str_hgn_err: db " load_err=", 0
str_hgn_reason: db " load_reason=", 0
str_hgn_shell: db " shell_ready=", 0
str_hgn_probes: db " shell_probes=", 0
str_hgn_dhcp_injected: db " dhcp_injected=", 0
str_hgn_guest_tx_packets: db " guest_tx_packets=", 0
str_hgn_nat_forwarded: db " nat_forwarded=", 0
str_hgn_nat_returned: db " nat_returned=", 0
str_hgn_ipv4: db " ipv4=", 0
str_hgn_udp: db " udp=", 0
str_hgn_dhcp: db " dhcp=", 0
str_hgn_discover: db " discover=", 0
str_hgn_request: db " request=", 0
str_hgn_tagged: db " tagged=", 0
str_hgn_replies: db " replies=", 0
str_hgn_reply_attempts: db " reply_attempts=", 0
str_hgn_rx_nobuf: db " rx_nobuf=", 0
str_hgn_frame_len: db " frame_len=", 0
str_hgn_l2_at_10: db " l2_at_10=", 0
str_hgn_l2_at_12: db " l2_at_12=", 0
str_hgn_running: db " running=", 0
align 8
hook_edge_guestnet: times HE_SZ db 0

; BLKINFO is the authority and the only producer. Serialized command dispatch
; owns these stages. Plan drops earlier output before admission; post requires
; a current pending plan and fresh native ready, validates the ENTIRE record,
; then copies and retires it. No block read/write/flush/RW/class/MMIO bypass.
HBI_REPLY_MAX equ 1152                 ; command_blk's actual staging allocation
HBI_NAME_MAX equ 23
hook_block_plan:
    mov  byte [rel hbi_pending], 0
    mov  byte [rel blk_out_ready], 0
    mov  byte [rel blk_out_buf], 0
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rdx], 0
    jne  .bad
    xor  ecx, ecx
.name:
    movzx eax, byte [rsi + rcx]
    test al, al
    jz   .end
    cmp  ecx, HBI_NAME_MAX
    jae  .bad
    cmp  al, 'a'
    jb   .other
    cmp  al, 'z'
    jbe  .keep
.other:
    test ecx, ecx
    jz   .bad
    cmp  al, '_'
    je   .keep
    cmp  al, '-'
    je   .keep
    sub  al, '0'
    cmp  al, 9
    ja   .bad
.keep:
    mov  al, [rsi + rcx]
    lea  rdi, [rel hbi_backend]
    mov  [rdi + rcx], al
    inc  ecx
    jmp  .name
.end:
    test ecx, ecx
    jz   .bad
    lea  rdi, [rel hbi_backend]
    mov  byte [rdi + rcx], 0
    call command_hook_arg_str
    mov  byte [rel hbi_pending], 1
    lea  rax, [rel str_hbi_verb]
    ret
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

hook_block_post:
    push rbx
    push r12
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .native_refused
    cmp  byte [rel hbi_pending], 1
    jne  .bad
    cmp  byte [rel blk_out_ready], 1
    jne  .bad
    lea  rdi, [rel blk_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HBI_REPLY_MAX
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel blk_out_cur]
    jne  .bad                           ; NUL and producer end must agree
    mov  r12d, ecx
    cmp  ecx, HOOK_OUT_MAX - 1
    ja   .bad
    ; Native no_backend reports an error body with CODE=OK. It remains an error
    ; through the typed interface and never becomes a successful observation.
    lea  rsi, [rel str_hbi_native_e_nodev]
    call strcmp
    test eax, eax
    jz   .native_error
    lea  rdi, [rel blk_out_buf]
    call hbi_record
    test eax, eax
    jz   .bad
    call command_hook_out_reset
    lea  rdi, [rel blk_out_buf]
    mov  esi, r12d
    call command_hook_out_strn
    jmp  .retire
.native_error:
    call command_hook_out_reset
    lea  rdi, [rel str_hbi_native_e_nodev]
    call command_hook_out_str
    jmp  .refuse
.bad:
    call command_hook_out_reset
    lea  rdi, [rel str_hbi_bad]
    call command_hook_out_str
.refuse:
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hbi_bad]
    mov  [rbx + RSP_HINT], rax
.retire:
    call hbi_retire
    mov  eax, 1
    jmp  .out
.native_refused:
    call hbi_retire
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret
hbi_retire:
    mov  byte [rel hbi_pending], 0
    mov  byte [rel blk_out_ready], 0
    mov  byte [rel blk_out_buf], 0
    mov  byte [rel hbi_backend], 0
    ret

; The bounded NUL scan precedes ALL parsing. Each parser stops on NUL and
; advances only on a match. Ordered fields and final NUL reject duplicates,
; foreign identities, suffixes, truncated optional groups and extra records.
hbi_record:
    lea  rsi, [rel str_hbi_native_info_pre]
    call hbi_literal
    test eax, eax
    jz   .no
    lea  rsi, [rel hbi_backend]
    call hbi_literal
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hbi_native_info_model]
    call hbi_literal
    test eax, eax
    jz   .no
    xor  ecx, ecx
.model:
    movzx eax, byte [rdi]
    cmp  al, ' '
    je   .model_end
    cmp  al, 33
    jb   .no
    cmp  al, 126
    ja   .no
    cmp  ecx, 47
    jae  .no
    inc  ecx
    inc  rdi
    jmp  .model
.model_end:
    test ecx, ecx
    jz   .no
    ; Optional serial is native AHCI only; maximum 20 printable bytes, spaces
    ; included (the producer does not sanitize serial as it does the model).
    push rdi
    lea  rsi, [rel str_hbi_native_info_serial]
    call hbi_literal
    test eax, eax
    pop  rax
    jz   .no_serial
    lea  rsi, [rel hbi_backend]
    cmp  dword [rsi], 'ahci'
    jne  .no
    cmp  byte [rsi + 4], '0'
    jb   .no
    cmp  byte [rsi + 4], '7'
    ja   .no
    cmp  byte [rsi + 5], 0
    jne  .no
    xor  r9d, r9d
    xor  r10d, r10d                     ; last complete LBA delimiter within serial bound
    xor  r11d, r11d
.serial:
    push rdi
    lea  rsi, [rel str_hbi_native_info_lba]
    call hbi_literal
    test eax, eax
    pop  rax
    jz   .serial_next
    mov  r10, rdi
    mov  r11d, r9d
.serial_next:
    mov  rdi, rax
    cmp  r9d, 20
    jae  .serial_end
    cmp  byte [rdi], 32
    jb   .serial_end
    cmp  byte [rdi], 126
    ja   .no
    inc  rdi
    inc  r9d
    jmp  .serial
.serial_end:
    test r10, r10
    jz   .no
    test r11d, r11d
    jz   .no
    mov  rdi, r10
    jmp  .sector
.no_serial:
    mov  rdi, rax
    lea  rsi, [rel str_hbi_native_info_lba]
    call hbi_literal
    test eax, eax
    jz   .no
.sector:
    call hbi_decimal
    test eax, eax
    jz   .no
    mov  r8d, 0xffffffff
    cmp  rdx, r8
    ja   .no
    lea  rsi, [rel str_hbi_native_info_max]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  byte [rdi], 0
    je   .yes
    ; The four diagnostics are all present or all absent, only for nvme0.
    lea  rsi, [rel hbi_backend]
    cmp  dword [rsi], 'nvme'
    jne  .no
    cmp  word [rsi + 4], '0'
    jne  .no
    lea  rsi, [rel str_hbi_native_i_csts]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_hex
    test eax, eax
    jz   .no
    mov  r8, 0xffffffff
    cmp  rdx, r8
    ja   .no
    lea  rsi, [rel str_hbi_native_i_cc]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_hex
    test eax, eax
    jz   .no
    mov  r8, 0xffffffff
    cmp  rdx, r8
    ja   .no
    lea  rsi, [rel str_hbi_native_i_pcicmd]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_hex
    test eax, eax
    jz   .no
    mov  r8, 0xffff
    cmp  rdx, r8
    ja   .no
    lea  rsi, [rel str_hbi_native_i_bar]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_hex
    test eax, eax
    jz   .no
    mov  r8, -1
    cmp  rdx, r8
    ja   .no
    cmp  byte [rdi], 0
    jne  .no
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

hbi_literal:
    mov  al, [rsi]
    test al, al
    jz   .yes
    cmp  al, [rdi]
    jne  .no
    inc  rdi
    inc  rsi
    jmp  hbi_literal
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Natural u64, including UINT64_MAX without multiply wrap or saturation.
hbi_decimal:
    xor  edx, edx
    cmp  byte [rdi], '0'
    jne  .digits
    inc  rdi
    mov  eax, 1
    ret
.digits:
    xor  ecx, ecx
    mov  r8, 1844674407370955161
.next:
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 9
    ja   .end
    cmp  rdx, r8
    ja   .no
    jne  .accumulate
    cmp  eax, 5
    ja   .no
.accumulate:
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

; Native fmt_hex may pad up to 16 lower-case digits; accept its full width.
hbi_hex:
    xor  ecx, ecx
    xor  edx, edx
.next:
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 9
    jbe  .digit
    movzx eax, byte [rdi]
    sub  eax, 'a'
    cmp  eax, 5
    ja   .end
    add  eax, 10
.digit:
    cmp  ecx, 16
    jae  .no
    shl  rdx, 4
    or   rdx, rax
    inc  ecx
    inc  rdi
    jmp  .next
.end:
    xor  eax, eax
    test ecx, ecx
    setnz al
    ret
.no:
    xor  eax, eax
    ret

str_hbi_name: db "block", 0
str_hbi_verb: db "BLKINFO", 0
str_hbi_bad: db " hook err=block_reply_incomplete", 0
str_hbi_schema: db "v=1 inst=<backend [a-z][a-z0-9_-]{0,22}> get=BLKINFO{dev,MODEL,[AHCI:SERIAL],LBA:u32,lba_max:u64,[NVMe:csts:u32,cc:u32,pcicmd:u16,bar:u64]} observe=whole-native-inventory-and-diagnostics authority=native errors=refused current=one-use-native-stage capacity=reported-LBA-count-not-free-space no-health-or-install-eligibility-proof list=na set=na input=na cancel=na", 0
hbi_backend: times HBI_NAME_MAX + 1 db 0
hbi_pending: db 0
align 8
hook_edge_block: times HE_SZ db 0

str_hbi_native_e_nodev:    db " BLK ERR no_backend", 0

str_hbi_native_i_bar:      db " bar=0x", 0

str_hbi_native_i_cc:       db " cc=0x", 0

str_hbi_native_i_csts:     db " csts=0x", 0

str_hbi_native_i_pcicmd:   db " pcicmd=0x", 0

str_hbi_native_info_lba:   db " LBA=", 0

str_hbi_native_info_max:   db " lba_max=", 0

str_hbi_native_info_model: db " MODEL=", 0

str_hbi_native_info_pre:   db " BLK INFO dev=", 0

str_hbi_native_info_serial: db " SERIAL=", 0

; SCHEDSTAT is a cached throughput PLACEMENT census, not utilization, active
; work, SMP execution or scheduler health. The producer omits zero counters.
; Dispatch remains native; only a complete current response can be observed.
HSCHED_REPLY_MAX equ 384                  ; command_sched staging ABI
HSCHED_CORES_MAX equ 32                   ; command_sched placement table width
hook_scheduler_plan:
    call hsched_retire
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    jne  .bad
    mov  byte [rel hsched_pending], 1
    lea  rax, [rel str_hsched_verb]
    ret
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

hook_scheduler_post:
    push rbx
    push r12
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .native_refused
    cmp  byte [rel hsched_pending], 1
    jne  .bad
    cmp  byte [rel sched_out_ready], 1
    jne  .bad
    lea  rdi, [rel sched_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HSCHED_REPLY_MAX
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel sched_out_cur]
    jne  .bad                           ; exact native producer end, not a prefix
    mov  r12d, ecx
    call hsched_record
    test eax, eax
    jz   .bad
    call command_hook_out_reset
    lea  rdi, [rel sched_out_buf]
    mov  esi, r12d
    call command_hook_out_strn
    jmp  .retire
.bad:
    call command_hook_out_reset
    lea  rdi, [rel str_hsched_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hsched_bad]
    mov  [rbx + RSP_HINT], rax
.retire:
    call hsched_retire
    mov  eax, 1
    jmp  .out
.native_refused:
    call hsched_retire
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret
hsched_retire:
    mov  byte [rel hsched_pending], 0
    mov  byte [rel sched_out_ready], 0
    mov  byte [rel sched_out_buf], 0
    mov  qword [rel sched_out_cur], 0
    ret

; Parse only after the bounded NUL scan. Strictly increasing, unique indices
; below cores; positive canonical u32 counts. "truncated=1" always refuses,
; including complete native partial replies: no successful partial witness.
hsched_record:
    push r12
    push r13
    lea  rsi, [rel str_hsched_cores]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    test rdx, rdx
    jz   .no
    cmp  rdx, HSCHED_CORES_MAX
    ja   .no
    mov  r12d, edx
    xor  r13d, r13d                     ; smallest next index (zero rows omitted)
.row:
    cmp  byte [rdi], 0
    je   .yes
    lea  rsi, [rel str_hsched_core]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  rdx, r12
    jae  .no
    cmp  rdx, r13
    jb   .no
    lea  r13, [rdx + 1]
    lea  rsi, [rel str_hsched_eq]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    test rdx, rdx
    jz   .no
    mov  ecx, 0xffffffff
    cmp  rdx, rcx
    ja   .no
    lea  rsi, [rel str_hsched_tput]
    call hbi_literal
    test eax, eax
    jz   .no
    jmp  .row
.yes:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    ret
str_hsched_name: db "scheduler", 0
str_hsched_kind: db "service", 0
str_hsched_verb: db "SCHEDSTAT", 0
str_hsched_schema: db "v=1 inst=none get=SCHEDSTAT observe=whole-validated-native-reply fields=cores,ordered-nonzero-core-u32-throughput meaning=cached-throughput-placement-counts zero=omitted limits=cores1..32,reply383 partial=refused no-load-or-liveness-proof list=na set=na input=na cancel=na authority=native", 0
str_hsched_bad: db " hook err=scheduler_reply_incomplete", 0
str_hsched_cores: db " cores=", 0
str_hsched_core: db " core", 0
str_hsched_eq: db "=", 0
str_hsched_tput: db "throughput", 0
hsched_pending: db 0
align 8
hook_edge_scheduler: times HE_SZ db 0

; Native RTADMIT computes a fixed-demand budget test. It reserves no capacity
; and performs no timing/placement work. The fixed token is correlation only.
HRT_REPLY_MAX equ 384
hook_rtadmit_plan:
    call hrt_retire
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rdx], 0
    jne  .bad
    cmp  word [rsi], 'ok'
    jne  .over
    cmp  byte [rsi + 2], 0
    jne  .bad
    mov  qword [rel hrt_demand], 300
    lea  rdi, [rel str_hrt_arg_ok]
    jmp  .arg
.over:
    cmp  dword [rsi], 'over'
    jne  .bad
    cmp  byte [rsi + 4], 0
    jne  .bad
    mov  qword [rel hrt_demand], 900
    lea  rdi, [rel str_hrt_arg_over]
.arg:
    call command_hook_arg_reset
    call command_hook_arg_str
    mov  byte [rel hrt_pending], 1
    lea  rax, [rel str_hrt_verb]
    xor  edx, edx
    ret
.na:
    xor  eax, eax
    mov  edx, HOOK_PLAN_NA
    ret
.bad:
    xor  eax, eax
    mov  edx, HOOK_PLAN_BADARG
    ret
hook_rtadmit_post:
    push rbx
    push r12
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .native_refused
    cmp  byte [rel hrt_pending], 1
    jne  .bad
    cmp  byte [rel rt_out_ready], 1
    jne  .bad
    lea  rdi, [rel rt_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HRT_REPLY_MAX
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel rt_out_cur]
    jne  .bad                           ; exact native producer end, not a prefix
    mov  r12d, ecx
    call hrt_record
    test eax, eax
    jz   .bad
    call command_hook_out_reset
    lea  rdi, [rel rt_out_buf]
    mov  esi, r12d
    call command_hook_out_strn
    jmp  .retire
.bad:
    call command_hook_out_reset
    lea  rdi, [rel str_hrt_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hrt_bad]
    mov  [rbx + RSP_HINT], rax
.retire:
    call hrt_retire
    mov  eax, 1
    jmp  .out
.native_refused:
    call hrt_retire
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret
hrt_retire:
    mov  byte [rel hrt_pending], 0
    mov  byte [rel rt_out_ready], 0
    mov  byte [rel rt_out_buf], 0
    mov  qword [rel rt_out_cur], 0
    ret

; Complete canonical fields; verdict/reason must agree with the selected demand
; and available budget. The bound scan always runs before this parser.
hrt_record:
    push r12
    push r13
    mov  r12, rdi
    lea  rsi, [rel str_hrt_yes]
    call hbi_literal
    test eax, eax
    jnz  .true
    mov  rdi, r12
    lea  rsi, [rel str_hrt_no]
    call hbi_literal
    test eax, eax
    jz   .no
    xor  r12d, r12d
    jmp  .demand
.true:
    mov  r12d, 1
.demand:
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  rdx, [rel hrt_demand]
    jne  .no
    mov  r13, rdx
    lea  rsi, [rel str_hrt_avail]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  rdx, 700
    ja   .no
    cmp  r13, rdx
    setbe al
    movzx eax, al
    cmp  eax, r12d
    jne  .no
    lea  rsi, [rel str_hrt_tail]
    call hbi_literal
    test eax, eax
    jz   .no
    cmp  byte [rdi], 0
    jne  .no
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    ret

str_hrt_name: db "rtadmit", 0
str_hrt_kind: db "service", 0
str_hrt_verb: db "RTADMIT", 0
str_hrt_schema: db "v=1 inst=ok|over get=RTADMIT observe=whole-validated-native-reply fields=admitted,reason,demand,avail,cap units=permille demand=300|900 cap=700 correlation=fixed limits=reply383 no-reservation-or-latency-proof list=na set=na input=na cancel=na authority=native", 0
str_hrt_arg_ok: db "ok hook", 0
str_hrt_arg_over: db "over hook", 0
str_hrt_yes: db " admitted=true reason=fits demand=", 0
str_hrt_no: db " admitted=false reason=over_budget demand=", 0
str_hrt_avail: db " avail=", 0
str_hrt_tail: db " cap=700 nonce=hook", 0
str_hrt_bad: db " hook err=rtadmit_reply_incomplete", 0
align 8
hook_edge_rtadmit: times HE_SZ db 0
hrt_pending: db 0
align 8
hrt_demand: dq 0

; Read-only native single-vCPU SUMMARY projection. It neither starts a guest
; nor changes placement/run time. CPU 0 returns existing native per-vCPU counters.
; The native producer is not an atomic snapshot.
HGC_REPLY_MAX equ 1024
hook_guestcpu_plan:
    call hgc_retire
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rdx], 0
    jne  .bad
    cmp  byte [rsi], 0
    je   .summary
    cmp  word [rsi], '0'
    jne  .bad
    mov  byte [rel hgc_pending], 2
    jmp  .arg
.summary:
    mov  byte [rel hgc_pending], 1
.arg:
    call command_hook_arg_reset
    xor  edi, edi
    call hse_arg_nonce
    lea  rdi, [rel str_hgc_arg]
    cmp  byte [rel hgc_pending], 2
    jne  .append
    lea  rdi, [rel str_hgc_cpu_arg]
.append:
    call command_hook_arg_str
    lea  rax, [rel str_hgc_verb]
    xor  edx, edx
    ret
.na:
    xor  eax, eax
    mov  edx, HOOK_PLAN_NA
    ret
.bad:
    xor  eax, eax
    mov  edx, HOOK_PLAN_BADARG
    ret
hook_guestcpu_post:
    push rbx
    push r12
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    movzx eax, byte [rel hgc_pending]
    dec  eax
    cmp  eax, 1
    ja   .bad
    cmp  byte [rel smpobs_out_ready], 1
    jne  .bad
    lea  rdi, [rel smpobs_out_buf]
    cmp  [rbx + RSP_VAL], rdi
    jne  .bad                          ; exact native producer result
    xor  ecx, ecx
.length:
    cmp  ecx, HGC_REPLY_MAX
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel smpobs_out_cur]
    jne  .bad
    lea  rsi, [rel str_hgc_nonce]
    call hbi_literal
    test eax, eax
    jz   .bad
    lea  rsi, [rel hse_nonce_buf]
    call hbi_literal
    test eax, eax
    jz   .bad
    mov  r12, rdi                     ; whole native data after correlation
    cmp  byte [rel hgc_pending], 2
    je   .cpu
    call hgc_record
    jmp  .recorded
.cpu:
    call hgc_cpu_record
.recorded:
    test eax, eax
    jz   .bad
    sub  rdi, r12
    push rdi
    call command_hook_out_reset
    lea  rdi, [rel str_hgc_head]
    call command_hook_out_str
    pop  rsi
    mov  rdi, r12
    call command_hook_out_strn
    jmp  .done
.bad:
    call command_hook_out_reset
    lea  rdi, [rel str_hgc_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hgc_bad]
    mov  [rbx + RSP_HINT], rax
.done:
    call hgc_retire
    mov  eax, 1
    jmp  .out
.refused:
    call hgc_retire
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret
hgc_retire:
    mov  byte [rel hgc_pending], 0
    mov  byte [rel smpobs_out_ready], 0
    mov  byte [rel smpobs_out_buf], 0
    mov  qword [rel smpobs_out_cur], 0
    ret

; Complete ordered SUMMARY grammar. Native state/backend are observations;
; no relationship between independently rendered fields implies atomicity.
hgc_record:
    lea  rsi, [rel str_hgc_max]
    call hbi_literal
    test eax, eax
    jz   .no
    call hgc_u32
    test eax, eax
    jz   .no
    test rdx, rdx
    jz   .no
    lea  rsi, [rel str_hgc_online]
    call hbi_literal
    test eax, eax
    jz   .no
    call hgc_u32
    test eax, eax
    jz   .no
    cmp  rdx, 1
    ja   .no
    lea  rsi, [rel str_hgc_generation]
    call hbi_literal
    test eax, eax
    jz   .no
    call hgc_u32
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgc_state]
    call hbi_literal
    test eax, eax
    jz   .no
    lea  rsi, [rel hgc_states]
    call hgc_enum
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgc_backend]
    call hbi_literal
    test eax, eax
    jz   .no
    lea  rsi, [rel hgc_backends]
    call hgc_enum
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgc_tail]
    call hbi_literal
    test eax, eax
    jz   .no
    cmp  byte [rdi], 0
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret
; Exact CPU 0 receipt. Independent native fields remain observations rather
; than an atomic placement/latency claim. All counters retain unsigned64 width.
hgc_cpu_record:
    push rbx
    lea  rsi, [rel str_hgc_cpu_state]
    call hbi_literal
    test eax, eax
    jz   .no
    lea  rsi, [rel hgc_states]
    call hgc_enum
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hgc_host]
    call hbi_literal
    test eax, eax
    jz   .no
    cmp  dword [rdi], 'none'
    jne  .host_number
    add  rdi, 4
    jmp  .counters
.host_number:
    call hgc_u32
    test eax, eax
    jz   .no
    cmp  rdx, MAXCORE
    jae  .no
.counters:
    lea  rbx, [rel hgc_counter_labels]
.next:
    mov  rsi, rbx
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
.skip_label:
    cmp  byte [rbx], 0
    lea  rbx, [rbx + 1]
    jne  .skip_label
    cmp  byte [rbx], 0
    jne  .next
    cmp  byte [rdi], 0
    jne  .no
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  rbx
    ret
hgc_u32:
    call hbi_decimal
    test eax, eax
    jz   .out
    mov  ecx, 0xffffffff
    cmp  rdx, rcx
    jbe  .out
    xor  eax, eax
.out:
    ret
hgc_enum:
    push rbx
    push r12
    mov  r12, rdi
    mov  rbx, rsi
.next:
    mov  rdi, r12
    mov  rsi, rbx
    call hbi_literal
    test eax, eax
    jnz  .out
.skip:
    cmp  byte [rbx], 0
    lea  rbx, [rbx + 1]
    jne  .skip
    cmp  byte [rbx], 0
    jne  .next
    mov  rdi, r12
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

str_hgc_name: db "guestcpu", 0
str_hgc_kind: db "vm", 0
str_hgc_verb: db "GUESTCPU", 0
str_hgc_arg: db " SUMMARY", 0
str_hgc_cpu_arg: db " CPU 0", 0
str_hgc_cpu_state: db " vcpu=0 state=", 0
str_hgc_host: db " host_logical=", 0
hgc_counter_labels: db " run_ns=",0," exits=",0," interrupts=",0," halt_wakes=",0," last_progress_ms=",0," faults=",0,0
str_hgc_nonce: db "nonce=", 0
str_hgc_schema: db "v=1 inst=none(SUMMARY)|0(CPU 0) get=GUESTCPU SUMMARY{max_vcpus:u32,configured:1,online:bool,generation:u32,state:stopped|runnable|running|halted|degraded,backend:vmx|svm|unavailable,ai_projection:registry}|CPU 0{vcpu:0,state,host_logical:none|0..MAXCORE-1,run_ns:u64,exits:u64,interrupts:u64,halt_wakes:u64,last_progress_ms:u64,faults:u64} observe=whole-selected-native-fields nonce=excluded scope=saved-software not-atomic no-placement-or-guest-runtime-proof authority=native-public list=na set=na input=na cancel=na", 0
str_hgc_head: db " guestcpu v=1 scope=saved-software", 0
str_hgc_bad: db " hook err=guestcpu_reply_incomplete", 0
str_hgc_max: db " max_vcpus=", 0
str_hgc_online: db " configured=1 online=", 0
str_hgc_generation: db " generation=", 0
str_hgc_state: db " state=", 0
str_hgc_backend: db " backend=", 0
str_hgc_tail: db " ai_projection=registry", 0
hgc_states: db "stopped",0,"runnable",0,"running",0,"halted",0,"degraded",0,0
hgc_backends: db "vmx",0,"svm",0,"unavailable",0,0
align 8
hook_edge_guestcpu: times HE_SZ db 0
hgc_pending: db 0

; Cached native C2RECOVERY observation. No preload, EFI or recovery operation.
HRC_REPLY_MAX equ 480
hook_recovery_plan:
    call hrc_retire
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    jne  .bad
    lea  rax, [rel str_hrc_verb]
    mov  byte [rel hrc_pending], 1
    xor  edx, edx
    ret
.na:
    xor  eax, eax
    mov  edx, HOOK_PLAN_NA
    ret
.bad:
    xor  eax, eax
    mov  edx, HOOK_PLAN_BADARG
    ret
hook_recovery_post:
    push rbx
    push r12
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  byte [rel hrc_pending], 1
    jne  .bad
    cmp  byte [rel c2rs_out_ready], 1
    jne  .bad
    lea  rdi, [rel c2rs_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HRC_REPLY_MAX
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel c2rs_out_cur]
    jne  .bad
    mov  r12, rdi
    call hrc_record
    test eax, eax
    jz   .bad
    cmp  [rbx + RSP_VAL], rdx           ; native availability binds grammar branch
    jne  .bad
    sub  rdi, r12
    push rdi
    call command_hook_out_reset
    pop  rsi
    mov  rdi, r12
    call command_hook_out_strn
    jmp  .done
.bad:
    call command_hook_out_reset
    lea  rdi, [rel str_hrc_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hrc_bad]
    mov  [rbx + RSP_HINT], rax
.done:
    call hrc_retire
    mov  eax, 1
    jmp  .out
.refused:
    call hrc_retire
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret
hrc_retire:
    mov  byte [rel hrc_pending], 0
    mov  byte [rel c2rs_out_ready], 0
    mov  byte [rel c2rs_out_buf], 0
    mov  qword [rel c2rs_out_cur], 0
    ret

; RDI=bounded native row; EAX=complete, RDX=matched availability on success.
hrc_record:
    push r12
    xor  r12d, r12d
    lea  rsi, [rel str_hrc_prefix]
    call hbi_literal
    test eax, eax
    jz   .no
    cmp  byte [rdi], 'm'
    jne  .unavailable
    lea  rsi, [rel str_hrc_matched]
    call hbi_literal
    test eax, eax
    jz   .no
    mov  ecx, 16
    call hrc_hex
    test eax, eax
    jz   .no
    lea  rsi, [rel hrc_matched_fields]
    call hrc_fields8
    test eax, eax
    jz   .no
    mov  r12d, 1
    jmp  .common
.unavailable:
    lea  rsi, [rel str_hrc_unavailable]
    call hbi_literal
    test eax, eax
    jz   .no
.common:
    lea  rsi, [rel hrc_common_fields]
    call hrc_fields8
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hrc_policy]
    call hbi_literal
    test eax, eax
    jz   .no
    cmp  byte [rdi], 0
    jne  .no
    mov  rdx, r12
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r12
    ret
hrc_fields8:
    push rbx
    mov  rbx, rsi
.next:
    mov  rsi, [rbx]
    test rsi, rsi
    jz   .yes
    add  rsi, rbx                     ; self-relative literal at this live row
    call hbi_literal
    test eax, eax
    jz   .out
    mov  ecx, 2
    call hrc_hex
    test eax, eax
    jz   .out
    add  rbx, 8
    jmp  .next
.yes:
    mov  eax, 1
.out:
    pop  rbx
    ret
; Exact native lowercase 0x + ECX digits. No broader integer spellings.
hrc_hex:
    cmp  word [rdi], '0x'
    jne  .no
    add  rdi, 2
.next:
    mov  al, [rdi]
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .digit
    cmp  al, 'a'
    jb   .no
    cmp  al, 'f'
    ja   .no
.digit:
    inc  rdi
    loop .next
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret
str_hrc_name: db "recovery",0
str_hrc_kind: db "service",0
str_hrc_verb: db "C2RECOVERY",0
str_hrc_schema: db "v=2 inst=none get=C2RECOVERY{journal:matched|unavailable,generation:hex64,verified_mask:hex8,quarantine_mask:hex8,failure_count:hex8,boot_in_progress:hex8,manager_launch:hex8,entry:hex8,profile:hex8,reason:hex8,strong_health_published:hex8,notice_kind:hex8,recovery_policy,failure_evidence,direct_bootmgfw_write:0,writes:0} unavailable=journal-fields-absent observe=whole-native-reply scope=cached-manager-journal-and-publication-latch authority=native no-recovery-selection-or-health-proof list=na set=na input=na cancel=na",0
str_hrc_bad: db " hook err=recovery_reply_incomplete",0
str_hrc_prefix: db " c2_recovery journal=",0
str_hrc_matched: db "matched generation=",0
str_hrc_unavailable: db "unavailable",0
str_hrc_verified: db " verified_mask=",0
str_hrc_quarantine: db " quarantine_mask=",0
str_hrc_failures: db " failure_count=",0
str_hrc_bip: db " boot_in_progress=",0
str_hrc_launch: db " manager_launch=",0
str_hrc_entry: db " entry=",0
str_hrc_profile: db " profile=",0
str_hrc_reason: db " reason=",0
str_hrc_published: db " strong_health_published=",0
str_hrc_notice: db " notice_kind=",0
str_hrc_policy: db " recovery_policy=vault-digest+verified-slot+journalstore-readback failure_evidence=preserve-until-strong-health direct_bootmgfw_write=0 writes=0",0
align 8
; Pointer entries are signed offsets from their own cells; zero ends a table.
hrc_matched_fields:
    dq str_hrc_verified - $
    dq str_hrc_quarantine - $
    dq str_hrc_failures - $
    dq str_hrc_bip - $
    dq 0
hrc_common_fields:
    dq str_hrc_launch - $
    dq str_hrc_entry - $
    dq str_hrc_profile - $
    dq str_hrc_reason - $
    dq str_hrc_published - $
    dq str_hrc_notice - $
    dq 0
hook_edge_recovery: times HE_SZ db 0
hrc_pending: db 0

; Cached native C3WATCH observation. No checkpoint writes, recovery or reset operation.
HCW_REPLY_MAX equ 640
hook_watchdog_plan:
    call hcw_retire
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    jne  .bad
    lea  rax, [rel str_hcw_verb]
    mov  byte [rel hcw_pending], 1
    xor  edx, edx
    ret
.na:
    xor  eax, eax
    mov  edx, HOOK_PLAN_NA
    ret
.bad:
    xor  eax, eax
    mov  edx, HOOK_PLAN_BADARG
    ret
hook_watchdog_post:
    push rbx
    push r12
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  byte [rel hcw_pending], 1
    jne  .bad
    cmp  byte [rel c3wd_out_ready], 1
    jne  .bad
    lea  rdi, [rel c3wd_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HCW_REPLY_MAX
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel c3wd_out_cur]
    jne  .bad
    mov  r12, rdi
    call hcw_record
    test eax, eax
    jz   .bad
    cmp  [rbx + RSP_VAL], rdx           ; native durability byte binds the complete reply
    jne  .bad
    sub  rdi, r12
    push rdi
    call command_hook_out_reset
    pop  rsi
    mov  rdi, r12
    call command_hook_out_strn
    jmp  .done
.bad:
    call command_hook_out_reset
    lea  rdi, [rel str_hcw_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hcw_bad]
    mov  [rbx + RSP_HINT], rax
.done:
    call hcw_retire
    mov  eax, 1
    jmp  .out
.refused:
    call hcw_retire
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret
hcw_retire:
    mov  byte [rel hcw_pending], 0
    mov  byte [rel c3wd_out_ready], 0
    mov  byte [rel c3wd_out_buf], 0
    mov  qword [rel c3wd_out_cur], 0
    ret

; RDI=bounded native row. EAX=complete, RDX=native durable byte.
hcw_record:
    push rbx
    push r12
    push r13
    xor  r12d, r12d
    lea  rsi, [rel str_hcw_prefix]
    call hbi_literal
    test eax, eax
    jz   .no
    cmp  byte [rdi], 'd'
    jne  .unavailable
    lea  rsi, [rel str_hcw_durable]
    call hbi_literal
    test eax, eax
    jz   .no
    mov  r12d, 1
    jmp  .fields
.unavailable:
    lea  rsi, [rel str_hcw_unavailable]
    call hbi_literal
    test eax, eax
    jz   .no
.fields:
    lea  rbx, [rel hcw_leading_fields]
    call hcw_fields
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hcw_durable_field]
    call hbi_literal
    test eax, eax
    jz   .no
    mov  ecx, 2
    call hcw_hex
    test eax, eax
    jz   .no
    mov  r13, rdx
    test r12d, r12d
    jz   .common
    cmp  edx, 1                         ; durable label requires native durable=1
    jne  .no
.common:
    lea  rbx, [rel hcw_remaining_fields]
    call hcw_fields
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hcw_policy]
    call hbi_literal
    test eax, eax
    jz   .no
    cmp  byte [rdi], 0
    jne  .no
    mov  rdx, r13
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
; RBX=(literal,width) pairs, terminated by null literal.
hcw_fields:
.next:
    mov  rsi, [rbx]
    test rsi, rsi
    jz   .yes
    add  rsi, rbx                     ; self-relative literal at this live row
    call hbi_literal
    test eax, eax
    jz   .out
    mov  ecx, [rbx + 8]
    call hcw_hex
    test eax, eax
    jz   .out
    add  rbx, 16
    jmp  .next
.yes:
    mov  eax, 1
.out:
    ret
; Exact native lowercase 0x + ECX digits, value in EDX (at most32bits).
hcw_hex:
    cmp  word [rdi], '0x'
    jne  .no
    add  rdi, 2
    xor  edx, edx
.next:
    movzx eax, byte [rdi]
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .digit
    cmp  al, 'a'
    jb   .no
    cmp  al, 'f'
    ja   .no
    sub  eax, 'a' - 10
    jmp  .accumulate
.digit:
    sub  eax, '0'
.accumulate:
    shl  edx, 4
    or   edx, eax
    inc  rdi
    loop .next
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret
str_hcw_name: db "watchdog",0
str_hcw_kind: db "service",0
str_hcw_verb: db "C3WATCH",0
str_hcw_schema: db "v=1 inst=none get=C3WATCH{checkpoint:durable|unavailable,stage:hex8,transition:hex8,result:hex8,durable:hex8,checkpoint_rc:hex8,p6_elapsed_ms:hex32,p6_budget_ms:hex32,p3_start_checkpoint_ms:hex32,p3_start_status:hex8,p3_elapsed_ms:hex32,p3_budget_ms:hex32,p3_total_status:hex8,manager_launch:hex8,entry:hex8,profile:hex8,reason:hex8,strong_health:hex8,recovery_owner,retry_budget,routes,timeout_min_s,timeout_max_s,false_health,power_cycle:0,tco_selfreset:0,direct_bootmgfw_write:0} observe=whole-native-reply scope=cached-checkpoint-and-timing authority=native recovery-owner=manager no-reset-recovery-or-health-proof list=na set=na input=na cancel=na",0
str_hcw_bad: db " hook err=watchdog_reply_incomplete",0
str_hcw_prefix: db " c3_watch checkpoint=",0
str_hcw_durable: db "durable",0
str_hcw_unavailable: db "unavailable",0
str_hcw_stage: db " stage=",0
str_hcw_transition: db " transition=",0
str_hcw_result: db " result=",0
str_hcw_durable_field: db " durable=",0
str_hcw_checkpoint_rc: db " checkpoint_rc=",0
str_hcw_p6_elapsed: db " p6_elapsed_ms=",0
str_hcw_p6_budget: db " p6_budget_ms=",0
str_hcw_p3_start: db " p3_start_checkpoint_ms=",0
str_hcw_p3_start_status: db " p3_start_status=",0
str_hcw_p3_elapsed: db " p3_elapsed_ms=",0
str_hcw_p3_budget: db " p3_budget_ms=",0
str_hcw_p3_total_status: db " p3_total_status=",0
str_hcw_manager: db " manager_launch=",0
str_hcw_entry: db " entry=",0
str_hcw_profile: db " profile=",0
str_hcw_reason: db " reason=",0
str_hcw_health: db " strong_health=",0
str_hcw_policy:
    db " recovery_owner=manager retry_budget=one-safe-per-verified-slot"
    db " routes=safe>known-good>rescue timeout_min_s=3 timeout_max_s=30"
    db " false_health=refuse-until-p8-complete power_cycle=0 tco_selfreset=0"
    db " direct_bootmgfw_write=0",0
align 8
hcw_leading_fields:
    dq str_hcw_stage - $, 2
    dq str_hcw_transition - $, 2
    dq str_hcw_result - $, 2
    dq 0, 0
hcw_remaining_fields:
    dq str_hcw_checkpoint_rc - $, 2
    dq str_hcw_p6_elapsed - $, 8
    dq str_hcw_p6_budget - $, 8
    dq str_hcw_p3_start - $, 8
    dq str_hcw_p3_start_status - $, 2
    dq str_hcw_p3_elapsed - $, 8
    dq str_hcw_p3_budget - $, 8
    dq str_hcw_p3_total_status - $, 2
    dq str_hcw_manager - $, 2
    dq str_hcw_entry - $, 2
    dq str_hcw_profile - $, 2
    dq str_hcw_reason - $, 2
    dq str_hcw_health - $, 2
    dq 0, 0
hook_edge_watchdog: times HE_SZ db 0
hcw_pending: db 0

; Cached native C7HEALTH observation. No publication, EFI, promotion or policy operation.
HCH_REPLY_MAX equ 768
hook_health_plan:
    call hch_retire
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    jne  .bad
    lea  rax, [rel str_hch_verb]
    mov  byte [rel hch_pending], 1
    xor  edx, edx
    ret
.na:
    xor  eax, eax
    mov  edx, HOOK_PLAN_NA
    ret
.bad:
    xor  eax, eax
    mov  edx, HOOK_PLAN_BADARG
    ret
hook_health_post:
    push rbx
    push r12
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  byte [rel hch_pending], 1
    jne  .bad
    cmp  byte [rel c7hv_out_ready], 1
    jne  .bad
    lea  rdi, [rel c7hv_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HCH_REPLY_MAX
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel c7hv_out_cur]
    jne  .bad
    mov  r12, rdi
    call hch_record
    test eax, eax
    jz   .bad
    cmp  [rbx + RSP_VAL], rdx           ; native availability value binds the complete reply
    jne  .bad
    sub  rdi, r12
    push rdi
    call command_hook_out_reset
    pop  rsi
    mov  rdi, r12
    call command_hook_out_strn
    jmp  .done
.bad:
    call command_hook_out_reset
    lea  rdi, [rel str_hch_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hch_bad]
    mov  [rbx + RSP_HINT], rax
.done:
    call hch_retire
    mov  eax, 1
    jmp  .out
.refused:
    call hch_retire
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret
hch_retire:
    mov  byte [rel hch_pending], 0
    mov  byte [rel c7hv_out_ready], 0
    mov  byte [rel c7hv_out_buf], 0
    mov  qword [rel c7hv_out_cur], 0
    ret

; RDI=bounded native row; EAX=complete, RDX=native availability.
; The handoff payload hash is a claim, separate from the running build ID.
hch_record:
    push rbx
    push r12
    push r13
    push r14
    xor  r12d, r12d
    lea  rsi, [rel str_hch_prefix]
    call hbi_literal
    test eax, eax
    jz   .no
    cmp  byte [rdi], 'v'
    jne  .unavailable
    lea  rsi, [rel str_hch_valid]
    call hbi_literal
    test eax, eax
    jz   .no
    mov  r12d, 1
    lea  rsi, [rel str_hch_entry]
    call hbi_literal
    test eax, eax
    jz   .no
    call hch_hex_prefix
    test eax, eax
    jz   .no
    mov  ecx, 2
    call hch_hex
    test eax, eax
    jz   .no
    cmp  rdx, 1
    jb   .no
    cmp  rdx, 2
    ja   .no
    lea  rbx, [rel hch_identity_fields]
.identity:
    mov  rsi, [rbx]
    test rsi, rsi
    jz   .payload
    add  rsi, rbx                     ; self-relative literal at this live row
    call hbi_literal
    test eax, eax
    jz   .no
    call hch_hex_prefix
    test eax, eax
    jz   .no
    mov  ecx, 16
    call hch_hex
    test eax, eax
    jz   .no
    test rdx, rdx
    jz   .no
    add  rbx, 8
    jmp  .identity
.payload:
    lea  rsi, [rel str_hch_payload]
    call hbi_literal
    test eax, eax
    jz   .no
    mov  ecx, 64
    call hch_hex
    test eax, eax
    jz   .no
    test r8, r8                       ; native core predicate requires nonzero payload claim
    jz   .no
    lea  rsi, [rel str_hch_build_id]
    call hbi_literal
    test eax, eax
    jz   .no
    xor  r13d, r13d
    cmp  byte [rdi], ' '
    je   .bid                          ; native UNMEASURED may have no hex text
    mov  ecx, 64
    call hch_hex
    test eax, eax
    jz   .no
    mov  r13d, 1
.bid:
    lea  rsi, [rel str_hch_bid]
    call hbi_literal
    test eax, eax
    jz   .no
    lea  rbx, [rel hch_bid_values]
    call hch_choice
    test eax, eax
    jz   .no
    test r13d, r13d
    jnz  .core
    cmp  edx, 3                       ; empty build text belongs only to unmeasured
    jne  .no
.core:
    lea  rsi, [rel str_hch_core]
    call hbi_literal
    test eax, eax
    jz   .no
    lea  rbx, [rel hch_status_values]
    call hch_choice
    test eax, eax
    jz   .no
    mov  r13, rdx                     ; network status index
    lea  rsi, [rel str_hch_display]
    call hbi_literal
    test eax, eax
    jz   .no
    lea  rbx, [rel hch_status_values]
    call hch_choice
    test eax, eax
    jz   .no
    mov  r14, rdx                     ; display status index
    or   r13, rdx
    lea  rsi, [rel str_hch_machine_ready]
    test r13, r13
    jz   .machine
    lea  rsi, [rel str_hch_machine_degraded]
.machine:
    call hbi_literal
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hch_display_established]
    test r14, r14
    jz   .content
    lea  rsi, [rel str_hch_display_degraded]
.content:
    call hbi_literal
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hch_policy]
    call hbi_literal
    test eax, eax
    jz   .no
    jmp  .heap
.unavailable:
    lea  rsi, [rel str_hch_unavailable]
    call hbi_literal
    test eax, eax
    jz   .no
.heap:
    lea  rsi, [rel str_hch_heap]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hch_optblk]
    call hbi_literal
    test eax, eax
    jz   .no
    lea  rbx, [rel hch_status_values]
    call hch_choice
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hch_opt_epoch]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hch_opt_state]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  rdx, 4
    ja   .no
    cmp  byte [rdi], 0
    jne  .no
    mov  rdx, r12
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
hch_hex_prefix:
    cmp  byte [rdi], '0'
    jne  .no
    cmp  byte [rdi + 1], 'x'
    jne  .no
    add  rdi, 2
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret
; Exactly ECX lowercase hex digits; RDX=last64bits, R8=nonzero census.
hch_hex:
    xor  edx, edx
    xor  r8d, r8d
.next:
    movzx eax, byte [rdi]
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .digit
    cmp  al, 'a'
    jb   .no
    cmp  al, 'f'
    ja   .no
    sub  eax, 'a' - 10
    jmp  .accumulate
.digit:
    sub  eax, '0'
.accumulate:
    shl  rdx, 4
    or   rdx, rax
    or   r8, rax
    inc  rdi
    loop .next
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret
; Null-terminated literal choices. RDX=index. Failed choice restores input.
hch_choice:
    push r12
    push r13
    mov  r12, rdi
    xor  r13d, r13d
.next:
    lea  rsi, [rbx + r13*8]
    mov  rax, [rsi]
    test rax, rax
    jz   .no
    add  rsi, rax                     ; self-relative choice at this live cell
    mov  rdi, r12
    call hbi_literal
    test eax, eax
    jnz  .yes
    inc  r13
    jmp  .next
.yes:
    mov  rdx, r13
    jmp  .out
.no:
    mov  rdi, r12
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    ret
str_hch_name: db "health",0
str_hch_kind: db "service",0
str_hch_verb: db "C7HEALTH",0
str_hch_schema: db "v=1 inst=none get=C7HEALTH{status:valid|unavailable,schema:hex8,entry:hex8,nonce:hex64,manager_seq:hex64,state_generation:hex64,init_generation:hex64,payload_sha256:handoff-claim,build_id:running-image-measurement,bid:match|unstamped|mismatch|unmeasured,image,core,desktop,command,storage,network,display,machine,optional,display_content,promotion_token,external_authority,projection,heap_used:u64,optblk:ready|degraded|unavailable,opt_epoch:u64,opt_state:0..4} observe=whole-native-reply scope=cached-PBMH-and-live-heap-and-optblk authority=native no-publication-or-promotion-authority no-independent-health-proof list=na set=na input=na cancel=na",0
str_hch_bad: db " hook err=health_reply_incomplete",0
str_hch_prefix: db " c7_health status=",0
str_hch_valid: db "valid schema=0x02 identity=slot-nonce-manifest profile=normal core_checkpoint=strong readback=exact",0
str_hch_unavailable: db "unavailable schema=0x02 projection=read-only",0
str_hch_entry: db " entry=",0
str_hch_nonce: db " nonce=",0
str_hch_sequence: db " manager_seq=",0
str_hch_state_generation: db " state_generation=",0
str_hch_init_generation: db " init_generation=",0
str_hch_payload: db " payload_sha256=",0
str_hch_build_id: db " build_id=",0
str_hch_bid: db " bid=",0
str_hch_match: db "match",0
str_hch_unstamped: db "unstamped",0
str_hch_mismatch: db "mismatch",0
str_hch_unmeasured: db "unmeasured",0
str_hch_core: db " image=ready core=ready desktop=ready command=ready storage=ready network=",0
str_hch_ready: db "ready",0
str_hch_degraded: db "degraded",0
str_hch_unavail_value: db "unavailable",0
str_hch_display: db " display=",0
str_hch_machine_ready: db " machine=ready optional=ready",0
str_hch_machine_degraded: db " machine=degraded optional=degraded",0
str_hch_display_established: db " display_content=established",0
str_hch_display_degraded: db " display_content=degraded",0
str_hch_policy: db " promotion_token=published external_authority=none projection=read-only",0
str_hch_heap: db " heap_used=",0
str_hch_optblk: db " optblk=",0
str_hch_opt_epoch: db " opt_epoch=",0
str_hch_opt_state: db " opt_state=",0
align 8
hch_identity_fields:
    dq str_hch_nonce - $
    dq str_hch_sequence - $
    dq str_hch_state_generation - $
    dq str_hch_init_generation - $
    dq 0
hch_bid_values:
    dq str_hch_match - $
    dq str_hch_unstamped - $
    dq str_hch_mismatch - $
    dq str_hch_unmeasured - $
    dq 0
hch_status_values:
    dq str_hch_ready - $
    dq str_hch_degraded - $
    dq str_hch_unavail_value - $
    dq 0
hook_edge_health: times HE_SZ db 0
hch_pending: db 0

; Cached native C6BLACKBOX observation. No EFI, history publication or recovery operation.
HBB_REPLY_MAX equ 384
hook_blackbox_plan:
    call hbb_retire
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    jne  .bad
    lea  rax, [rel str_hbb_verb]
    mov  byte [rel hbb_pending], 1
    xor  edx, edx
    ret
.na:
    xor  eax, eax
    mov  edx, HOOK_PLAN_NA
    ret
.bad:
    xor  eax, eax
    mov  edx, HOOK_PLAN_BADARG
    ret
hook_blackbox_post:
    push rbx
    push r12
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  byte [rel hbb_pending], 1
    jne  .bad
    cmp  byte [rel c6bb_out_ready], 1
    jne  .bad
    lea  rdi, [rel c6bb_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HBB_REPLY_MAX
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel c6bb_out_cur]
    jne  .bad
    mov  r12, rdi
    call hbb_record
    test eax, eax
    jz   .bad
    cmp  [rbx + RSP_VAL], rdx           ; native availability value binds the complete reply
    jne  .bad
    sub  rdi, r12
    push rdi
    call command_hook_out_reset
    pop  rsi
    mov  rdi, r12
    call command_hook_out_strn
    jmp  .done
.bad:
    call command_hook_out_reset
    lea  rdi, [rel str_hbb_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hbb_bad]
    mov  [rbx + RSP_HINT], rax
.done:
    call hbb_retire
    mov  eax, 1
    jmp  .out
.refused:
    call hbb_retire
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret
hbb_retire:
    mov  byte [rel hbb_pending], 0
    mov  byte [rel c6bb_out_ready], 0
    mov  byte [rel c6bb_out_buf], 0
    mov  qword [rel c6bb_out_cur], 0
    ret

; RDI=bounded native reply; EAX=complete, RDX=native availability.
hbb_record:
    push rbx
    push r12
    xor  r12d, r12d
    lea  rsi, [rel str_hbb_prefix]
    call hbi_literal
    test eax, eax
    jz   .no
    cmp  byte [rdi], 'v'
    jne  .unavailable
    lea  rsi, [rel str_hbb_valid]
    call hbi_literal
    test eax, eax
    jz   .no
    mov  r12d, 1
    lea  rsi, [rel str_hbb_generation]
    call hbi_literal
    test eax, eax
    jz   .no
    mov  ecx, 16
    call hbb_hex                       ; generation may wrap to zero
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hbb_count]
    call hbi_literal
    test eax, eax
    jz   .no
    mov  ecx, 2
    call hbb_hex
    test eax, eax
    jz   .no
    cmp  edx, 1
    jb   .no
    cmp  edx, 8
    ja   .no
    lea  rsi, [rel str_hbb_index]
    call hbi_literal
    test eax, eax
    jz   .no
    mov  ecx, 2
    call hbb_hex
    test eax, eax
    jz   .no
    cmp  edx, 8
    jae  .no
    lea  rsi, [rel str_hbb_reset]
    call hbi_literal
    test eax, eax
    jz   .no
    mov  ecx, 2
    call hbb_hex
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hbb_policy]
    call hbi_literal
    test eax, eax
    jz   .no
    jmp  .end
.unavailable:
    lea  rsi, [rel str_hbb_unavailable]
    call hbi_literal
    test eax, eax
    jz   .no
.end:
    cmp  byte [rdi], 0
    jne  .no
    mov  rdx, r12
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret
; Exact 0x and ECX lowercase hex digits; EDX=low32bits (bounds use2digits).
hbb_hex:
    cmp  byte [rdi], '0'
    jne  .no
    cmp  byte [rdi + 1], 'x'
    jne  .no
    add  rdi, 2
    xor  edx, edx
.next:
    movzx eax, byte [rdi]
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .digit
    cmp  al, 'a'
    jb   .no
    cmp  al, 'f'
    ja   .no
    sub  eax, 'a' - 10
    jmp  .accumulate
.digit:
    sub  eax, '0'
.accumulate:
    shl  edx, 4
    or   edx, eax
    inc  rdi
    loop .next
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret
str_hbb_name: db "blackbox",0
str_hbb_kind: db "service",0
str_hbb_verb: db "C6BLACKBOX",0
str_hbb_schema: db "v=1 inst=none get=C6BLACKBOX{status:valid|unavailable,pbmh_v2:2,ring_capacity:8,copies:2,generation:hex64,count:1..8,write_index:0..7,reset_cause:hex8,newest_valid,slot_crc,ring_crc,readback,selection,projection} observe=whole-native-reply scope=cached-ring-status authority=native no-history-publication-or-recovery-authority no-independent-boot-proof list=na set=na input=na cancel=na",0
str_hbb_bad: db " hook err=blackbox_reply_incomplete",0
str_hbb_prefix: db " c6_blackbox status=",0
str_hbb_valid: db "valid pbmh_v2=2 ring_capacity=0x08 copies=0x02",0
str_hbb_unavailable: db "unavailable pbmh_v2=2 ring_capacity=0x08 copies=0x02",0
str_hbb_generation: db " generation=",0
str_hbb_count: db " count=",0
str_hbb_index: db " write_index=",0
str_hbb_reset: db " reset_cause=",0
str_hbb_policy: db " newest_valid=1 slot_crc=ok ring_crc=ok readback=exact selection=serial-half-range projection=read-only",0
align 8
hook_edge_blackbox: times HE_SZ db 0
hbb_pending: db 0

; FSJOBS is the sole producer. LIST consumes a fresh complete native stage;
; it never sweeps, ticks, enumerates mounts or touches a medium. Legacy ops
; keep their native replies. Private spans refer only to this serialized stage
; until it has been copied, then are cleared with the stage on every exit.
HFJ_NATIVE_CAP equ 1408                  ; command_fs FS_OUT_CAP, pinned by controls
HFJ_ROWS equ 4                          ; native keyed request inventory bound
HFJ_FIELDS equ 11
hook_fsjob_post:
    cmp  edi, HOP_LIST
    je   .list
    xor  eax, eax
    ret
.list:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .native_refusal
    cmp  qword [rbx + RSP_ACCEPTED], 0
    jne  .bad
    cmp  qword [rbx + RSP_JOBID], 0    ; synchronous discovery allocates no job
    jne  .bad
    cmp  byte [rel hfj_pending], 1
    jne  .bad
    cmp  byte [rel fs_out_ready], 1
    jne  .bad
    cmp  byte [rel fs_out_truncated], 0
    jne  .bad
    lea  rax, [rel command_hook_arg]
    cmp  [rbx + RSP_VAL], rax             ; fs_finish's original argument scalar
    jne  .bad
    lea  rdi, [rel fs_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HFJ_NATIVE_CAP
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel fs_out_cur]
    jne  .bad
    call hfj_record
    test eax, eax
    jz   .bad
    ; Native fields are now wholly validated. Keep its header and encode the
    ; eleven row values in the schema's fixed order. Typed widths bound each
    ; row by 160 and the header by 136: <=776 bytes, below HOOK_OUT_MAX-1.
    call command_hook_out_reset
    lea  rdi, [rel fs_out_buf]
    mov  esi, [rel hfj_header_len]
    call command_hook_out_strn
    mov  r12d, [rel hfj_count]
    lea  r13, [rel hfj_spans]
.row:
    test r12d, r12d
    jz   .copied
    lea  rdi, [rel str_hfj_row]
    call command_hook_out_str
    xor  r14d, r14d
.field:
    test r14d, r14d
    jz   .value
    lea  rdi, [rel str_hfj_colon]
    call command_hook_out_str
.value:
    mov  rdi, [r13]
    mov  esi, [r13 + 8]
    call command_hook_out_strn
    add  r13, 16
    inc  r14d
    cmp  r14d, HFJ_FIELDS
    jb   .field
    dec  r12d
    jmp  .row
.copied:
    call hfj_retire
    mov  eax, 1
    jmp  .out
.bad:
    call command_hook_out_reset
    lea  rdi, [rel str_hfj_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hfj_bad]
    mov  [rbx + RSP_HINT], rax
    call hfj_retire
    mov  eax, 1
    jmp  .out
.native_refusal:
    call hfj_retire
    xor  eax, eax                       ; original native refusal passes through
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

hfj_retire:
    mov  byte [rel hfj_pending], 0
    mov  byte [rel fs_out_ready], 0
    mov  byte [rel fs_out_buf], 0
    mov  qword [rel fs_out_cur], 0
    mov  byte [rel fs_out_truncated], 0
    lea  rdi, [rel hfj_spans]
    xor  eax, eax
    mov  ecx, HFJ_ROWS * HFJ_FIELDS * 2
    rep stosq
    lea  rdi, [rel hfj_ids]
    mov  ecx, HFJ_ROWS
    rep stosq
    mov  qword [rel hfj_nonce], 0
    mov  qword [rel hfj_nonce + 8], 0
    mov  dword [rel hfj_count], 0
    mov  dword [rel hfj_header_len], 0
    mov  dword [rel hfj_state], 0
    ret

%macro HFJ_LITERAL 1
    lea  rsi, [rel %1]
    call hbi_literal
    test eax, eax
    jz   .no
%endmacro
; Validate the ENTIRE ordered grammar, canonical scalar widths, nonce, limits,
; row census, unique nonzero IDs and state/cancel relation before publication.
; Unknown native state/durability stay unknown; no completion inference.
hfj_record:
    push rbx
    push r12
    push r13
    push r14
    push r15
    HFJ_LITERAL str_hfj_prefix
    lea  rsi, [rel hfj_nonce]
    mov  ecx, 16
.nonce:
    mov  al, [rsi]
    cmp  al, [rdi]
    jne  .no
    inc  rsi
    inc  rdi
    loop .nonce
    HFJ_LITERAL str_hfj_count
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  rdx, HFJ_ROWS
    ja   .no
    mov  [rel hfj_count], edx
    mov  r12d, edx
    HFJ_LITERAL str_hfj_limits
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  rdx, HFJ_ROWS
    ja   .no
    add  rdx, r12
    cmp  rdx, HFJ_ROWS
    ja   .no
    HFJ_LITERAL str_hfj_history
    lea  rax, [rel fs_out_buf]
    mov  rcx, rdi
    sub  rcx, rax
    mov  [rel hfj_header_len], ecx
    xor  r13d, r13d
    lea  r15, [rel hfj_spans]
.row:
    cmp  r13d, r12d
    jae  .end
    xor  r14d, r14d
.field:
    lea  rax, [rel hfj_fields]
    mov  rdx, r14
    shl  rdx, 4
    add  rax, rdx
    mov  rsi, [rax]
    add  rsi, rax                     ; self-relative field at this live row
    mov  rbx, [rax + 8]
    call hbi_literal
    test eax, eax
    jz   .no
    mov  [r15], rdi
    cmp  ebx, 3
    jb   .number
    cmp  ebx, 7
    je   .number
    lea  rax, [rel hfj_enums]
    mov  rdx, rbx
    sub  edx, 3
    lea  rsi, [rax + rdx * 8]
    add  rsi, [rsi]                   ; self-relative enum at this live cell
    call hfj_enum
    test eax, eax
    jz   .no
    cmp  ebx, 3
    jne  .cancel
    mov  [rel hfj_state], edx
.cancel:
    cmp  ebx, 5
    jne  .span
    xor  eax, eax
    cmp  dword [rel hfj_state], 3
    jne  .cancelled
    mov  eax, 1
.cancelled:
    cmp  dword [rel hfj_state], 5
    jne  .cancel_check
    mov  eax, 2
.cancel_check:
    cmp  eax, edx
    jne  .no
    jmp  .span
.number:
    cmp  ebx, 2
    jne  .decimal
    cmp  byte [rdi], 'u'
    jne  .decimal
    HFJ_LITERAL str_hfj_unknown
    jmp  .span
.decimal:
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  ebx, 2
    jne  .u32
    cmp  rdx, -1                       ; native sentinel is spelled unknown
    je   .no
.u32:
    cmp  ebx, 7
    jne  .id
    mov  eax, 0xffffffff
    cmp  rdx, rax
    ja   .no
.id:
    test ebx, ebx
    jnz  .span
    test rdx, rdx
    jz   .no
    lea  rax, [rel hfj_ids]
    xor  ecx, ecx
.unique:
    cmp  ecx, r13d
    jae  .remember
    cmp  rdx, [rax + rcx * 8]
    je   .no
    inc  ecx
    jmp  .unique
.remember:
    mov  [rax + r13 * 8], rdx
.span:
    mov  rax, rdi
    sub  rax, [r15]
    cmp  rax, 20                       ; all scalar/token width maxima
    ja   .no
    mov  [r15 + 8], rax
    add  r15, 16
    inc  r14d
    cmp  r14d, HFJ_FIELDS
    jb   .field
    inc  r13d
    jmp  .row
.end:
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
%unmacro HFJ_LITERAL 1

; Exact delimited enum token, EDX=index. Failed candidates reset the input;
; the NUL scan in post has already established an accessible finite extent.
hfj_enum:
    mov  r9, rdi
    mov  r10, rsi
    xor  r11d, r11d
.next:
    mov  rsi, r10
    mov  rdi, r9
    call hbi_literal
    test eax, eax
    jz   .skip
    mov  al, [rdi]
    cmp  al, ' '
    je   .yes
    cmp  al, 10
    je   .yes
    test al, al
    jz   .yes
.skip:
    cmp  byte [r10], 0
    je   .advance
    inc  r10
    jmp  .skip
.advance:
    inc  r10
    inc  r11d
    cmp  byte [r10], 0
    jne  .next
    xor  eax, eax
    ret
.yes:
    mov  edx, r11d
    mov  eax, 1
    ret

str_hfj_verb: db "FSJOBS",0
str_hfj_bad: db " hook err=fsjobs_reply_incomplete",0
str_hfj_prefix: db "FSJOBS NONCE=",0
str_hfj_count: db " COUNT=",0
str_hfj_limits: db " REQUEST_LIMIT=4 QUEUE_LIMIT=4 RETAINED_LIMIT=10 OMITTED=",0
str_hfj_history: db " HISTORY=bounded EVICTED=unknown TRUNCATED=0",0
str_hfj_colon: db ":",0
str_hfj_row: db 10,"J=",0
str_hfj_unknown: db "unknown",0
str_hfj_job: db 10,"JOB=",0
str_hfj_state: db " STATE=",0
str_hfj_done: db " DONE=",0
str_hfj_total: db " TOTAL=",0
str_hfj_durable: db " DURABLE=",0
str_hfj_cancel: db " CANCEL=",0
str_hfj_record: db " RECORD=",0
str_hfj_pos: db " POS=",0
str_hfj_error: db " ERROR=",0
str_hfj_files: db " FILES_DONE=",0
str_hfj_skipped: db " SKIPPED=",0
str_hfj_states: db "idle",0,"running",0,"verifying",0,"cancelling",0,"done",0,"cancelled",0,"failed",0,"queued",0,"unknown",0,0
str_hfj_durables: db "0",0,"1",0,"unverified",0,"uncertain",0,"unknown",0,0
str_hfj_cancels: db "none",0,"pending",0,"complete",0,0
str_hfj_origins: db "current",0,"queued",0,"cancelled",0,"dropped",0,0
align 8
hfj_fields:
    dq str_hfj_job - $, 0
    dq str_hfj_state - $, 3
    dq str_hfj_done - $, 1
    dq str_hfj_total - $, 2
    dq str_hfj_durable - $, 4
    dq str_hfj_cancel - $, 5
    dq str_hfj_record - $, 6
    dq str_hfj_pos - $, 7
    dq str_hfj_error - $, 7
    dq str_hfj_files - $, 7
    dq str_hfj_skipped - $, 7
hfj_enums:
    dq str_hfj_states - $
    dq str_hfj_durables - $
    dq str_hfj_cancels - $
    dq str_hfj_origins - $
hfj_ids: times HFJ_ROWS dq 0
hfj_spans: times HFJ_ROWS * HFJ_FIELDS * 2 dq 0
hfj_nonce: times 16 db 0
hfj_count: dd 0
hfj_header_len: dd 0
hfj_state: dd 0
hfj_pending: db 0

; Native BACKUP STAT and CANCEL receipts. Native owner/MUTATE gate stays decisive.
; The output workspace is the native 1408-byte upper ciphertext staging area;
; consume only its current complete reply, then retire the entire private stage.
HBK_STAGE_CAP equ 1408
hook_backup_plan:
    push r12
    call hbk_retire
    cmp  edi, HOP_CANCEL
    je   .cancel
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    jne  .bad
    call command_hook_arg_reset
    lea  rdi, [rel str_hbk_arg]
    call command_hook_arg_str
    mov  edi, 1
    call hse_arg_nonce
    lea  rsi, [rel hse_nonce_buf]
    lea  rdi, [rel hbk_nonce]
    mov  ecx, 17
    rep movsb
    mov  byte [rel hbk_pending], 1
.planned:
    lea  rax, [rel str_hbk_verb]
    xor  edx, edx
    pop  r12
    ret
.cancel:
    cmp  byte [rdx], 0
    jne  .bad
    mov  r12, rsi
    mov  rdi, rsi
    call hbi_decimal
    test eax, eax
    jz   .bad
    cmp  byte [rdi], 0
    jne  .bad
    test rdx, rdx
    jz   .bad
    mov  [rel hbk_cancel_generation], rdx
    call command_hook_arg_reset
    lea  rdi, [rel str_hbk_cancel_arg]
    call command_hook_arg_str
    mov  rdi, r12
    call command_hook_arg_str
    mov  edi, 1
    call hse_arg_nonce
    lea  rsi, [rel hse_nonce_buf]
    lea  rdi, [rel hbk_nonce]
    mov  ecx, 17
    rep movsb
    mov  byte [rel hbk_pending], 2
    jmp  .planned
.na:
    xor  eax, eax
    mov  edx, HOOK_PLAN_NA
    pop  r12
    ret
.bad:
    call hbk_retire
    xor  eax, eax
    mov  edx, HOOK_PLAN_BADARG
    pop  r12
    ret
hook_backup_post:
    push rbx
    push r12
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  byte [rel hbk_pending], 1
    je   .pending
    cmp  byte [rel hbk_pending], 2
    jne  .bad
.pending:
    cmp  byte [rel backup_out_ready], 1
    jne  .bad
    cmp  qword [rbx + RSP_VAL], 0
    jne  .bad
    cmp  qword [rbx + RSP_ACCEPTED], 1
    jne  .bad
    lea  r12, [rel backup_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HOOK_OUT_MAX - 1
    jae  .bad
    cmp  byte [r12 + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    lea  rax, [r12 + rcx]
    cmp  rax, [rel backup_out_cur]
    jne  .bad
    mov  rdi, r12
    call hbk_record
    test eax, eax
    jz   .bad
    sub  rdx, r12                     ; all native fields except per-call nonce
    push rdx
    call command_hook_out_reset
    pop  rsi
    mov  rdi, r12
    call command_hook_out_strn
    jmp  .done
.bad:
    call command_hook_out_reset
    lea  rdi, [rel str_hbk_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hbk_bad]
    mov  [rbx + RSP_HINT], rax
.done:
    call hbk_retire
    mov  eax, 1
    jmp  .out
.refused:
    call hbk_retire
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret
; Preserve planner's operation and instance/rest pointers. Native persistent
; consent, source, recipient, counters and nonce remain native-owned state.
hbk_retire:
    push rdi
    xor  eax, eax
    lea  rdi, [rel backup_out_buf]
    mov  ecx, HBK_STAGE_CAP
    rep stosb
    lea  rdi, [rel hbk_nonce]
    mov  ecx, 17
    rep stosb
    mov  byte [rel hbk_pending], 0
    mov  qword [rel hbk_cancel_generation], 0
    mov  byte [rel backup_out_ready], 0
    mov  qword [rel backup_out_cur], 0
    pop  rdi
    ret
; RDI=bounded current native record. EAX=valid, RDX=end before nonce.
; Decimal/hash/path bounds match the actual finite producer, not substring keys.
hbk_record:
    push rbx
    push r12
    push r13
    push r14
    lea  rsi, [rel str_hbk_prefix]
    call hbi_literal
    test eax, eax
    jz   .no
    cmp  byte [rel hbk_pending], 2
    jne  .any_state
    lea  rsi, [rel str_hbk_cancelled]
    call hbi_literal
    test eax, eax
    jz   .no
    cmp  byte [rdi], ' '
    jne  .no
    jmp  .state_ok
.any_state:
    mov  r12, rdi
    lea  rbx, [rel hbk_states]
.state:
    mov  rdi, r12
    mov  rsi, rbx
    call hbi_literal
    test eax, eax
    jz   .next_state
    cmp  byte [rdi], ' '
    je   .state_ok
.next_state:
    cmp  byte [rbx], 0
    je   .advance_state
    inc  rbx
    jmp  .next_state
.advance_state:
    inc  rbx
    cmp  byte [rbx], 0
    jne  .state
    jmp  .no
.state_ok:
    lea  rsi, [rel str_hbk_generation]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  byte [rel hbk_pending], 2
    jne  .generation_ok
    cmp  rdx, [rel hbk_cancel_generation]
    jne  .no
.generation_ok:
    lea  rsi, [rel str_hbk_source]
    call hbi_literal
    test eax, eax
    jz   .no
    xor  ecx, ecx
.path:
    movzx eax, byte [rdi]
    cmp  al, ' '
    je   .path_done
    cmp  al, 33
    jb   .no
    cmp  al, 126
    ja   .no
    inc  ecx
    cmp  ecx, 95
    ja   .no
    inc  rdi
    jmp  .path
.path_done:
    lea  rsi, [rel str_hbk_source_bytes]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hbk_archive_bytes]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hbk_destination]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  rdx, 255
    ja   .no
    lea  rsi, [rel str_hbk_dot]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  rdx, 255
    ja   .no
    lea  rsi, [rel str_hbk_dot]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  rdx, 255
    ja   .no
    lea  rsi, [rel str_hbk_dot]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  rdx, 255
    ja   .no
    lea  rsi, [rel str_hbk_colon]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  rdx, 65535
    ja   .no
    lea  rsi, [rel str_hbk_fingerprint]
    call hbi_literal
    test eax, eax
    jz   .no
    mov  ecx, 64
    call hbk_hash
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hbk_manifest]
    call hbi_literal
    test eax, eax
    jz   .no
    mov  ecx, 64
    call hbk_hash
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hbk_cipher]
    call hbi_literal
    test eax, eax
    jz   .no
    mov  ecx, 64
    call hbk_hash
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hbk_ack]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  rdx, 1
    ja   .no
    lea  rsi, [rel str_hbk_sent]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hbk_frame]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hbk_rb]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    mov  r13, rdx
    lea  rsi, [rel str_hbk_ra]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  r13, rdx
    sete r13b
    movzx r13d, r13b
    lea  rsi, [rel str_hbk_wb]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    mov  r14, rdx
    lea  rsi, [rel str_hbk_wa]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  r14, rdx
    sete r14b
    movzx r14d, r14b
    and  r13d, r14d
    lea  rsi, [rel str_hbk_same]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  rdx, 1
    ja   .no
    cmp  rdx, r13
    jne  .no
    lea  rsi, [rel str_hbk_time]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hbk_fixed]
    call hbi_literal
    test eax, eax
    jz   .no
    mov  r12, rdi
    lea  rsi, [rel str_hbk_nonce]
    call hbi_literal
    test eax, eax
    jz   .no
    lea  rsi, [rel hbk_nonce]
    call hbi_literal
    test eax, eax
    jz   .no
    cmp  byte [rdi], 0
    jne  .no
    mov  rdx, r12
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
hbk_hash:
    movzx eax, byte [rdi]
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .ok
    cmp  al, 'a'
    jb   .no
    cmp  al, 'f'
    ja   .no
.ok:
    inc  rdi
    loop hbk_hash
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret
str_hbk_name: db "backup",0
str_hbk_verb: db "BACKUP",0
str_hbk_arg: db "STAT",0
str_hbk_cancel_arg: db "CANCEL ",0
str_hbk_cancelled: db "cancelled",0
str_hbk_bad: db " hook err=backup_reply_incomplete",0
str_hbk_schema: db "v=1 inst=none(get/observe)|positive-u64-consent-generation(cancel) get=BACKUP-STAT{state,consent_generation:u64,source:0..95,source_bytes:u64,archive_bytes:u64,destination:IPv4:port16,recipient_fingerprint:hex256,manifest:hex256,ciphertext_digest:hex256,receiver_ack_exact:bool,sent_bytes:u64,frame_bytes:u64,rtc_reads_before:u64,rtc_reads_after:u64,rtc_writes_before:u64,rtc_writes_after:u64,rtc_unchanged:bool,receipt_utc_us:u64,native-fixed-metadata} observe=whole-validated-native-receipt-excluding-nonce authority=native-owner-MUTATE scope=private-saved-status current=one-use-no-export-or-crypto-or-receiver-proof list=na set=na input=na cancel=BACKUP-CANCEL(args=none;native-active-consent;reply=cancelled,exact-generation)",0
hbk_states: db "idle",0,"consented",0,"connecting",0,"sending",0,"awaiting_ack",0,"acked",0,"failed",0,"cancelled",0,"complete",0,0
str_hbk_prefix: db "BACKUP state=",0
str_hbk_generation: db " consent_generation=",0
str_hbk_source: db " source=",0
str_hbk_source_bytes: db " source_bytes=",0
str_hbk_archive_bytes: db " archive_bytes=",0
str_hbk_destination: db " destination=",0
str_hbk_dot: db ".",0
str_hbk_colon: db ":",0
str_hbk_fingerprint: db " recipient_fingerprint=",0
str_hbk_manifest: db " manifest=",0
str_hbk_cipher: db " ciphertext_digest=",0
str_hbk_ack: db " receiver_ack_exact=",0
str_hbk_sent: db " sent_bytes=",0
str_hbk_frame: db " frame_bytes=",0
str_hbk_rb: db " rtc_reads_before=",0
str_hbk_ra: db " rtc_reads_after=",0
str_hbk_wb: db " rtc_writes_before=",0
str_hbk_wa: db " rtc_writes_after=",0
str_hbk_same: db " rtc_unchanged=",0
str_hbk_time: db " receipt_utc_us=",0
str_hbk_fixed: db " hpke=RFC9180-X25519-HKDF-SHA256-AES256GCM hpke_mode=0 hpke_seq=0 csprng_service_only=1 telemetry_self=0 involvement_authorizes_self=0 archive=ustar-complete",0
str_hbk_nonce: db " nonce=",0
align 8
hook_edge_backup: times HE_SZ db 0
hbk_nonce: times 17 db 0
hbk_pending: db 0
hbk_cancel_generation: dq 0

; STAT and bounded range-digest READAT of the two native safe rework artifacts.
; No alias, arbitrary path, content disclosure, KAT or guest launch seam.
HGA_REPLY_MAX equ 512
HGA_READ_MAX equ 16384
hook_artifact_plan:
    call hga_retire
    cmp  edi, HOP_GET
    jne  .na
    push rbx
    push r12
    push r13
    mov  r13, rdx
    mov  rbx, rsi
    mov  rdi, rbx
    lea  rsi, [rel str_hga_bz]
    call strcmp
    test eax, eax
    jz   .bz
    mov  rdi, rbx
    lea  rsi, [rel str_hga_initrd]
    call strcmp
    test eax, eax
    jnz  .bad_pop
    lea  r12, [rel str_hga_initrd]
    lea  rbx, [rel str_hga_stat_initrd]
    jmp  .operation
.bz:
    lea  r12, [rel str_hga_bz]
    lea  rbx, [rel str_hga_stat_bz]
.operation:
    cmp  byte [r13], 0
    jne  .readat
    call command_hook_arg_reset
    mov  rdi, rbx
    call command_hook_arg_str
    mov  byte [rel hga_pending], 1
    jmp  .planned
.readat:
    ; OBSERVE retains the STAT witness; a fresh nonce must not move a witness.
    cmp  dword [rel hook_p_op], HOP_GET
    jne  .bad_pop
    mov  rdi, r13
    lea  rsi, [rel str_hga_readat]
    call command_hook_after_word
    test rax, rax
    jz   .bad_pop
    mov  r13, rax                        ; exact decimal suffix for native args
    mov  rdi, rax
    call hbi_decimal
    test eax, eax
    jz   .bad_pop
    mov  [rel hga_offset], rdx
    cmp  byte [rdi], ' '
    jne  .bad_pop
    inc  rdi
    call hbi_decimal
    test eax, eax
    jz   .bad_pop
    cmp  byte [rdi], 0
    jne  .bad_pop
    test rdx, rdx
    jz   .bad_pop
    cmp  rdx, HGA_READ_MAX
    ja   .bad_pop
    mov  [rel hga_length], rdx
    mov  rax, [rel hga_offset]
    add  rax, rdx
    jc   .bad_pop                       ; a range must never wrap
    cmp  qword [rel hse_nonce_ctr], -1
    je   .bad_pop                       ; never reuse a wrapped correlation
    call command_hook_arg_reset
    lea  rdi, [rel str_hga_readat_arg]
    call command_hook_arg_str
    mov  rdi, r12
    call command_hook_arg_str
    lea  rdi, [rel str_hse_sp]
    call command_hook_arg_str
    mov  rdi, r13
    call command_hook_arg_str
    mov  edi, 1
    call hse_arg_nonce
    lea  rsi, [rel hse_nonce_buf]
    lea  rdi, [rel hga_nonce]
    mov  ecx, 17
    rep movsb
    mov  byte [rel hga_pending], 2
.planned:
    pop  r13
    pop  r12
    pop  rbx
    lea  rax, [rel str_hga_verb]
    xor  edx, edx
    ret
.bad_pop:
    pop  r13
    pop  r12
    pop  rbx
    call hga_retire
    xor  eax, eax
    mov  edx, HOOK_PLAN_BADARG
    ret
.na:
    xor  eax, eax
    mov  edx, HOOK_PLAN_NA
    ret
; Bound to command_guestfile GF_OUT_CAP, not another service staging size.
HGA_REPLY_MAX equ 512
hook_artifact_post:
    push rbx
    push r12
    push r13
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  byte [rel hga_pending], 1
    je   .pending
    cmp  byte [rel hga_pending], 2
    jne  .bad
.pending:
    cmp  byte [rel gf_out_ready], 1
    jne  .bad
    lea  rdi, [rel gf_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HGA_REPLY_MAX
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel gf_out_cur]
    jne  .bad
    mov  r12, rdi
    call hga_record
    test eax, eax
    jz   .bad
    mov  r13d, eax
    cmp  qword [rbx + RSP_VAL], 0      ; this producer never sets a nonzero value
    jne  .bad
    sub  rdi, r12
    push rdi
    call command_hook_out_reset
    pop  rsi
    mov  rdi, r12
    call command_hook_out_strn
    cmp  r13d, 2                      ; native ERR uses CODE=OK; typed observation refuses
    je   .error_code
    jmp  .done
.bad:
    call command_hook_out_reset
    lea  rdi, [rel str_hga_bad]
    call command_hook_out_str
.error_code:
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hga_bad]
    mov  [rbx + RSP_HINT], rax
.done:
    call hga_retire
    mov  eax, 1
    jmp  .out
.refused:
    call hga_retire
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
hga_retire:
    mov  byte [rel hga_pending], 0
    mov  byte [rel gf_out_ready], 0
    mov  qword [rel gf_out_cur], 0
    mov  qword [rel hga_offset], 0
    mov  qword [rel hga_length], 0
    mov  qword [rel hga_nonce], 0
    mov  qword [rel hga_nonce + 8], 0
    mov  byte [rel hga_nonce + 16], 0
    push rax
    push rcx
    push rdi
    xor  eax, eax
    lea  rdi, [rel gf_out_buf]
    mov  ecx, HGA_REPLY_MAX
    rep stosb
    pop  rdi
    pop  rcx
    pop  rax
    ret


; RDI=bounded native row; EAX=1 complete planned receipt,2 exact native error,0 invalid.
hga_record:
    push rbx
    mov  rbx, rdi
    lea  rsi, [rel str_hga_error_args]
    call hbi_literal
    test eax, eax
    jnz  .error_end
    mov  rdi, rbx
    lea  rsi, [rel str_hga_error_file]
    call hbi_literal
    test eax, eax
    jnz  .error_end
    mov  rdi, rbx
    lea  rsi, [rel str_hga_error_io]
    call hbi_literal
    test eax, eax
    jnz  .error_end
    mov  rdi, rbx
    cmp  byte [rel hga_pending], 2
    je   .readat
    lea  rsi, [rel str_hga_prefix]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    lea  rsi, [rel str_hga_sha]
    call hbi_literal
    test eax, eax
    jz   .no
    mov  ecx, 64
.hex:
    movzx eax, byte [rdi]
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .digit
    cmp  al, 'a'
    jb   .no
    cmp  al, 'f'
    ja   .no
.digit:
    inc  rdi
    loop .hex
    lea  rsi, [rel str_hga_backend]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    mov  eax, 0xffffffff
    cmp  rdx, rax
    ja   .no
    lea  rsi, [rel str_hga_volume]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    mov  eax, 0xffffffff
    cmp  rdx, rax
    ja   .no
    lea  rsi, [rel str_hga_reason]
    call hbi_literal
    test eax, eax
    jz   .no
    mov  rbx, rdi
    lea  rsi, [rel str_hga_marker]
    call hbi_literal
    test eax, eax
    jnz  .end
    mov  rdi, rbx
    lea  rsi, [rel str_hga_fallback]
    call hbi_literal
    test eax, eax
    jnz  .end
    mov  rdi, rbx
    lea  rsi, [rel str_hga_none]
    call hbi_literal
    test eax, eax
    jz   .no
.end:
    cmp  byte [rdi], 0
    jne  .no
    mov  eax, 1
    pop  rbx
    ret
.readat:
    lea  rsi, [rel str_hga_read_prefix]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  rdx, [rel hga_offset]
    jne  .no
    lea  rsi, [rel str_hga_len]
    call hbi_literal
    test eax, eax
    jz   .no
    call hbi_decimal
    test eax, eax
    jz   .no
    cmp  rdx, [rel hga_length]
    jne  .no
    lea  rsi, [rel str_hga_sha]
    call hbi_literal
    test eax, eax
    jz   .no
    mov  ecx, 64
.read_hex:
    movzx eax, byte [rdi]
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .read_digit
    cmp  al, 'a'
    jb   .no
    cmp  al, 'f'
    ja   .no
.read_digit:
    inc  rdi
    loop .read_hex
    lea  rsi, [rel str_hga_read_post]
    call hbi_literal
    test eax, eax
    jz   .no
    lea  rsi, [rel hga_nonce]
    call hbi_literal
    test eax, eax
    jz   .no
    jmp  .end
.error_end:
    cmp  byte [rdi], 0
    jne  .no
    mov  eax, 2
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret
str_hga_name: db "artifact",0
str_hga_kind: db "service",0
str_hga_verb: db "GUESTFILE",0
str_hga_schema: db "v=1 inst=BZIMAGE2|INITRD2.GZ get=GUESTFILE STAT{size:u64,sha256:hex256,backend:fat32_disk,via:fs_ops,selected_port:u32,volume_id:u32,reason:content_marker|fallback|none}|readat <offset:u64> <length:1..16384>:GUESTFILE READAT{off:u64,len:u64,sha256:hex256,via:fs_ops,nonce:generated-hex16;range-sha256-only;range-no-wrap} observe=STAT-whole-native-reply hash=streamed-16KiB authority=native errors=refused current=one-use-native-stage no-guest-launch-or-boot-proof list=na set=na input=na cancel=na",0
str_hga_bad: db " hook err=artifact_reply_incomplete",0
str_hga_bz: db "BZIMAGE2",0
str_hga_initrd: db "INITRD2.GZ",0
str_hga_stat_bz: db "STAT BZIMAGE2",0
str_hga_stat_initrd: db "STAT INITRD2.GZ",0
str_hga_readat: db "READAT",0
str_hga_readat_arg: db "READAT ",0
str_hga_read_prefix: db " GUESTFILE READAT off=",0
str_hga_len: db " len=",0
str_hga_read_post: db " via=fs_ops nonce=",0
str_hga_prefix: db " GUESTFILE STAT size=",0
str_hga_sha: db " sha256=",0
str_hga_backend: db " backend=fat32_disk via=fs_ops selected_port=",0
str_hga_volume: db " volume_id=",0
str_hga_reason: db " reason=",0
str_hga_marker: db "content_marker",0
str_hga_fallback: db "fallback",0
str_hga_none: db "none",0
str_hga_error_args: db " GUESTFILE ERR bad_args",0
str_hga_error_file: db " GUESTFILE ERR no_file_or_mount",0
str_hga_error_io: db " GUESTFILE ERR read_or_hash",0
hga_pending: db 0
hga_nonce: times 17 db 0
align 8
hga_offset: dq 0
hga_length: dq 0
align 8
hook_edge_artifact: times HE_SZ db 0

; AIRLOCKSTATUS is a native observation, including a fresh status read when the
; controller exists. Counters and retained raw status are not health/containment
; proof. No FILE, fault injection, reset or controller write is planned here.
HAL_REPLY_MAX equ 512                 ; actual command_airlock staging allocation
%if !PAOS_PUBLIC_BUILD
hook_airlock_plan:
    call hal_retire
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    jne  .bad
    call command_hook_arg_reset
    lea  rax, [rel str_hal_verb]
    mov  byte [rel hal_pending], 1
    xor  edx, edx
    ret
.na:
    xor  eax, eax
    mov  edx, HOOK_PLAN_NA
    ret
.bad:
    xor  eax, eax
    mov  edx, HOOK_PLAN_BADARG
    ret
hook_airlock_post:
    push rbx
    push r12
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  byte [rel hal_pending], 1
    jne  .bad
    cmp  byte [rel airlock_out_ready], 1
    jne  .bad
    lea  rdi, [rel airlock_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HAL_REPLY_MAX
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel airlock_out_cur]
    jne  .bad
    mov  r12, rdi
    call hal_record
    test eax, eax
    jz   .bad
    sub  rdi, r12
    push rdi
    call command_hook_out_reset
    pop  rsi
    mov  rdi, r12
    call command_hook_out_strn
    jmp  .done
.bad:
    call command_hook_out_reset
    lea  rdi, [rel str_hal_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hal_bad]
    mov  [rbx + RSP_HINT], rax
.done:
    call hal_retire
    mov  eax, 1
    jmp  .out
.refused:
    call hal_retire
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret
; Retire all native stage bytes and custody, preserving planner/post arguments.
hal_retire:
    push rax
    push rcx
    push rdi
    mov  byte [rel hal_pending], 0
    mov  byte [rel airlock_out_ready], 0
    mov  qword [rel airlock_out_cur], 0
    lea  rdi, [rel airlock_out_buf]
    mov  ecx, HAL_REPLY_MAX / 8
    xor  eax, eax
    rep stosq
    pop  rdi
    pop  rcx
    pop  rax
    ret
; Ordered finite native grammar. Decimal fields are canonical natural integers;
; usbsts uses the actual formatter's lower-case hex, bounded to u32. The repeated
; contained counter must agree. Wrapped counters need no invented inequalities.
; A native power-gate sentinel (live=UINT32_MAX) is not a typed observation.
hal_record:
    push rbx
    push r12
    lea  rbx, [rel hal_fields]
.next:
    mov  rsi, [rbx]
    test rsi, rsi
    jz   .end
    add  rsi, rbx                     ; self-relative literal at this live row
    call hbi_literal
    test eax, eax
    jz   .no
    cmp  qword [rbx + 16], 1
    je   .hex
    call hbi_decimal
    jmp  .number
.hex:
    call hbi_hex
.number:
    test eax, eax
    jz   .no
    cmp  rdx, [rbx + 8]
    ja   .no
    cmp  qword [rbx + 16], 2
    jne  .duplicate
    mov  r12, rdx
.duplicate:
    cmp  qword [rbx + 16], 3
    jne  .advance
    cmp  rdx, r12
    jne  .no
.advance:
    add  rbx, 24
    jmp  .next
.end:
    cmp  byte [rdi], 0
    jne  .no
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret
str_hal_name: db "airlock",0
str_hal_kind: db "device",0
str_hal_verb: db "AIRLOCKSTATUS",0
str_hal_schema: db "v=1 inst=none get=AIRLOCKSTATUS{driver:xhci,live:bool,hch:bool,usbsts:u32hex,bdf:pci,attempts:u64,injected:u64,faults_contained:u64,faults_uncontained:u64,stab.contained_faults:u64} observe=whole-native-reply current=one-use-native-stage scope=native-status-read-and-saved-counters raw-status-may-be-retained-if-absent authority=native-owner-MUTATE errors=refused no-fault-or-write-authority no-independent-health-or-containment-proof list=na set=na input=na cancel=na",0
str_hal_bad: db " hook err=airlock_reply_incomplete",0
str_hal_live: db " AIRLOCK driver=xhci live=",0
str_hal_hch: db " hch=",0
str_hal_usbsts: db " usbsts=0x",0
str_hal_bus: db " bdf=",0
str_hal_dev: db ":",0
str_hal_fn: db ".",0
str_hal_attempts: db " attempts=",0
str_hal_injected: db " injected=",0
str_hal_contained: db " faults_contained=",0
str_hal_uncontained: db " faults_uncontained=",0
str_hal_stab: db " stab.contained_faults=",0
align 8
hal_fields:
    dq str_hal_live - $, 1, 0
    dq str_hal_hch - $, 1, 0
    dq str_hal_usbsts - $, 0xffffffff, 1
    dq str_hal_bus - $, 255, 0
    dq str_hal_dev - $, 31, 0
    dq str_hal_fn - $, 7, 0
    dq str_hal_attempts - $, -1, 0
    dq str_hal_injected - $, -1, 0
    dq str_hal_contained - $, -1, 2
    dq str_hal_uncontained - $, -1, 0
    dq str_hal_stab - $, -1, 3
    dq 0, 0, 0
hook_edge_airlock: times HE_SZ db 0
hal_pending: db 0

%endif
; ---------------------------------------------------------------------------
; OWNERSTAT is a synchronous owner-private RSP_HINT record (no native ready or
; end cursor exists). Retire before dispatch, then require the current plan,
; exact native buffer identity, complete bounded record and native state value.
; No owner-store operation, key material, authority or producer is introduced.
HOW_NATIVE_CAP equ 128
hook_owner_plan:
    push rdi
    push rsi
    push rdx
    call how_retire
    pop  rdx
    pop  rsi
    pop  rdi
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    jne  .bad
    call command_hook_arg_reset
    mov  byte [rel how_pending], 1
    lea  rax, [rel str_how_verb]
    ret
.na:
    xor  eax, eax
    mov  edx, HOOK_PLAN_NA
    ret
.bad:
    xor  eax, eax
    mov  edx, HOOK_PLAN_BADARG
    ret

hook_owner_post:
    push rbx
    push r12
    push r13
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  byte [rel how_pending], 1
    jne  .bad
    lea  rdi, [rel ownerstat_buf]
    cmp  [rbx + RSP_HINT], rdi
    jne  .bad
    xor  ecx, ecx
.length:
    cmp  ecx, HOW_NATIVE_CAP
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    lea  r13, [rdi + rcx]
    call how_record
    test eax, eax
    jz   .bad
    cmp  rdi, r13
    jne  .bad
    cmp  [rbx + RSP_VAL], r12
    jne  .bad
    lea  r12, [rel ownerstat_buf]
    sub  rdi, r12
    push rdi
    call command_hook_out_reset
    pop  rsi
    mov  rdi, r12
    call command_hook_out_strn
    lea  rax, [rel command_hook_out_buf]
    mov  [rbx + RSP_HINT], rax          ; native bytes are retired below
    jmp  .done
.bad:
    call command_hook_out_reset
    lea  rdi, [rel str_how_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_how_bad]
    mov  [rbx + RSP_HINT], rax
.done:
    call how_retire
    mov  eax, 1
    jmp  .out
.refused:
    call how_retire
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

how_retire:
    mov  byte [rel how_pending], 0
    lea  rdi, [rel ownerstat_buf]
    xor  eax, eax
    mov  ecx, HOW_NATIVE_CAP / 8
    cld
    rep  stosq
    ret

; Complete ordered grammar at the actual native load widths. Do not invent
; enum policy or cross-field consistency; state is bound to native RSP_VAL.
; EAX=valid, R12=state. RDI advances to NUL. Caller owns saved R12/R13.
how_record:
    push rbx
    xor  ebx, ebx
.next:
    lea  rax, [rel how_fields]
    mov  rsi, [rax + rbx*8]
    add  rsi, rax
    call hbi_literal
    test eax, eax
    jz   .out
    call hbi_decimal
    test eax, eax
    jz   .out
    cmp  ebx, 1                         ; generation is full u64
    je   .advance
    mov  r8d, 0xffffffff
    cmp  ebx, 2                         ; summary is native dword
    je   .width
    mov  r8d, 255                       ; state/stage/slot/planted are bytes
.width:
    cmp  rdx, r8
    ja   .no
    test ebx, ebx
    jnz  .advance
    mov  r12, rdx
.advance:
    inc  ebx
    cmp  ebx, 6
    jb   .next
    cmp  byte [rdi], 0
    jne  .no
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  rbx
    ret

str_how_name: db "owner",0
str_how_kind: db "session",0
str_how_verb: db "OWNERSTAT",0
str_how_schema: db "v=1 inst=none get=OWNERSTAT{state:u8,gen:u64,summary:u32,stage:u8,slot:u8,planted:u8} observe=whole-validated-native-record authority=native-owner-only receipt=current-synchronous-hint,state-bound,complete,max127 scope=saved-boot-owner-store-scalars no-key-verifier-stage-name-or-live-store-read list=na set=na input=na cancel=na",0
str_how_bad: db " hook err=owner_reply_incomplete",0
str_how_state: db "owner_store state=",0
str_how_gen: db " gen=",0
str_how_summary: db " summary=",0
str_how_stage: db " stage=",0
str_how_slot: db " slot=",0
str_how_planted: db " planted=",0
how_fields:
    dq str_how_state-how_fields, str_how_gen-how_fields
    dq str_how_summary-how_fields, str_how_stage-how_fields
    dq str_how_slot-how_fields, str_how_planted-how_fields
%macro WDATA_svc_hook_owner 0
hook_edge_owner: times (HE_SZ / 8) dq 0
how_pending: db 0
%endmacro
WDATA_DEFER WDATA_svc_hook_owner

str_hse_word_check: db "CHECK",0
str_hse_word_issue: db "ISSUE",0
str_hse_item_eq: db "ITEM=",0
str_hse_verb_fscheck: db "FSCHECK",0
str_hse_check_options:
    db "TREE=1",0
    db "MODE=refuse",0
    db "MODE=refuse TREE=1",0
    db "MODE=keepboth",0
    db "MODE=keepboth TREE=1",0
    db "MODE=skipsame",0
    db "MODE=skipsame TREE=1",0
    db "MODE=skipsame+keepboth",0
    db "MODE=skipsame+keepboth TREE=1",0
    db 0
