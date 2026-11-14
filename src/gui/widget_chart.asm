;; MODULE gui/widget_chart
;; LAYER 6
;; EXPORTS wgt_chart_register, wgt_chart_draw, wgt_chart_set, wgt_chart_get, wgt_chart_push, wgt_chart_type
;; IMPORTS gui/widget, gui/widget_progress, gui/window_mgmt, core/lib/fmt, core/lib/str, svc/command, svc/command_auth, boot/serial
;; OWNER saga:gui_kit_wave2
;
; Chart v1 is deliberately small: one registered type, two paint modes, and one
; 64-entry unsigned-integer ring per live instance. It draws no text, axes or
; legends. Every colour is a theme token and every scale is derived with
; integer arithmetic from the same samples exposed by CHARTREAD.

CHART_RING_CAP        equ 64
CHART_RING_MASK       equ CHART_RING_CAP-1
CHART_INSTANCE_MAX    equ 8
CHART_MODE_SPARKLINE  equ 0
CHART_MODE_BAR        equ 1

; Type-local reuse of the base widget tail. WGI_BIND remains available to the
; form/netmon cadence seam.
CHART_MODE       equ WGI_RSVD          ; byte
CHART_COUNT      equ WGI_SCROLL        ; dword, 0..64
CHART_HEAD       equ WGI_CARET         ; dword, next write index
CHART_SLOT       equ WGI_EDIT          ; dword, ring slot + 1 (zero = unbound)
CHART_SCALE      equ WGI_MAXVAL        ; qword, integer maximum (at least one)

; Register after image/grid/overlay and before secret/console-grid. This keeps
; every already-shipped type number stable while using the normal additive seam.
wgt_chart_register:
    push rbx
    lea  rdi, [rel chart_ring_owner]
    mov  ecx, CHART_INSTANCE_MAX
    mov  eax, -1
.owner_init:
    mov  [rdi], eax
    add  rdi, 4
    loop .owner_init
    lea  rdi, [rel str_wt_chart]
    lea  rsi, [rel wgt_chart_draw]
    lea  rdx, [rel wgt_rect_hittest]
    lea  rcx, [rel wgt_chart_set]
    lea  r8,  [rel wgt_chart_get]
    mov  r9, (72 << 32) | 260
    call wgt_type_register
    mov  [rel wgt_chart_type], eax
    cmp  eax, -1
    je   .fail

    xor  ebx, ebx
    lea  rdi, [rel str_verb_chartpush]
    lea  rsi, [rel cmd_verb_chartpush]
    mov  rdx, CMD_AUTH_CAP_MUTATE
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                         ; signed state mutation
    call command_register_verb
    or   ebx, eax
    lea  rdi, [rel str_verb_chartread]
    lea  rsi, [rel cmd_verb_chartread]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                        ; exact public-T0 name in command_auth
    call command_register_verb
    or   ebx, eax
    test ebx, ebx
    js   .fail
    call wgt_chart_selftest
    test eax, eax
    jnz  .fail
    lea  rdi, [rel str_chart_marker]
    call serial_string
    xor  eax, eax
    pop  rbx
    ret
.fail:
    lea  rdi, [rel str_chart_fail]
    call serial_string
    mov  eax, 1
    pop  rbx
    ret

; Resolve/allocate the bounded backing ring for EDI=widget id.
; CF=0 RAX=ring base; CF=1 means the chart-instance budget is full.
wgt_chart_ring_ptr:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    call wgt_slot_ptr
    mov  ebx, [rax + CHART_SLOT]
    test ebx, ebx
    jz   .scan
    dec  ebx
    cmp  ebx, CHART_INSTANCE_MAX
    jae  .scan
    lea  r13, [rel chart_ring_owner]
    cmp  [r13 + rbx*4], r12d
    je   .have
.scan:
    xor  ebx, ebx
    lea  r13, [rel chart_ring_owner]
.candidate:
    cmp  ebx, CHART_INSTANCE_MAX
    jae  .full
    mov  eax, [r13 + rbx*4]
    cmp  eax, -1
    je   .claim
    cmp  eax, [rel wgt_count]
    jae  .claim                         ; retired tail widget
    mov  edi, eax
    call wgt_slot_ptr
    mov  ecx, [rel wgt_chart_type]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .claim                         ; closed/reused widget id
    mov  ecx, ebx
    inc  ecx
    cmp  [rax + CHART_SLOT], ecx
    jne  .claim
    inc  ebx
    jmp  .candidate
.claim:
    mov  [r13 + rbx*4], r12d
    mov  edi, r12d
    call wgt_slot_ptr
    mov  ecx, ebx
    inc  ecx
    mov  [rax + CHART_SLOT], ecx
    mov  dword [rax + CHART_COUNT], 0
    mov  dword [rax + CHART_HEAD], 0
    mov  qword [rax + CHART_SCALE], 1
    mov  qword [rax + WGI_NUM], 0
    imul rax, rbx, CHART_RING_CAP*4
    lea  rdi, [rel chart_rings]
    add  rdi, rax
    push rdi
    xor  eax, eax
    mov  ecx, CHART_RING_CAP
    cld
    rep  stosd
    pop  rax
    clc
    jmp  .out
.have:
    imul rax, rbx, CHART_RING_CAP*4
    lea  rdx, [rel chart_rings]
    add  rax, rdx
    clc
    jmp  .out
.full:
    xor  eax, eax
    stc
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Release EDI's backing slot. Used by the no-residue boot KAT.
wgt_chart_release:
    push rbx
    mov  ebx, edi
    call wgt_slot_ptr
    mov  ecx, [rax + CHART_SLOT]
    mov  dword [rax + CHART_SLOT], 0
    test ecx, ecx
    jz   .out
    dec  ecx
    cmp  ecx, CHART_INSTANCE_MAX
    jae  .out
    lea  rdx, [rel chart_ring_owner]
    cmp  [rdx + rcx*4], ebx
    jne  .out
    mov  dword [rdx + rcx*4], -1
.out:
    pop  rbx
    ret

; Clear EDI's ring. No externally visible field changes unless allocation
; succeeds, so CHARTPUSH can validate its whole batch before calling here.
wgt_chart_reset:
    push r12
    mov  r12d, edi
    call wgt_chart_ring_ptr
    jc   .bad
    mov  rdi, rax
    xor  eax, eax
    mov  ecx, CHART_RING_CAP
    cld
    rep  stosd
    mov  edi, r12d
    call wgt_slot_ptr
    mov  dword [rax + CHART_COUNT], 0
    mov  dword [rax + CHART_HEAD], 0
    mov  qword [rax + CHART_SCALE], 1
    mov  qword [rax + WGI_NUM], 0
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 1
.out:
    pop  r12
    ret

; Append ESI to EDI's ring and recompute its integer autoscale.
wgt_chart_push:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, edi
    mov  r14d, esi
    call wgt_chart_ring_ptr
    jc   .bad
    mov  r13, rax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  eax, [rbx + CHART_HEAD]
    and  eax, CHART_RING_MASK
    mov  [r13 + rax*4], r14d
    inc  eax
    and  eax, CHART_RING_MASK
    mov  [rbx + CHART_HEAD], eax
    cmp  dword [rbx + CHART_COUNT], CHART_RING_CAP
    jae  .count_ready
    inc  dword [rbx + CHART_COUNT]
.count_ready:
    mov  [rbx + WGI_NUM], r14
    mov  eax, 1                         ; zero-only rings still scale by one
    xor  ecx, ecx
.max_loop:
    cmp  ecx, CHART_RING_CAP
    jae  .max_done
    mov  edx, [r13 + rcx*4]
    cmp  edx, eax
    cmova eax, edx
    inc  ecx
    jmp  .max_loop
.max_done:
    mov  [rbx + CHART_SCALE], rax
    inc  qword [rbx + WGI_INTENT_SEQ]   ; data generation, useful semantic delta
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Token-only painter. Sparkline uses integer-scaled point columns; bar mode
; uses wider bottom-aligned columns. Both remain visibly non-flat for changing
; samples without introducing a chart-private line or text primitive.
wgt_chart_draw:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32
    mov  r12d, edi
    call wgt_slot_ptr
    mov  rbp, rax
    mov  r8d, [rbp + WGI_X]
    mov  r9d, [rbp + WGI_Y]
    mov  r10d, [rbp + WGI_W]
    mov  r11d, [rbp + WGI_H]
    mov  ebx, GUI_TOK_OUTLINE
    call wgt_fill_rect
    mov  r8d, [rbp + WGI_X]
    inc  r8d
    mov  r9d, [rbp + WGI_Y]
    inc  r9d
    mov  r10d, [rbp + WGI_W]
    cmp  r10d, 2
    jbe  .out
    sub  r10d, 2
    mov  r11d, [rbp + WGI_H]
    cmp  r11d, 2
    jbe  .out
    sub  r11d, 2
    mov  ebx, GUI_TOK_WINDOW_BODY
    call wgt_fill_rect
    mov  r14d, [rbp + CHART_COUNT]
    test r14d, r14d
    jz   .out
    mov  eax, [rbp + WGI_W]
    sub  eax, 2
    cmp  r14d, eax
    jbe  .visible_count_ready
    mov  r14d, eax                     ; newest samples that fit, state remains 64
.visible_count_ready:
    mov  edi, r12d
    call wgt_chart_ring_ptr
    jc   .out
    mov  r13, rax
    mov  r15d, [rbp + CHART_HEAD]
    sub  r15d, r14d
    and  r15d, CHART_RING_MASK          ; oldest retained sample
    mov  eax, [rbp + CHART_SCALE]
    test eax, eax
    jnz  .scale_ready
    mov  eax, 1
.scale_ready:
    mov  [rsp + 8], eax                 ; scale
    mov  dword [rsp], 0                 ; sample ordinal
.sample:
    mov  ecx, [rsp]
    cmp  ecx, r14d
    jae  .out
    mov  eax, r15d
    add  eax, ecx
    and  eax, CHART_RING_MASK
    mov  eax, [r13 + rax*4]             ; sample
    test eax, eax
    jnz  .scale_sample
    cmp  byte [rbp + CHART_MODE], CHART_MODE_BAR
    je   .next                           ; zero bar has no filled area
.scale_sample:
    mov  r10d, [rbp + WGI_H]
    sub  r10d, 2
    imul rax, r10
    xor  edx, edx
    mov  ecx, [rsp + 8]
    div  rcx
    test eax, eax
    jnz  .height_ready
    mov  eax, 1
.height_ready:
    mov  [rsp + 12], eax                ; scaled height
    mov  eax, [rbp + WGI_W]
    sub  eax, 2
    xor  edx, edx
    div  r14d
    test eax, eax
    jnz  .stride_ready
    mov  eax, 1
.stride_ready:
    mov  [rsp + 16], eax                ; sample stride
    cmp  byte [rbp + CHART_MODE], CHART_MODE_BAR
    je   .bar
    ; Sparkline: a one-pixel staircase connector between integer-scaled
    ; points. It never fills down to a baseline (that visual belongs to bar).
    mov  eax, [rsp]
    imul eax, [rsp + 16]
    add  eax, [rbp + WGI_X]
    inc  eax
    mov  [rsp + 24], eax                ; current x
    mov  eax, [rbp + WGI_Y]
    add  eax, [rbp + WGI_H]
    dec  eax
    sub  eax, [rsp + 12]
    mov  [rsp + 28], eax                ; current y
    cmp  dword [rsp], 0
    je   .spark_point
    mov  r8d, [rsp + 4]
    mov  r10d, [rsp + 24]
    sub  r10d, r8d
    inc  r10d
    mov  r9d, [rsp + 28]
    mov  r11d, 1
    mov  ebx, GUI_TOK_SELECTION
    call wgt_fill_rect
    mov  r8d, [rsp + 24]
    mov  r9d, [rsp + 20]
    mov  eax, [rsp + 28]
    cmp  r9d, eax
    jbe  .spark_y_ready
    mov  r9d, eax
.spark_y_ready:
    mov  r11d, [rsp + 20]
    sub  r11d, [rsp + 28]
    jns  .spark_h_ready
    neg  r11d
.spark_h_ready:
    inc  r11d
    mov  r10d, 1
    mov  ebx, GUI_TOK_SELECTION
    call wgt_fill_rect
    jmp  .spark_remember
.spark_point:
    mov  r8d, [rsp + 24]
    mov  r9d, [rsp + 28]
    mov  r10d, 1
    mov  r11d, 1
    mov  ebx, GUI_TOK_SELECTION
    call wgt_fill_rect
.spark_remember:
    mov  eax, [rsp + 24]
    mov  [rsp + 4], eax
    mov  eax, [rsp + 28]
    mov  [rsp + 20], eax
    jmp  .next
.bar:
    mov  eax, [rsp + 16]
    cmp  eax, 1
    jbe  .bar_width
    dec  eax                            ; retain a body-token gap between bars
.bar_width:
    mov  r10d, eax
    mov  eax, [rsp]
    imul eax, [rsp + 16]
    add  eax, [rbp + WGI_X]
    inc  eax
    mov  r8d, eax
    mov  r11d, [rsp + 12]
    mov  r9d, [rbp + WGI_Y]
    add  r9d, [rbp + WGI_H]
    dec  r9d
    sub  r9d, r11d
    mov  ebx, GUI_TOK_SELECTION_MUTED
    call wgt_fill_rect
.next:
    inc  dword [rsp]
    jmp  .sample
.out:
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

wgt_chart_set:
    push rbx
    push r12
    mov  r12d, edi
    mov  rbx, rdx
    lea  rdi, [rel str_chart_mode]
    call strcmp
    test eax, eax
    jnz  .bad
    mov  rdi, rbx
    call wgt_chart_parse_mode
    jc   .bad
    mov  ebx, eax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  [rax + CHART_MODE], bl
    mov  edi, r12d
    call wgt_draw_id
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 1
.out:
    pop  r12
    pop  rbx
    ret

wgt_chart_get:
    push rbx
    push r12
    mov  r12d, edi
    mov  rbx, rsi
    lea  rdi, [rel str_chart_mode]
    call strcmp
    test eax, eax
    jz   .mode
    lea  rdi, [rel str_chart_count]
    mov  rsi, rbx
    call strcmp
    test eax, eax
    jz   .count
    lea  rdi, [rel str_chart_scale]
    mov  rsi, rbx
    call strcmp
    test eax, eax
    jnz  .bad
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rdi, [rax + CHART_SCALE]
    jmp  .number
.count:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  edi, [rax + CHART_COUNT]
.number:
    lea  rsi, [rel chart_num_buf]
    push rsi
    call fmt_dec
    pop  rsi
    mov  byte [rsi + rax], 0
    lea  rax, [rel chart_num_buf]
    jmp  .out
.mode:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  edx, [rax + CHART_MODE]
    lea  rax, [rel str_chart_sparkline]
    cmp  dl, CHART_MODE_BAR
    jne  .out
    lea  rax, [rel str_chart_bar]
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; RDI=mode token -> EAX mode, CF=0; CF=1 invalid.
wgt_chart_parse_mode:
    push rbx
    mov  rbx, rdi
    lea  rsi, [rel str_chart_sparkline]
    call strcmp
    test eax, eax
    jz   .spark
    mov  rdi, rbx
    lea  rsi, [rel str_chart_bar]
    call strcmp
    test eax, eax
    jnz  .bad
    mov  eax, CHART_MODE_BAR
    clc
    pop  rbx
    ret
.spark:
    mov  eax, CHART_MODE_SPARKLINE
    clc
    pop  rbx
    ret
.bad:
    xor  eax, eax
    stc
    pop  rbx
    ret

; Exact stable form-local id lookup. Returns EAX widget id or -1.
wgt_chart_find:
    push rbx
    push r12
    push r13
    mov  r13, rdi
    xor  r12d, r12d
    mov  ebx, [rel wgt_chart_type]
    inc  ebx
.loop:
    cmp  r12d, [rel wgt_count]
    jae  .miss
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  [rax + WGI_TYPE], ebx
    jne  .next
    mov  rdi, [rax + WGI_ID]
    test rdi, rdi
    jz   .next
    mov  rsi, r13
    call strcmp
    test eax, eax
    jz   .hit
.next:
    inc  r12d
    jmp  .loop
.hit:
    mov  eax, r12d
    jmp  .out
.miss:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Bounded request copy. EAX=0 success, 1 oversize.
wgt_chart_arg_copy:
    lea  rax, [rel chart_arg_buf]
    xor  ecx, ecx
.copy:
    cmp  ecx, CHART_ARG_MAX
    jae  .too_long
    mov  dl, [rsi + rcx]
    test dl, dl
    jz   .done
    mov  [rax + rcx], dl
    inc  ecx
    jmp  .copy
.done:
    mov  byte [rax + rcx], 0
    xor  eax, eax
    ret
.too_long:
    mov  byte [rax + CHART_ARG_MAX], 0
    mov  eax, 1
    ret

; Parse a comma list at RDI into chart_parse_values. EAX=count, CF=0; no
; chart/ring state is touched on error. Samples are exact unsigned 32-bit ints.
wgt_chart_parse_samples:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    xor  ebx, ebx
.token:
    cmp  ebx, CHART_RING_CAP
    jae  .bad
    cmp  byte [r12], 0
    je   .bad
    mov  rdx, r12
.scan:
    mov  al, [rdx]
    test al, al
    jz   .last
    cmp  al, ','
    je   .split
    inc  rdx
    jmp  .scan
.split:
    mov  byte [rdx], 0
    lea  r13, [rdx + 1]
    jmp  .parse
.last:
    xor  r13d, r13d
.parse:
    mov  rdi, r12
    call wgt_progress_parse_num
    jc   .bad
    mov  edx, 0xffffffff
    cmp  rax, rdx
    ja   .bad
    lea  rdx, [rel chart_parse_values]
    mov  [rdx + rbx*4], eax
    inc  ebx
    test r13, r13
    jz   .done
    mov  r12, r13
    jmp  .token
.done:
    mov  eax, ebx
    clc
    pop  r13
    pop  r12
    pop  rbx
    ret
.bad:
    xor  eax, eax
    stc
    pop  r13
    pop  r12
    pop  rbx
    ret

; Shared read record. EDI=widget id, RSI=id token, RDX=nonce token.
wgt_chart_stage_read:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13, rsi
    mov  r14, rdx
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  r15d, [rbx + CHART_COUNT]
    mov  edi, r12d
    call wgt_chart_ring_ptr
    jc   .capacity
    mov  r12, rax
    lea  rdi, [rel str_chart_read_ok]
    call wgt_out_str
    mov  rdi, r13
    call wgt_out_str
    lea  rdi, [rel str_chart_nonce_out]
    call wgt_out_str
    mov  rdi, r14
    call wgt_out_str
    lea  rdi, [rel str_chart_mode_out]
    call wgt_out_str
    lea  rdi, [rel str_chart_sparkline]
    cmp  byte [rbx + CHART_MODE], CHART_MODE_BAR
    jne  .mode_ready
    lea  rdi, [rel str_chart_bar]
.mode_ready:
    call wgt_out_str
    lea  rdi, [rel str_chart_count_out]
    call wgt_out_str
    mov  edi, r15d
    call wgt_out_dec
    lea  rdi, [rel str_chart_scale_out]
    call wgt_out_str
    mov  rdi, [rbx + CHART_SCALE]
    call wgt_out_dec
    lea  rdi, [rel str_chart_samples_out]
    call wgt_out_str
    mov  ebx, [rbx + CHART_HEAD]
    sub  ebx, r15d
    and  ebx, CHART_RING_MASK
    xor  r14d, r14d
.sample:
    cmp  r14d, r15d
    jae  .out
    test r14d, r14d
    jz   .number
    lea  rdi, [rel str_chart_comma]
    call wgt_out_str
.number:
    mov  eax, ebx
    add  eax, r14d
    and  eax, CHART_RING_MASK
    mov  edi, [r12 + rax*4]
    call wgt_out_dec
    inc  r14d
    jmp  .sample
.capacity:
    lea  rdi, [rel str_chart_err_capacity]
    call wgt_out_str
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; CHARTPUSH <stable-id> <nonce> <csv>. The command gate rejects unsigned
; requests before this handler runs. The entire batch parses before reset, so
; every handler-level refusal also has zero ring/tree effect.
cmd_verb_chartpush:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r15, rsi
    call wgt_out_reset
    mov  rsi, [rdi + REQ_ARG]
    test rsi, rsi
    jz   .syntax
    call wgt_chart_arg_copy
    test eax, eax
    jnz  .oversize
    lea  rdi, [rel chart_arg_buf]
    cmp  byte [rdi], 0
    je   .syntax
    call wgt_tok_split
    mov  r12, rdi                       ; stable widget id
    mov  rdi, rax
    cmp  byte [rdi], 0
    je   .syntax
    call wgt_tok_split
    mov  r13, rdi                       ; caller nonce
    mov  r14, rax                       ; csv batch
    cmp  byte [r14], 0
    je   .syntax
    mov  rdi, r14
    call wgt_chart_parse_samples
    jc   .samples
    mov  ebx, eax
    mov  rdi, r12
    call wgt_chart_find
    cmp  eax, -1
    je   .missing
    mov  r14d, eax
    mov  edi, r14d
    call wgt_chart_reset
    test eax, eax
    jnz  .capacity
    xor  r12d, r12d
.commit:
    cmp  r12d, ebx
    jae  .committed
    lea  rax, [rel chart_parse_values]
    mov  esi, [rax + r12*4]
    mov  edi, r14d
    call wgt_chart_push
    inc  r12d
    jmp  .commit
.committed:
    call wmx_draw_all
    lea  rdi, [rel str_chart_push_ok]
    call wgt_out_str
    mov  edi, r14d
    call wgt_slot_ptr
    mov  rdi, [rax + WGI_ID]
    call wgt_out_str
    lea  rdi, [rel str_chart_nonce_out]
    call wgt_out_str
    mov  rdi, r13
    call wgt_out_str
    lea  rdi, [rel str_chart_count_out]
    call wgt_out_str
    mov  edi, r12d                      ; the committed count (r12 == ebx after .commit); the painters
                                        ; under wmx_draw_all leave RBX dirty (MSI seam census 2026-10-02)
    call wgt_out_dec
    jmp  .stage
.oversize:
    lea  rdi, [rel str_chart_err_oversize]
    jmp  .error
.syntax:
    lea  rdi, [rel str_chart_err_syntax]
    jmp  .error
.samples:
    lea  rdi, [rel str_chart_err_samples]
    jmp  .error
.missing:
    lea  rdi, [rel str_chart_err_missing]
    jmp  .error
.capacity:
    lea  rdi, [rel str_chart_err_capacity]
.error:
    call wgt_out_str
.stage:
    mov  byte [rel wgt_out_ready], 1
    mov  qword [r15 + RSP_CODE], CMDE_OK
    mov  qword [r15 + RSP_VAL], 0
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; CHARTREAD <stable-id> <nonce> is public T0 and echoes the challenge with the
; chronological samples, mode, count and integer scale.
cmd_verb_chartread:
    call cmd_handler_prologue
    push r12
    push r13
    push r14
    mov  r14, rsi
    call wgt_out_reset
    mov  rsi, [rdi + REQ_ARG]
    test rsi, rsi
    jz   .bad
    call wgt_chart_arg_copy
    test eax, eax
    jnz  .bad
    lea  rdi, [rel chart_arg_buf]
    cmp  byte [rdi], 0
    je   .bad
    call wgt_tok_split
    mov  r12, rdi
    mov  rdi, rax
    cmp  byte [rdi], 0
    je   .bad
    call wgt_tok_split
    mov  r13, rdi
    cmp  byte [rax], 0
    jne  .bad
    mov  rdi, r12
    call wgt_chart_find
    cmp  eax, -1
    je   .missing
    mov  edi, eax
    mov  rsi, r12
    mov  rdx, r13
    call wgt_chart_stage_read
    jmp  .stage
.bad:
    lea  rdi, [rel str_chart_err_syntax]
    call wgt_out_str
    jmp  .stage
.missing:
    lea  rdi, [rel str_chart_err_missing]
    call wgt_out_str
.stage:
    mov  byte [rel wgt_out_ready], 1
    mov  qword [r14 + RSP_CODE], CMDE_OK
    mov  qword [r14 + RSP_VAL], 0
    pop  r14
    pop  r13
    pop  r12
    ret

; Pure boot KAT with no surviving widget/tree state. It exercises ordered
; insert, wrap, autoscale and both mode tokens through production helpers.
wgt_chart_selftest:
    push rbx
    push r12
    push r13
    mov  r12d, [rel wgt_count]
    inc  byte [rel wgt_paint_suspended]
    mov  edi, [rel wgt_chart_type]
    xor  esi, esi
    call wgt_create
    dec  byte [rel wgt_paint_suspended]
    cmp  eax, -1
    je   .bad
    mov  r13d, eax
    mov  edi, r13d
    call wgt_slot_ptr
    and  dword [rax + WGI_FLAGS], ~1
    mov  edi, r13d
    call wgt_chart_reset
    test eax, eax
    jnz  .bad_widget
    mov  edi, r13d
    mov  esi, 3
    call wgt_chart_push
    mov  edi, r13d
    mov  esi, 5
    call wgt_chart_push
    mov  edi, r13d
    mov  esi, 8
    call wgt_chart_push
    mov  edi, r13d
    mov  esi, 13
    call wgt_chart_push
    mov  edi, r13d
    call wgt_slot_ptr
    cmp  dword [rax + CHART_COUNT], 4
    jne  .bad_widget
    cmp  qword [rax + CHART_SCALE], 13
    jne  .bad_widget
    lea  rdi, [rel str_chart_sparkline]
    call wgt_chart_parse_mode
    jc   .bad_widget
    cmp  eax, CHART_MODE_SPARKLINE
    jne  .bad_widget
    lea  rdi, [rel str_chart_bar]
    call wgt_chart_parse_mode
    jc   .bad_widget
    cmp  eax, CHART_MODE_BAR
    jne  .bad_widget
    mov  edi, r13d
    call wgt_chart_reset
    xor  ebx, ebx
.wrap:
    inc  ebx
    mov  edi, r13d
    mov  esi, ebx
    call wgt_chart_push
    cmp  ebx, CHART_RING_CAP+1
    jb   .wrap
    mov  edi, r13d
    call wgt_slot_ptr
    cmp  dword [rax + CHART_COUNT], CHART_RING_CAP
    jne  .bad_widget
    cmp  dword [rax + CHART_HEAD], 1
    jne  .bad_widget
    cmp  qword [rax + CHART_SCALE], CHART_RING_CAP+1
    jne  .bad_widget
    mov  edi, r13d
    call wgt_chart_ring_ptr
    jc   .bad_widget
    cmp  dword [rax], CHART_RING_CAP+1 ; newest wrapped sample (65) at slot zero
    jne  .bad_widget
    cmp  dword [rax + 4], 2            ; oldest retained sample follows head
    jne  .bad_widget
    mov  edi, r13d
    call wgt_chart_release
    mov  edi, r13d
    call wgt_slot_ptr
    mov  dword [rax + WGI_TYPE], 0
    mov  [rel wgt_count], r12d
    xor  eax, eax
    jmp  .out
.bad_widget:
    mov  edi, r13d
    call wgt_chart_release
    mov  edi, r13d
    call wgt_slot_ptr
    mov  dword [rax + WGI_TYPE], 0
.bad:
    mov  [rel wgt_count], r12d
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

CHART_ARG_MAX equ 767
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_gui_widget_chart_0 0
align 8
wgt_chart_type: dd -1
chart_ring_owner: times CHART_INSTANCE_MAX dd -1
times 24 db 0                  ; chart_rings..chart_num_buf moved to WDATA_gui_widget_chart_0_bss1: keeps the labels below at their offset mod 64

str_wt_chart:          db "chart",0
str_chart_mode:        db "mode",0
str_chart_count:       db "count",0
str_chart_scale:       db "scale",0
str_chart_sparkline:   db "sparkline",0
str_chart_bar:         db "bar",0
str_verb_chartpush:    db "CHARTPUSH",0
str_verb_chartread:    db "CHARTREAD",0
str_chart_read_ok:     db " chart read id=",0
str_chart_push_ok:     db " chart push id=",0
str_chart_nonce_out:   db " nonce=",0
str_chart_mode_out:    db " mode=",0
str_chart_count_out:   db " count=",0
str_chart_scale_out:   db " scale=",0
str_chart_samples_out: db " samples=",0
str_chart_comma:       db ",",0
str_chart_err_syntax:  db " chart ERR syntax",0
str_chart_err_samples: db " chart ERR samples",0
str_chart_err_oversize: db " chart ERR oversize",0
str_chart_err_missing: db " chart ERR missing",0
str_chart_err_capacity: db " chart ERR capacity",0
str_chart_marker: db "[PAOS64] GUI kit: bounded sparkline/bar chart v1 KAT PASS [gui.kit.chart_v1]",13,10,0
str_chart_fail: db "[PAOS64] GUI kit: bounded sparkline/bar chart v1 KAT FAILED",13,10,0
%endmacro
WDATA_DEFER WDATA_gui_widget_chart_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_gui_widget_chart_0_bss1 0
resb 36                 ; keeps chart_rings at its WDATA offset mod 64
chart_rings: resd (CHART_INSTANCE_MAX*CHART_RING_CAP)
chart_parse_values: resd CHART_RING_CAP
chart_arg_buf: resb (CHART_ARG_MAX+1)
chart_num_buf: resb 24
%endmacro
WDATA_BSS_DEFER WDATA_gui_widget_chart_0_bss1
