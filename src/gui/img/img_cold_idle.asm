;; MODULE gui/img/img_cold_idle
;; LAYER 6
;; EXPORTS img_cold_idle_poll, img_cold_checkpoint, img_cold_pending, img_cold_running
;; IMPORTS gui/img/img_cold_job, svc/command, core/time, core/reset_wipe
;; CAPS
;; OWNER saga:gui_image_pipeline
;; CONTEXT: bsp_only
; Private continuation for the fixed cold-image worker. This is not a general
; task API: neither a caller-selected PC nor a caller/painter stack is saved.
; Codec locals live on this owner's bounded private stack. Checkpoints belong
; only in pure image work or the paired private FAT read lease, outside
; allocator, device, transport and paint calls. The job owns codec state and
; its scratch until completion/cancellation.
;
; The coordinator supplies three FIXED native entries:
;   img_cold_context_current: CF=0 only for this job's generation, authority,
;       source, preference and surface; never accepts a partial stale result.
;   img_cold_run: decode/scale the staged job, publish only after revalidation.
;   img_cold_cancel: discard staged resources without touching the live image.
;   img_cold_resume / img_cold_suspend: expose/retire only the worker's private
;       cache descriptors; preserve every register and flag across the seam.
; Checkpoint coverage and bounded operations between checkpoints are a separate
; obligation; this owner alone does not make an unsliced codec bounded.

IMG_COLD_STEPS equ 32
IMG_COLD_MS equ 2
IMG_COLD_STACK_BYTES equ 65536

%macro IMG_COLD_SAVE 0
    pushfq
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
%endmacro

%macro IMG_COLD_RESTORE 0
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
%endmacro

; Sole entry is the idle loop between command_udp_poll calls. Every return
; restores the idle caller's registers/flags and leaves no transport frame.
img_cold_idle_poll:
    IMG_COLD_SAVE
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    cmp byte [rel img_cold_running],0
    jne .out
    cmp byte [rel img_cold_pending],0
    je .out
    cmp byte [rel reset_wipe_done],0
    jne .cancel
    call img_cold_context_current
    jc .cancel
    ; No TSC calibration means no continuation, rather than an unbounded turn.
    mov rax,[rel tsc_khz]
    test rax,rax
    jz .out
    cmp rax,0x3fffffff
    ja .out
    imul rax,IMG_COLD_MS
    mov rbx,rax
    lfence
    rdtsc
    shl rdx,32
    or rax,rdx
    add rax,rbx
    jc .out
    mov [rel img_cold_deadline],rax
    mov dword [rel img_cold_fuel],IMG_COLD_STEPS
    mov [rel img_cold_host_rsp],rsp
    mov byte [rel img_cold_running],1
    call img_cold_resume
    cmp byte [rel img_cold_started],0
    jne .resume
    mov byte [rel img_cold_started],1
    lea rsp,[rel img_cold_stack_end]
    call img_cold_run
    ; A completed worker must have returned normally. There is no saved PC
    ; after completion and a later request starts on a fresh private stack.
    mov byte [rel img_cold_pending],0
    mov byte [rel img_cold_started],0
    mov qword [rel img_cold_saved_rsp],0
    jmp img_cold_return_host
.resume:
    mov rsp,[rel img_cold_saved_rsp]
    IMG_COLD_RESTORE
    ret
.cancel:
    mov byte [rel img_cold_pending],0
    mov byte [rel img_cold_started],0
    mov qword [rel img_cold_saved_rsp],0
    call img_cold_cancel
.out:
    IMG_COLD_RESTORE
    ret

; All integer registers and flags survive, including carry and DF used by
; codec loops. There is no SIMD state in the admitted image worker. A caller
; outside the running worker receives an exact no-op and cannot yield dispatch.
img_cold_checkpoint:
    IMG_COLD_SAVE
    cmp byte [rel img_cold_running],1
    jne .continue
    dec dword [rel img_cold_fuel]
    jz .yield
    lfence
    rdtsc
    shl rdx,32
    or rax,rdx
    cmp rax,[rel img_cold_deadline]
    jb .continue
.yield:
    mov [rel img_cold_saved_rsp],rsp
    jmp img_cold_return_host
.continue:
    IMG_COLD_RESTORE
    ret

img_cold_return_host:
    call img_cold_suspend
    mov byte [rel img_cold_running],0
    mov rsp,[rel img_cold_host_rsp]
    mov qword [rel img_cold_host_rsp],0
    IMG_COLD_RESTORE
    ret

%include "core/abi/wdata.inc"
%macro WDATA_gui_img_cold_idle 0
align 16
img_cold_host_rsp: dq 0
img_cold_saved_rsp: dq 0
img_cold_deadline: dq 0
img_cold_fuel: dd 0
img_cold_pending: db 0
img_cold_running: db 0
img_cold_started: db 0
%endmacro
WDATA_DEFER WDATA_gui_img_cold_idle

%macro WDATA_BSS_gui_img_cold_idle 0
alignb 16
img_cold_stack: resb IMG_COLD_STACK_BYTES
img_cold_stack_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_img_cold_idle
