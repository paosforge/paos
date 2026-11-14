;; MODULE svc/aer_poll
;; LAYER 5
;; EXPORTS aer_poll_init, aer_poll_bind, aer_poll_tick, aer_poll_lookup, aer_poll_coverage_lookup, aer_poll_bind_root
;; IMPORTS core/time, core/diag, bus/pci_bdf, bus/pci_contain, svc/aer_dma_probe, svc/command_audit
;; CAPS
;; OWNER saga:command
; BSP-only AER observation; config stop on new actionable uncorrected status.
; Discovery/control binds at most32 qualified segment0 AER functions; one is sampled per
; second through the admitted ECAM reader. No allocation, IRQ, status
; acknowledgement or recovery. Configuration stop is separate from DMA proof.
;
; Each row retains the last full nonzero-status observation for this boot, plus
; the last successful sample for dedup. Unchanged sticky status is suppressed;
; an observed clear permits a later identical record. Mask/header changes with
; sticky status also count as observations, never hardware error totals. A failed
; read updates only last status/attempts, preserving both snapshots and count.
; Removal/replacement between successful polls cannot be distinguished from a
; status transition at the same BDF; there is no device-lifetime identity claim.
; Full raw masks/severity/header logs remain in RAM, with class bitmaps offered
; once to the existing diag ring (which can refuse/drop and has its own policy).
;
; Callers are the BSP boot enumerator, BSP service pump and serialized AERLOG.
; Lookup is read-only; no caller owns or can reset the returned internal row.
AER_POLL_N          equ 32
AER_POLL_STRIDE     equ 320
AER_POLL_INTERVAL   equ 1000000
AER_POLL_STATUS    equ 4       ; last reader result,10 not sampled,11 not bound
AER_POLL_ATTEMPTS  equ 8       ; saturating attempted polls
AER_POLL_COUNT     equ 16      ; saturating nonzero changed observations
AER_POLL_EVENT_US  equ 24      ; timestamp of retained nonzero observation
AER_POLL_SAMPLE_US equ 32      ; timestamp of last successful read
AER_POLL_FLAGS     equ 40      ; bit0 previous valid, bit1 retained event valid
AER_POLL_BLIND     equ 60      ; first raw US: repeated sticky types cannot be dated
AER_POLL_ACTION    equ 56      ; private newly asserted actionable US bits
AER_POLL_DROPS     equ 48      ; saturating diag append refusals (no retries)
AER_POLL_PREVIOUS  equ 64      ; exact64B last successful sample, including clears
AER_POLL_EVENT     equ 128     ; exact64B retained nonzero observation

; Independent immutable initial successful snapshot (not a fault-time claim).
AER_BOOT_VALID     equ 192
AER_BOOT_COMMIT    equ 200
AER_BOOT_DROP      equ 208
AER_BOOT_COUNT     equ 216
AER_BOOT_RAW       equ 224
AER_BOOT_ROOT_FLAGS equ 288     ; bit0 sampled,bit1 applicable,bit2 later raw change
AER_BOOT_ROOT_RAW   equ 296
AER_BOOT_ROOT_COMMIT equ 304
AER_BOOT_ROOT_DROP  equ 312

AER_Q_STRIDE       equ 128
AER_Q_ATTEMPTS     equ 0
AER_Q_POLLS        equ 8
AER_Q_FIRST        equ 16
AER_Q_LAST         equ 24
AER_Q_FAILED       equ 32
AER_Q_US           equ 40
AER_Q_CS           equ 44
AER_Q_RS           equ 48
AER_Q_ROOT         equ 52
AER_Q_TYPE         equ 56
AER_Q_ID           equ 60
AER_Q_STATUS       equ 64
AER_Q_NOTIFY_ROOT  equ 68

aer_poll_init:
    lea rdi,[rel aer_poll_state]
    xor eax,eax
    mov ecx,(aer_poll_state_end-aer_poll_state)/8
    rep stosq
    ret

; RDI=packed16BDF, returns EAX1 bound/already bound,0 invalid/full. No I/O.
; Boot discovery qualifies bus0 ports. Owner control snapshots may register
; qualified root ports on other buses for observation only, never containment.
aer_poll_bind:
    cmp rdi,65535
    ja .no
    sub rsp,8
    call aer_poll_lookup
    add rsp,8
    test rax,rax
    jnz .yes
    mov ecx,[rel aer_poll_n]
    cmp ecx,AER_POLL_N
    jae .no
    imul eax,ecx,AER_POLL_STRIDE
    lea rdx,[rel aer_poll_rows]
    add rax,rdx
    mov [rax],edi
    mov dword [rax+AER_POLL_STATUS],10
    mov eax,ecx
    shl eax,7
    lea rdx,[rel aer_poll_coverage_rows]
    mov dword [rdx+rax+AER_Q_STATUS],10
    inc dword [rel aer_poll_n]
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

; Original boot-discovered bus0 root-port producer keeps its notification scope.
; Other qualified functions are read/count/log only; they cannot become roots.
aer_poll_bind_root:
    push rdi
    call aer_poll_bind
    test eax,eax
    jz .done
    mov rdi,[rsp]
    call aer_poll_coverage_lookup
    mov dword [rax+AER_Q_NOTIFY_ROOT],1
    mov eax,1
.done:
    pop rdi
    ret

; RDI=packed BDF. RAX=private row pointer or0; preserves RDI. Bounded32 rows.
aer_poll_lookup:
    cmp rdi,65535
    ja .no
    mov ecx,[rel aer_poll_n]
    lea rax,[rel aer_poll_rows]
.loop:
    test ecx,ecx
    jz .no
    cmp [rax],edi
    je .done
    add rax,AER_POLL_STRIDE
    dec ecx
    jmp .loop
.no:
    xor eax,eax
.done:
    ret

; RDI packed BDF -> private census row or0, read-only and BSP serialized.
aer_poll_coverage_lookup:
    sub rsp,8
    call aer_poll_lookup
    add rsp,8
    test rax,rax
    jz .done
    lea rdx,[rel aer_poll_rows]
    sub rax,rdx
    xor edx,edx
    mov ecx,AER_POLL_STRIDE
    div rcx
    shl rax,7
    lea rdx,[rel aer_poll_coverage_rows]
    add rax,rdx
.done:
    ret

; One try per due service tick, never catch up after a long scheduling gap.
; Publish the next deadline before callbacks; busy also excludes recursive entry.
aer_poll_tick:
    cmp byte [rel audit_sec_test_active],0
    jne .return                           ; KAT cannot consume a real observation
    cmp dword [rel aer_poll_n],0
    je .return
    cmp byte [rel aer_poll_busy],0
    jne .return
    push rbx
    push r12
    push r13
    sub rsp,16
    mov byte [rel aer_poll_busy],1
    call aer_dma_tick
    call time_monotonic_now_us
    test rax,rax
    jz .done
    mov r12,rax
    mov rdx,[rel aer_poll_due]
    cmp rdx,-1
    je .done
    cmp rax,rdx
    jb .done
    add rax,AER_POLL_INTERVAL
    jnc .deadline
    mov rax,-1                            ; exhausted clock, never wrap/repeat
.deadline:
    mov [rel aer_poll_due],rax
    mov eax,[rel aer_poll_cursor]
    imul eax,AER_POLL_STRIDE
    lea rbx,[rel aer_poll_rows]
    add rbx,rax
    mov eax,[rel aer_poll_cursor]
    shl eax,7
    lea rdx,[rel aer_poll_coverage_rows]
    add rax,rdx
    mov [rsp],rax
    cmp qword [rax+AER_Q_ATTEMPTS],-1
    je .attempted
    inc qword [rax+AER_Q_ATTEMPTS]
.attempted:
    mov eax,[rel aer_poll_cursor]
    inc eax
    cmp eax,[rel aer_poll_n]
    jb .cursor
    xor eax,eax
.cursor:
    mov [rel aer_poll_cursor],eax
    cmp qword [rbx+AER_POLL_ATTEMPTS],-1
    je .read
    inc qword [rbx+AER_POLL_ATTEMPTS]
.read:
    mov edi,[rbx]
    lea rsi,[rel aer_poll_scratch]
    call pci_ecam_aer_snapshot
    mov [rbx+AER_POLL_STATUS],eax
    test eax,eax
    jnz .coverage_failed                 ; retain event data, census records failure
    mov r13,[rsp]
    mov eax,[rel aer_poll_scratch+8]
    or [r13+AER_Q_US],eax
    mov eax,[rel aer_poll_scratch+20]
    or [r13+AER_Q_CS],eax
    mov edi,[rbx]
    lea rsi,[rel aer_poll_coverage_scratch]
    call pci_ecam_aer_coverage_snapshot
    mov r13,[rsp]
    mov [r13+AER_Q_STATUS],eax
    test eax,eax
    jnz .coverage_refused
    mov eax,[rel aer_poll_coverage_scratch+8]
    or [r13+AER_Q_US],eax
    mov eax,[rel aer_poll_coverage_scratch+12]
    or [r13+AER_Q_CS],eax
    mov eax,[rel aer_poll_coverage_scratch+16]
    or [r13+AER_Q_RS],eax
    mov eax,[rel aer_poll_coverage_scratch+20]
    mov ecx,[rel aer_poll_coverage_scratch+24]
    mov edx,[rel aer_poll_coverage_scratch+28]
    cmp qword [r13+AER_Q_POLLS],0
    je .coverage_identity
    cmp eax,[r13+AER_Q_ROOT]
    jne .coverage_changed
    cmp ecx,[r13+AER_Q_TYPE]
    jne .coverage_changed
    cmp edx,[r13+AER_Q_ID]
    jne .coverage_changed
.coverage_identity:
    mov [r13+AER_Q_ROOT],eax
    mov [r13+AER_Q_TYPE],ecx
    mov [r13+AER_Q_ID],edx
    cmp ecx,4
    jne .coverage_not_root
    mov dword [r13+AER_Q_NOTIFY_ROOT],1
.coverage_not_root:
    cmp qword [r13+AER_Q_POLLS],-1
    je .coverage_clock
    inc qword [r13+AER_Q_POLLS]
.coverage_clock:
    ; Reuse the successful companion read. Initial root status is independent
    ; of US/CS and its later transitions must not borrow initial-error credit.
    mov eax,[rel aer_poll_coverage_scratch+16]
    cmp qword [rbx+AER_BOOT_ROOT_FLAGS],0
    jne .root_compare
    mov qword [rbx+AER_BOOT_ROOT_FLAGS],1
    cmp dword [r13+AER_Q_ROOT],0
    je .root_saved
    or qword [rbx+AER_BOOT_ROOT_FLAGS],2
    mov [rbx+AER_BOOT_ROOT_RAW],rax
    test eax,eax
    jz .root_saved
    mov edx,eax
    mov edi,5
    mov esi,[rbx]
    mov ecx,[r13+AER_Q_ID]
    mov r8d,1
    lea r9,[rel aer_boot_root_tag]
    call diag_ring_append
    cmp eax,1
    jne .root_drop
    mov qword [rbx+AER_BOOT_ROOT_COMMIT],1
    jmp .root_saved
.root_drop:
    mov qword [rbx+AER_BOOT_ROOT_DROP],1
    jmp .root_saved
.root_compare:
    cmp rax,[rbx+AER_BOOT_ROOT_RAW]
    je .root_saved
    or qword [rbx+AER_BOOT_ROOT_FLAGS],4
.root_saved:
    cmp qword [r13+AER_Q_FIRST],0
    jne .coverage_end
    mov [r13+AER_Q_FIRST],r12
.coverage_end:
    call time_monotonic_now_us
    mov [r13+AER_Q_LAST],rax
    jmp .sampled
.coverage_changed:
    mov dword [r13+AER_Q_STATUS],8
.coverage_refused:
    cmp qword [r13+AER_Q_FAILED],-1
    je .sampled
    inc qword [r13+AER_Q_FAILED]
.sampled:
    cmp qword [rbx+AER_BOOT_VALID],0
    jne .boot_saved
    lea rdi,[rbx+AER_BOOT_RAW]
    lea rsi,[rel aer_poll_scratch]
    mov ecx,8
    rep movsq
    mov qword [rbx+AER_BOOT_VALID],1
    mov eax,[rel aer_poll_scratch+8]
    or eax,[rel aer_poll_scratch+20]
    jz .boot_saved
    mov qword [rbx+AER_BOOT_COUNT],1
.boot_saved:
    mov [rbx+AER_POLL_SAMPLE_US],r12
    lea rsi,[rel aer_poll_scratch]
    lea rdi,[rbx+AER_POLL_PREVIOUS]
    test qword [rbx+AER_POLL_FLAGS],1
    jz .changed
    mov ecx,8
    repe cmpsq
    je .done
.changed:
    ; Error observations follow raw US/CS assertions, never mask, severity or
    ; header changes. A sticky bit remains the same error; a cleared bit can
    ; be observed asserted again. Keep the latest full raw sample separately.
    mov eax,[rel aer_poll_scratch+8]
    mov edx,[rel aer_poll_scratch+20]
    test qword [rbx+AER_POLL_FLAGS],1
    jz .new_status
    mov ecx,[rbx+AER_POLL_PREVIOUS+8]
    not ecx
    and eax,ecx
    mov ecx,[rbx+AER_POLL_PREVIOUS+20]
    not ecx
    and edx,ecx
.new_status:
    or eax,edx
    mov [rsp+8],eax
    ; Keep/log the first snapshot, but it cannot date firmware sticky status.
    ; Nonfatal needs a later raw US 0->1 edge; fatal-first remains contained.
    ; Mask/severity/header
    ; changes cannot turn old status into a newly observed hardware fault.
    mov dword [rbx+AER_POLL_ACTION],0
    test qword [rbx+AER_POLL_FLAGS],1
    jz .baseline
    lea r13,[rel aer_poll_scratch]
    mov eax,[r13+52]                      ; nonfatal unmasked
    test dword [r13+20],0x2000            ; Advisory Non-Fatal corrected status
    jz .with_fatal
    mov edx,eax
    and edx,0x100000
    or [rbx+AER_POLL_BLIND],edx           ; sticky ANFE cannot date this UR
    and eax,0xffefffff                    ; suppressed UR stays explicitly blind
.with_fatal:
    or eax,[r13+56]                       ; fatal is never advisory-suppressed
    mov edx,[rbx+AER_POLL_PREVIOUS+8]      ; previous raw US, not derived classes
    not edx
    and eax,edx
    mov [rbx+AER_POLL_ACTION],eax
    jmp .save_sample
.baseline:
    mov eax,[rel aer_poll_scratch+8]
    mov [rbx+AER_POLL_BLIND],eax
    mov eax,[rel aer_poll_scratch+56]      ; fatal-first remains fail-closed
    mov [rbx+AER_POLL_ACTION],eax
.save_sample:
    lea rsi,[rel aer_poll_scratch]
    lea rdi,[rbx+AER_POLL_PREVIOUS]
    mov ecx,8
    rep movsq
    or qword [rbx+AER_POLL_FLAGS],1
    cmp dword [rsp+8],0
    je .done                             ; raw metadata/clears are not new errors
    lea r13,[rel aer_poll_scratch]
    mov eax,[r13+8]                       ; raw US, including masked/reserved bits
    or eax,[r13+20]                       ; raw CS
    jz .done                             ; clear resets dedup, retains last event
    lea rdi,[rbx+AER_POLL_EVENT]
    mov rsi,r13
    mov ecx,8
    rep movsq
    or qword [rbx+AER_POLL_FLAGS],2
    mov [rbx+AER_POLL_EVENT_US],r12
    cmp qword [rbx+AER_POLL_COUNT],-1
    je .log
    inc qword [rbx+AER_POLL_COUNT]
.log:
    mov edi,5                            ; existing DIAG_K_AER, distinct poll tag
    mov esi,[rbx]                        ; packed segment0 BDF
    mov edx,[r13+48]                     ; unmasked corrected bitmap
    mov ecx,[r13+56]                     ; v2 B: fatal high32, nonfatal low32
    shl rcx,32
    mov eax,[r13+52]
    or rcx,rax
    mov r8,[rbx+AER_POLL_COUNT]           ; v2 C: exact software observation count
    lea r9,[rel aer_poll_tag]
    call diag_ring_append
    cmp qword [rbx+AER_POLL_COUNT],1
    jne .boot_joined
    cmp qword [rbx+AER_BOOT_COUNT],1
    jne .boot_joined
    cmp eax,1
    jne .boot_drop
    mov qword [rbx+AER_BOOT_COMMIT],1
    jmp .boot_joined
.boot_drop:
    mov qword [rbx+AER_BOOT_DROP],1
.boot_joined:
    test eax,eax
    jnz .notify
    cmp qword [rbx+AER_POLL_DROPS],-1
    je .notify
    inc qword [rbx+AER_POLL_DROPS]
.notify:
    mov rax,[rsp]
    cmp dword [rax+AER_Q_NOTIFY_ROOT],1
    jne .done                            ; endpoints/RCEC never enter old root containment
    cmp dword [rbx],255
    ja .done                             ; widened observation is never containment/Guardian
    ; Independent of diag admission. Baseline/corrected/masked observations do not
    ; enter this uncorrected notification source. Fence/stop precedes Guardian;
    ; the retained stop outcome remains distinct from actual DMA cessation.
    cmp dword [rbx+AER_POLL_ACTION],0
    je .notify_audit
    mov edi,[rbx]
    call aer_dma_before_stop
    mov edi,[rbx]
    call pci_contain_root_port
.notify_audit:
    mov edi,[rbx]
    mov esi,[r13+52]
    mov edx,[r13+56]
    mov rcx,r12
    call audit_sec_aer_event
    jmp .done
.coverage_failed:
    mov r13,[rsp]
    mov [r13+AER_Q_STATUS],eax
    cmp qword [r13+AER_Q_FAILED],-1
    je .done
    inc qword [r13+AER_Q_FAILED]
.done:
    mov byte [rel aer_poll_busy],0
    add rsp,16
    pop r13
    pop r12
    pop rbx
.return:
    ret

; Explicit new record grammar; retained previous-boot aer-poll stays readable.
; A=unmasked corrected, B=nonfatal|(fatal<<32), C=software count (not physical).
aer_poll_tag: db 'aer-poll-v2',0
aer_boot_root_tag: db 'aer-boot-root',0
%include "core/abi/wdata.inc"
%macro WDATA_aer_poll 0
alignb 8
aer_poll_state:
aer_poll_due:     resq 1
aer_poll_n:       resd 1
aer_poll_cursor:  resd 1
aer_poll_busy:    resq 1
aer_poll_scratch: resb 64
aer_poll_coverage_scratch: resb 64
aer_poll_rows:    resb AER_POLL_N * AER_POLL_STRIDE
alignb 64
aer_poll_coverage_rows: resb AER_POLL_N * AER_Q_STRIDE
aer_poll_state_end:
%endmacro
WDATA_BSS_DEFER WDATA_aer_poll
