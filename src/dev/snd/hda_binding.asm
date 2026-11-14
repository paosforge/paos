;; MODULE dev/snd/hda_binding
;; LAYER 3
;; EXPORTS hda_binding_begin, hda_binding_next, hda_binding_reply, hda_binding_abort, hda_binding_capture_timeout
;; IMPORTS boot/native_driver_gate, dev/snd/hda_codec
;; CAPS
;; OWNER saga:audio
%include "boot/native_driver_gate.inc"
; RCQ-36 C1: controller-owned secondary-codec recovery around the S2 walker.
; Policy ports Classic's skip-failed-codec behavior, with explicit primary
; protection and a verified shared-transport reset before every fresh walk.
; Include after hda_codec.asm. Private trusted driver API; no public pointers.
;
; Caller fills discovery*, reset_fn*, reset_arg*. reset_fn(RDI=reset_arg) must
; cooperatively stop command DMA, verify controller/ring reset, drain stale
; replies and reinitialize transport cursors BEFORE returning 0. Return 1
; pending or -1 failure, with bounded work per call and its own time deadline.
; It must preserve SysV nonvolatile registers, never allocate/reenter, never
; silently replace the controller, and leave stream DMA safely stopped.
; There are also at most 4096 reset polls here. This helper does not certify
; physical reset from register-shaped host memory: its owner supplies proof.
;
; begin schedules initial reset. next returns 0 verb / 1 waiting / 2 DONE /
; 3 resetting / -1 error. reply returns 0 consumed / 3 resetting / -1 error.
; Wrong-stage reply/command-timeout calls are refused without changing state.
; Consumers MUST gate inventory use on stage DONE; -1 alone is not a latch.
; A global abort always latches FAILED/revokes, except an already sticky FAILED.
; abort(reason=1 per-command timeout, 2 controller-wide transport fault) may
; skip only a secondary command timeout, NEVER a controller-wide fault.
; Only an invalid root vendor response (0 / FFFFFFFF) is skippable topology;
; malformed node ranges, capacity/input errors remain fatal for every codec.
; Failed inventories have all counts revoked immediately. No reads/SETs while
; resetting. A skip is committed only AFTER reset succeeds, before re-begin.
; Original STATESTS, caller-selected primary, mask and reasons survive retries.
; Initial attempt + at most 14 secondary skips; no memory allocation anywhere.
; Caller serializes calls; begin only on a fresh/retired context, not mid-DMA.

HDB_WALK       equ 1
HDB_RESET      equ 2
HDB_DONE       equ 3
HDB_FAILED     equ 4
HDB_RESETTING  equ 3
HDB_E_INPUT    equ 1
HDB_E_RESET    equ 2
HDB_E_CODEC    equ 3
HDB_E_GLOBAL   equ 4
HDB_SKIP_VENDOR equ 1
HDB_SKIP_TIMEOUT equ 2

struc hda_binding
  .discovery:    resq 1
  .reset_fn:     resq 1
  .reset_arg:    resq 1
  .snapshot:     resd 1
  .primary:      resd 1
  .active_mask:  resd 1
  .skipped_mask: resd 1
  .stage:        resd 1
  .error:        resd 1
  .reset_polls:  resd 1
  .attempts:     resd 1
  .failed_codec: resd 1
  .failed_reason: resd 1
  .last_verb:    resd 1
  .skip_reason:  resd 15
endstruc

; begin(RDI=binding, ESI=STATESTS, EDX=explicit primary codec) -> 0/-1.
hda_binding_begin:
    NATIVE_DRIVER_REFUSE 7
    mov dword [rdi + hda_binding.error], 0
    mov dword [rdi + hda_binding.skipped_mask], 0
    mov dword [rdi + hda_binding.attempts], 0
    mov dword [rdi + hda_binding.reset_polls], 0
    mov dword [rdi + hda_binding.failed_codec], -1
    mov dword [rdi + hda_binding.failed_reason], 0
    mov dword [rdi + hda_binding.last_verb], 0
    xor ecx, ecx
.clear:
    mov dword [rdi + hda_binding.skip_reason + rcx*4], 0
    inc ecx
    cmp ecx, 15
    jb .clear
    and esi, 0x7FFF
    mov [rdi + hda_binding.snapshot], esi
    mov [rdi + hda_binding.active_mask], esi
    mov [rdi + hda_binding.primary], edx
    cmp qword [rdi + hda_binding.discovery], 0
    je .invalid
    call hdb_revoke
    cmp qword [rdi + hda_binding.reset_fn], 0
    je .invalid
    cmp edx, 15
    jae .invalid
    bt esi, edx
    jnc .invalid
    mov dword [rdi + hda_binding.stage], HDB_RESET
    xor eax, eax
    ret
.invalid:
    mov eax, HDB_E_INPUT
    jmp hdb_fatal

; next(RDI=binding, RSI=out_verb*) preserves out_verb unless 0 returned.
hda_binding_next:
    push rbx
    push r12
    sub rsp, 8
    mov rbx, rdi
    mov r12, rsi
    cmp dword [rbx + hda_binding.stage], HDB_RESET
    je .reset
    cmp dword [rbx + hda_binding.stage], HDB_DONE
    je .done
    cmp dword [rbx + hda_binding.stage], HDB_WALK
    jne .error
    mov rdi, [rbx + hda_binding.discovery]
    call hda_codec_next
    test eax, eax
    js .codec_error
    cmp eax, HDAC_DONE
    je .complete
    test eax, eax
    jnz .out
    mov eax, [r12]
    mov [rbx + hda_binding.last_verb], eax
    xor eax, eax
    jmp .out
.reset:
    inc dword [rbx + hda_binding.reset_polls]
    cmp dword [rbx + hda_binding.reset_polls], 4096
    ja .reset_error
    mov rdi, [rbx + hda_binding.reset_arg]
    call [rbx + hda_binding.reset_fn]
    test eax, eax
    jz .reset_ok
    cmp eax, 1
    jne .reset_error
    mov eax, HDB_RESETTING
    jmp .out
.reset_ok:
    mov ecx, [rbx + hda_binding.failed_codec]
    cmp ecx, -1
    je .begin_walk
    ; A committed skip always follows the verified reset boundary.
    btr dword [rbx + hda_binding.active_mask], ecx
    bts dword [rbx + hda_binding.skipped_mask], ecx
    mov eax, [rbx + hda_binding.failed_reason]
    mov [rbx + hda_binding.skip_reason + rcx*4], eax
.begin_walk:
    inc dword [rbx + hda_binding.attempts]
    cmp dword [rbx + hda_binding.attempts], 15
    ja .reset_error
    mov rdi, [rbx + hda_binding.discovery]
    mov esi, [rbx + hda_binding.active_mask]
    call hda_codec_begin
    test eax, eax
    js .codec_error
    mov dword [rbx + hda_binding.failed_codec], -1
    mov dword [rbx + hda_binding.failed_reason], 0
    mov dword [rbx + hda_binding.stage], HDB_WALK
    ; No command emitted on the same call that completes a reset.
    mov eax, HDB_RESETTING
    jmp .out
.complete:
    mov dword [rbx + hda_binding.stage], HDB_DONE
.done:
    mov eax, HDAC_DONE
    jmp .out
.reset_error:
    mov eax, HDB_E_RESET
    jmp .fatal
.codec_error:
    mov eax, HDB_E_CODEC
.fatal:
    mov rdi, rbx
    call hdb_fatal
    jmp .out
.error:
    mov rax, -1
.out:
    add rsp, 8
    pop r12
    pop rbx
    ret

; reply(RDI=binding, ESI=attributed S1 response).
hda_binding_reply:
    push rbx
    push r12
    sub rsp, 8
    mov rbx, rdi
    cmp dword [rbx + hda_binding.stage], HDB_WALK
    jne .error
    mov rdi, [rbx + hda_binding.discovery]
    mov r12d, [rdi + hda_discovery.phase]
    call hda_codec_reply
    test eax, eax
    jns .out
    ; Only root-vendor rejection can use Classic's topology skip policy.
    cmp r12d, HDAC_VENDOR
    jne .fatal
    mov rdi, [rbx + hda_binding.discovery]
    cmp dword [rdi + hda_discovery.error], HDAC_E_TOPO
    jne .fatal
    mov esi, HDB_SKIP_VENDOR
    mov rdi, rbx
    call hdb_skip
    jmp .out
.fatal:
    mov rdi, rbx
    mov eax, HDB_E_CODEC
    call hdb_fatal
    jmp .out
.error:
    mov rax, -1
.out:
    add rsp, 8
    pop r12
    pop rbx
    ret

; Reason 1 requires an outstanding attributed command. Reason 2 (or unknown)
; is controller-wide: revoke even after DONE or during a pending reset. A
; previously latched failure preserves its first error and diagnostics.
hda_binding_abort:
    cmp dword [rdi + hda_binding.stage], HDB_FAILED
    je .error
    cmp esi, 1
    jne .global
    cmp dword [rdi + hda_binding.stage], HDB_WALK
    jne .error
    mov r8, [rdi + hda_binding.discovery]
    cmp dword [r8 + hda_discovery.waiting], 1
    jne .invalid
    mov esi, HDB_SKIP_TIMEOUT
    jmp hdb_skip
.invalid:
    mov eax, HDB_E_INPUT
    jmp hdb_fatal
.global:
    mov eax, HDB_E_GLOBAL
    jmp hdb_fatal
.error:
    mov rax, -1
    ret

; RDI=binding, ESI=skip reason; only current present secondary is eligible.
hdb_skip:
    mov r8, [rdi + hda_binding.discovery]
    mov ecx, [r8 + hda_discovery.codec]
hdb_skip_codec:
    cmp ecx, 15
    jae .bad
    cmp ecx, [rdi + hda_binding.primary]
    je .bad
    bt dword [rdi + hda_binding.active_mask], ecx
    jnc .bad
    mov [rdi + hda_binding.failed_codec], ecx
    mov [rdi + hda_binding.failed_reason], esi
    call hdb_revoke
    mov dword [rdi + hda_binding.reset_polls], 0
    mov dword [rdi + hda_binding.stage], HDB_RESET
    mov eax, HDB_RESETTING
    ret
.bad:
    mov eax, HDB_E_CODEC
    jmp hdb_fatal

; Revocation must precede any pending reset, and invalidates whole inventory.
; Preserve ESI/EDX so begin/skip can use their original arguments.
hdb_revoke:
    mov r8, [rdi + hda_binding.discovery]
    test r8, r8
    jz .out
    mov dword [r8 + hda_discovery.codec_count], 0
    mov dword [r8 + hda_discovery.group_count], 0
    mov dword [r8 + hda_discovery.widget_count], 0
    mov dword [r8 + hda_discovery.waiting], 0
    mov dword [r8 + hda_discovery.phase], HDAC_FAILED
.out:
    ret

hdb_fatal:
    ; Public entry points stop touching hardware on failure. The owner must
    ; still reset/stop transport before retirement; memory is never released.
    mov [rdi + hda_binding.error], eax
    call hdb_revoke
    mov dword [rdi + hda_binding.stage], HDB_FAILED
    mov rax, -1
    ret

; hda_binding_capture_timeout(RDI=binding, ESI=codec) ->3 reset scheduled/-1.
; Private session-owner entry after discovery DONE. Owner proves this is the
; sole queued capture command's response timeout in the same controller epoch.
; Reuse identical secondary eligibility/verified-reset skip policy. Never call
; for CORB busy, global fault, unqueued command, or an unattributed response.
hda_binding_capture_timeout:
    cmp dword [rdi + hda_binding.stage], HDB_DONE
    jne .error
    mov ecx, esi
    mov esi, HDB_SKIP_TIMEOUT
    jmp hdb_skip_codec
.error:
    mov rax, -1
    ret
