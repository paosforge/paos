;; MODULE gui/img/img_viewer_sequence
;; LAYER 6
;; EXPORTS img_viewer_sequence
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; Image Viewer admitted-ID sequence and caller-clock slideshow state.
; Actual creator: rc-ai-claude on OpenAI Codex.
;
; RDI -> immutable little-endian request96, all fields u64:
;   state0, binding8, expectedRevision16, ids24, count32, index40,
;   op48, options56, now64, interval72, reserved80/88 (zero).
; EAX=0/RDX=revision on success; EAX=2/RDX=0 on refusal (no writes).
; CLOSE succeeds with revision0. Preserves flags, DF and nonvolatile GPRs.
;
; State80 (caller-owned, initially ALL zero): magic0, binding8, revision16,
; borrowedIds24, count32, index40, selectedId48, deadline56, interval64,
; flags72 (bit0 playing, bit1 loop). Every span must be mapped, nonwrapping;
; state80 excludes full request96 and used ids[count]*8. Read-only aliases
; between request and IDs are allowed. Slack is never accessed or changed.
;
; OPEN=0: expected/now/interval=0, unique nonzero full64 IDs (1..4096),
; index<count, options0/1=loop. IDs stay alive and immutable until CLOSE.
; Caller assigns a distinct nonzero binding to each lifetime. Binding and
; revision detect stale caller results, not authority or concurrent access.
; Later ops require fresh binding/revision and ids/count/index/options=0;
; request interval=0 except START. All state/IDs validated before publication.
; Freshness is checked BEFORE following the borrowed IDs pointer.
;
; NEXT=1/PREVIOUS=2: clamp or wrap; changed selection restarts a running
; interval from now. START=3: interval>0, rearm now+interval. PAUSE=4.
; TICK=5: paused/early are noops; due advances at most one, scheduling from
; now (no catch-up burst). Nonloop final photo stops after its own interval.
; CLOSE=6: clear exactly80 bytes, including at maximum revision.
; All actual non-CLOSE changes increment revision, refusing at UINT64_MAX;
; noops preserve bytes/revision even at MAX. All deadline additions checked.
; Caller supplies monotonic unsigned now in interval units; no clock reads,
; rollback detection, allocation, decoding, timer, rendering, UI or file IO.

img_viewer_sequence:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 96
    xor eax, eax
%assign ivs_z 0
%rep 12
    mov [rsp+ivs_z], rax
%assign ivs_z ivs_z+8
%endrep
    mov rbp, rdi
    test rbp, rbp
    jz .bad
    mov rax, rbp
    add rax, 96
    jc .bad
    mov rbx, [rbp]
    test rbx, rbx
    jz .bad
    mov rcx, rbx
    add rcx, 80
    jc .bad
    cmp rax, rbx
    jbe .request_disjoint
    cmp rbp, rcx
    jb .bad
.request_disjoint:
    cmp qword [rbp+8], 0
    je .bad
    mov r15, [rbp+48]
    cmp r15, 6
    ja .bad
    mov rax, [rbp+80]
    or rax, [rbp+88]
    jnz .bad
    test r15, r15
    jz .open

    mov rax, [rbp+24]
    or rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+56]
    jnz .bad
    cmp r15, 3
    je .step_interval_ok
    cmp qword [rbp+72], 0
    jne .bad
.step_interval_ok:
    mov rax, 0x31305756534f4150 ; PAOSVW01
    cmp [rbx], rax
    jne .bad
    mov rax, [rbp+8]
    cmp [rbx+8], rax
    jne .bad
    mov rax, [rbp+16]
    test rax, rax
    jz .bad
    cmp [rbx+16], rax
    jne .bad
    mov r12, [rbx+24]
    mov r13, [rbx+32]
    mov r14, [rbx+40]
    cmp qword [rbx+72], 3
    ja .bad
    test byte [rbx+72], 1
    jnz .playing_state
    mov rax, [rbx+56]
    or rax, [rbx+64]
    jnz .bad
    jmp .copy_state
.playing_state:
    mov rax, [rbx+64]
    test rax, rax
    jz .bad
    cmp [rbx+56], rax
    jb .bad
.copy_state:
%assign ivs_c 0
%rep 10
    mov rax, [rbx+ivs_c]
    mov [rsp+ivs_c], rax
%assign ivs_c ivs_c+8
%endrep
    jmp .validate_ids

.open:
    mov rax, [rbp+16]
    or rax, [rbp+64]
    or rax, [rbp+72]
    jnz .bad
    cmp qword [rbp+56], 1
    ja .bad
    xor ecx, ecx
.zero_state:
    cmp qword [rbx+rcx*8], 0
    jne .bad
    inc ecx
    cmp ecx, 10
    jb .zero_state
    mov r12, [rbp+24]
    mov r13, [rbp+32]
    mov r14, [rbp+40]

.validate_ids:
    test r12, r12
    jz .bad
    test r13, r13
    jz .bad
    cmp r13, 4096
    ja .bad
    cmp r14, r13
    jae .bad
    lea rax, [r13*8]
    add rax, r12
    jc .bad
    cmp rax, rbx
    jbe .ids_disjoint
    lea rcx, [rbx+80] ; state end was already checked
    cmp r12, rcx
    jb .bad
.ids_disjoint:
    xor r8d, r8d
.id_outer:
    mov r10, [r12+r8*8]
    test r10, r10
    jz .bad
    xor r9d, r9d
.id_inner:
    cmp r9, r8
    jae .id_next
    cmp [r12+r9*8], r10
    je .bad
    inc r9
    jmp .id_inner
.id_next:
    inc r8
    cmp r8, r13
    jb .id_outer
    mov rax, [r12+r14*8]
    test r15, r15
    jz .open_publish
    cmp [rsp+48], rax
    jne .bad
    cmp r15, 1
    je .next
    cmp r15, 2
    je .previous
    cmp r15, 3
    je .start
    cmp r15, 4
    je .pause
    cmp r15, 5
    je .tick
    ; CLOSE: validated state and borrowed list; no revision increment.
    xor eax, eax
%assign ivs_c 0
%rep 10
    mov [rsp+ivs_c], rax
%assign ivs_c ivs_c+8
%endrep
    jmp .publish

.open_publish:
    mov [rsp+48], rax
    mov rax, 0x31305756534f4150
    mov [rsp], rax
    mov rax, [rbp+8]
    mov [rsp+8], rax
    mov qword [rsp+16], 1
    mov [rsp+24], r12
    mov [rsp+32], r13
    mov [rsp+40], r14
    mov rax, [rbp+56]
    shl rax, 1
    mov [rsp+72], rax
    jmp .publish

.next:
    lea rax, [r14+1]
    cmp rax, r13
    jb .navigate
    test byte [rsp+72], 2
    jz .noop
    xor eax, eax
    jmp .navigate
.previous:
    mov rax, r14
    test rax, rax
    jnz .decrement
    test byte [rsp+72], 2
    jz .noop
    mov rax, r13
.decrement:
    dec rax
.navigate:
    cmp rax, r14
    je .noop
    mov [rsp+40], rax
    mov rax, [r12+rax*8]
    mov [rsp+48], rax
    test byte [rsp+72], 1
    jz .changed
    jmp .reschedule

.start:
    mov rax, [rbp+72]
    test rax, rax
    jz .bad
    mov [rsp+64], rax
    or qword [rsp+72], 1
    jmp .reschedule
.pause:
    test byte [rsp+72], 1
    jz .noop
.stop:
    mov qword [rsp+56], 0
    mov qword [rsp+64], 0
    and qword [rsp+72], -2
    jmp .changed
.tick:
    test byte [rsp+72], 1
    jz .noop
    mov rax, [rbp+64]
    cmp rax, [rsp+56]
    jb .noop
    lea rax, [r14+1]
    cmp rax, r13
    jb .tick_select
    test byte [rsp+72], 2
    jz .stop
    xor eax, eax
.tick_select:
    mov [rsp+40], rax
    mov rax, [r12+rax*8]
    mov [rsp+48], rax
.reschedule:
    mov rax, [rbp+64]
    add rax, [rsp+64]
    jc .bad
    mov [rsp+56], rax
.changed:
    cmp qword [rsp+16], -1
    je .bad
    inc qword [rsp+16]
.publish:
%assign ivs_c 0
%rep 10
    mov rax, [rsp+ivs_c]
    mov [rbx+ivs_c], rax
%assign ivs_c ivs_c+8
%endrep
.noop:
    mov rdx, [rsp+16]
    xor eax, eax
    jmp .done
.bad:
    mov eax, 2
    xor edx, edx
.done:
    xor r11d, r11d
%assign ivs_z 0
%rep 12
    mov [rsp+ivs_z], r11
%assign ivs_z ivs_z+8
%endrep
    add rsp, 96
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret
