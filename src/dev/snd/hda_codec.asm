;; MODULE dev/snd/hda_codec
;; LAYER 3
;; EXPORTS hda_codec_begin, hda_codec_next, hda_codec_reply, hda_codec_abort
;; IMPORTS
;; CAPS
;; OWNER saga:audio
; RCQ-36 S2: port Classic hda_init STATESTS/root/AFG/widget discovery.
; Classic 0cabd75f8653ae3f8778ad0af51469a4f20adf25, paos.asm:26347-26645.
; Extend its read-only parameter sequence and retain packed verbs; replace first-codec/
; last-AFG globals with caller-owned inventory and cooperative request/reply.
; Hardware field facts: Intel HDA rev1.0a 7.1.1, 7.3.4.1-4/6/9/11,
; 7.3.4.7/8 (PCM rates/sizes and stream formats), 7.3.3.31 (pin default). No Linux driver implementation is used.
;
; Private API: pointers/capacities are trusted, stable driver-owned buffers.
; The caller serializes all calls and owns the only command transport. Begin
; is legal only on a fresh context or after the transport has stopped/reset;
; it does not cancel a hardware command. Fill buffer pointers/capacities first.
; next emits one read verb and marks it awaiting reply. Retain that verb while
; CORB is busy; reply only after S1 attributed completion. Abort on timeout or
; transport fault, then reset the transport before any new begin.
; Inventory is provisional until next returns DONE; discard it on any error.
; No allocation, MMIO, SET verb, route selection, sound registration or health
; claim. Indirect NID addressing (>=128) is explicitly unsupported and refused.
; At most 15 codecs * 127 non-root direct NIDs, with one read per next/reply.

HDAC_READ      equ 0
HDAC_WAIT      equ 1
HDAC_DONE      equ 2
HDAC_ERROR     equ -1
HDAC_E_INPUT   equ 1
HDAC_E_TOPO    equ 2
HDAC_E_SPACE   equ 3
HDAC_E_XFER    equ 4
HDAC_VENDOR    equ 1
HDAC_REVISION  equ 2
HDAC_ROOT      equ 3
HDAC_FG_TYPE   equ 4
HDAC_FG_NODES  equ 5
HDAC_WCAP      equ 6
HDAC_PIN_CAP   equ 7
HDAC_PIN_CFG   equ 8
HDAC_CONN_LEN  equ 9
HDAC_PCM       equ 10
HDAC_STREAMS   equ 11
HDAC_FINISHED  equ 12
HDAC_FAILED    equ 13

struc hda_discovery
  .codecs:        resq 1
  .groups:        resq 1
  .widgets:       resq 1
  .codec_cap:     resd 1
  .group_cap:     resd 1
  .widget_cap:    resd 1
  .codec_count:   resd 1
  .group_count:   resd 1
  .widget_count:  resd 1
  .mask:          resd 1
  .phase:         resd 1
  .waiting:       resd 1
  .codec:         resd 1
  .fg_nid:        resd 1
  .fg_end:        resd 1
  .widget_nid:    resd 1
  .widget_end:    resd 1
  .active_codec:  resd 1
  .active_group:  resd 1
  .active_widget: resd 1
  .error:         resd 1
  .seen:          resb 32             ; current codec's unique NIDs (root/FG/widget)
endstruc

struc hda_codec_info                   ; 32 bytes
  .address:       resd 1
  .vendor:        resd 1
  .revision:      resd 1
  .group_start:   resd 1
  .group_count:   resd 1             ; root's total FG count (includes non-audio)
  .audio_groups:  resd 1
  .first_group:   resd 1             ; index in audio-group array
  .reserved:      resd 1
endstruc

struc hda_group_info                   ; 24 bytes
  .codec:         resd 1
  .nid:           resd 1
  .widget_start:  resd 1
  .widget_count:  resd 1
  .first_widget:  resd 1             ; index in widget array
  .reserved:      resd 1
endstruc

struc hda_widget_info                  ; 32 bytes
  .codec:         resd 1
  .group:         resd 1
  .nid:           resd 1
  .caps:          resd 1
  .pin_caps:      resd 1             ; converter union: effective raw PCM mask
  .config:        resd 1             ; converter union: effective stream mask
  .conn_len:      resd 1             ; raw low byte: long-form bit + 7-bit count
  .reserved:      resd 1
endstruc

; Type-tagged union, only widget types0/1 use these aliases. The old pin
; fields remain unchanged for pins. Read both parameters from this converter
; when Format Override is set, otherwise its scoped AFG. Zero is a valid raw
; observation, never replaced with invented defaults. Publish only on DONE.
hda_widget_info.pcm equ hda_widget_info.pin_caps
hda_widget_info.streams equ hda_widget_info.config

; begin(RDI=context, ESI=STATESTS snapshot) -> 0 initialized, -1 invalid buffers.
; All functions preserve RBX/RBP/R12-R15; clobber volatile registers only.
hda_codec_begin:
    mov dword [rdi + hda_discovery.codec_count], 0
    mov dword [rdi + hda_discovery.group_count], 0
    mov dword [rdi + hda_discovery.widget_count], 0
    mov dword [rdi + hda_discovery.waiting], 0
    mov dword [rdi + hda_discovery.error], 0
    ; A zero-capacity buffer may be null; space refusal occurs before a write.
    cmp dword [rdi + hda_discovery.codec_cap], 0
    je .groups
    cmp qword [rdi + hda_discovery.codecs], 0
    je .input_fault
.groups:
    cmp dword [rdi + hda_discovery.group_cap], 0
    je .widgets
    cmp qword [rdi + hda_discovery.groups], 0
    je .input_fault
.widgets:
    cmp dword [rdi + hda_discovery.widget_cap], 0
    je .ready
    cmp qword [rdi + hda_discovery.widgets], 0
    je .input_fault
.ready:
    and esi, 0x7FFF                    ; Classic STATESTS codec bits 0..14 only
    mov [rdi + hda_discovery.mask], esi
    jmp hdac_select_codec
.input_fault:
    mov eax, HDAC_E_INPUT
    jmp hdac_fault

; next(RDI=context, RSI=out_verb*) -> 0 read emitted, 1 waiting, 2 done, -1 fault.
; out_verb changes only when a command is emitted. No command may be reissued
; from this API while awaiting reply; an unqueued verb remains owned by caller.
hda_codec_next:
    cmp dword [rdi + hda_discovery.phase], HDAC_FAILED
    jae .error
    cmp dword [rdi + hda_discovery.waiting], 0
    jne .wait
    mov ecx, [rdi + hda_discovery.phase]
    cmp ecx, HDAC_FINISHED
    je .done
    mov eax, [rdi + hda_discovery.codec]
    shl eax, 28
    xor edx, edx
    cmp ecx, HDAC_VENDOR
    je .vendor
    cmp ecx, HDAC_REVISION
    je .revision
    cmp ecx, HDAC_ROOT
    je .nodes
    mov edx, [rdi + hda_discovery.fg_nid]
    shl edx, 20
    cmp ecx, HDAC_FG_TYPE
    je .fg_type
    cmp ecx, HDAC_FG_NODES
    je .nodes
    mov edx, [rdi + hda_discovery.widget_nid]
    shl edx, 20
    cmp ecx, HDAC_WCAP
    je .wcap
    cmp ecx, HDAC_PIN_CAP
    je .pin_cap
    cmp ecx, HDAC_PIN_CFG
    je .pin_cfg
    cmp ecx, HDAC_PCM
    je .formats
    cmp ecx, HDAC_STREAMS
    je .formats
    cmp ecx, HDAC_CONN_LEN
    jne .error
    or eax, 0xF000E
    jmp .emit
.formats:
    mov r9d, [rdi + hda_discovery.active_widget]
    shl r9, 5
    add r9, [rdi + hda_discovery.widgets]
    test dword [r9 + hda_widget_info.caps], 0x10
    jnz .format_node
    mov edx, [rdi + hda_discovery.fg_nid]
    shl edx, 20
.format_node:
    or eax, 0xF000A
    cmp ecx, HDAC_PCM
    je .emit
    inc eax
    jmp .emit
.vendor:
    or eax, 0xF0000
    jmp .emit
.revision:
    or eax, 0xF0002
    jmp .emit
.nodes:
    or eax, 0xF0004
    jmp .emit
.fg_type:
    or eax, 0xF0005
    jmp .emit
.wcap:
    or eax, 0xF0009
    jmp .emit
.pin_cap:
    or eax, 0xF000C
    jmp .emit
.pin_cfg:
    or eax, 0xF1C00
.emit:
    or eax, edx
    mov [rsi], eax
    mov dword [rdi + hda_discovery.waiting], 1
    xor eax, eax
    ret
.wait:
    mov eax, HDAC_WAIT
    ret
.done:
    mov eax, HDAC_DONE
    ret
.error:
    mov rax, HDAC_ERROR
    ret

; reply(RDI=context, ESI=attributed response) -> 0 consumed, -1 refusal/fault.
; A zero response is valid except the root vendor ID. Transport errors MUST
; call abort instead, never fake a zero-valued codec reply.
hda_codec_reply:
    cmp dword [rdi + hda_discovery.phase], HDAC_FAILED
    jae .error
    cmp dword [rdi + hda_discovery.waiting], 1
    jne .error
    mov dword [rdi + hda_discovery.waiting], 0
    mov ecx, [rdi + hda_discovery.phase]
    cmp ecx, HDAC_VENDOR
    je .vendor
    cmp ecx, HDAC_REVISION
    je .revision
    cmp ecx, HDAC_ROOT
    je .root
    cmp ecx, HDAC_FG_TYPE
    je .fg_type
    cmp ecx, HDAC_FG_NODES
    je .fg_nodes
    cmp ecx, HDAC_WCAP
    je .wcap
    ; These phases refer to the widget already appended at WCAP.
    mov eax, [rdi + hda_discovery.active_widget]
    shl rax, 5
    add rax, [rdi + hda_discovery.widgets]
    mov r8, rax
    cmp ecx, HDAC_PCM
    je .pcm
    cmp ecx, HDAC_STREAMS
    je .streams
    cmp ecx, HDAC_PIN_CAP
    je .pin_cap
    cmp ecx, HDAC_PIN_CFG
    je .pin_cfg
    cmp ecx, HDAC_CONN_LEN
    jne .bad_topology
    and esi, 0xFF                      ; keep long-form bit (Classic lost it)
    mov [r8 + hda_widget_info.conn_len], esi
    jmp hdac_advance_widget
.vendor:
    test esi, esi
    jz .bad_topology
    cmp esi, -1
    je .bad_topology
    mov eax, [rdi + hda_discovery.codec_count]
    cmp eax, [rdi + hda_discovery.codec_cap]
    jae .capacity_fault
    mov [rdi + hda_discovery.active_codec], eax
    inc dword [rdi + hda_discovery.codec_count]
    shl rax, 5
    add rax, [rdi + hda_discovery.codecs]
    mov r8, rax
    mov qword [r8], 0
    mov qword [r8 + 8], 0
    mov qword [r8 + 16], 0
    mov qword [r8 + 24], 0
    mov eax, [rdi + hda_discovery.codec]
    mov [r8 + hda_codec_info.address], eax
    mov [r8 + hda_codec_info.vendor], esi
    mov eax, [rdi + hda_discovery.group_count]
    mov [r8 + hda_codec_info.first_group], eax
    mov dword [rdi + hda_discovery.phase], HDAC_REVISION
    jmp .ok
.revision:
    mov eax, [rdi + hda_discovery.active_codec]
    shl rax, 5
    add rax, [rdi + hda_discovery.codecs]
    mov [rax + hda_codec_info.revision], esi
    mov dword [rdi + hda_discovery.phase], HDAC_ROOT
    jmp .ok
.root:
    call hdac_decode_range               ; EDX=start, ECX=end, EAX=count
    jc .bad_topology
    mov [rdi + hda_discovery.fg_nid], edx
    mov [rdi + hda_discovery.fg_end], ecx
    mov r9d, eax
    mov eax, [rdi + hda_discovery.active_codec]
    shl rax, 5
    add rax, [rdi + hda_discovery.codecs]
    mov [rax + hda_codec_info.group_start], edx
    mov [rax + hda_codec_info.group_count], r9d
    cmp edx, ecx
    je hdac_select_codec
    ; Reserve all root FG nodes, including modem/vendor groups, before any
    ; widget walk. Widgets must never alias root or another FG/widget.
.reserve_fg:
    bts dword [rdi + hda_discovery.seen], edx
    inc edx
    cmp edx, ecx
    jb .reserve_fg
    mov dword [rdi + hda_discovery.phase], HDAC_FG_TYPE
    jmp .ok
.fg_type:
    and esi, 0xFF
    cmp esi, 1                         ; Classic Audio Function Group type
    jne hdac_advance_group
    mov eax, [rdi + hda_discovery.group_count]
    cmp eax, [rdi + hda_discovery.group_cap]
    jae .capacity_fault
    mov [rdi + hda_discovery.active_group], eax
    inc dword [rdi + hda_discovery.group_count]
    imul rax, hda_group_info_size
    add rax, [rdi + hda_discovery.groups]
    mov r8, rax
    mov qword [r8], 0
    mov qword [r8 + 8], 0
    mov qword [r8 + 16], 0
    mov eax, [rdi + hda_discovery.codec]
    mov [r8 + hda_group_info.codec], eax
    mov eax, [rdi + hda_discovery.fg_nid]
    mov [r8 + hda_group_info.nid], eax
    mov eax, [rdi + hda_discovery.widget_count]
    mov [r8 + hda_group_info.first_widget], eax
    mov eax, [rdi + hda_discovery.active_codec]
    shl rax, 5
    add rax, [rdi + hda_discovery.codecs]
    inc dword [rax + hda_codec_info.audio_groups]
    mov dword [rdi + hda_discovery.phase], HDAC_FG_NODES
    jmp .ok
.fg_nodes:
    call hdac_decode_range
    jc .bad_topology
    mov [rdi + hda_discovery.widget_nid], edx
    mov [rdi + hda_discovery.widget_end], ecx
    mov r9d, eax
    add eax, [rdi + hda_discovery.widget_count]
    cmp eax, [rdi + hda_discovery.widget_cap]
    ja .capacity_fault
    mov eax, [rdi + hda_discovery.active_group]
    imul rax, hda_group_info_size
    add rax, [rdi + hda_discovery.groups]
    mov [rax + hda_group_info.widget_start], edx
    mov [rax + hda_group_info.widget_count], r9d
    cmp edx, ecx
    je hdac_advance_group
    ; A finite <=127-bit walk, performed once per audio FG. Partial marks on
    ; refusal are harmless: FAILED inventories are never published or reused.
.reserve_widget:
    bts dword [rdi + hda_discovery.seen], edx
    jc .bad_topology
    inc edx
    cmp edx, ecx
    jb .reserve_widget
    mov dword [rdi + hda_discovery.phase], HDAC_WCAP
    jmp .ok
.wcap:
    mov eax, [rdi + hda_discovery.widget_count]
    ; Capacity was reserved for this entire FG before its first WCAP.
    mov [rdi + hda_discovery.active_widget], eax
    inc dword [rdi + hda_discovery.widget_count]
    shl rax, 5
    add rax, [rdi + hda_discovery.widgets]
    mov r8, rax
    mov qword [r8], 0
    mov qword [r8 + 8], 0
    mov qword [r8 + 16], 0
    mov qword [r8 + 24], 0
    mov eax, [rdi + hda_discovery.codec]
    mov [r8 + hda_widget_info.codec], eax
    mov eax, [rdi + hda_discovery.fg_nid]
    mov [r8 + hda_widget_info.group], eax
    mov eax, [rdi + hda_discovery.widget_nid]
    mov [r8 + hda_widget_info.nid], eax
    mov [r8 + hda_widget_info.caps], esi
    mov eax, esi
    shr eax, 20
    and eax, 15
    cmp eax, 1
    jbe .converter
    cmp eax, 4
    jne hdac_after_pin
    mov dword [rdi + hda_discovery.phase], HDAC_PIN_CAP
    jmp .ok
.converter:
    mov dword [rdi + hda_discovery.phase], HDAC_PCM
    jmp .ok
.pcm:
    mov [r8 + hda_widget_info.pcm], esi
    mov dword [rdi + hda_discovery.phase], HDAC_STREAMS
    jmp .ok
.streams:
    mov [r8 + hda_widget_info.streams], esi
    jmp hdac_after_pin
.pin_cap:
    mov [r8 + hda_widget_info.pin_caps], esi
    mov dword [rdi + hda_discovery.phase], HDAC_PIN_CFG
    jmp .ok
.pin_cfg:
    mov [r8 + hda_widget_info.config], esi
    jmp hdac_after_pin
.bad_topology:
    mov eax, HDAC_E_TOPO
    jmp hdac_fault
.capacity_fault:
    mov eax, HDAC_E_SPACE
    jmp hdac_fault
.ok:
    xor eax, eax
    ret
.error:
    mov rax, HDAC_ERROR
    ret

; abort(RDI=context) -> -1, sticky transport fault. Idempotent; preserves an
; earlier, more specific fault rather than overwriting its diagnostic cause.
hda_codec_abort:
    cmp dword [rdi + hda_discovery.phase], HDAC_FAILED
    je .error
    mov eax, HDAC_E_XFER
    jmp hdac_fault
.error:
    mov rax, HDAC_ERROR
    ret

; Private transitions. No callbacks, scheduler calls or unbounded polling.
hdac_fault:
    mov [rdi + hda_discovery.error], eax
    mov dword [rdi + hda_discovery.waiting], 0
    mov dword [rdi + hda_discovery.phase], HDAC_FAILED
    mov rax, HDAC_ERROR
    ret

hdac_select_codec:
    mov eax, [rdi + hda_discovery.mask]
    test eax, eax
    jz .done
    bsf eax, eax
    btr dword [rdi + hda_discovery.mask], eax
    mov [rdi + hda_discovery.codec], eax
    mov qword [rdi + hda_discovery.seen], 1 ; reserve root NID 0
    mov qword [rdi + hda_discovery.seen + 8], 0
    mov qword [rdi + hda_discovery.seen + 16], 0
    mov qword [rdi + hda_discovery.seen + 24], 0
    mov dword [rdi + hda_discovery.phase], HDAC_VENDOR
    xor eax, eax
    ret
.done:
    mov dword [rdi + hda_discovery.phase], HDAC_FINISHED
    xor eax, eax
    ret

hdac_advance_group:
    inc dword [rdi + hda_discovery.fg_nid]
    mov eax, [rdi + hda_discovery.fg_nid]
    cmp eax, [rdi + hda_discovery.fg_end]
    jae hdac_select_codec
    mov dword [rdi + hda_discovery.phase], HDAC_FG_TYPE
    xor eax, eax
    ret

hdac_after_pin:
    mov eax, [rdi + hda_discovery.active_widget]
    shl rax, 5
    add rax, [rdi + hda_discovery.widgets]
    test dword [rax + hda_widget_info.caps], 0x100
    jz hdac_advance_widget
    mov dword [rdi + hda_discovery.phase], HDAC_CONN_LEN
    xor eax, eax
    ret

hdac_advance_widget:
    inc dword [rdi + hda_discovery.widget_nid]
    mov eax, [rdi + hda_discovery.widget_nid]
    cmp eax, [rdi + hda_discovery.widget_end]
    jae hdac_advance_group
    mov dword [rdi + hda_discovery.phase], HDAC_WCAP
    xor eax, eax
    ret

; Decode SUBNODE as two 8-bit fields, not Classic's 16-bit halves.
; ESI=response -> EAX=count, EDX=start, ECX=exclusive end, CF=invalid.
; Reserved bits ignored per spec. Nonempty direct-node ranges are 1..127;
; no wrap, root aliases or undefined indirect addressing. Empty ranges do not
; address any node, so their start field is retained but never dereferenced.
hdac_decode_range:
    mov edx, esi
    shr edx, 16
    and edx, 0xFF
    mov eax, esi
    and eax, 0xFF
    mov ecx, edx
    test eax, eax
    jz .ok
    test edx, edx
    jz .bad
    add ecx, eax
    cmp ecx, 128
    ja .bad
.ok:
    clc
    ret
.bad:
    stc
    ret
