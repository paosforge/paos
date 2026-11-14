;; MODULE dev/snd/hda_transport
;; LAYER 3
;; EXPORTS hda_corb_queue, hda_rirb_take
;; IMPORTS
;; CAPS mmio dma
;; OWNER saga:audio
; Optional sole-controller power fence. Zero leaves ordinary audio unchanged.
; Hook is trusted kernel-only, serialized by the native controller owner.
%macro HDA_TRANSPORT_POWER 0
 cmp qword [rel hda_transport_power_gate],0
 je %%admit
 push rdi
 push rsi
 push rdx
 push rcx
 push r8
 push r9
 push r10
 push r11
 sub rsp,8
 call [rel hda_transport_power_gate]
 add rsp,8
 pop r11
 pop r10
 pop r9
 pop r8
 pop rcx
 pop rdx
 pop rsi
 pop rdi
 test rax,rax
 jz %%admit
 mov rax,-1
 ret
%%admit:
%endmacro

; RCQ-36 S1: port of Classic hda_send_verb's CORB/RIRB data path.
; Source: Classic 0cabd75f8653ae3f8778ad0af51469a4f20adf25, paos.asm
; hda_send_verb; identical extracted body at v0.7.74 / 5e92a7e8313d46e12bc55ed50c4a2d3e16b5cc4a.
;
; The future controller backend owns this context and serializes ALL calls.
; Before use: reset rings, select 256-entry sizes, install valid mapped DMA
; buffers, start CORB/RIRB, then zero this software state. mmio/corb/rirb are
; trusted driver-owned VAs; this API is private, never a user-pointer boundary.
; No allocation, hardware discovery, registration, or boot call in this slice.
;
; Classic's increment/mask/store/doorbell and RIRB increment/mask/read sequence
; are retained. Queue and receive are split so a stalled codec cannot monopolize
; the cooperative scheduler. One outstanding command per controller; no retry
; after a deadline until the owning backend stops DMA and resets the transport.
; Controller internal RIRB FIFO overrun (RIRBOIS) latches fault until reset.
; DMA-ring lapping is NOT reported by this bit: keep unsolicited responses
; disabled unless the owner services by interrupt counts fast enough to prevent
; lapping. Lost solicited entries remain pending until the owner's deadline.
; No sound capability/health claim is made by these helpers.

HDA_XFER_OK      equ 0
HDA_XFER_PENDING equ 1
HDA_XFER_ERROR   equ -1
HDAT_CORBWP     equ 0x48
HDAT_CORBRP     equ 0x4A
HDAT_RIRBWP     equ 0x58
HDAT_RIRBSTS    equ 0x5D

struc hda_transport
  .mmio:       resq 1
  .corb:       resq 1
  .rirb:       resq 1
  .corb_wp:    resd 1
  .rirb_rp:    resd 1
  .pending:    resd 1
  .codec:      resd 1
  .discarded:  resd 1
  .fault:      resd 1
endstruc

; hda_corb_queue(RDI=context, ESI=packed verb) -> RAX 0 queued, 1 busy, -1 fault.
; Caller must not enqueue again on busy; it drains/waits at its next service
; tick. A codec address 15 broadcast is unsupported (no unambiguous reply).
; Clobbers RAX, RCX, RDX, R8-R10. Busy/invalid-codec paths change no state.
; An observed overrun changes only the sticky fault flag.
hda_corb_queue:
 HDA_TRANSPORT_POWER
    cmp dword [rdi + hda_transport.fault], 0
    jne .error
    mov eax, esi
    shr eax, 28
    cmp eax, 15
    jae .error
    cmp dword [rdi + hda_transport.pending], 0
    jne .busy
    mov r8, [rdi + hda_transport.mmio]
    test byte [r8 + HDAT_RIRBSTS], 4
    jnz .overrun
    mov r10d, eax                       ; expected responder, including codec 0
    mov eax, [rdi + hda_transport.corb_wp]
    inc eax
    and eax, 0xFF                      ; Classic wrap at 256 entries
    movzx ecx, word [r8 + HDAT_CORBRP]
    and ecx, 0xFF
    cmp eax, ecx
    je .busy_full                       ; never advance WP onto RP (which would look empty)
    mov r9, [rdi + hda_transport.corb]
    mov [r9 + rax*4], esi
    mov [rdi + hda_transport.corb_wp], eax
    mov [rdi + hda_transport.codec], r10d
    mov dword [rdi + hda_transport.pending], 1
    sfence                              ; DMA command visible before doorbell
    mov [r8 + HDAT_CORBWP], ax
    mov eax, HDA_XFER_OK
    ret
.overrun:
    mov dword [rdi + hda_transport.fault], 1
.error:
    mov rax, HDA_XFER_ERROR
    ret
.busy_full:
.busy:
    mov eax, HDA_XFER_PENDING
    ret

; hda_rirb_take(RDI=context, RSI=out_response*) -> RAX 0 complete, 1 pending,
; -1 fault/no command. *out_response changes ONLY for a solicited response from
; the pending codec. Zero is a valid response, distinct from pending/failure.
; Wrong-codec, unsolicited and reserved-bit entries are drained and counted.
; This does not detect DMA-ring lapping; no software RIRB RP register exists.
; At most 256 entries per service call, even if hardware keeps advancing WP.
; Clobbers RAX, RCX, RDX, R8-R11. The owner supplies deadline/recovery policy.
hda_rirb_take:
 HDA_TRANSPORT_POWER
    cmp dword [rdi + hda_transport.fault], 0
    jne .error
    cmp dword [rdi + hda_transport.pending], 0
    je .error
    mov r8, [rdi + hda_transport.mmio]
    mov r9, [rdi + hda_transport.rirb]
    mov ecx, 256
.next:
    test byte [r8 + HDAT_RIRBSTS], 4
    jnz .overrun
    movzx eax, word [r8 + HDAT_RIRBWP]
    and eax, 0xFF
    mov edx, [rdi + hda_transport.rirb_rp]
    cmp eax, edx
    je .pending
    inc edx
    and edx, 0xFF
    mov [rdi + hda_transport.rirb_rp], edx
    lfence                              ; observe DMA entry after hardware WP
    mov r10d, [r9 + rdx*8]               ; Classic response dword
    mov r11d, [r9 + rdx*8 + 4]           ; codec/unsolicited metadata (new)
    test r11d, 0xFFFFFFE0
    jnz .discard_reserved
    test r11d, 0x10
    jnz .discard_unsolicited
    and r11d, 0xF
    cmp r11d, [rdi + hda_transport.codec]
    jne .discard_codec
.accept_response:
    ; A concurrent hardware overrun invalidates attribution even when the
    ; candidate entry looked valid. Never publish it as successful completion.
    test byte [r8 + HDAT_RIRBSTS], 4
    jnz .overrun
    mov [rsi], r10d
    mov dword [rdi + hda_transport.pending], 0
    ; RINTCNT=1 stops further CORB fetch until the consumed response is ACKed.
    ; Byte W1C of RINTFL only: never clear a concurrent overrun (bit2).
    mov byte [r8 + HDAT_RIRBSTS], 1
    mov eax, HDA_XFER_OK
    ret
.discard_reserved:
.discard_unsolicited:
.discard_codec:
    inc dword [rdi + hda_transport.discarded]
    ; An ignored response consumed a response-count credit too. Preserve the
    ; pending command and its deadline while allowing the next response.
    mov byte [r8 + HDAT_RIRBSTS], 1
    dec ecx
    jnz .next
.pending:
    mov eax, HDA_XFER_PENDING
    ret
.overrun:
    mov dword [rdi + hda_transport.fault], 1
.error:
    mov rax, HDA_XFER_ERROR
    ret

%macro WDATA_hda_transport_power 0
 align 8
hda_transport_power_gate: dq 0
%endmacro
%ifmacro WDATA_DEFER 1
 WDATA_DEFER WDATA_hda_transport_power
%else
 section .data
 WDATA_hda_transport_power
 section .text
%endif
