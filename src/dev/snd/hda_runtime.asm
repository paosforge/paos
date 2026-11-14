;; MODULE dev/snd/hda_runtime
;; LAYER 3
;; EXPORTS hda_probe_terminal, hda_probe_power_guard, hda_probe_controller_busy, hda_probe_guest_claim, hda_probe_tone, hda_probe_init_at, hda_probe_error, hda_probe_stage, hda_probe_generate
;; IMPORTS boot/native_driver_gate, dev/snd/hda_loopback_native, dev/snd/hda_transport, dev/snd/hda_codec, dev/snd/hda_output, bus/pci, boot/paging, boot/serial, core/time, core/dma
;; CAPS mmio dma
;; OWNER saga:audio
%include "boot/native_driver_gate.inc"
; RCQ-36 S4: explicit, foreground bring-up probe; NOT snd_ops or metal acceptance.
; Port Classic hda_detect/hda_init and hda_playback: pinned 0cabd75f8653ae3f8778ad0af51469a4f20adf25.
; Intel HDA rev1.0a controller 3.3/4.5, verbs 7.3. No GPL implementation input.
; One BSP command caller, interrupts never touch this controller. No auto-play.
; QEMU-only diagnostic: CPUID hypervisor gate precedes PCI/MMIO/DMA activity.
; One controller, Intel/AMD class 040300/040380; direct QEMU (vendor 1af4) pin->DAC only.
; Native codec quirks/indirect paths, secondary-codec masking and snd_ops follow.
; Every polling loop has a monotonic deadline AND a finite iteration ceiling.
; DMA allocation is once-only; retained forever, including all failures. Explicit
; replay resets the whole exclusively owned controller before reusing contexts.
; RCQ-36 S5b (root L12913 F1): the buffer is core/dma tag 1, the HDA-only VT-d
; DID 3. Allocation, the domain attach and its receipt happen while the
; controller is held in reset, and no DMA address register is written unless
; the receipt says state=ok; a replay needs the same map serial. A refusal
; (no enforcing IOMMU, AMD, any precondition) keeps CRST=0: no native audio.
; Controller session has a 2s budget, plus the finite PCI scan; foreground
; diagnostic only. Production playback must be cooperative.

%macro HDAR_CHECK 0
    test rax, rax
    js hdar_init_fail
%endmacro

; Private init_at(RDI=trusted mapped 4KiB MMIO VA), after PCI ownership/mapping.
; Callers MUST gate CPUID.1:ECX[31] before this ungated MMIO/DMA seam.
; Host model calls this same consumer without executing PCI port IO.
hda_probe_init_at:
    cmp dword [rel hdar_terminal_latched],0
    jne hdart_denied
    call hdarf_new_attempt         ; invalidate historical failure observation
    NATIVE_DRIVER_REFUSE 7
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    mov dword [rel hda_probe_error], 0
    mov dword [rel hda_probe_stage], 1
    mov rax, [rel hdar_mmio]
    test rax, rax
    jz .same_controller
    cmp rax, rbx
    je .same_controller
    ; The original controller may still DMA after a failed reset request.
    ; Never reuse its pinned storage on another controller or touch that BAR.
    mov dword [rel hda_probe_error], 7
    mov rax, -1
    jmp hdar_init_out
.same_controller:
    mov [rel hdar_mmio], rbx
    cmp qword [rel tsc_khz], 0
    je hdar_init_fail
    call time_monotonic_now_us
    add rax, 2000000
    jc hdar_init_fail
    mov [rel hdar_overall_deadline], rax
    ; Disable interrupts and unsolicited delivery. All native streams are ours.
    mov dword [rbx + 0x20], 0
    mov word [rbx + 0x0C], 0
    mov byte [rbx + 0x4C], 0
    mov byte [rbx + 0x5C], 0
    and dword [rbx + 8], 0xFFFFFEFE ; clear CRST + UNSOL
    lea rdi, [rbx + 8]
    mov esi, 1
    xor edx, edx
    call hdar_wait32
    HDAR_CHECK
    ; Stage 6, inside reset (CRST=0 read back): DID 3 before any DMA register.
    mov dword [rel hda_probe_stage], 6
    cmp qword [rel hdar_dma], 0
    jne .domain_replay
    mov edi, 131072
    mov esi, 1                          ; core/dma DMA_DOM_HDA
    call dma_alloc_domain
    test rax, rax
    jz .domain_refused
    mov [rel hdar_dma], rax             ; pinned and tagged even if refused below
    mov edi, [rel hdar_bdf]
    mov rsi, rbx
    mov edx, 1
    call dma_domain_attach
    test eax, eax
    jnz .domain_refused
    mov edi, 1
    call dma_domain_receipt
    test eax, eax
    jz .domain_line_fail
    mov [rel hdar_map_serial], rdx
    jmp .domain_ok
.domain_replay:
    mov edi, 1
    call dma_domain_receipt
    test eax, eax
    jz .domain_line_fail
    cmp rdx, [rel hdar_map_serial]      ; the mapping the first attach proved
    jne .domain_line_fail
.domain_ok:
    mov rdi, rsi
    call serial_string
    call serial_newline
    mov dword [rel hda_probe_stage], 1
    ; HDA requires >=100 us in reset, >=521 us after deassertion.
    mov edi, 100
    call hdar_delay
    HDAR_CHECK
    or dword [rbx + 8], 1
    lea rdi, [rbx + 8]
    mov esi, 1
    mov edx, 1
    call hdar_wait32
    HDAR_CHECK
    mov edi, 1000
    call hdar_delay
    HDAR_CHECK
    movzx eax, word [rbx + 0x0E]
    and eax, 0x7FFF
    mov [rel hdar_statests], eax
    jz hdar_init_fail
    mov dword [rel hda_probe_stage], 2
    ; Fixed-size 256-entry rings are required by S1. Cap bits are read-only.
    test byte [rbx + 0x4E], 0x40
    jz hdar_init_fail
    test byte [rbx + 0x5E], 0x40
    jz hdar_init_fail
    mov r12, [rel hdar_dma]
    mov rax, r12
    add rax, 131071
    jc hdar_init_fail
    test word [rbx], 1
    jnz .address_ok
    shr rax, 32
    jnz hdar_init_fail
.address_ok:
    mov rdi, r12
    xor eax, eax
    mov ecx, 131072/8
    rep stosq
    lea rdi, [rel hdar_output]
    xor eax, eax
    mov ecx, hda_output_size/8
    rep stosq
    lea rdi, [rel hdar_output]
    mov [rdi + hda_output.mmio], rbx
    mov eax, [rel hdar_pci_id]
    mov [rdi + hda_output.pci_id], rax
    lea rax, [r12 + 0x2000]
    mov [rdi + hda_output.bdl], rax
    mov [rdi + hda_output.bdl_dma], rax
    lea rax, [r12 + 0x4000]
    mov [rdi + hda_output.pcm], rax
    mov [rdi + hda_output.pcm_dma], rax
    lea rax, [r12 + 0x3000]
    mov [rdi + hda_output.position], rax
    mov [rdi + hda_output.position_dma], rax
    mov qword [rdi + hda_output.timeout], 100000
    mov dword [rdi + hda_output.mmio_bytes], 4096
    mov dword [rdi + hda_output.bdl_bytes], 64
    mov dword [rdi + hda_output.pcm_bytes], 16384
    mov dword [rdi + hda_output.position_bytes], 256
    mov esi, 48000
    mov edx, 2
    mov ecx, 1
    call hda_output_bind                 ; BEFORE command DMA/global DPLBASE
    HDAR_CHECK
    ; CORB and RIRB registers. Never write PCI Status (W1C) back to itself.
    mov byte [rbx + 0x4E], 2
    mov byte [rbx + 0x5E], 2
    mov rax, r12
    mov [rbx + 0x40], eax
    shr rax, 32
    mov [rbx + 0x44], eax
    lea rax, [r12 + 0x1000]
    mov [rbx + 0x50], eax
    shr rax, 32
    mov [rbx + 0x54], eax
    mov word [rbx + 0x4A], 0x8000
    lea rdi, [rbx + 0x4A]
    mov esi, 0x8000
    mov edx, 0x8000
    call hdar_wait16
    HDAR_CHECK
    mov word [rbx + 0x4A], 0
    lea rdi, [rbx + 0x4A]
    mov esi, 0x8000
    xor edx, edx
    call hdar_wait16
    HDAR_CHECK
    mov word [rbx + 0x48], 0
    mov word [rbx + 0x58], 0x8000       ; RIRBWP reset is write-one self-clearing
    mov word [rbx + 0x5A], 1
    mov byte [rbx + 0x4D], 1            ; CORBSTS CMEI W1C
    mov byte [rbx + 0x5D], 5            ; RIRBSTS response/overrun W1C
    lea rdi, [rbx + 0x58]
    mov esi, 0x80FF
    xor edx, edx
    call hdar_wait16
    HDAR_CHECK
    lea rdi, [rbx + 0x4D]
    mov esi, 1
    xor edx, edx
    call hdar_wait8
    HDAR_CHECK
    lea rdi, [rbx + 0x5D]
    mov esi, 4
    xor edx, edx
    call hdar_wait8
    HDAR_CHECK
    lea rdi, [rel hdar_transport]
    xor eax, eax
    mov ecx, hda_transport_size/8
    rep stosq
    lea rdi, [rel hdar_transport]
    mov [rdi + hda_transport.mmio], rbx
    mov [rdi + hda_transport.corb], r12
    lea rax, [r12 + 0x1000]
    mov [rdi + hda_transport.rirb], rax
    sfence
    ; Response status locally enabled; INTCTL stays masked (polled transport).
    mov byte [rbx + 0x5C], 3
    mov byte [rbx + 0x4C], 2
    lea rdi, [rbx + 0x4C]
    mov esi, 2
    mov edx, 2
    call hdar_wait8
    HDAR_CHECK
    lea rdi, [rbx + 0x5C]
    mov esi, 2
    mov edx, 2
    call hdar_wait8
    HDAR_CHECK
    mov dword [rel hda_probe_stage], 3
    lea rdi, [rel hdar_discovery]
    lea rax, [rel hdar_codecs]
    mov [rdi + hda_discovery.codecs], rax
    lea rax, [rel hdar_groups]
    mov [rdi + hda_discovery.groups], rax
    lea rax, [rel hdar_widgets]
    mov [rdi + hda_discovery.widgets], rax
    mov dword [rdi + hda_discovery.codec_cap], 15
    mov dword [rdi + hda_discovery.group_cap], 127*15
    mov dword [rdi + hda_discovery.widget_cap], 127*15
    mov esi, [rel hdar_statests]
    call hda_codec_begin
    HDAR_CHECK
.discover:
    lea rdi, [rel hdar_discovery]
    lea rsi, [rel hdar_verb]
    call hda_codec_next
    cmp eax, HDAC_DONE
    je .discovered
    test eax, eax
    jnz hdar_init_fail
    mov edi, [rel hdar_verb]
    call hdar_command
    HDAR_CHECK
    lea rdi, [rel hdar_discovery]
    mov esi, [rel hdar_reply]
    call hda_codec_reply
    HDAR_CHECK
    jmp .discover
.discovered:
    mov dword [rel hda_probe_stage], 4
    call hdar_route
    HDAR_CHECK
    call time_monotonic_now_us
    mov rsi, rax
    lea rdi, [rel hdar_output]
    call hda_output_prepare
    HDAR_CHECK
    mov r14d, 1000000
.prepare:
    dec r14d
    jz hdar_init_fail
    call time_monotonic_now_us
    mov rsi, rax
    lea rdi, [rel hdar_output]
    call hda_output_service
    test rax, rax
    js hdar_init_fail
    jz .ready
    call hdar_budget
    HDAR_CHECK
    jmp .prepare
.ready:
    mov edi, [rel hdar_output + hda_output.sd_index]
    shl edi, 5
    lea rdi, [rbx + rdi + 0x83]
    mov esi, 0x1C
    xor edx, edx
    call hdar_wait8
    HDAR_CHECK
    lea rdi, [rel hdar_ready_msg]
    call serial_string
    xor eax, eax
    jmp hdar_init_out
.domain_refused:
    mov edi, 1
    call dma_domain_receipt             ; the reason line, for the operator
.domain_line_fail:
    mov rdi, rsi
    call serial_string
    call serial_newline
    jmp hdar_init_fail                  ; stage 6; CRST stays 0, no DMA register written
hdar_init_fail:
    mov eax, [rel hda_probe_stage]
    mov [rel hda_probe_error], eax
    ; Stop requests only; DMA storage remains pinned even if reset never ACKs.
    mov byte [rbx + 0x4C], 0
    mov byte [rbx + 0x5C], 0
    and dword [rbx + 8], 0xFFFFFEFE
    mov eax,1                     ; original init-failure boundary
    call hdarf_capture             ; passive readback; original result unchanged
    mov rax, -1
hdar_init_out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Width-specific polling: use each register's defined byte/word/dword width.
; RDI=register, ESI=mask, EDX=expected. 100ms and iteration ceilings.
hdar_wait8:
    mov ecx, 1
    jmp hdar_wait_bits
hdar_wait16:
    mov ecx, 2
    jmp hdar_wait_bits
hdar_wait32:
    mov ecx, 4
hdar_wait_bits:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov ebx, ecx
    mov r12, rdi
    mov r13d, esi
    mov r14d, edx
    call time_monotonic_now_us
    lea r15, [rax + 100000]
    mov ecx, 1000000
.loop:
    push rcx
    call time_monotonic_now_us
    pop rcx
    cmp rax, r15
    jae .bad
    cmp rax, [rel hdar_overall_deadline]
    jae .bad
    cmp ebx, 1
    je .read8
    cmp ebx, 2
    je .read16
    mov eax, [r12]
    jmp .loaded
.read8:
    movzx eax, byte [r12]
    jmp .loaded
.read16:
    movzx eax, word [r12]
.loaded:
    and eax, r13d
    cmp eax, r14d
    je .ok
    pause
    dec ecx
    jnz .loop
.bad:
    mov rax, -1
    jmp .out
.ok:
    xor eax, eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

hdar_delay:
    push r12
    push r13
    mov r12, rdi
    call time_monotonic_now_us
    add r12, rax
    mov r13d, 1000000
.loop:
    call hdar_budget
    test rax, rax
    js .out
    call time_monotonic_now_us
    cmp rax, r12
    jae .ok
    pause
    dec r13d
    jnz .loop
    mov rax, -1
    jmp .out
.ok:
    xor eax, eax
.out:
    pop r13
    pop r12
    ret
hdar_budget:
    call time_monotonic_now_us
    cmp rax, [rel hdar_overall_deadline]
    jae .bad
    xor eax, eax
    ret
.bad:
    mov rax, -1
    ret

; Single serialized command; zero is a legal response. Error/timeout poisons
; this session; no same-command retry or new discovery until controller reset.
hdar_command:
    cmp dword [rel hdar_terminal_latched],0
    jne hdart_denied
    push r12
    push r13
    push r14
    mov r12d, edi
    mov [rel hdar_verb], edi
    call time_monotonic_now_us
    lea r13, [rax + 100000]
    mov r14d, 1000000
.queue:
    call hdar_command_guard
    test rax, rax
    js .out
    lea rdi, [rel hdar_transport]
    mov esi, r12d
    call hda_corb_queue
    test rax, rax
    js .out
    jz .take
    pause
    jmp .queue
.take:
    call hdar_command_guard
    test rax, rax
    js .out
    lea rdi, [rel hdar_transport]
    lea rsi, [rel hdar_reply]
    call hda_rirb_take
    test rax, rax
    js .out
    jz .out
    pause
    jmp .take
.out:
    pop r14
    pop r13
    pop r12
    ret
hdar_command_guard:
    cmp dword [rel hdar_terminal_latched],0
    jne .bad
    dec r14d
    jz .bad
    mov rax, [rel hdar_mmio]
    test byte [rax + 0x4D], 1
    jnz .bad
    call time_monotonic_now_us
    cmp rax, r13
    jae .bad
    cmp rax, [rel hdar_overall_deadline]
    jae .bad
    xor eax, eax
    ret
.bad:
    mov rax, -1
    ret

; A deliberately bounded direct-path first proof. Never guess a DAC or program
; hardware outside the discovered same-codec/same-AFG connection. QEMU only.
hdar_route:
    push rbx
    push r12
    push r13
    push r14
    push r15
    xor r12d, r12d
.pin:
    cmp r12d, [rel hdar_discovery + hda_discovery.widget_count]
    jae .bad
    mov eax, r12d
    shl eax, 5
    lea rbx, [rel hdar_widgets]
    add rbx, rax
    mov eax, [rbx + hda_widget_info.caps]
    shr eax, 20
    and eax, 15
    cmp eax, 4
    jne .next
    test dword [rbx + hda_widget_info.pin_caps], 0x10
    jz .next
    mov eax, [rbx + hda_widget_info.config]
    shr eax, 30
    cmp eax, 1
    je .next
    cmp dword [rbx + hda_widget_info.conn_len], 1 ; short, one direct connection
    jne .next
    mov r13d, [rbx + hda_widget_info.codec]
    ; Require an inventoried QEMU codec, never a guessed physical board route.
    xor ecx, ecx
.vendor:
    cmp ecx, [rel hdar_discovery + hda_discovery.codec_count]
    jae .next
    mov eax, ecx
    shl eax, 5
    lea rdx, [rel hdar_codecs]
    add rdx, rax
    cmp [rdx + hda_codec_info.address], r13d
    je .vendor_found
    inc ecx
    jmp .vendor
.vendor_found:
    mov eax, [rdx + hda_codec_info.vendor]
    shr eax, 16
    cmp eax, 0x1AF4
    jne .next
    shl r13d, 28
    mov eax, [rbx + hda_widget_info.nid]
    shl eax, 20
    or r13d, eax                       ; pin command prefix
    mov edi, r13d
    or edi, 0xF0200
    call hdar_command
    test rax, rax
    js .bad
    mov r14d, [rel hdar_reply]
    and r14d, 255
    test r14d, 0x80
    jnz .next
    test r14d, r14d
    jz .next
    xor r15d, r15d
.dac:
    cmp r15d, [rel hdar_discovery + hda_discovery.widget_count]
    jae .next
    mov eax, r15d
    shl eax, 5
    lea rdx, [rel hdar_widgets]
    add rdx, rax
    cmp [rdx + hda_widget_info.nid], r14d
    jne .dac_next
    mov eax, [rbx + hda_widget_info.codec]
    cmp [rdx + hda_widget_info.codec], eax
    jne .dac_next
    mov eax, [rbx + hda_widget_info.group]
    cmp [rdx + hda_widget_info.group], eax
    jne .dac_next
    mov eax, [rdx + hda_widget_info.caps]
    and eax, 0xF00001
    cmp eax, 1                        ; stereo output converter
    je .path
.dac_next:
    inc r15d
    jmp .dac
.next:
    inc r12d
    jmp .pin
.path:
    mov [rel hdar_pin], r13d
    mov eax, r13d
    and eax, 0xF0000000
    shl r14d, 20
    or r14d, eax
    mov [rel hdar_dac], r14d
    mov eax, [rbx + hda_widget_info.codec]
    shl eax, 28
    mov ecx, [rbx + hda_widget_info.group]
    shl ecx, 20
    or eax, ecx
    mov [rel hdar_group], eax
    or eax, 0x70500                    ; AFG D0
    mov edi, eax
    call hdar_command
    test rax, rax
    js .bad
    ; Require 48 kHz and 16-bit PCM before setting the converter.
    mov eax, r15d
    shl eax, 5
    lea rdx, [rel hdar_widgets]
    add rdx, rax
    mov r15, rdx
    mov edi, r14d
    test dword [r15 + hda_widget_info.caps], 0x10 ; format override
    jnz .pcm_node
    mov edi, [rel hdar_group]
.pcm_node:
    mov [rel hdar_format_node], edi
    or edi, 0xF000A
    call hdar_command
    test rax, rax
    js .bad
    mov eax, [rel hdar_reply]
    and eax, 0x20040
    cmp eax, 0x20040
    jne .bad
    mov edi, [rel hdar_format_node]
    or edi, 0xF000B
    call hdar_command
    test rax, rax
    js .bad
    test dword [rel hdar_reply], 1
    jz .bad
    ; Power control only on widgets that advertise it.
    mov rdi, r15
    mov esi, r14d
    call hdar_widget_power_amp
    test rax, rax
    js .bad
    mov rdi, rbx
    mov esi, r13d
    call hdar_widget_power_amp
    test rax, rax
    js .bad
    mov edi, r14d
    or edi, 0x20011
    call hdar_command
    test rax, rax
    js .bad
    mov edi, r14d
    or edi, 0x70610
    call hdar_command
    test rax, rax
    js .bad
    mov edi, r13d
    or edi, 0x70740
    call hdar_command
    test rax, rax
    js .bad
    test dword [rbx + hda_widget_info.pin_caps], 0x10000
    jz .verify
    mov edi, r13d
    or edi, 0x70C02
    call hdar_command
    test rax, rax
    js .bad
.verify:
    mov edi, r14d
    or edi, 0xA0000
    call hdar_command
    test rax, rax
    js .bad
    cmp dword [rel hdar_reply], 0x11
    jne .bad
    mov edi, r14d
    or edi, 0xF0600
    call hdar_command
    test rax, rax
    js .bad
    cmp dword [rel hdar_reply], 0x10
    jne .bad
    mov edi, r13d
    or edi, 0xF0700
    call hdar_command
    test rax, rax
    js .bad
    cmp dword [rel hdar_reply], 0x40
    jne .bad
    xor eax, eax
    jmp .out
.bad:
    mov rax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; widget ptr RDI/prefix ESI. Gain=0dB capability offset, clamped to numsteps;
; amp override determines node-vs-AFG capability. No universal max-gain guess.
hdar_widget_power_amp:
    push r12
    push r13
    mov r12, rdi
    mov r13d, esi
    test dword [r12 + hda_widget_info.caps], 0x400
    jz .amp
    mov edi, r13d
    or edi, 0x70500
    call hdar_command
    test rax, rax
    js .out
.amp:
    test dword [r12 + hda_widget_info.caps], 4
    jz .ok
    mov edi, r13d
    test dword [r12 + hda_widget_info.caps], 8
    jnz .amp_node
    mov edi, [rel hdar_group]
.amp_node:
    or edi, 0xF0012
    call hdar_command
    test rax, rax
    js .out
    mov eax, [rel hdar_reply]
    mov ecx, eax
    and eax, 127
    shr ecx, 8
    and ecx, 127
    cmp eax, ecx
    cmova eax, ecx
    or eax, 0x3B000
    or eax, r13d
    mov edi, eax
    call hdar_command
    jmp .out
.ok:
    xor eax, eax
.out:
    pop r13
    pop r12
    ret

; Public explicit probe: native PCI discovery, reset, route, one 0.5s tone.
; This QEMU-only diagnostic observes DMA fetch, not codec presentation. The
; QEMU8.2 timer codec retains up to8192 bytes separately from the HDA ring;
; RUNclear disables that consumer. Fetch8192 additional silent bytes before
; halt so the complete tone crosses that queue while the voice is active.
; Same2s session/pump/refill bounds and verified RUNclear; no metal latency
; promise. PCM generation/reference stays exactly24000 frames, no replay.
HDAR_TONE_BYTES       equ 96000
HDAR_CODEC_DRAIN_BYTES equ 8192
; Existing foreground diagnostic, distinct from loopback-native and guest owners.
; Trusted96B RDI, original serialized BSP/IF0 terminal caller. RAM-only guard;
; no policy/PCI/MMIO reads, no stop/reset/cleanup and no ownership transfer.
; RAX0 means ONLY this original diagnostic has no retained lifetime/work.
; RAX-1 refuses before effect. Even STOPPED9/FAILED10 retains DMA custody;
; successful foreground return never independently proved terminal closure.
; Sticky guest claim is exported HISTORY, not native I/O ownership/work.
hda_probe_power_guard:
    pushfq
    pop r11
    shr r11d,9
    and r11d,1
    mov dword [rdi],1
    mov dword [rdi+4],-1
    mov dword [rdi+8],3
    mov dword [rdi+12],3             ; original globals and embedded contexts read
    xor r9d,r9d
    xor eax,eax
    cmp qword [rel hdar_mmio],0
    setne al
    mov [rdi+24],eax
    shl eax,0
    or r9d,eax
    xor eax,eax
    cmp qword [rel hdar_dma],0
    setne al
    mov [rdi+28],eax
    shl eax,1
    or r9d,eax
    xor eax,eax
    cmp qword [rel hdar_map_serial],0
    setne al
    mov [rdi+32],eax
    shl eax,2
    or r9d,eax
    xor eax,eax
    cmp qword [rel hdar_transport + hda_transport.mmio],0
    setne al
    mov [rdi+36],eax
    shl eax,3
    or r9d,eax
    xor eax,eax
    cmp qword [rel hdar_transport + hda_transport.corb],0
    setne al
    mov [rdi+40],eax
    shl eax,4
    or r9d,eax
    xor eax,eax
    cmp qword [rel hdar_transport + hda_transport.rirb],0
    setne al
    mov [rdi+44],eax
    shl eax,5
    or r9d,eax
    xor eax,eax
    cmp qword [rel hdar_output + hda_output.mmio],0
    setne al
    mov [rdi+56],eax
    shl eax,6
    or r9d,eax
    xor eax,eax
    cmp qword [rel hdar_output + hda_output.bdl],0
    setne al
    mov [rdi+60],eax
    shl eax,7
    or r9d,eax
    xor eax,eax
    cmp qword [rel hdar_output + hda_output.pcm],0
    setne al
    mov [rdi+64],eax
    shl eax,8
    or r9d,eax
    xor eax,eax
    cmp qword [rel hdar_output + hda_output.position],0
    setne al
    mov [rdi+68],eax
    shl eax,9
    or r9d,eax
    xor eax,eax
    cmp qword [rel hdar_output + hda_output.bdl_dma],0
    setne al
    shl eax,10
    or r9d,eax
    xor eax,eax
    cmp qword [rel hdar_output + hda_output.pcm_dma],0
    setne al
    shl eax,11
    or r9d,eax
    xor eax,eax
    cmp qword [rel hdar_output + hda_output.position_dma],0
    setne al
    shl eax,12
    or r9d,eax
    mov [rdi+16],r9d
    movzx eax,byte [rel hdar_guest_claimed]
    mov [rdi+20],eax
    mov eax,[rel hdar_transport + hda_transport.pending]
    mov [rdi+48],eax
    mov eax,[rel hdar_transport + hda_transport.fault]
    mov [rdi+52],eax
    mov eax,[rel hdar_output + hda_output.state]
    mov [rdi+72],eax
    mov eax,[rel hda_probe_stage]
    mov [rdi+76],eax
    mov eax,[rel hda_probe_error]
    mov [rdi+80],eax
    mov eax,[rel hdar_bdf]
    mov [rdi+84],eax
    mov eax,[rel hdar_pci_id]
    mov [rdi+88],eax
    mov [rdi+92],r11d
    test r11d,r11d
    jnz .if_refusal
    cmp dword [rdi+48],0
    jne .work_refusal
    mov eax,[rdi+72]
    test eax,eax
    jz .lifetime
    cmp eax,8
    jbe .work_refusal                ; original configured/in-flight output1..8
    jmp .refuse                     ; STOPPED/FAILED/unknown is not closure
.lifetime:
    test r9d,r9d
    jnz .refuse
    cmp dword [rdi+52],0
    jne .refuse
    mov dword [rdi+4],0
    mov dword [rdi+8],0
    xor eax,eax
    ret
.if_refusal:
    mov dword [rdi+8],1
    jmp .refuse
.work_refusal:
    mov dword [rdi+8],2
.refuse:
    mov rax,-1
    ret

hda_probe_controller_busy:
    mov rax,[rel hdar_mmio]
    test rax,rax
    jnz .out
    movzx eax,byte [rel hdar_guest_claimed] ; RCQ-36 V2: a guest-assigned controller is never native
.out:
    ret
; RCQ-36 V2: the VM owner (hv/pci_assign) takes the one HDA controller for a
; guest. RAX 0 claimed, sticky for the boot (no native owner may open it
; again); nonzero: the native owner already holding it, nothing claimed.
hda_probe_guest_claim:
    mov rax,[rel hdar_mmio]
    test rax,rax
    jnz .out
    call hda_loopback_native_busy
    test rax,rax
    jnz .out
    mov byte [rel hdar_guest_claimed],1
    xor eax,eax
.out:
    ret
hda_probe_tone:
    cmp dword [rel hdar_terminal_latched],0
    jne hdart_denied
    call hdarf_new_attempt         ; original native attempt, no device effect
    call hdart_entry_prepare       ; original prior completed owner, RAM only
    push rbx
    push r12
    push r13
    push r14
    push r15
    call hda_loopback_native_busy
    test rax,rax
    jnz .fail
    cmp byte [rel hdar_guest_claimed],0 ; RCQ-36 V2: this boot assigned it to a guest
    jne .fail
    mov dword [rel hda_probe_stage], 0
    mov dword [rel hda_probe_error], 0
    mov dword [rel hdar_verb], 0        ; current invocation, including early refusal
    mov dword [rel hdar_output + hda_output.error], 0
    mov dword [rel hdar_pci_candidates], 0
    mov dword [rel hdar_discovery_error], 0
    mov qword [rel hdar_bar], 0
    mov qword [rel hdar_pde], 0
    ; This guard protects BOTH the owner verb and the optional boot fixture.
    ; Physical-controller bring-up requires a separately reviewed target rail.
    mov eax, 1
    cpuid
    test ecx, 0x80000000
    jz .host_refused
    mov qword [rel hdar_found], 0
    lea rdi, [rel hdar_pci_cb]
    call pci_scan_with_filter
    mov rdi, [rel hdar_found]
    test rdi, rdi
    jz .scan_failed
    call hda_probe_init_at
    test rax, rax
    js .fail
    mov dword [rel hda_probe_stage], 5
    mov rdi, [rel hdar_dma]
    add rdi, 0x8000
    call hda_probe_generate
    mov rsi, [rel hdar_dma]
    add rsi, 0x8000
    mov rdi, [rel hdar_dma]
    add rdi, 0x4000
    mov ecx, 16384/8
    rep movsq
    mov r12d, 16384                    ; next source byte
    mov r13d, 4096                     ; next completed period boundary
    xor r14d, r14d                     ; unwrapped consumed bytes
    xor r15d, r15d                     ; last modulo position
    call time_monotonic_now_us
    mov [rel hdar_last_poll], rax
    mov rsi, rax
    lea rdi, [rel hdar_output]
    call hda_output_start
    test rax, rax
    js .fail_reset
    mov ebx, 10000000                  ; independent finite pump ceiling
.pump:
    dec ebx
    jz .fail_reset
    call hdar_budget
    test rax, rax
    js .fail_reset
    call time_monotonic_now_us
    mov rcx, rax
    sub rcx, [rel hdar_last_poll]
    cmp rcx, 60000                     ; reject ambiguity before 85.3ms wrap
    jae .fail_reset
    mov [rel hdar_last_poll], rax
    mov rsi, rax
    lea rdi, [rel hdar_output]
    call hda_output_service
    test rax, rax
    js .fail_reset
    jnz .pending
    lea rdi, [rel hdar_output]
    lea rsi, [rel hdar_position]
    call hda_output_position
    test rax, rax
    js .fail_reset
    mov eax, [rel hdar_position]
    and eax, 0x3FFF                    ; raw CBL endpoint aliases ring start
    mov ecx, eax
    sub ecx, r15d
    and ecx, 0x3FFF
    mov r15d, eax
    add r14d, ecx
    cmp r14d, HDAR_TONE_BYTES + HDAR_CODEC_DRAIN_BYTES
    jae .stop
.refill:
    cmp r14d, r13d
    jb .pending
    ; If >one whole cycle was consumed without refill, fail instead of replay.
    lea eax, [r13 + 12288]
    cmp r14d, eax
    jae .fail_reset
    mov edi, r13d
    sub edi, 4096
    and edi, 0x3FFF
    add rdi, [rel hdar_dma]
    add rdi, 0x4000
    mov ecx, 1024
.copy:
    xor eax, eax
    cmp r12d, HDAR_TONE_BYTES
    jae .store                         ; drain is silence, never source overread
    mov rdx, [rel hdar_dma]
    mov eax, [rdx + r12 + 0x8000]
.store:
    stosd
    add r12d, 4
    dec ecx
    jnz .copy
    sfence
    add r13d, 4096
    jmp .refill
.pending:
    pause
    jmp .pump
.stop:
    call time_monotonic_now_us
    mov rsi, rax
    lea rdi, [rel hdar_output]
    call hda_output_halt
    test rax, rax
    js .fail_reset
.stopping:
    dec ebx
    jz .fail_reset
    call hdar_budget
    test rax, rax
    js .fail_reset
    call time_monotonic_now_us
    mov rsi, rax
    lea rdi, [rel hdar_output]
    call hda_output_service
    test rax, rax
    js .fail_reset
    jnz .stopping
    mov rax, [rel hdar_mmio]
    mov byte [rax + 0x4C], 0
    mov byte [rax + 0x5C], 0
    lea rdi, [rel hdar_done_msg]
    call serial_string
    xor eax, eax
    jmp .out
.scan_failed:
    call hdart_scan_failed         ; original no-candidate rejection, no MMIO
    jmp .fail
.fail_reset:
    mov rax, [rel hdar_mmio]
    mov byte [rax + 0x4C], 0
    mov byte [rax + 0x5C], 0
    and dword [rax + 8], 0xFFFFFEFE
    mov eax,2                     ; original tone failure stop/reset boundary
    call hdarf_capture             ; no additional device write or retry
.fail:
    mov eax, [rel hda_probe_stage]
    inc eax
    jmp .report
.host_refused:
    mov eax, 8                        ; stage 0: CPUID refusal; no controller is 1
.report:
    mov [rel hda_probe_error], eax
    lea rdi, [rel hdar_fail_msg]
    call serial_string
    mov edi, [rel hda_probe_stage]
    call serial_hex64
    lea rdi, [rel hdar_error_msg]
    call serial_string
    mov edi, [rel hda_probe_error]
    call serial_hex64
    lea rdi, [rel hdar_verb_msg]
    call serial_string
    mov edi, [rel hdar_verb]
    call serial_hex64
    lea rdi, [rel hdar_out_msg]
    call serial_string
    mov edi, [rel hdar_output + hda_output.error]
    call serial_hex64
    lea rdi, [rel hdar_discovery_msg]
    call serial_string
    mov edi, [rel hdar_discovery_error]
    call serial_hex64
    lea rdi, [rel hdar_candidates_msg]
    call serial_string
    mov edi, [rel hdar_pci_candidates]
    call serial_hex64
    lea rdi, [rel hdar_bar_msg]
    call serial_string
    mov rdi, [rel hdar_bar]
    call serial_hex64
    lea rdi, [rel hdar_pde_msg]
    call serial_string
    mov rdi, [rel hdar_pde]
    call serial_hex64
    call serial_newline
    mov rax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Scan callback owns no hardware writes until class/vendor/BAR/type/live-map
; validation. Private diagnostics describe the LAST matching Intel/AMD 040300
; candidate; later unrelated PCI functions leave its refusal intact. Success
; clears the reason, not the snapshots. Zero candidates means no class match.
; discovery_error: 0 none/accepted, 2 BAR type, 3 zero/unaligned BAR,
; 4 controller affinity, 5 no PDE, 6 P/RW/PCD/PS, 7 NX, 8 identity,
; 9 PCI command readback. These diagnostic values are not a sound-driver ABI.
hdar_pci_cb:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp,8                       ; scanner SysV entry8 -> calls0
    cmp qword [rel hdar_found], 0
    jne .out
    cmp cx, 0x8086
    je .vendor_ok
    cmp cx, 0x1022
    jne .out
.vendor_ok:
    mov r15d,ecx                    ; original scanner identity, before calls
    mov r12d, edi
    mov r13d, esi
    mov r14d, edx
    mov ecx, 8
    call pci_cfg_read32
    mov ebp,eax                     ; original raw class/revision
    shr eax, 8
    and eax, 0xFFFF7F               ; HDA progIF00/80 only; all other bits exact
    cmp eax, 0x040300
    jne .out
    inc dword [rel hdar_pci_candidates]
    mov qword [rel hdar_bar], 0
    mov qword [rel hdar_pde], 0
    mov dword [rel hdar_discovery_error], 2
    mov edx, r14d
    mov ecx, 0x10
    call pci_cfg_read32
    mov ebx, eax
    and eax, 15
    cmp eax, 0
    je .bar32
    cmp eax, 4
    jne .out                            ; refuse IO/reserved/prefetchable BAR
    mov edx, r14d
    mov ecx, 0x14
    call pci_cfg_read32
    shl rax, 32
    and ebx, 0xFFFFFFF0
    or rbx, rax
    jmp .bar
.bar32:
    and ebx, 0xFFFFFFF0
.bar:
    mov [rel hdar_bar], rbx
    mov dword [rel hdar_discovery_error], 3
    test rbx, rbx
    jz .out
    test ebx, 0xFFF
    jnz .out
    mov dword [rel hdar_discovery_error], 4
    mov rax, [rel hdar_mmio]
    test rax, rax
    jz .controller_ok
    cmp rax, rbx
    jne .out                            ; reject replacement BEFORE PCI writes
.controller_ok:
    ; Read live page-table mapping, not an assumed identity-map ceiling.
    mov dword [rel hdar_discovery_error], 5
    mov rdi, rbx
    call paging_pd_entry_ptr
    test rax, rax
    jz .out
    mov rax, [rax]
    mov [rel hdar_pde], rax
    mov dword [rel hdar_discovery_error], 6
    mov ecx, eax
    and ecx, 0x93
    cmp ecx, 0x93                       ; P/RW/PCD/2MiB
    jne .out
    mov dword [rel hdar_discovery_error], 7
    bt rax, 63
    jnc .out
    mov dword [rel hdar_discovery_error], 8
    mov rcx, 0x000FFFFFFFE00000
    and rax, rcx
    and rcx, rbx
    cmp rax, rcx
    jne .out
    ; Immutable first claim, before the original PCI enable write. Refuse a
    ; retained pre-anchor lifetime; never reconstruct its provenance here.
    mov eax,r12d
    shl eax,8
    mov ecx,r13d
    shl ecx,3
    or eax,ecx
    or eax,r14d
    cmp dword [rel hdar_anchor_valid],0
    jne .anchor_replay
    cmp qword [rel hdar_mmio],0
    jne .out
    cmp qword [rel hdar_dma],0
    jne .out
    cmp dword [rel hdar_terminal_latched],0
    jne .out
    mov [rel hdar_anchor_bdf],eax
    mov [rel hdar_anchor_id],r15d
    mov [rel hdar_anchor_class],ebp
    mov [rel hdar_anchor_bar],rbx
    mov rcx,[rel hdar_pde]
    mov [rel hdar_anchor_pde],rcx
    mov dword [rel hdar_anchor_valid],1
    jmp .anchor_ok
.anchor_replay:
    cmp dword [rel hdar_terminal_latched],0
    jne .out
    cmp [rel hdar_anchor_bdf],eax
    jne .out
    cmp [rel hdar_anchor_id],r15d
    jne .out
    cmp [rel hdar_anchor_class],ebp
    jne .out
    cmp [rel hdar_anchor_bar],rbx
    jne .out
    mov rcx,[rel hdar_pde]
    xor rcx,[rel hdar_anchor_pde]
    and rcx,~0x60                  ; hardware Accessed/Dirty may advance
    jnz .out
.anchor_ok:
    mov dword [rel hdar_discovery_error], 9
    mov edi, r12d
    mov esi, r13d
    mov edx, r14d
    mov ecx, 4
    call pci_cfg_read32
    cmp eax, -1
    je .command_unknown                 ; refuse before deriving/writing Command
    and eax, 0xFFFF                      ; NEVER replay W1C PCI Status
    or eax, 6
    mov r8d, eax
    mov edx, r14d
    ; Whole-scan provenance: attempted enable is an effect even if readback
    ; fails or a later candidate rejects before enable. Never clear here.
    mov dword [rel hdart_scan_effects],1
    call pci_cfg_write32
    mov edx, r14d
    call pci_cfg_read32
    cmp eax, -1
    je .command_unknown                 ; unknown is not an enabled controller
    and eax, 6
    cmp eax, 6
    jne .out
    mov [rel hdar_found], rbx
    mov eax, r12d                       ; packed BDF for the DID-3 attach
    shl eax, 8
    mov ecx, r13d
    shl ecx, 3
    or eax, ecx
    or eax, r14d
    mov [rel hdar_bdf], eax
    mov edi, r12d
    mov esi, r13d
    mov edx, r14d
    xor ecx, ecx
    call pci_cfg_read32
    mov [rel hdar_pci_id], eax
    mov dword [rel hdar_discovery_error], 0
    jmp .out
.command_unknown:
    ; Whole-attempt availability is sticky across later callbacks. Keep the
    ; separate actual write-attempt operand: an initial unknown read wrote
    ; nothing, while an unknown readback followed an attempted enable.
    mov dword [rel hdart_scan_observed],2
.out:
    add rsp,8
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Generate S16LE stereo 440Hz/48k, 0.5s, linear 75ms attack/100ms release.
; Integer envelope over an independently generated 1200-frame/11-cycle table.
hda_probe_generate:
    push rbx
    push r12
    xor ebx, ebx
    xor r12d, r12d
.loop:
    lea rdx, [rel hdar_sine]
    movsx eax, word [rdx + r12*2]
    cmp ebx, 3600
    jae .release
    imul eax, ebx
    cdq
    mov ecx, 3600
    idiv ecx
    jmp .write
.release:
    cmp ebx, 19200
    jb .write
    mov ecx, 23999
    sub ecx, ebx
    imul eax, ecx
    cdq
    mov ecx, 4800
    idiv ecx
.write:
    mov [rdi], ax
    mov [rdi + 2], ax
    add rdi, 4
    inc r12d
    cmp r12d, 1200
    jb .next
    xor r12d, r12d
.next:
    inc ebx
    cmp ebx, 24000
    jb .loop
    pop r12
    pop rbx
    ret

hdar_ready_msg: db "HDA probe: controller/rings/discovery/direct route ready",13,10,0
hdar_done_msg: db "HDA probe: tone DMA stopped; grade captured bytes for audio proof",13,10,0
hdar_fail_msg: db "HDA probe: FAILED stage=",0
hdar_error_msg: db " probe_error=",0
hdar_verb_msg: db " last_verb=",0
hdar_out_msg: db " output_error=",0
hdar_discovery_msg: db " discovery_error=",0
hdar_candidates_msg: db " pci_candidates=",0
hdar_bar_msg: db " bar=",0
hdar_pde_msg: db " pde=",0
align 2
hdar_sine:
%include "dev/snd/hda_tone_table.inc"

%macro WDATA_hdar 0
hdar_dma: resq 1
hdar_mmio: resq 1
hdar_found: resq 1
hdar_bar: resq 1
hdar_pde: resq 1
hdar_pci_candidates: resd 1
hdar_discovery_error: resd 1
hdar_overall_deadline: resq 1
hdar_last_poll: resq 1
hda_probe_error: resd 1
hda_probe_stage: resd 1
hdar_statests: resd 1
hdar_verb: resd 1
hdar_reply: resd 1
hdar_position: resd 1
hdar_pin: resd 1
hdar_dac: resd 1
hdar_group: resd 1
hdar_format_node: resd 1
hdar_transport: resb hda_transport_size
hdar_output: resb hda_output_size
hdar_discovery: resb hda_discovery_size
hdar_codecs: resb 15*hda_codec_info_size
hdar_groups: resb 127*15*hda_group_info_size
hdar_widgets: resb 127*15*hda_widget_info_size
%endmacro
WDATA_BSS_DEFER WDATA_hdar
%macro WDATA_hdar_guest 0
hdar_guest_claimed: resb 1              ; RCQ-36 V2: hda_probe_guest_claim, sticky for the boot
%endmacro
WDATA_BSS_DEFER WDATA_hdar_guest

; RCQ-36 S5b DID 3: its own block, so WDATA_hdar keeps its moved layout.
%macro WDATA_hdar_dom 0
hdar_map_serial: resq 1             ; the receipt serial the first attach proved
hdar_bdf: resd 1                    ; packed BDF of the selected controller
hdar_pci_id: resd 1                 ; exact controller device:vendor dword
%endmacro
WDATA_BSS_DEFER WDATA_hdar_dom

%include "dev/snd/hda_runtime_terminal.inc"
