;; MODULE dev/snd/hda_output
;; LAYER 3
;; EXPORTS hda_output_bind_s24, hda_output_bind, hda_output_prepare, hda_output_service, hda_output_start, hda_output_halt, hda_output_position
;; IMPORTS boot/native_driver_gate
;; CAPS mmio dma
;; OWNER saga:audio
%include "boot/native_driver_gate.inc"
; Optional sole-controller power fence. Zero leaves ordinary audio unchanged.
; Hook is trusted kernel-only, serialized by the native controller owner.
%macro HDA_OUTPUT_POWER 0
 cmp qword [rel hda_output_power_gate],0
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
 call [rel hda_output_power_gate]
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

; RCQ-36 S3: Classic hda_playback BDL/register sequence, corrected output SD
; selection from audio_hda_play_wav. Classic HEAD 0cabd75f8653ae3f8778ad0af51469a4f20adf25.
; Primary facts: Intel HDA rev1.0a 3.3.2, 3.3.32-43, 3.6.1-3, 3.7.1.
; Controller position selection also uses the documented upstream AMD Raven
; quirk (1022:15e3); see docs/HDA_AMD_PLAYBACK_POSITION.md for provenance.
;
; PRIVATE controller-owned API. All VAs/capacities/mappings are trusted and
; stable; buffers are preallocated through RC dma_alloc/IOMMU by the future
; owner, never supplied by a user. Separate CPU VA and device IOVA explicitly.
; Caller owns the ENTIRE native controller, serializes all calls and IRQs,
; reserves the first dedicated output SD/tag, and validates codec format/routes.
; bind installs the GLOBAL position buffer only while every stream and both
; command DMA engines are stopped. Other streams may not concurrently bind it.
; No allocation, PCI binding, codec verbs, PCM submit, IRQ registration or boot
; call. S16LE mono/stereo, 44.1/48 kHz only in this primitive. Four 4-KiB periods.
; Deadlines use one monotonic caller clock; timeout is a positive tick duration.
; Faults request RUN=0 but NEVER claim stop acknowledgement or free DMA memory.
; Real controller reset/verified DMA stop is required before reinitialization.
; Position is RAW DMA bytes, NOT an audible/presentation clock or submit count.

HDAO_BOUND       equ 1
HDAO_STOPPING    equ 2
HDAO_RESET_SET   equ 3
HDAO_RESET_CLEAR equ 4
HDAO_READY       equ 5
HDAO_STARTING    equ 6
HDAO_RUNNING     equ 7
HDAO_HALTING     equ 8
HDAO_STOPPED     equ 9
HDAO_FAILED      equ 10
HDAO_E_CONFIG    equ 1
HDAO_E_CLOCK     equ 2
HDAO_E_TIMEOUT   equ 3
HDAO_E_DMA       equ 4
HDAO_E_POSITION  equ 5

struc hda_output
  .mmio:           resq 1
  .bdl:            resq 1
  .bdl_dma:        resq 1
  .pcm:            resq 1
  .pcm_dma:        resq 1
  .position:       resq 1
  .position_dma:   resq 1
  .timeout:        resq 1
  .deadline:       resq 1
  .last_now:       resq 1
  .mmio_bytes:     resd 1
  .bdl_bytes:      resd 1
  .pcm_bytes:      resd 1
  .position_bytes: resd 1
  .sd_index:       resd 1
  .format:         resd 1
  .frame_bytes:    resd 1
  .tag:            resd 1
  .state:          resd 1
  .error:          resd 1
  .observed_pos:   resd 1
  .xruns:          resd 1
  ; First primitive timeout only. Scalar RAM evidence survives cleanup; no
  ; pointers or ownership claims. Appended to preserve existing field offsets.
  .timeout_state:        resq 1
  .timeout_now:          resq 1
  .timeout_previous_now: resq 1
  .timeout_deadline:     resq 1
  .timeout_ticks:        resq 1
  .timeout_sd_index:     resq 1
  .timeout_sd_control:   resq 1
  .timeout_sd_status:    resq 1
  .timeout_lpib:         resq 1
  .timeout_dpl:          resq 1
  ; Trusted controller owner supplies the PCI ID dword (device:vendor).
  ; Zero/other IDs keep DPL. Bind freezes this identity for the stream.
  .pci_id:               resq 1
  .bound_pci_id:         resq 1
endstruc

%macro HDAO_SD 0
    mov eax, [rdi + hda_output.sd_index]
    shl eax, 5
    lea r8, [rax + 0x80]
    add r8, [rdi + hda_output.mmio]
%endmacro
%macro HDAO_NOW 0
    cmp rsi, [rdi + hda_output.last_now]
    jb hdao_clock_fault
    mov [rdi + hda_output.last_now], rsi
%endmacro
%macro HDAO_DEADLINE 0
    mov rax, rsi
    add rax, [rdi + hda_output.timeout]
    jc hdao_clock_fault
    mov [rdi + hda_output.deadline], rax
%endmacro

; bind(RDI=context, ESI=rate, EDX=channels, ECX=tag) -> 0 bound, -1 refused.
; Fresh zero state only. Refusal changes diagnostics/context but no MMIO or
; buffer bytes. All functions preserve RBX/RBP/R12-R15, clobber volatiles.
; hda_output_bind_s24 uses the same admission/lifecycle with24bit samples in
; 32bit containers (Intel HDA rev1.0a4.5.1); caller supplies zero low8bits.
hda_output_bind:
    NATIVE_DRIVER_REFUSE 7
 HDA_OUTPUT_POWER
    mov r8d,2                        ; legacy S16 containers
    jmp hda_output_bind_common
hda_output_bind_s24:
    NATIVE_DRIVER_REFUSE 7
 HDA_OUTPUT_POWER
    mov r8d,4                        ; explicit24,32bit padded containers
hda_output_bind_common:
    cmp dword [rdi + hda_output.state], 0
    jne .error
    cmp dword [rdi + hda_output.pci_id + 4], 0
    jne .config_fault
    cmp qword [rdi + hda_output.mmio], 0
    je .config_fault
    cmp dword [rdi + hda_output.mmio_bytes], 4096
    jb .config_fault
    cmp qword [rdi + hda_output.bdl], 0
    je .config_fault
    cmp qword [rdi + hda_output.pcm], 0
    je .config_fault
    cmp qword [rdi + hda_output.position], 0
    je .config_fault
    cmp dword [rdi + hda_output.bdl_bytes], 64
    jb .config_fault
    cmp dword [rdi + hda_output.pcm_bytes], 16384
    jb .config_fault
    cmp dword [rdi + hda_output.position_bytes], 256
    jb .config_fault
    cmp qword [rdi + hda_output.timeout], 0
    jle .config_fault
    cmp edx, 1
    jb .config_fault
    cmp edx, 2
    ja .config_fault
    cmp ecx, 1
    jb .config_fault
    cmp ecx, 15
    ja .config_fault
    mov [rdi + hda_output.tag], ecx
    mov eax,edx
    imul eax,r8d
    mov [rdi + hda_output.frame_bytes], eax
    mov eax, edx
    dec eax
    or eax, 0x10                       ; PCM 16-bit, channels minus one
    cmp r8d,4
    jne .sample_bits
    or eax,0x20                        ; BITS3=24; low8 memory bits zero
.sample_bits:
    cmp esi, 48000
    je .format_ready
    cmp esi, 96000
    jne .format_44k1
    or eax, 0x0800                     ; Classic96k: 48kHz base x2, divisor1
    jmp .format_ready
.format_44k1:
    cmp esi, 44100
    jne .config_fault
    or eax, 0x4000                     ; 44.1 kHz base, multiplier/divisor 1
.format_ready:
    mov [rdi + hda_output.format], eax
    mov r8, [rdi + hda_output.mmio]
    movzx r10d, word [r8]
    mov eax, r10d
    and eax, 6
    cmp eax, 6                         ; reserved NSDO encoding
    je .config_fault
    mov eax, r10d
    shr eax, 8
    and eax, 15                        ; Classic later fix: inputs precede outputs
    mov [rdi + hda_output.sd_index], eax
    mov r9d, eax
    mov eax, r10d
    shr eax, 12
    and eax, 15
    jz .config_fault                   ; no dedicated output SD (BSS deferred)
    add r9d, eax
    shr r10d, 3
    and r10d, 31
    add r9d, r10d
    cmp r9d, 30                        ; spec total stream limit
    ja .config_fault
    test byte [r8 + 0x4C], 2           ; CORB DMA must be stopped for global DPLBASE
    jnz .config_fault
    test byte [r8 + 0x5C], 2           ; RIRB DMA must also be stopped
    jnz .config_fault
    xor ecx, ecx
.check_streams:
    mov eax, ecx
    shl eax, 5
    test byte [r8 + rax + 0x80], 2
    jnz .config_fault
    inc ecx
    cmp ecx, r9d
    jb .check_streams
    ; Validate entire non-overlapping IOVA spans, not only their base dwords.
    mov r8, [rdi + hda_output.bdl_dma]
    test r8, r8
    jz .config_fault
    test r8, 127
    jnz .config_fault
    mov r9, r8
    add r9, 63
    jc .config_fault
    mov r10, [rdi + hda_output.pcm_dma]
    test r10, r10
    jz .config_fault
    test r10, 127
    jnz .config_fault
    mov r11, r10
    add r11, 16383
    jc .config_fault
    mov rax, [rdi + hda_output.position_dma]
    test rax, rax
    jz .config_fault
    test rax, 127
    jnz .config_fault
    mov rdx, rax
    add rdx, 255
    jc .config_fault
    cmp r9, r10
    jb .bdl_pcm_ok
    cmp r11, r8
    jae .config_fault
.bdl_pcm_ok:
    cmp r9, rax
    jb .bdl_position_ok
    cmp rdx, r8
    jae .config_fault
.bdl_position_ok:
    cmp r11, rax
    jb .pcm_position_ok
    cmp rdx, r10
    jae .config_fault
.pcm_position_ok:
    mov rcx, [rdi + hda_output.mmio]
    test word [rcx], 1                 ; GCAP.64OK covers all DMA addresses
    jnz .addresses_ok
    mov rax, r9
    or rax, r11
    or rax, rdx
    shr rax, 32
    test rax, rax
    jnz .config_fault
.addresses_ok:
    ; Classic four-period BDL, IOC per period for later refill service.
    mov r8, [rdi + hda_output.bdl]
    mov rax, [rdi + hda_output.pcm_dma]
    mov ecx, 4
.fill_bdl:
    mov [r8], rax
    mov dword [r8 + 8], 4096
    mov dword [r8 + 12], 1
    add rax, 4096
    add r8, 16
    dec ecx
    jnz .fill_bdl
    push rdi
    mov r8, rdi
    mov rdi, [r8 + hda_output.pcm]
    xor eax, eax
    mov ecx, 4096
    rep stosd
    mov rdi, [r8 + hda_output.position]
    mov ecx, 64
    rep stosd
    pop rdi
    sfence
    mov r8, [rdi + hda_output.mmio]
    mov dword [r8 + 0x70], 0           ; disable before replacing global base
    mov rax, [rdi + hda_output.position_dma]
    shr rax, 32
    mov [r8 + 0x74], eax
    mov rax, [rdi + hda_output.position_dma]
    or eax, 1                          ; enable DMA position write-back
    mov [r8 + 0x70], eax
    mov qword [rdi + hda_output.deadline], 0
    mov qword [rdi + hda_output.last_now], 0
    mov dword [rdi + hda_output.observed_pos], 0
    mov dword [rdi + hda_output.xruns], 0
    mov dword [rdi + hda_output.error], 0
    mov rax, [rdi + hda_output.pci_id]
    mov [rdi + hda_output.bound_pci_id], rax
    mov dword [rdi + hda_output.state], HDAO_BOUND
    xor eax, eax
    ret
.config_fault:
    mov dword [rdi + hda_output.error], HDAO_E_CONFIG
    mov dword [rdi + hda_output.state], HDAO_FAILED
.error:
    mov rax, -1
    ret

; prepare(RDI=context, RSI=now) -> 1 pending, -1 refused.
; Clear RUN first, then service will VERIFY it before asserting SRST.
hda_output_prepare:
 HDA_OUTPUT_POWER
    mov eax, [rdi + hda_output.state]
    cmp eax, HDAO_BOUND
    je .begin
    cmp eax, HDAO_STOPPED
    jne .error
.begin:
    HDAO_NOW
    HDAO_DEADLINE
    HDAO_SD
    and byte [r8], 0xFD
    mov dword [rdi + hda_output.state], HDAO_STOPPING
    mov eax, 1
    ret
.error:
    mov rax, -1
    ret

; start(RDI=context, RSI=now) -> 1 pending, -1 refused. Caller has filled PCM
; and configured/powered the chosen codec converter/route for this format/tag.
hda_output_start:
 HDA_OUTPUT_POWER
    cmp dword [rdi + hda_output.state], HDAO_READY
    jne .error
    HDAO_NOW
    HDAO_DEADLINE
    HDAO_SD
    test byte [r8], 3
    jnz hdao_dma_fault
    sfence                             ; caller's PCM stores precede RUN
    or byte [r8], 2
    mov dword [rdi + hda_output.state], HDAO_STARTING
    mov eax, 1
    ret
.error:
    mov rax, -1
    ret

; halt(RDI=context, RSI=now) -> 1 pending, -1 refused. No buffer release until
; service returns STOPPED. A fault needs external verified controller recovery.
hda_output_halt:
 HDA_OUTPUT_POWER
    mov eax, [rdi + hda_output.state]
    cmp eax, HDAO_READY
    je .begin
    cmp eax, HDAO_STARTING
    je .begin
    cmp eax, HDAO_RUNNING
    jne .error
.begin:
    HDAO_NOW
    HDAO_DEADLINE
    HDAO_SD
    and byte [r8], 0xFD
    mov dword [rdi + hda_output.state], HDAO_HALTING
    mov eax, 1
    ret
.error:
    mov rax, -1
    ret

; service(RDI=context, RSI=now) -> 0 stable state, 1 pending, -1 fault/refusal.
; At most one transition, with one fixed register sequence; NEVER polls/spins.
hda_output_service:
 HDA_OUTPUT_POWER
    mov ecx, [rdi + hda_output.state]
    test ecx, ecx
    jz .error
    cmp ecx, HDAO_FAILED
    jae .error
    mov r10, [rdi + hda_output.last_now]
    HDAO_NOW
    HDAO_SD
    cmp ecx, HDAO_STOPPING
    je .stopping
    cmp ecx, HDAO_RESET_SET
    je .reset_set
    cmp ecx, HDAO_RESET_CLEAR
    je .reset_clear
    cmp ecx, HDAO_STARTING
    je .starting
    cmp ecx, HDAO_RUNNING
    je .running
    cmp ecx, HDAO_HALTING
    je .halting
    xor eax, eax                       ; BOUND, READY, STOPPED
    ret
.stopping:
    ; Setup observes completed hardware levels before expiring a wait: the
    ; cooperative owner may service us after the acknowledgment. Missing ack
    ; still reaches .pending's fixed deadline; each call advances one state.
    ; This does not prove when hardware acknowledged. RUN start and DMA
    ; retirement below retain their strict deadline-first policy.
    test byte [r8], 2
    jnz .pending
    HDAO_DEADLINE
    or byte [r8], 1
    mov dword [rdi + hda_output.state], HDAO_RESET_SET
    mov eax, 1
    ret
.reset_set:
    test byte [r8], 1
    jz .pending
    HDAO_DEADLINE
    and byte [r8], 0xFE
    mov dword [rdi + hda_output.state], HDAO_RESET_CLEAR
    mov eax, 1
    ret
.reset_clear:
    test byte [r8], 1
    jnz .pending
    ; Only after both reset acknowledgements may stream registers be written.
    mov eax, [rdi + hda_output.format]
    mov [r8 + 0x12], ax
    mov dword [r8 + 8], 16384
    mov word [r8 + 0x0C], 3
    mov rax, [rdi + hda_output.bdl_dma]
    mov [r8 + 0x18], eax
    shr rax, 32
    mov [r8 + 0x1C], eax
    mov eax, [rdi + hda_output.tag]
    shl eax, 4
    mov [r8 + 2], al
    mov byte [r8 + 3], 0x1C            ; W1C only: never write LPIB (read-only)
    mov r9, [rdi + hda_output.mmio]
    mov eax, [r9 + 0x38]
    mov ecx, [rdi + hda_output.sd_index]
    btr eax, ecx                       ; preserve other streams' SSYNC bits
    mov [r9 + 0x38], eax
    mov r9, [rdi + hda_output.position]
    mov dword [r9 + rcx*8], 0          ; stopped stream's absolute position slot
    mov dword [rdi + hda_output.observed_pos], 0
    mov dword [rdi + hda_output.state], HDAO_READY
    xor eax, eax
    ret
.starting:
    cmp rsi, [rdi + hda_output.deadline]
    jae .timeout
    test byte [r8 + 3], 0x18
    jnz hdao_dma_fault
    test byte [r8], 2
    jz .pending
    test byte [r8 + 3], 0x20           ; output FIFO readiness, not an audible proof
    jz .pending
    mov dword [rdi + hda_output.state], HDAO_RUNNING
    xor eax, eax
    ret
.running:
    test byte [r8 + 3], 0x18
    jnz hdao_dma_fault
    test byte [r8], 2
    jz hdao_dma_fault
    test byte [r8], 1
    jnz hdao_dma_fault
    test byte [r8 + 3], 4
    jz .ok
    mov byte [r8 + 3], 4               ; W1C completion, no inferred wrap count
.ok:
    xor eax, eax
    ret
.halting:
    cmp rsi, [rdi + hda_output.deadline]
    jae .timeout
    test byte [r8], 2
    jnz .pending
    mov dword [rdi + hda_output.state], HDAO_STOPPED
    xor eax, eax
    ret
.pending:
    cmp rsi, [rdi + hda_output.deadline]
    jae .timeout
    mov eax, 1
    ret
.timeout:
    ; Mapping/SD/position were admitted by bind; owner keeps them pinned.
    ; Capture before hdao_fault clears RUN. Observations qualify no samples.
    ; No new clock, polling, retry, deadline slack or stop acknowledgement.
    cmp qword [rdi + hda_output.timeout_state], 0
    jne .timeout_recorded
    mov eax, [rdi + hda_output.state]
    mov [rdi + hda_output.timeout_state], rax
    mov [rdi + hda_output.timeout_now], rsi
    mov [rdi + hda_output.timeout_previous_now], r10
    mov rax, [rdi + hda_output.deadline]
    mov [rdi + hda_output.timeout_deadline], rax
    mov rax, [rdi + hda_output.timeout]
    mov [rdi + hda_output.timeout_ticks], rax
    mov ecx, [rdi + hda_output.sd_index]
    mov [rdi + hda_output.timeout_sd_index], rcx
    mov eax, [r8]
    and eax, 0xFFFFFF
    mov [rdi + hda_output.timeout_sd_control], rax
    movzx eax, byte [r8 + 3]
    mov [rdi + hda_output.timeout_sd_status], rax
    mov eax, [r8 + 4]
    mov [rdi + hda_output.timeout_lpib], rax
    mov r9, [rdi + hda_output.position]
    lfence
    mov eax, [r9 + rcx*8]
    mov [rdi + hda_output.timeout_dpl], rax
.timeout_recorded:
    mov eax, HDAO_E_TIMEOUT
    jmp hdao_fault
.error:
    mov rax, -1
    ret

; position(RDI=context, RSI=out_raw_bytes*) -> 0 sample, -1 refusal/fault.
; Default DMA position uses ABSOLUTE SD index * 8, including input engines.
; AMD 1022:15e3 instead uses raw playback LPIB (known position-buffer quirk).
; PCM still brackets this sample with two LPIBs and its owner/time/ring checks.
; This is DMA retirement, not the post-FIFO audible position.
; Range is inclusive 0..CBL; partial frames are legal raw byte observations.
; Never unwrap or infer a presentation clock from a possibly stale DMA sample.
hda_output_position:
 HDA_OUTPUT_POWER
    cmp dword [rdi + hda_output.state], HDAO_RUNNING
    jne .error
    HDAO_SD
    test byte [r8 + 3], 0x18
    jnz hdao_dma_fault
    test byte [r8], 2
    jz hdao_dma_fault
    test byte [r8], 1
    jnz hdao_dma_fault
    mov rax, [rdi + hda_output.pci_id]
    cmp rax, [rdi + hda_output.bound_pci_id]
    jne .identity_fault
    cmp eax, 0x15e31022
    jne .dpl
    mov eax, [r8 + 4]                  ; exact AMD Raven playback quirk
    jmp .sample
.dpl:
    mov eax, [rdi + hda_output.sd_index]
    mov r8, [rdi + hda_output.position]
    lfence
    mov eax, [r8 + rax*8]
.sample:
    cmp eax, 16384
    ja .position_fault
    mov [rsi], eax
    mov [rdi + hda_output.observed_pos], eax
    xor eax, eax
    ret
.identity_fault:
    mov eax, HDAO_E_CONFIG
    jmp hdao_fault
.position_fault:
    inc dword [rdi + hda_output.xruns]
    mov eax, HDAO_E_POSITION
    jmp hdao_fault
.error:
    mov rax, -1
    ret

hdao_clock_fault:
    mov eax, HDAO_E_CLOCK
    jmp hdao_fault
hdao_dma_fault:
    inc dword [rdi + hda_output.xruns]
    mov eax, HDAO_E_DMA
hdao_fault:
    mov [rdi + hda_output.error], eax
    mov dword [rdi + hda_output.state], HDAO_FAILED
    HDAO_SD
    and byte [r8], 0xFD                ; request stop, no acknowledgement claimed
    mov rax, -1
    ret

%macro WDATA_hda_output_power 0
 align 8
hda_output_power_gate: dq 0
%endmacro
%ifmacro WDATA_DEFER 1
 WDATA_DEFER WDATA_hda_output_power
%else
 section .data
 WDATA_hda_output_power
 section .text
%endif
