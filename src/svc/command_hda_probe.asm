;; MODULE svc/command_hda_probe
%include "core/abi/build_profile.inc"
;; LAYER 5
;; EXPORTS command_hda_probe_init, command_hda_probe_arm
;; IMPORTS svc/command_uac1_input_probe, svc/command_uac1_sound, svc/command_uac1_capture, svc/command_uac1_tone, svc/command_wav_playback, svc/command_opus_playback, svc/command_hda_loopback, svc/command, svc/command_pci_mmio, svc/command_fs, dev/snd/hda_runtime
;; CAPS
;; OWNER saga:audio
; Explicit mutating diagnostic through the one command registry. Default builds
; never initialize/play HDA automatically. No new public/auth exemption.
%ifndef PAOS_HDA_PROBE_BOOT_TONE
%define PAOS_HDA_PROBE_BOOT_TONE 0
%endif
%if PAOS_HDA_PROBE_BOOT_TONE != 0 && PAOS_HDA_PROBE_BOOT_TONE != 1
%error PAOS_HDA_PROBE_BOOT_TONE must be 0 or 1
%endif
command_hda_probe_init:
    sub rsp,8
    call command_uac1_input_probe_init
    call command_uac1_capture_init
    call command_uac1_sound_init
    call command_uac1_tone_init
    add rsp,8
    sub rsp,8
    call command_pci_mmio_init
    lea rdi, [rel hda_probe_verb]
    lea rsi, [rel hda_probe_handler]
    xor edx, edx
    mov ecx, ARGT_U64
    xor r8d, r8d
    mov r9d, 1                        ; mutating, owner policy applies
    call command_register_verb
    add rsp,8
    sub rsp,8
    call command_hda_loopback_init
    add rsp,8
    sub rsp,8
%if !PAOS_PUBLIC_BUILD
    call command_opus_playback_init
%endif
    add rsp,8
    jmp command_wav_playback_init
hda_probe_handler:
    call cmd_handler_prologue
    push rbx
    mov rbx, rsi
    call hda_probe_tone
    mov [rbx + RSP_VAL], rax
    test rax, rax
    jns .ok
    mov qword [rbx + RSP_CODE], CMDE_BADARG
    lea rax, [rel hda_probe_hint]
    mov [rbx + RSP_HINT], rax
.ok:
    pop rbx
    ret

; Retain the existing late cadence chain. An explicit test-image build may
; request the SAME native probe at this seam, after other boot tests/drivers.
; CPUID hypervisor guard prevents this fixture path on bare metal. No auth
; policy is changed: test boot fixture calls the private API, not a wire verb.
command_hda_probe_arm:
    call fs_registry_census_arm
%if PAOS_HDA_PROBE_BOOT_TONE
    push rbx
    mov eax, 1
    cpuid
    test ecx, 0x80000000
    jz .out
    call hda_probe_tone
.out:
    pop rbx
%endif
    ret
hda_probe_verb: db "HDA_TONE",0
hda_probe_hint: db "HDA probe failed; read serial stage/error; no audio pass claimed",0
