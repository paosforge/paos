; C3 actual retained audio selections. No snd_select/attach/admission/device
; call, handoff or probe. A fake/empty registry does not mean absent hardware.
hw_r_bindaud:
    push rbx
    sub rsp,64
    lea rdi,[rel hwc_aud_scope]
    call hw_puts
    mov rsi,rsp
    call snd_census_snapshot
    mov ebx,[rsp]
    HWC_DEC "snd",ebx
    mov ebx,[rsp+4]
    HWC_DEC "members",ebx
    mov ebx,[rsp+8]
    HWC_DEC "flags",ebx
    mov ebx,[rsp+12]
    HWC_DEC "pci_id",ebx
    HWC_BYTE "legacy",hdar_guest_claimed
    mov ebx,[rel hdar_bdf]
    HWC_DEC "legacy_bdf",ebx
    mov ebx,[rel hdar_pci_id]
    HWC_DEC "legacy_id",ebx
    HWC_BOOLPTR "loop",hln_mmio
    mov ebx,[rel hln_bdf]
    HWC_DEC "loop_bdf",ebx
    mov ebx,[rel hln_pci_id]
    HWC_DEC "loop_id",ebx
    lea rdi,[rsp+16]
    call uacs_census_snapshot
    mov ebx,[rsp+16]
    HWC_DEC "uacs_phase",ebx
    mov ebx,[rsp+20]
    HWC_DEC "uacs_mode",ebx
    mov edi,10
    lea rsi,[rsp+16]
    call hw_audio_census_emit
    ; Exact owner HC+port join; no guessed interface class from endpoint type.
    mov rdi,[rel uacs_hc]
    mov esi,[rel uacs_address]
    mov edx,10
    mov ecx,[rsp+16]
    mov r8d,[rsp+44]
    cmp dword [rsp+52],0
    je .output_identity
    mov r8d,-1
.output_identity:
    call hw_usb_census_emit
    lea rdi,[rsp+16]
    call uaci_census_snapshot
    mov ebx,[rsp+16]
    HWC_DEC "uaci_phase",ebx
    mov ebx,[rsp+20]
    HWC_DEC "uaci_mode",ebx
    mov edi,11
    lea rsi,[rsp+16]
    call hw_audio_census_emit
    mov rdi,[rel uaci_hc]
    mov esi,[rel uaci_address]
    mov edx,11
    mov ecx,[rsp+16]
    mov r8d,[rsp+44]
    cmp dword [rsp+52],0
    je .input_identity
    mov r8d,-1
.input_identity:
    call hw_usb_census_emit
    add rsp,64
    pop rbx
    ret
hwc_aud_scope: db " scope=audio-v1 usb_interfaces=retained-v1",0

; EDI backend,RSI mapped40B retained owner record. Whole report cap remains
; atomic: a clipped record is refused, never published as a partial census.
hw_audio_census_emit:
    push rbx
    push r12
    push r13
    mov ebx,edi
    mov r12,rsi
    lea rdi,[rel hwc_aud_row]
    call hw_puts
    mov edi,ebx
    call hw_put_dec
    xor r13d,r13d
.column:
    lea rdi,[rel str_hw_comma]
    call hw_puts
    mov edi,[r12+r13*4]
    call hw_put_dec
    inc r13d
    cmp r13d,10
    jb .column
    pop r13
    pop r12
    pop rbx
    ret
hwc_aud_row: db " uac=",0
