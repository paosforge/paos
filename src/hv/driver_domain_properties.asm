;; MODULE hv/driver_domain_properties
;; LAYER 6
;; EXPORTS nd_properties_append
;; IMPORTS hv/driver_domain, hv/driver_domain_learned, gui/form_loader
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Append observations to the existing scrollable Properties facts list. The
; original machine/CPU rows retain their positions. A signed record in RAM is
; explicitly distinct from a verified DATA record. No IO or identity mutation.
nd_properties_append:
    sub rsp,8
    lea rdi,[rel nd_props_domain]
    call form_live_put_str
    mov edi,[rel nd_state]
    call form_live_put_dec
    lea rdi,[rel nd_props_learned]
    call form_live_put_str
    mov eax,[rel nd_learn_state]
    lea rdi,[rel nd_props_invalid]
    cmp eax,6
    ja .label
    lea rdx,[rel nd_props_offsets]
    movsxd rax,dword [rdx+rax*4]
    add rax,rdx
    mov rdi,rax
.label:
    call form_live_put_str
    lea rdi,[rel nd_props_data]
    call form_live_put_str
    mov eax,[rel nd_learn_persist_state]
    lea rdi,[rel nd_props_invalid]
    cmp eax,4
    ja .data_label
    lea rdx,[rel nd_props_data_offsets]
    movsxd rax,dword [rdx+rax*4]
    add rax,rdx
    mov rdi,rax
.data_label:
    call form_live_put_str
    lea rdi,[rel nd_props_received]
    call form_live_put_str
    mov edi,[rel nd_learn_received]
    call form_live_put_dec
    lea rdi,[rel nd_props_sequence]
    call form_live_put_str
    xor edi,edi
    cmp dword [rel nd_learn_state],4
    jne .sequence
    mov rdi,[rel nd_learn_sequence]
.sequence:
    call form_live_put_dec
    add rsp,8
    ret
nd_props_domain: db ',driver_domain=',0
nd_props_learned: db ',learned_manifest=',0
nd_props_received: db ',learned_received=',0
nd_props_sequence: db ',learned_sequence=',0
nd_props_invalid: db 'unknown',0
nd_props_waiting: db 'waiting',0
nd_props_receiving: db 'receiving',0
nd_props_verified: db 'hash_verified',0
nd_props_signed: db 'signed_not_saved',0
nd_props_saved: db 'DATA_verified',0
nd_props_refused: db 'refused',0
nd_props_pending: db 'node_identity_pending',0
align 4
nd_props_offsets:
    dd nd_props_waiting-nd_props_offsets,nd_props_receiving-nd_props_offsets
    dd nd_props_verified-nd_props_offsets,nd_props_signed-nd_props_offsets
    dd nd_props_saved-nd_props_offsets,nd_props_refused-nd_props_offsets
    dd nd_props_pending-nd_props_offsets

nd_props_data: db ',learned_DATA=',0
nd_props_data_pending: db 'pending',0
nd_props_data_bound: db 'bound_not_saved',0
nd_props_data_verified: db 'verified',0
nd_props_data_uncertain: db 'uncertain',0
nd_props_data_refused: db 'refused',0
align 4
nd_props_data_offsets:
    dd nd_props_data_pending-nd_props_data_offsets,nd_props_data_bound-nd_props_data_offsets
    dd nd_props_data_verified-nd_props_data_offsets,nd_props_data_uncertain-nd_props_data_offsets
    dd nd_props_data_refused-nd_props_data_offsets
