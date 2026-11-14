; R7 observation only. The shared serializer accepts RSI=bounded static header,
; preserves GPRs/flags and has one total finite UART polling budget. No journal,
; firmware-variable, policy, timer or payload mutation is performed here.
r7_serial_journal_admission:
    pushfq
    push rsi
    lea rsi,[rel r7_admission_header]
    call journal_serial_witness_from_rsi
    pop rsi
    popfq
    ret

r7_serial_journal_after_arm:
    pushfq
    push rax
    push rsi
    mov rax,[rel selected_state_ptr]
    test rax,rax
    jz .done
    cmp byte [rax+PBM_STATE_START_COUNT_OFF],2
    jne .done
    cmp byte [rax+PBM_STATE_START_ARMED_OFF],1
    jne .done
    cmp byte [rax+PBM_STATE_LAST_ENTRY_OFF],PBM_ENTRY_RESCUE
    jne .done
    cmp byte [rax+PBM_STATE_LAST_PROFILE_OFF],PBM_PROFILE_RESCUE
    jne .done
    cmp byte [rax+PBM_STATE_LAST_REASON_OFF],PBM_REASON_RESCUE
    jne .done
    test byte [rax+PBM_STATE_LAST_FLAGS_OFF],PBM_LAST_F_DELIBERATE_RESCUE
    jnz .done
    lea rsi,[rel r7_rescue_header]
    call journal_serial_witness_from_rsi
.done:
    pop rsi
    pop rax
    popfq
    ret

r7_admission_header: db 13,10,'PAOS-R7-JOURNAL1 ADMIT 1024 ',0
r7_rescue_header: db 13,10,'PAOS-R7-JOURNAL1 RESCUE 1024 ',0
