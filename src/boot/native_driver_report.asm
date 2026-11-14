;; MODULE boot/native_driver_report
;; LAYER 0
;; EXPORTS native_driver_report, native_driver_report_selection
;; IMPORTS boot/native_driver_gate, boot/native_driver_preload, boot/serial
;; CAPS
;; OWNER saga:boot
; Boot-local facts only. An allow count is an admission, not a successful
; probe, ownership transfer, working guest, or compatibility PASS. Classes:
; 0 platform,1 GOP,2 USB HC,3 HID,4 domain net,5 exact boot storage,
; 6 native net,7 native sound,8 accelerated display,9 other USB,10 unknown.
; The whole compatibility check must separately bind effective coverage and
; actual devices to its original build/boot/START generation.
native_driver_report_selection:
    sub rsp, 8
    lea rdi, [rel ndp_report_policy]
    call serial_string
    mov rdi, [rel native_driver_selected_policy]
    call serial_hex64
    lea rdi, [rel ndp_report_bdf]
    call serial_string
    mov rdi, [rel native_driver_boot_bdf]
    call serial_hex64
    call serial_newline
    add rsp, 8
    ret
native_driver_report:
    push rbx
    call native_driver_report_selection
    cmp qword [rel native_driver_selected_policy], 0
    je .done                       ; ordinary boots need no detailed census
    xor ebx, ebx
.row:
    lea rdi, [rel ndp_report_class]
    call serial_string
    mov rdi, rbx
    call serial_hex64
    lea rdi, [rel ndp_report_allow]
    call serial_string
    lea rax, [rel native_driver_permitted]
    mov rdi, [rax + rbx*8]
    call serial_hex64
    lea rdi, [rel ndp_report_deny]
    call serial_string
    lea rax, [rel native_driver_blocked]
    mov rdi, [rax + rbx*8]
    call serial_hex64
    call serial_newline
    inc ebx
    cmp ebx, 11
    jb .row
.done:
    pop rbx
    ret
ndp_report_policy: db "[NDP] selected=",0
ndp_report_bdf: db " firmware_boot_bdf=",0
ndp_report_class: db "[NDP] class=",0
ndp_report_allow: db " allowed_calls=",0
ndp_report_deny: db " refused_calls=",0
