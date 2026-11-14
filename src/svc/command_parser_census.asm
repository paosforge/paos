;; MODULE svc/command_parser_census
;; LAYER 5
;; EXPORTS command_parser_census_init, parser_census_out_ready, parser_census_is_verb, udp_parser_census_take
;; IMPORTS core/lib/fmt, svc/command, svc/command_udp, svc/command_serial, net/dhcp, net/dns, net/tcp, net/tls13, net/http, svc/ssh, boot/smbios, bus/acpi_table_spans, dev/usb/hid, fs/ntfs_disk, fs/exfat_disk, fs/fat32_disk
;; CAPS
;; OWNER rc-resource-claude
; Read-only, normal owner-authenticated registry dispatch. No publicity grant.
; GUI catalog limits are link-time equ values only, with no upward calls or
; GUI data dereferences. Runtime imports above are the report/caller boundaries.
; Each page reports the compiled parser limit symbols, not copied host values.
; The catalog names exact guards, units, scope and outstanding parser families.
; An incomplete inventory/negative-case audit is deliberately NOT an X7 PASS.

command_parser_census_init:
    lea rdi, [rel pc_verb]
    lea rsi, [rel cmd_verb_parser_census]
    xor edx, edx
    mov ecx, ARGT_U64
    xor r8d, r8d
    xor r9d, r9d
    jmp command_register_verb

; No prefix/suffix match. Clobbers EAX/flags only.
parser_census_is_verb:
    xor eax, eax
    cmp dword [rel udp_line], 'PARS'
    jne .out
    cmp dword [rel udp_line+4], 'ECEN'
    jne .out
    cmp word [rel udp_line+8], 'SU'
    jne .out
    cmp byte [rel udp_line+10], 'S'
    jne .out
    cmp byte [rel udp_line+11], 0
    jne .out
    inc eax
.out:
    ret

udp_parser_census_take:
    push rbx
    movzx ebx, byte [rel parser_census_out_ready]
    mov byte [rel parser_census_out_ready], 0
    call parser_census_is_verb
    test eax, eax
    jz .out
    call udp_put_uptime
    cmp qword [rel udp_rsp+RSP_CODE], CMDE_OK
    jne .yes
    test ebx, ebx
    jz .yes
    lea rdi, [rel parser_census_out_buf]
    call udp_put_str
.yes:
    mov eax, 1
.out:
    pop rbx
    ret

cmd_verb_parser_census:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rsi
    mov byte [rel parser_census_out_ready], 0
    mov byte [rel parser_census_out_buf], 0
    mov r12, [rdi+REQ_ARG]
    cmp r12, PC_PAGE_COUNT
    jae .bad
    lea rax, [rel parser_census_out_buf]
    mov [rel pc_cur], rax
    lea rdi, [rel pc_prefix]
    call pc_text
    mov rdi, r12
    call pc_num
    lea rdi, [rel pc_header]
    call pc_text
    lea rdi, [rel pc_records]
    call pc_text
    shl r12, 3                       ; eight entries per page, page checked first
    lea r13, [r12+8]
    cmp r13, PC_ENTRY_COUNT
    jbe .end_ready
    mov r13d, PC_ENTRY_COUNT
.end_ready:
    mov r14, r12
.entry:
    cmp r12, r14
    je .first
    lea rdi, [rel pc_comma]
    call pc_text
.first:
    mov rdi, r12
    call pc_num
    lea rdi, [rel pc_colon]
    call pc_text
    lea rax, [rel pc_limits]
    mov rdi, [rax+r12*8]              ; actual compiled parser constant
    call pc_num
    inc r12
    cmp r12, r13
    jb .entry
    ; This flag is ONLY the existing network framing KAT. It supplies neither
    ; a whole-census result nor negative coverage for any non-network parser.
    lea rdi, [rel pc_kat]
    call pc_text
    movzx edi, byte [rel network_parser_bounds_kat_ok]
    call pc_num
    mov byte [rel parser_census_out_ready], 1
    mov qword [rbx+RSP_CODE], CMDE_OK
    jmp .out
.bad:
    mov qword [rbx+RSP_CODE], CMDE_BADARG
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

pc_num:
    lea rsi, [rel pc_number]
    call fmt_dec
    lea rdi, [rel pc_number]
pc_text:
    mov rsi, [rel pc_cur]
.copy:
    lea rdx, [rel parser_census_out_buf+511]
    cmp rsi, rdx
    jae .end
    mov al, [rdi]
    test al, al
    jz .end
    mov [rsi], al
    inc rsi
    inc rdi
    jmp .copy
.end:
    mov byte [rsi], 0
    mov [rel pc_cur], rsi
    ret

parser_census_out_ready: db 0
parser_census_out_buf: times 512 db 0
pc_cur: dq 0
pc_number: times 24 db 0
pc_verb: db 'PARSECENSUS',0
pc_prefix: db ' PARSECENSUS rev=1 page=',0
pc_records: db ' records=',0
pc_comma: db ',',0
pc_colon: db ':',0
pc_kat: db ' kat=',0
%include "svc/parser_census_table.inc"
