;; MODULE svc/command_parser_census
;; LAYER 5
;; EXPORTS command_parser_census_init, parser_census_out_ready, parser_census_is_verb, udp_parser_census_take
;; IMPORTS core/time, core/lib/sha256, core/lib/fmt, svc/command, svc/command_udp, svc/command_serial, net/tls13_certificate_policy, net/dhcp, net/dns, net/ntp, net/icmp, net/tcp, net/tls13, net/http, svc/ssh, boot/smbios, bus/acpi_table_spans, dev/usb/hid, fs/ntfs_disk, fs/exfat_disk, fs/fat32_disk
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
    mov [rel pc_arp_case], r12
    cmp r12, PC_LIMIT_PAGE_COUNT
    jb .limit_page
    lea rdi, [rel pc_empty]
    call pc_text
    jmp .records_done
.limit_page:
    shl r12, 3                       ; eight entries per limit page, checked first
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
.records_done:
    ; This flag is ONLY the existing network framing KAT. It supplies neither
    ; a whole-census result nor negative coverage for any non-network parser.
    lea rdi, [rel pc_kat]
    call pc_text
    movzx edi, byte [rel network_parser_bounds_kat_ok]
    call pc_num
    call pc_arp_observe
    call pc_ntp_observe
    call pc_icmp_observe
    call pc_tcp_observe
    call pc_ingress_observe
    call pc_der_observe
    call pc_ssh_observe
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

; Original shared SSH string cursor; no decrypt/channel/auth/command effects.
; Pages15..19: valid, inconsistent length, short header, oversize, header wrap.
; Overflow hashes separate accessible backing, never the invalid pointer.
pc_ssh_observe:
    push r12
    push r13
    mov r12, [rel pc_arp_case]
    sub r12, 15
    cmp r12, 5
    jae .done
    lea rax, [rel pc_ssh_fixtures]
    mov r13, [rax+r12*8]
    add r13, rax                         ; image-relative table
    mov byte [rel pc_ssh_integrity], 1
    lea rdi, [rel pc_ssh_before]
    mov rsi, r13
    mov edx, 32
    call sha256_hash
    test rax, rax
    setz al
    and [rel pc_ssh_integrity], al
    lea rdi, [r13+8]
    cmp r12, 4
    jne .base
    mov rdi, -3
.base:
    mov [rel pc_ssh_base], rdi
    lea rax, [rel pc_ssh_lengths]
    mov rsi, [rax+r12*8]
    add rsi, rdi                        ; actual exclusive end, including wrap case
    call ssh_string_read                ; original authenticated channel string cursor
    mov qword [rel pc_ssh_return], -1
    mov qword [rel pc_ssh_value], 0
    mov qword [rel pc_ssh_length], 0
    mov qword [rel pc_ssh_next], 0
    cmp rax, -1
    je .hashed
    mov qword [rel pc_ssh_return], 0
    sub rax, [rel pc_ssh_base]
    mov [rel pc_ssh_value], rax
    mov [rel pc_ssh_length], rdx
    sub r8, [rel pc_ssh_base]
    mov [rel pc_ssh_next], r8
.hashed:
    lea rdi, [rel pc_ssh_after]
    mov rsi, r13
    mov edx, 32
    call sha256_hash
    test rax, rax
    setz al
    and [rel pc_ssh_integrity], al
    mov rax, 0x6b2ad84f0917c5e3
    cmp [r13], rax
    sete dl
    cmp [r13+24], rax
    sete cl
    and dl, cl
    and [rel pc_ssh_integrity], dl
    lea rdi, [rel pc_ssh_prefix]
    call pc_text
    mov rdi, r12
    call pc_arp_field
    mov edi, PAOS_PUBLIC_BUILD
    call pc_arp_field
    lea rax, [rel pc_ssh_lengths]
    mov rdi, [rax+r12*8]
    call pc_arp_field
    xor edi, edi
    cmp r12, 4
    jne .field
    mov rdi, [rel pc_ssh_base]
.field:
    call pc_arp_field
    mov rdi, [rel pc_ssh_return]
    call pc_arp_field
    mov rdi, [rel pc_ssh_value]
    call pc_arp_field
    mov rdi, [rel pc_ssh_length]
    call pc_arp_field
    mov rdi, [rel pc_ssh_next]
    call pc_arp_field
    movzx edi, byte [rel pc_ssh_integrity]
    call pc_arp_field
    lea r12, [rel pc_ssh_before]
    call pc_arp_digest
    lea rdi, [rel pc_comma]
    call pc_text
    lea r12, [rel pc_ssh_after]
    call pc_arp_digest
    lea rdi, [rel pc_comma]
    call pc_text
    mov r12, r13
    call pc_arp_digest                 ; original guard/input/guard bytes, 32B
.done:
    pop r13
    pop r12
    ret

; Original certificate-policy DER cursor; pages10..14 unchanged.
pc_der_observe:
    push r12
    push r13
    mov r12, [rel pc_arp_case]
    sub r12, 10
    cmp r12, 5
    jae .done
    lea rax, [rel pc_der_fixtures]
    mov r13, [rax+r12*8]
    add r13, rax                         ; image-relative table
    mov byte [rel pc_der_integrity], 1
    lea rdi, [rel pc_der_before]
    mov rsi, r13
    mov edx, 32
    call sha256_hash
    test rax, rax
    setz al
    and [rel pc_der_integrity], al
    lea rdi, [r13+8]
    cmp r12, 4
    jne .base
    mov rdi, -21
.base:
    mov [rel pc_der_base], rdi
    lea rax, [rel pc_der_lengths]
    mov rsi, [rax+r12*8]
    add rsi, rdi                        ; actual exclusive end, including wrap case
    call tlscp_der                      ; same cursor used by certificate policy
    mov qword [rel pc_der_return], -1
    mov qword [rel pc_der_tag], 0
    mov qword [rel pc_der_value], 0
    mov qword [rel pc_der_length], 0
    mov qword [rel pc_der_next], 0
    jc .hashed                          ; MOVs preserve original CF
    mov qword [rel pc_der_return], 0
    mov [rel pc_der_tag], rax
    sub rdx, [rel pc_der_base]
    mov [rel pc_der_value], rdx
    mov [rel pc_der_length], rcx
    sub rdi, [rel pc_der_base]
    mov [rel pc_der_next], rdi
.hashed:
    lea rdi, [rel pc_der_after]
    mov rsi, r13
    mov edx, 32
    call sha256_hash
    test rax, rax
    setz al
    and [rel pc_der_integrity], al
    mov rax, 0x6b2ad84f0917c5e3
    cmp [r13], rax
    sete dl
    cmp [r13+24], rax
    sete cl
    and dl, cl
    and [rel pc_der_integrity], dl
    lea rdi, [rel pc_der_prefix]
    call pc_text
    mov rdi, r12
    call pc_arp_field
    mov edi, PAOS_PUBLIC_BUILD
    call pc_arp_field
    lea rax, [rel pc_der_lengths]
    mov rdi, [rax+r12*8]
    call pc_arp_field
    xor edi, edi
    cmp r12, 4
    jne .field
    mov rdi, [rel pc_der_base]
.field:
    call pc_arp_field
    mov rdi, [rel pc_der_return]
    call pc_arp_field
    mov rdi, [rel pc_der_tag]
    call pc_arp_field
    mov rdi, [rel pc_der_value]
    call pc_arp_field
    mov rdi, [rel pc_der_length]
    call pc_arp_field
    mov rdi, [rel pc_der_next]
    call pc_arp_field
    movzx edi, byte [rel pc_der_integrity]
    call pc_arp_field
    lea r12, [rel pc_der_before]
    call pc_arp_digest
    lea rdi, [rel pc_comma]
    call pc_text
    lea r12, [rel pc_der_after]
    call pc_arp_digest
.done:
    pop r13
    pop r12
    ret

; Five bounded calls to the SAME pure view used by udp_handle_arp. No network,
; cache learning, pending state, send or new entry verb. One case per old page.
; Before/after digests cover all 2049 real backing bytes, not a host receipt.
; Case4 passes UINT64_MAX-20 (base+14+28 wraps); its backing hash describes the
; separate fixture, never accessible bytes at the deliberately invalid pointer.
pc_arp_observe:
    push r12
    push r13
    mov r12, [rel pc_arp_case]
    cmp r12, 5                           ; finite case table, independent of future limit pages
    jae .done
    lea r13, [rel pc_arp_valid]
    cmp r12, 1
    jne .fixture
    lea r13, [rel pc_arp_malformed]
.fixture:
    mov byte [rel pc_arp_hash_ok], 1
    lea rdi, [rel pc_arp_before]
    mov rsi, r13
    mov edx, 2049
    call sha256_hash
    test rax, rax
    setz al
    and [rel pc_arp_hash_ok], al
    mov rdi, r13
    cmp r12, 4
    jne .base
    mov rdi, -21
.base:
    mov [rel pc_arp_base], rdi
    lea rax, [rel pc_arp_lengths]
    mov rsi, [rax+r12*8]
    call arp_frame_view                    ; actual original native receive view
    cmp rax, -1
    je .result
    sub rax, [rel pc_arp_base]              ; accepted body offset, not ASLR address
.result:
    mov [rel pc_arp_return], rax
    lea rdi, [rel pc_arp_after]
    mov rsi, r13
    mov edx, 2049
    call sha256_hash
    test rax, rax
    setz al
    and [rel pc_arp_hash_ok], al
    ; Both fixture boundaries and SHA call results are actual observations.
    mov rax, 0x6b2ad84f0917c5e3
    cmp [rel pc_arp_guard0], rax
    sete dl
    cmp [rel pc_arp_guard1], rax
    sete cl
    and dl, cl
    cmp [rel pc_arp_guard2], rax
    sete cl
    and dl, cl
    and dl, [rel pc_arp_hash_ok]
    mov [rel pc_arp_integrity], dl
    lea rdi, [rel pc_arp_prefix]
    call pc_text
    mov rdi, r12
    call pc_arp_field
    mov edi, PAOS_PUBLIC_BUILD             ; actual carrying build profile
    call pc_arp_field
    lea rax, [rel pc_arp_lengths]
    mov rdi, [rax+r12*8]
    call pc_arp_field
    xor edi, edi                          ; normalized actual fixture base
    cmp r12, 4
    jne .base_field
    mov rdi, [rel pc_arp_base]             ; actual invalid overflow argument
.base_field:
    call pc_arp_field
    mov rdi, [rel pc_arp_return]
    call pc_arp_field
    movzx edi, byte [rel pc_arp_integrity]
    call pc_arp_field
    lea r12, [rel pc_arp_before]
    call pc_arp_digest
    lea rdi, [rel pc_comma]
    call pc_text
    lea r12, [rel pc_arp_after]
    call pc_arp_digest
.done:
    pop r13
    pop r12
    ret

; Next finite original decoder used by live ntp_accept_reply. Explicit T1/T4
; inputs avoid all transaction/clock mutation; no route or deadline is bypassed
; in the live caller. Each actual result and both real backing hashes are saved.
pc_ntp_observe:
    push r12
    push r13
    mov r12, [rel pc_arp_case]
    cmp r12, 5
    jae .done
    lea r13, [rel pc_ntp_valid]
    cmp r12, 1
    jne .fixture
    lea r13, [rel pc_ntp_malformed]
.fixture:
    mov byte [rel pc_ntp_hash_ok], 1
    lea rdi, [rel pc_ntp_before]
    mov rsi, r13
    mov edx, 2049
    call sha256_hash
    test rax, rax
    setz al
    and [rel pc_ntp_hash_ok], al
    mov rdi, r13
    cmp r12, 4
    jne .base
    mov rdi, -21
.base:
    mov [rel pc_ntp_base], rdi
    lea rax, [rel pc_ntp_lengths]
    mov rsi, [rax+r12*8]
    mov rcx, PC_NTP_T1
    mov rdx, PC_NTP_T1 + 0x40000000
    call ntp_reply_view
    mov [rel pc_ntp_return], rax
    mov [rel pc_ntp_offset], rsi
    mov [rel pc_ntp_delay], rdx
    mov [rel pc_ntp_stratum], ecx
    lea rdi, [rel pc_ntp_after]
    mov rsi, r13
    mov edx, 2049
    call sha256_hash
    test rax, rax
    setz al
    and [rel pc_ntp_hash_ok], al
    mov rax, 0x6b2ad84f0917c5e3
    cmp [rel pc_ntp_guard0], rax
    sete dl
    cmp [rel pc_ntp_guard1], rax
    sete cl
    and dl, cl
    cmp [rel pc_ntp_guard2], rax
    sete cl
    and dl, cl
    and dl, [rel pc_ntp_hash_ok]
    mov [rel pc_ntp_integrity], dl
    lea rdi, [rel pc_ntp_prefix]
    call pc_text
    mov rdi, r12
    call pc_arp_field
    mov edi, PAOS_PUBLIC_BUILD
    call pc_arp_field
    lea rax, [rel pc_ntp_lengths]
    mov rdi, [rax+r12*8]
    call pc_arp_field
    xor edi, edi
    cmp r12, 4
    jne .base_field
    mov rdi, [rel pc_ntp_base]
.base_field:
    call pc_arp_field
    mov rdi, [rel pc_ntp_return]
    call pc_arp_field
    movzx edi, byte [rel pc_ntp_integrity]
    call pc_arp_field
    mov rdi, [rel pc_ntp_offset]
    call pc_arp_field
    mov rdi, [rel pc_ntp_delay]
    call pc_arp_field
    mov edi, [rel pc_ntp_stratum]
    call pc_arp_field
    lea r12, [rel pc_ntp_before]
    call pc_arp_digest
    lea rdi, [rel pc_comma]
    call pc_text
    lea r12, [rel pc_ntp_after]
    call pc_arp_digest
.done:
    pop r13
    pop r12
    ret

; One actual ICMP builder call per existing page, no network/owner/cache state
; mutation. SHA covers request, full destination, MAC inputs and all canaries.
; Overflow passes an invalid source pointer; its hash names separate backing.
pc_icmp_observe:
    push r12
    push r13
    mov r12, [rel pc_arp_case]
    cmp r12, 5                           ; finite case table, independent of future limit pages
    jae .done
    lea r13, [rel pc_icmp_valid]
    cmp r12, 1
    jne .fixture
    lea r13, [rel pc_icmp_malformed]
.fixture:
    ; Reset only destination bytes. Original request/MACs/canaries are observed,
    ; never repaired here; corruption remains visible in both real SHA values.
    lea rdi, [r13+PC_ICMP_DST]
    mov ecx, 1514
    mov al, 0xa5
    cld
    rep stosb
    mov byte [rel pc_icmp_hash_ok], 1
    lea rdi, [rel pc_icmp_before]
    mov rsi, r13
    mov edx, PC_ICMP_BACKING_BYTES
    call sha256_hash
    test rax, rax
    setz al
    and [rel pc_icmp_hash_ok], al
    lea rsi, [r13+8]
    cmp r12, 4
    jne .base
    mov rsi, -21
.base:
    mov [rel pc_icmp_base], rsi
    lea rax, [rel pc_icmp_lengths]
    mov rdx, [rax+r12*8]
    lea rdi, [r13+PC_ICMP_DST]
    mov ecx, 20
    lea r8, [r13+PC_ICMP_PEER]
    lea r9, [r13+PC_ICMP_OUR]
    call icmp_build_ipv4_reply             ; original live reply parser/builder
    mov [rel pc_icmp_return], rax
    lea rdi, [rel pc_icmp_after]
    mov rsi, r13
    mov edx, PC_ICMP_BACKING_BYTES
    call sha256_hash
    test rax, rax
    setz al
    and [rel pc_icmp_hash_ok], al
    ; Every guard is inside the hashed backing; explicitly observe all four
    ; boundaries for the fixture used by this actual execution.
    mov rax, 0x6b2ad84f0917c5e3
    cmp [r13], rax
    sete dl
    cmp [r13+PC_ICMP_DST-8], rax
    sete cl
    and dl, cl
    cmp [r13+PC_ICMP_PEER-8], rax
    sete cl
    and dl, cl
    cmp [r13+PC_ICMP_BACKING_BYTES-8], rax
    sete cl
    and dl, cl
    and dl, [rel pc_icmp_hash_ok]
    mov [rel pc_icmp_integrity], dl
    lea rdi, [rel pc_icmp_prefix]
    call pc_text
    mov rdi, r12
    call pc_arp_field
    mov edi, PAOS_PUBLIC_BUILD             ; actual carrying build profile
    call pc_arp_field
    lea rax, [rel pc_icmp_lengths]
    mov rdi, [rax+r12*8]
    call pc_arp_field
    xor edi, edi                          ; normalized actual fixture base
    cmp r12, 4
    jne .base_field
    mov rdi, [rel pc_icmp_base]             ; actual invalid overflow argument
.base_field:
    call pc_arp_field
    mov rdi, [rel pc_icmp_return]
    call pc_arp_field
    movzx edi, byte [rel pc_icmp_integrity]
    call pc_arp_field
    lea r12, [rel pc_icmp_before]
    call pc_arp_digest
    lea rdi, [rel pc_comma]
    call pc_text
    lea r12, [rel pc_icmp_after]
    call pc_arp_digest
.done:
    pop r13
    pop r12
    ret

; TCP-only pages5..9 keep every prior complete execution tail inside the
; original 768-byte staging/wire bound. This is the SAME original pure helper
; used by tcp4_ingress. No TCB, lock, RX, checksum, negotiation or network call.
pc_tcp_observe:
    push r12
    push r13
    mov r12, [rel pc_arp_case]
    sub r12, 5
    cmp r12, 5
    jae .done
    lea rax, [rel pc_tcp_fixtures]
    mov r13, [rax+r12*8]
    add r13, rax                         ; table-relative delta at live image base
    mov byte [rel pc_tcp_hash_ok], 1
    lea rdi, [rel pc_tcp_before]
    mov rsi, r13
    mov edx, 80
    call sha256_hash
    test rax, rax
    setz al
    and [rel pc_tcp_hash_ok], al
    lea rdi, [r13+8]
    lea rax, [rel pc_tcp_lengths]
    mov esi, [rax+r12*8]
    call tcp_options_validate              ; original native entry, no proxy
    mov [rel pc_tcp_return], rax
    ; The original contract defines R8D only on success. Do not invent a
    ; failure MSS result from a caller-saved register after a refusal.
    xor ecx, ecx
    test rax, rax
    cmovz ecx, r8d
    mov [rel pc_tcp_mss], ecx
    lea rdi, [rel pc_tcp_after]
    mov rsi, r13
    mov edx, 80
    call sha256_hash
    test rax, rax
    setz al
    and [rel pc_tcp_hash_ok], al
    mov rax, 0x6b2ad84f0917c5e3
    cmp [r13], rax
    sete dl
    cmp [r13+72], rax
    sete cl
    and dl, cl
    and dl, [rel pc_tcp_hash_ok]
    mov [rel pc_tcp_integrity], dl
    lea rdi, [rel pc_tcp_prefix]
    call pc_text
    mov rdi, r12
    call pc_arp_field
    mov edi, PAOS_PUBLIC_BUILD
    call pc_arp_field
    lea rax, [rel pc_tcp_lengths]
    mov rdi, [rax+r12*8]
    call pc_arp_field
    xor edi, edi                          ; normalized actual fixture base
    call pc_arp_field
    mov rdi, [rel pc_tcp_return]
    call pc_arp_field
    mov edi, [rel pc_tcp_mss]
    call pc_arp_field
    movzx edi, byte [rel pc_tcp_integrity]
    call pc_arp_field
    lea r12, [rel pc_tcp_before]
    call pc_arp_digest
    lea rdi, [rel pc_comma]
    call pc_text
    lea r12, [rel pc_tcp_after]
    call pc_arp_digest
.done:
    pop r13
    pop r12
    ret

; Last COMPLETED original ingress, never a synthetic live-table invocation.
; The same ten-page caller/budget remains. No observation is a literal0, not PASS.
pc_ingress_observe:
    push r12
    push r13
    cmp qword [rel pc_arp_case], 5
    jb .done
    cmp qword [rel pc_arp_case], 10
    jae .done
    lea rdi, [rel pc_ingress_prefix]
    call pc_text
    lea rdi, [rel pc_ingress_snapshot]
    call tcp_ingress_observation_snapshot
    test rax, rax
    jz .absent
    mov edi, 1
    call pc_arp_field
    mov edi, PAOS_PUBLIC_BUILD
    call pc_arp_field
    mov rdi, [rel pc_ingress_snapshot]
    call pc_arp_field
    call boot_ms_now
    sub rax, [rel pc_ingress_snapshot+64]
    mov rdi, rax
    call pc_arp_field
    mov rdi, [rel pc_ingress_snapshot+8]
    call pc_arp_field
    mov rdi, [rel pc_ingress_snapshot+16]
    call pc_arp_field
    mov r12d, 24
.fields:
    lea rax, [rel pc_ingress_snapshot]
    mov edi, [rax+r12]
    call pc_arp_field
    add r12d, 4
    cmp r12d, 60
    jb .fields
    mov byte [rel pc_ingress_hash_ok], 1
    lea rdi, [rel pc_ingress_before]
    lea rsi, [rel pc_ingress_snapshot+72]
    mov rdx, [rel pc_ingress_snapshot+8]
    call sha256_hash
    test rax, rax
    setz al
    and [rel pc_ingress_hash_ok], al
    lea rdi, [rel pc_ingress_after]
    lea rsi, [rel pc_ingress_snapshot+152]
    mov rdx, [rel pc_ingress_snapshot+8]
    call sha256_hash
    test rax, rax
    setz al
    and [rel pc_ingress_hash_ok], al
    movzx edi, byte [rel pc_ingress_hash_ok]
    call pc_arp_field
    lea r12, [rel pc_ingress_before]
    call pc_arp_digest
    lea rdi, [rel pc_comma]
    call pc_text
    lea r12, [rel pc_ingress_after]
    call pc_arp_digest
    lea rdi, [rel pc_comma]
    call pc_text
    xor r13d, r13d
.hex:
    cmp r13, [rel pc_ingress_snapshot+8]
    jae .done
    lea rax, [rel pc_ingress_snapshot+72]
    movzx edi, byte [rax+r13]
    lea rsi, [rel pc_number]
    mov edx, 2
    call fmt_hex
    lea rdi, [rel pc_number]
    call pc_text
    inc r13
    jmp .hex
.absent:
    xor edi, edi
    call pc_num
.done:
    pop r13
    pop r12
    ret

pc_arp_field:
    call pc_num
    lea rdi, [rel pc_comma]
    jmp pc_text

; Use the canonical formatter, four network-order qwords per SHA256 digest.
pc_arp_digest:
    push r13
    xor r13d, r13d
.next:
    mov rdi, [r12+r13*8]
    bswap rdi
    lea rsi, [rel pc_number]
    mov edx, 16
    call fmt_hex
    lea rdi, [rel pc_number]
    call pc_text
    inc r13
    cmp r13, 4
    jb .next
    pop r13
    ret

pc_num:
    lea rsi, [rel pc_number]
    call fmt_dec
    lea rdi, [rel pc_number]
pc_text:
    mov rsi, [rel pc_cur]
.copy:
    lea rdx, [rel parser_census_out_buf+767]
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
parser_census_out_buf: times 768 db 0
pc_cur: dq 0
pc_number: times 24 db 0
pc_verb: db 'PARSECENSUS',0
pc_prefix: db ' PARSECENSUS rev=1 page=',0
pc_records: db ' records=',0
pc_empty: db '-',0
pc_comma: db ',',0
pc_colon: db ':',0
pc_kat: db ' kat=',0
align 8
pc_arp_case: dq 0
pc_arp_base: dq 0
pc_arp_return: dq 0
pc_arp_lengths: dq 42,42,41,2049,42
pc_arp_hash_ok: db 0
pc_arp_integrity: db 0
pc_arp_before: times 32 db 0
pc_arp_after: times 32 db 0
pc_arp_prefix: db ' arp=1,',0
pc_arp_guard0: dq 0x6b2ad84f0917c5e3
pc_arp_valid: db 0xff,0xff,0xff,0xff,0xff,0xff,0x52,0x54,0,0x12,0x34,0x56,8,6,0,1,8,0,6,4,0,2,0x52,0x54,0,0x12,0x34,0x56,0xc0,0,2,1,0,0,0,0,0,0,0xc0,0,2,2
    times 2049-42 db 0
pc_arp_guard1: dq 0x6b2ad84f0917c5e3
pc_arp_malformed: db 0xff,0xff,0xff,0xff,0xff,0xff,0x52,0x54,0,0x12,0x34,0x56,8,6,0,1,8,0,5,4,0,2,0x52,0x54,0,0x12,0x34,0x56,0xc0,0,2,1,0,0,0,0,0,0,0xc0,0,2,2
    times 2049-42 db 0
pc_arp_guard2: dq 0x6b2ad84f0917c5e3

PC_NTP_T1 equ 0xe8fe6f8000000000
align 8
pc_ntp_base: dq 0
pc_ntp_return: dq 0
pc_ntp_offset: dq 0
pc_ntp_delay: dq 0
pc_ntp_stratum: dd 0
pc_ntp_lengths: dq 48,48,47,2049,48
pc_ntp_hash_ok: db 0
pc_ntp_integrity: db 0
pc_ntp_before: times 32 db 0
pc_ntp_after: times 32 db 0
pc_ntp_prefix: db ' ntp=1,',0
pc_ntp_guard0: dq 0x6b2ad84f0917c5e3
pc_ntp_valid: db 0x24,0x2,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0xe8,0xfe,0x6f,0x80,0x0,0x0,0x0,0x0,0xe8,0xfe,0x6f,0x80,0x10,0x0,0x0,0x0,0xe8,0xfe,0x6f,0x80,0x20,0x0,0x0,0x0
    times 2049-48 db 0
pc_ntp_guard1: dq 0x6b2ad84f0917c5e3
pc_ntp_malformed: db 0xe4,0x2,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0xe8,0xfe,0x6f,0x80,0x0,0x0,0x0,0x0,0xe8,0xfe,0x6f,0x80,0x10,0x0,0x0,0x0,0xe8,0xfe,0x6f,0x80,0x20,0x0,0x0,0x0
    times 2049-48 db 0
pc_ntp_guard2: dq 0x6b2ad84f0917c5e3

PC_ICMP_DST equ 8+2049+8
PC_ICMP_PEER equ PC_ICMP_DST+1514+8
PC_ICMP_OUR equ PC_ICMP_PEER+6
PC_ICMP_BACKING_BYTES equ PC_ICMP_OUR+6+8
align 8
pc_icmp_base: dq 0
pc_icmp_return: dq 0
pc_icmp_lengths: dq 46,46,45,2049,46
pc_icmp_hash_ok: db 0
pc_icmp_integrity: db 0
pc_icmp_before: times 32 db 0
pc_icmp_after: times 32 db 0
pc_icmp_prefix: db ' icmp=1,',0
pc_icmp_valid: dq 0x6b2ad84f0917c5e3
    db 0x2,0x50,0x61,0x4f,0x53,0x2,0x2,0x50,0x61,0x4f,0x53,0x4,0x8,0x0,0x45,0x0,0x0,0x20,0x56,0x78,0x40,0x0,0x29,0x1,0x77,0xdb,0xc0,0xa8,0x1,0x7,0xc0,0xa8,0x1,0x32,0x8,0x0,0x56,0x83,0xa5,0x79,0x12,0x34,0x77,0x69,0x72,0x65
    times 2049-46 db 0
    dq 0x6b2ad84f0917c5e3
    times 1514 db 0xa5
    dq 0x6b2ad84f0917c5e3
    db 0x02,0x50,0x61,0x4f,0x53,0x04,0x02,0x50,0x61,0x4f,0x53,0x02
    dq 0x6b2ad84f0917c5e3
pc_icmp_malformed: dq 0x6b2ad84f0917c5e3
    db 0x2,0x50,0x61,0x4f,0x53,0x2,0x2,0x50,0x61,0x4f,0x53,0x4,0x8,0x0,0x45,0x0,0x0,0x20,0x56,0x78,0x40,0x0,0x29,0x1,0x77,0xdb,0xc0,0xa8,0x1,0x7,0xc0,0xa8,0x1,0x32,0x8,0x1,0x56,0x82,0xa5,0x79,0x12,0x34,0x77,0x69,0x72,0x65
    times 2049-46 db 0
    dq 0x6b2ad84f0917c5e3
    times 1514 db 0xa5
    dq 0x6b2ad84f0917c5e3
    db 0x02,0x50,0x61,0x4f,0x53,0x04,0x02,0x50,0x61,0x4f,0x53,0x02
    dq 0x6b2ad84f0917c5e3

align 8
align 8
pc_ssh_base: dq 0
pc_ssh_return: dq 0
pc_ssh_value: dq 0
pc_ssh_length: dq 0
pc_ssh_next: dq 0
pc_ssh_lengths: dq 7,7,3,4,8
pc_ssh_integrity: db 0
pc_ssh_before: times 32 db 0
pc_ssh_after: times 32 db 0
pc_ssh_prefix: db " ssh=1,",0
align 8
pc_ssh_fixtures:
    dq pc_ssh_valid-pc_ssh_fixtures
    dq pc_ssh_malformed-pc_ssh_fixtures
    dq pc_ssh_truncated-pc_ssh_fixtures
    dq pc_ssh_oversize-pc_ssh_fixtures
    dq pc_ssh_overflow-pc_ssh_fixtures
pc_ssh_valid: dq 0x6b2ad84f0917c5e3
    db 0x00,0x00,0x00,0x03,0x65,0x6e,0x76
    times 9 db 0
    dq 0x6b2ad84f0917c5e3

pc_ssh_malformed: dq 0x6b2ad84f0917c5e3
    db 0x00,0x00,0x00,0x04,0x65,0x6e,0x76
    times 9 db 0
    dq 0x6b2ad84f0917c5e3

pc_ssh_truncated: dq 0x6b2ad84f0917c5e3
    db 0x00,0x00,0x00
    times 13 db 0
    dq 0x6b2ad84f0917c5e3

pc_ssh_oversize: dq 0x6b2ad84f0917c5e3
    db 0xff,0xff,0xff,0xff
    times 12 db 0
    dq 0x6b2ad84f0917c5e3

pc_ssh_overflow: dq 0x6b2ad84f0917c5e3
    db 0x00,0x00,0x00,0x03,0x65,0x6e,0x76
    times 9 db 0
    dq 0x6b2ad84f0917c5e3

pc_der_base: dq 0
pc_der_return: dq 0
pc_der_tag: dq 0
pc_der_value: dq 0
pc_der_length: dq 0
pc_der_next: dq 0
pc_der_lengths: dq 5,5,3,4,42
pc_der_integrity: db 0
pc_der_before: times 32 db 0
pc_der_after: times 32 db 0
pc_der_prefix: db " der=1,",0
align 8
pc_der_fixtures:
    dq pc_der_valid-pc_der_fixtures
    dq pc_der_malformed-pc_der_fixtures
    dq pc_der_truncated-pc_der_fixtures
    dq pc_der_oversize-pc_der_fixtures
    dq pc_der_overflow-pc_der_fixtures
pc_der_valid: dq 0x6b2ad84f0917c5e3
    db 0x30,0x3,0x2,0x1,0x1
    times 11 db 0
    dq 0x6b2ad84f0917c5e3
pc_der_malformed: dq 0x6b2ad84f0917c5e3
    db 0x30,0x80,0x0,0x0,0x0
    times 11 db 0
    dq 0x6b2ad84f0917c5e3
pc_der_truncated: dq 0x6b2ad84f0917c5e3
    db 0x30,0x82,0x1
    times 13 db 0
    dq 0x6b2ad84f0917c5e3
pc_der_oversize: dq 0x6b2ad84f0917c5e3
    db 0x4,0x82,0x80,0x1
    times 12 db 0
    dq 0x6b2ad84f0917c5e3
pc_der_overflow: dq 0x6b2ad84f0917c5e3
    db 0x30,0x3,0x2,0x1,0x1
    times 11 db 0
    dq 0x6b2ad84f0917c5e3

pc_tcp_return: dq 0
pc_tcp_mss: dd 0
pc_tcp_lengths: dq 24,24,24,64,24
pc_tcp_hash_ok: db 0
pc_tcp_integrity: db 0
pc_tcp_before: times 32 db 0
pc_tcp_after: times 32 db 0
pc_tcp_prefix: db ' tcp=1,',0
align 8
; org0 images relocate without fixing stored pointers. Resolve from this anchor.
pc_tcp_fixtures: dq pc_tcp_valid-pc_tcp_fixtures,pc_tcp_malformed-pc_tcp_fixtures,pc_tcp_truncated-pc_tcp_fixtures,pc_tcp_oversize-pc_tcp_fixtures,pc_tcp_unsupported-pc_tcp_fixtures
pc_tcp_valid: dq 0x6b2ad84f0917c5e3
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x60,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x04,0x04,0xb0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    dq 0x6b2ad84f0917c5e3
pc_tcp_malformed: dq 0x6b2ad84f0917c5e3
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x60,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x03,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    dq 0x6b2ad84f0917c5e3
pc_tcp_truncated: dq 0x6b2ad84f0917c5e3
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x60,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x01,0xfe,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    dq 0x6b2ad84f0917c5e3
pc_tcp_oversize: dq 0x6b2ad84f0917c5e3
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xf0,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    dq 0x6b2ad84f0917c5e3
pc_tcp_unsupported: dq 0x6b2ad84f0917c5e3
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x60,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0xfe,0x04,0x12,0x34,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    dq 0x6b2ad84f0917c5e3

%include "svc/parser_census_table.inc"

; Dedicated snapshot/digests: never alias accepted original component scratch.
pc_ingress_prefix: db ' ingress=',0
pc_ingress_snapshot: times 232 db 0
pc_ingress_before: times 32 db 0
pc_ingress_after: times 32 db 0
pc_ingress_hash_ok: db 0
