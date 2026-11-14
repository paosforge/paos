; Generated documentation is never an authority source. Registry presence and
; the existing effective classifier determine the live labels below. No dispatch
; or session state is changed by these readers. Called on the BSP, like HELP.
%include "svc/command_catalog_data.inc"

; PaOS uses org 0 and may be relocated by the Manager. Every generated text
; reference is an image-relative offset, resolved from a RIP-relative base.
%macro CC_PTR 3
    mov  %1, [%2 + %3]
    lea  rdx, [rel command_catalog_table]
    add  %1, rdx
%endmacro

CC_PAGE_SIZE equ 8
; Four group blocks plus five independent, <=255-byte blocks per command.
; Keeping syntax, example and policy separate also fits narrow Help windows.
COMMAND_CATALOG_BLOCKS equ COMMAND_CATALOG_COUNT * 5 + 4

command_catalog_help_verb:
    call cmd_handler_prologue
    push rdi
    push rsi
    sub  rsp, 8
    mov  rdi, [rdi + REQ_ARG]
    call command_catalog_help_stage
    add  rsp, 8
    pop  rsi
    pop  rdi
    mov  [rsi + RSP_CODE], rax
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    ret

; RDI bounded command word or @cursor/group (NUL <= 63 bytes). Output uses the
; same canonical staged buffer/transport clamp as AUTHSTAT, but is independent.
; EAX=CMDE_OK or CMDE_BADARG. Every page has <=8 complete entries, never a cut
; line. Metadata limits prove the full page plus headings/footer fits 1280.
command_catalog_help_stage:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    call command_auth_out_reset
    xor  ebx, ebx
    test r12, r12
    jz   .list
    xor  ecx, ecx
.bound:
    cmp  ecx, 64
    jae  .bad
    cmp  byte [r12 + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .bound
.bounded:
    ; Trim leading/trailing spaces; reject embedded words, controls and escapes.
    xor  edx, edx
.leading:
    cmp  byte [r12 + rdx], ' '
    jne  .start
    inc  edx
    jmp  .leading
.start:
    add  r12, rdx
    lea  rdi, [rel cc_query]
    xor  ecx, ecx
.copy:
    mov  al, [r12 + rcx]
    test al, al
    jz   .copied
    cmp  al, ' '
    je   .trailing
    cmp  al, '!'
    jb   .bad
    cmp  al, '~'
    ja   .bad
    mov  [rdi + rcx], al
    inc  ecx
    jmp  .copy
.trailing:
    lea  rdx, [r12 + rcx]
.spaces:
    inc  rdx
    cmp  byte [rdx], ' '
    je   .spaces
    cmp  byte [rdx], 0
    jne  .bad
.copied:
    mov  byte [rdi + rcx], 0
    mov  r12, rdi
    test ecx, ecx
    jz   .list
    cmp  byte [r12], '@'
    je   .cursor
    ; Prefer an exact spelling (Terminal 'windows' vs native 'WINDOWS'), then
    ; ASCII case-insensitive native lookup. Unknown input is never reflected.
    xor  r13d, r13d
.pass:
    xor  ebx, ebx
.find:
    cmp  ebx, COMMAND_CATALOG_COUNT
    jae  .next_pass
    mov  edi, ebx
    call command_catalog_row
    mov  r14, rax
    mov  rdi, r12
    CC_PTR rsi, r14, CC_NAME
    mov  edx, r13d
    call command_catalog_equal
    test eax, eax
    jnz  .detail
    inc  ebx
    jmp  .find
.next_pass:
    inc  r13d
    cmp  r13d, 2
    jb   .pass
    lea  rdi, [rel cc_unknown]
    call command_auth_put_str
    jmp  .error
.detail:
    CC_PTR rdi, r14, CC_DESCRIPTION
    call command_auth_put_str
    call command_catalog_newline
    CC_PTR rdi, r14, CC_SYNTAX
    call command_auth_put_str
    call command_catalog_newline
    mov  edi, ebx
    call command_catalog_permission
    mov  rdi, rax
    call command_auth_put_str
    call command_catalog_newline
    CC_PTR rdi, r14, CC_EXAMPLE
    call command_auth_put_str
    call command_catalog_newline
    CC_PTR rdi, r14, CC_NOTE
    call command_auth_put_str
    call command_catalog_newline
    jmp  .ok
.cursor:
    inc  r12
    xor  r13d, r13d
.group:
    mov  rdi, r12
    lea  rax, [rel cc_group_words]
    mov  rsi, [rax + r13 * 8]
    add  rsi, rax
    xor  edx, edx
    call command_catalog_equal
    test eax, eax
    jnz  .group_found
    inc  r13d
    cmp  r13d, 4
    jb   .group
    ; Strict unsigned decimal: bounded before each multiply (no wrap).
    xor  ebx, ebx
    cmp  byte [r12], 0
    je   .bad
.decimal:
    movzx eax, byte [r12]
    test eax, eax
    jz   .cursor_done
    sub  eax, '0'
    cmp  eax, 9
    ja   .bad
    cmp  ebx, COMMAND_CATALOG_COUNT
    jae  .bad
    imul ebx, ebx, 10
    add  ebx, eax
    inc  r12
    jmp  .decimal
.cursor_done:
    cmp  ebx, COMMAND_CATALOG_COUNT
    jae  .bad
    jmp  .list
.group_found:
    xor  ebx, ebx
.seek_group:
    mov  edi, ebx
    call command_catalog_row
    cmp  [rax + CC_GROUP], r13
    je   .list
    inc  ebx
    cmp  ebx, COMMAND_CATALOG_COUNT
    jb   .seek_group
    jmp  .bad
.list:
    lea  rdi, [rel cc_list_intro]
    call command_auth_put_str
    mov  r13d, -1                       ; previous group
    xor  r15d, r15d                     ; complete rows
.next:
    cmp  ebx, COMMAND_CATALOG_COUNT
    jae  .last
    mov  edi, ebx
    call command_catalog_available
    test eax, eax
    jz   .skip
    cmp  r15d, CC_PAGE_SIZE
    jae  .more
    mov  edi, ebx
    call command_catalog_row
    mov  r14, rax
    mov  eax, [r14 + CC_GROUP]
    cmp  eax, r13d
    je   .entry
    mov  r13d, eax
    lea  rdx, [rel command_catalog_group_titles]
    mov  rdi, [rdx + rax * 8]
    lea  rdx, [rel command_catalog_table]
    add  rdi, rdx
    call command_auth_put_str
    call command_catalog_newline
.entry:
    CC_PTR rdi, r14, CC_DESCRIPTION
    call command_auth_put_str
    lea  rdi, [rel cc_sep]
    call command_auth_put_str
    mov  edi, ebx
    call command_catalog_permission_short
    mov  rdi, rax
    call command_auth_put_str
    call command_catalog_newline
    inc  r15d
.skip:
    inc  ebx
    jmp  .next
.more:
    lea  rdi, [rel cc_more]
    call command_auth_put_str
    mov  edi, ebx
    call command_auth_put_dec
    call command_catalog_newline
    jmp  .ok
.last:
    lea  rdi, [rel cc_end]
    call command_auth_put_str
.ok:
    xor  eax, eax
    jmp  .ready
.bad:
    lea  rdi, [rel cc_usage]
    call command_auth_put_str
.error:
    mov  eax, CMDE_BADARG
.ready:
    mov  byte [rel command_auth_out_ready], 1
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

command_catalog_newline:
    lea  rdi, [rel cc_newline]
    jmp  command_auth_put_str

; EDI source-union index -> RAX descriptor, or zero for an invalid index.
command_catalog_row:
    xor  eax, eax
    cmp  edi, COMMAND_CATALOG_COUNT
    jae  .out
    mov  eax, edi
    shl  rax, 6
    lea  rdx, [rel command_catalog_table]
    add  rax, rdx
.out:
    ret

; Exact or ASCII-insensitive comparison. EDX=0 exact; nonzero insensitive.
; Strings are bounded by their caller/table; never accepts a prefix.
command_catalog_equal:
.loop:
    movzx eax, byte [rdi]
    movzx ecx, byte [rsi]
    test edx, edx
    jz   .compare
    cmp  al, 'a'
    jb   .right
    cmp  al, 'z'
    ja   .right
    sub  al, 32
.right:
    cmp  cl, 'a'
    jb   .compare
    cmp  cl, 'z'
    ja   .compare
    sub  cl, 32
.compare:
    cmp  al, cl
    jne  .no
    test al, al
    jz   .yes
    inc  rdi
    inc  rsi
    jmp  .loop
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Resolve availability without inventing a live profile. An alias requires its
; real target. A local command may still refuse in its handler (e.g. no guest).
command_catalog_available:
    call command_catalog_row
    test rax, rax
    jz   .out
    test qword [rax + CC_FLAGS], 8
    jnz  .no
%ifndef PAOS_TERMINAL_SSH
    test qword [rax + CC_FLAGS], 2
    jnz  .no
%endif
    mov  rdi, [rax + CC_TARGET]
    test rdi, rdi
    jz   .yes
    lea  rdx, [rel command_catalog_table]
    add  rdi, rdx
    call command_lookup
    cmp  eax, -1
    setne al
    movzx eax, al
    ret
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
.out:
    ret

; EDI source-union index -> immutable policy line. Never authorizes a call.
command_catalog_permission:
    push rbx
    mov  ebx, edi
    call command_catalog_available
    test eax, eax
    jz   .absent
    mov  edi, ebx
    call command_catalog_row
    test qword [rax + CC_FLAGS], 4
    jnz  .owner_local
    mov  rdi, [rax + CC_TARGET]
    test rdi, rdi
    jz   .local
    lea  rdx, [rel command_catalog_table]
    add  rdi, rdx
    call command_lookup
    mov  edi, eax
    call command_auth_registry_id_is_public
    test eax, eax
    jz   .owner
    lea  rax, [rel cc_permission_public]
    jmp  .out
.owner:
    lea  rax, [rel cc_permission_owner]
    jmp  .out
.owner_local:
    lea  rax, [rel cc_permission_owner_local]
    jmp  .out
.local:
    lea  rax, [rel cc_permission_local]
    jmp  .out
.absent:
    lea  rax, [rel cc_permission_absent]
.out:
    pop  rbx
    ret

command_catalog_permission_short:
    call command_catalog_permission
    ; Short labels point into a parallel table, selected by exact static pointer.
    lea  rdx, [rel cc_permission_public]
    cmp  rax, rdx
    je   .public
    lea  rdx, [rel cc_permission_local]
    cmp  rax, rdx
    je   .local
    lea  rax, [rel cc_short_owner]
    ret
.public:
    lea  rax, [rel cc_short_public]
    ret
.local:
    lea  rax, [rel cc_short_local]
    ret

; Help's ninth page presents the SAME generated strings, including unavailable
; profile rows. Pure reads: five blocks per command plus four group headings.
cc_block_count:
    mov  eax, COMMAND_CATALOG_BLOCKS
    ret

; EDI=-1 title, 0..blocks-1 block -> RSI immutable cstr or zero. Preserves all
; registers except RAX/RSI (l10n painter ABI), including the live paint geometry.
cc_block_text:
    push rbx
    push rcx
    push rdx
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    mov  ebx, edi
    lea  rsi, [rel cc_title]
    cmp  edi, -1
    je   .out
    xor  esi, esi
    cmp  edi, COMMAND_CATALOG_BLOCKS
    jae  .out
    lea  rdx, [rel command_catalog_block_refs]
    mov  eax, [rdx + rbx * 4]
    test eax, eax
    js   .heading
    xor  edx, edx
    mov  ecx, 5
    div  ecx
    mov  r12d, eax
    mov  ebx, edx
    mov  edi, eax
    call command_catalog_row
    jmp  .field
.heading:
    not  eax                            ; -1..-4 -> group 0..3
    lea  rdx, [rel command_catalog_group_titles]
    mov  rsi, [rdx + rax * 8]
    lea  rdx, [rel command_catalog_table]
    add  rsi, rdx
    jmp  .out
.field:
    cmp  ebx, 2
    je   .permission
    ; Blocks: description, syntax, effective permission, example, handler note.
    lea  rdx, [rel cc_field_offsets]
    movzx edx, byte [rdx + rbx]
    mov  rsi, [rax + rdx]
    lea  rdx, [rel command_catalog_table]
    add  rsi, rdx
    jmp  .out
.permission:
    mov  edi, r12d
    call command_catalog_permission
    mov  rsi, rax
.out:
    mov  rax, rsi
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rdx
    pop  rcx
    pop  rbx
    ret

cc_title: db "Commands: live permissions; unavailable profile entries are marked. Read-only help examples inspect a command without running it.",0
cc_list_intro: db "Commands: HELP <word> for syntax, permission and example. HELP @paos|@linux|@ai|@guest",10,0
cc_usage: db "Usage: HELP [command | @decimal-cursor | @paos | @linux | @ai | @guest]",10,0
cc_unknown: db "Unknown command. Use HELP to list live commands.",10,0
cc_more: db "Next: HELP @",0
cc_end: db "End. HELP <word> describes one command. Session and handler guards still apply.",10,0
cc_newline: db 10,0
cc_sep: db " ",0
cc_short_public: db "[public]",0
cc_short_owner: db "[owner-authorized]",0
cc_short_local: db "[local]",0
cc_permission_public: db "Permission: public dispatch; session, input-origin and handler restrictions still apply.",0
cc_permission_owner: db "Permission: authorization required (owner/capability policy); session and handler restrictions still apply.",0
cc_permission_owner_local: db "Permission: local owner action; session, input-origin and confirmation restrictions apply.",0
cc_permission_local: db "Permission: local Terminal command; session and input-origin restrictions still apply.",0
cc_permission_absent: db "Permission: unavailable in this profile or unmapped; documentation grants no access.",0
cc_field_offsets: db CC_DESCRIPTION, CC_SYNTAX, 0, CC_EXAMPLE, CC_NOTE
align 8
cc_group_words: dq cc_word_paos-cc_group_words, cc_word_linux-cc_group_words, cc_word_ai-cc_group_words, cc_word_guest-cc_group_words
cc_word_paos: db "paos",0
cc_word_linux: db "linux",0
cc_word_ai: db "ai",0
cc_word_guest: db "guest",0

%include "core/abi/wdata.inc"
%macro WDATA_BSS_command_catalog 0
cc_query: resb 64
%endmacro
WDATA_BSS_DEFER WDATA_BSS_command_catalog
