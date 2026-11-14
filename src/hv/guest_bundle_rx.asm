;; MODULE hv/guest_bundle_rx
;; LAYER 5
;; PURPOSE Owner-armed one-shot receiver for a bundle a Terminal guest prints on hvc0.
;; EXPORTS gbr_arm, gbr_disarm, gbr_feed, gbr_tick, gbr_candidate
;; IMPORTS hv/terminal_console, core/heap, core/lib/sha256, core/smp, sec/session, core/time
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; hvc0 is the Terminal's own output: any program, or cat of a hostile file, can
; print these lines. Bytes here are untrusted and prove nothing about origin.
; Unarmed costs one compare per byte and holds no memory. An owner action arms
; one offer for one Terminal; the exit path only rings bytes. Parse, decode and
; hash run in the BSP tick. No verify, stage, card, grant or file from here:
; gbr_candidate hands a native caller hash-checked bytes, nothing more.
; Lines: PAOS_APP_BEGIN <len> <sha256hex> / PAOS_APP_DATA <offset> <hex> /
; PAOS_APP_END. Decimal has no leading zero, hex is lowercase, offsets are in
; order. Other lines are Terminal output and are ignored; a line with the prefix
; that breaks the grammar ends the arm. Every end state scrubs what was received
; here. The allocation stays for the next arm, and SHA-256 keeps block bytes in
; its own context: none of it is secret, the bytes came from the guest.
GBR_MAX equ 65536
GBR_RING equ 8192
GBR_LINE equ 640
GBR_CHUNK_HEX equ 512
GBR_BOUND_US equ 120000000
GBR_S_IDLE equ 0
GBR_S_WAIT equ 1
GBR_S_RECEIVING equ 2
GBR_S_READY equ 3
GBR_END_DISARM equ 1
GBR_END_DETACH equ 2
GBR_END_CONSOLE equ 3
GBR_END_OVERFLOW equ 4
GBR_END_LOCK equ 5
GBR_END_SESSION equ 6
GBR_END_EXPIRED equ 7
GBR_END_GRAMMAR equ 8
GBR_END_HASH equ 9

; RDI=Terminal window owner, ESI=its consumed START. EAX 1 armed, 0 refused.
gbr_arm:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13d,esi
    call smp_current_logical
    test eax,eax
    jnz .refuse
    cmp byte [rel gbr_state],GBR_S_IDLE
    jne .refuse
    mov rdi,r12
    mov esi,r13d
    call hv_terminal_matches
    cmp eax,1
    jne .refuse
    call session_shell_require_unlocked
    test eax,eax
    jnz .refuse
    mov rbx,[rel session_authority_epoch]
    test rbx,rbx
    jz .refuse
    cmp qword [rel session_bound_pid],PRIN_OWNER
    jne .refuse
    call time_monotonic_now_us
    test rax,rax
    jz .refuse
    add rax,GBR_BOUND_US
    jc .refuse
    mov [rel gbr_deadline],rax
    cmp qword [rel gbr_bytes],0
    jne .allocated
    mov edi,GBR_MAX+GBR_RING
    call kmalloc
    test rax,rax
    jz .refuse
    mov [rel gbr_bytes],rax
    mov rdi,rax                         ; kmalloc is not zeroed
    mov ecx,GBR_MAX+GBR_RING
    xor eax,eax
    cld
    rep stosb
.allocated:
    mov rax,[rel gbr_bytes]
    add rax,GBR_MAX
    mov [rel gbr_ring],rax
    mov [rel gbr_owner],r12
    mov [rel gbr_generation],r13d
    mov [rel gbr_session],rbx
    mov rax,[rel hv_vcon_epoch]
    mov [rel gbr_console],rax
    mov dword [rel gbr_last_end],0
    mov byte [rel gbr_state],GBR_S_WAIT
    mov byte [rel gbr_feed_on],1
    mov eax,1
    jmp .out
.refuse:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

gbr_disarm:
    cmp byte [rel gbr_state],GBR_S_IDLE
    je .out
    mov edi,GBR_END_DISARM
    jmp gbr_end
.out:
    ret

; AL=one validated hvc0 TX byte. Exit path: preserves all but flags, no parse.
gbr_feed:
    push rcx
    push rdx
    mov ecx,[rel gbr_count]
    cmp ecx,GBR_RING
    jae .over
    add ecx,[rel gbr_head]
    and ecx,GBR_RING-1
    mov rdx,[rel gbr_ring]
    mov [rdx+rcx],al
    inc dword [rel gbr_count]
    jmp .out
.over:
    mov byte [rel gbr_over],1
    mov byte [rel gbr_feed_on],0
.out:
    pop rdx
    pop rcx
    ret

; Idle BSP depth zero. Drains the ring; nothing here yields.
gbr_tick:
    cmp byte [rel gbr_state],GBR_S_IDLE
    je .idle
    cmp byte [rel cmd_in_dispatch],0
    jne .idle
    push rbx
    call smp_current_logical
    test eax,eax
    jnz .out
    call gbr_check
    test eax,eax
    jz .current
    mov edi,eax
    call gbr_end
    jmp .out
.current:
    cmp byte [rel gbr_state],GBR_S_READY
    je .out
    mov ebx,[rel gbr_count]
.next:
    test ebx,ebx
    jz .out
    dec ebx
    mov ecx,[rel gbr_head]
    mov rdx,[rel gbr_ring]
    movzx edi,byte [rdx+rcx]
    mov byte [rdx+rcx],0
    inc ecx
    and ecx,GBR_RING-1
    mov [rel gbr_head],ecx
    dec dword [rel gbr_count]
    call gbr_byte
    cmp byte [rel gbr_state],GBR_S_RECEIVING
    je .next
    cmp byte [rel gbr_state],GBR_S_WAIT
    je .next
.out:
    pop rbx
.idle:
    ret

; RAX=hash-checked bytes, RDX=length, only while the arm is still current.
; The caller copies; the bytes end with gbr_disarm or any later end state.
gbr_candidate:
    cmp byte [rel gbr_state],GBR_S_READY
    jne .none
    call smp_current_logical
    test eax,eax
    jnz .none
    call gbr_check
    test eax,eax
    jz .current
    mov edi,eax
    call gbr_end
.none:
    xor eax,eax
    xor edx,edx
    ret
.current:
    mov rax,[rel gbr_bytes]
    mov edx,[rel gbr_total]
    ret

; EAX 0 while the arm is current, else the end reason.
gbr_check:
    mov rdi,[rel gbr_owner]
    mov esi,[rel gbr_generation]
    call hv_terminal_matches
    cmp eax,1
    mov eax,GBR_END_DETACH
    jne .out
    mov rax,[rel hv_vcon_epoch]
    cmp rax,[rel gbr_console]
    mov eax,GBR_END_CONSOLE
    jne .out
    cmp byte [rel gbr_over],0
    mov eax,GBR_END_OVERFLOW
    jne .out
    call session_shell_require_unlocked
    test eax,eax
    mov eax,GBR_END_LOCK
    jnz .out
    mov rax,[rel session_authority_epoch]
    cmp rax,[rel gbr_session]
    mov eax,GBR_END_SESSION
    jne .out
    cmp qword [rel session_bound_pid],PRIN_OWNER
    jne .out
    call time_monotonic_now_us
    test rax,rax
    jz .expired
    cmp rax,[rel gbr_deadline]
    jae .expired
    xor eax,eax
    ret
.expired:
    mov eax,GBR_END_EXPIRED
.out:
    ret

; EDI=reason. Every end state: nothing armed, nothing received remains.
gbr_end:
    mov [rel gbr_last_end],edi
    mov byte [rel gbr_feed_on],0
    mov byte [rel gbr_state],GBR_S_IDLE
    mov rdi,[rel gbr_bytes]
    test rdi,rdi
    jz .fixed
    mov ecx,GBR_MAX+GBR_RING
    xor eax,eax
    cld
    rep stosb
.fixed:
    call gbr_scrub_line
    lea rdi,[rel gbr_expected]
    mov ecx,64
    xor eax,eax
    rep stosb
    mov dword [rel gbr_total],0
    mov dword [rel gbr_received],0
    mov byte [rel gbr_over],0
    ret

gbr_scrub_line:
    lea rdi,[rel gbr_line]
    mov ecx,GBR_LINE
    xor eax,eax
    cld
    rep stosb
    mov dword [rel gbr_head],0
    mov dword [rel gbr_count],0
    mov dword [rel gbr_pos],0
    mov byte [rel gbr_long],0
    mov byte [rel gbr_synced],0
    ret

; EDI=one drained byte. Text before the first newline predates the arm.
gbr_byte:
    cmp dil,10
    je .newline
    cmp byte [rel gbr_synced],0
    je .out
    mov eax,[rel gbr_pos]
    cmp eax,GBR_LINE
    jae .long
    lea rdx,[rel gbr_line]
    mov [rdx+rax],dil
    inc dword [rel gbr_pos]
    ret
.long:
    mov byte [rel gbr_long],1
.out:
    ret
.newline:
    cmp byte [rel gbr_synced],0
    jne .complete
    mov byte [rel gbr_synced],1
    ret
.complete:
    call gbr_parse
    cmp byte [rel gbr_state],GBR_S_RECEIVING
    je .fresh
    cmp byte [rel gbr_state],GBR_S_WAIT
    jne .out
.fresh:
    mov dword [rel gbr_pos],0
    mov byte [rel gbr_long],0
    ret

; One complete line in gbr_line. Only this namespace is parsed.
gbr_parse:
    push rbx
    push r12
    lea rbx,[rel gbr_line]
    mov r12d,[rel gbr_pos]
    test r12d,r12d
    jz .ignore
    cmp byte [rbx+r12-1],13             ; console line discipline's one CR
    jne .stripped
    dec r12d
.stripped:
    cmp r12d,9
    jb .ignore
    mov rdi,rbx
    lea rsi,[rel gbr_tag]
    mov ecx,9
    cld
    repe cmpsb
    jne .ignore
    cmp byte [rel gbr_long],0
    jne .grammar
    mov rdi,rbx
    lea rsi,[rel gbr_tag_end]
    mov ecx,12
    cmp r12d,12
    jne .not_end
    repe cmpsb
    je .end
.not_end:
    cmp r12d,15
    jb .grammar
    mov rdi,rbx
    lea rsi,[rel gbr_tag_begin]
    mov ecx,15
    repe cmpsb
    je .begin
    mov rdi,rbx
    lea rsi,[rel gbr_tag_data]
    mov ecx,14
    repe cmpsb
    je .data
.grammar:
    mov edi,GBR_END_GRAMMAR
    call gbr_end
.ignore:
    pop r12
    pop rbx
    ret
.begin:
    cmp byte [rel gbr_state],GBR_S_WAIT
    jne .grammar
    add rbx,15
    sub r12d,15
    call gbr_decimal
    jc .grammar
    test rax,rax
    jz .grammar
    cmp rax,GBR_MAX
    ja .grammar
    cmp r12d,65
    jne .grammar
    cmp byte [rbx],' '
    jne .grammar
    mov [rel gbr_total],eax
    lea rsi,[rbx+1]
    lea rdi,[rel gbr_expected]
    mov ecx,32
    call gbr_hex
    jc .grammar
    mov dword [rel gbr_received],0
    mov byte [rel gbr_state],GBR_S_RECEIVING
    jmp .ignore
.data:
    cmp byte [rel gbr_state],GBR_S_RECEIVING
    jne .grammar
    add rbx,14
    sub r12d,14
    call gbr_decimal
    jc .grammar
    cmp eax,[rel gbr_received]
    jne .grammar
    cmp r12d,3                          ; space + one hex pair
    jb .grammar
    cmp byte [rbx],' '
    jne .grammar
    inc rbx
    dec r12d
    test r12d,1
    jnz .grammar
    cmp r12d,GBR_CHUNK_HEX
    ja .grammar
    mov ecx,r12d
    shr ecx,1
    mov eax,[rel gbr_received]
    add eax,ecx
    cmp eax,[rel gbr_total]
    ja .grammar
    mov rdi,[rel gbr_bytes]
    mov edx,[rel gbr_received]
    add rdi,rdx
    mov rsi,rbx
    mov [rel gbr_received],eax
    call gbr_hex
    jc .grammar
    jmp .ignore
.end:
    cmp byte [rel gbr_state],GBR_S_RECEIVING
    jne .grammar
    mov eax,[rel gbr_received]
    cmp eax,[rel gbr_total]
    jne .grammar
    lea rdi,[rel gbr_digest]
    mov rsi,[rel gbr_bytes]
    mov edx,[rel gbr_total]
    call sha256_hash
    lea rdi,[rel gbr_digest]
    lea rsi,[rel gbr_expected]
    mov ecx,32
    cld
    repe cmpsb
    je .ready
    mov edi,GBR_END_HASH
    call gbr_end
    jmp .ignore
.ready:
    mov byte [rel gbr_feed_on],0        ; one offer: later output is only output
    mov byte [rel gbr_state],GBR_S_READY
    call gbr_scrub_line
    mov rdi,[rel gbr_ring]
    mov ecx,GBR_RING
    xor eax,eax
    rep stosb
    jmp .ignore

; RBX=cursor, R12D=remaining. RAX=value, CF on no digit, leading zero or more
; than 6 digits. Stops at the first non-digit.
gbr_decimal:
    xor eax,eax
    xor ecx,ecx
.digit:
    cmp ecx,r12d
    jae .done
    movzx edx,byte [rbx+rcx]
    sub edx,'0'
    cmp edx,9
    ja .done
    cmp ecx,6
    jae .bad
    imul eax,eax,10
    add eax,edx
    inc ecx
    jmp .digit
.done:
    test ecx,ecx
    jz .bad
    cmp ecx,1
    je .good
    cmp byte [rbx],'0'
    je .bad
.good:
    add rbx,rcx
    sub r12d,ecx
    clc
    ret
.bad:
    stc
    ret

; RSI=hex, RDI=out, ECX=bytes. CF on any byte not lowercase hex.
gbr_hex:
    test ecx,ecx
    jz .done
.pair:
    movzx eax,byte [rsi]
    call gbr_nibble
    jc .bad
    mov edx,eax
    shl edx,4
    movzx eax,byte [rsi+1]
    call gbr_nibble
    jc .bad
    or eax,edx
    mov [rdi],al
    add rsi,2
    inc rdi
    dec ecx
    jnz .pair
.done:
    clc
    ret
.bad:
    stc
    ret

gbr_nibble:
    sub eax,'0'
    cmp eax,9
    jbe .good
    sub eax,'a'-'0'
    cmp eax,5
    ja .bad
    add eax,10
.good:
    clc
    ret
.bad:
    stc
    ret

gbr_tag: db 'PAOS_APP_'
gbr_tag_begin: db 'PAOS_APP_BEGIN '
gbr_tag_data: db 'PAOS_APP_DATA '
gbr_tag_end: db 'PAOS_APP_END'
%include "core/abi/wdata.inc"
%macro WDATA_guest_bundle_rx 0
align 8
gbr_bytes: dq 0
gbr_ring: dq 0
gbr_owner: dq 0
gbr_session: dq 0
gbr_console: dq 0
gbr_deadline: dq 0
gbr_generation: dd 0
gbr_head: dd 0
gbr_count: dd 0
gbr_total: dd 0
gbr_received: dd 0
gbr_pos: dd 0
gbr_last_end: dd 0
gbr_state: db 0
gbr_feed_on: db 0
gbr_over: db 0
gbr_long: db 0
gbr_synced: db 0
gbr_expected: times 32 db 0
gbr_digest: times 32 db 0
gbr_line: times GBR_LINE db 0
%endmacro
WDATA_DEFER WDATA_guest_bundle_rx
