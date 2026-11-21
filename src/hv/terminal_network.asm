;; MODULE hv/terminal_network
;; LAYER 6
;; PURPOSE Native bounded tools hostname DNS/TCP broker; no guest entry yet.
;; EXPORTS terminal_network_open, terminal_network_send, terminal_network_read, terminal_network_status, terminal_network_close, terminal_network_retire, terminal_network_tick
;; IMPORTS sec/terminal_network_gate, sec/terminal_network_session, core/smp, core/time, svc/command, net/dns, net/arp_cache, net/udp, net/tcp
;; OWNER saga:terminal_network
;; CONTEXT: bsp_only
;
; Native spans only, mapped/disjoint from private state. VM owns guest GPA
; copying and final copyout currentness. No device/verb exposes these entries.
; Before use, trusted init must configure session's immutable actual-tools and
; authenticated exact-host policy callbacks. Defaults NULL deny before DNS.
; Four independent original-cookie connections; no app/driver identity reuse.
;
; open(host,len,443)->handle/0; send(handle,bytes,len1..1024)->whole admitted
; count,0 busy,-1 fail; read(handle,out,cap1..1024)->bytes,0 pending,-1 failure,
; -2 EOF (out untouched). status(handle)->phase0invalid,1DNS,2route,3connecting,
; 4ClientHello,5draining,6stream,7retiring. close(handle)->1 retired/0 pending.
; Retire/tick are native BSP hooks, never requests or guest identity selectors.
TN_ID equ 0
TN_PHASE equ 8
TN_PEER equ 12
TN_ROUTE equ 16                      ; next-hop4,source4,cookie8
TN_TCP equ 32
TN_DEADLINE equ 40
TN_SNAPSHOT equ 48                   ; source4,gateway4,mask4,MAC6,pad6
TN_HOST equ 72
TN_HOSTLEN equ 328
TN_TXLEN equ 332
TN_TXOFF equ 336
TN_DNS_STARTED equ 340
TN_TX equ 344
TN_SIZE equ 1368
TN_COUNT equ 4
TN_DNS equ 1
TN_ROUTE_WAIT equ 2
TN_CONNECT equ 3
TN_HELLO equ 4
TN_DRAIN equ 5
TN_STREAM equ 6
TN_RETIRING equ 7
TN_START_US equ 10000000
TN_STREAM_US equ 1800000000           ; fixed30min, never refresh on traffic

%macro TN_CALL 1
    sub rsp,8
    call %1
    add rsp,8
%endmacro

tnb_local:
    cmp byte [rel cmd_in_dispatch],0
    jne .no
    cmp dword [rel cmd_dispatch_depth],0
    jne .no
    cmp byte [rel command_auth_remote_active],0
    jne .no
    TN_CALL smp_current_logical
    test eax,eax
    setz al
    movzx eax,al
    ret
.no:
    xor eax,eax
    ret

tnb_find:
    test rdi,rdi
    jz .no
    lea rax,[rel tnb_slots]
    mov ecx,TN_COUNT
.next:
    cmp rdi,[rax+TN_ID]
    je .out
    add rax,TN_SIZE
    loop .next
.no:
    xor eax,eax
.out:
    ret

; RBX original native slot. No stale policy/VM may authorize an effect.
tnb_current:
    sub rsp,8
    cmp dword [rbx+TN_PHASE],TN_RETIRING
    je .no
    mov rdi,[rbx+TN_ID]
    call terminal_network_session_current
    cmp eax,1
    jne .no
    call time_monotonic_now_us
    test rax,rax
    jz .no
    cmp rax,[rbx+TN_DEADLINE]
    jae .no
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    add rsp,8
    ret

; This broker conservatively excludes whole protocol/deprecated blocks, plus
; shared/benchmark/documentation space, beyond VM's private/LAN floor.
; IANA special registry, source linked in terminal_network_gate.md.
tnb_public_peer:
    mov r9d,eax
    bswap r9d
    and r9d,0xffc00000
    cmp r9d,0x64400000               ;100.64/10
    je .no
    mov r9d,eax
    bswap r9d
    and r9d,0xfffe0000
    cmp r9d,0xc6120000               ;198.18/15
    je .no
    mov r9d,eax
    bswap r9d
    and r9d,0xffffff00
    cmp r9d,0xc0000000               ;192.0.0/24, including global exceptions
    je .no
    cmp r9d,0xc0000200               ;192.0.2/24
    je .no
    cmp r9d,0xc0586300               ;192.88.99/24
    je .no
    cmp r9d,0xc6336400               ;198.51.100/24
    je .no
    cmp r9d,0xcb007100               ;203.0.113/24
    je .no
    jmp terminal_network_selected_peer
.no:
    xor eax,eax
    ret

; Current selected route must equal the original TCP route. No source-zero
; class preflight or stale DHCP snapshot becomes a later wire permission.
tnb_route_current:
    sub rsp,40
    mov rdi,rsp
    call dns_wire_route_snapshot
    test rax,rax
    jnz .no
    mov rax,[rsp]
    cmp rax,[rbx+TN_SNAPSHOT]
    jne .no
    mov eax,[rsp+8]
    cmp eax,[rbx+TN_SNAPSHOT+8]
    jne .no
    mov edx,[rsp]
    mov ecx,[rsp+8]
    mov eax,[rbx+TN_PEER]
    call tnb_public_peer
    jmp .out
.no:
    xor eax,eax
.out:
    add rsp,40
    ret

; Fence/wipe first, retain original TCP/cookie on try-lock busy. No current
; endpoint permission is necessary to finish cancelling that original cookie.
tnb_cancel:
    sub rsp,8
    mov dword [rbx+TN_PHASE],TN_RETIRING
    mov rdi,[rbx+TN_ID]
    call terminal_network_session_close
    lea rdi,[rbx+TN_TX]
    mov ecx,1024
    xor eax,eax
    cld
    rep stosb
    mov qword [rbx+TN_TXLEN],0
    cmp qword [rbx+TN_TCP],0
    je .clear
    mov rdi,[rbx+TN_TCP]
    mov rsi,[rbx+TN_ROUTE+8]
    xor edx,edx
    xor ecx,ecx
    mov r8d,2
    call tcp_client_io_owned
    cmp rax,-1
    je .pending
    ; -2: original no longer owns TCB. Every other return aborted original.
.clear:
    mov rdi,rbx
    mov ecx,TN_SIZE
    xor eax,eax
    rep stosb
    mov eax,1
    jmp .out
.pending:
    xor eax,eax
.out:
    add rsp,8
    ret

terminal_network_open:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13d,esi
    mov ebx,edx
    call tnb_local
    test eax,eax
    jz .no
    cmp ebx,443
    jne .no
    lea rbx,[rel tnb_slots]
    mov ecx,TN_COUNT
.free:
    cmp qword [rbx+TN_ID],0
    je .slot
    add rbx,TN_SIZE
    loop .free
    jmp .no
.slot:
    lea rdi,[rbx+TN_HOST]
    mov rsi,r12
    mov edx,r13d
    call terminal_network_host_canon
    test eax,eax
    js .clear
    mov [rbx+TN_HOSTLEN],eax
    mov rdi,r12
    mov esi,r13d
    mov edx,443
    call terminal_network_session_open
    test rax,rax
    jz .clear
    mov [rbx+TN_ID],rax
    mov dword [rbx+TN_PHASE],TN_DNS
    call time_monotonic_now_us
    test rax,rax
    jz .drop
    add rax,TN_START_US
    jc .drop
    mov [rbx+TN_DEADLINE],rax
    call tnb_current
    test eax,eax
    jz .drop
    mov rax,[rbx+TN_ID]
    jmp .out
.drop:
    call tnb_cancel
    jmp .no
.clear:
    mov rdi,rbx
    mov ecx,TN_SIZE
    xor eax,eax
    rep stosb
.no:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Caller input is copied completely before returning acceptance. No native
; TCP effect occurs here; a busy return has no uncertain send to replay.
terminal_network_send:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12,rsi
    mov r13d,edx
    call tnb_local
    test eax,eax
    jz .bad
    mov rdi,rbx
    call tnb_find
    test rax,rax
    jz .bad
    mov rbx,rax
    call tnb_current
    test eax,eax
    jz .drop
    test r12,r12
    jz .drop
    test r13d,r13d
    jz .drop
    cmp r13d,1024
    ja .drop
    cmp dword [rbx+TN_PHASE],TN_HELLO
    je .hello
    cmp dword [rbx+TN_PHASE],TN_STREAM
    jne .busy
    cmp dword [rbx+TN_TXLEN],0
    jne .busy
    lea rdi,[rbx+TN_TX]
    mov rsi,r12
    mov ecx,r13d
    cld
    rep movsb
    mov [rbx+TN_TXLEN],r13d
    mov dword [rbx+TN_TXOFF],0
    call tnb_current
    test eax,eax
    jz .drop
    mov eax,r13d
    jmp .out
.hello:
    mov rdi,[rbx+TN_ID]
    mov rsi,r12
    mov edx,r13d
    call terminal_network_session_stage
    cmp eax,r13d
    jne .drop
    mov rdi,[rbx+TN_ID]
    call terminal_network_session_phase
    test eax,eax
    jz .drop
    cmp eax,2                         ; SN_READY, exact complete SNI
    jne .accepted
    mov dword [rbx+TN_PHASE],TN_DRAIN
.accepted:
    mov eax,r13d
    jmp .out
.busy:
    xor eax,eax
    jmp .out
.drop:
    call tnb_cancel
.bad:
    mov eax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

terminal_network_status:
    push rbx
    mov rbx,rdi
    call tnb_local
    test eax,eax
    jz .out
    mov rdi,rbx
    call tnb_find
    test rax,rax
    jz .out
    mov rbx,rax
    cmp dword [rbx+TN_PHASE],TN_RETIRING
    je .phase
    call tnb_current
    test eax,eax
    jnz .phase
    call tnb_cancel
    xor eax,eax
    jmp .out
.phase:
    mov eax,[rbx+TN_PHASE]
.out:
    pop rbx
    ret

terminal_network_read:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    mov rbx,rdi
    mov r12,rsi
    mov r13d,edx
    call tnb_local
    test eax,eax
    jz .foreign
    mov rdi,rbx
    call tnb_find
    test rax,rax
    jz .bad
    mov rbx,rax
    call tnb_current
    test eax,eax
    jz .drop
    test r12,r12
    jz .bad
    test r13d,r13d
    jz .bad
    cmp r13d,1024
    ja .bad
    cmp dword [rbx+TN_PHASE],TN_STREAM
    jne .pending
    call tnb_route_current
    test eax,eax
    jz .drop
    call tnb_current
    test eax,eax
    jz .drop
    ; Native private staging, no direct guest/outer output consumption.
    mov rdi,[rbx+TN_TCP]
    mov rsi,[rbx+TN_ROUTE+8]
    lea rdx,[rel tnb_readbuf]
    mov ecx,r13d
    xor r8d,r8d
    call tcp_client_io_owned
    cmp rax,-1
    je .pending
    test rax,rax
    js .drop
    cmp edx,r13d
    ja .drop
    cmp eax,2
    je .read
    cmp eax,3                          ; LAST_ACK, drain before EOF
    jne .drop
    test edx,edx
    jnz .read
    call tnb_current
    test eax,eax
    jz .drop
    mov rdi,[rbx+TN_TCP]
    mov rsi,[rbx+TN_ROUTE+8]
    xor edx,edx
    xor ecx,ecx
    mov r8d,3                          ; actual ACK+detach; busy retains cookie
    call tcp_client_io_owned
    cmp rax,-1
    je .pending
    cmp rax,-2
    je .drop
    mov qword [rbx+TN_TCP],0
    call tnb_cancel
    mov eax,-2
    jmp .wipe
.read:
    mov r14d,edx
    call tnb_current
    test eax,eax
    jz .drop
    mov rdi,r12
    lea rsi,[rel tnb_readbuf]
    mov ecx,r14d
    cld
    rep movsb
    call tnb_current                   ; failed final native copyout wiped
    test eax,eax
    jnz .copied
    mov rdi,r12
    mov ecx,r14d
    xor eax,eax
    rep stosb
    jmp .drop
.copied:
    mov eax,r14d
    jmp .wipe
.pending:
    xor eax,eax
    jmp .wipe
.drop:
    call tnb_cancel
.bad:
    mov eax,-1
.wipe:
    mov r14d,eax
    lea rdi,[rel tnb_readbuf]
    mov ecx,1024
    xor eax,eax
    cld
    rep stosb
    mov eax,r14d
    jmp .out
.foreign:
    mov eax,-1
.out:
    add rsp,8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

terminal_network_close:
    push rbx
    mov rbx,rdi
    call tnb_local
    test eax,eax
    jz .out
    mov rdi,rbx
    call tnb_find
    test rax,rax
    jz .out
    mov rbx,rax
    call tnb_cancel
.out:
    pop rbx
    ret

terminal_network_retire:
    push rbx
    push r12
    sub rsp,8
    call tnb_local
    test eax,eax
    jz .out
    lea rbx,[rel tnb_slots]
    mov r12d,TN_COUNT
.next:
    cmp qword [rbx+TN_ID],0
    je .skip
    call tnb_cancel
.skip:
    add rbx,TN_SIZE
    dec r12d
    jnz .next
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; One bounded progress operation per slot per native tick. DNS resolver and
; TCP have independent native progress; no spin/poll/yield or guest callback.
terminal_network_tick:
    push rbx
    push r12
    sub rsp,8
    call tnb_local
    test eax,eax
    jz .out
    lea rbx,[rel tnb_slots]
    mov r12d,TN_COUNT
.next:
    cmp qword [rbx+TN_ID],0
    je .skip
    cmp dword [rbx+TN_PHASE],TN_RETIRING
    je .cancel
    call tnb_current
    test eax,eax
    jz .cancel
    call tnb_progress
    jmp .skip
.cancel:
    call tnb_cancel
.skip:
    add rbx,TN_SIZE
    dec r12d
    jnz .next
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

tnb_progress:
    sub rsp,24
    cmp dword [rbx+TN_PHASE],TN_DNS
    jne .route
    lea rdi,[rbx+TN_HOST]
    call dns_cache_get
    cmp eax,1
    je .address
    cmp eax,2
    je .fail
    cmp eax,6
    je .fail
    cmp eax,4
    jne .query
    cmp dword [rbx+TN_DNS_STARTED],1
    je .fail
.query:
    cmp dword [rbx+TN_DNS_STARTED],1
    je .out
    call tnb_current
    test eax,eax
    jz .fail
    lea rdi,[rbx+TN_HOST]
    call dns_resolve_start
    cmp eax,3
    je .started
    cmp eax,1
    je .out
    cmp eax,5
    je .out
    jmp .fail
.started:
    mov dword [rbx+TN_DNS_STARTED],1
    jmp .out
.address:
    mov [rbx+TN_PEER],edx
    mov dword [rbx+TN_PHASE],TN_ROUTE_WAIT
    jmp .out
.route:
    cmp qword [rbx+TN_TCP],0
    jne .connected
    cmp dword [rbx+TN_PHASE],TN_ROUTE_WAIT
    jb .out
    lea rdi,[rbx+TN_SNAPSHOT]
    call dns_wire_route_snapshot
    test rax,rax
    jnz .out
    mov eax,[rbx+TN_PEER]
    mov edx,[rbx+TN_SNAPSHOT]
    mov ecx,[rbx+TN_SNAPSHOT+8]
    call tnb_public_peer
    test eax,eax
    jz .fail
    mov eax,[rbx+TN_SNAPSHOT]
    mov [rbx+TN_ROUTE+4],eax
    mov eax,[rbx+TN_SNAPSHOT+4]        ; public peer cannot be on selected LAN
    test eax,eax
    jz .fail
    mov [rbx+TN_ROUTE],eax
    call tnb_current
    test eax,eax
    jz .fail
    mov edi,[rbx+TN_ROUTE]
    call arp_cache_lookup
    test rax,rax
    jnz .cookie
    cmp dword [rbx+TN_PHASE],TN_CONNECT
    je .out                           ; one bounded ARP, no repeated broadcasts
    call tnb_current
    test eax,eax
    jz .fail
    lea rdi,[rbx+TN_SNAPSHOT+12]
    mov esi,[rbx+TN_ROUTE+4]
    mov edx,[rbx+TN_ROUTE]
    lea rcx,[rel tnb_arp_frame]
    mov r8d,64
    call udp4_arp_request
    mov dword [rbx+TN_PHASE],TN_CONNECT
    jmp .out
.cookie:
    call tnb_current
    test eax,eax
    jz .fail
    cmp qword [rbx+TN_ROUTE+8],0
    jne .open
    call tcp_client_cookie_alloc
    test rax,rax
    jz .out
    mov [rbx+TN_ROUTE+8],rax
.open:
    call tnb_route_current            ; selected route immediately before TCP
    test eax,eax
    jz .fail
    call tnb_current
    test eax,eax
    jz .fail
    mov edi,[rbx+TN_PEER]
    mov esi,443
    mov edx,[rbx+TN_ROUTE+8]
    and edx,0x3fff
    add edx,49152
    xor ecx,ecx
    xor r8d,r8d
    lea r9,[rbx+TN_ROUTE]
    call tcp_client_open_routed
    cmp rax,-1
    je .out                           ; documented no attempt; retain cookie
    test rax,rax
    jz .fail
    mov [rbx+TN_TCP],rax
    mov dword [rbx+TN_PHASE],TN_CONNECT
    jmp .out
.connected:
    call tnb_route_current
    test eax,eax
    jz .fail
    call tnb_current
    test eax,eax
    jz .fail
    cmp dword [rbx+TN_PHASE],TN_CONNECT
    jne .send
    mov rdi,[rbx+TN_TCP]
    mov rsi,[rbx+TN_ROUTE+8]
    xor edx,edx
    xor ecx,ecx
    xor r8d,r8d
    call tcp_client_io_owned
    cmp rax,-1
    je .out
    cmp eax,4
    je .out
    cmp eax,2
    jne .fail
    mov dword [rbx+TN_PHASE],TN_HELLO
    jmp .out
.send:
    cmp dword [rbx+TN_PHASE],TN_DRAIN
    jne .stream
    mov rdi,[rbx+TN_ID]
    lea rsi,[rel tnb_sendbuf]
    mov edx,1024
    call terminal_network_session_copy
    test eax,eax
    jle .fail
    mov [rsp],eax
    lea rdx,[rel tnb_sendbuf]
    mov ecx,eax
    jmp .write
.stream:
    cmp dword [rbx+TN_PHASE],TN_STREAM
    jne .out
    cmp dword [rbx+TN_TXLEN],0
    je .out
    mov ecx,[rbx+TN_TXLEN]
    mov eax,[rbx+TN_TXOFF]
    sub ecx,eax
    lea rdx,[rbx+TN_TX]
    add rdx,rax
    mov [rsp],ecx
.write:
    mov [rsp+8],rdx
    call tnb_current                  ; before the actual owned TCP effect
    test eax,eax
    jz .fail
    mov rdx,[rsp+8]
    mov ecx,[rsp]
    mov rdi,[rbx+TN_TCP]
    mov rsi,[rbx+TN_ROUTE+8]
    mov r8d,1
    call tcp_client_io_owned
    cmp rax,-1
    je .wipe                          ; no accepted bytes
    cmp eax,2
    jne .fail
    cmp edx,[rsp]
    ja .fail
    test edx,edx
    jz .wipe
    mov [rsp],edx
    cmp dword [rbx+TN_PHASE],TN_DRAIN
    jne .advance_stream
    mov rdi,[rbx+TN_ID]
    mov esi,edx
    call terminal_network_session_advance
    cmp eax,1
    jne .fail                         ; never replay uncertain accepted bytes
    mov rdi,[rbx+TN_ID]
    call terminal_network_session_phase
    cmp eax,3
    jne .wipe
    call time_monotonic_now_us
    test rax,rax
    jz .fail
    add rax,TN_STREAM_US
    jc .fail
    mov [rbx+TN_DEADLINE],rax
    mov dword [rbx+TN_PHASE],TN_STREAM
    jmp .wipe
.advance_stream:
    mov eax,[rbx+TN_TXOFF]
    lea rdi,[rbx+TN_TX]
    add rdi,rax
    mov ecx,[rsp]
    xor eax,eax
    cld
    rep stosb
    mov eax,[rsp]
    add [rbx+TN_TXOFF],eax
    mov eax,[rbx+TN_TXOFF]
    cmp eax,[rbx+TN_TXLEN]
    jne .wipe
    mov qword [rbx+TN_TXLEN],0
    jmp .wipe
.fail:
    call tnb_cancel
.wipe:
    lea rdi,[rel tnb_sendbuf]
    mov ecx,1024
    xor eax,eax
    cld
    rep stosb
.out:
    add rsp,24
    ret

%include "core/abi/wdata.inc"
%macro WDATA_BSS_hv_terminal_network 0
alignb 8
tnb_slots: resb TN_SIZE*TN_COUNT
tnb_sendbuf: resb 1024
tnb_readbuf: resb 1024
tnb_arp_frame: resb 64
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_terminal_network
