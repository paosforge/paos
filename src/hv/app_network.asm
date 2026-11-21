;; MODULE hv/app_network
;; LAYER 5
;; PURPOSE App-private one-host DNS/TCP mediation, never a virtual NIC.
;; EXPORTS app_network_configure, app_network_retire, app_network_tick, app_network_pio, app_network_observe
;; IMPORTS hv/app_vm, hv/settings_update_service, core/smp, core/time, net/dns, net/tcp, net/arp_cache, net/udp
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
%include "hv/app_network.inc"
%include "hv/guest_destination.inc"
; One actual app VM exists. All pointers, bindings, routes and TCP custody are
; native. Linux supplies only a bounded host/port and opaque stream bytes.
; Policy callback: RDI actual snapshot128, RSI zeroed host256, EDX256,
; ECX original service port -> EAX1/RDX nonzero approval generation, else0.
; LIVE owns that callback and its exact current OWNER/account approval.
AN_IDLE equ 0
AN_DNS equ 1
AN_ARP equ 2
AN_CONNECT equ 3
AN_STREAM equ 4
AN_RETIRING equ 5

; Private helpers enter with RSP=8 mod16 and tail-dispatch without a frame.
; Pad their nested calls; exported framed functions use ordinary aligned CALL.
%macro AN_CALL 1
    sub rsp,8
    call %1
    add rsp,8
%endmacro

; Trusted native initialization only. Reconfiguration cannot abandon a TCB.
app_network_configure:
    push rbx
    mov rbx,rdi
    call an_local
    test eax,eax
    jz .bad
    cmp qword [rel an_handle],0
    jne .bad
    cmp dword [rel an_phase],AN_IDLE
    jne .bad
    mov [rel an_policy],rbx
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

an_local:
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    AN_CALL smp_current_logical
    test eax,eax
    setz al
    movzx eax,al
    ret
.bad:
    xor eax,eax
    ret

; Original app device retirement invalidates incomplete/unread wire bytes.
; Keep original handle/cookie through TCP try-lock backpressure. No policy or
; new app admission is necessary to finish retiring an already-owned TCB.
app_network_retire:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    sub rsp,8
    call an_wire_clear
    call an_cancel
    add rsp,8
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    ret

an_wire_clear:
    mov dword [rel an_receiving],0
    mov dword [rel an_received],0
    mov dword [rel an_expected],0
    mov dword [rel an_reply_bytes],0
    mov dword [rel an_cursor],0
    lea rdi,[rel an_request]
    xor eax,eax
    mov ecx,AN_MAX_FRAME*2/8
    cld
    rep stosq
    ret

an_cancel:
    mov dword [rel an_phase],AN_RETIRING
an_cleanup:
    cmp qword [rel an_handle],0
    je .clear
    mov rdi,[rel an_handle]
    mov rsi,[rel an_route+8]
    xor edx,edx
    xor ecx,ecx
    mov r8d,2
    AN_CALL tcp_client_io_owned
    cmp rax,-1
    je .pending
    ; -2 proves the original cookie no longer owns this slot. Never touch a
    ; replacement. Every other return completed the atomic original abort.
.clear:
    mov qword [rel an_handle],0
    lea rdi,[rel an_connection_begin]
    xor eax,eax
    mov ecx,(an_connection_end-an_connection_begin)/8
    cld
    rep stosq
    mov dword [rel an_phase],AN_IDLE
    mov eax,1
    ret
.pending:
    xor eax,eax
    ret

; Native current actual binding + canonical one-host approval. No guest ID.
an_authorized:
    mov rdi,[rel avm_instance]
    lea rsi,[rel an_current]
    mov edx,128
    AN_CALL app_vm_snapshot
    cmp eax,1
    jne .bad
    lea rdi,[rel an_current]
    lea rsi,[rel an_original]
    mov ecx,16
    cld
    repe cmpsq
    jne .bad
    lea rdi,[rel an_allowed]
    xor eax,eax
    mov ecx,32
    rep stosq
    lea rdi,[rel an_current]
    lea rsi,[rel an_allowed]
    mov edx,256
    mov ecx,[rel an_port]
    lea r8,[rel an_host]
    AN_CALL an_select_policy
    cmp eax,1
    jne .bad
    test rdx,rdx
    jz .bad
    cmp rdx,[rel an_approval]
    jne .bad
    mov rax,[rel an_evaluated_deadline]
    cmp rax,[rel an_fixed_deadline]
    jne .bad
    lea rdi,[rel an_allowed]
    lea rsi,[rel an_host]
    mov ecx,32
    cld
    repe cmpsq
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Runs from original BSP app_vm_tick even when the old VM is stopped. Native
; cancellation progresses independently of guest willingness to poll/close.
app_network_tick:
    push rbx
    call an_local
    test eax,eax
    jz .out
    cmp dword [rel an_phase],AN_IDLE
    je .out
    cmp dword [rel an_phase],AN_RETIRING
    je .cleanup
    call an_authorized
    test eax,eax
    jz .cancel
    call time_monotonic_now_us
    test rax,rax
    jz .cancel
    cmp rax,[rel an_deadline]
    jb .out
.cancel:
    call an_cancel
    jmp .out
.cleanup:
    call an_cleanup
.out:
    pop rbx
    ret

; Non-yielding, actual closed app-vCPU scalar dword exit only.
; EDI qualification, ESI EAX -> EAX claimed1/0, EDX IN value.
app_network_pio:
    push rbx
    push r12
    sub rsp,8
    mov ebx,edi
    mov r12d,esi
    call an_local
    test eax,eax
    jz .bad
    call app_vm_exit_endpoint
    test rax,rax
    jz .bad
    mov eax,ebx
    and eax,0xffbf
    cmp ax,3
    je .width
    cmp ax,11
    jne .bad
.width:
    mov rdi,[rel avm_instance]
    lea rsi,[rel an_current]
    mov edx,128
    call app_vm_snapshot
    cmp eax,1
    jne .invalidate
    mov rax,[rel an_current+56]
    cmp rax,[rel an_seen_instance]
    jb .invalidate
    je .same
    ; New actual instance may start a new sequence space, after invalidating
    ; only the old wire. Original TCP retirement remains separate custody.
    call an_wire_clear
    mov rax,[rel an_current+56]
    mov [rel an_seen_instance],rax
    mov qword [rel an_floor],0
    lea rdi,[rel an_wire_binding]
    lea rsi,[rel an_current]
    mov ecx,16
    cld
    rep movsq
.same:
    lea rdi,[rel an_wire_binding]
    lea rsi,[rel an_current]
    mov ecx,16
    cld
    repe cmpsq
    jne .invalidate
    mov eax,ebx
    shr eax,16
    cmp eax,AN_CONTROL
    je .control
    cmp eax,AN_DATA
    jne .bad
    test ebx,8
    jnz .read
    cmp dword [rel an_receiving],1
    jne .invalidate
    mov eax,[rel an_received]
    cmp eax,[rel an_expected]
    jae .invalidate
    lea rdx,[rel an_request]
    mov [rdx+rax],r12d
    add dword [rel an_received],4
    jmp .claimed
.control:
    test ebx,8
    jnz .length
    cmp r12d,1
    je .submit
    cmp r12d,AN_HEADER
    jb .invalidate
    cmp r12d,AN_MAX_FRAME
    ja .invalidate
    test r12d,3
    jnz .invalidate
    cmp dword [rel an_receiving],0
    jne .invalidate
    cmp dword [rel an_reply_bytes],0
    jne .invalidate
    call an_wire_clear
    mov [rel an_expected],r12d
    mov dword [rel an_receiving],1
    jmp .claimed
.submit:
    cmp dword [rel an_receiving],1
    jne .invalidate
    mov eax,[rel an_received]
    cmp eax,[rel an_expected]
    jne .invalidate
    mov dword [rel an_receiving],0
    mov dword [rel an_reply],AN_VERSION
    mov rax,[rel an_request+8]
    mov [rel an_reply+8],rax
    call an_request_run
    mov [rel an_reply+4],eax
    mov [rel an_last_status],rax
    mov [rel an_reply+20],edx
    add ecx,3
    and ecx,-4
    add ecx,AN_HEADER
    mov [rel an_reply_bytes],ecx
    lea rdi,[rel an_request]
    xor eax,eax
    mov ecx,AN_MAX_FRAME/8
    cld
    rep stosq
    jmp .claimed
.length:
    mov r12d,[rel an_reply_bytes]
    jmp .claimed
.read:
    mov eax,[rel an_cursor]
    cmp eax,[rel an_reply_bytes]
    jae .invalidate
    lea rdx,[rel an_reply]
    mov r12d,[rdx+rax]
    add eax,4
    mov [rel an_cursor],eax
    cmp eax,[rel an_reply_bytes]
    jb .claimed
    call an_wire_clear
.claimed:
    mov edx,r12d
    mov eax,1
    jmp .out
.invalidate:
    call app_network_retire
.bad:
    xor eax,eax
    xor edx,edx
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; Return status EAX, admitted/copied EDX, actual output body length ECX.
an_request_run:
    cmp dword [rel an_request],AN_VERSION
    jne an_fault
    cmp qword [rel an_request+24],0
    jne an_fault
    mov rax,[rel an_request+8]
    test rax,rax
    jz an_fault
    cmp rax,[rel an_floor]
    jbe an_fault
    mov [rel an_floor],rax             ; denied attempts burn their sequence
    mov eax,[rel an_request+4]
    cmp eax,AN_OPEN
    je an_open_shape
    cmp dword [rel an_request+16],0
    jne an_fault
    cmp eax,AN_SEND
    je an_send_shape
    cmp dword [rel an_expected],AN_HEADER
    jne an_fault
    cmp eax,AN_READ
    je an_read_shape
    cmp dword [rel an_request+20],0
    jne an_fault
    cmp eax,AN_CLOSE
    je an_close
    cmp eax,AN_STATUS
    je an_status
    jmp an_fault

an_open_shape:
    mov eax,[rel an_request+16]
    test eax,eax
    jz an_fault
    cmp eax,65535
    ja an_fault
    mov ecx,[rel an_request+20]
    test ecx,ecx
    jz an_fault
    cmp ecx,AN_HOST_MAX
    ja an_fault
    jmp an_body_shape
an_send_shape:
    mov ecx,[rel an_request+20]
    test ecx,ecx
    jz an_fault
    cmp ecx,AN_CAPACITY
    ja an_fault
an_body_shape:
    lea eax,[ecx+3]
    and eax,-4
    lea edx,[eax+AN_HEADER]
    cmp edx,[rel an_expected]
    jne an_fault
    lea rdx,[rel an_request+AN_HEADER]
.pad:
    cmp ecx,eax
    jae .valid
    cmp byte [rdx+rcx],0
    jne an_fault
    inc ecx
    jmp .pad
.valid:
    cmp dword [rel an_request+4],AN_OPEN
    je an_open
    jmp an_send
an_read_shape:
    mov ecx,[rel an_request+20]
    test ecx,ecx
    jz an_fault
    cmp ecx,AN_CAPACITY
    ja an_fault
    jmp an_read

; Canonicalize and validate independently of the Linux parser. No IP literal,
; URL, suffix match, wildcard, empty/trailing label or embedded NUL accepted.
an_host_copy:
    lea rdi,[rel an_candidate]
    xor eax,eax
    mov ecx,32
    cld
    rep stosq
    mov ecx,[rel an_request+20]
    xor r8d,r8d                     ; label length
    xor r9d,r9d                     ; ASCII letter seen
    xor r10d,r10d
    lea rdi,[rel an_candidate]
    lea rsi,[rel an_request+AN_HEADER]
.byte:
    mov al,[rsi+r10]
    cmp al,'A'
    jb .lower
    cmp al,'Z'
    ja .lower
    add al,32
.lower:
    cmp al,'.'
    je .dot
    cmp al,'a'
    jb .number
    cmp al,'z'
    ja .number
    mov r9d,1
    jmp .label
.number:
    cmp al,'0'
    jb .hyphen
    cmp al,'9'
    jbe .label
.hyphen:
    cmp al,'-'
    jne .bad
    test r8d,r8d
    jz .bad
.label:
    inc r8d
    cmp r8d,63
    ja .bad
    jmp .store
.dot:
    test r8d,r8d
    jz .bad
    cmp byte [rdi+r10-1],'-'
    je .bad
    xor r8d,r8d
.store:
    mov [rdi+r10],al
    inc r10d
    cmp r10d,ecx
    jb .byte
    test r8d,r8d
    jz .bad
    test r9d,r9d
    jz .bad
    cmp al,'-'
    je .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

an_open:
    cmp dword [rel an_phase],AN_IDLE
    jne an_busy
    AN_CALL an_host_copy
    test eax,eax
    jz an_deny
    ; Native current snapshot was obtained at this exact PIO submit exit.
    lea rdi,[rel an_allowed]
    xor eax,eax
    mov ecx,32
    cld
    rep stosq
    lea rdi,[rel an_current]
    lea rsi,[rel an_allowed]
    mov edx,256
    mov ecx,[rel an_request+16]
    lea r8,[rel an_candidate]
    AN_CALL an_select_policy
    cmp eax,1
    jne an_deny
    test rdx,rdx
    jz an_deny
    lea rdi,[rel an_allowed]
    lea rsi,[rel an_candidate]
    mov ecx,32
    cld
    repe cmpsq
    jne an_deny
    mov [rel an_approval],rdx
    mov rax,[rel an_evaluated_deadline]
    mov [rel an_fixed_deadline],rax
    AN_CALL time_monotonic_now_us
    test rax,rax
    jz an_failed
    cmp qword [rel an_fixed_deadline],0
    je .ordinary_deadline
    cmp rax,[rel an_fixed_deadline]
    jae an_failed
    mov rax,[rel an_fixed_deadline]
    jmp .deadline
.ordinary_deadline:
    add rax,10000000
    jc an_failed
.deadline:
    mov [rel an_deadline],rax
    lea rdi,[rel an_original]
    lea rsi,[rel an_current]
    mov ecx,16
    cld
    rep movsq
    lea rdi,[rel an_host]
    lea rsi,[rel an_candidate]
    mov ecx,32
    rep movsq
    mov eax,[rel an_request+16]
    mov [rel an_port],eax
    mov dword [rel an_phase],AN_DNS
    inc qword [rel an_opens]
    ; Public witness retains identity after cleanup; no native addresses.
    mov rax,[rel an_current+56]
    mov [rel an_witness_instance],rax
    mov rax,[rel an_current+24]
    mov [rel an_witness_start],rax
    lea rdi,[rel an_witness_digest]
    lea rsi,[rel an_current+64]
    mov ecx,4
    rep movsq
    jmp an_progress

an_public_peer:
    HV_GUEST_PUBLIC_IP

an_status:
    cmp dword [rel an_phase],AN_IDLE
    je an_fault
    cmp dword [rel an_phase],AN_RETIRING
    je an_busy
    AN_CALL an_authorized
    test eax,eax
    jz an_revoked
an_progress:
    AN_CALL time_monotonic_now_us
    test rax,rax
    jz an_failed
    cmp rax,[rel an_deadline]
    jae an_failed
    cmp dword [rel an_phase],AN_DNS
    jne .route
    lea rdi,[rel an_host]
    AN_CALL dns_cache_get               ; only cache_get supplies a valid A in EDX
    cmp eax,1
    je .address
    cmp eax,2
    je an_failed
    cmp eax,6
    je an_failed
    cmp eax,4
    jne .query
    cmp byte [rel an_dns_started],1
    je an_failed
.query:
    cmp byte [rel an_dns_started],1
    je an_pending
    lea rdi,[rel an_host]
    AN_CALL dns_resolve_start           ; status only, never consume scratch EDX
    cmp eax,3
    je .started
    cmp eax,1
    je an_pending                   ; cache_get next time
    cmp eax,5
    je an_pending                   ; no query admitted, retry later
    jmp an_failed
.started:
    mov byte [rel an_dns_started],1
    inc qword [rel an_queries]
    jmp an_pending
.address:
    mov [rel an_peer_ip],edx
    mov eax,edx
    xor edx,edx
    xor ecx,ecx
    AN_CALL an_public_peer
    test eax,eax
    jz an_failed
    mov edx,[rel an_peer_ip]
    mov [rel an_peer_ip],edx
    mov dword [rel an_phase],AN_ARP
.route:
    cmp dword [rel an_phase],AN_ARP
    jne .connect
    lea rdi,[rel an_route_snapshot]
    AN_CALL dns_wire_route_snapshot
    test rax,rax
    jnz an_pending
    mov edx,[rel an_route_snapshot]
    test edx,edx
    jz an_failed
    mov ecx,[rel an_route_snapshot+8]
    test ecx,ecx
    jz an_failed
    mov eax,[rel an_peer_ip]
    AN_CALL an_public_peer
    test eax,eax
    jz an_failed
    mov eax,[rel an_route_snapshot]
    mov [rel an_route+4],eax
    xor eax,[rel an_peer_ip]
    test eax,[rel an_route_snapshot+8]
    mov eax,[rel an_peer_ip]
    jz .next_hop
    mov eax,[rel an_route_snapshot+4]
.next_hop:
    test eax,eax
    jz an_failed
    mov [rel an_route],eax
    mov edi,eax
    AN_CALL arp_cache_lookup
    test rax,rax
    jnz .cookie
    ; One native ARP solicitation, bounded by the original OPEN deadline.
    cmp byte [rel an_arp_sent],1
    je an_pending
    lea rdi,[rel an_route_snapshot+12]
    mov esi,[rel an_route+4]
    mov edx,[rel an_route]
    lea rcx,[rel an_arp_frame]
    mov r8d,64
    AN_CALL udp4_arp_request
    mov byte [rel an_arp_sent],1
    jmp an_pending
.cookie:
    AN_CALL tcp_client_cookie_alloc    ; shared with DNS, not a private counter
    test rax,rax
    jz an_pending
    mov [rel an_route+8],rax
    mov dword [rel an_phase],AN_CONNECT
.connect:
    cmp dword [rel an_phase],AN_CONNECT
    jne .connected
    cmp qword [rel an_handle],0
    jne .state
    mov edi,[rel an_peer_ip]
    mov esi,[rel an_port]
    ; Bounded ephemeral choice; TCP atomically refuses any existing tuple.
    mov edx,[rel an_route+8]
    and edx,0x3fff
    add edx,49152
    xor ecx,ecx
    xor r8d,r8d
    lea r9,[rel an_route]
    AN_CALL tcp_client_open_routed
    cmp rax,-1
    je an_pending                  ; explicit no-attempt table backpressure
    test rax,rax
    jz an_failed
    mov [rel an_handle],rax
    inc qword [rel an_tcp_opens]
.state:
    mov rdi,[rel an_handle]
    mov rsi,[rel an_route+8]
    xor edx,edx
    xor ecx,ecx
    xor r8d,r8d
    AN_CALL tcp_client_io_owned
    cmp rax,-1
    je an_pending
    cmp eax,4                      ; SYN_SENT
    je an_pending
    cmp eax,2                      ; ESTABLISHED
    jne an_failed
    mov dword [rel an_phase],AN_STREAM
.connected:
    jmp an_ok

an_send:
    mov r8d,1
    lea rdx,[rel an_request+AN_HEADER]
    jmp an_stream
an_read:
    xor r8d,r8d
    lea rdx,[rel an_reply+AN_HEADER]
an_stream:
    push rdx
    push r8
    cmp dword [rel an_phase],AN_STREAM
    jne .bad
    AN_CALL an_authorized
    test eax,eax
    jz .revoked
    AN_CALL time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,[rel an_deadline]
    jae .bad
    pop r8
    pop rdx
    mov ecx,[rel an_request+20]
    mov rdi,[rel an_handle]
    mov rsi,[rel an_route+8]
    AN_CALL tcp_client_io_owned
    cmp rax,-1
    je an_busy
    test rax,rax
    js an_failed
    cmp edx,[rel an_request+20]
    ja an_failed
    cmp eax,2
    jne .eof
    mov r12d,AN_OK
    jmp .bytes
.eof:
    ; TCP_LAST_ACK=3 may still hold receive bytes for the original reader.
    ; Report EOF only after draining; a full read is not proof of empty RX.
    cmp dword [rel an_request+4],AN_READ
    jne an_failed
    cmp eax,3
    jne an_failed
    mov r12d,AN_EOF
    test edx,edx
    jz .bytes
    mov r12d,AN_OK
.bytes:
    push rdx
    call time_monotonic_now_us
    pop rdx
    cmp qword [rel an_fixed_deadline],0
    je .ordinary_refresh
    test rax,rax
    jz an_failed
    cmp rax,[rel an_fixed_deadline]
    jae an_failed
    jmp .count
.ordinary_refresh:
    add rax,10000000
    jc an_failed
    test edx,edx
    jz .count
    mov [rel an_deadline],rax
.count:
    xor ecx,ecx
    cmp dword [rel an_request+4],AN_READ
    jne .sent
    mov ecx,edx
    add [rel an_rx],rdx
    jmp .result
.sent:
    add [rel an_tx],rdx
.result:
    mov eax,r12d
    ret
.bad:
    pop r8
    pop rdx
    jmp an_failed
.revoked:
    pop r8
    pop rdx
    jmp an_revoked

an_close:
    AN_CALL an_cancel
    test eax,eax
    jz an_busy
an_ok:
    xor eax,eax
    jmp an_empty
an_busy:
    mov eax,AN_BUSY
    jmp an_empty
an_pending:
    mov eax,AN_PENDING
    jmp an_empty
an_deny:
    inc qword [rel an_denied]
    mov eax,AN_DENY
    jmp an_empty
an_revoked:
    AN_CALL an_cancel
    jmp an_deny
an_failed:
    AN_CALL an_cancel
an_fault:
    mov eax,AN_FAULT
an_empty:
    xor edx,edx
    xor ecx,ecx
    ret

; Native public observation only, no guest operation or policy setter. Exact
; 192B output has counters + actual instance/START/digest, never raw pointers,
; host/IP/TCP handles, stream bytes, account values or saved credentials.
app_network_observe:
    cmp esi,192
    jne .bad
    test rdi,rdi
    jz .bad
    mov r8,rdi
    xor eax,eax
    mov ecx,24
    cld
    rep stosq
    mov qword [r8],1
    mov rax,[rel an_witness_instance]
    mov [r8+8],rax
    mov rax,[rel an_witness_start]
    mov [r8+16],rax
    mov eax,[rel an_phase]
    mov [r8+24],rax
    mov rax,[rel an_opens]
    mov [r8+32],rax
    mov rax,[rel an_denied]
    mov [r8+40],rax
    mov rax,[rel an_queries]
    mov [r8+48],rax
    mov rax,[rel an_tcp_opens]
    mov [r8+56],rax
    mov rax,[rel an_tx]
    mov [r8+64],rax
    mov rax,[rel an_rx]
    mov [r8+72],rax
    mov rax,[rel an_last_status]
    mov [r8+80],rax
    mov rax,[rel an_approval]
    mov [r8+88],rax
    mov rax,[rel an_floor]
    mov [r8+96],rax
    xor eax,eax
    cmp qword [rel an_handle],0
    setne al
    mov [r8+104],rax
    xor eax,eax
    cmp dword [rel an_phase],AN_RETIRING
    sete al
    mov [r8+112],rax
    lea rdi,[r8+128]
    lea rsi,[rel an_witness_digest]
    mov ecx,4
    rep movsq
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

%include "hv/updater_network_policy.inc"

%unmacro AN_CALL 1

%include "core/abi/wdata.inc"
%macro WDATA_hv_app_network 0
align 8
an_policy: dq 0
an_evaluated_deadline: dq 0
an_seen_instance: dq 0
an_floor: dq 0
an_handle: dq 0
an_phase: dd 0
an_receiving: dd 0
an_received: dd 0
an_expected: dd 0
an_reply_bytes: dd 0
an_cursor: dd 0
an_opens: dq 0
an_denied: dq 0
an_queries: dq 0
an_tcp_opens: dq 0
an_tx: dq 0
an_rx: dq 0
an_last_status: dq 0
an_witness_instance: dq 0
an_witness_start: dq 0
an_witness_digest: times 32 db 0
an_wire_binding: times 128 db 0
an_current: times 128 db 0
an_candidate: times 256 db 0
an_allowed: times 256 db 0
an_request: times AN_MAX_FRAME db 0
an_reply: times AN_MAX_FRAME db 0
an_connection_begin:
an_original: times 128 db 0
an_host: times 256 db 0
an_route: times 16 db 0
an_route_snapshot: times 24 db 0
an_arp_frame: times 64 db 0
an_approval: dq 0
an_deadline: dq 0
an_fixed_deadline: dq 0
an_port: dd 0
an_peer_ip: dd 0
an_dns_started: db 0
an_arp_sent: db 0
times 6 db 0
an_connection_end:
%endmacro
WDATA_DEFER WDATA_hv_app_network
