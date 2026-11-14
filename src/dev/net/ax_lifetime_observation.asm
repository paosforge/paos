;; MODULE dev/net/ax_lifetime_observation
;; LAYER 3
;; EXPORTS ax_lifetime_snapshot
;; IMPORTS dev/net/ax88179, dev/net/ax88179b, dev/usb/xhci
;; CAPS
;; OWNER saga:net
%include "dev/net/ax_lifecycle.inc"
; EDI=explicit backend0 legacy/1 exact0200,RSI=136B output. EAX=status:
; 0 actual registered class sample,1 absent/invalid,2 runtime owner busy.
; Failure output is zero except status/selector. No pointer leaves this API.
; Read-only under the exact same class owner as TX/RX/link/rebind; no polls,
; health changes, transfers, port writes, retries, clock or enumeration.
ax_lifetime_snapshot:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx,rsi
    mov r15d,edi
    test rsi,rsi
    jz .invalid_null
    mov rdi,rsi
    xor eax,eax
    mov ecx,17
    cld
    rep stosq
    mov dword [rbx],1
    mov [rbx+4],r15d
    cmp r15d,1
    ja .unavailable
    lea r14,[rel ax_io_busy]
    test r15d,r15d
    jz .acquire
    lea r14,[rel axb_busy]
.acquire:
    lock bts dword [r14],0
    jc .busy
    test r15d,r15d
    jnz .newer
    cmp byte [rel ax_present],1
    jne .release
    cmp dword [rel ax_reg_rc],0
    jl .release
    lea r13,[rel ax_dev]
    lea rax,[rel ax_ops]
    cmp [r13+dev.ops],rax
    jne .release
    lea r12,[rel ax_life]
    mov rdi,r13
    call ax88179_frame_stats
    test eax,eax
    jnz .release
    mov [rbx+56],rdx
    mov [rbx+64],rcx
    mov eax,[rel ax_mac]
    mov [rbx+72],eax
    mov ax,[rel ax_mac+4]
    mov [rbx+76],ax
    mov eax,[rel ax_devbuf+8]
    mov [rbx+80],eax
    movzx eax,word [rel ax_devbuf+12]
    mov [rbx+84],eax
    mov rdi,[rel ax_hc]
    movzx esi,byte [rel ax_port]
    jmp .common
.newer:
    cmp byte [rel axb_registered],1
    jne .release
    lea r13,[rel axb_dev]
    lea rax,[rel axb_ops]
    cmp [r13+dev.ops],rax
    jne .release
    lea r12,[rel axb_life]
    mov rdi,r13
    call ax88179b_frame_stats
    test eax,eax
    jnz .release
    mov [rbx+56],rdx
    mov [rbx+64],rcx
    mov eax,[rel axb_link]
    mov [rbx+72],eax
    mov ax,[rel axb_link+4]
    mov [rbx+76],ax
    mov eax,[rel axb_devbuf+8]
    mov [rbx+80],eax
    movzx eax,word [rel axb_devbuf+12]
    mov [rbx+84],eax
    mov rdi,[rel axb_hc]
    movzx esi,byte [rel axb_port]
.common:
    mov [rbx+16],esi
    lea rdx,[rbx+88]
    call xhci_readiness_snapshot
    mov eax,[r13+dev.health]
    mov [rbx+8],eax
    mov eax,[r12+ax_lifetime.phase]
    mov [rbx+12],eax
    mov eax,[r12+ax_lifetime.generation]
    mov [rbx+20],eax
    mov rax,[r12+ax_lifetime.incarnation]
    mov [rbx+24],rax
    mov rax,[r12+ax_lifetime.retired]
    mov [rbx+32],rax
    mov rax,[r12+ax_lifetime.rebound]
    mov [rbx+40],rax
    mov rax,[r12+ax_lifetime.refused]
    mov [rbx+48],rax
    movzx eax,byte [r12+ax_lifetime.topo+usb_topo.speed]
    mov [rbx+128],eax
    mov dword [rbx],0
.release:
    mov dword [r14],0
    mov eax,[rbx]
    jmp .out
.busy:
    mov dword [rbx],2
    mov eax,2
    jmp .out
.unavailable:
    mov eax,1
    jmp .out
.invalid_null:
    mov eax,1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
