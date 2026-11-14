;; MODULE dev/net/ax_lifecycle
;; LAYER 3
;; EXPORTS ax_lifecycle_capture, ax_lifecycle_poll, ax_lifecycle_descriptor_same
;; IMPORTS dev/usb/xhci, usb/enum, core/time
;; CAPS
;; OWNER saga:net
; Root-leaf class lifetime only. Caller holds its same runtime owner across
; status, exact once-only HC retirement and replacement wire bind. No register,
; controller reset, general scan, command authority or retry of uncertain work.
%include "dev/net/ax_lifecycle.inc"

; RDI=zeroed class storage,ESI=actual inventory index,RDX=registered member,
; RCX=class wire-bind callback,R8=fresh18B descriptor,R9=actual6B MAC.
; Initial capture is one-shot. Unsupported topology/controller leaves phase0.
ax_lifecycle_capture:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,32
    mov rbx,rdi
    mov r12d,esi
    test rdi,rdi
    jz .done
    cmp qword [rbx+ax_lifetime.incarnation],0
    jne .done
    mov [rsp],rdx
    mov [rsp+8],rcx
    mov [rsp+16],r8
    mov [rsp+24],r9
    test rdx,rdx
    jz .done
    test rcx,rcx
    jz .done
    test r8,r8
    jz .done
    test r9,r9
    jz .done
    mov edi,r12d
    call usb_dev_hc
    test rax,rax
    jz .done
    mov r13,rax
    mov r14,[rax+dev.ops]
    test r14,r14
    jz .done
    cmp qword [r14+usbhc_ops.port_status],0
    je .done
    mov edi,r12d
    call usb_dev_addr
    test eax,eax
    jz .done
    cmp eax,255
    ja .done
    mov r15d,eax
    mov edi,r12d
    call usb_dev_topo_ptr
    mov rdi,rax
    mov esi,r15d
    call ax_lifecycle_root_topo
    test eax,eax
    jz .done
    mov rdi,r13
    call xhci_hc_generation
    test eax,eax
    jz .done
    mov [rbx+ax_lifetime.generation],eax
    mov [rbx+ax_lifetime.hc],r13
    mov [rbx+ax_lifetime.ops],r14
    mov [rbx+ax_lifetime.root],r15d
    mov edi,r12d
    call usb_dev_topo_ptr
    mov rdx,[rax]
    mov [rbx+ax_lifetime.topo],rdx
    mov rdx,[rax+8]
    mov [rbx+ax_lifetime.topo+8],rdx
    mov rax,[rsp]
    mov [rbx+ax_lifetime.member],rax
    mov rax,[rsp+8]
    mov [rbx+ax_lifetime.bind],rax
    mov rax,[rsp+16]
    mov rdx,[rax]
    mov [rbx+ax_lifetime.descriptor],rdx
    mov rdx,[rax+8]
    mov [rbx+ax_lifetime.descriptor+8],rdx
    mov dx,[rax+16]
    mov [rbx+ax_lifetime.descriptor+16],dx
    mov rax,[rsp+24]
    mov edx,[rax]
    mov [rbx+ax_lifetime.mac],edx
    mov dx,[rax+4]
    mov [rbx+ax_lifetime.mac+4],dx
    mov qword [rbx+ax_lifetime.incarnation],1
    mov dword [rbx+ax_lifetime.phase],1
.done:
    add rsp,32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI=actual topology*,ESI=exact root; EAX1 valid root leaf,0 unsupported.
ax_lifecycle_root_topo:
    xor eax,eax
    test rdi,rdi
    jz .out
    cmp byte [rdi+usb_topo.slot],0
    je .out
    cmp [rdi+usb_topo.root],sil
    jne .out
    cmp byte [rdi+usb_topo.depth],0
    jne .out
    cmp dword [rdi+usb_topo.parent_slot],0
    jne .out
    cmp dword [rdi+usb_topo.route],0
    jne .out
    cmp word [rdi+usb_topo.hub_ports],0
    jne .out
    movzx edx,byte [rdi+usb_topo.speed]
    cmp edx,USB_SPEED_FULL
    je .yes
    cmp edx,USB_SPEED_HIGH
    je .yes
    cmp edx,USB_SPEED_SUPER
    jne .out
.yes:
    mov eax,1
.out:
    ret

; RDI=class storage. At most one status per second. Negative status is unknown.
ax_lifecycle_poll:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    test rdi,rdi
    jz .out
    mov eax,[rbx+ax_lifetime.phase]
    dec eax
    cmp eax,1
    ja .out
    call boot_ms_now
    cmp rax,[rbx+ax_lifetime.next_ms]
    jb .out
    add rax,1000
    jc .quarantine
    mov [rbx+ax_lifetime.next_ms],rax
    mov rdi,[rbx+ax_lifetime.hc]
    call xhci_hc_generation
    test eax,eax
    jz .quarantine
    cmp eax,[rbx+ax_lifetime.generation]
    jne .quarantine
    mov rdi,[rbx+ax_lifetime.hc]
    mov esi,[rbx+ax_lifetime.root]
    mov rax,[rbx+ax_lifetime.ops]
    call [rax+usbhc_ops.port_status]
    test rax,rax
    js .out
    test al,1
    jz .disconnected
    cmp dword [rbx+ax_lifetime.phase],2
    jne .out
    ; Spend the replacement offer BEFORE enumeration or class writes. A failed
    ; or uncertain refresh/bind is quarantined, never replayed on a timer.
    mov dword [rbx+ax_lifetime.phase],3
    cmp qword [rbx+ax_lifetime.incarnation],-1
    je .quarantine
    inc qword [rbx+ax_lifetime.incarnation]
    mov rdi,[rbx+ax_lifetime.hc]
    mov esi,[rbx+ax_lifetime.root]
    call usb_dev_refresh_root
    test eax,eax
    jz .quarantine
    lea r12d,[eax-1]
    mov edi,r12d
    call usb_dev_hc
    cmp rax,[rbx+ax_lifetime.hc]
    jne .quarantine
    mov edi,r12d
    call usb_dev_addr
    cmp eax,[rbx+ax_lifetime.root]
    jne .quarantine
    mov edi,r12d
    call usb_dev_desc_ptr
    test rax,rax
    jz .quarantine
    mov rdx,[rax]
    cmp rdx,[rbx+ax_lifetime.descriptor]
    jne .quarantine
    mov rdx,[rax+8]
    cmp rdx,[rbx+ax_lifetime.descriptor+8]
    jne .quarantine
    mov dx,[rax+16]
    cmp dx,[rbx+ax_lifetime.descriptor+16]
    jne .quarantine
    mov edi,r12d
    call usb_dev_topo_ptr
    mov r13,rax
    mov rdi,rax
    mov esi,[rbx+ax_lifetime.root]
    call ax_lifecycle_root_topo
    test eax,eax
    jz .quarantine
    ; Save actual new incarnation topology before any class transfer can fail.
    mov rax,[r13]
    mov [rbx+ax_lifetime.topo],rax
    mov rax,[r13+8]
    mov [rbx+ax_lifetime.topo+8],rax
    mov edi,r12d
    lea rsi,[rbx+ax_lifetime.mac]
    call [rbx+ax_lifetime.bind]
    test rax,rax
    jnz .quarantine
    ; Callback0 requires actual fresh descriptor/config/endpoints/chip state
    ; and unchanged original MAC. Registry membership is not repeated.
    mov rax,[rbx+ax_lifetime.member]
    mov dword [rax+dev.health],HEALTH_OK
    inc qword [rbx+ax_lifetime.rebound]
    mov dword [rbx+ax_lifetime.phase],1
    jmp .out
.disconnected:
    cmp dword [rbx+ax_lifetime.phase],1
    jne .out
    mov dword [rbx+ax_lifetime.phase],3 ; retained incarnation consumed once
    mov rax,[rbx+ax_lifetime.member]
    mov dword [rax+dev.health],HEALTH_DEAD
    mov rdi,[rbx+ax_lifetime.hc]
    mov esi,[rbx+ax_lifetime.root]
    mov edx,[rbx+ax_lifetime.generation]
    lea rcx,[rbx+ax_lifetime.topo]
    call xhci_device_root_retire
    test eax,eax
    jnz .quarantine
    inc qword [rbx+ax_lifetime.retired]
    mov dword [rbx+ax_lifetime.phase],2
    jmp .out
.quarantine:
    mov dword [rbx+ax_lifetime.phase],3
    mov rax,[rbx+ax_lifetime.member]
    test rax,rax
    jz .out
    mov dword [rax+dev.health],HEALTH_DEAD
    inc qword [rbx+ax_lifetime.refused]
.out:
    pop r13
    pop r12
    pop rbx
    ret

; RDI=class storage,RSI=complete fresh18B wire descriptor. No device operation.
ax_lifecycle_descriptor_same:
    xor eax,eax
    test rsi,rsi
    jz .out
    mov rdx,[rsi]
    cmp rdx,[rdi+ax_lifetime.descriptor]
    jne .out
    mov rdx,[rsi+8]
    cmp rdx,[rdi+ax_lifetime.descriptor+8]
    jne .out
    mov dx,[rsi+16]
    cmp dx,[rdi+ax_lifetime.descriptor+16]
    jne .out
    mov eax,1
.out:
    ret
