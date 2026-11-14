;; MODULE dev/usb/uac1_retire
;; LAYER 3
;; EXPORTS uac1_fs_retire
;; IMPORTS dev/usb/xhci, core/time
;; CAPS
;; OWNER rc-codex-av
; Explicit serialized native UAC1 retirement, after acknowledged HC STOP.
; RDI private activation receipt192B, RSI HC, RDX address, RCX generation,
; R8 original absolute us deadline, R9 trusted exact owner callback:
;   callback(receipt,HC,address,generation) ->0/-1, proving stopped and empty.
; Mapped stable native receipt/device/vtable/code spans are caller preconditions.
; Keep configuration/composite siblings. Never reset/retry/rollback uncertain I/O.
; Receipt reserved tail: +176 phase0fresh/1busy/2retired/3failed, +180 stage,
; +184 last monotonic time (seeded by the native adapter's last checked time).
uac1_fs_retire:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,72                     ; aligned callbacks: setup8,data8,topology16
 mov rbp,rsp
 mov r12,rdi
 mov rbx,rsi
 mov r13,rdx
 mov r14,rcx
 mov r15,r8
 mov [rbp+32],r9
 test rdi,rdi
 jz .invalid
 test dil,3
 jnz .invalid
 lea rax,[rdi+191]
 cmp rax,rdi
 jb .invalid
 shr rax,47
 jnz .invalid
 test rsi,rsi
 jz .invalid
 lea rax,[rsi+dev_size-1]
 cmp rax,rsi
 jb .invalid
 shr rax,47
 jnz .invalid
 lea rax,[rsi+dev_size]
 cmp rdi,rax
 jae .device_disjoint
 lea rax,[rdi+192]
 cmp rsi,rax
 jb .invalid
.device_disjoint:
 mov r11,[rbx+dev.ops]
 test r11,r11
 jz .invalid
 lea rax,[r11+usbhc_ops_size-1]
 cmp rax,r11
 jb .invalid
 shr rax,47
 jnz .invalid
 lea rax,[r11+usbhc_ops_size]
 cmp r12,rax
 jae .ops_disjoint
 lea rax,[r12+192]
 cmp r11,rax
 jb .invalid
.ops_disjoint:
 mov rax,[r11+usbhc_ops.control]
 mov [rbp+40],rax
 test rax,rax
 jz .invalid
 shr rax,47
 jnz .invalid
 mov rax,[r11+usbhc_ops.topology]
 mov [rbp+48],rax
 test rax,rax
 jz .invalid
 shr rax,47
 jnz .invalid
 test r9,r9
 jz .invalid
 shr r9,47
 jnz .invalid
 cmp r13,1
 jb .invalid
 cmp r13,255
 ja .invalid
 mov rax,r14
 shr rax,32
 jnz .invalid
 cmp r14d,-1
 je .invalid
 cmp dword [r12+128],15
 jne .invalid
 cmp dword [r12+136],1
 jne .invalid
 cmp rbx,[r12+144]
 jne .invalid
 cmp r13d,[r12+140]
 jne .invalid
 cmp r14d,[r12+152]
 jne .invalid
 cmp dword [r12],255            ; interface0 is valid
 ja .invalid
 cmp dword [r12+4],1
 jb .invalid
 cmp dword [r12+4],255
 ja .invalid
 cmp dword [r12+64],1
 jb .invalid
 cmp dword [r12+64],255
 ja .invalid
 call .owner                    ; foreign/reentrant request cannot claim receipt
 test rax,rax
 jnz .invalid
 xor eax,eax
 mov edx,1
 lock cmpxchg [r12+176],edx
 jne .invalid
 mov dword [r12+180],1
 ; GET_CONFIGURATION must still identify the activated composite function.
 mov qword [rbp],0
 mov word [rbp],0x0880
 mov word [rbp+6],1
 call .wire
 test eax,eax
 jnz .failed
 movzx eax,byte [rbp+8]
 cmp eax,[r12+64]
 jne .failed
 mov dword [r12+180],2
 call .get_interface
 test eax,eax
 jnz .failed
 movzx eax,byte [rbp+8]
 cmp eax,[r12+4]
 jne .failed
 mov dword [r12+180],3
 mov qword [rbp],0
 mov word [rbp],0x0b01
 mov eax,[r12]
 mov [rbp+4],ax
 call .wire
 test eax,eax
 jnz .failed
 mov dword [r12+180],4
 call .get_interface
 test eax,eax
 jnz .failed
 cmp byte [rbp+8],0
 jne .failed
 mov dword [r12+176],2
 xor eax,eax
 jmp .out
.failed:
 mov dword [r12+176],3
.invalid:
 mov rax,-1
.out:
 add rsp,72
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.owner:
 mov rdi,r12
 mov rsi,rbx
 mov rdx,r13
 mov rcx,r14
 jmp [rbp+32]
.get_interface:
 mov qword [rbp],0
 mov word [rbp],0x0a81
 mov eax,[r12]
 mov [rbp+4],ax
 mov word [rbp+6],1
 jmp .wire
.wire:
 sub rsp,8
 call .guard
 test eax,eax
 jnz .wire_out
 cmp word [rbp],0x0b01
 jne .read
 or dword [r12+132],16          ; submitted AS-alt0, including unknown ACK
.read:
 mov rdi,rbx
 lea rsi,[rbp]
 mov rdx,r13
 lea rcx,[rbp+8]
 movzx r8d,word [rbp+6]
 call [rbp+40]
 movzx edx,word [rbp+6]
 cmp rax,rdx                    ; exact complete reply only
 jne .wire_bad
 call .guard                    ; actual native clock AFTER every EP0 exchange
 jmp .wire_out
.wire_bad: mov eax,-1
.wire_out:
 add rsp,8
 ret
.guard:
 sub rsp,8
 call .time
 test eax,eax
 jnz .guard_out
 call .owner
 test rax,rax
 jnz .guard_bad
 mov rdi,rbx
 call xhci_hc_generation
 cmp eax,r14d
 jne .guard_bad
 mov rdi,rbx
 mov rsi,r13
 lea rdx,[rbp+16]
 call [rbp+48]
 test rax,rax
 jnz .guard_bad
 mov rax,[rbp+16]
 cmp rax,[r12+160]
 jne .guard_bad
 mov rax,[rbp+24]
 cmp rax,[r12+168]
 jne .guard_bad
 call .time                     ; same budget includes owner/topology callbacks
 jmp .guard_out
.guard_bad: mov eax,-1
.guard_out:
 add rsp,8
 ret
.time:
 sub rsp,8
 call time_monotonic_now_us
 cmp rax,[r12+184]
 jb .time_bad
 cmp rax,r15
 jae .time_bad
 mov rdx,r15
 sub rdx,rax
 cmp rdx,10000000               ; finite admission, no deadline renewal
 ja .time_bad
 mov [r12+184],rax
 xor eax,eax
 jmp .time_out
.time_bad: mov eax,-1
.time_out:
 add rsp,8
 ret
