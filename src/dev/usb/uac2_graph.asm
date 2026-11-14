;; MODULE dev/usb/uac2_graph
;; LAYER 3
;; EXPORTS uac2_clock_graph_parse
;; IMPORTS uac2_clock_request
;; CAPS
;; OWNER rc-codex-av
; Pure complete AC class-specific block, not config/function/terminal authority.
; RDI mapped block*, RSI9..4096, RDX selected Clock Entity ID1..255,
; RCX0,R8=0,R9 mapped disjoint64B output. EAX0/-1; refusal output unchanged.
; Namespace max64 entities, every clock chain <=32 entries ending at Clock Source.
; Single-input selectors only; multipliers require readable numerator/denominator.
uac2_clock_graph_parse:
 pushfq
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,704
 mov r12,rdi
 mov r13,rsi
 mov r14,r9
 mov r15,rdx
 test rcx,rcx
 jnz .no
 test r8,r8
 jnz .no
 test rdi,rdi
 jz .no
 cmp rsi,9
 jb .no
 cmp rsi,4096
 ja .no
 mov rax,rdi
 add rax,rsi
 jc .no
 mov rcx,rax
 dec rcx
 shr rcx,47
 jnz .no
 test r9,r9
 jz .no
 mov r10,r9
 add r10,64
 jc .no
 mov rcx,r10
 dec rcx
 shr rcx,47
 jnz .no
 cmp rdi,r10
 jae .disjoint
 cmp r9,rax
 jb .no
.disjoint:
 cmp r15,1
 jb .no
 cmp r15,255
 ja .no
 mov rdi,rsp
 xor eax,eax
 mov ecx,88
 cld
 rep stosq
 cmp dword [r12],0x00012409           ;9,CS_INTERFACE,HEADER,ADC low0
 jne .no
 cmp byte [r12+4],2                  ; bcdADC0200
 jne .no
 movzx eax,word [r12+6]
 cmp rax,r13
 jne .no
 movzx eax,byte [r12+8]
 cmp eax,3
 ja .no
 cmp eax,2
 je .no
 mov ebp,9
.map:
 cmp rbp,r13
 je .mapped
 lea rax,[rbp+4]
 cmp rax,r13
 ja .no
 movzx ecx,byte [r12+rbp]
 cmp ecx,4
 jb .no
 lea rax,[rbp+rcx]
 cmp rax,r13
 ja .no
 cmp byte [r12+rbp+1],0x24
 jne .no
 movzx edx,byte [r12+rbp+2]
 cmp edx,2
 jb .no
 cmp edx,13
 ja .no
 movzx edx,byte [r12+rbp+3]
 test edx,edx
 jz .no
 cmp word [rsp+rdx*2+64],0
 jne .no
 lea edx,[rbp+1]
 movzx esi,byte [r12+rbp+3]
 mov [rsp+rsi*2+64],dx                ; offset+1, all entity kinds share IDs
 inc dword [rsp+576]
 cmp dword [rsp+576],64
 ja .no
 add rbp,rcx
 jmp .map
.mapped:
 movzx eax,word [rsp+r15*2+64]
 test eax,eax
 jz .no
 mov ebx,1
.audit:
 cmp ebx,256
 je .walk_start
 movzx ebp,word [rsp+rbx*2+64]
 test ebp,ebp
 jz .audit_next
 dec ebp
 movzx eax,byte [r12+rbp+2]
 cmp eax,10
 je .audit_source
 cmp eax,11
 je .audit_selector
 cmp eax,12
 jne .audit_next                     ; non-clock payload semantics stay caller's
 cmp byte [r12+rbp],7
 jne .no
 cmp byte [r12+rbp+5],5              ; numerator + denominator read-only
 jne .no
 jmp .audit_next
.audit_selector:
 cmp byte [r12+rbp],8                ; exactly one input, no selection ambiguity
 jne .no
 cmp byte [r12+rbp+4],1
 jne .no
 movzx eax,byte [r12+rbp+6]
 cmp eax,3
 ja .no
 cmp eax,2
 je .no
 jmp .audit_next
.audit_source:
 cmp byte [r12+rbp],8
 jne .no
 lea rdi,[r12+rbp]
 mov esi,8
 xor edx,edx
 mov ecx,2                          ; readable frequency, validated CSD attributes
 xor r8d,r8d
 lea r9,[rsp+624]
 call uac2_clock_request
 test eax,eax
 jnz .no
 movzx edx,byte [r12+rbp+6]
 test edx,edx
 jz .audit_next
 movzx eax,word [rsp+rdx*2+64]
 test eax,eax
 jz .no
 dec eax
 cmp byte [r12+rax+2],2
 je .assoc_input
 cmp byte [r12+rax+2],3
 jne .no
 cmp byte [r12+rax],12
 jne .no
 jmp .audit_next
.assoc_input:
 cmp byte [r12+rax],17
 jne .no
.audit_next:
 inc ebx
 jmp .audit
.walk_start:
 mov ebx,1
.each_clock:
 cmp ebx,256
 je .publish
 movzx ebp,word [rsp+rbx*2+64]
 test ebp,ebp
 jz .next_clock
 dec ebp
 movzx eax,byte [r12+rbp+2]
 cmp eax,10
 jb .next_clock
 cmp eax,12
 ja .next_clock
 mov r8d,ebx                        ; current entity
 xor r10d,r10d                      ; path flags
 xor r11d,r11d                      ; bounded path length, no partial publication
.walk:
 cmp r11d,32
 jae .no
 test r8d,r8d
 jz .no
 movzx ebp,word [rsp+r8*2+64]
 test ebp,ebp
 jz .no
 dec ebp
 cmp ebx,r15d
 jne .path_saved
 mov [rsp+r11+32],r8b
.path_saved:
 inc r11d
 movzx eax,byte [r12+rbp+2]
 cmp eax,10
 je .root
 cmp eax,11
 je .selector
 cmp eax,12
 jne .no                            ; no terminal/unit can substitute a clock
 or r10d,2                          ; live multiplier CUR ratios still required
 movzx r8d,byte [r12+rbp+4]
 jmp .walk
.selector:
 or r10d,1
 movzx r8d,byte [r12+rbp+5]
 jmp .walk
.root:
 cmp ebx,r15d
 jne .next_clock
 mov dword [rsp],1
 mov [rsp+4],r15d
 mov [rsp+8],r8d
 mov [rsp+12],r11d
 mov [rsp+16],ebp
 mov [rsp+20],r13d
 mov eax,[rsp+576]
 mov [rsp+24],eax
 mov [rsp+28],r10d
.next_clock:
 inc ebx
 jmp .each_clock
.publish:
 cmp dword [rsp],1                  ; selected ID must itself be a clock
 jne .no
 mov rsi,rsp
 mov rdi,r14
 mov ecx,8
 cld
 rep movsq
 xor eax,eax
 jmp .out
.no:
 mov eax,-1
.out:
 add rsp,704
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 popfq
 ret
