;; MODULE dev/usb/uac2_function
;; LAYER 3
;; EXPORTS uac2_pcm16_function_parse
;; IMPORTS uac2_pcm16_stream_parse, uac2_clock_graph_parse
;; CAPS
;; OWNER rc-codex-av
; Pure complete config with exactly one two-interface UAC2 IAD, AC alt0,
; AS alt0 and one selected active alt. Direct Input->Output signal path only,
; no terminal controls/associations, no units except supported clock entities.
; RDI mapped config*, RSI9..4096, RDX ASif|alt<<8|IN<<16|HS<<17,
; RCX rate8k..192k,R8 channels1/2,R9 mapped disjoint224B output.
; Output stream96,declared clock64,provenance64. No IO/effective-clock authority.
; EAX0/-1, unchanged output on refusal; preserves nonvolatiles and DF.
uac2_pcm16_function_parse:
 pushfq
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,320
 mov r12,rdi
 mov r13,rsi
 mov r14,r9
 mov r15,rdx
 mov rbx,rcx
 mov rbp,r8
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
 add r10,224
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
 cmp r15,0x3ffff
 ja .no
 test r15d,0xff00
 jz .no
 cmp rbx,8000
 jb .no
 cmp rbx,192000
 ja .no
 cmp rbp,1
 jb .no
 cmp rbp,2
 ja .no
 cmp r13,90
 jb .no
 mov rdi,rsp
 xor eax,eax
 mov ecx,40
 cld
 rep stosq
 cmp word [r12],0x0209
 jne .no
 movzx eax,word [r12+2]
 cmp rax,r13
 jne .no
 cmp byte [r12+4],2
 jne .no
 cmp byte [r12+5],0
 je .no
 mov al,[r12+7]
 and al,0x9f
 cmp al,0x80
 jne .no
 cmp word [r12+9],0x0b08
 jne .no
 cmp byte [r12+12],2
 jne .no
 cmp word [r12+13],1
 jne .no
 cmp byte [r12+15],0x20
 jne .no
 movzx edx,byte [r12+11]
 cmp edx,254
 ja .no
 mov [rsp+224],edx                  ; AC interface
 inc edx
 cmp dl,r15b
 jne .no
 cmp word [r12+17],0x0409
 jne .no
 movzx eax,byte [r12+19]
 inc eax
 cmp eax,edx
 jne .no
 cmp word [r12+20],0
 jne .no
 cmp word [r12+22],0x0101
 jne .no
 cmp byte [r12+24],0x20
 jne .no
 cmp dword [r12+26],0x00012409
 jne .no
 cmp byte [r12+30],2
 jne .no
 movzx eax,word [r12+32]
 cmp eax,9
 jb .no
 mov [rsp+228],eax                  ; AC block length
 add eax,26
 mov [rsp+232],eax                  ; AS zero offset
 add eax,55                        ; zero9 + active46, no extra members
 cmp rax,r13
 jne .no
 mov ecx,[rsp+232]
 cmp word [r12+rcx],0x0409
 jne .no
 movzx eax,byte [r12+rcx+2]
 cmp eax,edx
 jne .no
 cmp word [r12+rcx+3],0
 jne .no
 cmp word [r12+rcx+5],0x0201
 jne .no
 cmp byte [r12+rcx+7],0x20
 jne .no
 add ecx,9
 mov [rsp+236],ecx                  ; selected AS offset
 movzx eax,byte [r12+rcx+2]
 cmp eax,edx
 jne .no
 mov eax,r15d
 shr eax,8
 cmp al,[r12+rcx+3]
 jne .no
 lea rdi,[r12+rcx]
 mov esi,46
 mov edx,r15d
 shr edx,17
 inc edx
 mov rcx,rbx
 mov r8,rbp
 mov r9,rsp
 call uac2_pcm16_stream_parse
 test eax,eax
 jnz .no
 mov eax,r15d
 shr eax,16
 and eax,1
 mov edx,[rsp+16]
 shr edx,7
 cmp edx,eax
 jne .no
 ; Walk bounded AC block; only two exact terminals and clock entities.
 mov ebx,35
.scan:
 cmp ebx,[rsp+232]
 je .scanned
 lea eax,[rbx+4]
 cmp eax,[rsp+232]
 ja .no
 movzx edx,byte [r12+rbx]
 cmp edx,4
 jb .no
 lea eax,[rbx+rdx]
 cmp eax,[rsp+232]
 ja .no
 cmp byte [r12+rbx+1],0x24
 jne .no
 movzx eax,byte [r12+rbx+2]
 cmp eax,2
 je .input
 cmp eax,3
 je .output
 cmp eax,10
 jb .no
 cmp eax,12
 ja .no
 jmp .next
.input:
 cmp edx,17
 jne .no
 cmp dword [rsp+240],0
 jne .no
 mov [rsp+240],ebx                  ; IT offset
 cmp byte [r12+rbx+6],0
 jne .no
 cmp word [r12+rbx+14],0
 jne .no
 movzx eax,byte [r12+rbx+8]
 cmp rax,rbp
 jne .no
 mov eax,[r12+rbx+9]
 cmp eax,[rsp+56]
 jne .no
 jmp .next
.output:
 cmp edx,12
 jne .no
 cmp dword [rsp+244],0
 jne .no
 mov [rsp+244],ebx                  ; OT offset
 cmp byte [r12+rbx+6],0
 jne .no
 cmp word [r12+rbx+9],0
 jne .no
.next:
 add ebx,edx
 jmp .scan
.scanned:
 mov ebx,[rsp+240]
 mov edx,[rsp+244]
 test ebx,ebx
 jz .no
 test edx,edx
 jz .no
 mov al,[r12+rbx+3]
 cmp al,[r12+rdx+7]                 ; actual direct signal edge IT -> OT
 jne .no
 mov al,[r12+rbx+7]
 cmp al,[r12+rdx+8]                 ; same declared clock entity
 jne .no
 movzx ecx,al
 mov [rsp+248],ecx
 test r15d,0x10000
 jnz .capture
 cmp word [r12+rbx+4],0x0101        ; USB streaming Input Terminal for OUT EP
 jne .no
 movzx eax,word [r12+rdx+4]
 cmp eax,0x0301
 jb .line_output
 cmp eax,0x0307
 jbe .play_types_ok
.line_output:
 cmp eax,0x0603
 jne .no
.play_types_ok:
 movzx eax,byte [r12+rbx+3]
 cmp eax,[rsp+12]
 jne .no
 mov [rsp+252],eax                  ; USB terminal
 movzx eax,byte [r12+rdx+3]
 mov [rsp+256],eax                  ; physical terminal
 jmp .clock
.capture:
 cmp word [r12+rdx+4],0x0101        ; USB streaming Output Terminal for IN EP
 jne .no
 movzx eax,word [r12+rbx+4]
 cmp eax,0x0201
 jb .line_input
 cmp eax,0x0206
 jbe .capture_types_ok
.line_input:
 cmp eax,0x0603
 jne .no
.capture_types_ok:
 movzx eax,byte [r12+rdx+3]
 cmp eax,[rsp+12]
 jne .no
 mov [rsp+252],eax
 movzx eax,byte [r12+rbx+3]
 mov [rsp+256],eax
.clock:
 lea rdi,[r12+26]
 mov esi,[rsp+228]
 mov edx,[rsp+248]
 xor ecx,ecx
 xor r8d,r8d
 lea r9,[rsp+96]
 call uac2_clock_graph_parse         ; complete namespace, every clock chain
 test eax,eax
 jnz .no
 mov dword [rsp+160],1
 movzx eax,byte [r12+5]
 mov [rsp+164],eax
 mov eax,[rsp+224]
 mov [rsp+168],eax
 movzx eax,r15b
 mov [rsp+172],eax
 mov eax,[rsp+8]
 mov [rsp+176],eax
 mov eax,r15d
 shr eax,16
 and eax,1
 mov [rsp+180],eax
 mov eax,[rsp+252]
 mov [rsp+184],eax
 mov eax,[rsp+256]
 mov [rsp+188],eax
 mov eax,[rsp+248]
 mov [rsp+192],eax
 mov dword [rsp+196],26
 mov eax,[rsp+236]
 mov [rsp+200],eax
 mov [rsp+204],r13d
 mov eax,[rsp+228]
 mov [rsp+208],eax
 mov eax,[rsp+224]
 mov [rsp+212],eax
 mov dword [rsp+216],2
 mov rsi,rsp
 mov rdi,r14
 mov ecx,28
 cld
 rep movsq
 xor eax,eax
 jmp .out
.no:
 mov eax,-1
.out:
 add rsp,320
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 popfq
 ret
