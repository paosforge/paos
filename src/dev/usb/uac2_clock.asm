;; MODULE dev/usb/uac2_clock
;; LAYER 3
;; EXPORTS uac2_clock_request, uac2_frequency_select
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
; Pure UAC2 Clock Source controls. No IO, binding, allocation or live caller.
; USB-IF ADC2 (Sept2026) 4.7.2.1,5.2.1..3,5.2.5.1. Caller supplies stable
; mapped, disjoint native spans and owns function/terminal/speed provenance.
; Both functions preserve nonvolatiles and DF; output unchanged on refusal.
;
; request(RDI=8B descriptor,RSI=8,RDX=AC interface0..255,RCX=operation0..4,
; R8=operand,R9=16B result)->EAX0/-1. Result: setup8,payload4,operation4.
; 0 GET_RANGE count(operand0),1 GET_RANGE full(operand count1..32),
; 2 GET_CUR frequency(operand0),3 GET_CUR validity(operand0),
; 4 SET_CUR frequency(operand8k..192k, writable frequency control required).
; SET completion is not rate confirmation; caller must GET_CUR exact readback.
uac2_clock_request:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,16
 mov r12,rdi
 mov r13,r9
 mov rbp,rdx
 mov r14,rcx
 mov r15,r8
 test rdi,rdi
 jz .no
 cmp rsi,8
 jne .no
 mov eax,16
 call uac2_disjoint
 jc .no
 cmp rbp,255
 ja .no
 cmp r14,4
 ja .no
 cmp word [r12],0x2408
 jne .no
 cmp byte [r12+2],10               ; CLOCK_SOURCE
 jne .no
 cmp byte [r12+3],0
 je .no
 test byte [r12+4],0xf8
 jnz .no
 cmp byte [r12+4],4               ; External Clock cannot synchronize to SOF
 je .no
 movzx ebx,byte [r12+5]
 test ebx,0xf0
 jnz .no
 mov eax,ebx
 and eax,3
 cmp eax,2                        ; reserved access encoding
 je .no
 mov edx,ebx
 shr edx,2
 and edx,3
 cmp edx,1                        ; validity is absent or read-only
 ja .no
 xor eax,eax
 mov [rsp],rax
 mov [rsp+8],rax
 mov byte [rsp],0xa1              ; device-to-host/class/interface
 mov byte [rsp+1],1               ; CUR
 mov byte [rsp+3],1               ; sampling frequency, channel0
 movzx eax,byte [r12+3]
 shl eax,8
 or eax,ebp
 mov [rsp+4],ax                   ; entity in high byte, AC interface low
 mov word [rsp+6],4
 mov [rsp+12],r14d
 cmp r14,3
 je .validity
 test ebx,1                       ; frequency readable required
 jz .no
 cmp r14,4
 je .set
 cmp r14,2
 je .zero_operand
 mov byte [rsp+1],2               ; RANGE
 cmp r14,0
 je .range_count
 cmp r15,1
 jb .no
 cmp r15,32
 ja .no
 imul eax,r15d,12
 add eax,2
 mov [rsp+6],ax
 jmp .publish
.range_count:
 mov word [rsp+6],2
.zero_operand:
 test r15,r15
 jnz .no
 jmp .publish
.validity:
 cmp edx,1
 jne .no
 mov byte [rsp+3],2               ; clock validity, channel0
 mov word [rsp+6],1
 jmp .zero_operand
.set:
 and ebx,3
 cmp ebx,3
 jne .no
 cmp r15,8000
 jb .no
 cmp r15,192000
 ja .no
 mov byte [rsp],0x21              ; host-to-device/class/interface
 mov [rsp+8],r15d
.publish:
 mov rax,[rsp]
 mov rdx,[rsp+8]
 mov [r13],rax
 mov [r13+8],rdx
 xor eax,eax
 jmp .out
.no: mov eax,-1
.out:
 add rsp,16
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; select(RDI=complete Layout3 RANGE,RSI=actual bytes14..386,
; RDX=requested rate8k..192k,RCX=0,R8=0,R9=32B result)->EAX0/-1.
; Result u32: version1,count,index,rate,min,max,res,reserved0.
; Validate every subrange even after a match: unsigned ordered disjoint ranges,
; min<=max, singleton res0, non-singleton res>0. Selected delta % res ==0.
uac2_frequency_select:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,32
 mov r12,rdi
 mov r13,r9
 mov r14,rdx
 test rdi,rdi
 jz .no
 cmp rsi,14
 jb .no
 cmp rsi,386
 ja .no
 test rcx,rcx
 jnz .no
 test r8,r8
 jnz .no
 mov eax,32
 call uac2_disjoint
 jc .no
 cmp r14,8000
 jb .no
 cmp r14,192000
 ja .no
 movzx r15d,word [r12]
 cmp r15d,1
 jb .no
 cmp r15d,32
 ja .no
 imul eax,r15d,12
 add eax,2
 cmp rax,rsi
 jne .no
 mov dword [rsp],1
 mov [rsp+4],r15d
 mov dword [rsp+8],-1
 mov [rsp+12],r14d
 mov dword [rsp+28],0
 xor ebx,ebx
 xor ebp,ebp                      ; previous MAX, only used after first range
 lea rdi,[r12+2]
.scan:
 mov r8d,[rdi]
 mov r9d,[rdi+4]
 mov r10d,[rdi+8]
 cmp r8d,r9d
 ja .no
 test ebx,ebx
 jz .ordered
 cmp r8d,ebp
 jbe .no                          ; touching, overlapping or descending ranges
.ordered:
 mov ebp,r9d
 cmp r8d,r9d
 jne .nonsingle
 test r10d,r10d
 jnz .no
 jmp .membership
.nonsingle:
 test r10d,r10d
 jz .no
.membership:
 cmp r14d,r8d
 jb .next
 cmp r14d,r9d
 ja .next
 test r10d,r10d
 jz .matched
 mov eax,r14d
 sub eax,r8d
 xor edx,edx
 div r10d
 test edx,edx
 jnz .next
.matched:
 mov [rsp+8],ebx
 mov [rsp+16],r8d
 mov [rsp+20],r9d
 mov [rsp+24],r10d
.next:
 add rdi,12
 inc ebx
 cmp ebx,r15d
 jb .scan
 cmp dword [rsp+8],-1
 je .no
 mov rax,[rsp]
 mov rdx,[rsp+8]
 mov rcx,[rsp+16]
 mov r8,[rsp+24]
 mov [r13],rax
 mov [r13+8],rdx
 mov [r13+16],rcx
 mov [r13+24],r8
 xor eax,eax
 jmp .out
.no: mov eax,-1
.out:
 add rsp,32
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; RDI input,RSI size,R13 output,EAX out size. CF refusal; no dereference.
; Low canonical mapped spans are caller precondition; wrap/overlap rejected.
uac2_disjoint:
 mov r10,rdi
 add r10,rsi
 jc .bad
 mov r11,r10
 dec r11
 shr r11,47
 jnz .bad
 test r13,r13
 jz .bad
 mov r11,r13
 add r11,rax
 jc .bad
 mov rax,r11
 dec rax
 shr rax,47
 jnz .bad
 cmp rdi,r11
 jae .ok
 cmp r13,r10
 jb .bad
.ok: clc
 ret
.bad: stc
 ret
