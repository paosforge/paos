;; MODULE dev/snd/hda_conn
;; LAYER 3
;; EXPORTS hda_conn_decode
;; IMPORTS dev/snd/hda_codec, dev/snd/hda_route
;; CAPS
;; OWNER rc-codex-av
;
; Classic0cabd75f hda_conn_entry packing, extended per Intel HDA1.0a sections
; 7.1.2,7.3.3.2-3,7.3.4.11: short entries are8 bits, long entries16 bits,
; low entry first. Length low7 bits is encoded entry count; bit7 is long form.
; A range endpoint pairs with the preceding ordinary entry; first/consecutive
; ranges and non-increasing endpoints refuse. Expanded selector indices are
; sequential input positions (not compressed GET_CONN offsets). No indirect
; NID addressing: reject long targets>127 without truncation.
; Pure attributed-reply bridge, no MMIO/commands/allocation/global state.
; Caller supplies complete/DONE widget and exact ordered attributed replies;
; this helper cannot authenticate hardware responses. Stable mapped serialized
; context/widget/reply/output spans must be pairwise disjoint.
;
; hda_conn_decode(RDI=context48) ->0 success, -1 malformed input/range/span or
; nonzero final padding, -2 unaddressable NID, -3 capacity, -4 expansion>256.
; <=127 encoded entries, <=256 expanded edges/8bit selector indices. Exact
; reply_count=ceil(raw_count/4) short or ceil(raw_count/2) long. Unused response
; bytes must be zero. All decoded targets are staged/validated before output.
; Ordinary short rows remain byte-compatible (reserved0). Long/range rows use
; reserved=HDA_EDGE_EXPANDED|expanded_count, consistent across the whole list;
; route planner uses it to check completeness against expanded selector indices.
; Only edge_count and expanded output rows change on success. All operands
; unchanged on refusal; unused capacity is not accessed. Empty lists permit
; poison unused reply/output pointers. SysV preserved GPRs/RSP, DF0 ABI.

struc hda_conn_context
 .widget: resq 1
 .replies: resq 1
 .reply_count: resq 1
 .edges: resq 1
 .edge_capacity: resq 1
 .edge_count: resq 1
endstruc

HDACN_STACK equ 344              ;64 span table +256 NIDs +24 locals
HDACN_COUNT equ 320
HDACN_RAW equ 324
HDACN_LONG equ 328
HDACN_RANGE equ 332

hda_conn_decode:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,HDACN_STACK
 mov r12,rdi
 test rdi,rdi
 jz hdacn_bad
 mov rax,rdi
 add rax,hda_conn_context_size
 jc hdacn_bad
 mov [rsp],rdi
 mov [rsp+8],rax
 mov r13,[r12+hda_conn_context.widget]
 test r13,r13
 jz hdacn_bad
 mov rax,r13
 add rax,hda_widget_info_size
 jc hdacn_bad
 mov [rsp+16],r13
 mov [rsp+24],rax
 mov ebx,[r13+hda_widget_info.conn_len]
 cmp ebx,255
 ja hdacn_bad
 mov eax,ebx
 and ebx,127
 and eax,128
 mov [rsp+HDACN_LONG],eax
 mov [rsp+HDACN_RAW],ebx
 mov dword [rsp+HDACN_RANGE],0
 test ebx,ebx
 jz .length_ok
 test dword [r13+hda_widget_info.caps],0x100
 jz hdacn_bad
.length_ok:
 cmp dword [r13+hda_widget_info.codec],15
 jae hdacn_bad
 mov eax,[r13+hda_widget_info.group]
 dec eax
 cmp eax,127
 jae hdacn_bad
 mov eax,[r13+hda_widget_info.nid]
 dec eax
 cmp eax,127
 jae hdacn_bad
 cmp dword [r13+hda_widget_info.reserved],0
 jne hdacn_bad
 lea eax,[rbx+3]
 shr eax,2
 cmp dword [rsp+HDACN_LONG],0
 je .reply_count
 lea eax,[rbx+1]
 shr eax,1
.reply_count:
 cmp rax,[r12+hda_conn_context.reply_count]
 jne hdacn_bad
 mov qword [rsp+32],0
 mov qword [rsp+40],0
 mov qword [rsp+48],0
 mov qword [rsp+56],0
 test ebx,ebx
 jz .source_spans
 mov r14,[r12+hda_conn_context.replies]
 test r14,r14
 jz hdacn_bad
 shl eax,2
 add rax,r14
 jc hdacn_bad
 mov [rsp+32],r14
 mov [rsp+40],rax
.source_spans:
 mov rdi,rsp
 call hdacn_disjoint
 jc hdacn_bad
 xor ebp,ebp
 xor r8d,r8d                    ;expanded count
 xor r9d,r9d                    ;preceding target
 xor r10d,r10d                  ;preceding range flag
.decode:
 cmp ebp,ebx
 jae .padding
 mov r11d,0x80
 cmp dword [rsp+HDACN_LONG],0
 jne .long_entry
 movzx eax,byte [r14+rbp]
 jmp .entry
.long_entry:
 movzx eax,word [r14+rbp*2]
 shl r11d,8
.entry:
 mov edx,eax
 lea ecx,[r11-1]
 and eax,ecx
 test eax,eax
 jz hdacn_bad
 cmp eax,127
 ja hdacn_unsupported
 test edx,r11d
 jz .ordinary
 test ebp,ebp
 jz hdacn_bad
 test r10d,r10d
 jnz hdacn_bad
 cmp eax,r9d
 jbe hdacn_bad
 mov dword [rsp+HDACN_RANGE],1
.range_loop:
 inc r9d
 cmp r8d,256
 jae hdacn_limit
 mov [rsp+r8+64],r9b
 inc r8d
 cmp r9d,eax
 jb .range_loop
 mov r10d,1
 jmp .next
.ordinary:
 cmp r8d,256
 jae hdacn_limit
 mov [rsp+r8+64],al
 inc r8d
 mov r9d,eax
 xor r10d,r10d
.next:
 inc ebp
 jmp .decode
.padding:
 mov [rsp+HDACN_COUNT],r8d
 test ebx,ebx
 jz .output_span
 mov eax,ebx
 cmp dword [rsp+HDACN_LONG],0
 je .padding_start
 shl eax,1
.padding_start:
 add rax,r14
.padding_loop:
 cmp rax,[rsp+40]
 jae .output_span
 cmp byte [rax],0
 jne hdacn_bad
 inc rax
 jmp .padding_loop
.output_span:
 mov ebx,[rsp+HDACN_COUNT]
 cmp [r12+hda_conn_context.edge_capacity],rbx
 jb hdacn_space
 test ebx,ebx
 jz .publish
 mov r15,[r12+hda_conn_context.edges]
 test r15,r15
 jz hdacn_bad
 imul rax,rbx,hda_route_edge_size
 add rax,r15
 jc hdacn_bad
 mov [rsp+48],r15
 mov [rsp+56],rax
 mov rdi,rsp
 call hdacn_disjoint
 jc hdacn_bad
.publish:
 xor r10d,r10d
 cmp dword [rsp+HDACN_LONG],0
 jne .expanded
 cmp dword [rsp+HDACN_RANGE],0
 je .emit_start
.expanded:
 mov r10d,ebx
 or r10d,HDA_EDGE_EXPANDED
.emit_start:
 xor ebp,ebp
.emit:
 cmp ebp,ebx
 jae .done
 mov eax,[r13+hda_widget_info.codec]
 mov [r15+hda_route_edge.codec],eax
 mov eax,[r13+hda_widget_info.group]
 mov [r15+hda_route_edge.group],eax
 mov eax,[r13+hda_widget_info.nid]
 mov [r15+hda_route_edge.node],eax
 mov [r15+hda_route_edge.index],ebp
 movzx eax,byte [rsp+rbp+64]
 mov [r15+hda_route_edge.target],eax
 mov [r15+hda_route_edge.reserved],r10d
 add r15,hda_route_edge_size
 inc ebp
 jmp .emit
.done:
 mov [r12+hda_conn_context.edge_count],rbx
 xor eax,eax
 jmp hdacn_return
hdacn_bad:
 mov rax,-1
 jmp hdacn_return
hdacn_unsupported:
 mov rax,-2
 jmp hdacn_return
hdacn_space:
 mov rax,-3
 jmp hdacn_return
hdacn_limit:
 mov rax,-4
hdacn_return:
 add rsp,HDACN_STACK
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; RDI=four bounded span pairs. CF=overlap; empty spans ignored.
hdacn_disjoint:
 xor ecx,ecx
.outer:
 mov r8,[rdi+rcx]
 mov r9,[rdi+rcx+8]
 cmp r8,r9
 je .next_outer
 lea edx,[rcx+16]
.inner:
 cmp edx,64
 jae .next_outer
 mov r10,[rdi+rdx]
 mov r11,[rdi+rdx+8]
 cmp r10,r11
 je .next_inner
 cmp r8,r11
 jae .next_inner
 cmp r10,r9
 jb .bad
.next_inner:
 add edx,16
 jmp .inner
.next_outer:
 add ecx,16
 cmp ecx,64
 jb .outer
 clc
 ret
.bad:
 stc
 ret
