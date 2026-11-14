;; MODULE dev/snd/hda_route
;; LAYER 3
;; EXPORTS hda_route_plan
;; IMPORTS dev/snd/hda_codec
;; CAPS
;; OWNER rc-codex-av
;
; Port Classic hda_route_pin_to_dac_mixer (0cabd75f8653ae3f8778ad0af51469a4f20adf25):
; search pin connections in index order for a mixer containing the chosen DAC.
; RC adds direct/selector paths, explicit codec+AFG identity, complete-list and
; typed-inventory checks. hda_conn_decode expands short/long range entries;
; marked rows carry the complete decoded list length and expanded selector
; index. Paths deeper than one mixer or selector remain unsupported.
; No codec verbs, MMIO, allocation or health
; claim. Returned indices are a plan; the owner still programs power, amps,
; connection selection, format and stream tag before starting output DMA.
;
; hda_route_plan(RDI=context64) ->0 plan, -1 invalid graph/span, -2 no supported
; route, -4 work limit. Stable mapped caller-owned context/widget/edge spans,
; pairwise disjoint and serialized. Inventory must be complete/DONE. Edges
; carry codec+AFG identity and decoded entries (NIDs1..127).
; Other codec/AFG rows are ignored. Selected pin and candidate intermediate
; lists must be complete; duplicate indices and cross-scope targets refuse.
; All operands unchanged on refusal; only outputs48..63 change on success.
; Stereo analog output only. At most1905 widgets,2048 edges,256 connections
; per decoded list. Raw descriptor length remains <=127 plus long bit.
; Search is fixed-depth/bounded, not a scheduler grant.
; SysV preserved GPRs/RSP, no FP/global state; DF=0 ABI.

struc hda_route_edge
 .codec: resd 1
 .group: resd 1
 .node: resd 1
 .index: resd 1
 .target: resd 1
 .reserved: resd 1                 ;0 ordinary short, or EXPANDED|decoded count
endstruc
struc hda_route_context
 .widgets: resq 1
 .widget_count: resq 1
 .edges: resq 1
 .edge_count: resq 1
 .codec: resd 1
 .group: resd 1
 .pin: resd 1
 .dac: resd 1
 .middle: resd 1
 .pin_index: resd 1
 .middle_index: resd 1
 .kind: resd 1                      ;0 direct,1 mixer,2 selector
endstruc
HDA_EDGE_EXPANDED equ 0x80000000
HDARP_COUNTS equ 1024                ;128 expected u16 counts (bit15=marked)
HDARP_SEEN equ 1280                  ;128 observed u16 counts
HDARP_MASKS equ 1536                 ;128 256bit selector masks
HDARP_PIN_COUNT equ 5632
HDARP_PIN_INDEX equ 5636
HDARP_MIDDLE equ 5640
HDARP_WIDGET_END equ 5656
HDARP_EDGE_END equ 5664
HDARP_STACK equ 5672

hda_route_plan:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,HDARP_STACK
 mov r12,rdi
 test r12,r12
 jz hdarp_bad
 mov rbx,r12
 add rbx,hda_route_context_size
 jc hdarp_bad
 cmp dword [r12+hda_route_context.codec],15
 jae hdarp_bad
 mov eax,[r12+hda_route_context.group]
 dec eax
 cmp eax,126
 ja hdarp_bad
 mov eax,[r12+hda_route_context.pin]
 dec eax
 cmp eax,126
 ja hdarp_bad
 mov eax,[r12+hda_route_context.dac]
 dec eax
 cmp eax,126
 ja hdarp_bad
 mov rax,[r12+hda_route_context.widget_count]
 test rax,rax
 jz hdarp_bad
 cmp rax,1905
 ja hdarp_limit
 shl rax,5                         ;accepted hda_widget_info size32
 mov r13,[r12+hda_route_context.widgets]
 test r13,r13
 jz hdarp_bad
 add rax,r13
 jc hdarp_bad
 mov [rsp+HDARP_WIDGET_END],rax
 cmp r13,rbx
 jae .widgets_context_ok
 cmp r12,rax
 jb hdarp_bad
.widgets_context_ok:
 mov r15,[r12+hda_route_context.edge_count]
 cmp r15,2048
 ja hdarp_limit
 mov r14,[r12+hda_route_context.edges]
 mov rdx,r14
 test r15,r15
 jz .edges_ok
 test r14,r14
 jz hdarp_bad
 imul rax,r15,hda_route_edge_size
 add rdx,rax
 jc hdarp_bad
 cmp r14,rbx
 jae .edges_context_ok
 cmp r12,rdx
 jb hdarp_bad
.edges_context_ok:
 cmp r14,[rsp+HDARP_WIDGET_END]
 jae .edges_ok
 cmp r13,rdx
 jb hdarp_bad
.edges_ok:
 mov [rsp+HDARP_EDGE_END],rdx
 mov rdi,rsp
 xor eax,eax
 mov ecx,HDARP_PIN_COUNT/8
 rep stosq                         ;private NID map and complete-list masks
.widget:
 cmp r13,[rsp+HDARP_WIDGET_END]
 jae .pin_dac
 mov eax,[r13+hda_widget_info.codec]
 cmp eax,[r12+hda_route_context.codec]
 jne .next_widget
 mov eax,[r13+hda_widget_info.group]
 cmp eax,[r12+hda_route_context.group]
 jne .next_widget
 mov eax,[r13+hda_widget_info.nid]
 lea edx,[rax-1]
 cmp edx,126
 ja hdarp_bad
 cmp qword [rsp+rax*8],0
 jne hdarp_bad
 mov [rsp+rax*8],r13
.next_widget:
 add r13,hda_widget_info_size
 jmp .widget
.pin_dac:
 mov r13d,[r12+hda_route_context.pin]
 mov rbx,[rsp+r13*8]
 test rbx,rbx
 jz hdarp_bad
 mov eax,[rbx+hda_widget_info.caps]
 and eax,0xF00201                ; widget type, Digital I/O (must be clear), stereo
 cmp eax,0x400001
 jne hdarp_no_route
 test dword [rbx+hda_widget_info.pin_caps],0x10
 jz hdarp_no_route
 mov eax,[rbx+hda_widget_info.config]
 mov edx,eax
 shr edx,20
 and edx,15
 cmp edx,2                         ;Classic analog line-out/speaker/headphone
 ja hdarp_no_route
 shr eax,30
 cmp eax,1
 je hdarp_no_route
 mov eax,[r12+hda_route_context.dac]
 mov rdx,[rsp+rax*8]
 test rdx,rdx
 jz hdarp_bad
 mov eax,[rdx+hda_widget_info.caps]
 and eax,0xF00201                ; widget type, Digital I/O (must be clear), stereo
 cmp eax,1
 jne hdarp_no_route
 mov eax,[rbx+hda_widget_info.conn_len]
 cmp eax,255
 ja hdarp_bad
 and eax,127
 test eax,eax
 jz hdarp_no_route
 mov rdi,r14
.edge:
 cmp rdi,[rsp+HDARP_EDGE_END]
 jae .complete_pin
 mov eax,[rdi+hda_route_edge.codec]
 cmp eax,[r12+hda_route_context.codec]
 jne .next_edge
 mov eax,[rdi+hda_route_edge.group]
 cmp eax,[r12+hda_route_context.group]
 jne .next_edge
 mov r8d,[rdi+hda_route_edge.node]
 lea eax,[r8-1]
 cmp eax,126
 ja hdarp_bad
 mov r9,[rsp+r8*8]
 test r9,r9
 jz hdarp_bad
 mov edx,[r9+hda_widget_info.conn_len]
 cmp edx,255
 ja hdarp_bad
 mov r10d,edx
 and edx,127
 test edx,edx
 jz hdarp_bad
 mov eax,[rdi+hda_route_edge.reserved]
 test eax,eax
 jnz .expanded_count
 test r10d,128                   ;long rows require explicit decoded count
 jnz hdarp_bad
 jmp .list_count
.expanded_count:
 mov r11d,eax
 and r11d,0xFFFFFE00
 cmp r11d,HDA_EDGE_EXPANDED
 jne hdarp_bad
 and eax,0x1FF
 cmp eax,256
 ja hdarp_bad
 cmp eax,edx
 jb hdarp_bad
 cmp edx,1                      ;one encoded entry cannot expand a range
 jne .count_ok
 cmp eax,1
 jne hdarp_bad
.count_ok:
 mov edx,eax
 or edx,0x8000
.list_count:
 cmp word [rsp+HDARP_COUNTS+r8*2],0
 jne .same_count
 mov [rsp+HDARP_COUNTS+r8*2],dx
.same_count:
 cmp dx,[rsp+HDARP_COUNTS+r8*2]
 jne hdarp_bad
 and edx,0x7FFF
 mov ecx,[rdi+hda_route_edge.index]
 cmp ecx,edx
 jae hdarp_bad
 mov eax,r8d
 shl eax,5
 bts qword [rsp+rax+HDARP_MASKS],rcx
 jc hdarp_bad
 inc word [rsp+HDARP_SEEN+r8*2]
 mov eax,[rdi+hda_route_edge.target]
 lea edx,[rax-1]
 cmp edx,126
 ja hdarp_bad
 cmp qword [rsp+rax*8],0
 je hdarp_bad
.next_edge:
 add rdi,hda_route_edge_size
 jmp .edge
.complete_pin:
 movzx eax,word [rsp+HDARP_COUNTS+r13*2]
 and eax,0x7FFF
 test eax,eax
 jz hdarp_bad
 cmp ax,[rsp+HDARP_SEEN+r13*2]
 jne hdarp_bad
 mov [rsp+HDARP_PIN_COUNT],eax
 mov dword [rsp+HDARP_PIN_INDEX],0
.pin_index:
 mov rdi,r14
.find_pin_edge:
 cmp rdi,[rsp+HDARP_EDGE_END]
 jae hdarp_bad                     ;complete mask guaranteed an edge
 mov eax,[rdi+hda_route_edge.codec]
 cmp eax,[r12+hda_route_context.codec]
 jne .next_pin_edge
 mov eax,[rdi+hda_route_edge.group]
 cmp eax,[r12+hda_route_context.group]
 jne .next_pin_edge
 cmp [rdi+hda_route_edge.node],r13d
 jne .next_pin_edge
 mov eax,[rdi+hda_route_edge.index]
 cmp eax,[rsp+HDARP_PIN_INDEX]
 jne .next_pin_edge
 mov eax,[rdi+hda_route_edge.target]
 cmp eax,[r12+hda_route_context.dac]
 je .direct
 mov r11,[rsp+rax*8]
 mov edx,[r11+hda_widget_info.caps]
 test edx,1
 jz .next_pin_index
 shr edx,20
 and edx,15
 sub edx,2
 cmp edx,1
 ja .next_pin_index
 mov [rsp+HDARP_MIDDLE],r11
 mov ecx,[r11+hda_widget_info.conn_len]
 and ecx,127
 test ecx,ecx
 jz .next_pin_index
 mov ecx,[r11+hda_widget_info.nid]
 movzx edx,word [rsp+HDARP_COUNTS+rcx*2]
 and edx,0x7FFF
 test edx,edx
 jz hdarp_bad
 cmp dx,[rsp+HDARP_SEEN+rcx*2]
 jne hdarp_bad
 mov r8d,-1
 mov rsi,r14
.middle_edge:
 cmp rsi,[rsp+HDARP_EDGE_END]
 jae .middle_done
 mov eax,[rsi+hda_route_edge.codec]
 cmp eax,[r12+hda_route_context.codec]
 jne .next_middle_edge
 mov eax,[rsi+hda_route_edge.group]
 cmp eax,[r12+hda_route_context.group]
 jne .next_middle_edge
 cmp [rsi+hda_route_edge.node],ecx
 jne .next_middle_edge
 mov eax,[rsi+hda_route_edge.target]
 cmp eax,[r12+hda_route_context.dac]
 jne .next_middle_edge
 mov eax,[rsi+hda_route_edge.index]
 cmp eax,r8d
 cmovb r8d,eax
.next_middle_edge:
 add rsi,hda_route_edge_size
 jmp .middle_edge
.middle_done:
 cmp r8d,-1
 je .next_pin_index
 mov r11,[rsp+HDARP_MIDDLE]
 mov edx,[r11+hda_widget_info.nid]
 mov r10d,[r11+hda_widget_info.caps]
 shr r10d,20
 and r10d,15
 dec r10d                          ;mixer2->kind1,selector3->kind2
 jmp .publish
.next_pin_edge:
 add rdi,hda_route_edge_size
 jmp .find_pin_edge
.next_pin_index:
 inc dword [rsp+HDARP_PIN_INDEX]
 mov eax,[rsp+HDARP_PIN_INDEX]
 cmp eax,[rsp+HDARP_PIN_COUNT]
 jb .pin_index
 jmp hdarp_no_route
.direct:
 xor edx,edx
 xor r8d,r8d
 xor r10d,r10d
.publish:
 mov [r12+hda_route_context.middle],edx
 mov eax,[rsp+HDARP_PIN_INDEX]
 mov [r12+hda_route_context.pin_index],eax
 mov [r12+hda_route_context.middle_index],r8d
 mov [r12+hda_route_context.kind],r10d
 xor eax,eax
 jmp hdarp_out
hdarp_bad:
 mov rax,-1
 jmp hdarp_out
hdarp_no_route:
 mov rax,-2
 jmp hdarp_out
hdarp_limit:
 mov rax,-4
hdarp_out:
 add rsp,HDARP_STACK
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
