;; MODULE dev/snd/hda_input_route
;; LAYER 3
;; EXPORTS hda_input_route_plan
;; IMPORTS dev/snd/hda_route, dev/snd/hda_codec
;; CAPS
;; OWNER rc-codex-av
; Input direction is ADC->upstream selector/mixer->physical pin in HDA lists.
; Port accepted output planner's bounded complete-list/map/mask machinery;
; do not reverse edges or treat a pin's DAC inputs as microphone capture.
; Context72: exact graph view/codec/AFG/ADC/pin plus channels1/2. Output48..63
; only publishes a supported plan; input/arrays unchanged on refusal. Expanded
; long/range indices and exact parent metadata preserved. Same1905/2048/256
; bounds and disjoint full64 spans. Typed analogue microphone/line-in only;
; direct or one middle, no digital/processing/stripe/extended channel widgets.
; SysV GPR/RSP, DF0, no verbs/MMIO/FP/allocation/readiness claim.
struc hda_input_route
 .widgets: resq 1
 .widget_count: resq 1
 .edges: resq 1
 .edge_count: resq 1
 .codec: resd 1
 .group: resd 1
 .adc: resd 1
 .pin: resd 1
 .middle: resd 1
 .adc_index: resd 1
 .middle_index: resd 1
 .kind: resd 1                      ;0 direct,1 mixer,2 selector
 .channels: resd 1
 .reserved: resd 1
endstruc
HDAIRP_COUNTS equ 1024                ;128 expected u16 counts (bit15=marked)
HDAIRP_SEEN equ 1280                  ;128 observed u16 counts
HDAIRP_MASKS equ 1536                 ;128 256bit selector masks
HDAIRP_PIN_COUNT equ 5632
HDAIRP_PIN_INDEX equ 5636
HDAIRP_MIDDLE equ 5640
HDAIRP_WIDGET_END equ 5656
HDAIRP_EDGE_END equ 5664
HDAIRP_STACK equ 5672

hda_input_route_plan:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,HDAIRP_STACK
 mov r12,rdi
 test r12,r12
 jz hdairp_bad
 mov rbx,r12
 add rbx,hda_input_route_size
 jc hdairp_bad
 cmp dword [r12+hda_input_route.codec],15
 jae hdairp_bad
 mov eax,[r12+hda_input_route.group]
 dec eax
 cmp eax,126
 ja hdairp_bad
 mov eax,[r12+hda_input_route.adc]
 dec eax
 cmp eax,126
 ja hdairp_bad
 mov eax,[r12+hda_input_route.pin]
 dec eax
 cmp eax,126
 ja hdairp_bad
 mov rax,[r12+hda_input_route.widget_count]
 test rax,rax
 jz hdairp_bad
 cmp rax,1905
 ja hdairp_limit
 shl rax,5                         ;accepted hda_widget_info size32
 mov r13,[r12+hda_input_route.widgets]
 test r13,r13
 jz hdairp_bad
 add rax,r13
 jc hdairp_bad
 mov [rsp+HDAIRP_WIDGET_END],rax
 cmp r13,rbx
 jae .widgets_context_ok
 cmp r12,rax
 jb hdairp_bad
.widgets_context_ok:
 mov r15,[r12+hda_input_route.edge_count]
 cmp r15,2048
 ja hdairp_limit
 mov r14,[r12+hda_input_route.edges]
 mov rdx,r14
 test r15,r15
 jz .edges_ok
 test r14,r14
 jz hdairp_bad
 imul rax,r15,hda_route_edge_size
 add rdx,rax
 jc hdairp_bad
 cmp r14,rbx
 jae .edges_context_ok
 cmp r12,rdx
 jb hdairp_bad
.edges_context_ok:
 cmp r14,[rsp+HDAIRP_WIDGET_END]
 jae .edges_ok
 cmp r13,rdx
 jb hdairp_bad
.edges_ok:
 mov [rsp+HDAIRP_EDGE_END],rdx
 mov rdi,rsp
 xor eax,eax
 mov ecx,HDAIRP_PIN_COUNT/8
 rep stosq                         ;private NID map and complete-list masks
.widget:
 cmp r13,[rsp+HDAIRP_WIDGET_END]
 jae .pin_dac
 mov eax,[r13+hda_widget_info.codec]
 cmp eax,[r12+hda_input_route.codec]
 jne .next_widget
 mov eax,[r13+hda_widget_info.group]
 cmp eax,[r12+hda_input_route.group]
 jne .next_widget
 mov eax,[r13+hda_widget_info.nid]
 lea edx,[rax-1]
 cmp edx,126
 ja hdairp_bad
 cmp qword [rsp+rax*8],0
 jne hdairp_bad
 mov [rsp+rax*8],r13
.next_widget:
 add r13,hda_widget_info_size
 jmp .widget
.pin_dac:
 mov r13d,[r12+hda_input_route.adc]
 mov rbx,[rsp+r13*8]
 test rbx,rbx
 jz hdairp_bad
 mov eax,[r12+hda_input_route.channels]
 dec eax
 cmp eax,1
 ja hdairp_bad
 cmp dword [r12+hda_input_route.reserved],0
 jne hdairp_bad
 mov ecx,eax
 mov eax,[rbx+hda_widget_info.caps]
 and eax,0xF0E261              ;type/digital/processing/stripe/ext/stereo
 or ecx,0x100000              ;ADC1, exact converter channel count
 cmp eax,ecx
 jne hdairp_no_route
 test dword [rbx+hda_widget_info.caps],0x100
 jz hdairp_no_route
 mov eax,[r12+hda_input_route.pin]
 mov rdx,[rsp+rax*8]
 test rdx,rdx
 jz hdairp_bad
 mov eax,[rdx+hda_widget_info.caps]
 mov ecx,eax
 and eax,0xF0E260
 cmp eax,0x400000             ;typed analogue physical input pin
 jne hdairp_no_route
 cmp dword [r12+hda_input_route.channels],2
 jne .pin_channels
 test ecx,1
 jz hdairp_no_route
.pin_channels:
 test dword [rdx+hda_widget_info.pin_caps],0x20
 jz hdairp_no_route
 mov eax,[rdx+hda_widget_info.config]
 mov ecx,eax
 shr ecx,20
 and ecx,15
 cmp ecx,8                   ;Line In
 je .pin_device
 cmp ecx,10                  ;Mic In
 jne hdairp_no_route
.pin_device:
 shr eax,30
 cmp eax,1
 je hdairp_no_route
 mov eax,[rbx+hda_widget_info.conn_len]
 cmp eax,255
 ja hdairp_bad
 and eax,127
 test eax,eax
 jz hdairp_no_route
 mov rdi,r14
.edge:
 cmp rdi,[rsp+HDAIRP_EDGE_END]
 jae .complete_pin
 mov eax,[rdi+hda_route_edge.codec]
 cmp eax,[r12+hda_input_route.codec]
 jne .next_edge
 mov eax,[rdi+hda_route_edge.group]
 cmp eax,[r12+hda_input_route.group]
 jne .next_edge
 mov r8d,[rdi+hda_route_edge.node]
 lea eax,[r8-1]
 cmp eax,126
 ja hdairp_bad
 mov r9,[rsp+r8*8]
 test r9,r9
 jz hdairp_bad
 mov edx,[r9+hda_widget_info.conn_len]
 cmp edx,255
 ja hdairp_bad
 mov r10d,edx
 and edx,127
 test edx,edx
 jz hdairp_bad
 mov eax,[rdi+hda_route_edge.reserved]
 test eax,eax
 jnz .expanded_count
 test r10d,128                   ;long rows require explicit decoded count
 jnz hdairp_bad
 jmp .list_count
.expanded_count:
 mov r11d,eax
 and r11d,0xFFFFFE00
 cmp r11d,HDA_EDGE_EXPANDED
 jne hdairp_bad
 and eax,0x1FF
 cmp eax,256
 ja hdairp_bad
 cmp eax,edx
 jb hdairp_bad
 cmp edx,1                      ;one encoded entry cannot expand a range
 jne .count_ok
 cmp eax,1
 jne hdairp_bad
.count_ok:
 mov edx,eax
 or edx,0x8000
.list_count:
 cmp word [rsp+HDAIRP_COUNTS+r8*2],0
 jne .same_count
 mov [rsp+HDAIRP_COUNTS+r8*2],dx
.same_count:
 cmp dx,[rsp+HDAIRP_COUNTS+r8*2]
 jne hdairp_bad
 and edx,0x7FFF
 mov ecx,[rdi+hda_route_edge.index]
 cmp ecx,edx
 jae hdairp_bad
 mov eax,r8d
 shl eax,5
 bts qword [rsp+rax+HDAIRP_MASKS],rcx
 jc hdairp_bad
 inc word [rsp+HDAIRP_SEEN+r8*2]
 mov eax,[rdi+hda_route_edge.target]
 lea edx,[rax-1]
 cmp edx,126
 ja hdairp_bad
 cmp qword [rsp+rax*8],0
 je hdairp_bad
.next_edge:
 add rdi,hda_route_edge_size
 jmp .edge
.complete_pin:
 movzx eax,word [rsp+HDAIRP_COUNTS+r13*2]
 and eax,0x7FFF
 test eax,eax
 jz hdairp_bad
 cmp ax,[rsp+HDAIRP_SEEN+r13*2]
 jne hdairp_bad
 mov [rsp+HDAIRP_PIN_COUNT],eax
 mov dword [rsp+HDAIRP_PIN_INDEX],0
.pin_index:
 mov rdi,r14
.find_pin_edge:
 cmp rdi,[rsp+HDAIRP_EDGE_END]
 jae hdairp_bad                     ;complete mask guaranteed an edge
 mov eax,[rdi+hda_route_edge.codec]
 cmp eax,[r12+hda_input_route.codec]
 jne .next_pin_edge
 mov eax,[rdi+hda_route_edge.group]
 cmp eax,[r12+hda_input_route.group]
 jne .next_pin_edge
 cmp [rdi+hda_route_edge.node],r13d
 jne .next_pin_edge
 mov eax,[rdi+hda_route_edge.index]
 cmp eax,[rsp+HDAIRP_PIN_INDEX]
 jne .next_pin_edge
 mov eax,[rdi+hda_route_edge.target]
 cmp eax,[r12+hda_input_route.pin]
 je .direct
 mov r11,[rsp+rax*8]
 mov edx,[r11+hda_widget_info.caps]
 test edx,0xE260
 jnz .next_pin_index
 cmp dword [r12+hda_input_route.channels],2
 jne .middle_channels
 test edx,1
 jz .next_pin_index
.middle_channels:
 shr edx,20
 and edx,15
 sub edx,2
 cmp edx,1
 ja .next_pin_index
 mov [rsp+HDAIRP_MIDDLE],r11
 mov ecx,[r11+hda_widget_info.conn_len]
 and ecx,127
 test ecx,ecx
 jz .next_pin_index
 mov ecx,[r11+hda_widget_info.nid]
 movzx edx,word [rsp+HDAIRP_COUNTS+rcx*2]
 and edx,0x7FFF
 test edx,edx
 jz hdairp_bad
 cmp dx,[rsp+HDAIRP_SEEN+rcx*2]
 jne hdairp_bad
 mov r8d,-1
 mov rsi,r14
.middle_edge:
 cmp rsi,[rsp+HDAIRP_EDGE_END]
 jae .middle_done
 mov eax,[rsi+hda_route_edge.codec]
 cmp eax,[r12+hda_input_route.codec]
 jne .next_middle_edge
 mov eax,[rsi+hda_route_edge.group]
 cmp eax,[r12+hda_input_route.group]
 jne .next_middle_edge
 cmp [rsi+hda_route_edge.node],ecx
 jne .next_middle_edge
 mov eax,[rsi+hda_route_edge.target]
 cmp eax,[r12+hda_input_route.pin]
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
 mov r11,[rsp+HDAIRP_MIDDLE]
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
 inc dword [rsp+HDAIRP_PIN_INDEX]
 mov eax,[rsp+HDAIRP_PIN_INDEX]
 cmp eax,[rsp+HDAIRP_PIN_COUNT]
 jb .pin_index
 jmp hdairp_no_route
.direct:
 xor edx,edx
 xor r8d,r8d
 xor r10d,r10d
.publish:
 mov [r12+hda_input_route.middle],edx
 mov eax,[rsp+HDAIRP_PIN_INDEX]
 mov [r12+hda_input_route.adc_index],eax
 mov [r12+hda_input_route.middle_index],r8d
 mov [r12+hda_input_route.kind],r10d
 xor eax,eax
 jmp hdairp_out
hdairp_bad:
 mov rax,-1
 jmp hdairp_out
hdairp_no_route:
 mov rax,-2
 jmp hdairp_out
hdairp_limit:
 mov rax,-4
hdairp_out:
 add rsp,HDAIRP_STACK
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
