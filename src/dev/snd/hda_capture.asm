;; MODULE dev/snd/hda_capture
;; LAYER 3
;; EXPORTS hda_capture_begin, hda_capture_next, hda_capture_reply, hda_capture_abort
;; IMPORTS dev/snd/hda_codec, dev/snd/hda_route, dev/snd/hda_conn
;; CAPS
;; OWNER rc-codex-av
;
; Cooperative Classic0cabd75f hda_conn_entry acquisition: GET_CONN base indices
; multiples of4 short /2 long, four short or two long entries per response.
; Reuse the
; accepted hda_conn_decode for whole-widget validation and scoped edge rows.
; No command submission, MMIO, allocation or global state. The controller owner
; serializes calls, retains each emitted verb while CORB is busy, and supplies
; ONLY the solicited response attributed by hda_rirb_take. Abort on transport
; fault/deadline; reset/drain transport before begin again. Begin never cancels
; an outstanding hardware request. Wrong-stage replies are refused unchanged.
;
; PRIVATE trusted driver API. Context is writable/mapped384 bytes. Inventory
; is complete/DONE, stable and readonly for the entire walk; the owner must
; not mutate any input pointer/count after begin. Output edges are preallocated
; writable/mapped; context, accessed inventory and edge spans are disjoint.
; next's command output is a separate trusted writable dword outside these
; spans. Owner prevents other controller command users during acquisition.
; Validate all metadata/capacity before emitting the first request. Work bounds:
; <=1905 widgets, <=127 raw entries /256 expanded entries per widget,
; <=2048 graph edges. Duplicate targets/indices across distinct
; widgets are preserved; planner validates graph topology and scoped uniqueness.
;
; begin(RDI=context) ->0 active / -1 refused. Refusal latches FAILED/revokes count
; for a valid context; no external inventory/edge/command writes.
; next(RDI=context,RSI=out_verb*) ->0 read request /1 waiting /2 DONE /-1 refused.
; reply(RDI=context,ESI=attributed response) ->0 consumed /-1 refused/fault.
; abort(RDI=context) ->-1 sticky FAILED; revokes even a completed graph.
; Rows are provisional until next returns DONE and publishes edge_count. On
; fault/abort, discard all rows even if earlier widgets decoded successfully.
; Each call is bounded: next skips at most1905 empty widgets; reply decodes at
; most127 raw /256 expanded entries. Transport owns deadlines, not this helper.
; Begin bounds the raw minimum output; expansion is not known until replies.
; Reply decodes into a private6KiB stack staging buffer, checks the actual
; expanded output against full inventory/context spans, remaining capacity and
; graph bound, then copies that widget. Excess revokes the entire graph.
; Only context and decoded rows change; all functions preserve SysV GPRs/RSP.

struc hda_capture
 .widgets: resq 1
 .widget_count: resq 1
 .edges: resq 1
 .edge_capacity: resq 1
 .edge_count: resq 1
 .widget_index: resq 1
 .written: resq 1
 .needed: resq 1
 .phase: resd 1                  ;1 ACTIVE,2 DONE,3 FAILED
 .waiting: resd 1
 .offset: resd 1                 ;GET_CONN base offset within current widget
 .error: resd 1                  ;1 input/capacity,2 decoded reply,3 abort
 .decode: resb hda_conn_context_size
 .raw: resd 64                   ;ceil(127 long entries/2) u32 replies
endstruc

hda_capture_begin:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 mov r12,rdi
 test rdi,rdi
 jz hdacap_begin_bad_pointer
 mov rbp,rdi
 add rbp,hda_capture_size
 jc hdacap_begin_bad_pointer
 mov dword [r12+hda_capture.phase],3
 mov dword [r12+hda_capture.error],1
 mov dword [r12+hda_capture.waiting],0
 mov dword [r12+hda_capture.offset],0
 mov qword [r12+hda_capture.edge_count],0
 mov qword [r12+hda_capture.widget_index],0
 mov qword [r12+hda_capture.written],0
 mov qword [r12+hda_capture.needed],0
 mov rax,[r12+hda_capture.widget_count]
 cmp rax,1905
 ja hdacap_begin_bad_pointer
 xor ebx,ebx
 test rax,rax
 jz .ready
 mov r13,[r12+hda_capture.widgets]
 test r13,r13
 jz hdacap_begin_bad_pointer
 shl rax,5
 add rax,r13
 jc hdacap_begin_bad_pointer
 mov r14,rax
 cmp r13,rbp
 jae .widget_span_ok
 cmp r12,r14
 jb hdacap_begin_bad_pointer
.widget_span_ok:
 mov r8,r13
.preflight:
 cmp dword [r8+hda_widget_info.codec],15
 jae hdacap_begin_bad_pointer
 mov eax,[r8+hda_widget_info.group]
 dec eax
 cmp eax,127
 jae hdacap_begin_bad_pointer
 mov eax,[r8+hda_widget_info.nid]
 dec eax
 cmp eax,127
 jae hdacap_begin_bad_pointer
 cmp dword [r8+hda_widget_info.reserved],0
 jne hdacap_begin_bad_pointer
 mov eax,[r8+hda_widget_info.conn_len]
 cmp eax,255
 ja hdacap_begin_bad_pointer
 and eax,127
 test eax,eax
 jz .empty
 test dword [r8+hda_widget_info.caps],0x100
 jz hdacap_begin_bad_pointer
 add ebx,eax
 cmp ebx,2048
 ja hdacap_begin_bad_pointer
.empty:
 add r8,hda_widget_info_size
 cmp r8,r14
 jb .preflight
 cmp [r12+hda_capture.edge_capacity],rbx
 jb hdacap_begin_bad_pointer
 test ebx,ebx
 jz .ready
 mov r15,[r12+hda_capture.edges]
 test r15,r15
 jz hdacap_begin_bad_pointer
 imul rax,rbx,hda_route_edge_size ;known minimum, actual expansion checked later
 add rax,r15
 jc hdacap_begin_bad_pointer
 cmp r15,rbp
 jae .edge_ctx_ok
 cmp r12,rax
 jb hdacap_begin_bad_pointer
.edge_ctx_ok:
 cmp r15,r14
 jae .ready
 cmp r13,rax
 jb hdacap_begin_bad_pointer
.ready:
 mov [r12+hda_capture.needed],rbx
 mov dword [r12+hda_capture.phase],1
 mov dword [r12+hda_capture.error],0
 xor eax,eax
 jmp hdacap_begin_return
hdacap_begin_bad_pointer:
 mov rax,-1
hdacap_begin_return:
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

hda_capture_next:
 cmp dword [rdi+hda_capture.phase],2
 je .done_repeat
 cmp dword [rdi+hda_capture.phase],1
 jne .error
 cmp dword [rdi+hda_capture.waiting],0
 jne .wait
.find:
 mov rax,[rdi+hda_capture.widget_index]
 cmp rax,[rdi+hda_capture.widget_count]
 jae .finish
 shl rax,5
 add rax,[rdi+hda_capture.widgets]
 mov r8,rax
 mov eax,[r8+hda_widget_info.conn_len]
 and eax,127
 test eax,eax
 jne .emit
 inc qword [rdi+hda_capture.widget_index]
 jmp .find
.emit:
 test rsi,rsi
 jz .error
 mov rax,rsi
 add rax,4
 jc .error
 mov eax,[r8+hda_widget_info.codec]
 shl eax,28
 mov ecx,[r8+hda_widget_info.nid]
 shl ecx,20
 or eax,ecx
 or eax,0xF0200
 or eax,[rdi+hda_capture.offset]
 mov [rsi],eax
 mov dword [rdi+hda_capture.waiting],1
 xor eax,eax
 ret
.finish:
 mov rax,[rdi+hda_capture.written]
 mov [rdi+hda_capture.edge_count],rax
 mov dword [rdi+hda_capture.phase],2
.done_repeat:
 mov eax,2
 ret
.wait:
 mov eax,1
 ret
.error:
 mov rax,-1
 ret

hda_capture_reply:
 cmp dword [rdi+hda_capture.phase],1
 jne .error
 cmp dword [rdi+hda_capture.waiting],1
 jne .error
 push r12                       ;align for call into actual decoder
 sub rsp,256*hda_route_edge_size ;private complete-widget staging; no early output
 mov r12,rdi
 mov rcx,[rdi+hda_capture.widget_index]
 shl rcx,5
 add rcx,[rdi+hda_capture.widgets]
 mov eax,[rdi+hda_capture.offset]
 mov edx,4
 test dword [rcx+hda_widget_info.conn_len],128
 jz .raw_offset
 shl eax,1
 mov edx,2
.raw_offset:
 mov [rdi+hda_capture.raw+rax],esi
 add [rdi+hda_capture.offset],edx
 mov eax,[rdi+hda_capture.offset]
 mov dword [rdi+hda_capture.waiting],0
 mov edx,[rcx+hda_widget_info.conn_len]
 and edx,127
 cmp eax,edx
 jb .consumed
 mov [rdi+hda_capture.decode+hda_conn_context.widget],rcx
 lea rax,[rdi+hda_capture.raw]
 mov [rdi+hda_capture.decode+hda_conn_context.replies],rax
 mov eax,[rcx+hda_widget_info.conn_len]
 and eax,127
 test dword [rcx+hda_widget_info.conn_len],128
 jnz .long_count
 add eax,3
 shr eax,2
 jmp .count_ready
.long_count:
 inc eax
 shr eax,1
.count_ready:
 mov [rdi+hda_capture.decode+hda_conn_context.reply_count],rax
 mov qword [rdi+hda_capture.decode+hda_conn_context.edge_capacity],256
 mov [rdi+hda_capture.decode+hda_conn_context.edges],rsp
 lea rdi,[rdi+hda_capture.decode]
 call hda_conn_decode
 mov qword [r12+hda_capture.decode+hda_conn_context.edges],0 ;no dangling stack VA
 test rax,rax
 jnz .decode_failed
 mov rcx,[r12+hda_capture.decode+hda_conn_context.edge_count]
 mov rdx,[r12+hda_capture.written]
 lea rax,[rdx+rcx]
 cmp rax,2048
 ja .decode_failed
 cmp rax,[r12+hda_capture.edge_capacity]
 ja .decode_failed
 imul rdx,rdx,hda_route_edge_size
 add rdx,[r12+hda_capture.edges]
 jc .decode_failed
 mov rdi,rdx
 imul r8,rcx,hda_route_edge_size
 add r8,rdx
 jc .decode_failed
 lea r9,[r12+hda_capture_size]
 cmp rdi,r9
 jae .ctx_disjoint
 cmp r12,r8
 jb .decode_failed
.ctx_disjoint:
 mov r9,[r12+hda_capture.widgets]
 mov r10,[r12+hda_capture.widget_count]
 shl r10,5
 add r10,r9
 cmp rdi,r10
 jae .inventory_disjoint
 cmp r9,r8
 jb .decode_failed
.inventory_disjoint:
 imul rcx,rcx,hda_route_edge_size/8
 mov rsi,rsp
 rep movsq
 mov [r12+hda_capture.written],rax
 inc qword [r12+hda_capture.widget_index]
 mov dword [r12+hda_capture.offset],0
.consumed:
 xor eax,eax
 add rsp,256*hda_route_edge_size
 pop r12
 ret
.decode_failed:
 mov dword [r12+hda_capture.phase],3
 mov dword [r12+hda_capture.error],2
 mov qword [r12+hda_capture.edge_count],0
 mov rax,-1
 add rsp,256*hda_route_edge_size
 pop r12
 ret
.error:
 mov rax,-1
 ret

hda_capture_abort:
 cmp dword [rdi+hda_capture.phase],3
 je .error
 mov dword [rdi+hda_capture.phase],3
 mov dword [rdi+hda_capture.waiting],0
 mov dword [rdi+hda_capture.error],3
 mov qword [rdi+hda_capture.edge_count],0
.error:
 mov rax,-1
 ret
