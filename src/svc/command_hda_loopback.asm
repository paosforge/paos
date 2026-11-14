;; MODULE svc/command_hda_loopback
;; LAYER 5
;; EXPORTS command_hda_loopback_init, hdaloop_out_buf, hdaloop_out_ready, hlc_diagnostic_retire, hlc_diag_valid, hlc_diag_req, hlc_diag_arg, hlc_diag_end
;; IMPORTS dev/snd/hda_boot_handoff, svc/command, dev/snd/hda_loopback_native, dev/snd/hda_backend, core/build_id
;; CAPS
;; OWNER rc-codex-av
; Owner/MUTATE registry verb only. Strict bounded decimal operands, never raw
; pointers, MMIO/codec verbs, arbitrary PCM, paths or caller-chosen amplitude.
; No implicit play: OPEN discovers, SELECT configures, RUN1 explicitly starts.
; HL1 diagnostics and HLR1 refusals are documented in NATIVE_AUDIO_LOOPBACK.md.
; Whole mandatory HL1 record budget, including its longest bounded READ tail.
; Magic+15 u64 fields+measured BID+8 u32 route fields+2 u64 read fields+
; 32 frames * 2 channels * 4 hex digits+NUL. PIN/NODE tails <=9*u32.
HL1_RECORD_CAP equ 1050
%if hda_route_program.steps-hda_route_program.phase != 9*4 || hda_route_program.request_phase-hda_route_program.saved_format != 10*4 || hda_program_node_size != 6*4
 %error "diagnostic scalar block layout changed"
%endif
; DIAG6 and DIAG9 are the largest tails: page u32 plus 25 full-width u64 values.
; DIAG5 has 11 u64 observations; program pages have <=40 u32 values.
%if hda_input.failure_sd_status-hda_input.failure_reason != 23*8 || hda_input.observation_mismatch_count-hda_input.observation_count != 10*8
 %error "input diagnostic scalar block layout changed"
%endif
%if hda_pcm.timeout_frame_bytes-hda_pcm.timeout_reason != 24*8
 %error "PCM timeout scalar block layout changed"
%endif
%if hda_output.timeout_dpl-hda_output.timeout_state != 9*8
 %error "output timeout scalar block layout changed"
%endif
%if hda_pcm.controller_fifo-hda_pcm.controller_valid != 24*8
 %error "PCM controller scalar block layout changed"
%endif
%if hda_pcm.failure_cyclic-hda_pcm.failure_reason != 17*8
 %error "PCM position scalar block layout changed"
%endif
HL1_DIAG_MAX equ 4 + 15*21 + 65 + 8*11 + 11 + 25*21 + 1
%if HL1_DIAG_MAX > HL1_RECORD_CAP
 %error "whole HL1 diagnostic exceeds staging capacity"
%endif
HL1_RECORD_MAX equ 4 + 15*21 + 65 + 8*11 + 2*21 + 32*2*4 + 1
%if HL1_RECORD_MAX > HL1_RECORD_CAP
 %error "whole HL1 record exceeds staging capacity"
%endif
command_hda_loopback_init:
 lea rdi,[rel hlc_verb]
 lea rsi,[rel hlc_handler]
 xor edx,edx
 mov ecx,ARGT_TEXT
 xor r8d,r8d
 mov r9d,1
 jmp command_register_verb
hlc_handler:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 call cmd_handler_prologue
 mov r12,rdi
 mov r13,rsi
 call hlc_diagnostic_begin          ; request custody only; no admission
 mov byte [rel hdaloop_out_ready],0
 mov byte [rel hdaloop_out_buf],0
 cmp qword [r12+REQ_PRINCIPAL],CMD_PRINCIPAL_OWNER
 jne .deny
 mov rdi,[r12+REQ_ARG]
 call hlc_parse
 test eax,eax
 js .bad
 mov ebp,eax
 cmp eax,11
 je .handoff
 cmp eax,1
 je .open
 mov rsi,[rel hlc_args]
 cmp rsi,[rel hln_epoch]
 jne .bad
 cmp dword [rel hlc_count],1
 jb .bad
 lea rdi,[rel hln_loop]
 cmp ebp,12
 je .diag
 cmp ebp,2
 je .stat
 cmp ebp,7
 je .cancel
 cmp ebp,8
 je .release
 cmp dword [rel hln_phase],2
 jne .bad
 cmp ebp,9
 je .node
 cmp ebp,10
 je .edge
 cmp ebp,15
 je .format
 cmp ebp,3
 je .pin
 cmp ebp,13
 je .pinout
 cmp ebp,14
 je .runout
 cmp ebp,4
 je .select
 cmp ebp,5
 je .run
 cmp ebp,6
 je .read
 cmp ebp,7
 je .cancel
 cmp ebp,8
 je .release
 jmp .bad
.handoff:
 cmp dword [rel hlc_count],1
 jne .bad
 mov rax,[rel hlc_args]
 cmp rax,32
 jae .bad
 test rax,rax                   ; row0 also reports a globally skipped census
 jz .handoff_index
 cmp eax,[rel hda_handoff_visited]
 jae .bad
.handoff_index:
 shl rax,6
 lea rbx,[rel hda_handoff_rows]
 add rbx,rax
 mov qword [r13+RSP_CODE],CMDE_OK
 mov qword [r13+RSP_ACCEPTED],1
 call hlc_handoff_record
 jmp .out
.open:
 cmp dword [rel hlc_count],2
 jne .bad
 mov edi,[rel hlc_args]
 mov rsi,[rel hlc_args+8]
 call hda_loopback_native_open
 jmp .result
.diag:
 cmp dword [rel hlc_count],2
 jne .bad
 cmp qword [rel hlc_args+8],11
 ja .bad
 xor eax,eax
 jmp .result
.stat:
 cmp dword [rel hlc_count],1
 jne .bad
 xor eax,eax
 jmp .result
.pin:
 cmp dword [rel hlc_count],2
 jne .bad
 cmp dword [rdi+hda_loopback.phase],HLB_DISCOVERED
 jb .bad
 mov eax,[rel hlc_args+8]
 cmp eax,[rdi+hda_loopback.pin_count]
 jae .bad
 imul eax,hda_loopback_pin_size
 mov rbx,[rdi+hda_loopback.pins]
 add rbx,rax
 xor eax,eax
 jmp .result
.node:
 cmp dword [rel hlc_count],2
 jne .bad
 cmp dword [rel hln_graph+hda_graph.phase],HDAGS_DONE
 jne .bad
 mov eax,[rel hlc_args+8]
 cmp eax,[rel hln_graph+hda_graph.public_widget_count]
 jae .bad
 shl eax,5
 mov rbx,[rel hln_graph+hda_graph.widgets]
 add rbx,rax
 xor eax,eax
 jmp .result
.format:
 cmp dword [rel hlc_count],2
 jne .bad
 cmp dword [rel hln_loop+hda_loopback.phase],HLB_DISCOVERED
 jne .bad
 lea rdi,[rel hln_backend]
 mov rsi,[rel hln_epoch]
 call hda_backend_discovery_check ; current owner/epoch and live DID3 receipt
 test rax,rax
 js .bad
 cmp dword [rel hln_graph+hda_graph.phase],HDAGS_DONE
 jne .bad
 lea rdx,[rel hln_widgets]
 cmp [rel hln_graph+hda_graph.widgets],rdx
 jne .bad
 cmp dword [rel hln_graph+hda_graph.widget_cap],256
 ja .bad
 mov ecx,[rel hln_graph+hda_graph.public_widget_count]
 cmp ecx,[rel hln_graph+hda_graph.widget_cap]
 ja .bad
 mov eax,[rel hlc_args+8]
 cmp eax,ecx
 jae .bad
 shl rax,5
 lea rbx,[rdx+rax]
 mov eax,[rbx+hda_widget_info.caps]
 shr eax,20
 and eax,15
 cmp eax,1
 ja .bad                         ; every ADC/DAC, including digital converters
 xor eax,eax
 jmp .result
.edge:
 cmp dword [rel hlc_count],2
 jne .bad
 cmp dword [rel hln_loop+hda_loopback.phase],HLB_DISCOVERED
 jne .bad
 lea rdi,[rel hln_backend]
 mov rsi,[rel hln_epoch]
 call hda_backend_discovery_check ; current owner/config/epoch and DID3 receipt
 test rax,rax
 js .bad
 cmp dword [rel hln_graph+hda_graph.phase],HDAGS_DONE
 jne .bad
 lea rdx,[rel hln_edges]
 cmp [rel hln_graph+hda_graph.edges],rdx
 jne .bad                         ; exact retained static span, no caller pointer
 cmp dword [rel hln_graph+hda_graph.edge_cap],512
 ja .bad
 mov ecx,[rel hln_graph+hda_graph.public_edge_count]
 cmp ecx,[rel hln_graph+hda_graph.edge_cap]
 ja .bad
 mov eax,[rel hlc_args+8]
 cmp eax,ecx
 jae .bad
 imul rax,rax,hda_route_edge_size  ; full64 arithmetic inside pinned 512-row span
 mov rbx,[rel hln_graph+hda_graph.edges]
 add rbx,rax
 xor eax,eax
 jmp .result
.pinout:
 cmp dword [rel hlc_count],5
 je .pinout_pack
 cmp dword [rel hlc_count],6
 jne .bad
 cmp qword [rel hlc_args+40],48000
 jne .bad
.pinout_pack:
 lea rdx,[rel hlc_selection]
 xor eax,eax
 mov [rdx+16],rax
 mov [rdx+24],rax
 lea r14,[rel hlc_args+8]
 xor ecx,ecx
.pack_output:
 mov eax,[r14+rcx*8]
 mov [rdx+rcx*4],eax
 inc ecx
 cmp ecx,4
 jb .pack_output
 cmp dword [rel hlc_count],6
 je .pinout48
 call hda_loopback_select_output
 jmp .result
.pinout48:
 call hda_loopback_select_output48
 jmp .result
.runout:
 cmp qword [rel hln_media_hook],0
 jne .bad
 cmp dword [rel hlc_count],3
 jne .bad
 mov edx,[rel hlc_args+8]
 mov ecx,[rel hlc_args+16]
 call hda_loopback_run_output
 jmp .result
.select:
 cmp dword [rel hlc_count],9
 je .select_pack
 cmp dword [rel hlc_count],10
 jne .bad
 cmp qword [rel hlc_args+72],48000
 jne .bad
.select_pack:
 lea rdx,[rel hlc_selection]
 lea r14,[rel hlc_args+8]
 xor ecx,ecx
.pack:
 mov eax,[r14+rcx*8]
 mov [rdx+rcx*4],eax
 inc ecx
 cmp ecx,8
 jb .pack
 cmp dword [rel hlc_count],10
 je .select48
 call hda_loopback_select
 jmp .result
.select48:
 call hda_loopback_select48
 jmp .result
.run:
 cmp qword [rel hln_media_hook],0
 jne .bad                       ; explicit file owner exclusively owns RUN
 cmp dword [rel hlc_count],3
 jne .bad
 mov edx,[rel hlc_args+8]
 mov ecx,[rel hlc_args+16]
 call hda_loopback_run
 jmp .result
.read:
 cmp dword [rel hlc_count],3
 jne .bad
 cmp dword [rdi+hda_loopback.phase],HLB_DONE
 jne .bad                        ; no partial/live/uncertain samples published
 cmp dword [rel hln_backend+hda_backend.phase],HDAB_RETIRED
 jne .bad
 mov rax,[rel hlc_args+16]
 test eax,eax
 jz .bad
 cmp eax,32
 ja .bad
 add rax,[rel hlc_args+8]
 jc .bad
 cmp rax,[rdi+hda_loopback.captured_frames]
 ja .bad
 xor eax,eax
 jmp .result
.cancel:
 cmp dword [rel hlc_count],1
 jne .bad
 call hda_loopback_native_cancel
 jmp .result
.release:
 cmp dword [rel hlc_count],1
 jne .bad
 call hda_loopback_native_release
.result:
 test rax,rax
 jns .accepted
 cmp ebp,1                        ; parsed OPEN refusal: actual owner state
 je .refused_record
 cmp ebp,7                        ; CANCEL/RELEASE passed epoch and arity guards
 je .refused_record
 cmp ebp,8
 jne .bad
.refused_record:
 call hlc_record                  ; diagnostic only; BADARG/accepted=0 still apply
 jmp .bad
.accepted:
 mov qword [r13+RSP_CODE],CMDE_OK
 mov qword [r13+RSP_ACCEPTED],1
 call hlc_record
 jmp .out
.deny:
 mov qword [r13+RSP_CODE],CMDE_AUTHDENY
 mov qword [r13+RSP_ACCEPTED],0
 lea rsi,[rel hlc_denied]
 jmp .refusal
.bad:
 mov qword [r13+RSP_CODE],CMDE_BADARG
 mov qword [r13+RSP_ACCEPTED],0
 ; Parsed native OPEN/CANCEL/RELEASE errors already own diagnostic HL1.
 cmp byte [rel hdaloop_out_ready],1
 je .out
 lea rsi,[rel hlc_badarg]
.refusal:
 ; Constant-only, distinct from HL1: malformed/stale requests may not inspect
 ; owner state, echo arbitrary input or inherit a prior successful row/capture.
 lea rdi,[rel hdaloop_out_buf]
.copy_refusal:
 lodsb
 stosb
 test al,al
 jnz .copy_refusal
 mov [rel hlc_cur],rdi             ; refusal NUL extent
 dec qword [rel hlc_cur]
 mov byte [rel hdaloop_out_ready],1
.out:
 cmp byte [rel hdaloop_out_ready],1
 jne .no_extent
 mov rax,[rel hlc_cur]
 mov [rel hlc_diag_end],rax
.no_extent:
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; parse <=240 bytes, uppercase subcommand then <=10 decimal u16s. No signs,
; empty numeric tokens, suffixes, control chars or arithmetic wrap are accepted.
hlc_parse:
 test rdi,rdi
 jz .bad
 xor ecx,ecx
.len:
 cmp ecx,240
 jae .bad
 cmp byte [rdi+rcx],0
 je .length
 inc ecx
 jmp .len
.length:
 mov r8,rdi
 lea r9,[rdi+rcx]
 xor edx,edx
.word:
 cmp r8,r9
 jae .bad
 mov al,[r8]
 cmp al,' '
 je .lookup
 cmp al,'A'
 jb .bad
 cmp al,'Z'
 ja .bad
 cmp edx,7
 jae .bad
 lea rsi,[rel hlc_word]
 mov [rsi+rdx],al
 inc edx
 inc r8
 jmp .word
.lookup:
 lea rsi,[rel hlc_word]
 mov byte [rsi+rdx],0
 lea r10,[rel hlc_names]
 mov r11d,1
.name:
 mov rsi,r10
 lea rdi,[rel hlc_word]
.compare:
 mov al,[rsi]
 cmp al,[rdi]
 jne .next
 inc rsi
 inc rdi
 test al,al
 jnz .compare
 mov [rel hlc_opcode],r11d
 jmp .numbers
.next:
 cmp byte [r10],0
 je .next_name
 inc r10
 jmp .next
.next_name:
 inc r10
 inc r11d
 cmp r11d,15
 jbe .name
.bad:
 mov eax,-1
 ret
.numbers:
 mov dword [rel hlc_count],0
.space:
 cmp r8,r9
 jae .done
 cmp byte [r8],' '
 jne .number
 inc r8
 jmp .space
.number:
 mov ecx,[rel hlc_count]
 cmp ecx,10
 jae .bad
 xor eax,eax
.digit:
 movzx edx,byte [r8]
 sub edx,'0'
 cmp edx,9
 ja .bad
 imul eax,10
 add eax,edx
 cmp eax,65535
 ja .bad
 inc r8
 cmp r8,r9
 jae .save
 cmp byte [r8],' '
 jne .digit
.save:
 lea rdi,[rel hlc_args]
 mov [rdi+rcx*8],rax
 inc dword [rel hlc_count]
 jmp .space
.done:
 mov eax,[rel hlc_opcode]
 ret

; All reply fields come from actual pinned owner state. READ repeats an absolute
; offset idempotently and never advances a hidden cursor or invents samples.
; Boot observations only: no MMIO read, owner creation or handoff invocation.
; Header6u32, row8u64, nonceu32 and BID fit the existing whole-record buffer.
hlc_handoff_record:
 sub rsp,8
 lea rdi,[rel hdaloop_out_buf]
 mov [rel hlc_cur],rdi
 lea rsi,[rel hlc_boot_magic]
 call hlc_string
 mov eax,[rel hda_handoff_closed]
 call hlc_number
 mov eax,[rel hda_handoff_disposition]
 call hlc_number
 mov eax,[rel hda_handoff_visited]
 call hlc_number
 mov eax,[rel hda_handoff_stopped]
 call hlc_number
 mov eax,[rel hda_handoff_refused]
 call hlc_number
 mov rax,[rel hlc_args]
 call hlc_number
 mov r14,rbx
 mov r12d,8
.row:
 mov rax,[r14]
 call hlc_number
 add r14,8
 dec r12d
 jnz .row
 mov eax,[rel boot_nonce]
 call hlc_number
 lea rsi,[rel paos_build_hex]
 call hlc_string
 mov rdi,[rel hlc_cur]
 mov byte [rdi],0
 mov byte [rel hdaloop_out_ready],1
 add rsp,8
 ret
hlc_record:
 sub rsp,8
 lea rdi,[rel hdaloop_out_buf]
 mov [rel hlc_cur],rdi
 lea rsi,[rel hlc_magic]
 call hlc_string
 mov eax,ebp
 call hlc_number
 mov eax,[rel hln_phase]
 call hlc_number
 mov eax,[rel hln_error]
 call hlc_number
 mov eax,[rel hln_loop+hda_loopback.phase]
 call hlc_number
 mov eax,[rel hln_loop+hda_loopback.error]
 call hlc_number
 mov rax,[rel hln_epoch]
 call hlc_number
 mov eax,[rel hln_bdf]
 call hlc_number
 mov rax,[rel hln_serial]
 call hlc_number
 mov eax,[rel hln_loop+hda_loopback.pin_count]
 call hlc_number
 mov rax,[rel hln_loop+hda_loopback.played_frames]
 call hlc_number
 mov rax,[rel hln_loop+hda_loopback.captured_frames]
 call hlc_number
 mov eax,[rel hln_input+hda_input.route+hda_input_route.channels]
 cmp dword [rel hln_loop+hda_loopback.output_only],1
 jne .input_channels
 xor eax,eax
.input_channels:
 call hlc_number
 mov eax,LB_FIXTURE_RATE
 cmp dword [rel hln_pcm+hda_pcm.rate],48000
 jne .fixture_rate
 mov eax,48000
.fixture_rate:
 call hlc_number
 mov eax,1
 cmp dword [rel hln_loop+hda_loopback.output_only],1
 jne .fixture_kind
 cmp dword [rel hln_pcm+hda_pcm.rate],48000
 jne .fixture_kind
 mov eax,2
.fixture_kind:
 cmp qword [rel hln_loop+hda_loopback.play_pcm],0
 je .fixture_id
 xor eax,eax                    ; caller PCM is not reference corpus ID1
 cmp dword [rel hln_loop+hda_loopback.streaming],2
 je .sustained_fixture
 cmp dword [rel hln_loop+hda_loopback.streaming],3
 jne .fixture_id
.sustained_fixture:
 mov eax,3                       ; immutable2s native corpus, paired or output-only
 cmp dword [rel hln_pcm+hda_pcm.rate],48000
 jne .fixture_id
 mov eax,4
.fixture_id:
 call hlc_number
 mov eax,[rel boot_nonce]
 call hlc_number
 lea rsi,[rel paos_build_hex]
 call hlc_string
 lea r14,[rel hln_loop+hda_loopback.selection]
 mov r12d,8
.route:
 mov eax,[r14]
 call hlc_number
 add r14,4
 dec r12d
 jnz .route
 cmp ebp,12
 je .diag
 cmp ebp,9
 je .node
 cmp ebp,10
 je .edge
 cmp ebp,15
 je .format
 cmp ebp,3
 je .pin
 cmp ebp,6
 je .read
 jmp .done
; Retained scalar facts only: never follow graph/script pointers or touch MMIO.
; The same epoch guard as STAT applies before reading any owner storage.
.diag:
 mov eax,[rel hlc_args+8]
 call hlc_number
 mov eax,[rel hlc_args+8]
 test eax,eax
 jz .diag_state
 cmp eax,3
 je .diag_reset
 cmp eax,4
 je .diag_input_failure
 cmp eax,5
 je .diag_input_observation
 cmp eax,6
 je .diag_pcm_timeout
 cmp eax,7
 je .diag_output_timeout
 cmp eax,8
 je .diag_readback
 cmp eax,9
 je .diag_pcm_controller
 cmp eax,10
 je .diag_pcm_position
 cmp eax,11
 je .diag_run_observation
 lea rbx,[rel hln_program]
 cmp eax,1
 je .diag_program
 lea rbx,[rel hln_input+hda_input.program]
.diag_program:
 lea r14,[rbx+hda_route_program.phase]
 mov r12d,10
 call .diag_values
 lea r14,[rbx+hda_route_program.saved_format]
 mov r12d,11
 call .diag_values
 lea r14,[rbx+hda_route_program.nodes]
 mov r12d,18
 call .diag_values
 jmp .done
.diag_readback:
 lea rbx,[rel hln_program]
 mov eax,[rbx+hda_route_program.phase]
 call hlc_number
 mov eax,[rbx+hda_route_program.error]
 call hlc_number
 mov eax,[rbx+hda_route_program.cursor]
 call hlc_number
 mov eax,[rbx+hda_route_program.count]
 call hlc_number
 lea r14,[rbx+hda_route_program.readback_valid]
 mov r12d,16
 call .diag_values
 jmp .done
.diag_state:
 mov eax,[rel hln_backend+hda_backend.phase]
 call hlc_number
 mov eax,[rel hln_backend+hda_backend.error]
 call hlc_number
 mov eax,[rel hln_backend+hda_backend.registered]
 call hlc_number
 mov eax,[rel hln_backend+hda_backend.graph_begun]
 call hlc_number
 mov eax,[rel hln_backend+hda_backend.output_bound]
 call hlc_number
 mov eax,[rel hln_backend+hda_backend.pcm_bound]
 call hlc_number
 mov eax,[rel hln_backend+hda_backend.input_state]
 call hlc_number
 mov eax,[rel hln_backend+hda_backend.input_cleanup_polls]
 call hlc_number
 mov eax,[rel hln_backend+hda_backend.input_halted]
 call hlc_number
 mov eax,[rel hln_backend+hda_backend.output_halted]
 call hlc_number
 mov eax,[rel hln_backend+hda_backend.polls]
 call hlc_number
 mov eax,[rel hln_graph+hda_graph.phase]
 call hlc_number
 mov eax,[rel hln_graph+hda_graph.error]
 call hlc_number
 mov eax,[rel hln_graph+hda_graph.clean]
 call hlc_number
 mov eax,[rel hln_graph+hda_graph.request_state]
 call hlc_number
 mov eax,[rel hln_graph+hda_graph.request_phase]
 call hlc_number
 mov eax,[rel hln_graph+hda_graph.command]
 call hlc_number
 mov eax,[rel hln_graph+hda_graph.response]
 call hlc_number
 mov eax,[rel hln_graph+hda_graph.command_polls]
 call hlc_number
 mov eax,[rel hln_graph+hda_graph.command_ready]
 call hlc_number
 mov eax,[rel hln_graph+hda_graph.pcm_quiescent]
 call hlc_number
 mov eax,[rel hln_graph+hda_graph.input_ready]
 call hlc_number
 mov eax,[rel hln_graph+hda_graph.input_quiescent]
 call hlc_number
 mov eax,[rel hln_output+hda_output.state]
 call hlc_number
 mov eax,[rel hln_output+hda_output.error]
 call hlc_number
 mov eax,[rel hln_pcm+hda_pcm.phase]
 call hlc_number
 mov eax,[rel hln_pcm+hda_pcm.error]
 call hlc_number
 mov eax,[rel hln_input+hda_input.stream_phase]
 call hlc_number
 mov eax,[rel hln_input+hda_input.stream_error]
 call hlc_number
 mov eax,[rel hln_input+hda_input.qualified]
 call hlc_number
 mov eax,[rel hln_input+hda_input.retired]
 call hlc_number
 mov eax,[rel hln_loop+hda_loopback.mute_index]
 call hlc_number
 mov eax,[rel hln_loop+hda_loopback.mute_state]
 call hlc_number
 mov eax,[rel hln_loop+hda_loopback.muted]
 call hlc_number
 mov eax,[rel hln_loop+hda_loopback.query_command]
 call hlc_number
 mov eax,[rel hln_loop+hda_loopback.query_response]
 call hlc_number
 mov eax,[rel hln_backend+hda_backend.pcm_begin_refusal]
 call hlc_number
 jmp .done
.diag_run_observation:
 mov rax,[rel hln_input+hda_input.clock_hz]
 call hlc_number
 mov rax,[rel hln_input+hda_input.run_valid]
 call hlc_number
 mov rax,[rel hln_input+hda_input.run_write_sample]
 call hlc_number
 mov rax,[rel hln_input+hda_input.run_ack_sample]
 call hlc_number
 mov rax,[rel hln_input+hda_input.observation_now]
 call hlc_number
 mov rax,[rel hln_input+hda_input.observation_selected]
 call hlc_number
 mov rax,[rel hln_input+hda_input.observation_valid]
 call hlc_number
 mov eax,[rel hln_input+hda_input.stream_phase]
 call hlc_number
 mov rax,[rel hln_pcm+hda_pcm.clock_hz]
 call hlc_number
 mov rax,[rel hln_pcm+hda_pcm.run_valid]
 call hlc_number
 mov rax,[rel hln_pcm+hda_pcm.run_write_sample]
 call hlc_number
 mov rax,[rel hln_pcm+hda_pcm.run_ack_sample]
 call hlc_number
 mov rax,[rel hln_pcm+hda_pcm.observation_now]
 call hlc_number
 mov eax,[rel hln_pcm+hda_pcm.last_pos]
 call hlc_number
 mov eax,[rel hln_pcm+hda_pcm.phase]
 call hlc_number
 jmp .done
.diag_output_timeout:
 lea r14,[rel hln_output+hda_output.timeout_state]
 mov r12d,10
 jmp .input_failure_values
.diag_pcm_controller:
 lea r14,[rel hln_pcm+hda_pcm.controller_valid]
 mov r12d,25
 jmp .input_failure_values
.diag_pcm_position:
 lea r14,[rel hln_pcm+hda_pcm.failure_reason]
 mov r12d,18
 jmp .input_failure_values
.diag_pcm_timeout:
 lea r14,[rel hln_pcm+hda_pcm.timeout_reason]
 mov r12d,25
 jmp .input_failure_values
.diag_input_observation:
 lea r14,[rel hln_input+hda_input.observation_count]
 mov r12d,11
 jmp .input_failure_values
.diag_input_failure:
 lea r14,[rel hln_input+hda_input.failure_reason]
 mov r12d,24
.input_failure_values:
 mov rax,[r14]
 call hlc_number
 add r14,8
 dec r12d
 jnz .input_failure_values
 jmp .done
.diag_reset:
 mov eax,[rel hln_reset_refusal]
 call hlc_number
 mov eax,[rel hln_reset_failure_state]
 call hlc_number
 mov eax,[rel hln_reset_failure_polls]
 call hlc_number
 mov eax,[rel hln_reset_failure_wait]
 call hlc_number
 mov eax,[rel hln_reset_failure_phase]
 call hlc_number
 mov eax,[rel hln_reset_state]
 call hlc_number
 mov eax,[rel hln_reset_polls]
 call hlc_number
 mov eax,[rel hln_reset_wait]
 call hlc_number
 xor eax,eax
 cmp qword [rel hln_dma],0
 setne al
 call hlc_number
 xor eax,eax
 cmp qword [rel hln_serial],0
 setne al
 call hlc_number
 jmp .done
.diag_values:
 sub rsp,8
.loop:
 mov eax,[r14]
 call hlc_number
 add r14,4
 dec r12d
 jnz .loop
 add rsp,8
 ret
.format:
 mov eax,[rel hln_graph+hda_graph.public_widget_count]
 call hlc_number
 mov eax,[rel hlc_args+8]
 call hlc_number
 mov r14,rbx
 mov r12d,3
.format_identity:
 mov eax,[r14]
 call hlc_number
 add r14,4
 dec r12d
 jnz .format_identity
 mov eax,[rbx+hda_widget_info.caps]
 shr eax,20
 and eax,15
 call hlc_number
 mov eax,[rbx+hda_widget_info.nid]
 test dword [rbx+hda_widget_info.caps],0x10
 jnz .format_source
 mov eax,[rbx+hda_widget_info.group]
.format_source:
 call hlc_number
 mov eax,[rbx+hda_widget_info.pcm]
 call hlc_number
 mov eax,[rbx+hda_widget_info.streams]
 call hlc_number
 jmp .done
.node:
 mov eax,[rel hln_graph+hda_graph.public_widget_count]
 call hlc_number
 mov r12d,8
 mov r14,rbx
.node_row:
 mov eax,[r14]
 cmp r12d,4
 je .node_union
 cmp r12d,3
 jne .node_emit
.node_union:
 mov ecx,[rbx+hda_widget_info.caps]
 shr ecx,20
 and ecx,15
 cmp ecx,1
 ja .node_emit
 xor eax,eax                     ; legacy wire pin-only slots stay zero
.node_emit:
 call hlc_number
 add r14,4
 dec r12d
 jnz .node_row
 jmp .done
.edge:
 mov eax,[rel hln_graph+hda_graph.public_edge_count]
 call hlc_number
 mov eax,[rel hlc_args+8]
 call hlc_number
 mov r12d,6
 mov r14,rbx
 jmp .row
.pin:
 mov r12d,9
 mov r14,rbx
.row:
 mov eax,[r14]
 call hlc_number
 add r14,4
 dec r12d
 jnz .row
 jmp .done
.read:
 mov rax,[rel hlc_args+8]
 call hlc_number
 mov rax,[rel hlc_args+16]
 call hlc_number
 mov r14,[rel hlc_args+8]
 mov eax,[rel hln_input+hda_input.frame_bytes]
 imul r14,rax
 add r14,[rel hln_loop+hda_loopback.recording]
 mov r12,[rel hlc_args+16]
 imul r12,rax
.hex:
 movzx eax,byte [r14]
 mov edx,eax
 shr eax,4
 lea rsi,[rel hlc_digits]
 mov al,[rsi+rax]
 mov rdi,[rel hlc_cur]
 mov [rdi],al
 and edx,15
 mov al,[rsi+rdx]
 mov [rdi+1],al
 add qword [rel hlc_cur],2
 inc r14
 dec r12
 jnz .hex
.done:
 mov rdi,[rel hlc_cur]
 mov byte [rdi],0
 mov byte [rel hdaloop_out_ready],1
 add rsp,8
 ret
hlc_string:                       ; bounded known constant <=65 chars
 mov rdi,[rel hlc_cur]
.copy:
 lodsb
 test al,al
 jz .end
 stosb
 jmp .copy
.end:
 mov al,' '
 stosb
 mov [rel hlc_cur],rdi
 ret
hlc_number:                       ; unsigned64 decimal, max20 chars +space
 sub rsp,40
 lea rsi,[rsp+31]
 mov byte [rsi],0
 mov ecx,10
.convert:
 xor edx,edx
 div rcx
 add dl,'0'
 dec rsi
 mov [rsi],dl
 test rax,rax
 jnz .convert
 call hlc_string
 add rsp,40
 ret

align 8
hlc_verb: db "HDALOOP",0
hlc_boot_magic: db "HB1",0
hlc_magic: db "HL1",0
hlc_badarg: db "HLR1 5 0",0
hlc_denied: db "HLR1 6 0",0
hlc_names: db "OPEN",0,"STAT",0,"PIN",0,"SELECT",0,"RUN",0,"READ",0,"CANCEL",0,"RELEASE",0,"NODE",0,"EDGE",0,"HANDOFF",0,"DIAG",0,"PINOUT",0,"RUNOUT",0,"FORMAT",0
hlc_digits: db "0123456789abcdef"
align 8
%macro WDATA_hlc_state 0
hlc_cur:dq 0
hlc_args:times 10 dq 0
hlc_selection:times 8 dd 0
hlc_word:times 8 db 0
hlc_opcode:dd 0
hlc_count:dd 0
hdaloop_out_ready:db 0
hdaloop_out_buf:times HL1_RECORD_CAP db 0

%endmacro
WDATA_DEFER WDATA_hlc_state

; One-use diagnostic publication custody for serialized command dispatch.
; Not authority: native handler/registry gates above remain decisive.
hlc_diagnostic_begin:
 sub rsp,8
 call hlc_diagnostic_retire
 lea rdx,[rel hlc_diag_req]
 mov ecx,REQ_SZ/8
.req:
 mov rax,[r12+rcx*8-8]
 mov [rdx+rcx*8-8],rax
 loop .req
 mov rsi,[r12+REQ_ARG]
 test rsi,rsi
 jz .done
 lea rdx,[rel hlc_diag_arg]
 xor ecx,ecx
.arg:
 cmp ecx,32
 jae .done
 mov al,[rsi+rcx]
 mov [rdx+rcx],al
 test al,al
 jz .valid
 inc ecx
 jmp .arg
.valid:
 mov byte [rel hlc_diag_valid],1
.done:
 add rsp,8
 ret
hlc_diagnostic_retire:
 lea rdi,[rel hlc_diag_req]
 xor eax,eax
 mov ecx,REQ_SZ+32+8+1
 rep stosb
 mov byte [rel hdaloop_out_ready],0
 mov byte [rel hdaloop_out_buf],0
 mov qword [rel hlc_cur],0
 ret
%macro WDATA_hlc_diagnostic 0
hlc_diag_req: times REQ_SZ db 0
hlc_diag_arg: times 32 db 0
hlc_diag_end: dq 0
hlc_diag_valid: db 0
%endmacro
WDATA_DEFER WDATA_hlc_diagnostic
