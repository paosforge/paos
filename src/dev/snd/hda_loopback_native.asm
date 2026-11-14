;; MODULE dev/snd/hda_loopback_native
;; LAYER 3
;; EXPORTS hda_loopback_native_open, hda_loopback_native_tick, hda_loopback_native_busy, hln_loop, hln_bdf, hln_epoch, hln_phase, hln_error, hln_serial, hda_loopback_native_cancel, hda_loopback_native_release, hda_loopback_native_terminal
;; IMPORTS boot/native_driver_gate, dev/snd/hda_loopback, dev/snd/hda_runtime, dev/snd/hda_transport, dev/snd/hda_session, dev/snd/hda_route_program, dev/snd/hda_output, dev/snd/hda_pcm, dev/snd/hda_input, dev/snd/hda_backend, bus/pci, boot/paging, core/time, core/dma, core/cadence
;; CAPS mmio dma
;; OWNER rc-codex-av
%include "boot/native_driver_gate.inc"
; Explicit typed owner command only. No boot allocation, PCI scan or playback.
; Single pinned controller lifetime. Never reuse/free an uncertain DMA arena.
; All reset and ring handshakes are bounded cooperative cadence operations.
; HDA_TONE and this owner exclude each other; no second timer or auth rail.
; Actual DID3 receipt precedes ALL DMA address-register writes; no fallback.

%macro HLN_PCI 1
 mov edi,[rel hln_bdf]
 mov edx,edi
 and edx,7
 mov esi,edi
 shr esi,3
 and esi,31
 shr edi,8
 mov ecx,%1
 call pci_cfg_read32
%endmacro
hda_loopback_native_busy:
 mov rax,[rel hln_mmio]
 ret
hda_loopback_native_open:             ; EDI=packed BDF, RSI=epoch
 cmp dword [rel hln_terminal_latched],0
 jne .terminal_refused
 ; Same original class7 policy, with genuine SysV CALL alignment and CF intact.
%ifdef PAOS_NATIVE_DRIVER_POLICY_LINKED
 push rdi
 push rsi
 sub rsp,8
 mov edi,7
 mov rsi,-1
 call native_driver_gate
 lea rsp,[rsp+8]
 pop rsi
 pop rdi
 jc .terminal_refused
%endif
 push rbx
 push rbp
 push r12
 mov ebp,edi
 mov r12,rsi
 cmp edi,65535
 ja .bad
 lea rax,[rsi-1]
 cmp rax,65534
 ja .bad
 cmp qword [rel hln_mmio],0
 jne .bad
 ; Preclaim diagnostics: owner state only; no PCI/MMIO write or DMA grant.
 mov [rel hln_bdf],ebp
 mov [rel hln_epoch],r12
 mov dword [rel hln_error],16       ; clock unavailable
 cmp qword [rel tsc_khz],0
 je .bad
 mov dword [rel hln_error],17       ; legacy probe owns the controller
 call hda_probe_controller_busy
 test rax,rax
 jnz .bad
 mov dword [rel hln_error],10       ; unsupported vendor
 HLN_PCI 0
 mov [rel hln_pci_id],eax           ; exact checked function, not codec ID
 cmp ax,0x8086
 je .vendor
 cmp ax,0x1022
 jne .bad
.vendor:
 mov dword [rel hln_error],11       ; unsupported class/interface
 HLN_PCI 8
 shr eax,8
 and eax,0xffff7f                  ; HDA progIF00 or observed progIF80 only
 cmp eax,0x040300
 jne .bad
 mov dword [rel hln_error],12       ; unsupported BAR type/prefetch
 HLN_PCI 0x10
 mov ebx,eax
 and eax,15
 cmp eax,0
 je .bar32
 cmp eax,4
 jne .bad
 HLN_PCI 0x14
 shl rax,32
 and ebx,0xfffffff0
 or rbx,rax
 jmp .bar
.bar32:
 and ebx,0xfffffff0
.bar:
 mov dword [rel hln_error],13       ; invalid BAR address
 test rbx,rbx
 jz .bad
 test ebx,4095
 jnz .bad
 mov rax,rbx
 shr rax,47
 jnz .bad
 mov dword [rel hln_error],20       ; no live PDE pointer
 mov rdi,rbx
 call paging_pd_entry_ptr
 test rax,rax
 jz .bad
 mov rax,[rax]
 ; Same P|RW|PCD|PS|NX predicates, each reported before any MMIO read.
 mov dword [rel hln_error],21       ; PDE nonpresent
 test al,1
 jz .bad
 mov dword [rel hln_error],22       ; PDE not writable
 test al,2
 jz .bad
 mov dword [rel hln_error],23       ; PDE cache-disable missing
 test al,0x10
 jz .bad
 mov dword [rel hln_error],24       ; PDE is not a 2MiB leaf
 test al,0x80
 jz .bad
 mov dword [rel hln_error],25       ; PDE executable
 bt rax,63
 jnc .bad
 mov dword [rel hln_error],26       ; PDE physical base differs from BAR
 mov rcx,0x000fffffffe00000
 and rax,rcx
 and rcx,rbx
 cmp rax,rcx
 jne .bad
 mov dword [rel hln_error],31       ; PCI memory decode disabled; MMIO invalid
 HLN_PCI 4
 test al,2
 jz .bad
 mov dword [rel hln_error],27       ; foreign CORB RUN
 ; Refuse foreign stream/command DMA before any write or domain attachment.
 test byte [rbx+0x4c],2
 jnz .bad
 mov dword [rel hln_error],28       ; foreign RIRB DMAEN
 test byte [rbx+0x5c],2
 jnz .bad
 movzx eax,word [rbx]
 mov ecx,eax
 shr ecx,8
 and ecx,15
 mov edx,eax
 shr edx,12
 and edx,15
 add ecx,edx
 shr eax,3
 and eax,31
 add ecx,eax
 mov dword [rel hln_error],29       ; no stream descriptors
 test ecx,ecx
 jz .bad
 mov dword [rel hln_error],30       ; unsupported stream count
 cmp ecx,30
 ja .bad
 xor edx,edx
.sd:
 lea eax,[rdx+32]                 ; foreign SD RUN: code32 + actual index
 mov [rel hln_error],eax
 imul eax,edx,32
 test byte [rbx+rax+0x80],2
 jnz .bad
 inc edx
 cmp edx,ecx
 jb .sd
 mov [rel hln_mmio],rbx            ; sticky exclusive claim, even on failure
 mov [rel hln_epoch],r12
 mov dword [rel hln_phase],1
 mov dword [rel hln_error],0
 ; Enable MEM/BM only after owner and live mapping validation. No PCI Status.
 HLN_PCI 4
 and eax,65535
 or eax,6
 mov r8d,eax
 mov edi,ebp
 mov edx,edi
 and edx,7
 mov esi,edi
 shr esi,3
 and esi,31
 shr edi,8
 mov ecx,4
 call pci_cfg_write32
 HLN_PCI 4
 and eax,6
 cmp eax,6
 jne .claimed_fail
 mov rcx,[rel tsc_khz]            ; kHz = calibrated TSC ticks per 1ms
 test rcx,rcx
 jz .claimed_fail
 lea rdi,[rel hln_cadence_name]
 mov esi,1                       ; canonical on-demand cadence class
 mov edx,1000
 lea r8,[rel hda_loopback_native_tick]
 call cadence_register_named
 cmp eax,-1
 je .claimed_fail
 mov [rel hln_slot],rax
 xor eax,eax
 jmp .out
.claimed_fail:
 mov dword [rel hln_phase],3
 mov dword [rel hln_error],1
.bad:
 mov rax,-1
.out:
 pop r12
 pop rbp
 pop rbx
 ret
.terminal_refused:
 mov rax,-1
 ret

hda_loopback_native_cancel:       ; RSI=exact epoch
 cmp dword [rel hln_terminal_latched],0
 jne .bad
 cmp rsi,[rel hln_epoch]
 jne .bad
 cmp dword [rel hln_phase],1
 je .boot
 cmp dword [rel hln_phase],2
 jne .bad
 lea rdi,[rel hln_loop]
 jmp hda_loopback_cancel
.boot:
 mov dword [rel hln_cancel],1
 xor eax,eax
 ret
.bad:
 mov rax,-1
 ret
hda_loopback_native_release:
 cmp dword [rel hln_terminal_latched],0
 jne .bad
 cmp rsi,[rel hln_epoch]
 jne .bad
 cmp dword [rel hln_phase],4
 je .boot
 cmp dword [rel hln_phase],2
 jne .bad
 lea rdi,[rel hln_loop]
 jmp hda_loopback_release
.boot:
 mov dword [rel hln_phase],5
 xor eax,eax
 ret
.bad:
 mov rax,-1
 ret

hln_stream_check:
 movzx eax,word [rbx]
 mov ecx,eax
 shr ecx,8
 and ecx,15
 mov edx,eax
 shr edx,12
 and edx,15
 add ecx,edx
 shr eax,3
 and eax,31
 add ecx,eax
 test ecx,ecx
 jz .bad
 cmp ecx,30
 ja .bad
 xor edx,edx
.scan:
 imul eax,edx,32
 test byte [rbx+rax+0x80],2
 jnz .bad
 inc edx
 cmp edx,ecx
 jb .scan
 xor eax,eax
 ret
.bad:
 mov eax,-1
 ret

hln_clock:                       ; graph callback: microseconds/known clock
 push rbx
 mov rbx,rsi
 cmp qword [rel tsc_khz],0
 je .bad
 call time_monotonic_now_us
 mov [rbx],rax
 xor eax,eax
 pop rbx
 ret
.bad:
 mov rax,-1
 pop rbx
 ret

hda_loopback_native_tick:
 cmp dword [rel hln_terminal_latched],0
 jne .terminal_out
 push rbx
 mov eax,[rel hln_phase]
 cmp eax,1
 je .bootstrap
 cmp eax,2
 jne .out
 ; Optional explicitly armed native media owner. A bounded file/decode turn
 ; returns1 to defer HDA work,0 to run it,-1 to use ordinary owner cleanup.
 ; The hook is never armed by boot and owns no hardware reset/DMA operation.
 mov rax,[rel hln_media_hook]
 test rax,rax
 jz .owner_step
 call rax
 test rax,rax
 js .media_cancel
 jnz .out
 jmp .owner_step
.media_cancel:
 mov qword [rel hln_media_hook],0
 mov rsi,[rel hln_epoch]
 call hda_loopback_native_cancel
.owner_step:
 lea rdi,[rel hln_loop]
 mov rsi,[rel hln_epoch]
 call hda_loopback_step
 cmp dword [rel hln_loop+hda_loopback.phase],HLB_DONE
 jb .out
 call hln_unschedule
 jmp .out
.bootstrap:
 cmp dword [rel hln_cancel],0
 jne .boot_cancel
 xor edi,edi
 call hln_reset
 cmp eax,1
 je .out
 test eax,eax
 jnz .failed
 call hln_setup
 mov dword [rel hln_phase],2
 lea rdi,[rel hln_loop]
 mov rsi,[rel hln_epoch]
 call hda_loopback_begin
 test rax,rax
 jz .out
.boot_cancel:
 mov rbx,[rel hln_mmio]
 call hln_stream_check
 test eax,eax
 jnz .failed
 call time_monotonic_now_us
 cmp dword [rel hln_cancel],1
 jne .cancel_poll
 add rax,50000
 jc .failed
 mov [rel hln_deadline],rax
 mov dword [rel hln_reset_polls],0
 mov dword [rel hln_cancel],2
 mov byte [rbx+0x4c],0
 mov byte [rbx+0x5c],0
 and dword [rbx+8],0xfffffefe
 jmp .out
.cancel_poll:
 inc dword [rel hln_reset_polls]
 cmp dword [rel hln_reset_polls],4096
 ja .failed
 cmp rax,[rel hln_deadline]
 jae .failed
 test byte [rbx+8],1
 jnz .out
 test byte [rbx+0x4c],2
 jnz .out
 test byte [rbx+0x5c],2
 jnz .out
 mov dword [rel hln_phase],4
 call hln_unschedule
 jmp .out
.failed:
 mov dword [rel hln_phase],3
 mov dword [rel hln_error],2
 call hln_unschedule              ; uncertainty keeps all memory/controller claim
.out:
 pop rbx
 ret
.terminal_out:
 ret
hln_unschedule:
 sub rsp,8
 mov rdi,[rel hln_slot]
 cmp rdi,-1
 je .out
 call cadence_unregister
 mov qword [rel hln_slot],-1
.out:
 add rsp,8
 ret

; Sole reset callback. Check every SD RUN before reset, including unused streams.
; CRST, CORBRP/RIRBWP and W1C status must read back; plain writes never prove stop.
; Each invocation <=one reset transition, 50ms deadline+4096 poll hard ceiling.
hln_reset:
 push rbx
 push r12
 push r13
 mov rbx,[rel hln_mmio]
 call time_monotonic_now_us
 mov r12,rax
 cmp rax,[rel hln_last_now]
 mov r13d,1                  ; retained first refusal, MOV preserves flags
 jb .bad
 mov [rel hln_last_now],rax
 cmp dword [rel hln_reset_state],0
 jne .bounded
 add rax,50000
 mov r13d,2                  ; retained first refusal, MOV preserves flags
 jc .bad
 mov [rel hln_deadline],rax
 mov dword [rel hln_reset_polls],0
.bounded:
 inc dword [rel hln_reset_polls]
 cmp dword [rel hln_reset_polls],4096
 mov r13d,3                  ; retained first refusal, MOV preserves flags
 ja .bad
 cmp r12,[rel hln_deadline]
 mov r13d,4                  ; retained first refusal, MOV preserves flags
 jae .bad
 movzx eax,word [rbx]
 mov ecx,eax
 shr ecx,8
 and ecx,15
 mov edx,eax
 shr edx,12
 and edx,15
 add ecx,edx
 shr eax,3
 and eax,31
 add ecx,eax
 test ecx,ecx
 mov r13d,5                  ; retained first refusal, MOV preserves flags
 jz .bad
 cmp ecx,30
 mov r13d,6                  ; retained first refusal, MOV preserves flags
 ja .bad
 xor edx,edx
.sd:
 imul eax,edx,32
 test byte [rbx+rax+0x80],2
 mov r13d,7                  ; retained first refusal, MOV preserves flags
 jnz .bad
 inc edx
 cmp edx,ecx
 jb .sd
 mov eax,[rel hln_reset_state]
 cmp eax,0
 je .stop
 cmp eax,1
 je .crst_clear
 cmp eax,2
 je .deassert
 cmp eax,3
 je .rings
 cmp eax,4
 je .rp_assert
 cmp eax,5
 je .rp_clear
 cmp eax,6
 je .finish
 mov r13d,8                  ; retained first refusal, MOV preserves flags
 jmp .bad
.stop:
 mov dword [rbx+0x20],0
 mov word [rbx+0x0c],0
 mov byte [rbx+0x4c],0
 mov byte [rbx+0x5c],0
 and dword [rbx+0x70],0xfffffffe ; stop owned position DMA before strict reset receipt
 mov dword [rel hln_reset_state],1
 mov r13d,0                   ; transition/defer, no blocked predicate
 jmp .pending
.crst_clear:
 test byte [rbx+0x70],1
 mov r13d,101                ; exact pending readback/dwell
 jnz .pending
 test byte [rbx+0x4c],2
 mov r13d,102                ; exact pending readback/dwell
 jnz .pending
 test byte [rbx+0x5c],2
 mov r13d,103                ; exact pending readback/dwell
 jnz .pending
 and dword [rbx+8],0xfffffefe
 mov dword [rel hln_reset_state],2
 mov dword [rel hln_clear_seen],0
 mov r13d,0                   ; transition/defer, no blocked predicate
 jmp .pending
.deassert:
 test byte [rbx+8],1
 mov r13d,104                ; exact pending readback/dwell
 jnz .pending
 cmp dword [rel hln_clear_seen],0
 jne .reset_dwell
 mov dword [rel hln_clear_seen],1
 mov [rel hln_reset_time],r12
 mov r13d,0                   ; transition/defer, no blocked predicate
 jmp .pending
.reset_dwell:
 mov rax,r12
 sub rax,[rel hln_reset_time]
 cmp rax,100
 mov r13d,105                ; exact pending readback/dwell
 jb .pending
 cmp qword [rel hln_dma],0
 jne .receipt
 ; Bootstrap allocation/attach is exclusively in read-back CRST0. No replay.
 cmp dword [rel hln_phase],1
 mov r13d,9                  ; retained first refusal, MOV preserves flags
 jne .bad
 mov edi,131072
 mov esi,1
 call dma_alloc_domain
 test rax,rax
 mov r13d,11                  ; retained first refusal, MOV preserves flags
 jz .bad
 mov [rel hln_dma],rax             ; pinned even if attach refuses
 mov edi,[rel hln_bdf]
 mov rsi,rbx
 mov edx,1
 call dma_domain_attach
 test eax,eax
 mov r13d,12                  ; retained first refusal, MOV preserves flags
 jnz .bad
 mov edi,1
 call dma_domain_receipt
 cmp eax,1
 mov r13d,13                  ; retained first refusal, MOV preserves flags
 jne .bad
 test rdx,rdx
 mov r13d,14                  ; retained first refusal, MOV preserves flags
 jz .bad
 mov [rel hln_serial],rdx
 jmp .address
.receipt:
 call hln_receipt
 test eax,eax
 mov r13d,15                  ; retained first refusal, MOV preserves flags
 jnz .bad
.address:
 mov rax,[rel hln_dma]
 add rax,131071
 mov r13d,16                  ; retained first refusal, MOV preserves flags
 jc .bad
 test word [rbx],1
 jnz .high_ok
 shr rax,32
 mov r13d,17                  ; retained first refusal, MOV preserves flags
 jnz .bad
.high_ok:
 or dword [rbx+8],1
 mov dword [rel hln_set_seen],0
 mov dword [rel hln_reset_state],3
 mov r13d,0                   ; transition/defer, no blocked predicate
 jmp .pending
.rings:
 test byte [rbx+8],1
 mov r13d,106                ; exact pending readback/dwell
 jz .pending
 cmp dword [rel hln_set_seen],0
 jne .codec_dwell
 mov dword [rel hln_set_seen],1
 mov [rel hln_reset_time],r12
 mov r13d,0                   ; transition/defer, no blocked predicate
 jmp .pending
.codec_dwell:
 mov rax,r12
 sub rax,[rel hln_reset_time]
 cmp rax,1000
 mov r13d,107                ; exact pending readback/dwell
 jb .pending
 call hln_live_receipt
 test eax,eax
 mov r13d,18                  ; retained first refusal, MOV preserves flags
 jnz .bad
 test byte [rbx+0x4e],0x40
 mov r13d,19                  ; retained first refusal, MOV preserves flags
 jz .bad
 test byte [rbx+0x5e],0x40
 mov r13d,20                  ; retained first refusal, MOV preserves flags
 jz .bad
 mov rdi,[rel hln_dma]
 xor eax,eax
 mov ecx,8192/8                  ; retain prebound BDL/stream/position bytes
 cmp dword [rel hln_phase],1
 jne .clear_rings
 mov ecx,131072/8                ; fresh bootstrap, before any output bind
.clear_rings:
 rep stosq
 mov byte [rbx+0x4e],2
 mov byte [rbx+0x5e],2
 mov rax,[rel hln_dma]
 mov [rbx+0x40],eax
 shr rax,32
 mov [rbx+0x44],eax
 mov rax,[rel hln_dma]
 add rax,0x1000
 mov [rbx+0x50],eax
 shr rax,32
 mov [rbx+0x54],eax
 ; Restore the SAME immutable position binding after CRST. Streams stopped.
 mov rax,[rel hln_dma]
 add rax,0x3000
 mov rdx,rax
 shr rdx,32
 mov [rbx+0x74],edx
 or rax,1
 mov [rbx+0x70],eax
 mov word [rbx+0x4a],0x8000
 mov dword [rel hln_reset_state],4
 mov r13d,0                   ; transition/defer, no blocked predicate
 jmp .pending
.rp_assert:
 test word [rbx+0x4a],0x8000
 mov r13d,108                ; exact pending readback/dwell
 jz .pending
 mov word [rbx+0x4a],0
 mov dword [rel hln_reset_state],5
 mov r13d,0                   ; transition/defer, no blocked predicate
 jmp .pending
.rp_clear:
 test word [rbx+0x4a],0x8000
 mov r13d,109                ; exact pending readback/dwell
 jnz .pending
 mov word [rbx+0x48],0
 mov word [rbx+0x58],0x8000
 mov word [rbx+0x5a],1
 mov byte [rbx+0x4d],1
 mov byte [rbx+0x5d],5
 mov dword [rel hln_reset_state],6
 mov r13d,0                   ; transition/defer, no blocked predicate
 jmp .pending
.finish:
 test word [rbx+0x58],0x80ff
 mov r13d,110                ; exact pending readback/dwell
 jnz .pending
 test byte [rbx+0x4d],1
 mov r13d,111                ; exact pending readback/dwell
 jnz .pending
 test byte [rbx+0x5d],4
 mov r13d,112                ; exact pending readback/dwell
 jnz .pending
 call hln_live_receipt
 test eax,eax
 mov r13d,21                  ; retained first refusal, MOV preserves flags
 jnz .bad
 lea rdi,[rel hln_transport]
 xor eax,eax
 mov ecx,hda_transport_size/8
 rep stosq
 mov [rel hln_transport+hda_transport.mmio],rbx
 mov rax,[rel hln_dma]
 mov [rel hln_transport+hda_transport.corb],rax
 add rax,0x1000
 mov [rel hln_transport+hda_transport.rirb],rax
 cmp dword [rel hln_phase],1
 je .quiet
 cmp dword [rel hln_graph+hda_graph.phase],HDAGS_CLEANUP
 je .quiet
 sfence
 ; Local response status enabled; global INTCTL remains masked.
 mov byte [rbx+0x5c],3
 mov byte [rbx+0x4c],2
.quiet:
 mov dword [rel hln_reset_state],0
 xor eax,eax
 jmp .out
.pending:
 mov [rel hln_reset_wait],r13d
 mov eax,1
 jmp .out
.bad:
 cmp dword [rel hln_reset_refusal],0
 jne .known_refusal
 mov [rel hln_reset_refusal],r13d
 mov eax,[rel hln_reset_state]
 mov [rel hln_reset_failure_state],eax
 mov eax,[rel hln_reset_polls]
 mov [rel hln_reset_failure_polls],eax
 mov eax,[rel hln_reset_wait]
 mov [rel hln_reset_failure_wait],eax
 mov eax,[rel hln_phase]
 mov [rel hln_reset_failure_phase],eax
.known_refusal:
 mov rax,-1
.out:
 pop r13
 pop r12
 pop rbx
 ret

hln_receipt:
 sub rsp,8
 mov edi,1
 call dma_domain_receipt
 cmp eax,1
 jne .bad
 cmp rdx,[rel hln_serial]
 jne .bad
 xor eax,eax
 jmp .out
.bad:
 mov eax,-1
.out:
 add rsp,8
 ret

hln_live_receipt:
 sub rsp,8
 mov edi,1
 call dma_domain_live_receipt
 cmp eax,1
 jne .bad
 cmp rdx,[rel hln_serial]
 jne .bad
 xor eax,eax
 jmp .out
.bad:
 mov eax,-1
.out:
 add rsp,8
 ret

hln_setup:
 lea rax,[rel hln_graph]
 mov [rel hln_lease+hda_graph_lease.holder],rax
 mov rax,[rel hln_epoch]
 mov [rel hln_lease+hda_graph_lease.epoch],rax
 lea rax,[rel hln_transport]
 mov [rel hln_lease+hda_graph_lease.transport],rax
 lea rax,[rel hln_lease]
 mov [rel hln_graph+hda_graph.owner],rax
 lea rax,[rel hln_reset]
 mov [rel hln_graph+hda_graph.reset_fn],rax
 lea rax,[rel hln_clock]
 mov [rel hln_graph+hda_graph.clock_fn],rax
 lea rax,[rel hln_codecs]
 mov [rel hln_graph+hda_graph.codecs],rax
 lea rax,[rel hln_groups]
 mov [rel hln_graph+hda_graph.groups],rax
 lea rax,[rel hln_widgets]
 mov [rel hln_graph+hda_graph.widgets],rax
 lea rax,[rel hln_edges]
 mov [rel hln_graph+hda_graph.edges],rax
 mov rax,50000
 mov [rel hln_graph+hda_graph.command_timeout],rax
 mov rax,5000000
 mov [rel hln_graph+hda_graph.session_timeout],rax
 mov dword [rel hln_graph+hda_graph.codec_cap],15
 mov dword [rel hln_graph+hda_graph.group_cap],32
 mov dword [rel hln_graph+hda_graph.widget_cap],256
 mov dword [rel hln_graph+hda_graph.edge_cap],512
 mov dword [rel hln_graph+hda_graph.poll_limit],4096
 mov dword [rel hln_graph+hda_graph.step_limit],100000
 mov rax,[rel hln_mmio]
 movzx eax,word [rax+0x0e]
 and eax,0x7fff
 mov [rel hln_graph+hda_graph.statests],eax
 bsf eax,eax
 mov [rel hln_graph+hda_graph.primary],eax
 lea rax,[rel hln_graph]
 mov [rel hln_backend+hda_backend.graph],rax
 lea rax,[rel hln_program]
 mov [rel hln_backend+hda_backend.program],rax
 lea rax,[rel hln_output]
 mov [rel hln_backend+hda_backend.output],rax
 lea rax,[rel hln_pcm]
 mov [rel hln_backend+hda_backend.pcm],rax
 lea rax,[rel hln_input]
 mov [rel hln_backend+hda_backend.input],rax
 mov rax,[rel hln_serial]
 mov [rel hln_backend+hda_backend.map_serial],rax
 lea rax,[rel hln_graph]
 mov [rel hln_program+hda_route_program.graph],rax
 mov dword [rel hln_program+hda_route_program.format],0x4011
 mov dword [rel hln_program+hda_route_program.tag],1
 mov rax,[rel hln_mmio]
 mov [rel hln_output+hda_output.mmio],rax
 mov eax,[rel hln_pci_id]
 mov [rel hln_output+hda_output.pci_id],rax
 mov rax,5000
 mov [rel hln_output+hda_output.timeout],rax
 mov rax,[rel hln_dma]
 add rax,8192
 mov [rel hln_output+hda_output.bdl],rax
 mov [rel hln_output+hda_output.bdl_dma],rax
 mov rax,[rel hln_dma]
 add rax,16384
 mov [rel hln_output+hda_output.pcm],rax
 mov [rel hln_output+hda_output.pcm_dma],rax
 mov rax,[rel hln_dma]
 add rax,12288
 mov [rel hln_output+hda_output.position],rax
 mov [rel hln_output+hda_output.position_dma],rax
 mov dword [rel hln_output+hda_output.mmio_bytes],4096
 mov dword [rel hln_output+hda_output.bdl_bytes],64
 mov dword [rel hln_output+hda_output.pcm_bytes],16384
 mov dword [rel hln_output+hda_output.position_bytes],256
 lea rax,[rel hln_graph]
 mov [rel hln_pcm+hda_pcm.graph],rax
 lea rax,[rel hln_program]
 mov [rel hln_pcm+hda_pcm.program],rax
 lea rax,[rel hln_output]
 mov [rel hln_pcm+hda_pcm.output],rax
 lea rax,[rel hln_out_queue]
 mov [rel hln_pcm+hda_pcm.queue],rax
 mov rax,32768
 mov [rel hln_pcm+hda_pcm.queue_bytes],rax
 mov rax,[rel hln_serial]
 mov [rel hln_pcm+hda_pcm.map_serial],rax
 lea rax,[rel hln_clock]
 mov [rel hln_pcm+hda_pcm.clock_fn],rax
 mov rax,1000000
 mov [rel hln_pcm+hda_pcm.clock_hz],rax
 mov dword [rel hln_pcm+hda_pcm.rate],44100
 mov dword [rel hln_pcm+hda_pcm.channels],1
 mov dword [rel hln_pcm+hda_pcm.backend_id],19522
 mov dword [rel hln_pcm+hda_pcm.poll_limit],4096
 lea rax,[rel hln_graph]
 mov [rel hln_input+hda_input.program+hda_route_program.graph],rax
 mov dword [rel hln_input+hda_input.program+hda_route_program.format],0x4011
 mov dword [rel hln_input+hda_input.program+hda_route_program.tag],2
 mov rax,[rel hln_dma]
 add rax,32768
 mov [rel hln_input+hda_input.bdl],rax
 mov [rel hln_input+hda_input.bdl_dma],rax
 mov rax,[rel hln_dma]
 add rax,49152
 mov [rel hln_input+hda_input.pcm],rax
 mov [rel hln_input+hda_input.pcm_dma],rax
 mov rax,[rel hln_dma]
 add rax,12288
 mov [rel hln_input+hda_input.position],rax
 mov [rel hln_input+hda_input.position_dma],rax
 lea rax,[rel hln_in_queue]
 mov [rel hln_input+hda_input.queue],rax
 mov rax,8192
 mov [rel hln_input+hda_input.queue_bytes],rax
 mov rax,[rel hln_serial]
 mov [rel hln_input+hda_input.map_serial],rax
 mov rax,1000000
 mov [rel hln_input+hda_input.clock_hz],rax
 mov dword [rel hln_input+hda_input.rate],44100
 mov dword [rel hln_input+hda_input.vref],0
 mov dword [rel hln_input+hda_input.sd_index],0
 mov dword [rel hln_input+hda_input.batch_frames],2048
 lea rax,[rel hln_backend]
 mov [rel hln_loop+hda_loopback.backend],rax
 lea rax,[rel hln_pins]
 mov [rel hln_loop+hda_loopback.pins],rax
 lea rax,[rel hln_recording]
 mov [rel hln_loop+hda_loopback.recording],rax
 ret

%include "dev/snd/hda_terminal.inc"

align 8
hln_cadence_name: db "hda-owner-loopback",0
align 8
%macro WDATA_hln_state 0
hln_slot: dq -1
hln_media_hook: dq 0
hln_mmio: dq 0
hln_dma: dq 0
hln_serial: dq 0
hln_epoch: dq 0
hln_phase: dd 0
hln_error: dd 0
hln_terminal_latched: dd 0         ; one-way terminal fence; no clear/rearm path
hln_cancel: dd 0
hln_bdf: dd 0
hln_pci_id: dd 0
hln_reset_state: dd 0
hln_reset_polls: dd 0
hln_reset_refusal: dd 0
hln_reset_failure_state: dd 0
hln_reset_failure_polls: dd 0
hln_reset_failure_wait: dd 0
hln_reset_failure_phase: dd 0
hln_reset_wait: dd 0
hln_clear_seen: dd 0
hln_set_seen: dd 0
align 8
hln_last_now: dq 0
hln_deadline: dq 0
hln_reset_time: dq 0
align 8
hln_lease: times hda_graph_lease_size db 0
align 8
hln_transport: times hda_transport_size db 0
align 8
hln_graph: times hda_graph_size db 0
align 8
hln_program: times hda_route_program_size db 0
align 8
hln_output: times hda_output_size db 0
align 8
hln_pcm: times hda_pcm_size db 0
align 8
hln_input: times hda_input_size db 0
align 8
hln_backend: times hda_backend_size db 0
align 8
hln_loop: times hda_loopback_size db 0
align 8
hln_pins: times 256*hda_loopback_pin_size db 0
align 8
hln_recording: times 8192 db 0
align 8
hln_codecs: times 15*hda_codec_info_size db 0
align 8
hln_groups: times 32*hda_group_info_size db 0
align 8
hln_widgets: times 256*hda_widget_info_size db 0
align 8
hln_edges: times 512*hda_route_edge_size db 0
align 8
hln_out_queue: times 32768 db 0
align 8
hln_in_queue: times 8192 db 0

%endmacro
WDATA_DEFER WDATA_hln_state
