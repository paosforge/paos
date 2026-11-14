; Original native single-controller terminal. Trusted160B record, BSP/IF0.
; See HDA_NATIVE_TERMINAL.md. No allocation, reset, cancellation or new cleanup.
; Every no-effect refusal retains all original RAM/device state. Once latched,
; all native and existing child producer entries remain denied, even on error.
%macro HLNT_SNAPSHOT 2
 mov eax,[rel %2]
 mov [r12+4*%1],eax
%endmacro
; Helpers use the exact original BDF and original PCI low16 write convention.
hlnt_cfg:
 mov edi,[rel hln_bdf]
 mov edx,edi
 and edx,7
 mov esi,edi
 shr esi,3
 and esi,31
 shr edi,8
 jmp pci_cfg_read32
hlnt_cfg_write:
 mov edi,[rel hln_bdf]
 mov edx,edi
 and edx,7
 mov esi,edi
 shr esi,3
 and esi,31
 shr edi,8
 mov ecx,4
 jmp pci_cfg_write32
hlnt_deny:
 mov rax,-1
 ret

hda_loopback_native_terminal:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8                       ; genuine SysV entry8 -> outgoing CALL0
 mov r12,rdi
 cld
 xor eax,eax
 mov ecx,40
 rep stosd
 mov dword [r12],1
 xor ebp,ebp
 HLNT_SNAPSHOT 5,hln_phase
 HLNT_SNAPSHOT 6,hln_error
 HLNT_SNAPSHOT 7,hln_bdf
 HLNT_SNAPSHOT 8,hln_epoch
 HLNT_SNAPSHOT 9,hln_epoch+4
 HLNT_SNAPSHOT 10,hln_serial
 HLNT_SNAPSHOT 11,hln_serial+4
 HLNT_SNAPSHOT 12,hln_loop+hda_loopback.phase
 HLNT_SNAPSHOT 13,hln_backend+hda_backend.phase
 HLNT_SNAPSHOT 14,hln_pcm+hda_pcm.phase
 HLNT_SNAPSHOT 15,hln_output+hda_output.state
 HLNT_SNAPSHOT 16,hln_input+hda_input.stream_phase
 HLNT_SNAPSHOT 17,hln_transport+hda_transport.pending
 HLNT_SNAPSHOT 18,hln_graph+hda_graph.clean
 HLNT_SNAPSHOT 20,hln_pci_id
 HLNT_SNAPSHOT 35,hln_loop+hda_loopback.query_state
 HLNT_SNAPSHOT 36,hln_graph+hda_graph.phase
 cmp qword [rel hln_slot],-1
 je .work0
 or dword [r12+4*19],1
.work0:
 cmp qword [rel hln_media_hook],0
 je .work1
 or dword [r12+4*19],2
.work1:
 cmp dword [rel hln_backend+hda_backend.registered],0
 je .work2
 or dword [r12+4*19],4
.work2:
 cmp dword [rel hln_pcm+hda_pcm.opened],0
 je .work3
 or dword [r12+4*19],8
.work3:
 cmp dword [rel hln_transport+hda_transport.fault],0
 je .work4
 or dword [r12+4*19],16
.work4:
 cmp dword [rel hln_graph+hda_graph.request_state],0
 je .work5
 or dword [r12+4*19],32
.work5:
 cmp dword [rel hln_graph+hda_graph.command_ready],0
 je .work6
 or dword [r12+4*19],64
.work6:
 cmp dword [rel hln_loop+hda_loopback.query_state],0
 je .work7
 or dword [r12+4*19],128
.work7:
 cmp qword [rel hln_mmio],0
 je .life0
 or dword [r12+4*37],1
.life0:
 cmp qword [rel hln_dma],0
 je .life1
 or dword [r12+4*37],2
.life1:
 cmp qword [rel hln_serial],0
 je .life2
 or dword [r12+4*37],4
.life2:
 cmp qword [rel hln_transport+hda_transport.mmio],0
 je .life3
 or dword [r12+4*37],8
.life3:
 cmp qword [rel hln_graph+hda_graph.mmio],0
 je .life4
 or dword [r12+4*37],16
.life4:
 cmp qword [rel hln_backend+hda_backend.graph],0
 je .life5
 or dword [r12+4*37],32
.life5:
 cmp qword [rel hln_loop+hda_loopback.backend],0
 je .life6
 or dword [r12+4*37],64
.life6:
 cmp qword [rel hln_pcm+hda_pcm.epoch],0
 je .life7
 or dword [r12+4*37],128
.life7:
 cmp qword [rel hln_input+hda_input.program+hda_route_program.epoch],0
 je .life8
 or dword [r12+4*37],256
.life8:
 cmp qword [rel hln_output+hda_output.mmio],0
 je .life9
 or dword [r12+4*37],512
.life9:
 cmp dword [rel hln_terminal_latched],0
 je .snapshot
 or dword [r12+4*37],1024
.snapshot:
 mov dword [r12+4*4],3          ; original RAM and context fields actually read
 cmp qword [rel hda_transport_power_gate],0
 je .hook0
 or dword [r12+4*34],1
.hook0:
 cmp qword [rel hda_session_power_gate],0
 je .hook1
 or dword [r12+4*34],2
.hook1:
 cmp qword [rel hda_route_program_power_gate],0
 je .hook2
 or dword [r12+4*34],4
.hook2:
 cmp qword [rel hda_output_power_gate],0
 je .hook3
 or dword [r12+4*34],8
.hook3:
 cmp qword [rel hda_pcm_power_gate],0
 je .hook4
 or dword [r12+4*34],16
.hook4:
 cmp qword [rel hda_input_power_gate],0
 je .hook5
 or dword [r12+4*34],32
.hook5:
 cmp qword [rel hda_backend_power_gate],0
 je .hook6
 or dword [r12+4*34],64
.hook6:
 mov ebp,1
 cmp dword [rel hln_terminal_latched],0
 jne .uncertain
 mov ebp,2
 pushfq
 pop rax
 test eax,0x200
 jnz .refuse
 mov ebp,3
 cmp dword [r12+4*19],0          ; actual work, not sticky exclusive claim
 jne .refuse
 cmp dword [r12+4*17],0
 jne .refuse
 mov ebp,4
 mov rbx,[rel hln_mmio]
 mov r13,[rel hln_epoch]
 mov r14,[rel hln_dma]
 mov r15,[rel hln_serial]
 test rbx,rbx
 jnz .owned
 ; Never-owned means empty original native lifetime, not physical PCI absence.
 cmp dword [r12+4*37],0
 jne .refuse
 cmp dword [r12+4*5],0
 jne .refuse
 mov eax,[r12+4*12]
 or eax,[r12+4*13]
 or eax,[r12+4*14]
 or eax,[r12+4*15]
 or eax,[r12+4*16]
 or eax,[r12+4*18]
 or eax,[r12+4*36]
 jnz .refuse
 xor ebp,ebp
 xor eax,eax
 jmp .out
.owned:
 cmp dword [rel hln_bdf],65535
 ja .refuse
 lea rax,[r13-1]
 cmp rax,65534
 ja .refuse
 cmp dword [r12+4*5],4           ; original completed bootstrap cancel
 je .bootstrap
 cmp dword [r12+4*5],5           ; original bootstrap release, no new reset
 je .bootstrap
 cmp dword [r12+4*5],2
 jne .refuse
 mov eax,[r12+4*12]
 cmp eax,HLB_DONE
 je .retired
 cmp eax,HLB_FAILED
 je .retired
 cmp eax,HLB_RELEASED
 jne .refuse
.retired:
 cmp dword [r12+4*13],HDAB_RETIRED
 jne .refuse
 cmp dword [r12+4*36],HDAGS_RETIRED
 jne .refuse
 cmp dword [r12+4*18],1
 jne .refuse
 ; Exact retained original contexts/lifetimes, never cached identity alone.
 lea rax,[rel hln_backend]
 cmp [rel hln_loop+hda_loopback.backend],rax
 jne .refuse
 lea rax,[rel hln_graph]
 cmp [rel hln_backend+hda_backend.graph],rax
 jne .refuse
 lea rax,[rel hln_program]
 cmp [rel hln_backend+hda_backend.program],rax
 jne .refuse
 lea rax,[rel hln_output]
 cmp [rel hln_backend+hda_backend.output],rax
 jne .refuse
 lea rax,[rel hln_pcm]
 cmp [rel hln_backend+hda_backend.pcm],rax
 jne .refuse
 lea rax,[rel hln_input]
 cmp [rel hln_backend+hda_backend.input],rax
 jne .refuse
 lea rax,[rel hln_lease]
 cmp [rel hln_graph+hda_graph.owner],rax
 jne .refuse
 lea rax,[rel hln_transport]
 cmp [rel hln_graph+hda_graph.transport],rax
 jne .refuse
 cmp [rel hln_loop+hda_loopback.epoch],r13
 jne .refuse
 cmp [rel hln_backend+hda_backend.epoch],r13
 jne .refuse
 cmp [rel hln_graph+hda_graph.epoch],r13
 jne .refuse
 cmp [rel hln_lease+hda_graph_lease.epoch],r13
 jne .refuse
 cmp [rel hln_backend+hda_backend.map_serial],r15
 jne .refuse
 cmp [rel hln_graph+hda_graph.mmio],rbx
 jne .refuse
 cmp qword [rel hln_lease+hda_graph_lease.holder],0
 jne .refuse
 cmp dword [rel hln_backend+hda_backend.pcm_bound],0
 je .pcm_unbound
 cmp dword [r12+4*14],HDPCM_RETIRED
 jne .refuse
 cmp dword [rel hln_graph+hda_graph.pcm_quiescent],1
 jne .refuse
 cmp [rel hln_pcm+hda_pcm.epoch],r13
 jne .refuse
 jmp .output
.pcm_unbound:
 cmp dword [r12+4*14],0
 jne .refuse
.output:
 cmp dword [rel hln_backend+hda_backend.output_bound],0
 je .output_unbound
 cmp dword [r12+4*15],HDAO_STOPPED
 jne .refuse
 cmp [rel hln_output+hda_output.mmio],rbx
 jne .refuse
 jmp .input
.output_unbound:
 cmp dword [r12+4*15],0
 jne .refuse
.input:
 mov eax,[rel hln_backend+hda_backend.input_state]
 test eax,eax
 jz .input_unbound
 cmp eax,6
 je .input_unbound
 cmp eax,5
 je .input_retired
 cmp eax,1
 jb .refuse
 cmp eax,4
 ja .refuse
 jmp .input_failed_clean
.input_retired:
 cmp dword [r12+4*16],HDI_RETIRED
 jne .refuse
 jmp .input_quiet
.input_failed_clean:
 ; Original backend may retain failed/cleanup-invalidated input as FAILED.
 ; Never call that input retired: only original graph clean+retire above and
 ; independent all-stream/command stop below can close controller ownership.
 cmp dword [r12+4*16],HDI_FAILED
 jne .refuse
 lea rax,[rel hln_input]
 cmp [rel hln_graph+hda_graph.input_owner],rax
 jne .refuse
.input_quiet:
 cmp dword [rel hln_graph+hda_graph.input_quiescent],1
 jne .refuse
 cmp [rel hln_input+hda_input.program+hda_route_program.epoch],r13
 jne .refuse
 jmp .lifetime_ok
.input_unbound:
 cmp dword [r12+4*16],0
 jne .refuse
 jmp .lifetime_ok
.bootstrap:
 ; No child work has begun in this original completed bootstrap cancellation.
 mov eax,[r12+4*12]
 or eax,[r12+4*13]
 or eax,[r12+4*14]
 or eax,[r12+4*15]
 or eax,[r12+4*16]
 or eax,[r12+4*18]
 or eax,[r12+4*36]
 jnz .refuse
.lifetime_ok:
 mov ebp,11
 cmp dword [r12+4*34],0
 jne .refuse                  ; do not steal retained coordinator hooks
 mov ebp,5
%ifdef PAOS_NATIVE_DRIVER_POLICY_LINKED
 mov edi,7
 mov rsi,-1
 call native_driver_gate
 jc .policy_refuse
 or dword [r12+4*4],4
%endif
 mov ebp,6
 xor ecx,ecx
 call hlnt_cfg
 mov [r12+4*21],eax
 or dword [r12+4*4],8
 cmp eax,-1
 je .refuse
 test eax,eax
 jz .refuse
 cmp eax,[rel hln_pci_id]
 jne .refuse
 mov ecx,0x10
 call hlnt_cfg
 mov [r12+4*24],eax
 mov edx,eax
 and edx,15
 cmp edx,0
 je .bar32
 cmp edx,4
 jne .refuse
 mov ecx,0x14
 call hlnt_cfg
 mov [r12+4*25],eax
 mov edx,eax
 shl rdx,32
 mov eax,[r12+4*24]
 and eax,0xfffffff0
 or rax,rdx
 jmp .bar
.bar32:
 mov eax,[r12+4*24]
 and eax,0xfffffff0
.bar:
 or dword [r12+4*4],16
 cmp rax,rbx
 jne .refuse
 test rbx,4095
 jnz .refuse
 mov rax,rbx
 shr rax,47
 jnz .refuse
 mov ecx,4
 call hlnt_cfg
 mov [r12+4*22],eax
 or dword [r12+4*4],128
 cmp eax,-1
 je .refuse
 test eax,2
 jz .refuse
 mov ebp,7
 mov rdi,rbx
 call paging_pd_entry_ptr
 test rax,rax
 jz .refuse
 mov rax,[rax]
 mov rdx,rax
 and edx,0x93
 cmp edx,0x93
 jne .refuse
 bt rax,63
 jnc .refuse
 mov rcx,0x000fffffffe00000
 and rax,rcx
 and rcx,rbx
 cmp rax,rcx
 jne .refuse
 or dword [r12+4*4],32
 mov ebp,8
 test r14,r14
 jz .no_dma
 test r15,r15
 jz .refuse
 call hln_live_receipt
 test eax,eax
 jnz .refuse
 or dword [r12+4*4],64
 jmp .mmio
.no_dma:
 test r15,r15
 jnz .refuse
.mmio:
 ; Only exact original mapping/identity/receipt can reach any observer MMIO.
 mov ebp,9
 movzx eax,word [rbx]
 mov [r12+4*26],eax
 or dword [r12+4*4],256
 cmp eax,65535
 je .refuse
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
 jz .refuse
 cmp ecx,30
 ja .refuse
 xor edx,edx
.scan:
 imul eax,edx,32
 movzx eax,byte [rbx+rax+0x80]
 cmp eax,255
 je .refuse
 test eax,2
 jz .next
 bts dword [r12+4*27],edx
.next:
 inc edx
 cmp edx,ecx
 jb .scan
 or dword [r12+4*4],512
 cmp dword [r12+4*27],0
 jne .refuse
 movzx eax,byte [rbx+0x4c]
 mov [r12+4*28],eax
 movzx eax,byte [rbx+0x5c]
 mov [r12+4*29],eax
 mov eax,[rbx+8]
 mov [r12+4*30],eax
 or dword [r12+4*4],1024
 cmp eax,-1
 je .refuse
 cmp dword [r12+4*28],255
 je .refuse
 cmp dword [r12+4*29],255
 je .refuse
 mov eax,[r12+4*28]
 or eax,[r12+4*29]
 test eax,2
 jnz .refuse
 ; Bootstrap completed cancellation must still be in original CRST0 state.
 cmp dword [r12+4*5],2
 je .position
 test byte [r12+4*30],1
 jnz .refuse
.position:
 mov ebp,10
 mov eax,[rbx+0x70]
 mov [r12+4*31],eax
 mov edx,[rbx+0x74]
 mov [r12+4*32],edx
 or dword [r12+4*4],2048
 cmp eax,-1
 je .refuse
 cmp edx,-1
 je .refuse
 shl rdx,32
 and eax,0xfffffffe
 or rdx,rax
 test r14,r14
 jz .empty_position
 lea rax,[r14+0x3000]
 cmp rax,r14
 jb .refuse
 cmp rdx,rax
 jne .refuse
 jmp .interrupt
.empty_position:
 test rdx,rdx
 jnz .refuse
.interrupt:
 mov eax,[rbx+0x20]
 mov [r12+4*33],eax
 or dword [r12+4*4],4096
 cmp eax,-1
 je .refuse
 mov dword [r12+4*3],1
 ; Original BSP/IF0 serialization excludes reentry. No callbacks after latch.
 mov dword [rel hln_terminal_latched],1
 lea rax,[rel hlnt_deny]
 mov [rel hda_transport_power_gate],rax
 mov [rel hda_session_power_gate],rax
 mov [rel hda_route_program_power_gate],rax
 mov [rel hda_output_power_gate],rax
 mov [rel hda_pcm_power_gate],rax
 mov [rel hda_input_power_gate],rax
 mov [rel hda_backend_power_gate],rax
 mov dword [r12+4*3],2
 mov ebp,12
 mov dword [rbx+0x20],0
 mov eax,[rbx+0x20]
 mov [r12+4*38],eax
 or dword [r12+4*4],8192
 test eax,eax
 jnz .uncertain
 mov dword [r12+4*3],3
 mov eax,[r12+4*31]
 and eax,0xfffffffe
 mov [rbx+0x70],eax
 mov eax,[rbx+0x70]
 mov [r12+4*39],eax
 or dword [r12+4*4],16384
 mov edx,[r12+4*31]
 and edx,0xfffffffe
 cmp eax,edx
 jne .uncertain
 mov dword [r12+4*3],4
 mov r8d,[r12+4*22]
 and r8d,0xfffb                 ; no PCI Status W1C bits; only own BM clear
 call hlnt_cfg_write
 mov ecx,4
 call hlnt_cfg
 mov [r12+4*23],eax
 or dword [r12+4*4],32768
 cmp eax,-1
 je .uncertain
 and eax,65535
 mov edx,[r12+4*22]
 and edx,0xfffb
 cmp eax,edx
 jne .uncertain
 mov dword [r12+4*3],5
 xor ebp,ebp
 mov eax,1
 jmp .out
.policy_refuse:
 or dword [r12+4*4],4
.refuse:
 mov eax,-1
 jmp .out
.uncertain:
 mov eax,-2
.out:
 mov [r12+4],eax
 mov [r12+8],ebp
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
%unmacro HLNT_SNAPSHOT 2
