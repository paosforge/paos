;; MODULE media/flac_producer
;; LAYER 4
;; EXPORTS media_flac_producer_begin, media_flac_producer_step, media_flac_producer_cancel
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
; Private UNWIRED S16 Classic0cab/accepted-RC port. AUTHORIZED ADAPTATIONS:
; resumable orchestration and incremental MD5. No allocation, globals or DMA.
; Trusted stable mapped full caller spans, serialized; encoded CONTENT untrusted.
; Context192, workspace398592; reserved zero. Source<=307200, PCM<=192000.
; Negative preserves ctx/source/PCM for this call; workspace may be dirty.
; Owner must cancel/discard any negative. No prefix/old READY publication.
; One stage/turn;<=4096 bits,256 scalar samples,8192 taps,1024 CRC bytes,
; <=512 output bytes/8 MD5 blocks. SysV nonvolatiles/RSP/DF preserved.

struc fpp_ctx
 .version: resd 1
 .phase: resd 1
 .generation: resq 1
 .epoch: resq 1
 .src: resq 1
 .src_bytes: resq 1
 .pcm: resq 1
 .capacity: resq 1
 .offset: resq 1
 .encoded_frames: resq 1
 .workspace: resq 1
 .workspace_bytes: resq 1
 .budget: resq 1
 .cursor: resq 1
 .frames: resq 1
 .bytes: resq 1
 .rate: resd 1
 .channels: resd 1
 .bits: resd 1
 .input_frame: resd 1
 .substate: resq 1
 .integrity: resq 1
 .reserved: resq 5
endstruc
struc fpp_info
 .src: resq 1
 .src_bytes: resq 1
 .sample_rate: resd 1
 .channels: resd 1
 .bits_per_sample: resd 1
 .min_block_size: resd 1
 .max_block_size: resd 1
 .min_frame_bytes: resd 1
 .max_frame_bytes: resd 1
 .metadata_blocks: resd 1
 .total_samples: resq 1
 .audio_offset: resq 1
 .stream_md5: resb 16
endstruc
struc fpp_work
 .bitpos: resq 1
 .width: resd 1
 .pad: resd 1
endstruc
struc fpp_state
 .ctx: resb 192
 .info: resb 80
 .work: resb 16
 .magic: resq 1
 .generation: resq 1
 .epoch: resq 1
 .outer_rsp: resq 1
 .a: resq 1
 .b: resq 1
 .coeff: resq 1
 .target: resq 1
 .frame_start: resq 1
 .frame_bit_start: resq 1
 .frame_end: resq 1
 .crc_scan: resq 1
 .number: resq 1
 .utf_min: resq 1
 .samples: resq 1
 .turns: resq 1
 .md5_length: resq 1
 .stage: resd 1
 .block: resd 1
 .first_block: resd 1
 .strategy: resd 1
 .mode: resd 1
 .bs_code: resd 1
 .sr_code: resd 1
 .utf_left: resd 1
 .channel: resd 1
 .width: resd 1
 .wasted: resd 1
 .type: resd 1
 .order: resd 1
 .precision: resd 1
 .shift: resd 1
 .index: resd 1
 .value: resd 1
 .parts: resd 1
 .part: resd 1
 .part_samples: resd 1
 .left: resd 1
 .param_bits: resd 1
 .k: resd 1
 .raw_width: resd 1
 .quotient: resd 1
 .res_phase: resd 1
 .crc_value: resd 1
 .turn_bits: resd 1
 .turn_samples: resd 1
 .turn_fuel: resd 1
 .turn_crc: resd 1
 .turn_taps: resd 1
 .turn_md5: resd 1
 .turn_output: resd 1
 .feed_count: resd 1
 .feed_index: resd 1
 .md5_fill: resd 1
 .md5_h: resd 4
 .md5_tail: resb 64
endstruc
%if fpp_state_size > 1152
 %error producer continuation exceeds declared control workspace
%endif
%define C(x) [r12+fpp_state.ctx+fpp_ctx. %+ x]
%define S(x) [r12+fpp_state. %+ x]
%define I(x) [r12+fpp_state.info+fpp_info. %+ x]
%define W(x) [r12+fpp_state.work+fpp_work. %+ x]
%macro GET 1
 mov ecx,%1
 call fpp_bits
%endmacro
%macro FUEL 1
 sub dword S(turn_fuel),%1
 jc fpp_limit
%endmacro

media_flac_producer_begin:
 xor eax,eax
 jmp fpp_enter
media_flac_producer_step:
 mov eax,1
 jmp fpp_enter
media_flac_producer_cancel:
 mov eax,2
fpp_enter:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,40
 mov [rsp],eax
 mov [rsp+8],rsi
 mov [rsp+16],rdx
 mov rbp,rdi
 test rdi,rdi
 jz fpp_early_invalid
 test rdi,7
 jnz fpp_early_invalid
 mov rsi,192
 call fpp_span
 jc fpp_early_invalid
 cmp dword [rbp+fpp_ctx.version],1
 jne fpp_early_invalid
 cmp dword [rbp+fpp_ctx.phase],4
 ja fpp_early_invalid
 cmp qword [rbp+fpp_ctx.generation],0
 je fpp_early_invalid
 cmp qword [rbp+fpp_ctx.epoch],0
 je fpp_early_invalid
 lea rdi,[rbp+fpp_ctx.reserved]
 mov ecx,5
.reserved:
 cmp qword [rdi],0
 jne fpp_early_invalid
 add rdi,8
 loop .reserved
 mov r13,[rbp+fpp_ctx.src]
 mov rdi,r13
 mov rsi,[rbp+fpp_ctx.src_bytes]
 cmp rsi,42
 jb fpp_early_invalid
 cmp rsi,307200
 ja fpp_early_limit
 call fpp_span
 jc fpp_early_invalid
 mov rdi,[rbp+fpp_ctx.pcm]
 mov rsi,[rbp+fpp_ctx.capacity]
 test rsi,rsi
 jz fpp_early_invalid
 cmp rsi,192000
 ja fpp_early_limit
 call fpp_span
 jc fpp_early_invalid
 mov r14,[rbp+fpp_ctx.workspace]
 test r14,7
 jnz fpp_early_invalid
 mov rdi,r14
 mov rsi,[rbp+fpp_ctx.workspace_bytes]
 cmp rsi,398592
 jb fpp_early_capacity
 call fpp_span
 jc fpp_early_invalid
 ; Validate every pair of FULL spans, including untouchable capacity tail.
 mov rdi,rbp
 mov esi,192
 mov rdx,r13
 mov rcx,[rbp+fpp_ctx.src_bytes]
 call fpp_pair
 jc fpp_early_invalid
 mov rdx,[rbp+fpp_ctx.pcm]
 mov rcx,[rbp+fpp_ctx.capacity]
 call fpp_pair
 jc fpp_early_invalid
 mov rdx,r14
 mov rcx,[rbp+fpp_ctx.workspace_bytes]
 call fpp_pair
 jc fpp_early_invalid
 mov rdi,r13
 mov rsi,[rbp+fpp_ctx.src_bytes]
 mov rdx,[rbp+fpp_ctx.pcm]
 mov rcx,[rbp+fpp_ctx.capacity]
 call fpp_pair
 jc fpp_early_invalid
 mov rdx,r14
 mov rcx,[rbp+fpp_ctx.workspace_bytes]
 call fpp_pair
 jc fpp_early_invalid
 mov rdi,[rbp+fpp_ctx.pcm]
 mov rsi,[rbp+fpp_ctx.capacity]
 call fpp_pair
 jc fpp_early_invalid
 cmp qword [rbp+fpp_ctx.budget],2457600
 ja fpp_early_limit
 cmp qword [rbp+fpp_ctx.integrity],1
 ja fpp_early_invalid
 mov rax,[rbp+fpp_ctx.cursor]
 cmp rax,[rbp+fpp_ctx.bytes]
 jne fpp_early_invalid
 cmp rax,[rbp+fpp_ctx.capacity]
 ja fpp_early_capacity
 mov rax,[rbp+fpp_ctx.offset]
 cmp rax,[rbp+fpp_ctx.src_bytes]
 ja fpp_early_invalid
 cmp qword [rbp+fpp_ctx.encoded_frames],4096
 ja fpp_early_limit
 lea r12,[r14+393344]
 mov eax,[rsp]
 test eax,eax
 jz fpp_begin
 cmp eax,2
 je fpp_cancel
 mov eax,[rbp+fpp_ctx.phase]
 cmp eax,3
 je fpp_ready_repeat
 cmp eax,1
 jb fpp_early_phase
 cmp eax,2
 ja fpp_early_phase
 cmp qword S(magic),0x46505031
 jne fpp_early_invalid
 mov rax,[rbp+fpp_ctx.generation]
 cmp rax,S(generation)
 jne fpp_early_phase
 mov rax,[rbp+fpp_ctx.epoch]
 cmp rax,S(epoch)
 jne fpp_early_phase
 ; Reject caller changes to the last published transaction/immutable spans.
 mov rsi,r12
 mov rdi,rbp
 mov ecx,24
 repe cmpsq
 jne fpp_early_invalid
 mov eax,S(stage)
 cmp rax,[rbp+fpp_ctx.substate]
 jne fpp_early_invalid
 cmp eax,14
 ja fpp_early_invalid
 cmp qword S(turns),65536
 jae fpp_early_limit
 mov rdi,r12
 mov rsi,rbp
 mov ecx,24
 rep movsq
 mov S(outer_rsp),rsp
 inc qword S(turns)
 mov dword S(turn_bits),4096
 mov dword S(turn_samples),256
 mov dword S(turn_fuel),16384
 mov dword S(turn_crc),0
 mov dword S(turn_taps),0
 mov dword S(turn_md5),0
 mov dword S(turn_output),0
 FUEL 256                         ; fixed admission/dispatch bookkeeping
 cmp dword C(phase),1
 je fpp_scan
 mov eax,S(stage)
 cmp eax,1
 je fpp_header
 cmp eax,2
 je fpp_subheader
 cmp eax,3
 je fpp_samples
 cmp eax,4
 je fpp_coefficients
 cmp eax,5
 je fpp_residual_header
 cmp eax,6
 je fpp_partition
 cmp eax,7
 je fpp_residual
 cmp eax,8
 je fpp_predict
 cmp eax,9
 je fpp_waste
 cmp eax,10
 je fpp_footer
 cmp eax,11
 je fpp_crc_turn
 cmp eax,12
 je fpp_decorrelate
 cmp eax,13
 je fpp_emit
 cmp eax,14
 je fpp_finish
 jmp fpp_invalid

fpp_begin:
 cmp dword [rbp+fpp_ctx.phase],0
 jne fpp_early_phase
 cmp qword [rbp+fpp_ctx.budget],0
 je fpp_early_limit
 ; All result/progress fields must be fresh; workspace inputs are the union.
 mov rax,[rbp+fpp_ctx.offset]
 or rax,[rbp+fpp_ctx.encoded_frames]
 or rax,[rbp+fpp_ctx.cursor]
 or rax,[rbp+fpp_ctx.frames]
 or rax,[rbp+fpp_ctx.bytes]
 or rax,[rbp+fpp_ctx.rate]
 or rax,[rbp+fpp_ctx.bits]
 or rax,[rbp+fpp_ctx.substate]
 or rax,[rbp+fpp_ctx.integrity]
 jnz fpp_early_invalid
 cmp dword [r13],0x43614c66
 jne fpp_early_invalid
 ; Only fixed-size continuation is initialized, never file/PCM-sized storage.
 mov rdi,r12
 xor eax,eax
 mov ecx,(fpp_state_size+7)/8
 rep stosq
 mov rdi,r12
 mov rsi,rbp
 mov ecx,24
 rep movsq
 mov S(outer_rsp),rsp
 mov qword S(magic),0x46505031
 mov rax,C(generation)
 mov S(generation),rax
 mov rax,C(epoch)
 mov S(epoch),rax
 mov S(a),r14
 lea rax,[r14+65536]
 mov S(b),rax
 lea rax,[r14+393216]
 mov S(coeff),rax
 mov dword S(md5_h),0x67452301
 mov dword [r12+fpp_state.md5_h+4],0xefcdab89
 mov dword [r12+fpp_state.md5_h+8],0x98badcfe
 mov dword [r12+fpp_state.md5_h+12],0x10325476
 mov dword C(phase),1
 mov qword C(offset),4
 jmp fpp_commit_zero

fpp_cancel:
 mov rax,[rsp+8]
 cmp rax,[rbp+fpp_ctx.generation]
 jne fpp_early_phase
 mov rax,[rsp+16]
 cmp rax,[rbp+fpp_ctx.epoch]
 jne fpp_early_phase
 mov eax,[rbp+fpp_ctx.phase]
 test eax,eax
 jz fpp_early_phase
 cmp eax,3
 je fpp_early_phase
 mov dword [rbp+fpp_ctx.phase],4
 mov eax,2
 jmp fpp_early_exit
fpp_ready_repeat:
 cmp qword S(magic),0x46505031
 jne fpp_early_invalid
 mov rax,[rbp+fpp_ctx.generation]
 cmp rax,S(generation)
 jne fpp_early_phase
 mov rax,[rbp+fpp_ctx.epoch]
 cmp rax,S(epoch)
 jne fpp_early_phase
 mov rsi,r12
 mov rdi,rbp
 mov ecx,24
 repe cmpsq
 jne fpp_early_invalid
 cmp qword [rbp+fpp_ctx.frames],0
 je fpp_early_invalid
 mov eax,[rbp+fpp_ctx.channels]
 dec eax
 cmp eax,1
 ja fpp_early_invalid
 mov eax,[rbp+fpp_ctx.rate]
 cmp eax,44100
 je .rate_ok
 cmp eax,48000
 jne fpp_early_invalid
.rate_ok:
 cmp dword [rbp+fpp_ctx.bits],16
 jne fpp_early_invalid
 mov eax,[rbp+fpp_ctx.channels]
 shl eax,1
 cmp eax,[rbp+fpp_ctx.input_frame]
 jne fpp_early_invalid
 imul rax,[rbp+fpp_ctx.frames]
 jo fpp_early_invalid
 cmp rax,[rbp+fpp_ctx.bytes]
 jne fpp_early_invalid
 mov rax,[rbp+fpp_ctx.offset]
 cmp rax,[rbp+fpp_ctx.src_bytes]
 jne fpp_early_invalid
 mov eax,1
 jmp fpp_early_exit

fpp_scan:
 FUEL 64
 mov rbx,C(offset)
 mov rax,C(src_bytes)
 sub rax,rbx
 cmp rax,4
 jb fpp_invalid
 cmp dword I(metadata_blocks),256
 jae fpp_limit
 movzx r15d,byte [r13+rbx]
 mov eax,r15d
 and eax,127
 cmp eax,127
 je fpp_invalid
 cmp dword I(metadata_blocks),0
 je .first
 test eax,eax
 jz fpp_invalid
 jmp .extent
.first:
 test eax,eax
 jnz fpp_invalid
.extent:
 mov eax,[r13+rbx]
 bswap eax
 and eax,0xffffff
 mov edx,eax
 add rbx,4
 mov rcx,C(src_bytes)
 sub rcx,rbx
 cmp rax,rcx
 ja fpp_invalid
 cmp dword I(metadata_blocks),0
 jne .skip
 cmp eax,34
 jne fpp_invalid
 call fpp_streaminfo
.skip:
 add rbx,rdx
 mov C(offset),rbx
 inc dword I(metadata_blocks)
 test r15b,128
 jz fpp_commit_zero
 mov I(audio_offset),rbx
 shl rbx,3
 mov W(bitpos),rbx
 mov dword C(phase),2
 mov dword S(stage),1
 jmp fpp_commit_zero

fpp_streaminfo:
 ; First STREAMINFO payload is at source+8, exactly34 bytes proven above.
 push rdx
 movzx eax,word [r13+8]
 rol ax,8
 mov I(min_block_size),eax
 movzx edx,word [r13+10]
 rol dx,8
 mov I(max_block_size),edx
 cmp eax,16
 jb fpp_invalid
 cmp edx,eax
 jb fpp_invalid
 cmp edx,16384
 ja fpp_limit
 mov eax,[r13+12]
 bswap eax
 shr eax,8
 mov I(min_frame_bytes),eax
 mov edx,[r13+15]
 bswap edx
 shr edx,8
 mov I(max_frame_bytes),edx
 test edx,edx
 jz .frame_bytes_ok
 cmp edx,eax
 jb fpp_invalid
.frame_bytes_ok:
 mov rax,[r13+18]
 bswap rax
 mov rcx,rax
 shr rcx,44
 mov I(sample_rate),ecx
 mov C(rate),ecx
 cmp ecx,44100
 je .rate_ok
 cmp ecx,48000
 jne fpp_phase
.rate_ok:
 mov rcx,rax
 shr rcx,41
 and ecx,7
 inc ecx
 cmp ecx,2
 ja fpp_phase
 mov I(channels),ecx
 mov C(channels),ecx
 shl ecx,1
 mov C(input_frame),ecx
 mov rcx,rax
 shr rcx,36
 and ecx,31
 inc ecx
 cmp ecx,16
 jne fpp_phase                     ; S24 explicitly NOT authorized
 mov I(bits_per_sample),ecx
 mov C(bits),ecx
 shl rax,28
 shr rax,28
 mov I(total_samples),rax
 mov ecx,C(input_frame)
 mul rcx
 test rdx,rdx
 jnz fpp_limit
 cmp rax,192000
 ja fpp_limit
 cmp rax,C(capacity)
 ja fpp_capacity
 mov rax,[r13+26]
 mov I(stream_md5),rax
 mov rax,[r13+34]
 mov [r12+fpp_state.info+fpp_info.stream_md5+8],rax
 pop rdx
 ret

fpp_subheader:
 FUEL 32
 mov eax,S(channel)
 mov rdx,S(a)
 test eax,eax
 jz .target
 mov rdx,S(b)
.target:
 mov S(target),rdx
 mov ecx,16
 cmp dword S(mode),9
 jne .second
 test eax,eax
 jz .side
 jmp .width
.second:
 test eax,eax
 jz .width
 cmp dword S(mode),8
 je .side
 cmp dword S(mode),10
 jne .width
.side:
 inc ecx
.width:
 mov S(width),ecx
 GET 1
 test eax,eax
 jnz fpp_invalid
 GET 6
 mov S(type),eax
 GET 1
 mov dword S(wasted),0
 test eax,eax
 jz .effective
.wasted:
 GET 1
 inc dword S(wasted)
 mov edx,S(wasted)
 cmp edx,S(width)
 jae fpp_invalid
 test eax,eax
 jz .wasted
.effective:
 mov eax,S(width)
 sub eax,S(wasted)
 mov W(width),eax
 mov dword S(index),0
 mov eax,S(type)
 cmp eax,1
 jbe .samples
 cmp eax,8
 jb fpp_invalid
 cmp eax,12
 jbe .fixed
 cmp eax,32
 jb fpp_invalid
 sub eax,31
 jmp .order
.fixed:
 sub eax,8
.order:
 cmp eax,S(block)
 ja fpp_invalid
 mov S(order),eax
.samples:
 mov dword S(stage),3
 jmp fpp_commit_zero

fpp_samples:
 mov eax,S(type)
 cmp eax,1
 ja .warmup
 test eax,eax
 jnz .simple_loop
 cmp dword S(index),0
 jne .simple_loop
 mov ecx,W(width)
 call fpp_signed
 mov S(value),eax
.simple_loop:
 FUEL 3
 mov ebx,S(index)
 cmp ebx,S(block)
 jae .simple_done
 cmp dword S(turn_samples),0
 je fpp_commit_zero
 cmp dword S(type),0
 je .constant
 mov ecx,W(width)
 cmp ecx,S(turn_bits)
 ja fpp_commit_zero
 call fpp_signed
 jmp .store
.constant:
 mov eax,S(value)
.store:
 mov rdx,S(target)
 mov [rdx+rbx*4],eax
 inc dword S(index)
 dec dword S(turn_samples)
 jmp .simple_loop
.simple_done:
 mov dword S(index),0
 mov dword S(stage),9
 jmp fpp_commit_zero
.warmup:
 FUEL 3
 mov ebx,S(index)
 cmp ebx,S(order)
 jae .warm_done
 mov ecx,W(width)
 call fpp_signed
 mov rdx,S(target)
 mov [rdx+rbx*4],eax
 inc dword S(index)
 dec dword S(turn_samples)
 jmp .warmup
.warm_done:
 mov dword S(stage),5
 cmp dword S(type),32
 jb fpp_commit_zero
 GET 4
 cmp eax,15
 je fpp_invalid
 inc eax
 mov S(precision),eax
 GET 5
 test eax,16
 jnz fpp_invalid
 mov S(shift),eax
 mov dword S(index),0
 mov dword S(stage),4
 jmp fpp_commit_zero
fpp_coefficients:
 FUEL 3
 mov ebx,S(index)
 cmp ebx,S(order)
 jae .done
 mov ecx,S(precision)
 call fpp_signed
 mov rdx,S(coeff)
 mov [rdx+rbx*4],eax
 inc dword S(index)
 jmp fpp_coefficients
.done:
 mov dword S(stage),5
 jmp fpp_commit_zero

fpp_residual_header:
 GET 2
 cmp eax,1
 ja fpp_invalid
 add eax,4
 mov S(param_bits),eax
 GET 4
 mov ecx,eax
 mov edx,1
 shl edx,cl
 mov S(parts),edx
 mov eax,S(block)
 mov ecx,edx
 dec ecx
 test eax,ecx
 jnz fpp_invalid
 xor edx,edx
 div dword S(parts)
 cmp eax,S(order)
 jb fpp_invalid
 mov S(part_samples),eax
 mov dword S(part),0
 mov eax,S(order)
 mov S(index),eax
 mov dword S(stage),6
 jmp fpp_commit_zero
fpp_partition:
 FUEL 16
 mov eax,S(part)
 cmp eax,S(parts)
 jae .done
 mov edx,S(part_samples)
 test eax,eax
 jnz .count
 sub edx,S(order)
.count:
 mov S(left),edx
 mov ecx,S(param_bits)
 GET ecx
 mov S(k),eax
 mov ecx,S(param_bits)
 mov edx,1
 shl edx,cl
 dec edx
 mov dword S(raw_width),0xffffffff
 cmp eax,edx
 jne .rice
 GET 5
 mov S(raw_width),eax
.rice:
 mov dword S(quotient),0
 mov dword S(res_phase),0
 mov dword S(stage),7
 jmp fpp_commit_zero
.done:
 mov eax,S(index)
 cmp eax,S(block)
 jne fpp_invalid
 mov eax,S(order)
 mov S(index),eax
 mov dword S(stage),8
 jmp fpp_commit_zero
fpp_residual:
 FUEL 2
 cmp dword S(left),0
 je .partition_done
 cmp dword S(turn_samples),0
 je fpp_commit_zero
 cmp dword S(raw_width),0xffffffff
 jne .escape
 cmp dword S(res_phase),0
 jne .remainder
.unary:
 cmp dword S(turn_bits),0
 je fpp_commit_zero
 GET 1
 test eax,eax
 jnz .unary_done
 cmp dword S(quotient),65535
 jae fpp_limit
 inc dword S(quotient)
 FUEL 1
 jmp .unary
.unary_done:
 mov dword S(res_phase),1
.remainder:
 mov ecx,S(k)
 cmp ecx,S(turn_bits)
 ja fpp_commit_zero
 GET ecx
 mov edx,S(quotient)
 mov ecx,S(k)
 shl rdx,cl
 or rax,rdx
 mov edx,0xffffffff
 cmp rax,rdx
 ja fpp_invalid
 mov edx,eax
 shr eax,1
 and edx,1
 neg edx
 xor eax,edx
 jmp .store
.escape:
 mov ecx,S(raw_width)
 test ecx,ecx
 jz .zero
 cmp ecx,S(turn_bits)
 ja fpp_commit_zero
 call fpp_signed
 jmp .store
.zero:
 xor eax,eax
.store:
 mov edx,S(index)
 cmp edx,S(block)
 jae fpp_invalid
 mov rdi,S(target)
 mov [rdi+rdx*4],eax
 inc dword S(index)
 dec dword S(left)
 dec dword S(turn_samples)
 mov dword S(quotient),0
 mov dword S(res_phase),0
 jmp fpp_residual
.partition_done:
 inc dword S(part)
 mov dword S(stage),6
 jmp fpp_commit_zero

fpp_predict:
 mov ebx,S(index)
 cmp ebx,S(block)
 jae .done
 cmp dword S(turn_samples),0
 je fpp_commit_zero
 mov eax,S(order)
 add eax,5
 sub S(turn_fuel),eax
 jc fpp_limit
 mov rdi,S(target)
 lea rdi,[rdi+rbx*4]
 cmp dword S(type),32
 jae .lpc
 xor eax,eax
 mov edx,S(order)
 test edx,edx
 jz .add
 movsxd rax,dword [rdi-4]
 cmp edx,1
 je .add
 cmp edx,2
 je .fixed2
 cmp edx,3
 je .fixed3
 imul rax,4
 movsxd rdx,dword [rdi-8]
 imul rdx,6
 sub rax,rdx
 movsxd rdx,dword [rdi-12]
 imul rdx,4
 add rax,rdx
 movsxd rdx,dword [rdi-16]
 sub rax,rdx
 jmp .add
.fixed3:
 imul rax,3
 movsxd rdx,dword [rdi-8]
 imul rdx,3
 sub rax,rdx
 movsxd rdx,dword [rdi-12]
 add rax,rdx
 jmp .add
.fixed2:
 imul rax,2
 movsxd rdx,dword [rdi-8]
 sub rax,rdx
 jmp .add
.lpc:
 xor r8d,r8d
 xor r9d,r9d
 mov rsi,S(coeff)
.dot:
 cmp r9d,S(order)
 jae .shift
 movsxd rax,dword [rsi+r9*4]
 mov ecx,r9d
 inc ecx
 shl ecx,2
 mov rdx,rdi
 sub rdx,rcx
 movsxd rdx,dword [rdx]
 imul rax,rdx
 jo fpp_invalid
 add r8,rax
 jo fpp_invalid
 inc r9d
 inc dword S(turn_taps)
 jmp .dot
.shift:
 mov rax,r8
 mov ecx,S(shift)
 sar rax,cl
.add:
 movsxd rdx,dword [rdi]
 add rax,rdx
 jo fpp_invalid
 movsxd rdx,eax
 cmp rax,rdx
 jne fpp_invalid
 mov [rdi],eax
 inc dword S(index)
 dec dword S(turn_samples)
 jmp fpp_predict
.done:
 mov dword S(index),0
 mov dword S(stage),9
 jmp fpp_commit_zero

fpp_waste:
 FUEL 4
 mov ebx,S(index)
 cmp ebx,S(block)
 jae .done
 cmp dword S(turn_samples),0
 je fpp_commit_zero
 mov rdi,S(target)
 mov eax,[rdi+rbx*4]
 mov ecx,32
 sub ecx,W(width)
 mov edx,eax
 shl edx,cl
 sar edx,cl
 cmp eax,edx
 jne fpp_invalid
 mov ecx,S(wasted)
 shl eax,cl
 mov [rdi+rbx*4],eax
 inc dword S(index)
 dec dword S(turn_samples)
 jmp fpp_waste
.done:
 inc dword S(channel)
 mov eax,S(channel)
 cmp eax,I(channels)
 jae .footer
 mov dword S(stage),2
 jmp fpp_commit_zero
.footer:
 mov dword S(stage),10
 jmp fpp_commit_zero

fpp_footer:
 mov ecx,W(bitpos)
 neg ecx
 and ecx,7
 call fpp_bits
 test eax,eax
 jnz fpp_invalid
 GET 16
 mov rax,W(bitpos)
 shr rax,3
 mov S(frame_end),rax
 mov rcx,rax
 sub rcx,S(frame_start)
 mov eax,I(min_frame_bytes)
 cmp rcx,rax
 jb fpp_invalid
 mov eax,I(max_frame_bytes)
 test eax,eax
 jz .frame_ok
 cmp rcx,rax
 ja fpp_invalid
.frame_ok:
 mov eax,S(block)
 cmp eax,I(min_block_size)
 jb .last_only
 cmp dword S(strategy),0
 jne .length_ok
 cmp eax,S(first_block)
 je .length_ok
.last_only:
 mov rax,S(frame_end)
 cmp rax,C(src_bytes)
 jne fpp_invalid
.length_ok:
 mov rax,S(frame_start)
 mov S(crc_scan),rax
 mov dword S(crc_value),0
 mov dword S(stage),11
 jmp fpp_commit_zero
fpp_crc_turn:
 mov rdi,r13
 add rdi,S(crc_scan)
 mov rcx,S(frame_end)
 sub rcx,S(crc_scan)
 cmp rcx,1024
 jbe .count
 mov ecx,1024
.count:
 mov rbx,rcx
 mov S(turn_crc),ecx
 imul eax,ecx,9
 sub S(turn_fuel),eax
 jc fpp_limit
 mov eax,S(crc_value)
 call fpp_crc16_continue
 mov S(crc_value),eax
 add S(crc_scan),rbx
 mov rdx,S(crc_scan)
 cmp rdx,S(frame_end)
 jne fpp_commit_zero
 test eax,eax
 jnz fpp_invalid
 mov dword S(index),0
 mov dword S(stage),12
 jmp fpp_commit_zero

fpp_decorrelate:
 FUEL 8
 mov ebx,S(index)
 cmp ebx,S(block)
 jae .done
 mov eax,I(channels)
 cmp S(turn_samples),eax
 jb fpp_commit_zero
 sub S(turn_samples),eax
 mov rsi,S(a)
 movsxd r8,dword [rsi+rbx*4]
 cmp dword I(channels),1
 je .mono
 mov rdi,S(b)
 movsxd r9,dword [rdi+rbx*4]
 mov eax,S(mode)
 cmp eax,8
 je .ls
 cmp eax,9
 je .rs
 cmp eax,10
 jne .stereo
 mov rdx,r9
 and edx,1
 shl r8,1
 or r8,rdx
 mov rax,r8
 add rax,r9
 sub r8,r9
 sar rax,1
 sar r8,1
 mov r9,r8
 mov r8,rax
 jmp .stereo
.ls:
 sub r8,r9
 mov r9,r8
 movsxd r8,dword [rsi+rbx*4]
 jmp .stereo
.rs:
 add r8,r9
.stereo:
 movsx rax,r9w
 cmp rax,r9
 jne fpp_invalid
.mono:
 movsx rax,r8w
 cmp rax,r8
 jne fpp_invalid
 ; Validate BOTH decoded channels before either in-place store. A refused
 ; mid/side pair must not become different decoder input on a later step.
 cmp dword I(channels),1
 je .store_left
 mov [rdi+rbx*4],r9d
.store_left:
 mov [rsi+rbx*4],r8d
 inc dword S(index)
 jmp fpp_decorrelate
.done:
 mov dword S(index),0
 mov dword S(stage),13
 jmp fpp_commit_zero

fpp_emit:
 lea rdi,[r14+394496]
 mov ebx,S(index)
 mov ecx,256
 cmp dword I(channels),1
 je .count
 shr ecx,1
.count:
 mov eax,S(block)
 sub eax,ebx
 cmp ecx,eax
 jbe .selected
 mov ecx,eax
.selected:
 mov r15d,ecx
 mov edx,I(channels)
 imul ecx,edx
 shl ecx,1
 mov S(feed_count),ecx
 mov rax,C(cursor)
 add rax,rcx
 jc fpp_invalid
 cmp rax,C(capacity)
 ja fpp_capacity
 cmp rax,192000
 ja fpp_limit
 mov rsi,S(a)
 mov rdx,S(b)
.loop:
 FUEL 4
 movsxd rax,dword [rsi+rbx*4]
 movsx r8,ax
 cmp r8,rax
 jne fpp_invalid
 stosw
 cmp dword I(channels),1
 je .advance
 movsxd rax,dword [rdx+rbx*4]
 movsx r8,ax
 cmp r8,rax
 jne fpp_invalid
 stosw
.advance:
 inc ebx
 dec r15d
 jnz .loop
 mov S(index),ebx
 call fpp_md5_feed
 ; All fallible operations precede these <=512-byte stores and ctx commit.
 mov rdi,C(pcm)
 add rdi,C(cursor)
 lea rsi,[r14+394496]
 mov ecx,S(feed_count)
 mov S(turn_output),ecx
 add C(cursor),rcx
 add C(bytes),rcx
 rep movsb
 mov eax,S(index)
 cmp eax,S(block)
 jne fpp_commit_zero
 mov eax,S(block)
 add C(frames),rax
 add S(samples),rax
 inc qword C(encoded_frames)
 mov dword S(stage),1
 jmp fpp_commit_zero

fpp_finish:
 cmp qword C(frames),0
 je fpp_invalid
 mov rax,I(total_samples)
 test rax,rax
 jz .total_ok
 cmp rax,C(frames)
 jne fpp_invalid
.total_ok:
 call fpp_md5_final
 mov rax,I(stream_md5)
 or rax,[r12+fpp_state.info+fpp_info.stream_md5+8]
 jz .unspecified
 mov rax,S(md5_h)
 cmp rax,I(stream_md5)
 jne fpp_invalid
 mov rax,[r12+fpp_state.md5_h+8]
 cmp rax,[r12+fpp_state.info+fpp_info.stream_md5+8]
 jne fpp_invalid
 mov qword C(integrity),1
.unspecified:
 mov dword C(phase),3
 mov eax,1
 jmp fpp_commit

fpp_commit_zero:
 xor eax,eax
fpp_commit:
 mov edx,S(stage)
 mov C(substate),rdx
 cmp dword C(phase),1
 je .copy
 mov rdx,W(bitpos)
 shr rdx,3
 mov C(offset),rdx
.copy:
 mov r15,rax
 mov rdi,rbp
 mov rsi,r12
 mov ecx,24
 rep movsq
 mov rax,r15
fpp_exit:
 ; Post-transaction refusals invalidate continuation before unwinding. The
 ; public ctx/PCM stay unchanged; only begin or a validated step reaches here.
 ; A retry must never re-finalize MD5 or re-use any other dirty private state.
 test rax,rax
 jns fpp_unwind
 mov qword S(magic),0
fpp_unwind:
 mov rsp,S(outer_rsp)
fpp_early_exit:
 add rsp,40
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
fpp_invalid:
 mov rax,-1
 jmp fpp_exit
fpp_phase:
 mov rax,-2
 jmp fpp_exit
fpp_capacity:
 mov rax,-3
 jmp fpp_exit
fpp_limit:
 mov rax,-4
 jmp fpp_exit
fpp_early_invalid:
 mov rax,-1
 jmp fpp_early_exit
fpp_early_phase:
 mov rax,-2
 jmp fpp_early_exit
fpp_early_capacity:
 mov rax,-3
 jmp fpp_early_exit
fpp_early_limit:
 mov rax,-4
 jmp fpp_early_exit

fpp_span:
 test rdi,rdi
 jz .bad
 mov rax,rdi
 add rax,rsi
 ret
.bad:
 stc
 ret
fpp_pair:
 lea r8,[rdi+rsi]
 lea r9,[rdx+rcx]
 cmp rdi,r9
 jae .ok
 cmp rdx,r8
 jae .ok
 stc
 ret
.ok:
 clc
 ret

fpp_bits:
 ; Port of accepted MSB reader; scalar0..32, fixed stack, explicit work charges.
 FUEL 1
 sub S(turn_fuel),ecx
 jc fpp_limit
 cmp ecx,32
 ja fpp_invalid
 cmp ecx,S(turn_bits)
 ja fpp_limit
 sub S(turn_bits),ecx
 mov eax,ecx
 cmp rax,C(budget)
 ja fpp_limit
 sub C(budget),rax
 mov rdx,W(bitpos)
 mov r8,C(src_bytes)
 shl r8,3
 sub r8,rdx
 jc fpp_invalid
 cmp rax,r8
 ja fpp_invalid
 mov r8,rdx
 add r8,rax
 sub r8,S(frame_bit_start)
 cmp dword C(phase),2
 jne .frame_ok
 cmp r8,1048576
 ja fpp_limit
.frame_ok:
 xor eax,eax
 test ecx,ecx
 jz .done
.loop:
 mov r8,rdx
 shr r8,3
 movzx r9d,byte [r13+r8]
 mov r10d,edx
 and r10d,7
 xor r10d,7
 bt r9d,r10d
 adc eax,eax
 inc rdx
 dec ecx
 jnz .loop
.done:
 mov W(bitpos),rdx
 ret
fpp_signed:
 push rcx
 call fpp_bits
 pop rcx
 mov edx,32
 sub edx,ecx
 mov ecx,edx
 shl eax,cl
 sar eax,cl
 ret

fpp_crc16_continue:
 test rcx,rcx
 jz .done
.byte:
 movzx edx,byte [rdi]
 shl edx,8
 xor eax,edx
 mov esi,8
.bit:
 shl eax,1
 test eax,0x10000
 jz .next
 xor eax,0x8005
.next:
 and eax,0xffff
 dec esi
 jnz .bit
 inc rdi
 dec rcx
 jnz .byte
.done:
 ret

; Native accepted frame-header parser, split at the subframe admission seam.
fpp_header:
 mov rax,W(bitpos)
 shr rax,3
 cmp rax,C(src_bytes)
 je .complete
 ja fpp_invalid
 cmp qword C(encoded_frames),4096
 jae fpp_limit
 mov S(frame_start),rax
 mov rax,W(bitpos)
 mov S(frame_bit_start),rax
 GET 14
 cmp eax,0x3FFE
 jne fpp_invalid
 GET 1
 test eax,eax
 jnz fpp_invalid
 GET 1
 cmp qword C(encoded_frames),0
 jne .same_strategy
 mov S(strategy),eax
.same_strategy:
 cmp eax,S(strategy)
 jne fpp_invalid
 GET 4
 test eax,eax
 jz fpp_invalid
 mov S(bs_code),eax
 GET 4
 cmp eax,15
 je fpp_invalid
 mov S(sr_code),eax
 GET 4
 cmp eax,10
 ja fpp_invalid
 mov S(mode),eax
 cmp eax,8
 jae .two_channels
 inc eax
 jmp .channel_count
.two_channels:
 mov eax,2
.channel_count:
 cmp eax,I(channels)
 jne fpp_invalid
 GET 3
 test eax,eax
 jz .bps_ok
 cmp eax,4
 jne fpp_invalid
.bps_ok:
 GET 1
 test eax,eax
 jnz fpp_invalid
 call fpp_number
 mov rax,S(number)
 cmp dword S(strategy),0
 jne .sample_number
 cmp rax,C(encoded_frames)
 jne fpp_invalid
 cmp rax,0x7FFFFFFF
 ja fpp_invalid
 jmp .number_ok
.sample_number:
 cmp rax,S(samples)
 jne fpp_invalid
.number_ok:
 mov eax,S(bs_code)
 cmp eax,1
 jne .block_other
 mov eax,192
 jmp .block_ready
.block_other:
 cmp eax,5
 ja .block_extra
 lea ecx,[rax-2]
 mov eax,576
 shl eax,cl
 jmp .block_ready
.block_extra:
 cmp eax,6
 jne .block7
 GET 8
 inc eax
 jmp .block_ready
.block7:
 cmp eax,7
 jne .block_power
 GET 16
 inc eax
 jmp .block_ready
.block_power:
 lea ecx,[rax-8]
 mov eax,256
 shl eax,cl
.block_ready:
 cmp eax,16384
 ja fpp_limit
 cmp eax,I(max_block_size)
 ja fpp_invalid
 mov S(block),eax
 cmp qword C(encoded_frames),0
 jne .block_not_first
 mov S(first_block),eax
.block_not_first:
 cmp dword S(strategy),0
 jne .block_strategy_ok
 cmp eax,S(first_block)
 ja fpp_invalid
.block_strategy_ok:
 mov eax,S(sr_code)
 test eax,eax
 jz .rate_ok
 cmp eax,11
 ja .rate_extra
 lea rdx,[rel fpp_rates]
 mov eax,[rdx+rax*4]
 jmp .rate_compare
.rate_extra:
 cmp eax,12
 jne .rate16
 GET 8
 imul eax,1000
 jmp .rate_compare
.rate16:
 GET 16
 cmp dword S(sr_code),14
 jne .rate_compare
 imul eax,10
.rate_compare:
 cmp eax,I(sample_rate)
 jne fpp_invalid
.rate_ok:
 ; CRC over entire header including CRC byte has zero remainder.
 GET 8
 mov rcx,W(bitpos)
 shr rcx,3
 sub rcx,S(frame_start)
 mov rdi,r13
 add rdi,S(frame_start)
 mov S(turn_crc),ecx
 imul eax,ecx,9
 sub S(turn_fuel),eax
 jc fpp_limit
 mov esi,8
 mov edx,7
 call fpp_crc
 test eax,eax
 jnz fpp_invalid

 mov eax,S(block)
 add rax,C(frames)
 mov edx,I(channels)
 imul rax,rdx
 shl rax,1
 cmp rax,192000
 ja fpp_limit
 cmp rax,C(capacity)
 ja fpp_capacity
 mov dword S(channel),0
 mov dword S(stage),2
 jmp fpp_commit_zero
.complete:
 mov dword S(stage),14
 jmp fpp_commit_zero
fpp_number:
 sub rsp,8
 GET 8
 cmp eax,128
 jb .single
 mov edx,eax
 mov ecx,0
 mov esi,128
.leading:
 test edx,esi
 jz .lead_done
 inc ecx
 shr esi,1
 jmp .leading
.lead_done:
 cmp ecx,2
 jb fpp_invalid
 cmp ecx,7
 ja fpp_invalid
 mov eax,127
 shr eax,cl
 and eax,edx
 mov S(number),rax
 dec ecx
 mov S(utf_left),ecx
 ; minima: 2=>2^7, 3=>2^11, ... 7=>2^31.
 mov edx,ecx
 lea ecx,[rcx*4+rcx+1]
 cmp edx,1
 jne .minimum
 mov ecx,7
.minimum:
 mov eax,1
 shl rax,cl
 mov S(utf_min),rax
.more:
 GET 8
 mov edx,eax
 and edx,0xC0
 cmp edx,0x80
 jne fpp_invalid
 and eax,63
 shl qword S(number),6
 or S(number),rax
 dec dword S(utf_left)
 jnz .more
 mov rax,S(number)
 cmp rax,S(utf_min)
 jb fpp_invalid
 add rsp,8
 ret
.single:
 mov S(number),rax
 add rsp,8
 ret
fpp_crc:
 xor eax,eax
 mov r8d,esi
 sub r8d,8
 mov r9d,1
 mov r10d,esi
 dec r10d
 push rcx
 mov ecx,r10d
 shl r9d,cl
 pop rcx
.byte:
 test rcx,rcx
 jz .done
 movzx r10d,byte [rdi]
 push rcx
 mov ecx,r8d
 shl r10d,cl
 xor eax,r10d
 mov ecx,8
.bit:
 test eax,r9d
 jz .plain
 shl eax,1
 xor eax,edx
 jmp .next
.plain:
 shl eax,1
.next:
 dec ecx
 jnz .bit
 pop rcx
 inc rdi
 dec rcx
 jmp .byte
.done:
 cmp esi,8
 jne .word
 movzx eax,al
 ret
.word:
 movzx eax,ax
 ret
align 4
fpp_rates: dd 0,88200,176400,192000,8000,16000,22050,24000,32000,44100,48000,96000

; Incremental ADAPTATION of the accepted native MD5 rounds, <=8 blocks/turn.
fpp_md5_feed:
 mov dword S(feed_index),0
 mov eax,S(feed_count)
 add S(md5_length),rax
.loop:
 mov eax,S(feed_index)
 cmp eax,S(feed_count)
 jae .done
 FUEL 1
 movzx edx,byte [r14+rax+394496]
 mov eax,S(md5_fill)
 mov [r12+fpp_state.md5_tail+rax],dl
 inc dword S(md5_fill)
 inc dword S(feed_index)
 cmp dword S(md5_fill),64
 jne .loop
 call fpp_md5_compress
 mov dword S(md5_fill),0
 jmp .loop
.done:
 ret
fpp_md5_final:
 mov eax,S(md5_fill)
 mov byte [r12+fpp_state.md5_tail+rax],128
 inc eax
 cmp eax,56
 jbe .short
.long_zero:
 cmp eax,64
 jae .first
 FUEL 1
 mov byte [r12+fpp_state.md5_tail+rax],0
 inc eax
 jmp .long_zero
.first:
 call fpp_md5_compress
 xor eax,eax
.short:
 cmp eax,56
 jae .length
 FUEL 1
 mov byte [r12+fpp_state.md5_tail+rax],0
 inc eax
 jmp .short
.length:
 mov rax,S(md5_length)
 shl rax,3
 mov [r12+fpp_state.md5_tail+56],rax
 call fpp_md5_compress
 ret
fpp_md5_compress:
 inc dword S(turn_md5)
 push rbx
 push rbp
 push r14
 lea r14,[r12+fpp_state.md5_tail]
 mov r8d,S(md5_h)
 mov r9d,[r12+fpp_state.md5_h+4]
 mov r10d,[r12+fpp_state.md5_h+8]
 mov r11d,[r12+fpp_state.md5_h+12]
 xor ebx,ebx
.md5_round:
 FUEL 2
    cmp ebx, 16
    jb .md5_g0
    cmp ebx, 32
    jb .md5_g1
    cmp ebx, 48
    jb .md5_g2
    ; group 3: F = C xor (B or ~D); g = (7i) & 15
    mov esi, r11d
    not esi
    or  esi, r9d
    xor esi, r10d
    mov eax, ebx
    imul eax, eax, 7
    and eax, 15
    mov ebp, eax
    jmp .md5_fg
.md5_g0:
    ; F = (B&C)|(~B&D); g = i
    mov esi, r9d
    and esi, r10d
    mov eax, r9d
    not eax
    and eax, r11d
    or  esi, eax
    mov ebp, ebx
    jmp .md5_fg
.md5_g1:
    ; F = (D&B)|(~D&C); g = (5i+1) & 15
    mov esi, r11d
    and esi, r9d
    mov eax, r11d
    not eax
    and eax, r10d
    or  esi, eax
    mov eax, ebx
    imul eax, eax, 5
    inc eax
    and eax, 15
    mov ebp, eax
    jmp .md5_fg
.md5_g2:
    ; F = B^C^D; g = (3i+5) & 15
    mov esi, r9d
    xor esi, r10d
    xor esi, r11d
    mov eax, ebx
    imul eax, eax, 3
    add eax, 5
    and eax, 15
    mov ebp, eax
.md5_fg:
    add esi, r8d                     ; + A
    lea rdi, [rel fpp_md5_k]
    add esi, [rdi + rbx*4]           ; + K[i]
    mov eax, ebp
    mov eax, [r14 + rax*4]           ; M[g]
    add esi, eax
    lea rdi, [rel fpp_md5_s]
    movzx ecx, byte [rdi + rbx]      ; s[i]
    mov r8d, r11d                    ; A = D
    mov r11d, r10d                   ; D = C
    mov r10d, r9d                    ; C = B
    mov eax, esi
    rol eax, cl
    add eax, r9d                     ; B + rol(F,s)
    mov r9d, eax                     ; B = new
    inc ebx
    cmp ebx, 64
    jb .md5_round

 add S(md5_h),r8d
 add [r12+fpp_state.md5_h+4],r9d
 add [r12+fpp_state.md5_h+8],r10d
 add [r12+fpp_state.md5_h+12],r11d
 pop r14
 pop rbp
 pop rbx
 ret
align 4
fpp_md5_k:
    dd 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee
    dd 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501
    dd 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be
    dd 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821
    dd 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa
    dd 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8
    dd 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed
    dd 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a
    dd 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c
    dd 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70
    dd 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05
    dd 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665
    dd 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039
    dd 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1
    dd 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1
    dd 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
fpp_md5_s:
    db 7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22
    db 5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20
    db 4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23
    db 6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21

%undef S
%undef C
%undef I
%undef W
%unmacro GET 1
%unmacro FUEL 1
