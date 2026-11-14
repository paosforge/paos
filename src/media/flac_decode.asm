;; MODULE media/flac_decode
;; LAYER 4
;; EXPORTS media_flac_decode
;; IMPORTS media_flac_probe, media_flac_read_bits, media_flac_read_signed, media_flac_read_unary, media_flac_simple, media_flac_residual, media_flac_fixed, media_flac_lpc, media_flac_decorrelate, media_flac_md5
;; CAPS
;; OWNER rc-codex-av
;
; Private UNWIRED Classic0cab frame/subframe/file port, composed with accepted
; RC metadata/primitives. Trusted stable mapped spans; arithmetic is not mapping.
; S16LE only, mono/stereo, rate1..192000. No clipping, allocator or mutable global.
; Whole-file CRC8/16, continuity, total and nonzero STREAMINFO MD5 before publish.
; Zero digest is unspecified (md5_verified=0), never a verified digest claim.
; SysV nonvolatile GPRs/RSP preserved; ordinary volatile GPRs/flags clobbered.

FLACD_MAX_PCM equ 4*1024*1024
FLACD_WORK_BYTES equ 393344         ; A/B 64KiB, tmp/scratch128KiB, coeff128B
FLACD_MAX_BITS equ 16*1024*1024*8
FLACD_MAX_FRAMES equ 65536
FLACD_MAX_SAMPLES equ 1048576

struc media_flac_decode_ctx
 .src: resq 1
 .src_bytes: resq 1
 .dst: resq 1
 .dst_bytes: resq 1
 .scratch: resq 1
 .scratch_bytes: resq 1
 .max_frames: resq 1
 .bit_budget: resq 1
 .frames: resq 1                    ; decoded PCM frames, not encoded frames
 .bytes: resq 1
 .rate: resd 1
 .channels: resd 1
 .md5_verified: resq 1
endstruc

struc flacd_state
 .info: resb 80
 .work: resb 120
 .a: resq 1
 .b: resq 1
 .tmp: resq 1
 .aux: resq 1
 .coeff: resq 1
 .pcm: resq 1
 .samples: resq 1
 .bytes: resq 1
 .encoded_frames: resq 1
 .remaining: resq 1
 .frame_start: resq 1
 .frame_budget: resq 1
 .block: resd 1
 .first_block: resd 1
 .strategy: resd 1
 .mode: resd 1
 .bs_code: resd 1
 .sr_code: resd 1
 .number: resq 1
 .utf_min: resq 1
 .utf_left: resd 1
 .channel: resd 1
 .target: resq 1
 .width: resd 1
 .wasted: resd 1
 .type: resd 1
 .order: resd 1
 .precision: resd 1
 .shift: resd 1
 .index: resd 1
 .verified: resd 1
 .digest: resb 16
endstruc
FLACD_STACK equ ((flacd_state_size+15)&~15)+8
%define S(x) [r12+flacd_state. %+ x]
%define W(x) [r12+flacd_state.work+media_flac_work. %+ x]
%define I(x) [r12+flacd_state.info+media_flac_info. %+ x]
%define C(x) [rbp+media_flac_decode_ctx. %+ x]
%macro GET 1
 mov ecx,%1
 call flacd_bits
%endmacro
%macro OP 1
 lea rax,[rel %1]
 call flacd_op
%endmacro

; RDI=96-byte context. RAX0 complete success, -1 invalid/unsupported/integrity/
; capacity, -4 resource policy/quota. Entire context/dst/source unchanged on
; refusal; scratch may be dirty. Success writes dst[0..bytes), fields64..95 only.
; All FULL declared src/dst/scratch/context spans pairwise disjoint, exact
; adjacency accepted. Scratch >= dst_bytes+FLACD_WORK_BYTES. dst_bytes1..4MiB.
; max_frames1..65536, bit_budget1..134217728; <=1048576 PCM frames, <=16384
; samples/block, <=1048576 encoded bits/frame. No scanning or prefix success.
media_flac_decode:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,FLACD_STACK
 mov r12,rsp
 test rdi,rdi
 jz flacd_invalid
 mov rbp,rdi
 mov rax,rdi
 add rax,media_flac_decode_ctx_size
 jc flacd_invalid
 mov rdi,r12
 xor eax,eax
 mov ecx,(FLACD_STACK-8)/8
 rep stosq
 mov r13,C(src)
 mov r15,C(dst_bytes)
 test r15,r15
 jz flacd_invalid
 cmp r15,FLACD_MAX_PCM
 ja flacd_limit
 mov rax,C(max_frames)
 test rax,rax
 jz flacd_invalid
 cmp rax,FLACD_MAX_FRAMES
 ja flacd_limit
 mov rax,C(bit_budget)
 test rax,rax
 jz flacd_limit
 cmp rax,FLACD_MAX_BITS
 ja flacd_limit
 mov S(remaining),rax
 mov rax,r15
 add rax,FLACD_WORK_BYTES
 cmp C(scratch_bytes),rax
 jb flacd_invalid
 ; Carry and full-span context overlap before any buffer access.
 mov rsi,r13
 mov rdx,C(src_bytes)
 call flacd_span
 mov rsi,C(dst)
 mov rdx,r15
 call flacd_span
 mov rsi,C(scratch)
 mov rdx,C(scratch_bytes)
 call flacd_span
 ; Pairwise declared spans. Ends already proved carry-free.
 mov rsi,r13
 mov rdx,C(src_bytes)
 mov r8,C(dst)
 mov r9,r15
 call flacd_pair
 mov r8,C(scratch)
 mov r9,C(scratch_bytes)
 call flacd_pair
 mov rsi,C(dst)
 mov rdx,r15
 call flacd_pair
 mov I(src),r13
 mov rax,C(src_bytes)
 mov I(src_bytes),rax
 lea rdi,[r12+flacd_state.info]
 call media_flac_probe
 test rax,rax
 jnz flacd_exit
 cmp dword I(bits_per_sample),16
 jne flacd_invalid
 cmp dword I(channels),2
 ja flacd_invalid
 cmp dword I(sample_rate),192000
 ja flacd_invalid
 cmp dword I(max_block_size),16384
 ja flacd_limit
 mov eax,I(min_frame_bytes)
 mov edx,I(max_frame_bytes)
 test edx,edx
 jz .frame_range_ok
 cmp eax,edx
 ja flacd_invalid
.frame_range_ok:
 mov rax,I(total_samples)
 cmp rax,FLACD_MAX_SAMPLES
 ja flacd_limit
 imul rax,2
 mov edx,I(channels)
 imul rax,rdx
 cmp rax,r15
 ja flacd_invalid
 mov rax,C(scratch)
 mov S(a),rax
 add rax,65536
 mov S(b),rax
 add rax,65536
 mov S(tmp),rax
 add rax,131072
 mov S(aux),rax
 add rax,131072
 mov S(coeff),rax
 add rax,128
 mov S(pcm),rax
 mov r14,rax
 mov W(src),r13
 mov rax,C(src_bytes)
 mov W(src_bytes),rax
 mov rax,I(audio_offset)
 shl rax,3
 mov W(bitpos),rax
.frame:
 mov rax,W(bitpos)
 shr rax,3
 cmp rax,C(src_bytes)
 je .complete
 ja flacd_invalid
 mov S(frame_start),rax
 mov rax,S(encoded_frames)
 cmp rax,C(max_frames)
 jae flacd_limit
 mov rax,S(remaining)
 cmp rax,FLACP_MAX_BITS
 jbe .quota_set
 mov eax,FLACP_MAX_BITS
.quota_set:
 mov W(budget),rax
 mov S(frame_budget),rax
 GET 14
 cmp eax,0x3FFE
 jne flacd_invalid
 GET 1
 test eax,eax
 jnz flacd_invalid
 GET 1
 cmp qword S(encoded_frames),0
 jne .same_strategy
 mov S(strategy),eax
.same_strategy:
 cmp eax,S(strategy)
 jne flacd_invalid
 GET 4
 test eax,eax
 jz flacd_invalid
 mov S(bs_code),eax
 GET 4
 cmp eax,15
 je flacd_invalid
 mov S(sr_code),eax
 GET 4
 cmp eax,10
 ja flacd_invalid
 mov S(mode),eax
 cmp eax,8
 jae .two_channels
 inc eax
 jmp .channel_count
.two_channels:
 mov eax,2
.channel_count:
 cmp eax,I(channels)
 jne flacd_invalid
 GET 3
 test eax,eax
 jz .bps_ok
 cmp eax,4
 jne flacd_invalid
.bps_ok:
 GET 1
 test eax,eax
 jnz flacd_invalid
 call flacd_number
 mov rax,S(number)
 cmp dword S(strategy),0
 jne .sample_number
 cmp rax,S(encoded_frames)
 jne flacd_invalid
 cmp rax,0x7FFFFFFF
 ja flacd_invalid
 jmp .number_ok
.sample_number:
 cmp rax,S(samples)
 jne flacd_invalid
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
 ja flacd_limit
 cmp eax,I(max_block_size)
 ja flacd_invalid
 mov S(block),eax
 mov W(count),eax
 cmp qword S(encoded_frames),0
 jne .block_not_first
 mov S(first_block),eax
.block_not_first:
 cmp dword S(strategy),0
 jne .block_strategy_ok
 cmp eax,S(first_block)
 ja flacd_invalid
.block_strategy_ok:
 mov eax,S(sr_code)
 test eax,eax
 jz .rate_ok
 cmp eax,11
 ja .rate_extra
 lea rdx,[rel flacd_rates]
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
 jne flacd_invalid
.rate_ok:
 ; CRC over entire header including CRC byte has zero remainder.
 GET 8
 mov rcx,W(bitpos)
 shr rcx,3
 sub rcx,S(frame_start)
 mov rdi,r13
 add rdi,S(frame_start)
 mov esi,8
 mov edx,7
 call flacd_crc
 test eax,eax
 jnz flacd_invalid
 mov eax,S(block)
 add rax,S(samples)
 cmp rax,FLACD_MAX_SAMPLES
 ja flacd_limit
 mov edx,I(channels)
 imul rax,rdx
 shl rax,1
 cmp rax,r15
 ja flacd_invalid
 mov dword S(channel),0
.subframes:
 mov eax,S(channel)
 mov rdx,S(a)
 test eax,eax
 jz .target_ok
 mov rdx,S(b)
.target_ok:
 mov S(target),rdx
 mov dword S(width),16
 cmp dword S(mode),9
 jne .side_second
 test eax,eax
 jnz .width_ok
 jmp .width17
.side_second:
 test eax,eax
 jz .width_ok
 cmp dword S(mode),8
 je .width17
 cmp dword S(mode),10
 jne .width_ok
.width17:
 mov dword S(width),17
.width_ok:
 call flacd_subframe
 inc dword S(channel)
 mov eax,S(channel)
 cmp eax,I(channels)
 jb .subframes
 ; Padding bits must all be zero. CRC16 is never consumed as samples.
 mov ecx,W(bitpos)
 neg ecx
 and ecx,7
 call flacd_bits
 test eax,eax
 jnz flacd_invalid
 GET 16
 mov rcx,W(bitpos)
 shr rcx,3
 sub rcx,S(frame_start)
 mov eax,I(min_frame_bytes)
 cmp rcx,rax
 jb flacd_invalid
 mov eax,I(max_frame_bytes)
 test eax,eax
 jz .frame_bytes_ok
 cmp rcx,rax
 ja flacd_invalid
.frame_bytes_ok:
 mov rdi,r13
 add rdi,S(frame_start)
 mov esi,16
 mov edx,0x8005
 call flacd_crc
 test eax,eax
 jnz flacd_invalid
 ; Only the final frame may be below STREAMINFO minimum/fixed block size.
 mov eax,S(block)
 cmp eax,I(min_block_size)
 jb .must_last
 cmp dword S(strategy),0
 jne .length_ok
 cmp eax,S(first_block)
 je .length_ok
.must_last:
 mov rax,W(bitpos)
 shr rax,3
 cmp rax,C(src_bytes)
 jne flacd_invalid
.length_ok:
 mov rax,S(a)
 cmp dword I(channels),1
 je .emit_setup
 mov W(input),rax
 mov rax,S(b)
 mov W(other),rax
 mov eax,S(block)
 shl rax,2
 mov W(input_bytes),rax
 mov W(other_bytes),rax
 mov rax,S(tmp)
 mov W(dst),rax
 mov qword W(dst_bytes),131072
 mov rax,S(aux)
 mov W(scratch),rax
 mov qword W(scratch_bytes),131072
 mov eax,S(mode)
 cmp eax,8
 jae .decorrelation_mode
 mov eax,1
.decorrelation_mode:
 mov W(param),eax
 OP media_flac_decorrelate
 mov rax,S(tmp)
.emit_setup:
 mov rsi,rax
 mov ecx,S(block)
 imul ecx,I(channels)
 mov rdi,r14
 add rdi,S(bytes)
.emit:
 movsxd rax,dword [rsi]
 movsx rdx,ax
 cmp rax,rdx
 jne flacd_invalid
 mov [rdi],ax
 add rsi,4
 add rdi,2
 dec ecx
 jnz .emit
 mov eax,S(block)
 add S(samples),rax
 imul eax,I(channels)
 shl eax,1
 add S(bytes),rax
 inc qword S(encoded_frames)
 mov rax,S(frame_budget)
 sub rax,W(budget)
 sub S(remaining),rax
 jmp .frame
.complete:
 cmp qword S(samples),0
 je flacd_invalid
 mov rax,I(total_samples)
 test rax,rax
 jz .total_ok
 cmp rax,S(samples)
 jne flacd_invalid
.total_ok:
 mov rax,I(stream_md5)
 or rax,[r12+flacd_state.info+media_flac_info.stream_md5+8]
 jz .publish
 mov rdi,r14
 mov rsi,S(bytes)
 lea rdx,[r12+flacd_state.digest]
 call media_flac_md5
 mov rax,S(digest)
 cmp rax,I(stream_md5)
 jne flacd_invalid
 mov rax,[r12+flacd_state.digest+8]
 cmp rax,[r12+flacd_state.info+media_flac_info.stream_md5+8]
 jne flacd_invalid
 mov dword S(verified),1
.publish:
 mov rdi,C(dst)
 mov rsi,r14
 mov rcx,S(bytes)
 rep movsb
 mov rax,S(samples)
 mov C(frames),rax
 mov rax,S(bytes)
 mov C(bytes),rax
 mov eax,I(sample_rate)
 mov C(rate),eax
 mov eax,I(channels)
 mov C(channels),eax
 mov eax,S(verified)
 mov C(md5_verified),rax
 xor eax,eax
flacd_exit:
 mov rsp,r12                         ; also unwind internal early aborts
 add rsp,FLACD_STACK
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
flacd_invalid:
 mov rax,-1
 jmp flacd_exit
flacd_limit:
 mov rax,-4
 jmp flacd_exit

; Private helpers abort through the outer transaction; never publish on error.
flacd_span:
 test rsi,rsi
 jz flacd_invalid
 test rdx,rdx
 jz flacd_invalid
 mov rax,rsi
 add rax,rdx
 jc flacd_invalid
 lea rcx,[rbp+media_flac_decode_ctx_size]
 cmp rsi,rcx
 jae .ok
 cmp rbp,rax
 jb flacd_invalid
.ok: ret
flacd_pair:
 lea rax,[r8+r9]
 cmp rsi,rax
 jae .ok
 lea rax,[rsi+rdx]
 cmp r8,rax
 jb flacd_invalid
.ok: ret
flacd_bits:
 sub rsp,8
 mov esi,ecx
 lea rdi,[r12+flacd_state.work]
 call media_flac_read_bits
 add rsp,8
 test rax,rax
 jnz flacd_exit
 mov rax,W(result)
 ret
flacd_signed:
 sub rsp,8
 mov esi,ecx
 lea rdi,[r12+flacd_state.work]
 call media_flac_read_signed
 add rsp,8
 test rax,rax
 jnz flacd_exit
 mov rax,W(result)
 ret
flacd_op:
 sub rsp,8
 lea rdi,[r12+flacd_state.work]
 call rax
 add rsp,8
 test rax,rax
 jnz flacd_exit
 ret

; Minimal canonical FLAC UTF-8 integer, 1..7 bytes, <=36 bits; no surrogates
; restriction (these are integers, not Unicode). Fixed frame numbers <=31 bits.
flacd_number:
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
 jb flacd_invalid
 cmp ecx,7
 ja flacd_invalid
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
 jne flacd_invalid
 and eax,63
 shl qword S(number),6
 or S(number),rax
 dec dword S(utf_left)
 jnz .more
 mov rax,S(number)
 cmp rax,S(utf_min)
 jb flacd_invalid
 add rsp,8
 ret
.single:
 mov S(number),rax
 add rsp,8
 ret

flacd_subframe:
 sub rsp,8
 GET 1
 test eax,eax
 jnz flacd_invalid
 GET 6
 mov S(type),eax
 GET 1
 mov dword S(wasted),0
 test eax,eax
 jz .effective
 mov esi,16
 lea rdi,[r12+flacd_state.work]
 call media_flac_read_unary
 test rax,rax
 jnz flacd_exit
 mov eax,W(result)
 inc eax
 mov S(wasted),eax
.effective:
 mov eax,S(width)
 sub eax,S(wasted)
 jle flacd_invalid
 mov W(width),eax
 mov rax,S(target)
 mov W(dst),rax
 mov qword W(dst_bytes),65536
 mov rax,S(aux)
 mov W(scratch),rax
 mov qword W(scratch_bytes),131072
 mov eax,S(type)
 cmp eax,1
 ja .predicted
 mov W(param),eax
 OP media_flac_simple
 jmp .apply_waste
.predicted:
 cmp eax,8
 jb flacd_invalid
 cmp eax,12
 jbe .fixed
 cmp eax,32
 jb flacd_invalid
 sub eax,31
 jmp .order
.fixed:
 sub eax,8
.order:
 cmp eax,S(block)
 ja flacd_invalid
 mov S(order),eax
 mov W(param),eax
 mov dword S(index),0
.warmup:
 mov eax,S(index)
 cmp eax,S(order)
 jae .warm_done
 mov ecx,W(width)
 call flacd_signed
 mov edx,S(index)
 mov rcx,S(target)
 mov [rcx+rdx*4],eax
 inc dword S(index)
 jmp .warmup
.warm_done:
 cmp dword S(type),32
 jb .residual
 GET 4
 cmp eax,15
 je flacd_invalid
 inc eax
 mov S(precision),eax
 GET 5
 ; Negative QLP shift is reserved by this encoded-header policy.
 test eax,16
 jnz flacd_invalid
 mov S(shift),eax
 mov dword S(index),0
.coefficients:
 mov ecx,S(precision)
 call flacd_signed
 mov edx,S(index)
 mov rcx,S(coeff)
 mov [rcx+rdx*4],eax
 inc dword S(index)
 mov eax,S(index)
 cmp eax,S(order)
 jb .coefficients
.residual:
 OP media_flac_residual
 mov rax,S(target)
 mov W(input),rax
 mov qword W(input_bytes),65536
 mov rax,S(tmp)
 mov W(dst),rax
 mov qword W(dst_bytes),131072
 cmp dword S(type),32
 jae .lpc
 OP media_flac_fixed
 jmp .reconstructed
.lpc:
 mov rax,S(coeff)
 mov W(other),rax
 mov qword W(other_bytes),128
 mov eax,S(shift)
 mov W(shift),eax
 OP media_flac_lpc
.reconstructed:
 mov rsi,S(tmp)
 mov rdi,S(target)
 mov ecx,S(block)
 rep movsd
.apply_waste:
 ; Validate effective sample width BEFORE restoring wasted bits; then width16/17.
 mov rsi,S(target)
 mov edx,S(block)
 mov ecx,32
 sub ecx,W(width)
.check_samples:
 mov eax,[rsi]
 mov r8d,eax
 shl r8d,cl
 sar r8d,cl
 cmp eax,r8d
 jne flacd_invalid
 push rcx
 mov ecx,S(wasted)
 shl eax,cl
 pop rcx
 mov [rsi],eax
 add rsi,4
 dec edx
 jnz .check_samples
 add rsp,8
 ret

; RDI=data, RCX=length, ESI=8/16, EDX=poly. Bitwise non-reflected FLAC CRC.
; Includes stored CRC byte(s); zero remainder verifies. No buffer writes.
flacd_crc:
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
flacd_rates: dd 0,88200,176400,192000,8000,16000,22050,24000,32000,44100,48000,96000
%undef S
%undef W
%undef I
%undef C
%unmacro GET 1
%unmacro OP 1
