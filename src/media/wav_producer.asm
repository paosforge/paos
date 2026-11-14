;; MODULE media/wav_producer
;; LAYER 4
;; EXPORTS media_wav_producer_begin, media_wav_producer_step, media_wav_producer_cancel
;; IMPORTS core/lib/mem
;; CAPS
;; OWNER rc-codex-av
; RCQ-36 S2: C1 S16 PORT + C2 authorized NEW RC S24 ADAPTATION. Classic paos.asm209279..209337 chunk walk,
; S16 ordering209451..209480; accepted RC media/wav bounds, caller ownership.
; Three entries/ctx192. One RIFF chunk or <=4096 owned S16 bytes per step.
; PCM private until READY. Trusted stable serialized mapped full spans.
; Also PCM WAVE_FORMAT_EXTENSIBLE: exact40-byte fmt/cbSize22/PCM GUID,
; full8/16/24/32 valid bits, mono FC/stereo FL+FR or unspecified channel mask.
; U8 adaptation is mono/stereo44100 only: (unsigned_byte-128)*256 to owned S16.
; No allocation/I/O/DMA/HDA/global state/consumer call or clock claim.
; Maintained WAVPLAY binds mono/stereo U8/S16/S24/S32 at44100,
; downmixing stereo to its existing mono owner. Other producer rates stay private.
; 0 progress,1 READY,2 cancelled; -1 invalid/malformed,-2 subset/phase/identity,
; -3 capacity,-4 quota. Negative calls preserve all operands for that call.
; SysV preserved GPRs/RSP; DF=0 ABI. U8 and S24/S32 floor shifts are new RC work.
struc media_wav_producer
 .version: resd 1
 .phase: resd 1                    ; EMPTY0 SCAN1 COPY2 READY3 CANCELLED4
 .generation: resq 1
 .epoch: resq 1
 .src: resq 1
 .src_bytes: resq 1
 .pcm: resq 1
 .capacity: resq 1
 .offset: resq 1
 .chunks: resq 1
 .fmt_offset: resq 1
 .data_offset: resq 1
 .data_bytes: resq 1
 .cursor: resq 1                  ; S16 OUTPUT bytes, also for U8/S24/S32 input
 .frames: resq 1
 .bytes: resq 1
 .rate: resd 1
 .channels: resd 1
 .bits: resd 1
 .input_frame: resd 1
 .seen: resq 1
 .integrity: resq 1
 .reserved: resq 5
endstruc
%define W(x) [rbx+media_wav_producer. %+ x]
media_wav_producer_begin:
 xor eax,eax
 jmp wvp_enter
media_wav_producer_step:
 mov eax,1
 jmp wvp_enter
media_wav_producer_cancel:
 mov eax,2
wvp_enter:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,88
 mov rbp,rsp
 mov rbx,rdi
 mov r12d,eax
 mov [rbp],rsi
 mov [rbp+8],rdx
 mov rsi,rbx
 mov edx,192
 call wvp_span
 test bl,7
 jnz wvp_bad
 cmp dword W(version),1
 jne wvp_bad
 cmp dword W(phase),4
 ja wvp_bad
 cmp qword W(generation),0
 je wvp_bad
 cmp qword W(epoch),0
 je wvp_bad
 mov rax,W(integrity)
 or rax,[rbx+152]
 or rax,[rbx+160]
 or rax,[rbx+168]
 or rax,[rbx+176]
 or rax,[rbx+184]
 jnz wvp_bad
 mov r13,W(src)
 mov r14,W(src_bytes)
 cmp r14,12
 jb wvp_bad
 cmp r14,307200
 ja wvp_limit
 mov r15,W(capacity)
 test r15,r15
 jz wvp_capacity
 cmp r15,192000
 ja wvp_limit
 mov rsi,r13
 mov rdx,r14
 call wvp_span
 mov rsi,W(pcm)
 mov rdx,r15
 call wvp_span
 mov rsi,rbx
 mov edx,192
 mov r8,r13
 mov r9,r14
 call wvp_pair
 mov r8,W(pcm)
 mov r9,r15
 call wvp_pair
 mov rsi,r13
 mov rdx,r14
 call wvp_pair
 cmp dword W(phase),0
 jne .live
 lea rsi,[rbx+56]
 mov ecx,17
 xor eax,eax
.fresh:
 or rax,[rsi]
 add rsi,8
 loop .fresh
 test rax,rax
 jnz wvp_bad
 jmp .validated
.live:
 cmp qword W(chunks),256
 ja wvp_limit
 mov rax,W(offset)
 cmp rax,12
 jb wvp_bad
 cmp rax,r14
 ja wvp_bad
 mov rax,W(seen)
 cmp rax,3
 ja wvp_bad
 cmp eax,2
 je wvp_bad
 test eax,1
 jnz .have_fmt
 mov rax,W(fmt_offset)
 or rax,W(data_offset)
 or rax,W(data_bytes)
 or rax,W(rate)
 or rax,W(bits)
 jnz wvp_bad
 jmp .scan_state
.have_fmt:
 mov rax,W(fmt_offset)
 cmp rax,20
 jb wvp_bad
 add rax,16
 jc wvp_bad
 cmp rax,W(offset)
 ja wvp_bad
 mov eax,W(rate)
 cmp eax,44100
 je .rate_ok
 cmp eax,48000
 jne wvp_bad
.rate_ok:
 mov ecx,W(channels)
 lea eax,[rcx-1]
 cmp eax,1
 ja wvp_bad
 mov eax,W(bits)
 cmp eax,8
 jne .wide_bits
 cmp dword W(rate),44100
 jne wvp_bad
 jmp .width_ok
.wide_bits:
 cmp eax,16
 je .width_ok
 cmp eax,24
 je .width_ok
 cmp eax,32
 jne wvp_bad
.width_ok:
 shr eax,3
 imul ecx,eax
 cmp ecx,W(input_frame)
 jne wvp_bad
 cmp qword W(seen),3
 je .have_data
 mov rax,W(data_offset)
 or rax,W(data_bytes)
 jnz wvp_bad
 jmp .scan_state
.have_data:
 mov rax,W(data_offset)
 cmp rax,W(fmt_offset)
 jbe wvp_bad
 cmp rax,W(offset)
 ja wvp_bad
 mov rdx,W(offset)
 sub rdx,rax
 cmp W(data_bytes),rdx
 ja wvp_bad
 mov rax,W(data_bytes)
 test rax,rax
 jz wvp_bad
 xor edx,edx
 div rcx
 test rdx,rdx
 jnz wvp_bad
 cmp dword W(phase),1
 je .scan_state
 cmp dword W(phase),4
 jne .planned
 cmp W(offset),r14
 jb .scan_state                  ; cancelled SCAN retains provisional state
.planned:
 ; COPY/READY or cancelled COPY: validate all planned/cursor products.
 cmp rax,W(frames)
 jne wvp_bad
 mov ecx,W(channels)
 shl ecx,1
 mul rcx
 test rdx,rdx
 jnz wvp_bad
 cmp rax,W(bytes)
 jne wvp_bad
 cmp rax,r15
 ja wvp_capacity
 cmp W(offset),r14
 jne wvp_bad
 mov rax,W(cursor)
 cmp rax,W(bytes)
 ja wvp_bad
 xor edx,edx
 div rcx
 test rdx,rdx
 jnz wvp_bad
 cmp dword W(phase),2
 jne .not_copy
 mov rax,W(cursor)
 cmp rax,W(bytes)
 jae wvp_bad
 jmp .validated
.not_copy:
 cmp dword W(phase),3
 jne .validated
 mov rax,W(cursor)
 cmp rax,W(bytes)
 jne wvp_bad
 jmp .validated
.scan_state:
 cmp dword W(phase),2
 je wvp_bad
 cmp dword W(phase),3
 je wvp_bad
 cmp W(offset),r14
 jae wvp_bad
 mov rax,W(cursor)
 or rax,W(frames)
 or rax,W(bytes)
 jnz wvp_bad
.validated:
 test r12d,r12d
 jz .begin
 cmp r12d,2
 je .cancel
 mov eax,W(phase)
 cmp eax,3
 je wvp_ready
 cmp eax,1
 je wvp_scan
 cmp eax,2
 je wvp_copy
 jmp wvp_unsupported
.cancel:
 mov rax,[rbp]
 cmp rax,W(generation)
 jne wvp_unsupported
 mov rax,[rbp+8]
 cmp rax,W(epoch)
 jne wvp_unsupported
 mov eax,W(phase)
 test eax,eax
 jz wvp_unsupported
 cmp eax,3
 je wvp_unsupported
 mov dword W(phase),4
 mov eax,2
 jmp wvp_out
.begin:
 cmp dword W(phase),0
 jne wvp_unsupported
 cmp dword [r13],'RIFF'
 jne wvp_bad
 cmp dword [r13+8],'WAVE'
 jne wvp_bad
 mov eax,[r13+4]
 add rax,8                       ; widened u32 before addition
 cmp rax,r14
 jne wvp_bad
 mov qword W(offset),12
 mov dword W(phase),1
 xor eax,eax
 jmp wvp_out
wvp_scan:
 ; Pending candidate state is local: a late refusal never half-publishes.
 mov rax,W(fmt_offset)
 mov [rbp],rax
 mov rax,W(data_offset)
 mov [rbp+8],rax
 mov rax,W(data_bytes)
 mov [rbp+16],rax
 mov rax,W(rate)
 mov [rbp+24],rax
 mov rax,W(bits)
 mov [rbp+32],rax
 mov rax,W(seen)
 mov [rbp+40],rax
 mov rax,W(chunks)
 inc rax
 cmp rax,256
 ja wvp_limit
 mov [rbp+56],rax
 mov r10,W(offset)
 mov rax,r14
 sub rax,r10
 cmp rax,8
 jb wvp_bad
 add r10,r13
 mov ecx,[r10+4]
 lea rdx,[r10+8]
 mov rax,r13
 add rax,r14
 sub rax,rdx
 cmp rcx,rax
 ja wvp_bad
 lea r11,[rdx+rcx]
 mov eax,ecx
 and eax,1
 add r11,rax
 jc wvp_bad
 sub r11,r13
 cmp r11,r14
 ja wvp_bad
 mov [rbp+48],r11
 cmp dword [r10],'fmt '
 je .fmt
 cmp dword [r10],'data'
 je .data
 jmp .next
.fmt:
 test qword [rbp+40],1
 jnz wvp_bad
 cmp ecx,16
 jb wvp_bad
 je .fmt_size
 cmp ecx,40
 je .fmt_extensible
 cmp ecx,18
 jne wvp_unsupported
 cmp word [rdx+16],0
 jne wvp_unsupported
.fmt_size:
 cmp word [rdx],1
 jne wvp_unsupported
 jmp .fmt_width
.fmt_extensible:
 ; Chunk bounds above cover all40 bytes before any extension access. Only
 ; integer PCM is admitted; no float GUID, partial valid bits or remapping.
 cmp word [rdx],0xfffe
 jne wvp_unsupported
 cmp word [rdx+16],22
 jne wvp_unsupported
 mov ax,[rdx+18]
 cmp ax,[rdx+14]
 jne wvp_unsupported
 cmp dword [rdx+24],1
 jne wvp_unsupported
 cmp dword [rdx+28],0x00100000
 jne wvp_unsupported
 cmp dword [rdx+32],0xaa000080
 jne wvp_unsupported
 cmp dword [rdx+36],0x719b3800
 jne wvp_unsupported
 mov eax,[rdx+20]
 test eax,eax
 jz .fmt_width                  ; unspecified order: existing mono/stereo
 cmp word [rdx+2],1
 jne .stereo_mask
 cmp eax,4                      ; one front-center channel
 jne wvp_unsupported
 jmp .fmt_width
.stereo_mask:
 cmp word [rdx+2],2
 jne wvp_unsupported
 cmp eax,3                      ; front-left then front-right, unchanged PCM
 jne wvp_unsupported
.fmt_width:
 movzx r9d,word [rdx+14]
 cmp r9d,8
 je .fmt_bits
 cmp r9d,16
 je .fmt_bits
 cmp r9d,24
 je .fmt_bits
 cmp r9d,32
 jne wvp_unsupported
.fmt_bits:
 movzx ecx,word [rdx+2]
 lea eax,[rcx-1]
 cmp eax,1
 ja wvp_unsupported
 mov eax,[rdx+4]
 cmp eax,44100
 je .fmt_rate
 cmp eax,48000
 jne wvp_unsupported
.fmt_rate:
 cmp r9d,8
 jne .fmt_plan
 ; U8 shares the mono/stereo geometry; keep its44100-only rate.
 cmp eax,44100
 jne wvp_unsupported
.fmt_plan:
 mov [rbp+24],eax
 mov [rbp+28],ecx
 mov r8d,r9d
 shr r8d,3
 imul ecx,r8d
 cmp [rdx+12],cx
 jne wvp_bad
 imul eax,ecx
 cmp [rdx+8],eax
 jne wvp_bad
 mov [rbp+32],r9d
 mov [rbp+36],ecx
 sub rdx,r13
 mov [rbp],rdx
 or qword [rbp+40],1
 jmp .next
.data:
 test qword [rbp+40],1
 jz wvp_unsupported
 test qword [rbp+40],2
 jnz wvp_bad
 test rcx,rcx
 jz wvp_bad
 mov [rbp+16],rcx
 mov rax,rcx
 mov ecx,[rbp+36]
 xor r8d,r8d
 mov r8,rdx
 xor edx,edx
 div rcx
 test edx,edx
 jnz wvp_bad
 mov rdx,r8
 sub rdx,r13
 mov [rbp+8],rdx
 or qword [rbp+40],2
.next:
 cmp r11,r14
 jne .publish
 cmp qword [rbp+40],3
 jne wvp_bad
 mov rax,[rbp+16]
 mov ecx,[rbp+36]
 xor edx,edx
 div rcx
 mov [rbp+64],rax
 mov ecx,[rbp+28]
 shl ecx,1
 mul rcx
 test rdx,rdx
 jnz wvp_bad
 cmp rax,192000
 ja wvp_limit
 cmp rax,r15
 ja wvp_capacity
 mov [rbp+72],rax
.publish:
 mov rax,[rbp]
 mov W(fmt_offset),rax
 mov rax,[rbp+8]
 mov W(data_offset),rax
 mov rax,[rbp+16]
 mov W(data_bytes),rax
 mov rax,[rbp+24]
 mov W(rate),rax
 mov rax,[rbp+32]
 mov W(bits),rax
 mov rax,[rbp+40]
 mov W(seen),rax
 mov W(offset),r11
 mov rax,[rbp+56]
 mov W(chunks),rax
 cmp r11,r14
 jne .progress
 mov rax,[rbp+64]
 mov W(frames),rax
 mov rax,[rbp+72]
 mov W(bytes),rax
 mov dword W(phase),2
.progress:
 xor eax,eax
 jmp wvp_out
wvp_copy:
 mov r8,W(bytes)
 sub r8,W(cursor)
 mov eax,4096
 cmp r8,rax
 cmova r8,rax
 mov [rbp+80],r8
 mov rdi,W(pcm)
 add rdi,W(cursor)
 mov rsi,r13
 add rsi,W(data_offset)
 cmp dword W(bits),8
 je .u8
 cmp dword W(bits),24
 je .s24
 cmp dword W(bits),32
 je .s32
 add rsi,W(cursor)                ; retained S16 byte identity
 mov rdx,r8
 call memcpy                     ; canonical9703 preserves r8-r15/rbp/rbx
 jmp .publish
.u8:
 ; OUTPUT cursor counts two bytes/sample; INPUT is exactly one unsigned byte.
 ; Exact bounded read/store, including a final odd-length padded data chunk.
 mov rax,W(cursor)
 shr rax,1
 add rsi,rax
 mov rcx,r8
 shr rcx,1
.u8_sample:
 movzx eax,byte [rsi]
 sub eax,128
 shl eax,8
 mov [rdi],ax
 inc rsi
 add rdi,2
 dec rcx
 jnz .u8_sample
 jmp .publish
.s24:
 ; Authorized adaptation: packed signed S24 floor>>8 equals upper LE word.
 ; Exact two-byte read at sample+1, no four-byte read across final sample.
 mov rax,W(cursor)
 shr rax,1
 lea rax,[rax+rax*2]
 add rsi,rax
 mov rcx,r8
 shr rcx,1
.s24_sample:
 movzx eax,word [rsi+1]
 mov [rdi],ax
 add rsi,3
 add rdi,2
 dec rcx
 jnz .s24_sample
 jmp .publish
.s32:
 ; Signed PCM32 floor>>16 is its upper LE word, independently of low bits.
 ; OUTPUT cursor*2 is INPUT byte offset for mono and interleaved stereo.
 ; Read exactly two bytes at sample+2, including the final sample tail.
 mov rax,W(cursor)
 lea rsi,[rsi+rax*2]
 mov rcx,r8
 shr rcx,1
.s32_sample:
 movzx eax,word [rsi+2]
 mov [rdi],ax
 add rsi,4
 add rdi,2
 dec rcx
 jnz .s32_sample
.publish:
 mov rax,[rbp+80]
 add W(cursor),rax
 mov rax,W(cursor)
 cmp rax,W(bytes)
 jne .progress
 mov dword W(phase),3             ; publish READY only after final stores
 jmp wvp_ready
.progress:
 xor eax,eax
 jmp wvp_out
wvp_ready:
 mov eax,1
 jmp wvp_out
wvp_bad: mov rax,-1
 jmp wvp_out
wvp_unsupported: mov rax,-2
 jmp wvp_out
wvp_capacity: mov rax,-3
 jmp wvp_out
wvp_limit: mov rax,-4
wvp_out:
 mov rsp,rbp
 add rsp,88
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
wvp_span:
 test rsi,rsi
 jz wvp_bad
 test rdx,rdx
 jz wvp_bad
 mov rax,rsi
 add rax,rdx
 jc wvp_bad
 ret
wvp_pair:
 lea rax,[r8+r9]
 cmp rsi,rax
 jae .ok
 lea rax,[rsi+rdx]
 cmp r8,rax
 jb wvp_bad
.ok: ret
%undef W
