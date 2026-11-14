;; MODULE media/opus_packet
;; LAYER 4
;; EXPORTS media_opus_packet_parse
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
;
; Private, UNWIRED Opus elementary packet framing boundary. No PCM decoding,
; allocation, Ogg demux, self-delimited multistream, device, globals or FP state.
; Packet framing agrees with the installed libopus opus_packet_parse API;
; tests independently obtain every frame pointer/length and duration from it.
;
; media_opus_packet_parse(RDI=stable source, RSI=truthful bytes,
;                         RDX=stable caller-owned result416*) -> RAX:
;   0 framed, -1 malformed/pointer/overlap, -4 packet work limit (65536 bytes).
; Source and result416 are disjoint mapped lower-canonical spans. Result is
; 4-byte aligned. No result/source store on ANY refusal. Zero-length frames are
; legal; frame offsets may equal source length, and authorize no payload read.
; Success establishes framing only, never a decodable entropy stream or PCM.
; SysV nonvolatile GPR/RSP preserved, DF0 on every exit, FP state untouched.
;
; Result: eight u32 {TOC, channels, frame_count, samples_per_frame_48000,
; packet_samples_48000, payload_offset, trailing_padding_bytes, reserved0};
; then48 {u32 offset, u32 size} rows. Unused rows are zero. No borrowed pointers.

MEDIA_OPUS_PACKET_MAX_BYTES equ 65536
MEDIA_OPUS_PACKET_RESULT_BYTES equ 416

media_opus_packet_parse:
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,424
 mov r12,rdi
 mov r14,rdx
 test r12,r12
 jz .bad
 test rsi,rsi
 jz .bad
 cmp rsi,MEDIA_OPUS_PACKET_MAX_BYTES
 ja .limit
 mov r13,r12
 add r13,rsi
 jc .bad
 mov rax,r13
 dec rax
 shr rax,47
 jnz .bad
 test r14,r14
 jz .bad
 test r14b,3
 jnz .bad
 mov rax,r14
 add rax,MEDIA_OPUS_PACKET_RESULT_BYTES
 jc .bad
 mov rcx,rax
 dec rcx
 shr rcx,47
 jnz .bad
 cmp r14,r13
 jae .spans_ok
 cmp r12,rax
 jb .bad
.spans_ok:
 mov rdi,rsp
 xor eax,eax
 mov ecx,MEDIA_OPUS_PACKET_RESULT_BYTES/8
 rep stosq
 movzx r10d,byte [r12]
 lea rbx,[r12+1]
 xor r11d,r11d                  ; trailing padding bytes, excludes header
 mov r9d,r10d
 shr r9d,3
 and r9d,3
 mov ecx,r9d
 mov r9d,120
 test r10b,0x80
 jnz .celt
 mov eax,r10d
 and eax,0x60
 cmp eax,0x60
 jne .silk
 mov r9d,480
 test r10b,8
 jz .duration_ready
 mov r9d,960
 jmp .duration_ready
.silk:
 mov r9d,480
 cmp ecx,3
 jne .celt
 mov r9d,2880
 jmp .duration_ready
.celt:
 shl r9d,cl
.duration_ready:
 mov eax,r10d
 and eax,3
 mov r8d,1
 test eax,eax
 jz .one
 mov r8d,2
 cmp eax,1
 je .cbr
 cmp eax,2
 je .two_vbr
 cmp rbx,r13
 jae .bad
 movzx r15d,byte [rbx]
 inc rbx
 mov r8d,r15d
 and r8d,63
 test r8d,r8d
 jz .bad
 cmp r8d,48
 ja .bad
 mov eax,r8d
 imul eax,r9d
 cmp eax,5760
 ja .bad
 test r15b,0x40
 jz .padding_done
.padding:
 cmp rbx,r13
 jae .bad
 movzx eax,byte [rbx]
 inc rbx
 cmp eax,255
 jne .padding_last
 add r11d,254
 mov rdx,r13
 sub rdx,rbx
 cmp r11,rdx
 ja .bad
 jmp .padding
.padding_last:
 add r11d,eax
 mov rax,r13
 sub rax,rbx
 cmp r11,rax
 ja .bad
 sub r13,r11
.padding_done:
 test r15b,0x80
 jz .cbr
 xor ebp,ebp                   ; aggregate explicitly encoded frame sizes
 xor r15d,r15d                 ; frame index
.vbr_headers:
 mov eax,r8d
 dec eax
 cmp r15d,eax
 jae .vbr_last
 call .size
 test rax,rax
 js .bad
 mov [rsp+32+r15*8+4],eax
 add rbp,rax
 inc r15d
 jmp .vbr_headers
.vbr_last:
 mov rax,r13
 sub rax,rbx
 sub rax,rbp
 jc .bad
 cmp rax,1275
 ja .bad
 mov [rsp+32+r15*8+4],eax
 jmp .sizes_ready
.one:
 mov rax,r13
 sub rax,rbx
 cmp rax,1275
 ja .bad
 mov [rsp+36],eax
 jmp .sizes_ready
.two_vbr:
 call .size
 test rax,rax
 js .bad
 mov [rsp+36],eax
 mov rdx,r13
 sub rdx,rbx
 sub rdx,rax
 jc .bad
 cmp rdx,1275
 ja .bad
 mov [rsp+44],edx
 jmp .sizes_ready
.cbr:
 mov rax,r13
 sub rax,rbx
 xor edx,edx
 div r8d
 test edx,edx
 jnz .bad
 cmp eax,1275
 ja .bad
 xor ecx,ecx
.cbr_rows:
 mov [rsp+32+rcx*8+4],eax
 inc ecx
 cmp ecx,r8d
 jb .cbr_rows
.sizes_ready:
 mov eax,r8d
 imul eax,r9d
 cmp eax,5760
 ja .bad
 mov [rsp+16],eax
 mov [rsp],r10d
 mov eax,r10d
 shr eax,2
 and eax,1
 inc eax
 mov [rsp+4],eax
 mov [rsp+8],r8d
 mov [rsp+12],r9d
 mov rax,rbx
 sub rax,r12
 mov [rsp+20],eax
 mov [rsp+24],r11d
 xor ecx,ecx
.offsets:
 mov rax,rbx
 sub rax,r12
 mov [rsp+32+rcx*8],eax
 mov eax,[rsp+32+rcx*8+4]
 add rbx,rax
 inc ecx
 cmp ecx,r8d
 jb .offsets
 cmp rbx,r13
 jne .bad
 ; Only after complete packet admission, publish one bounded result.
 mov rdi,r14
 mov rsi,rsp
 mov ecx,MEDIA_OPUS_PACKET_RESULT_BYTES/8
 rep movsq
 xor eax,eax
 jmp .out
.limit:
 mov rax,-4
 jmp .out
.bad:
 mov rax,-1
.out:
 add rsp,424
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; Internal size decoder: header cursor RBX < exclusive effective end R13.
; One byte <252 or two bytes first+4*second (max1275). Other state preserved.
.size:
 cmp rbx,r13
 jae .size_bad
 movzx eax,byte [rbx]
 inc rbx
 cmp eax,252
 jb .size_out
 cmp rbx,r13
 jae .size_bad
 movzx edx,byte [rbx]
 inc rbx
 lea eax,[rax+rdx*4]
.size_out:
 ret
.size_bad:
 mov rax,-1
 ret
