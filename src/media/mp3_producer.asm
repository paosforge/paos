;; MODULE media/mp3_producer
;; LAYER 4
;; EXPORTS media_mp3_producer_begin, media_mp3_producer_step, media_mp3_producer_take, media_mp3_producer_cancel
;; IMPORTS media/mp3_header_private, media/mp3_bits_private, media/mp3_math
;; CAPS
;; OWNER rc-codex-av
; Native MPEG1/2/2.5 L3 long/start/short/stop/mixed PCM, Classic0cab adaptation.
; Common producer envelope192B; caller-owned workspace98304B aligned16 and
; PCM capacity4608..192000. One staged frame / bounded entropy or filter turn.
; No allocation/I/O/global state/device action. See docs/MP3_NATIVE_STREAM.md.
; 0 progress,1 frame READY/backpressure,2 EOF/cancel; negatives sticky frame
; failure except stale/invalid admission (unchanged). Output commits atomically
; AFTER both granules/channels succeed. Unsupported is NEVER silent PCM.
; RDI=ctx,RSI=generation,RDX=epoch. take alsoRCX=dst,R8=max_frames ->frames.
; Take caller-owned PCM is the consumer seam; no HDA/sound op hidden here.
; Full SysV/DF0; full x87/MXCSR/XMM restored via FX save around normalized math.

MP3P_WORK equ 98304
MP3P_SCAN equ 1
MP3P_ENTROPY equ 2
MP3P_FILTER equ 3
MP3P_COMMIT equ 4
MP3P_READY equ 5
MP3P_DONE equ 6
MP3P_FAILED equ 7
MP3P_CANCEL equ 8
struc mp3p_ctx
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
; Committed history is separate from speculative frame state. No current
; stream history/reservoir gets replaced on malformed/unsupported late frame.
struc mp3p_work
 .snapshot: resb 48               ;ctx generation..capacity + workspace..budget below
 .public: resb 192
 .binding: resb 24
 .previous_generation: resq 1
 .previous_epoch: resq 1
 .magic: resq 1
 .resv_len: resd 1
 .pad: resd 1
 .reservoir: resb 512
 .history: resb 2*(576+1024)*8
 .header: resb 32
 .reader: resb 32
 .scfsi: resd 2
 .si: resb 4*72
 .bands: resq 1
 .frame_end: resq 1
 .md_bytes: resd 1
 .mdb: resd 1
 .part_end: resd 1
 .main_bit: resd 1
 .gr: resd 1
 .ch: resd 1
 .error: resd 1
 .pad2: resd 1
 .main: resb 2048                 ;511 previous + <=1440 frame + zero guard
 .aligned: resb 528              ;<=4095 entropy bits + padded lookahead
 .sf: resb 4*40*4
 .regions: resb 32
 .is: resb 576*4
 .xr: resb 2*576*8
 .hybrid: resb 576*8
 .synth: resb 576*8
 .tmp: resb 36*8
 .u: resb 512*8
 .staging: resb 4608
 ; Additive private LSF state; existing offsets/public envelope are unchanged.
 .ist: resd 4*40
 .slen: resd 4
 .partition: resd 4
 .granules: resd 1
 .samples: resd 1
 .band_index: resd 1
endstruc
; Place speculative persistent channel state at98304-25600, not .work end.
; Buffers above must not extend into it.
MP3P_TEMP equ MP3P_WORK-25600
%if mp3p_work_size > MP3P_TEMP
 %error MP3 workspace overlap
%endif
%define C(x) [rbx+mp3p_ctx. %+ x]
%define W(x) [r12+mp3p_work. %+ x]

media_mp3_producer_begin:
 xor eax,eax
 jmp mp3p_enter
media_mp3_producer_step:
 mov eax,1
 jmp mp3p_enter
media_mp3_producer_cancel:
 mov eax,2
 jmp mp3p_enter
media_mp3_producer_take:
 mov eax,3
mp3p_enter:
 ; Check every external full64 span and prospective stack before any push.
 test rdi,rdi
 jz mp3p_leaf_bad
 test dil,7
 jnz mp3p_leaf_bad
 mov r9,rdi
 add r9,mp3p_ctx_size
 jc mp3p_leaf_bad
 mov r10,r9
 dec r10
 shr r10,47
 jnz mp3p_leaf_bad
 cmp dword [rdi+mp3p_ctx.version],1
 jne mp3p_leaf_bad
 cmp rsi,[rdi+mp3p_ctx.generation]
 jne mp3p_leaf_stale
 cmp rdx,[rdi+mp3p_ctx.epoch]
 jne mp3p_leaf_stale
 test rsi,rsi
 jz mp3p_leaf_stale
 test rdx,rdx
 jz mp3p_leaf_stale
 mov r10,rsp
 sub r10,2048
 jc mp3p_leaf_bad
 lea r11,[rsp+8]
 cmp rdi,r11
 jae .ctx_stack
 cmp r9,r10
 ja mp3p_leaf_bad
.ctx_stack:
 mov r9d,eax                    ; operation; identity args already checked
%macro MP3P_LEAF_SPAN 2
 mov rsi,[rdi+mp3p_ctx.%1]
 mov rdx,[rdi+mp3p_ctx.%2]
 test rsi,rsi
 jz mp3p_leaf_bad
 test rdx,rdx
 jz mp3p_leaf_bad
 mov rax,rsi
 add rax,rdx
 jc mp3p_leaf_bad
 mov rdx,rax
 dec rdx
 shr rdx,47
 jnz mp3p_leaf_bad
 cmp rsi,r11
 jae %%ok
 cmp rax,r10
 ja mp3p_leaf_bad
%%ok:
%endmacro
 MP3P_LEAF_SPAN src,src_bytes
 MP3P_LEAF_SPAN pcm,capacity
 MP3P_LEAF_SPAN workspace,workspace_bytes
 mov eax,r9d
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,568                     ;aligned FX512 + locals56
 mov rbx,rdi
 mov [rsp+512],eax
 mov [rsp+520],rcx
 mov [rsp+528],r8
 mov r12,C(workspace)
 mov r13,C(src)
 mov r14,C(pcm)
 mov rsi,r13
 mov rdx,C(src_bytes)
 cmp rdx,4
 jb mp3p_bad
 cmp rdx,16*1024*1024
 ja mp3p_quota
 call mp3p_span
 jc mp3p_bad
 mov rsi,r14
 mov rdx,C(capacity)
 cmp rdx,4608
 jb mp3p_capacity
 cmp rdx,192000
 ja mp3p_quota
 call mp3p_span
 jc mp3p_bad
 test r12,15
 jnz mp3p_bad
 mov rsi,r12
 mov rdx,C(workspace_bytes)
 cmp rdx,MP3P_WORK
 jb mp3p_capacity
 call mp3p_span
 jc mp3p_bad
 mov rax,C(budget)
 dec rax
 cmp rax,65534
 ja mp3p_quota
 mov rax,C(substate)
 or rax,C(integrity)
 or rax,[rbx+152]
 or rax,[rbx+160]
 or rax,[rbx+168]
 or rax,[rbx+176]
 or rax,[rbx+184]
 jnz mp3p_bad
 mov rsi,r13
 mov rdx,C(src_bytes)
 mov r8,r14
 mov r9,C(capacity)
 call mp3p_pair
 jc mp3p_bad
 mov r8,r12
 mov r9,C(workspace_bytes)
 call mp3p_pair
 jc mp3p_bad
 mov rsi,r14
 mov rdx,C(capacity)
 call mp3p_pair
 jc mp3p_bad
 ; All spans admitted before touching FP state or workspace.
 fxsave [rsp]
 fninit
 mov dword [rsp+536],0x1f80
 ldmxcsr [rsp+536]
 mov dword [rsp+552],0
 cmp dword [rsp+512],0
 je mp3p_begin
 ; Fixed producer identity/binding, not caller booleans or stale metadata.
 mov rax,0x314d435033504d52
 cmp W(magic),rax
 jne mp3p_fp_stale
 lea rsi,[rbx+mp3p_ctx.generation]
 lea rdi,[r12+mp3p_work.snapshot]
 mov ecx,6
 repe cmpsq
 jne mp3p_fp_stale
 lea rsi,[rbx+mp3p_ctx.workspace]
 lea rdi,[r12+mp3p_work.binding]
 mov ecx,3
 repe cmpsq
 jne mp3p_fp_stale
 lea rsi,[r12+mp3p_work.public]
 mov rdi,rbx
 mov ecx,24
 repe cmpsq
 jne mp3p_fp_stale
 mov dword [rsp+552],1
 mov rax,C(offset)
 cmp rax,C(src_bytes)
 ja mp3p_fp_bad
 cmp qword C(encoded_frames),65535
 ja mp3p_fp_bad
 cmp dword [rsp+512],2
 je mp3p_cancel
 cmp dword [rsp+512],3
 je mp3p_take
 mov eax,C(phase)
 cmp eax,MP3P_SCAN
 je mp3p_scan
 cmp eax,MP3P_ENTROPY
 je mp3p_entropy
 cmp eax,MP3P_FILTER
 je mp3p_filter
 cmp eax,MP3P_COMMIT
 je mp3p_commit
 cmp eax,MP3P_READY
 je mp3p_ready
 cmp eax,MP3P_DONE
 je mp3p_done
 jmp mp3p_fp_stale

mp3p_begin:
 cmp dword C(phase),0
 je .fresh
 cmp dword C(phase),MP3P_CANCEL
 jne mp3p_fp_stale
 mov rax,0x314d435033504d52
 cmp W(magic),rax
 jne mp3p_fp_stale
 cmp [r12+mp3p_work.binding],r12
 jne mp3p_fp_stale
 mov rax,W(previous_generation)
 cmp C(generation),rax
 jbe mp3p_fp_stale
 mov rax,W(previous_epoch)
 cmp C(epoch),rax
 jbe mp3p_fp_stale
.fresh:
 mov rdi,r12
 xor eax,eax
 mov ecx,MP3P_WORK/8
 rep stosq
 lea rdi,[r12+mp3p_work.snapshot]
 lea rsi,[rbx+mp3p_ctx.generation]
 mov ecx,6
 rep movsq
 lea rdi,[r12+mp3p_work.binding]
 lea rsi,[rbx+mp3p_ctx.workspace]
 mov ecx,3
 rep movsq
 mov rax,0x314d435033504d52
 mov W(magic),rax
 mov rax,C(generation)
 mov W(previous_generation),rax
 mov rax,C(epoch)
 mov W(previous_epoch),rax
 lea rdi,[rbx+mp3p_ctx.offset]
 ; Clear outputs only, retaining workspace/budget inputs.
 mov qword C(offset),0
 mov qword C(encoded_frames),0
 mov qword C(cursor),0
 mov qword C(frames),0
 mov qword C(bytes),0
 mov qword C(rate),0
 mov qword C(bits),0
 mov qword C(substate),0
 mov qword C(integrity),0
 mov dword C(phase),MP3P_SCAN
 mov dword [rsp+552],1
 jmp mp3p_progress

mp3p_scan:
 mov rax,C(offset)
 cmp rax,C(src_bytes)
 je .eof
 mov rax,C(encoded_frames)
 cmp rax,C(budget)
 jae mp3p_frame_quota
 mov rdi,C(src)
 add rdi,C(offset)
 mov rsi,C(src_bytes)
 sub rsi,C(offset)
 lea rdx,[r12+mp3p_work.header]
 call media_mp3_frame_header
 cmp rax,-2
 je mp3p_unsupported
 test rax,rax
 jnz mp3p_malformed
 mov eax,[r12+mp3p_work.header+28]
 test eax,0x10000                ; CRC-protected frames require actual CRC
 jz mp3p_unsupported
 mov ecx,eax
 and ecx,3                       ; reserved emphasis
 cmp ecx,2
 je mp3p_unsupported
 mov eax,[r12+mp3p_work.header]
 cmp dword C(rate),0
 je .first
 cmp eax,C(rate)
 jne mp3p_unsupported
 mov eax,[r12+mp3p_work.header+12]
 cmp eax,C(channels)
 jne mp3p_unsupported
.first:
 mov dword W(granules),2
 mov dword W(samples),1152
 test dword [r12+mp3p_work.header+28],0x80000
 jnz .mpeg1_bands
 mov dword W(granules),1
 mov dword W(samples),576
 mov eax,[r12+mp3p_work.header]
 xor ecx,ecx
 cmp eax,11025
 je .lsf_bands
 cmp eax,12000
 je .lsf_bands
 inc ecx
 cmp eax,8000
 je .lsf_bands
 inc ecx
 cmp eax,22050
 je .lsf_bands
 inc ecx
 cmp eax,24000
 je .lsf_bands
 inc ecx
.lsf_bands:
 mov W(band_index),ecx
 lea rax,[rel mp3p_lsf_bands]
 movsxd rcx,[rax+rcx*4]
 add rax,rcx
 jmp .bands
.mpeg1_bands:
 lea rax,[rel mp3p_bands_44100]
 cmp dword [r12+mp3p_work.header],44100
 je .bands
 lea rax,[rel mp3p_bands_48000]
 cmp dword [r12+mp3p_work.header],48000
 je .bands
 lea rax,[rel mp3p_bands_32000]
.bands:
 mov W(bands),rax
 mov rax,C(offset)
 mov edx,[r12+mp3p_work.header+8]
 add rax,rdx
 mov W(frame_end),rax
 mov rdi,C(src)
 add rdi,C(offset)
 add rdi,4
 mov W(reader),rdi
 mov eax,[r12+mp3p_work.header+16]
 mov [r12+mp3p_work.reader+8],rax
 mov qword [r12+mp3p_work.reader+16],0
 mov qword [r12+mp3p_work.reader+24],0
 lea rdi,[r12+mp3p_work.si]
 xor eax,eax
 mov ecx,4*72/8
 rep stosq
 mov esi,9
 cmp dword W(granules),2
 je .mdb_bits
 mov esi,8
.mdb_bits:
 call mp3p_read
 jc mp3p_malformed
 mov W(mdb),edx
 cmp dword W(granules),2
 je .mpeg1_private
 mov esi,[r12+mp3p_work.header+12]
 call mp3p_read
 jc mp3p_malformed
 mov qword W(scfsi),0
 jmp .side_records
.mpeg1_private:
 cmp dword [r12+mp3p_work.header+12],1
 jne .stereo_private
 mov esi,5
 jmp .private
.stereo_private:
 mov esi,3
.private:
 call mp3p_read
 jc mp3p_malformed
 xor ebp,ebp
.scfsi:
 mov esi,4
 call mp3p_read
 jc mp3p_malformed
 mov [r12+mp3p_work.scfsi+rbp*4],edx
 inc ebp
 cmp ebp,[r12+mp3p_work.header+12]
 jb .scfsi
 .side_records:
 mov dword W(gr),0
 mov dword W(ch),0
 xor r15d,r15d                   ;side-info record
.si:
 lea r14,[r12+mp3p_work.si]
 mov eax,r15d
 imul eax,72
 add r14,rax
%macro MP3P_FIELD 2
 mov esi,%1
 call mp3p_read
 jc mp3p_malformed
 mov [r14+%2],edx
%endmacro
 MP3P_FIELD 12,0
 MP3P_FIELD 9,4
 MP3P_FIELD 8,8
 mov esi,4
 cmp dword W(granules),2
 je .sfc_bits
 mov esi,9
.sfc_bits:
 call mp3p_read
 jc mp3p_malformed
 mov [r14+12],edx
 MP3P_FIELD 1,16
 test edx,edx
 jnz .switched
 MP3P_FIELD 5,28
 MP3P_FIELD 5,32
 MP3P_FIELD 5,36
 MP3P_FIELD 4,40
 MP3P_FIELD 3,44
 jmp .tail
.switched:
 ; Parse the actual full branch including the shared three trailing bits,
 ; then reject its unsupported transform before any current-frame PCM commit.
 MP3P_FIELD 2,20
 MP3P_FIELD 1,24
 MP3P_FIELD 5,28
 MP3P_FIELD 5,32
 MP3P_FIELD 3,48
 MP3P_FIELD 3,52
 MP3P_FIELD 3,56
.tail:
 cmp dword W(granules),2
 jne .lsf_tail
 MP3P_FIELD 1,60
.lsf_tail:
 MP3P_FIELD 1,64
 MP3P_FIELD 1,68
 inc r15d
 mov eax,[r12+mp3p_work.header+12]
 imul eax,W(granules)
 cmp r15d,eax
 jb .si
 ; Semantic validation of ALL granules before decoding any current frame.
 xor r15d,r15d
 xor ebp,ebp
.validate:
 lea r14,[r12+mp3p_work.si]
 mov eax,r15d
 imul eax,72
 add r14,rax
 cmp dword [r14+16],0
 je .long_valid
 cmp dword [r14+20],0
 je mp3p_malformed              ; switched block_type0 is reserved
 cmp dword [r14+24],0
 je .long_valid
 cmp dword [r14+20],2
 jne mp3p_malformed             ; mixed prefix only with short type2
.long_valid:
 cmp dword [r14+4],288
 ja mp3p_malformed
 mov eax,[r14+40]
 add eax,[r14+44]
 cmp eax,20
 ja mp3p_malformed
 xor ecx,ecx
.tables:
 mov eax,[r14+28+rcx*4]
 cmp eax,4
 je mp3p_malformed
 cmp eax,14
 je mp3p_malformed
 inc ecx
 cmp ecx,3
 jb .tables
 add ebp,[r14]
 inc r15d
 mov eax,[r12+mp3p_work.header+12]
 imul eax,W(granules)
 cmp r15d,eax
 jb .validate
 mov eax,W(mdb)
 cmp eax,W(resv_len)
 ja mp3p_reservoir
 mov edx,[r12+mp3p_work.header+24]
 add edx,eax
 cmp edx,1952
 ja mp3p_malformed
 mov W(md_bytes),edx
 shl edx,3
 cmp ebp,edx
 ja mp3p_malformed
 ; Concatenate exact committed tail and current main data, with own zero guard.
 lea rdi,[r12+mp3p_work.main]
 lea rsi,[r12+mp3p_work.reservoir]
 mov ecx,W(resv_len)
 sub ecx,eax
 add rsi,rcx
 mov ecx,eax
 rep movsb
 mov rsi,C(src)
 add rsi,C(offset)
 mov eax,[r12+mp3p_work.header+20]
 add rsi,rax
 mov ecx,[r12+mp3p_work.header+24]
 rep movsb
 xor eax,eax
 mov ecx,16
 rep stosb
 ; Start speculative history from last completely committed PCM frame.
 lea rdi,[r12+MP3P_TEMP]
 lea rsi,[r12+mp3p_work.history]
 mov ecx,25600/8
 rep movsq
 lea rdi,[r12+mp3p_work.sf]
 xor eax,eax
 mov ecx,4*40*4/8
 rep stosq
 mov dword W(main_bit),0
 mov dword W(gr),0
 mov dword W(ch),0
 mov dword C(phase),MP3P_ENTROPY
 jmp mp3p_progress
.eof:
 cmp qword C(encoded_frames),0
 je mp3p_malformed
 mov dword C(phase),MP3P_DONE
 jmp mp3p_done

; One channel/granule scalefactor+entropy+requant turn. Native math is bounded
; by576 lines and finite trusted Huffman tables; no unbounded scan/resync.
mp3p_entropy:
 call mp3p_record
 lea rax,[r12+mp3p_work.main]
 mov W(reader),rax
 mov eax,W(md_bytes)
 mov [r12+mp3p_work.reader+8],rax
 mov eax,W(main_bit)
 mov [r12+mp3p_work.reader+16],rax
 mov eax,[r14]
 add eax,W(main_bit)
 mov W(part_end),eax
 cmp dword W(granules),2
 je .mpeg1_sf
 call mp3p_lsf_scalefactors
 jc mp3p_malformed
 jmp .sf_done
.mpeg1_sf:
 mov eax,[r14+12]
 lea rdx,[rel mp3p_slen1]
 movzx r13d,byte [rdx+rax]
 lea rdx,[rel mp3p_slen2]
 movzx r15d,byte [rdx+rax]
 mov dword [rsp+544],21          ; actual scalefactors read (last implicit)
 mov dword [rsp+548],11          ; slen1 prefix
 cmp dword [r14+20],2
 jne .sf_init
 mov dword [rsp+544],36          ; pure short:12bands*3 windows
 mov dword [rsp+548],18          ; first6bands*3 use slen1
 cmp dword [r14+24],0
 je .sf_init
 mov dword [rsp+544],35          ;8long +9short-slen1 +18short-slen2
 mov dword [rsp+548],17
.sf_init:
 xor ebp,ebp
.sf:
 mov esi,r13d
 cmp ebp,[rsp+548]
 jb .slen
 mov esi,r15d
.slen:
 cmp dword [r14+20],2
 je .read_sf                    ; scfsi sharing never applies to short layout
 cmp dword W(gr),1
 jne .read_sf
 mov eax,W(ch)
 imul eax,72
 lea rdx,[r12+mp3p_work.si+rax]
 cmp dword [rdx+20],2
 jne .share_long
 mov eax,W(ch)
 cmp dword [r12+mp3p_work.scfsi+rax*4],0
 jne mp3p_malformed             ; sharing long SF from short predecessor invalid
.share_long:
 xor ecx,ecx
 cmp ebp,6
 jb .group
 inc ecx
 cmp ebp,11
 jb .group
 inc ecx
 cmp ebp,16
 jb .group
 inc ecx
.group:
 mov eax,3
 sub eax,ecx
 mov ecx,W(ch)
 mov edx,[r12+mp3p_work.scfsi+rcx*4]
 bt edx,eax
 jnc .read_sf
 mov eax,W(ch)
 imul eax,160
 lea rdx,[r12+mp3p_work.sf+rax]
 mov edx,[rdx+rbp*4]
 jmp .store_sf
.read_sf:
 test esi,esi
 jz .zero_sf
 mov eax,[r12+mp3p_work.reader+16]
 add eax,esi
 cmp eax,W(part_end)
 ja mp3p_malformed
 call mp3p_read
 jc mp3p_malformed
 jmp .store_sf
.zero_sf:
 xor edx,edx
.store_sf:
 mov eax,W(gr)
 imul eax,2
 add eax,W(ch)
 imul eax,160
 lea rdi,[r12+mp3p_work.sf+rax]
 mov [rdi+rbp*4],edx
 inc ebp
 cmp ebp,[rsp+544]
 jb .sf
 .sf_done:
 ; Final long scale or final three short scales are implicit0.
 ; Long preflag affects11..20; short uses its independent window gains.
 ; Preserve raw gr0 scalefactors for scfsi: effective values staged separately.
 lea rdi,[r12+mp3p_work.aligned]
 mov ecx,528/8
 xor eax,eax
 rep stosq
 mov eax,W(part_end)
 sub eax,[r12+mp3p_work.reader+16]
 jc mp3p_malformed
 mov [rsp+544],eax               ; Huffman bit limit
 ; Align only ceil(valid entropy bits/8), no fixed unbounded source read.
 lea ebp,[eax+7]
 shr ebp,3
 mov rsi,[r12+mp3p_work.reader]
 mov eax,[r12+mp3p_work.reader+16]
 mov ecx,eax
 and ecx,7
 mov [rsp+548],ecx
 shr eax,3
 add rsi,rax
 lea rdi,[r12+mp3p_work.aligned]
.align:
 test ebp,ebp
 jz .aligned
 movzx eax,byte [rsi]
 movzx edx,byte [rsi+1]           ; own validated concatenation + zero guard
 mov ecx,[rsp+548]
 shl eax,cl
 mov ecx,8
 sub ecx,[rsp+548]
 shr edx,cl
 or eax,edx
 mov [rdi],al
 inc rsi
 inc rdi
 dec ebp
 jmp .align
.aligned:
 ; Classic region boundaries, now strict validated22-band rate-specific view.
 mov r13,W(bands)
 cmp dword [r14+16],0
 je .long_regions
 mov r8d,36                     ; switched short36 (8k72), LSF start/stop54/108
 cmp dword W(granules),2
 je .switched_region
 cmp dword [r14+20],2
 je .switched_region
 mov r8d,54
.switched_region:
 cmp dword [r12+mp3p_work.header],8000
 jne .switched_ready
 shl r8d,1
.switched_ready:
 mov edx,[r14+4]
 shl edx,1
 mov r9d,edx
 jmp .region_min
.long_regions:
 mov eax,[r14+40]
 inc eax
 mov r8d,[r13+rax*4]
 add eax,[r14+44]
 inc eax
 mov r9d,[r13+rax*4]
 mov edx,[r14+4]
 shl edx,1
.region_min:
 cmp r8d,edx
 cmova r8d,edx
 cmp r9d,edx
 cmova r9d,edx
 lea rdi,[r12+mp3p_work.regions]
 mov eax,[r14+28]
 mov [rdi],eax
 mov eax,r8d
 shr eax,1
 mov [rdi+4],eax
 mov eax,[r14+32]
 mov [rdi+8],eax
 mov eax,r9d
 sub eax,r8d
 shr eax,1
 mov [rdi+12],eax
 mov eax,[r14+36]
 mov [rdi+16],eax
 sub edx,r9d
 shr edx,1
 mov [rdi+20],edx
 mov dword [rdi+24],-1
 mov dword [rdi+28],0
 lea rdi,[r12+mp3p_work.is]
 xor eax,eax
 mov ecx,576/2
 rep stosq
 lea rdi,[r12+mp3p_work.aligned]
 mov esi,528
 lea rdx,[r12+mp3p_work.regions]
 mov ecx,[rsp+544]
 mov r8d,[r14+68]
 lea r9,[r12+mp3p_work.is]
 call mp3p_huffman_decode
 test eax,eax
 js mp3p_malformed
 ; Effective scalefactors/preflag in finite160B scratch (U is idle).
 mov eax,W(gr)
 shl eax,1
 add eax,W(ch)
 imul eax,160
 lea rsi,[r12+mp3p_work.sf+rax]
 lea rdi,[r12+mp3p_work.u]
 mov ecx,20
 rep movsq
 cmp dword [r14+20],2
 je .requant_short
 cmp dword [r14+60],0
 je .requant
 xor ecx,ecx
.pre:
 lea rdi,[r12+mp3p_work.u]
 lea rsi,[rel mp3p_pre]
 movzx eax,byte [rsi+rcx]
 add [rdi+rcx*4],eax
 inc ecx
 cmp ecx,22
 jb .pre
.requant:
 lea rdi,[r12+mp3p_work.is]
 mov eax,W(ch)
 imul eax,576*8
 lea rsi,[r12+mp3p_work.xr+rax]
 mov edx,[r14+8]
 lea rcx,[r12+mp3p_work.u]
 mov r8d,[r14+64]
 mov r9d,576
 mov r10,W(bands)
 call mp3p_requant_granule
 jmp .requant_done
.requant_short:
 call mp3p_short_layout           ; R9=longSF0/8,R10=widths40
 lea rdi,[r12+mp3p_work.is]
 mov eax,W(ch)
 imul eax,576*8
 lea rsi,[r12+mp3p_work.xr+rax]
 mov edx,[r14+8]
 lea rcx,[r12+mp3p_work.u]
 mov r8d,[r14+64]
 lea r11,[r14+48]                ; actual three window subblock gains
 call mp3p_requant_short
.requant_done:
 mov eax,W(part_end)
 mov W(main_bit),eax
 inc dword W(ch)
 mov eax,W(ch)
 cmp eax,[r12+mp3p_work.header+12]
 jb mp3p_progress
 ; Stereo reconstruction uses raw right SF and coded-order spectra, before
 ; either channel is reordered/filtered. Intensity tails exclude MS rotation.
 mov eax,[r12+mp3p_work.header+28]
 mov ecx,eax
 shr ecx,6
 and ecx,3
 cmp ecx,1
 jne .stereo_done
 test eax,0x10
 jz .ms_only
 call mp3p_intensity_stereo
 jmp .stereo_done
.ms_only:
 test eax,0x20
 jz .stereo_done
 lea rdi,[r12+mp3p_work.xr]
 lea rsi,[rdi+576*8]
 call mp3p_ms_stereo
.stereo_done:
 mov dword W(ch),0
 mov dword C(phase),MP3P_FILTER
 jmp mp3p_progress

mp3p_filter:
 call mp3p_record
 cmp dword [r14+20],2
 jne .alias_long
 call mp3p_short_layout
 mov rdx,r10
 mov ecx,r8d
 mov r8d,r9d
 mov r9d,ecx
 mov eax,W(ch)
 imul eax,576*8
 lea rdi,[r12+mp3p_work.xr+rax]
 lea rsi,[r12+mp3p_work.hybrid]
 call mp3p_reorder_short
 xor esi,esi                    ; pure short: no antialias
 cmp dword [r14+24],0
 je .alias
 mov esi,1                      ; mixed filter: two long SB, including8k
 jmp .alias
.alias_long:
 mov esi,31
.alias:
 mov eax,W(ch)
 imul eax,576*8
 lea rdi,[r12+mp3p_work.xr+rax]
 call mp3p_alias_reduce_bands
 mov eax,W(ch)
 imul eax,576*8
 lea rdi,[r12+mp3p_work.xr+rax]
 lea rsi,[r12+mp3p_work.hybrid]
 mov eax,W(ch)
 imul eax,12800
 lea rdx,[r12+MP3P_TEMP+rax]
 lea rcx,[r12+mp3p_work.tmp]
 mov r8d,[r14+20]
 xor r9d,r9d
 cmp r8d,2
 jne .hybrid
 cmp dword [r14+24],0
 je .hybrid
 mov r9d,2                      ; mixed filter: two long SB, including8k
.hybrid:
 call mp3p_hybrid_typed
 lea rdi,[r12+mp3p_work.hybrid]
 lea rsi,[r12+mp3p_work.synth]
 mov eax,W(ch)
 imul eax,12800
 lea rdx,[r12+MP3P_TEMP+576*8+rax]
 lea rcx,[r12+mp3p_work.u]
 call mp3p_synth_granule
 ; Independent per-channel history, interleaved complete1152-frame staging.
 mov eax,W(gr)
 imul eax,576
 mov edx,[r12+mp3p_work.header+12]
 imul eax,edx
 add eax,W(ch)
 lea rdi,[r12+mp3p_work.staging+rax*2]
 xor ecx,ecx
 lea rsi,[r12+mp3p_work.synth]
.cvt:
 movsd xmm0,[rsi+rcx*8]
 mulsd xmm0,[rel mp3p_scale]
 ucomisd xmm0,xmm0
 jp mp3p_malformed
 maxsd xmm0,[rel mp3p_min]
 minsd xmm0,[rel mp3p_max]
 cvttsd2si eax,xmm0
 mov [rdi],ax
 lea rdi,[rdi+rdx*2]
 inc ecx
 cmp ecx,576
 jb .cvt
 inc dword W(ch)
 mov eax,W(ch)
 cmp eax,[r12+mp3p_work.header+12]
 jb mp3p_progress
 mov dword W(ch),0
 inc dword W(gr)
 mov eax,W(gr)
 cmp eax,W(granules)
 jae .complete
 mov dword C(phase),MP3P_ENTROPY
 jmp mp3p_progress
.complete:
 mov dword C(phase),MP3P_COMMIT
 jmp mp3p_progress

mp3p_commit:
 ; No fallible operation remains. Persist only complete successfully decoded
 ; state and exact source consumption. PCM full frame copy before publication.
 mov rdi,C(pcm)
 lea rsi,[r12+mp3p_work.staging]
 mov eax,[r12+mp3p_work.header+12]
 imul eax,W(samples)
 shl eax,1
 mov ecx,eax
 rep movsb
 lea rdi,[r12+mp3p_work.history]
 lea rsi,[r12+MP3P_TEMP]
 mov ecx,25600/8
 rep movsq
 mov eax,W(main_bit)
 add eax,7
 shr eax,3
 mov ecx,W(md_bytes)
 sub ecx,eax
 cmp ecx,511
 jbe .reservoir_size
 mov eax,W(md_bytes)
 sub eax,511
 mov ecx,511
.reservoir_size:
 mov W(resv_len),ecx
 lea rsi,[r12+mp3p_work.main+rax]
 lea rdi,[r12+mp3p_work.reservoir]
 rep movsb
 mov rax,W(frame_end)
 mov C(offset),rax
 inc qword C(encoded_frames)
 mov eax,[r12+mp3p_work.header]
 mov C(rate),eax
 mov eax,[r12+mp3p_work.header+12]
 mov C(channels),eax
 imul eax,2
 mov C(input_frame),eax
 imul eax,W(samples)
 mov C(bytes),rax
 mov eax,W(samples)
 mov C(frames),rax
 mov qword C(cursor),0
 mov dword C(bits),16
 mov dword C(phase),MP3P_READY
mp3p_ready:
 mov eax,1
 jmp mp3p_exit
mp3p_done:
 mov eax,2
 jmp mp3p_exit
mp3p_progress:
 xor eax,eax
 jmp mp3p_exit

mp3p_take:
 cmp dword C(phase),MP3P_READY
 jne mp3p_fp_stale
 mov r15,[rsp+528]
 cmp r15,1152
 ja mp3p_fp_bad
 test r15,r15
 jz mp3p_progress
 mov rsi,[rsp+520]
 mov rdx,r15
 mov eax,C(input_frame)
 cmp eax,2
 je .frame
 cmp eax,4
 jne mp3p_fp_bad
.frame:
 imul rdx,rax
 mov [rsp+544],rdx
 call mp3p_span
 jc mp3p_fp_bad
 mov r8,C(src)
 mov r9,C(src_bytes)
 call mp3p_pair
 jc mp3p_fp_bad
 mov r8,C(pcm)
 mov r9,C(capacity)
 call mp3p_pair
 jc mp3p_fp_bad
 mov r8,C(workspace)
 mov r9,C(workspace_bytes)
 call mp3p_pair
 jc mp3p_fp_bad
 mov rax,C(bytes)
 cmp rax,4608
 ja mp3p_fp_bad
 mov rcx,C(cursor)
 cmp rcx,rax
 ja mp3p_fp_bad
 sub rax,rcx
 cmp rax,[rsp+544]
 cmova rax,[rsp+544]
 mov r15,rax
 mov rdi,[rsp+520]
 mov rsi,C(pcm)
 add rsi,rcx
 mov rcx,rax
 rep movsb
 add C(cursor),r15
 mov rax,r15
 xor edx,edx
 mov ecx,C(input_frame)
 div rcx
 mov r15,rax
 mov rax,C(cursor)
 cmp rax,C(bytes)
 jne .taken
 mov dword C(phase),MP3P_SCAN
 mov qword C(bytes),0
 mov qword C(frames),0
.taken:
 mov rax,r15
 jmp mp3p_exit

mp3p_cancel:
 mov dword C(phase),MP3P_CANCEL
 mov qword C(bytes),0
 mov qword C(frames),0
 mov qword C(cursor),0
 mov dword W(resv_len),0
 lea rdi,[r12+mp3p_work.history]
 xor eax,eax
 mov ecx,25600/8
 rep stosq
 jmp mp3p_done

; Current immutable rate-specific coded-order short/mixed width view.
; ReturnR10=widths40,R9d=long SF0/6/8,R8d=long exponent lines0/36/72.
mp3p_short_layout:
 cmp dword W(granules),2
 je .mpeg1
 xor r9d,r9d
 xor r8d,r8d
 lea r10,[rel mp3p_lsf_short]
 cmp dword [r14+24],0
 je .lsf_view
 mov r9d,6
 mov r8d,36
 cmp dword [r12+mp3p_work.header],8000
 jne .lsf_mixed
 mov r8d,72
.lsf_mixed:
 lea r10,[rel mp3p_lsf_mixed]
.lsf_view:
 mov eax,W(band_index)
 movsxd rax,[r10+rax*4]
 add r10,rax
 ret
.mpeg1:
 xor r9d,r9d
 xor r8d,r8d
 cmp dword [r14+24],0
 jne .mixed
 lea r10,[rel mp3p_widths_short_44100]
 cmp dword [r12+mp3p_work.header],44100
 je .done
 lea r10,[rel mp3p_widths_short_48000]
 cmp dword [r12+mp3p_work.header],48000
 je .done
 lea r10,[rel mp3p_widths_short_32000]
 ret
.mixed:
 mov r9d,8
 mov r8d,36
 lea r10,[rel mp3p_widths_mixed_44100]
 cmp dword [r12+mp3p_work.header],44100
 je .done
 lea r10,[rel mp3p_widths_mixed_48000]
 cmp dword [r12+mp3p_work.header],48000
 je .done
 lea r10,[rel mp3p_widths_mixed_32000]
.done:
 ret

; MPEG1/LSF intensity, traced to local CC0 L3_stereo_top_band/process.
; Final inheritance/mixed window edges corrected against FFmpeg; see provenance.
; Only called for joint stereo after both channel entropy turns. Widths total
; 576; <=39 SF bands. Reuse U scratch (dead after requant), never raw SF/history.
; Native requant has NO MS pre-scale: intensity uses plain pan coefficients;
; non-intensity bands alone use (M+S,M-S)/sqrt2. The CC0 sqrt2 on IS cancels
; its earlier MS pre-scale and must NOT be duplicated here.
mp3p_intensity_stereo:
 push rbx
 push rbp
 push r13
 push r14
 push r15
 sub rsp,16                     ; band count, long prefix, MS, top blocks
 mov eax,[r12+mp3p_work.header+28]
 and eax,0x20
 mov [rsp+8],eax
 mov eax,W(gr)
 shl eax,1
 imul eax,72
 lea r14,[r12+mp3p_work.si+rax]  ; left granule defines coded-order view
 lea rbp,[r12+mp3p_work.u]
 mov eax,W(gr)
 shl eax,1
 inc eax                         ; raw RIGHT positions, including gr1 scfsi
 imul eax,160
 lea rsi,[r12+mp3p_work.sf+rax]
 cmp dword W(granules),2
 je .positions
 lea rsi,[r12+mp3p_work.ist+rax]
.positions:
 mov rdi,rbp
 mov ecx,40
 rep movsd
 lea r13,[rbp+160]              ; three short-window maxima plus global/long maximum
 lea rdi,[rbp+192]              ; <=40 byte widths
 mov dword [rsp+12],1
 mov dword [rsp+4],22
 cmp dword [r14+20],2
 je .short
 mov rsi,W(bands)
 xor ecx,ecx
.long_width:
 mov eax,[rsi+rcx*4+4]
 sub eax,[rsi+rcx*4]
 mov [rdi+rcx],al
 inc ecx
 cmp ecx,22
 jb .long_width
 mov byte [rdi+22],0
 jmp .widths
.short:
 call mp3p_short_layout
 mov [rsp+4],r9d                ; pure short keeps three independent tails
 mov dword [rsp+12],3
 mov rsi,r10
 mov ecx,40
 rep movsb
.widths:
 lea r10,[rbp+192]
 mov dword [r13],-1
 mov dword [r13+4],-1
 mov dword [r13+8],-1
 mov dword [r13+12],-1
 lea rsi,[r12+mp3p_work.xr+576*8]
 xor r15d,r15d                  ; band
 xor ebx,ebx                    ; spectral offset
 xor r9d,r9d                    ; short-window modulo3; mixed prefix has8SF
 xorpd xmm7,xmm7
 cmp dword [rsp+4],8
 jne .top_band
 inc r9d
.top_band:
 movzx ecx,byte [r10+r15]
 test ecx,ecx
 jz .top_done
 xor edx,edx
.top_line:
 movsd xmm0,[rsi+rbx*8]
 ucomisd xmm0,xmm7
 jne .nonzero
 inc ebx
 inc edx
 cmp edx,ecx
 jb .top_line
 jmp .top_next
.nonzero:
 mov eax,3
 cmp r15d,[rsp+4]
 cmovge eax,r9d
 mov [r13+rax*4],r15d
 sub ecx,edx
 add ebx,ecx
.top_next:
 inc r9d
 cmp r9d,3
 jb .top_mod
 xor r9d,r9d
.top_mod:
 inc r15d
 jmp .top_band
.top_done:
 mov [rsp],r15d
 ; Any right short energy excludes intensity in the mixed long prefix,
 ; but MUST NOT collapse independent short-window tails into one maximum.
 mov eax,[r13+12]
 cmp eax,[r13]
 cmovl eax,[r13]
 cmp eax,[r13+4]
 cmovl eax,[r13+4]
 cmp eax,[r13+8]
 cmovl eax,[r13+8]
 mov [r13+12],eax
.implicit:
 xor r9d,r9d
 mov edx,[rsp]
 sub edx,[rsp+12]               ; first implicit last-band SF
.last_pos:
 mov ecx,edx
 sub ecx,[rsp+12]               ; previous band in this window
 ; MPEG1 final band inherits the previous position even if that band
 ; contains right energy. No invented position3 default.
 mov eax,[rbp+rcx*4]
.last_store:
 mov [rbp+rdx*4],eax
 inc edx
 inc r9d
 cmp r9d,[rsp+12]
 jb .last_pos
 lea rdi,[r12+mp3p_work.xr]
 lea rsi,[rdi+576*8]
 xor r15d,r15d
 xor r9d,r9d
 xor ebx,ebx
 cmp dword [rsp+4],8
 jne .band
 inc r9d
.band:
 movzx ecx,byte [r10+r15]
 mov eax,3
 cmp r15d,[rsp+4]
 cmovge eax,r9d
 cmp r15d,[r13+rax*4]
 jle .ms
 mov eax,[rbp+r15*4]
 cmp dword W(granules),2
 jne .lsf_pan
 cmp eax,7                      ; positions7..15 mean no intensity
 jae .ms
 shl eax,4
 lea rdx,[rel mp3p_intensity_pan]
 movsd xmm2,[rdx+rax]
 movsd xmm3,[rdx+rax+8]
 jmp .intensity_line
.lsf_pan:
 cmp eax,64                     ; -1 sentinel for all-ones SF partition
 jae .ms
 mov ecx,[r12+mp3p_work.si+72+12]
 and ecx,1                      ; intensity_scale (sfc low bit), not SF scale
 mov edx,eax
 inc eax
 shr eax,1
 shl eax,cl
 lea rcx,[rel mp3p_lsf_pan]
 movsd xmm2,[rcx]               ;1
 movsd xmm3,[rcx+rax*8]
 test edx,1
 jz .lsf_pan_even
 movapd xmm2,xmm3
 movsd xmm3,[rcx]
.lsf_pan_even:
 movzx ecx,byte [r10+r15]
.intensity_line:
 movsd xmm0,[rdi+rbx*8]
 movapd xmm1,xmm0
 mulsd xmm0,xmm2
 mulsd xmm1,xmm3
 movsd [rdi+rbx*8],xmm0
 movsd [rsi+rbx*8],xmm1
 inc ebx
 dec ecx
 jnz .intensity_line
 jmp .next_band
.ms:
 cmp dword [rsp+8],0
 je .skip
.ms_line:
 movsd xmm0,[rdi+rbx*8]
 movsd xmm1,[rsi+rbx*8]
 movapd xmm2,xmm0
 addsd xmm0,xmm1
 subsd xmm2,xmm1
 mulsd xmm0,[rel mp3p_ms_inv_sqrt2]
 mulsd xmm2,[rel mp3p_ms_inv_sqrt2]
 movsd [rdi+rbx*8],xmm0
 movsd [rsi+rbx*8],xmm2
 inc ebx
 dec ecx
 jnz .ms_line
 jmp .next_band
.skip:
 add ebx,ecx
.next_band:
 inc r9d
 cmp r9d,3
 jb .mod
 xor r9d,r9d
.mod:
 inc r15d
 cmp r15d,[rsp]
 jb .band
 add rsp,16
 pop r15
 pop r14
 pop r13
 pop rbp
 pop rbx
 ret

; LSF scalefactor decomposition from retained CC0 radix/partition facts.
; No scfsi in LSF. IS keeps partition all-ones sentinel separately from raw SF,
; so requantization never receives the sentinel and zero-width groups mean pos0.
mp3p_lsf_scalefactors:
 push rbp
 push r13
 push r15
 mov eax,[r14+12]
 xor r13d,r13d                  ; radix class0..5
 mov dword [r14+60],0
 mov edx,[r12+mp3p_work.header+28]
 and edx,0xd0
 cmp edx,0x50                   ; joint mode1 plus intensity
 jne .normal
 cmp dword W(ch),1
 jne .normal
 shr eax,1
 mov r13d,3
 jmp .class
.normal:
 cmp eax,500
 jb .class
 mov dword [r14+60],1            ; inferred preflag only ordinary LSF channel
.class:
 lea rdi,[rel mp3p_lsf_radices]
 mov ecx,r13d
 shl ecx,2
 add rdi,rcx
 movzx ecx,byte [rdi]
 movzx edx,byte [rdi+1]
 imul ecx,edx
 movzx edx,byte [rdi+2]
 imul ecx,edx
 movzx edx,byte [rdi+3]
 imul ecx,edx
 cmp eax,ecx
 jb .decompose
 sub eax,ecx
 inc r13d
 jmp .class
.decompose:
 mov ebp,3
.digit:
 movzx ecx,byte [rdi+rbp]
 xor edx,edx
 div ecx
 mov [r12+mp3p_work.slen+rbp*4],edx
 dec ebp
 jns .digit
 lea rdi,[rel mp3p_lsf_partition_0]
 cmp dword [r14+20],2
 jne .counts
 lea rdi,[rel mp3p_lsf_partition_2]
 cmp dword [r14+24],0
 je .counts
 lea rdi,[rel mp3p_lsf_partition_1]
.counts:
 lea rdi,[rdi+r13*4]
 xor ebp,ebp
 xor r15d,r15d                  ; SF index0..35
.group:
 movzx r13d,byte [rdi+rbp]
 mov [r12+mp3p_work.partition+rbp*4],r13d
 push rdi
.sf:
 test r13d,r13d
 jz .next
 mov esi,[r12+mp3p_work.slen+rbp*4]
 xor edx,edx
 test esi,esi
 jz .store
 mov eax,[r12+mp3p_work.reader+16]
 add eax,esi
 cmp eax,W(part_end)
 ja .bad_pop
 call mp3p_read
 jc .bad_pop
.store:
 mov eax,W(ch)
 imul eax,160
 lea rsi,[r12+mp3p_work.sf+rax]
 mov [rsi+r15*4],edx
 lea rsi,[r12+mp3p_work.ist+rax]
 mov ecx,[r12+mp3p_work.slen+rbp*4]
 test ecx,ecx
 jz .position
 mov eax,1
 shl eax,cl
 dec eax
 cmp eax,edx
 jne .position
 mov edx,-1
.position:
 mov [rsi+r15*4],edx
 inc r15d
 dec r13d
 jmp .sf
.next:
 pop rdi
 inc ebp
 cmp ebp,4
 jb .group
 pop r15
 pop r13
 pop rbp
 clc
 ret
.bad_pop:
 pop rdi
 pop r15
 pop r13
 pop rbp
 stc
 ret

mp3p_record:
 mov eax,W(gr)
 shl eax,1
 add eax,W(ch)
 ; Mono record storage is dense: gr0 at0, gr1 at72.
 cmp dword [r12+mp3p_work.header+12],1
 jne .index
 mov eax,W(gr)
.index:
 imul eax,72
 lea r14,[r12+mp3p_work.si+rax]
 ret
mp3p_read:
 push rdi
 lea rdi,[r12+mp3p_work.reader]
 call media_mp3_bits_read
 pop rdi
 test rax,rax
 jnz .bad
 clc
 ret
.bad:
 stc
 ret

; Trusted mapping required; all ranges nonempty/lower canonical/nonwrapping
; and disjoint from full producer context and prospective active stack.
mp3p_span:
 test rsi,rsi
 jz .bad
 test rdx,rdx
 jz .bad
 mov rax,rsi
 add rax,rdx
 jc .bad
 mov rcx,rax
 dec rcx
 shr rcx,47
 jnz .bad
 lea rcx,[rbx+mp3p_ctx_size]
 cmp rsi,rcx
 jae .stack
 cmp rbx,rax
 jb .bad
.stack:
 lea rcx,[rsp+640]               ;conservative original entry+return interval
 cmp rsi,rcx
 jae .ok
 lea rcx,[rsp-2048]
 cmp rax,rcx
 ja .bad
.ok:
 clc
 ret
.bad:
 stc
 ret
mp3p_pair:
 lea rax,[rsi+rdx]
 cmp r8,rax
 jae .ok
 lea rax,[r8+r9]
 cmp rsi,rax
 jb .bad
.ok:
 clc
 ret
.bad:
 stc
 ret

mp3p_malformed:
 mov eax,-1
 jmp mp3p_fail
mp3p_unsupported:
 mov eax,-2
 jmp mp3p_fail
mp3p_frame_quota:
 mov eax,-4
 jmp mp3p_fail
mp3p_reservoir:
 mov eax,-5
mp3p_fail:
 mov W(error),eax
 mov dword C(phase),MP3P_FAILED
 mov qword C(bytes),0
 mov qword C(frames),0
 mov qword C(cursor),0
 movsxd rax,eax
 jmp mp3p_exit
mp3p_fp_bad:
 mov rax,-1
 jmp mp3p_exit
mp3p_fp_stale:
 mov rax,-2
mp3p_exit:
 cmp dword [rsp+552],1
 jne .restore
 mov [rsp+560],rax
 lea rdi,[r12+mp3p_work.public]
 mov rsi,rbx
 mov ecx,24
 rep movsq
 mov rax,[rsp+560]
.restore:
 fxrstor [rsp]
 jmp mp3p_pop
mp3p_bad:
 mov rax,-1
 jmp mp3p_pop
mp3p_capacity:
 mov rax,-3
 jmp mp3p_pop
mp3p_quota:
 mov rax,-4
mp3p_pop:
 add rsp,568
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
mp3p_leaf_bad:
 mov rax,-1
 ret
mp3p_leaf_stale:
 mov rax,-2
 ret
; tan(pos*pi/12)/(1+tan), 0..6, symmetric exact MPEG1 pan.
mp3p_intensity_pan: dq 0.0,1.0,0.21132486540518713,0.7886751345948129,0.36602540378443865,0.6339745962155614,0.5,0.5,0.6339745962155614,0.36602540378443865,0.7886751345948129,0.21132486540518713,1.0,0.0
mp3p_ms_inv_sqrt2: dq 0.7071067811865475244
mp3p_scale: dq 16384.0 ; Classic window/IMDCT normalization corrected against independent decoder
mp3p_min: dq -32768.0
mp3p_max: dq 32767.0
%undef C
%undef W
%unmacro MP3P_FIELD 2
%include "media/mp3_tables.inc"

%unmacro MP3P_LEAF_SPAN 2
