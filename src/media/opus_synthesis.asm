;; MODULE media/opus_synthesis
;; LAYER 4
;; EXPORTS media_opus_synthesis
;; IMPORTS media_opus_denormalise_bands media_opus_imdct media_opus_postfilter media_opus_deemphasis
;; CAPS
;; OWNER rc-codex-av
;
; Standard48k fixed-point Opus1.5.2 celt_synthesis and normal decoded-frame
; history/filter/deemphasis composition. UNWIRED, not a packet decoder.
; RDI=readonly config160*:20 full64 fields documented in OPUS_NATIVE_SYNTHESIS.
; State64 header +CC*2168 i32 history. All5 full spans pairwise disjoint.
; Private complete state/PCM transaction: downstream refusal publishes nothing.
; Exact history shift, channel mapping, transient stride, overlap and clipping.
; No globals/allocator/FP/entropy/devices/runtime. SysV preserved,DF clear.
; Private41208 +48 saved bytes; nested helpers require <51KiB total stack.
; Source archive SHA25665c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1.
; Retain LICENSES/XIPH_OPUS_SYNTHESIS.txt and underlying helper licenses.
;
; celt_decoder.c
; /* Copyright (c) 2007-2008 CSIRO
;    Copyright (c) 2007-2010 Xiph.Org Foundation
;    Copyright (c) 2008 Gregory Maxwell
;    Written by Jean-Marc Valin and Gregory Maxwell */
; /*
;    Redistribution and use in source and binary forms, with or without
;    modification, are permitted provided that the following conditions
;    are met:
;
;    - Redistributions of source code must retain the above copyright
;    notice, this list of conditions and the following disclaimer.
;
;    - Redistributions in binary form must reproduce the above copyright
;    notice, this list of conditions and the following disclaimer in the
;    documentation and/or other materials provided with the distribution.
;
;    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;    ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
;    OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
;    EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
;    PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
;    PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
;    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
; */
;

; Private layout. Symbols are module-prefixed for flat composition.
mosy_freq equ 17408               ; two separately denormalised spectra
mosy_scratch equ 25088
mosy_planar equ 28928             ; contiguous postfiltered deemphasis input
mosy_pcm equ 36608
mosy_cfg equ 40448                ; immutable config snapshot
mosy_spans equ 40608              ; five [start,end) full spans
mosy_helper equ 40688             ; largest helper config104
mosy_v equ 40800                  ; M,B,NB,shift,PCMcount,statebytes,outoffset

; Nonempty lower canonical span, full64 length. RDX alignment mask.
mosy_span:
 test rdi,rdi
 jz .bad
 test rdi,rdx
 jnz .bad
 mov rax,rdi
 add rax,rsi
 jc .bad
 mov r9,rax
 dec r9
 shr r9,47
 jnz .bad
 mov [r8],rdi
 mov [r8+8],rax
 xor eax,eax
 ret
.bad:
 mov rax,-1
 ret

media_opus_synthesis:
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,41208
 mov r12,rsp
 mov r13,rdi
 mov esi,160
 mov edx,7
 lea r8,[r12+mosy_spans]
 call mosy_span
 test rax,rax
 jnz .bad
 mov rsi,r13
 lea rdi,[r12+mosy_cfg]
 mov ecx,20
 rep movsq
 ; Full-width scalar controls, before input/state effects.
 mov rcx,[r12+mosy_cfg]
 cmp rcx,3
 ja .bad
 mov ebx,120
 shl rbx,cl                      ; N=120<<LM
 mov eax,1
 shl rax,cl
 mov [r12+mosy_v],rax
 mov rax,[r12+mosy_cfg+8]
 cmp rax,21
 ja .bad
 mov rcx,[r12+mosy_cfg+16]
 cmp rcx,21
 ja .bad
 cmp rax,rcx
 ja .bad
 mov rax,[r12+mosy_cfg+24]
 dec rax
 cmp rax,1
 ja .bad
 mov rax,[r12+mosy_cfg+32]
 dec rax
 cmp rax,1
 ja .bad
 cmp qword [r12+mosy_cfg+40],1
 ja .bad
 cmp qword [r12+mosy_cfg+56],1
 ja .bad
 cmp qword [r12+mosy_cfg+64],1
 ja .bad
 mov rcx,[r12+mosy_cfg+48]
 cmp rcx,1
 je .ds
 cmp rcx,2
 je .ds
 cmp rcx,3
 je .ds
 cmp rcx,4
 je .ds
 cmp rcx,6
 jne .bad
.ds:
 mov rax,rbx
 xor edx,edx
 div rcx                         ; all admitted factors divide120
 imul rax,[r12+mosy_cfg+32]
 mov [r12+mosy_v+32],rax
 cmp qword [r12+mosy_cfg+72],1024
 ja .bad
 mov rax,[r12+mosy_cfg+80]
 add rax,32768
 cmp rax,65535
 ja .bad
 cmp qword [r12+mosy_cfg+88],2
 ja .bad
 ; Input fullC*N, energy fullC*21. Full declared capacities validated.
 mov rdi,[r12+mosy_cfg+96]
 mov rsi,[r12+mosy_cfg+104]
 mov rax,rbx
 imul rax,[r12+mosy_cfg+24]
 add rax,rax
 cmp rsi,rax
 jb .bad
 mov edx,1
 lea r8,[r12+mosy_spans+16]
 call mosy_span
 test rax,rax
 jnz .bad
 mov rdi,[r12+mosy_cfg+112]
 mov rsi,[r12+mosy_cfg+120]
 imul rax,[r12+mosy_cfg+24],42
 cmp rsi,rax
 jb .bad
 mov edx,1
 lea r8,[r12+mosy_spans+32]
 call mosy_span
 test rax,rax
 jnz .bad
 imul rax,[r12+mosy_cfg+32],8672
 add rax,64
 mov [r12+mosy_v+40],rax
 mov rdi,[r12+mosy_cfg+128]
 mov rsi,[r12+mosy_cfg+136]
 cmp rsi,rax
 jb .bad
 mov edx,7
 lea r8,[r12+mosy_spans+48]
 call mosy_span
 test rax,rax
 jnz .bad
 mov rdi,[r12+mosy_cfg+144]
 mov rsi,[r12+mosy_cfg+152]
 mov rax,[r12+mosy_v+32]
 add rax,rax
 cmp rsi,rax
 jb .bad
 mov edx,1
 lea r8,[r12+mosy_spans+64]
 call mosy_span
 test rax,rax
 jnz .bad
 xor r13d,r13d
.outer:
 lea r8,[r13+1]
 mov rax,r13
 shl rax,4
 lea r9,[r12+mosy_spans+rax]
.inner:
 cmp r8,5
 jae .next_outer
 mov rax,r8
 shl rax,4
 lea r10,[r12+mosy_spans+rax]
 mov rax,[r9]
 cmp rax,[r10+8]
 jae .next_pair
 mov rax,[r10]
 cmp rax,[r9+8]
 jb .bad
.next_pair:
 inc r8
 jmp .inner
.next_outer:
 inc r13
 cmp r13,5
 jb .outer
 ; State controls are full-width; channel count is fixed across a stream.
 mov r13,[r12+mosy_cfg+128]
 mov rax,[r13]
 cmp rax,[r12+mosy_cfg+32]
 jne .bad
 cmp qword [r13+8],1024
 ja .bad
 cmp qword [r13+16],1024
 ja .bad
 mov rax,[r13+24]
 add rax,32768
 cmp rax,65535
 ja .bad
 mov rax,[r13+32]
 add rax,32768
 cmp rax,65535
 ja .bad
 cmp qword [r13+40],2
 ja .bad
 cmp qword [r13+48],2
 ja .bad
 ; All further work is private; late helper admission still preserves caller.
 mov rsi,r13
 mov rdi,r12
 mov rcx,[r12+mosy_v+40]
 shr rcx,3
 rep movsq
 mov rsi,[r12+mosy_cfg+144]
 lea rdi,[r12+mosy_pcm]
 mov rcx,[r12+mosy_v+32]
 rep movsw                       ; initial PCM needed for accum only
 xor r14d,r14d
.shift_history:
 imul rax,r14,8672
 lea rdi,[r12+64+rax]
 lea rsi,[rdi+rbx*4]
 mov ecx,2168
 sub rcx,rbx
 rep movsd                       ; OPUS_MOVE(decode_mem,decode_mem+N,...)
 inc r14
 cmp r14,[r12+mosy_cfg+32]
 jb .shift_history
 ; One denormalisation per coded channel. Helpers use minimal subspans;
 ; the enclosing caller spans, including all tails, were validated above.
 xor r14d,r14d
.denorm_channel:
 lea rdi,[r12+mosy_helper]
 mov rax,[r12+mosy_cfg]
 mov [rdi],rax
 mov rax,[r12+mosy_cfg+8]
 mov [rdi+8],rax
 mov rax,[r12+mosy_cfg+16]
 mov [rdi+16],rax
 mov rax,[r12+mosy_cfg+48]
 mov [rdi+24],rax
 mov rax,[r12+mosy_cfg+56]
 mov [rdi+32],rax
 mov rax,r14
 imul rax,rbx
 lea rax,[rax*2]
 add rax,[r12+mosy_cfg+96]
 mov [rdi+40],rax
 imul rax,r14,42
 add rax,[r12+mosy_cfg+112]
 mov [rdi+48],rax
 imul rax,r14,3840
 lea rax,[r12+mosy_freq+rax]
 mov [rdi+56],rax
 lea rax,[rbx*2]
 mov [rdi+64],rax
 mov qword [rdi+72],42
 lea rax,[rbx*4]
 mov [rdi+80],rax
 lea rdx,[r12+mosy_scratch]
 mov [rdi+88],rdx
 mov [rdi+96],rax
 call media_opus_denormalise_bands
 test rax,rax
 jnz .bad
 inc r14
 cmp r14,[r12+mosy_cfg+24]
 jb .denorm_channel
 cmp qword [r12+mosy_cfg+24],2
 jne .geometry
 cmp qword [r12+mosy_cfg+32],1
 jne .geometry
 xor ecx,ecx
.downmix:
 mov eax,[r12+mosy_freq+rcx*4]
 sar eax,1                       ; HALF32 separately, before addition
 mov edx,[r12+mosy_freq+3840+rcx*4]
 sar edx,1
 add eax,edx
 mov [r12+mosy_freq+rcx*4],eax
 inc rcx
 cmp rcx,rbx
 jb .downmix
.geometry:
 mov qword [r12+mosy_v+8],1       ; B=1,NB=N,shift=3-LM
 mov [r12+mosy_v+16],rbx
 mov eax,3
 sub rax,[r12+mosy_cfg]
 mov [r12+mosy_v+24],rax
 cmp qword [r12+mosy_cfg+40],0
 je .geometry_done
 mov rax,[r12+mosy_v]
 mov [r12+mosy_v+8],rax           ; transient B=M,NB=120,shift=3
 mov qword [r12+mosy_v+16],120
 mov qword [r12+mosy_v+24],3
.geometry_done:
 mov eax,2048
 sub rax,rbx
 shl rax,2
 mov [r12+mosy_v+48],rax
 xor r14d,r14d
.transform_channel:
 imul rbp,r14,8672
 add rbp,r12
 add rbp,64
 add rbp,[r12+mosy_v+48]          ; out_syn[c]
 xor r15d,r15d
.block:
 xor eax,eax
 cmp qword [r12+mosy_cfg+24],1
 je .freq_selected
 cmp qword [r12+mosy_cfg+32],1
 je .freq_selected
 imul rax,r14,3840
.freq_selected:
 lea rax,[r12+mosy_freq+rax]
 lea rax,[rax+r15*4]
 lea rdi,[r12+mosy_helper]
 mov [rdi],rax
 mov rax,rbx
 sub rax,r15
 shl rax,2
 mov [rdi+8],rax
 mov rax,r15
 imul rax,[r12+mosy_v+16]
 lea rax,[rbp+rax*4]
 mov [rdi+16],rax
 mov rax,[r12+mosy_v+16]
 add rax,60
 shl rax,2
 mov [rdi+24],rax
 mov rax,[r12+mosy_v+24]
 mov [rdi+32],rax
 mov rax,[r12+mosy_v+8]
 mov [rdi+40],rax
 call media_opus_imdct
 test rax,rax
 jnz .bad
 inc r15
 cmp r15,[r12+mosy_v+8]
 jb .block
 xor ecx,ecx
.clip:
 mov eax,[rbp+rcx*4]
 mov edx,300000000
 cmp eax,edx
 cmovg eax,edx
 mov edx,-300000000
 cmp eax,edx
 cmovl eax,edx
 mov [rbp+rcx*4],eax
 inc rcx
 cmp rcx,rbx
 jb .clip                        ; raw overlap tail deliberately unclipped
 inc r14
 cmp r14,[r12+mosy_cfg+32]
 jb .transform_channel
 ; Upstream clamps retained periods before applying the old/current filter.
 mov eax,15
 cmp [r12+8],rax
 cmovae rax,[r12+8]
 mov [r12+8],rax
 mov eax,15
 cmp [r12+16],rax
 cmovae rax,[r12+16]
 mov [r12+16],rax
 xor r14d,r14d
.filter_channel:
 imul rbp,r14,8672
 add rbp,r12
 add rbp,64
 add rbp,[r12+mosy_v+48]
 ; Use exactly max(15,T0,T1)+2 preceding samples for each real helper.
 lea rdi,[r12+mosy_helper]
 mov qword [rdi+24],120
 mov rax,[r12+16]
 mov [rdi+32],rax
 mov rax,[r12+8]
 mov [rdi+40],rax
 mov rax,[r12+32]
 mov [rdi+48],rax
 mov rax,[r12+24]
 mov [rdi+56],rax
 mov rax,[r12+48]
 mov [rdi+64],rax
 mov rax,[r12+40]
 mov [rdi+72],rax
 mov qword [rdi+80],120
 mov rsi,rbp
 call .postfilter
 test rax,rax
 jnz .bad
 cmp qword [r12+mosy_cfg],0
 je .filtered
 lea rdi,[r12+mosy_helper]
 mov rax,rbx
 sub rax,120
 mov [rdi+24],rax
 mov rax,[r12+8]
 mov [rdi+32],rax
 mov rax,[r12+mosy_cfg+72]
 mov [rdi+40],rax
 mov rax,[r12+24]
 mov [rdi+48],rax
 mov rax,[r12+mosy_cfg+80]
 mov [rdi+56],rax
 mov rax,[r12+40]
 mov [rdi+64],rax
 mov rax,[r12+mosy_cfg+88]
 mov [rdi+72],rax
 lea rsi,[rbp+480]
 call .postfilter
 test rax,rax
 jnz .bad
.filtered:
 mov rsi,rbp
 mov rax,r14
 imul rax,rbx
 lea rdi,[r12+mosy_planar+rax*4]
 mov rcx,rbx
 rep movsd
 inc r14
 cmp r14,[r12+mosy_cfg+32]
 jb .filter_channel
 ; Persistent postfilter controls: LM0 delays the newly decoded filter;
 ; LM>0 finishes its second transition inside this frame.
 mov rax,[r12+8]
 mov [r12+16],rax
 mov rax,[r12+24]
 mov [r12+32],rax
 mov rax,[r12+40]
 mov [r12+48],rax
 mov rax,[r12+mosy_cfg+72]
 mov [r12+8],rax
 mov rax,[r12+mosy_cfg+80]
 mov [r12+24],rax
 mov rax,[r12+mosy_cfg+88]
 mov [r12+40],rax
 cmp qword [r12+mosy_cfg],0
 je .deemphasis
 mov rax,[r12+8]
 mov [r12+16],rax
 mov rax,[r12+24]
 mov [r12+32],rax
 mov rax,[r12+40]
 mov [r12+48],rax
.deemphasis:
 lea rdi,[r12+mosy_helper]
 mov [rdi],rbx
 mov rax,[r12+mosy_cfg+32]
 mov [rdi+8],rax
 mov rax,[r12+mosy_cfg+48]
 mov [rdi+16],rax
 mov rax,[r12+mosy_cfg+64]
 mov [rdi+24],rax
 lea rax,[r12+mosy_planar]
 mov [rdi+32],rax
 mov rax,rbx
 imul rax,[r12+mosy_cfg+32]
 shl rax,2
 mov [rdi+40],rax
 lea rax,[r12+mosy_pcm]
 mov [rdi+48],rax
 mov rax,[r12+mosy_v+32]
 add rax,rax
 mov [rdi+56],rax
 lea rax,[r12+56]
 mov [rdi+64],rax
 mov rax,[r12+mosy_cfg+32]
 shl rax,2
 mov [rdi+72],rax
 call media_opus_deemphasis
 test rax,rax
 jnz .bad
 ; The only writes to caller storage: complete success, exact used extents.
 mov rsi,r12
 mov rdi,[r12+mosy_cfg+128]
 mov rcx,[r12+mosy_v+40]
 shr rcx,3
 rep movsq
 lea rsi,[r12+mosy_pcm]
 mov rdi,[r12+mosy_cfg+144]
 mov rcx,[r12+mosy_v+32]
 rep movsw
 xor eax,eax
 jmp .done
.bad:
 mov rax,-1
.done:
 cld
 add rsp,41208
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; RDI=config88,RSI=current signal. Derive the smallest helper history that
; covers both clamped lags and +/-2 taps. Tail-call preserves call alignment.
.postfilter:
 mov eax,15
 cmp rax,[rdi+32]
 cmovb rax,[rdi+32]
 cmp rax,[rdi+40]
 cmovb rax,[rdi+40]
 add rax,2
 mov [rdi+16],rax
 mov rcx,rax
 shl rcx,2
 sub rsi,rcx
 mov [rdi],rsi
 add rax,[rdi+24]
 shl rax,2
 mov [rdi+8],rax
 jmp media_opus_postfilter
