;; MODULE media/opus_frame
;; LAYER 4
;; EXPORTS media_opus_frame_decode
;; IMPORTS media_opus_packet_parse, media_opus_range_init, media_opus_range_bit, media_opus_range_bits, media_opus_range_uint, media_opus_range_icdf, media_opus_range_tell, media_opus_range_tell_frac, media_opus_celt_energy, media_opus_tf_decode, media_opus_rate_cap, media_opus_celt_allocation_decode, media_opus_multiband_decode, media_opus_anti_collapse, media_opus_synthesis
;; CAPS
;; OWNER rc-codex-av
;
; Native standard48k CELT-only normal compressed-frame -> PCM transaction.
; RDI=readonly config80*, returns samples/channel or -1, DF0, SysV preserved.
; Ten full qwords: packet,packet_bytes,state,state_bytes,PCM,PCM_bytes,
; output_channels1/2,downsample1/2/3/4/6,accum0/1,frame_index.
; Actual packet parser supplies coded channels, LM, bandwidth and frame span.
; State: magic qword0x31465243, uint32 rng in qword8, then four i16[42]
; arrays at16/100/184/268: oldBandE,oldLogE,oldLogE2,backgroundLogE;
; reserved352..383 zero; native synthesis state at384. Size448+8672*CC.
; Initial state zero except magic, oldLogE/oldLogE2=-28672, synth.CC.
; All four full declared spans mutually disjoint, lower canonical, stable,
; truthfully mapped; config/state align8,PCM align2. Caller serializes.
; Any refusal preserves all caller bytes. Success publishes only minimal state
; and exact interleaved PCM, capacity tails untouched. See OPUS_NATIVE_FRAME.md.
; No PLC/FEC/SILK/hybrid/container/device/runtime/metal claim, no allocator/FP.
;
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
mofr_cfg equ 0
mofr_spans equ 80
mofr_parse equ 144
mofr_range equ 560
mofr_ecfg equ 624
mofr_tfcfg equ 688
mofr_acfg equ 752
mofr_mcfg equ 848
mofr_scfg equ 1040
mofr_ccfg equ 1200
mofr_meta equ 1352
mofr_v equ 1392
mofr_offs equ 1600
mofr_tf equ 1688
mofr_alloc equ 1776
mofr_masks equ 2064
mofr_x equ 2112
mofr_scratch equ 5952
mofr_pcm equ 9792
mofr_state equ 13632
mofr_span:
 test rdi,rdi
 jz .bad
 test rsi,rsi
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
media_opus_frame_decode:
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,31432
 mov r12,rsp
 mov r13,rdi
 mov esi,80
 mov edx,7
 lea r8,[r12+mofr_spans]
 call mofr_span
 test rax,rax
 jnz .bad
 lea rdi,[r12+mofr_v]
 xor eax,eax
 mov ecx,26
 rep stosq
 mov rsi,r13
 mov rdi,r12
 mov ecx,10
 rep movsq
 mov rax,[r12+48]
 dec rax
 cmp rax,1
 ja .bad
 mov rcx,[r12+56]
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
 cmp qword [r12+64],1
 ja .bad
 cmp qword [r12+8],65536
 ja .bad
 mov rdi,[r12]
 mov rsi,[r12+8]
 xor edx,edx
 lea r8,[r12+mofr_spans+16]
 call mofr_span
 test rax,rax
 jnz .bad
 imul rax,[r12+48],8672
 add rax,448
 mov [r12+mofr_v+48],rax
 mov rdi,[r12+16]
 mov rsi,[r12+24]
 cmp rsi,rax
 jb .bad
 mov edx,7
 lea r8,[r12+mofr_spans+32]
 call mofr_span
 test rax,rax
 jnz .bad
 mov rdi,[r12+32]
 mov rsi,[r12+40]
 mov edx,1
 lea r8,[r12+mofr_spans+48]
 call mofr_span
 test rax,rax
 jnz .bad
 xor ebx,ebx
.outer:
 lea ebp,[rbx+1]
 mov eax,ebx
 shl eax,4
 lea r10,[r12+mofr_spans+rax]
.inner:
 cmp ebp,4
 jae .next_outer
 mov eax,ebp
 shl eax,4
 lea r11,[r12+mofr_spans+rax]
 mov rax,[r10]
 cmp rax,[r11+8]
 jae .next_pair
 mov rax,[r11]
 cmp rax,[r10+8]
 jb .bad
.next_pair:
 inc ebp
 jmp .inner
.next_outer:
 inc ebx
 cmp ebx,4
 jb .outer
 mov rdi,[r12]
 mov rsi,[r12+8]
 lea rdx,[r12+mofr_parse]
 call media_opus_packet_parse
 test rax,rax
 jnz .bad
 mov eax,[r12+mofr_parse]
 test eax,128
 jz .bad                        ; no SILK or hybrid
 mov ebx,eax
 shr eax,3
 and eax,3
 mov [r12+mofr_v],rax            ; LM
 mov ecx,eax
 mov eax,120
 shl eax,cl
 mov [r12+mofr_v+8],rax          ; N
 xor edx,edx
 div qword [r12+56]
 mov [r12+mofr_v+16],rax         ; returned samples/channel
 imul rax,[r12+48]
 add rax,rax
 mov [r12+mofr_v+24],rax         ; PCM bytes
 cmp [r12+40],rax
 jb .bad
 shr ebx,5
 and ebx,3
 lea rax,[rel mofr_ends]
 movzx eax,byte [rax+rbx]
 mov [r12+mofr_v+32],rax         ; end
 mov eax,[r12+mofr_parse+4]
 mov [r12+mofr_v+40],rax         ; coded channels
 mov rax,[r12+72]
 mov edx,[r12+mofr_parse+8]
 cmp rax,rdx
 jae .bad
 mov edx,[r12+mofr_parse+32+rax*8+4]
 cmp edx,2
 jb .bad                        ; <=1 is upstream PLC, outside this entry
 mov [r12+mofr_v+56],rdx         ; real frame length
 mov esi,[r12+mofr_parse+32+rax*8]
 add rsi,[r12]
 lea rdi,[r12+mofr_range]
 call media_opus_range_init
 test rax,rax
 jnz .bad
 mov rsi,[r12+16]
 mov eax,0x31465243
 cmp [rsi],rax
 jne .bad
 mov eax,0xffffffff
 cmp [rsi+8],rax
 ja .bad
 mov rax,[r12+48]
 cmp [rsi+384],rax
 jne .bad
 mov rax,[rsi+352]
 or rax,[rsi+360]
 or rax,[rsi+368]
 or rax,[rsi+376]
 jnz .bad
 lea rdi,[r12+mofr_state]
 mov rcx,[r12+mofr_v+48]
 shr rcx,3
 rep movsq
 ; Initialize all internal outputs/config records. Entire X and masks zero.
 lea rdi,[r12+mofr_ecfg]
 xor eax,eax
 mov ecx,(mofr_v-mofr_ecfg)/8
 rep stosq
 lea rdi,[r12+mofr_offs]
 mov ecx,(mofr_state-mofr_offs)/8
 rep stosq
 ; Range is before the cleared region; state is after it.
 cmp qword [r12+mofr_v+40],1
 jne .flags
 xor ebx,ebx
.mono_energy:
 movsx eax,word [r12+mofr_state+16+rbx*2]
 movsx edx,word [r12+mofr_state+58+rbx*2]
 cmp eax,edx
 cmovl eax,edx
 mov [r12+mofr_state+16+rbx*2],ax
 inc ebx
 cmp ebx,21
 jb .mono_energy
.flags:
 ; Initialized entropy tell is exactly1 for a real >=2-byte frame.
 lea rdi,[r12+mofr_range]
 mov esi,15
 call media_opus_range_bit
 cmp rax,-1
 je .bad
 mov [r12+mofr_v+64],rax         ; silence
 test eax,eax
 jz .normal
 ; Upstream forces accounting to len*8; the later no-budget stages cannot
 ; change final range, and their spectral/energy result is discarded by silence.
 lea rdi,[r12+mofr_range]
 call media_opus_range_tell
 mov rcx,[r12+mofr_v+56]
 shl ecx,3
 sub ecx,eax
 add [r12+mofr_range+32],ecx
 xor ebx,ebx
.silent_energy:
 mov word [r12+mofr_state+16+rbx*2],-28672
 inc ebx
 imul eax,[r12+mofr_v+40],21
 cmp ebx,eax
 jb .silent_energy
 jmp .synthesize
.normal:
 lea rdi,[r12+mofr_range]
 call media_opus_range_tell
 mov rcx,[r12+mofr_v+56]
 shl ecx,3
 mov [r12+mofr_v+72],rcx         ; physical total bits
 add eax,16
 cmp eax,ecx
 ja .transient
 lea rdi,[r12+mofr_range]
 mov esi,1
 call media_opus_range_bit
 cmp rax,-1
 je .bad
 test eax,eax
 jz .transient
 lea rdi,[r12+mofr_range]
 mov esi,6
 call media_opus_range_uint
 cmp rax,-1
 je .bad
 mov [r12+mofr_v+80],rax         ; octave
 lea esi,[eax+4]
 lea rdi,[r12+mofr_range]
 call media_opus_range_bits
 cmp rax,-1
 je .bad
 mov rcx,[r12+mofr_v+80]
 mov edx,16
 shl edx,cl
 lea eax,[rax+rdx-1]
 mov [r12+mofr_v+88],rax         ; new pitch
 lea rdi,[r12+mofr_range]
 mov esi,3
 call media_opus_range_bits
 cmp rax,-1
 je .bad
 inc eax
 imul eax,3072
 mov [r12+mofr_v+96],rax         ; new gain
 lea rdi,[r12+mofr_range]
 call media_opus_range_tell
 add eax,2
 cmp eax,[r12+mofr_v+72]
 ja .transient
 lea rdi,[r12+mofr_range]
 lea rsi,[rel mofr_tapset]
 mov edx,3
 mov ecx,2
 call media_opus_range_icdf
 cmp rax,-1
 je .bad
 mov [r12+mofr_v+104],rax        ; tapset
.transient:
 cmp qword [r12+mofr_v],0
 je .intra
 lea rdi,[r12+mofr_range]
 call media_opus_range_tell
 add eax,3
 cmp eax,[r12+mofr_v+72]
 ja .intra
 lea rdi,[r12+mofr_range]
 mov esi,3
 call media_opus_range_bit
 cmp rax,-1
 je .bad
 mov [r12+mofr_v+112],rax        ; transient
.intra:
 lea rdi,[r12+mofr_range]
 call media_opus_range_tell
 add eax,3
 cmp eax,[r12+mofr_v+72]
 ja .coarse
 lea rdi,[r12+mofr_range]
 mov esi,3
 call media_opus_range_bit
 cmp rax,-1
 je .bad
 mov [r12+mofr_ecfg+56],rax
.coarse:
 mov rax,0
 mov [r12+mofr_ecfg+24],rax
 mov rax,[r12+mofr_v+32]
 mov [r12+mofr_ecfg+32],rax
 mov rax,[r12+mofr_v+40]
 mov [r12+mofr_ecfg+40],rax
 mov rax,[r12+mofr_v]
 mov [r12+mofr_ecfg+48],rax
 lea rdi,[r12+mofr_range]
 lea rsi,[r12+mofr_state+16]
 lea rdx,[r12+mofr_ecfg]
 call media_opus_celt_energy
 test rax,rax
 jnz .bad
 mov rax,[r12+mofr_v+32]
 mov [r12+mofr_tfcfg+8],rax
 mov rax,[r12+mofr_v+112]
 mov [r12+mofr_tfcfg+16],rax
 mov rax,[r12+mofr_v]
 mov [r12+mofr_tfcfg+24],rax
 mov rax,[r12+mofr_v+72]
 mov [r12+mofr_tfcfg+32],rax
 lea rax,[r12+mofr_tf]
 mov [r12+mofr_tfcfg+40],rax
 shl qword [r12+mofr_tfcfg+32],3
 mov rax,[r12+mofr_v+32]
 shl eax,2
 mov [r12+mofr_tfcfg+48],rax
 lea rdi,[r12+mofr_range]
 lea rsi,[r12+mofr_tfcfg]
 call media_opus_tf_decode
 test rax,rax
 jnz .bad
 mov qword [r12+mofr_v+120],2 ; SPREAD_NORMAL
 lea rdi,[r12+mofr_range]
 call media_opus_range_tell
 add eax,4
 cmp eax,[r12+mofr_v+72]
 ja .dynamic
 lea rdi,[r12+mofr_range]
 lea rsi,[rel mofr_spread]
 mov edx,4
 mov ecx,5
 call media_opus_range_icdf
 cmp rax,-1
 je .bad
 mov [r12+mofr_v+120],rax
.dynamic:
 mov rax,[r12+mofr_v+72]
 shl eax,3
 mov [r12+mofr_v+128],rax        ; dynamic remaining total eighthbits
 mov qword [r12+mofr_v+136],6    ; dynalloc_logp
 xor ebx,ebx
.dyn_band:
 mov edi,ebx
 mov rsi,[r12+mofr_v]
 mov rdx,[r12+mofr_v+40]
 call media_opus_rate_cap
 cmp rax,-1
 je .bad
 mov [r12+mofr_v+144],rax
 lea rax,[rel mofr_ebands]
 movzx ebp,word [rax+rbx*2+2]
 movzx eax,word [rax+rbx*2]
 sub ebp,eax
 imul ebp,[r12+mofr_v+40]
 mov rcx,[r12+mofr_v]
 shl ebp,cl
 mov eax,48
 cmp ebp,eax
 cmova eax,ebp
 lea ecx,[rbp*8]
 cmp eax,ecx
 cmova eax,ecx
 mov [r12+mofr_v+152],rax        ; quanta
 mov r14,[r12+mofr_v+136]
 xor r15d,r15d                  ; boost
.dyn_loop:
 lea rdi,[r12+mofr_range]
 call media_opus_range_tell_frac
 cmp rax,-1
 je .bad
 lea rcx,[rax+r14*8]
 cmp rcx,[r12+mofr_v+128]
 jge .dyn_done
 cmp r15,[r12+mofr_v+144]
 jae .dyn_done
 lea rdi,[r12+mofr_range]
 mov rsi,r14
 call media_opus_range_bit
 cmp rax,-1
 je .bad
 test eax,eax
 jz .dyn_done
 add r15,[r12+mofr_v+152]
 mov rax,[r12+mofr_v+152]
 sub [r12+mofr_v+128],rax
 mov r14d,1
 jmp .dyn_loop
.dyn_done:
 mov [r12+mofr_offs+rbx*4],r15d
 test r15d,r15d
 jz .dyn_next
 cmp qword [r12+mofr_v+136],2
 jbe .dyn_next
 dec qword [r12+mofr_v+136]
.dyn_next:
 inc ebx
 cmp rbx,[r12+mofr_v+32]
 jb .dyn_band
 lea rdi,[r12+mofr_range]
 call media_opus_range_tell_frac
 mov qword [r12+mofr_v+160],5    ; trim
 lea rcx,[rax+48]
 cmp rcx,[r12+mofr_v+128]
 jg .allocate
 lea rdi,[r12+mofr_range]
 lea rsi,[rel mofr_trim]
 mov edx,11
 mov ecx,7
 call media_opus_range_icdf
 cmp rax,-1
 je .bad
 mov [r12+mofr_v+160],rax
.allocate:
 lea rdi,[r12+mofr_range]
 call media_opus_range_tell_frac
 cmp rax,-1
 je .bad
 mov rcx,[r12+mofr_v+72]
 shl rcx,3
 sub rcx,rax
 dec rcx                       ; allocation bits
 js .bad
 mov qword [r12+mofr_v+168],0
 cmp qword [r12+mofr_v+112],0
 je .alloc_config
 cmp qword [r12+mofr_v],2
 jb .alloc_config
 mov rax,[r12+mofr_v]
 add eax,2
 shl eax,3
 cmp rcx,rax
 jb .alloc_config
 mov qword [r12+mofr_v+168],8
 sub rcx,8
.alloc_config:
 mov [r12+mofr_acfg+40],rcx
 mov rax,[r12+mofr_v+32]
 mov [r12+mofr_acfg+8],rax
 mov rax,[r12+mofr_v+40]
 mov [r12+mofr_acfg+16],rax
 mov rax,[r12+mofr_v]
 mov [r12+mofr_acfg+24],rax
 mov rax,[r12+mofr_v+160]
 mov [r12+mofr_acfg+32],rax
 mov rax,[r12+mofr_tfcfg+32]
 mov [r12+mofr_acfg+48],rax
 lea rax,[r12+mofr_offs]
 mov [r12+mofr_acfg+56],rax
 mov rax,84
 mov [r12+mofr_acfg+64],rax
 lea rax,[r12+mofr_alloc]
 mov [r12+mofr_acfg+72],rax
 mov rax,288
 mov [r12+mofr_acfg+80],rax
 lea rdi,[r12+mofr_range]
 lea rsi,[r12+mofr_acfg]
 call media_opus_celt_allocation_decode
 test rax,rax
 jnz .bad
 lea rax,[r12+mofr_alloc+116]
 mov [r12+mofr_ecfg+0],rax
 mov rax,1
 mov [r12+mofr_ecfg+16],rax
 mov rax,0
 mov [r12+mofr_ecfg+48],rax
 mov rax,0
 mov [r12+mofr_ecfg+56],rax
 lea rdi,[r12+mofr_range]
 lea rsi,[r12+mofr_state+16]
 lea rdx,[r12+mofr_ecfg]
 call media_opus_celt_energy
 test rax,rax
 jnz .bad
 mov rax,[r12+mofr_v+32]
 mov [r12+mofr_mcfg+8],rax
 mov rax,[r12+mofr_v+40]
 mov [r12+mofr_mcfg+16],rax
 mov rax,[r12+mofr_v]
 mov [r12+mofr_mcfg+24],rax
 mov rax,[r12+mofr_v+112]
 mov [r12+mofr_mcfg+32],rax
 mov rax,[r12+mofr_v+120]
 mov [r12+mofr_mcfg+40],rax
 mov rax,[r12+mofr_tfcfg+32]
 mov [r12+mofr_mcfg+48],rax
 mov rax,[r12+mofr_state+8]
 mov [r12+mofr_mcfg+56],rax
 mov rax,[r12+mofr_tfcfg+32]
 mov [r12+mofr_mcfg+72],rax
 lea rax,[r12+mofr_alloc]
 mov [r12+mofr_mcfg+80],rax
 mov rax,288
 mov [r12+mofr_mcfg+88],rax
 lea rax,[r12+mofr_tf]
 mov [r12+mofr_mcfg+96],rax
 mov rax,[r12+mofr_tfcfg+48]
 mov [r12+mofr_mcfg+104],rax
 lea rax,[r12+mofr_x]
 mov [r12+mofr_mcfg+112],rax
 lea rax,[r12+mofr_masks]
 mov [r12+mofr_mcfg+144],rax
 mov rax,42
 mov [r12+mofr_mcfg+152],rax
 lea rax,[r12+mofr_meta]
 mov [r12+mofr_mcfg+160],rax
 mov rax,32
 mov [r12+mofr_mcfg+168],rax
 mov rax,[r12+mofr_v+168]
 sub [r12+mofr_mcfg+48],rax
 cmp qword [r12+48],1
 sete al
 movzx eax,al
 mov [r12+mofr_mcfg+64],rax
 mov rax,[r12+mofr_v+8]
 add rax,rax
 mov [r12+mofr_mcfg+120],rax
 cmp qword [r12+mofr_v+40],1
 je .multi
 lea rcx,[r12+mofr_x+rax]
 mov [r12+mofr_mcfg+128],rcx
 mov [r12+mofr_mcfg+136],rax
.multi:
 lea rdi,[r12+mofr_range]
 lea rsi,[r12+mofr_mcfg]
 call media_opus_multiband_decode
 test rax,rax
 jnz .bad
 cmp qword [r12+mofr_v+168],0
 je .final_energy
 lea rdi,[r12+mofr_range]
 mov esi,1
 call media_opus_range_bits
 cmp rax,-1
 je .bad
 mov [r12+mofr_v+176],rax
.final_energy:
 lea rdi,[r12+mofr_range]
 call media_opus_range_tell
 mov rcx,[r12+mofr_v+72]
 sub rcx,rax
 js .bad
 mov [r12+mofr_ecfg+48],rcx
 lea rax,[r12+mofr_alloc+200]
 mov [r12+mofr_ecfg+8],rax
 mov rax,2
 mov [r12+mofr_ecfg+16],rax
 lea rdi,[r12+mofr_range]
 lea rsi,[r12+mofr_state+16]
 lea rdx,[r12+mofr_ecfg]
 call media_opus_celt_energy
 test rax,rax
 jnz .bad
 cmp qword [r12+mofr_v+176],0
 je .synthesize
 mov rax,[r12+mofr_v]
 mov [r12+mofr_ccfg+0],rax
 mov rax,[r12+mofr_v+40]
 mov [r12+mofr_ccfg+8],rax
 mov rax,[r12+mofr_v+32]
 mov [r12+mofr_ccfg+24],rax
 lea rax,[r12+mofr_x]
 mov [r12+mofr_ccfg+40],rax
 lea rax,[r12+mofr_masks]
 mov [r12+mofr_ccfg+48],rax
 lea rax,[r12+mofr_alloc+32]
 mov [r12+mofr_ccfg+56],rax
 lea rax,[r12+mofr_state+16]
 mov [r12+mofr_ccfg+64],rax
 lea rax,[r12+mofr_state+100]
 mov [r12+mofr_ccfg+72],rax
 lea rax,[r12+mofr_state+184]
 mov [r12+mofr_ccfg+80],rax
 mov rax,42
 mov [r12+mofr_ccfg+96],rax
 mov rax,84
 mov [r12+mofr_ccfg+104],rax
 mov rax,84
 mov [r12+mofr_ccfg+120],rax
 mov rax,84
 mov [r12+mofr_ccfg+128],rax
 lea rax,[r12+mofr_scratch]
 mov [r12+mofr_ccfg+136],rax
 mov eax,[r12+mofr_meta+16]
 mov [r12+mofr_ccfg+32],rax
 mov rax,[r12+mofr_v+8]
 imul rax,[r12+mofr_v+40]
 add rax,rax
 mov [r12+mofr_ccfg+88],rax
 mov [r12+mofr_ccfg+144],rax
 imul rax,[r12+mofr_v+40],42
 mov [r12+mofr_ccfg+112],rax
 lea rdi,[r12+mofr_ccfg]
 call media_opus_anti_collapse
 test rax,rax
 jnz .bad
 .synthesize:
 mov rsi,[r12+32]
 lea rdi,[r12+mofr_pcm]
 mov rcx,[r12+mofr_v+24]
 shr rcx,1
 rep movsw
 mov rax,[r12+mofr_v]
 mov [r12+mofr_scfg+0],rax
 mov rax,[r12+mofr_v+32]
 mov [r12+mofr_scfg+16],rax
 mov rax,[r12+mofr_v+40]
 mov [r12+mofr_scfg+24],rax
 mov rax,[r12+48]
 mov [r12+mofr_scfg+32],rax
 mov rax,[r12+mofr_v+112]
 mov [r12+mofr_scfg+40],rax
 mov rax,[r12+56]
 mov [r12+mofr_scfg+48],rax
 mov rax,[r12+mofr_v+64]
 mov [r12+mofr_scfg+56],rax
 mov rax,[r12+64]
 mov [r12+mofr_scfg+64],rax
 mov rax,[r12+mofr_v+88]
 mov [r12+mofr_scfg+72],rax
 mov rax,[r12+mofr_v+96]
 mov [r12+mofr_scfg+80],rax
 mov rax,[r12+mofr_v+104]
 mov [r12+mofr_scfg+88],rax
 lea rax,[r12+mofr_x]
 mov [r12+mofr_scfg+96],rax
 lea rax,[r12+mofr_state+16]
 mov [r12+mofr_scfg+112],rax
 lea rax,[r12+mofr_state+384]
 mov [r12+mofr_scfg+128],rax
 lea rax,[r12+mofr_pcm]
 mov [r12+mofr_scfg+144],rax
 mov rax,[r12+mofr_v+24]
 mov [r12+mofr_scfg+152],rax
 mov rax,[r12+mofr_v+8]
 imul rax,[r12+mofr_v+40]
 add rax,rax
 mov [r12+mofr_scfg+104],rax
 imul rax,[r12+mofr_v+40],42
 mov [r12+mofr_scfg+120],rax
 mov rax,[r12+mofr_v+48]
 sub rax,384
 mov [r12+mofr_scfg+136],rax
 lea rdi,[r12+mofr_scfg]
 call media_opus_synthesis
 test rax,rax
 jnz .bad
 cmp qword [r12+mofr_v+40],1
 jne .logs
 lea rsi,[r12+mofr_state+16]
 lea rdi,[r12+mofr_state+58]
 mov ecx,21
 rep movsw
.logs:
 cmp qword [r12+mofr_v+112],0
 jne .transient_log
 lea rsi,[r12+mofr_state+100]
 lea rdi,[r12+mofr_state+184]
 mov ecx,42
 rep movsw
 lea rsi,[r12+mofr_state+16]
 lea rdi,[r12+mofr_state+100]
 mov ecx,42
 rep movsw
 jmp .background
.transient_log:
 xor ebx,ebx
.log_loop:
 movsx eax,word [r12+mofr_state+16+rbx*2]
 movsx ecx,word [r12+mofr_state+100+rbx*2]
 cmp eax,ecx
 cmovg eax,ecx
 mov [r12+mofr_state+100+rbx*2],ax
 inc ebx
 cmp ebx,42
 jb .log_loop
.background:
 mov rcx,[r12+mofr_v]
 mov ebp,1
 shl ebp,cl                     ; max background increase M, QCONST16(.001)=1
 xor ebx,ebx
.background_loop:
 movsx eax,word [r12+mofr_state+268+rbx*2]
 add eax,ebp
 movsx ecx,word [r12+mofr_state+16+rbx*2]
 cmp eax,ecx
 cmovg eax,ecx
 mov [r12+mofr_state+268+rbx*2],ax
 inc ebx
 cmp ebx,42
 jb .background_loop
 xor ebp,ebp
.inactive_channel:
 mov rbx,[r12+mofr_v+32]
.inactive:
 cmp ebx,21
 jae .inactive_next
 lea eax,[rbx+rbp]
 mov word [r12+mofr_state+16+rax*2],0
 mov word [r12+mofr_state+100+rax*2],-28672
 mov word [r12+mofr_state+184+rax*2],-28672
 inc ebx
 jmp .inactive
.inactive_next:
 add ebp,21
 cmp ebp,42
 jb .inactive_channel
 mov eax,[r12+mofr_range+36]
 mov [r12+mofr_state+8],rax
 cmp dword [r12+mofr_range+48],0
 jne .bad
 lea rdi,[r12+mofr_range]
 call media_opus_range_tell
 cmp rax,-1
 je .bad
 mov rcx,[r12+mofr_v+56]
 shl rcx,3
 cmp rax,rcx
 ja .bad
 ; Publish only after all spectral, anti-collapse, synthesis and entropy checks.
 lea rsi,[r12+mofr_state]
 mov rdi,[r12+16]
 mov rcx,[r12+mofr_v+48]
 shr rcx,3
 rep movsq
 lea rsi,[r12+mofr_pcm]
 mov rdi,[r12+32]
 mov rcx,[r12+mofr_v+24]
 shr rcx,1
 rep movsw
 mov rax,[r12+mofr_v+16]
 jmp .done
.bad:
 mov rax,-1
.done:
 cld
 add rsp,31432
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
mofr_ends: db 13,17,19,21
mofr_tapset: db 2,1,0
mofr_spread: db 25,23,2,0
mofr_trim: db 126,124,119,109,87,41,19,9,4,2,0
mofr_ebands: dw 0,1,2,3,4,5,6,7,8,10,12,14,16,20,24,28,34,40,48,60,78,100
