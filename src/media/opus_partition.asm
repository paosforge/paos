;; MODULE media/opus_partition
;; LAYER 4
;; EXPORTS media_opus_partition_decode
;; IMPORTS media_opus_rate_bits_to_pulses, media_opus_rate_pulses_to_bits, media_opus_rate_get_pulses, media_opus_pvq_decode, media_opus_range_tell, media_opus_range_tell_frac
;; CAPS
;; OWNER rc-codex-av
;
; UNWIRED exact Opus1.5.2 quant_partition no-split decode/resynth consumer.
; RDI=range64*,RSI=readonly config128* ->0/-1. All16 fields full-width u64
; except signed LM:band,LM,b,B,spread,gain,remaining,seed,fill,cap,
; output*,output_bytes,optional lowband*,lowband_bytes,meta*,meta_bytes.
; Standard mode N=(eBands[i+1]-eBands[i])*2^LM;LM-1..3,N2..176.
; Refuse upstream split predicate;valid rate cache required;B1/2/4/8/16 dividesN.
; b/remaining0..81600,spread0..3,gain0..32767,seeduint32,filluint16.
; Outputi16[N],cap>=2N;meta6u32 cap>=24:N,q,cost,remaining_after,seed,cm.
; Lowband absent iffptr/cap0;otherwise readonly i16[N] cap>=2N.
; Fold whenq0/fill!=0:sum((abs(lowband)+4)^2)<=2^29;noiseE<2^30.
; All full declared spans pairwise disjoint,lowercanonical/no carry.
; Config/state align8,out/low2,meta4. Caller truthful mapped stable storage
; and serialization. Private bounded staging;refusal changes no caller spans.
; Cumulative cap<=framebytes*64,error0/whole/fractional budgets required.
; No encode/recursive splitting/TF/stereo/IMDCT/PCM/device/runtime wiring.
; SysV nonvolatiles preserved,DF0,FP untouched. Retain XIPH_OPUS_PARTITION.txt.
;
; Xiph Opus1.5.2 — fixed-point unsplit partition decoding and renormalization
; Archive SHA256: 65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1
;
; bands.c
; /* Copyright (c) 2007-2008 CSIRO
;    Copyright (c) 2007-2009 Xiph.Org Foundation
;    Copyright (c) 2008-2009 Gregory Maxwell
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
; vq.c
; /* Copyright (c) 2007-2008 CSIRO
;    Copyright (c) 2007-2009 Xiph.Org Foundation
;    Written by Jean-Marc Valin */
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
; mathops.c
; /* Copyright (c) 2002-2008 Jean-Marc Valin
;    Copyright (c) 2007-2008 CSIRO
;    Copyright (c) 2007-2009 Xiph.Org Foundation
;    Written by Jean-Marc Valin */
; /**
;    @file mathops.h
;    @brief Various math functions
; */
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
; mathops.h
; /* Copyright (c) 2002-2008 Jean-Marc Valin
;    Copyright (c) 2007-2008 CSIRO
;    Copyright (c) 2007-2009 Xiph.Org Foundation
;    Written by Jean-Marc Valin */
; /**
;    @file mathops.h
;    @brief Various math functions
; */
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
; modes.c
; /* Copyright (c) 2007-2008 CSIRO
;    Copyright (c) 2007-2009 Xiph.Org Foundation
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
mopart_rsqrt:
 lea ecx,[rdi-32768]
 imul eax,ecx,6713
 sar eax,15
 sub eax,13490
 movsx eax,ax
 imul eax,ecx
 sar eax,15
 add eax,23557
 movsx r8d,ax                    ; r
 mov eax,r8d
 imul eax,r8d
 sar eax,15
 movsx r9d,ax                    ; r2
 imul eax,ecx
 sar eax,15
 add eax,r9d
 movsx eax,ax
 sub eax,16384
 shl eax,1
 movsx r10d,ax                   ; y
 imul eax,r10d,12288
 sar eax,15
 movsx eax,ax
 sub eax,16384
 movsx eax,ax
 imul eax,r10d
 sar eax,15
 movsx eax,ax
 imul eax,r8d
 sar eax,15
 add eax,r8d
 movsx eax,ax
 ret


mopart_normalise:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 sub rsp,16
 mov [rsp],edx
 mov rbx,rdi
 mov ebp,esi
 mov r12d,1                     ; EPSILON
 xor r8d,r8d
.energy:
 movsx rax,word [rbx+r8*2]
 imul rax,rax
 add r12,rax
 inc r8
 cmp r8,rbp
 jb .energy
 bsr r13d,r12d
 shr r13d,1
 mov edi,r12d
 lea ecx,[r13-7]
 add ecx,ecx
 test ecx,ecx
 js .left
 sar edi,cl
 jmp .gain
.left:
 neg ecx
 shl edi,cl
.gain:
 call mopart_rsqrt
 imul eax,[rsp]
 add eax,16384
 sar eax,15
 movsx r14d,ax
 xor r8d,r8d
.scale:
 movsx eax,word [rbx+r8*2]
 imul eax,r14d
 mov ecx,r13d
 mov edx,1
 shl edx,cl
 add eax,edx
 inc ecx
 sar eax,cl
 mov [rbx+r8*2],ax
 inc r8
 cmp r8,rbp
 jb .scale
 add rsp,16
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret



mopart_span:
 test rdi,rdi
 jz mopart_bad
 test rdi,rdx
 jnz mopart_bad
 mov rax,rdi
 add rax,rsi
 jc mopart_bad
 mov r9,rax
 dec r9
 shr r9,47
 jnz mopart_bad
 mov [r8],rdi
 mov [r8+8],rax
 xor eax,eax
 ret

media_opus_partition_decode:
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,3144
 mov r12,rsp
 mov r13,rsi
 mov r14,rdi
 mov rdi,r13
 mov esi,128
 mov edx,7
 lea r8,[r12+2848]
 call mopart_span
 test rax,rax
 jnz .bad
 mov rsi,r13
 lea rdi,[r12+2944]
 mov ecx,16
 rep movsq
 cmp qword [r12+2944],20
 ja .bad
 mov rax,[r12+2952]
 cmp rax,-1
 jl .bad
 cmp rax,3
 jg .bad
 cmp qword [r12+2960],81600
 ja .bad
 mov rax,[r12+2968]
 test rax,rax
 jz .bad
 cmp rax,16
 ja .bad
 lea rcx,[rax-1]
 test rax,rcx
 jnz .bad
 cmp qword [r12+2976],3
 ja .bad
 cmp qword [r12+2984],32767
 ja .bad
 cmp qword [r12+2992],81600
 ja .bad
 mov eax,0xffffffff
 cmp [r12+3000],rax
 ja .bad
 cmp qword [r12+3008],65535
 ja .bad
 lea rsi,[rel mopart_ebands]
 mov rax,[r12+2944]
 movzx edx,word [rsi+rax*2+2]
 movzx eax,word [rsi+rax*2]
 sub edx,eax
 mov rcx,[r12+2952]
 cmp rcx,-1
 jne .scale_N
 shr edx,1
 jmp .N_ready
.scale_N:
 shl edx,cl
.N_ready:
 cmp edx,2
 jb .bad
 cmp edx,176
 ja .bad
 mov [r12+3072],rdx
 mov eax,edx
 xor edx,edx
 div dword [r12+2968]
 test edx,edx
 jnz .bad
 mov rdi,r14
 mov esi,64
 mov edx,7
 lea r8,[r12+2864]
 call mopart_span
 test rax,rax
 jnz .bad
 call media_opus_range_tell_frac
 test rax,rax
 js .bad
 cmp rax,[r12+3016]
 ja .bad
 cmp dword [r14+48],0
 jne .bad
 mov rax,[r14+8]
 shl rax,6
 cmp [r12+3016],rax
 ja .bad
 mov rdi,[r12+3024]
 mov rsi,[r12+3032]
 mov rax,[r12+3072]
 add rax,rax
 cmp rsi,rax
 jb .bad
 mov edx,1
 lea r8,[r12+2880]
 call mopart_span
 test rax,rax
 jnz .bad
 mov rdi,[r12+3056]
 mov rsi,[r12+3064]
 cmp rsi,24
 jb .bad
 mov edx,3
 lea r8,[r12+2896]
 call mopart_span
 test rax,rax
 jnz .bad
 mov qword [r12+3112],4
 mov rsi,[r14+8]
 test rsi,rsi
 jz .lowband_span
 mov rdi,[r14]
 xor edx,edx
 lea r8,[r12+2912]
 call mopart_span
 test rax,rax
 jnz .bad
 inc qword [r12+3112]
.lowband_span:
 mov rdi,[r12+3040]
 mov rsi,[r12+3048]
 test rdi,rdi
 jnz .lowband_present
 test rsi,rsi
 jnz .bad
 jmp .aliases
.lowband_present:
 mov rax,[r12+3072]
 add rax,rax
 cmp rsi,rax
 jb .bad
 mov edx,1
 mov rax,[r12+3112]
 shl rax,4
 lea r8,[r12+2848+rax]
 call mopart_span
 test rax,rax
 jnz .bad
 inc qword [r12+3112]
.aliases:
 xor ebx,ebx
.outer:
 lea r8,[rbx+1]
 mov rax,rbx
 shl rax,4
 lea r9,[r12+2848+rax]
.inner:
 cmp r8,[r12+3112]
 jae .next_outer
 mov rax,r8
 shl rax,4
 lea r10,[r12+2848+rax]
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
 inc rbx
 cmp rbx,[r12+3112]
 jb .outer
 ; Exact upstream no-split predicate:cache[last]+12=maxcost+11.
 mov rdi,[r12+2944]
 mov rsi,[r12+2952]
 mov edx,81600
 call media_opus_rate_bits_to_pulses
 test rax,rax
 js .bad
 mov rdx,rax
 mov rdi,[r12+2944]
 mov rsi,[r12+2952]
 call media_opus_rate_pulses_to_bits
 test rax,rax
 js .bad
 cmp qword [r12+2952],-1
 je .pulse_plan
 cmp qword [r12+3072],2
 jbe .pulse_plan
 add rax,11
 cmp [r12+2960],rax
 ja .bad
.pulse_plan:
 mov rdi,[r12+2944]
 mov rsi,[r12+2952]
 mov rdx,[r12+2960]
 call media_opus_rate_bits_to_pulses
 test rax,rax
 js .bad
 mov [r12+3080],rax
 mov rax,[r12+2992]
 mov [r12+3096],rax
.cost:
 mov rdi,[r12+2944]
 mov rsi,[r12+2952]
 mov rdx,[r12+3080]
 call media_opus_rate_pulses_to_bits
 test rax,rax
 js .bad
 mov [r12+3088],rax
 sub [r12+3096],rax
 jns .plan_ready
 cmp qword [r12+3080],0
 je .plan_ready
 add [r12+3096],rax
 dec qword [r12+3080]
 jmp .cost
.plan_ready:
 mov eax,[r12+3072]
 mov [r12+64],eax
 mov eax,[r12+3080]
 mov [r12+68],eax
 mov eax,[r12+3088]
 mov [r12+72],eax
 mov eax,[r12+3096]
 mov [r12+76],eax
 mov eax,[r12+3000]
 mov [r12+80],eax
 mov dword [r12+84],0
 mov rsi,r14
 mov rdi,r12
 mov ecx,8
 rep movsq
 cmp qword [r12+3080],0
 je .zero_pulses
 mov rdi,[r12+3080]
 call media_opus_rate_get_pulses
 test rax,rax
 js .bad
 mov [r12+3104],rax
 mov [r12+104],rax
 mov rax,[r12+3072]
 mov [r12+96],rax
 mov rax,[r12+2984]
 mov [r12+112],rax
 mov rax,[r12+2976]
 mov [r12+120],rax
 mov rax,[r12+2968]
 mov [r12+128],rax
 mov rax,[r12+3016]
 mov [r12+136],rax
 mov qword [r12+144],0
 lea rax,[r12+192]
 mov [r12+152],rax
 mov rax,[r12+3072]
 add rax,rax
 mov [r12+160],rax
 lea rax,[r12+84]
 mov [r12+168],rax
 lea rax,[r12+544]
 mov [r12+176],rax
 imul rax,[r12+3072],10
 mov rcx,[r12+3104]
 lea rax,[rax+rcx*4+12]
 mov [r12+184],rax
 mov rdi,r12
 lea rsi,[r12+96]
 call media_opus_pvq_decode
 test rax,rax
 js .bad
 jmp .finish
.zero_pulses:
 mov ecx,[r12+2968]
 mov ebx,1
 shl ebx,cl
 dec ebx
 mov eax,[r12+3008]
 and eax,ebx
 jnz .fill
 lea rdi,[r12+192]
 mov rcx,[r12+3072]
 xor eax,eax
 rep stosw
 jmp .finish
.fill:
 mov r15,[r12+3040]
 test r15,r15
 jz .noise
 mov [r12+84],eax
 xor r9d,r9d
 xor ebp,ebp
.fold_admit:
 movsx rax,word [r15+rbp*2]
 test rax,rax
 jns .positive_magnitude
 neg rax
.positive_magnitude:
 add rax,4
 imul rax,rax
 add r9,rax
 inc rbp
 cmp rbp,[r12+3072]
 jb .fold_admit
 cmp r9,536870912
 ja .bad
 xor ebp,ebp
.fold:
 imul eax,dword [r12+80],1664525
 add eax,1013904223
 mov [r12+80],eax
 movsx edx,word [r15+rbp*2]
 add edx,4
 test eax,0x8000
 jnz .fold_store
 sub edx,8
.fold_store:
 mov [r12+192+rbp*2],dx
 inc rbp
 cmp rbp,[r12+3072]
 jb .fold
 jmp .normalise
.noise:
 mov [r12+84],ebx
 xor ebp,ebp
.noise_sample:
 imul eax,dword [r12+80],1664525
 add eax,1013904223
 mov [r12+80],eax
 sar eax,20
 mov [r12+192+rbp*2],ax
 inc rbp
 cmp rbp,[r12+3072]
 jb .noise_sample
.normalise:
 lea rdi,[r12+192]
 mov esi,[r12+3072]
 mov edx,[r12+2984]
 call mopart_normalise
.finish:
 cmp dword [r12+48],0
 jne .bad
 mov rdi,r12
 call media_opus_range_tell
 test rax,rax
 js .bad
 mov rcx,[r14+8]
 shl rcx,3
 cmp rax,rcx
 ja .bad
 mov rdi,r12
 call media_opus_range_tell_frac
 test rax,rax
 js .bad
 cmp rax,[r12+3016]
 ja .bad
 lea rsi,[r12+192]
 mov rdi,[r12+3024]
 mov rcx,[r12+3072]
 rep movsw
 lea rsi,[r12+64]
 mov rdi,[r12+3056]
 mov ecx,6
 rep movsd
 mov rsi,r12
 mov rdi,r14
 mov ecx,8
 rep movsq
 xor eax,eax
 jmp .done
.bad:
 mov rax,-1
.done:
 add rsp,3144
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
mopart_bad:
 mov rax,-1
 ret
mopart_ebands:
 dw 0,1,2,3,4,5,6,7,8,10,12,14,16,20,24,28,34,40,48,60,78,100
