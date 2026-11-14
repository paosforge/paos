;; MODULE media/opus_collapse
;; LAYER 4
;; EXPORTS media_opus_anti_collapse
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
;
; UNWIRED exact fixed-point bands.c anti_collapse/vq.c renormalise_vector.
; RDI=readonly config152* ->0/-1.19u64 fields documented in OPUS_NATIVE_COLLAPSE.md.
; Standard21band shortMDCT120;LM0..3,C1/2,0<=start<=end<=21,uint32 seed value.
; All21 pulses0..81600; selected depth<=255; selected band/channel energy<=2^29.
; Current logs21*C i16; both history arrays42 i16 even for mono (stereo MAX).
; In-place X contains120*(1<<LM)*C i16; caller scratch stages complete X.
; Config align8,X/logs/scratch align2,pulses align4,masks unaligned bytes.
; All8 full declared spans disjoint, nonempty lower-canonical, no carry.
; Stable truthful mapped caller-owned spans and serialization. Full64 admission.
; Refusal changes nothing incl scratch; success publishes only X and scratch.
; No allocator/globals/entropy/FP/devices/runtime;SysV preserved,DF0.
; Seed taken by value like upstream; no caller seed publication.
; Retain LICENSES/XIPH_OPUS_COLLAPSE.txt.
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

; RDI positive span,RSI full size,EDX alignment mask,R8 descriptor pair.
moac_span:
 test rdi,rdi
 jz moac_bad
 test rdi,rdx
 jnz moac_bad
 mov rax,rdi
 add rax,rsi
 jc moac_bad
 mov r9,rax
 dec r9
 shr r9,47
 jnz moac_bad
 mov [r8],rdi
 mov [r8+8],rax
 xor eax,eax
 ret
moac_rsqrt:
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


; Fraction0..1023 -> exact positive Q14 exp2 fractional polynomial.
moac_frac:
 shl edi,4
 imul eax,edi,10204
 sar eax,15
 add eax,14819
 imul eax,edi
 sar eax,15
 add eax,22804
 imul eax,edi
 sar eax,15
 add eax,16383
 ret
; EDI signed Q10 in[-32640,0] -> upstream Q16 exp2.
moac_exp2:
 push rbx
 mov ebx,edi
 sar ebx,10
 cmp ebx,-15
 jl .zero
 and edi,1023
 call moac_frac
 lea ecx,[rbx+2]
 test ecx,ecx
 js .right
 shl eax,cl
 jmp .done
.right:
 neg ecx
 sar eax,cl
 jmp .done
.zero:
 xor eax,eax
.done:
 pop rbx
 ret

; RDI staged i16 vector,ESI count; admitted energy+1<2^30.
moac_normalise:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 sub rsp,16
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
 call moac_rsqrt
 imul eax,32767
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

media_opus_anti_collapse:
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,456
 mov r12,rsp
 mov r13,rdi
 mov esi,152
 mov edx,7
 mov r8,r12
 call moac_span
 test rax,rax
 jnz .bad
 mov rcx,[r13]
 cmp rcx,3
 ja .bad
 mov [r12+128],rcx
 mov eax,1
 shl eax,cl
 mov [r12+168],rax
 imul rax,120
 mov [r12+176],rax
 mov rcx,[r13+8]
 lea rdx,[rcx-1]
 cmp rdx,1
 ja .bad
 mov [r12+136],rcx
 imul rax,rcx
 mov [r12+184],rax
 add rax,rax
 mov [r12+336],rax
 mov [r12+384],rax
 imul rax,rcx,21
 mov [r12+344],rax
 add rax,rax
 mov [r12+360],rax
 mov qword [r12+352],84
 mov qword [r12+368],84
 mov qword [r12+376],84
 mov rax,[r13+16]
 cmp rax,21
 ja .bad
 mov [r12+144],rax
 mov rcx,[r13+24]
 cmp rcx,21
 ja .bad
 cmp rax,rcx
 ja .bad
 mov [r12+152],rcx
 mov rax,[r13+32]
 mov edx,0xffffffff
 cmp rax,rdx
 ja .bad
 mov [r12+160],eax
 xor ebx,ebx
.span_loop:
 cmp ebx,6
 je .scratch_span
 mov rdi,[r13+rbx*8+40]
 mov rsi,[r13+rbx*8+88]
 jmp .span_loaded
.scratch_span:
 mov rdi,[r13+136]
 mov rsi,[r13+144]
.span_loaded:
 cmp rsi,[r12+rbx*8+336]
 jb .bad
 mov [r12+rbx*8+192],rdi
 lea r11,[rel moac_alignments]
 movzx edx,byte [r11+rbx]
 lea r8,[rbx+1]
 shl r8,4
 add r8,r12
 call moac_span
 test rax,rax
 jnz .bad
 inc ebx
 cmp ebx,7
 jb .span_loop
 xor ebx,ebx
.outer:
 lea r8,[rbx+1]
 mov rax,rbx
 shl rax,4
 lea r9,[r12+rax]
.inner:
 cmp r8,8
 jae .next_outer
 mov rax,r8
 shl rax,4
 lea r10,[r12+rax]
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
 cmp rbx,8
 jb .outer
 mov rsi,[r12+208]
 xor ebx,ebx
.pulse_admit:
 cmp dword [rsi+rbx*4],81600
 ja .bad
 inc ebx
 cmp ebx,21
 jb .pulse_admit
 mov r14,[r12+192]
 mov rbx,[r12+144]
.admit_band:
 cmp rbx,[r12+152]
 jae .stage
 lea r11,[rel moac_ebands]
 movzx r8d,word [r11+rbx*2+2]
 movzx eax,word [r11+rbx*2]
 sub r8d,eax
 imul rax,[r12+168]
 mov [r12+264],rax
 mov eax,r8d
 imul rax,[r12+168]
 mov [r12+256],rax
 mov rsi,[r12+208]
 mov eax,[rsi+rbx*4]
 inc eax
 xor edx,edx
 div r8d
 mov ecx,[r12+128]
 shr eax,cl
 cmp eax,255
 ja .bad
 xor ebp,ebp
.admit_channel:
 mov rax,rbp
 imul rax,[r12+176]
 add rax,[r12+264]
 lea r11,[r14+rax*2]
 xor r9d,r9d
 xor r10d,r10d
.admit_energy:
 movsx rax,word [r11+r10*2]
 imul rax,rax
 add r9,rax
 inc r10
 cmp r10,[r12+256]
 jb .admit_energy
 cmp r9,536870912
 ja .bad
 inc rbp
 cmp rbp,[r12+136]
 jb .admit_channel
 inc rbx
 jmp .admit_band
.stage:
 ; No possible refusal after this boundary. Energy bound includes injected noise.
 mov rsi,r14
 mov rdi,[r12+240]
 mov rcx,[r12+184]
 rep movsw
 mov r14,[r12+240]
 mov rbx,[r12+144]
.band:
 cmp rbx,[r12+152]
 jae .publish
 lea r11,[rel moac_ebands]
 movzx edx,word [r11+rbx*2+2]
 movzx eax,word [r11+rbx*2]
 sub edx,eax
 mov [r12+248],edx
 imul rax,[r12+168]
 mov [r12+264],rax
 mov eax,edx
 imul rax,[r12+168]
 mov [r12+256],rax
 bsr ecx,eax
 shr ecx,1
 mov [r12+288],ecx
 mov edx,7
 sub edx,ecx
 mov ecx,edx
 add ecx,ecx
 shl eax,cl
 mov edi,eax
 call moac_rsqrt
 mov [r12+284],eax
 mov rsi,[r12+208]
 mov eax,[rsi+rbx*4]
 inc eax
 xor edx,edx
 div dword [r12+248]
 mov ecx,[r12+128]
 shr eax,cl
 shl eax,7
 neg eax
 mov edi,eax
 call moac_exp2
 shr eax,1
 cmp eax,32767
 jbe .thresh_min
 mov eax,32767
.thresh_min:
 shr eax,1
 mov [r12+280],eax
 xor ebp,ebp
.channel:
 imul rax,rbp,21
 add rax,rbx
 mov rsi,[r12+224]
 movsx edi,word [rsi+rax*2]
 mov rdx,[r12+232]
 movsx ecx,word [rdx+rax*2]
 cmp qword [r12+136],1
 jne .histories
 movsx r8d,word [rsi+rbx*2+42]
 cmp edi,r8d
 cmovl edi,r8d
 movsx r8d,word [rdx+rbx*2+42]
 cmp ecx,r8d
 cmovl ecx,r8d
.histories:
 cmp edi,ecx
 cmovg edi,ecx
 mov rsi,[r12+216]
 movsx eax,word [rsi+rax*2]
 sub eax,edi
 xor edx,edx
 test eax,eax
 cmovl eax,edx
 cmp eax,16384
 jge .zero_amplitude
 neg eax
 mov edi,eax
 call moac_exp2
 shr eax,1
 cmp eax,16383
 jbe .r_min
 mov eax,16383
.r_min:
 add eax,eax
 jmp .boost
.zero_amplitude:
 xor eax,eax
.boost:
 cmp qword [r12+128],3
 jne .r_ready
 cmp eax,23169
 jbe .boost_min
 mov eax,23169
.boost_min:
 imul eax,23170
 sar eax,14
.r_ready:
 cmp eax,[r12+280]
 jbe .r_clamped
 mov eax,[r12+280]
.r_clamped:
 sar eax,1
 imul eax,[r12+284]
 sar eax,15
 mov ecx,[r12+288]
 sar eax,cl
 mov [r12+296],eax
 mov rax,rbx
 imul rax,[r12+136]
 add rax,rbp
 mov rsi,[r12+200]
 movzx eax,byte [rsi+rax]
 mov [r12+300],eax
 mov rax,rbp
 imul rax,[r12+176]
 add rax,[r12+264]
 lea r15,[r14+rax*2]
 mov dword [r12+312],0
 xor r10d,r10d
.block:
 bt dword [r12+300],r10d
 jc .next_block
 mov dword [r12+312],1
 xor r11d,r11d
.noise:
 imul eax,dword [r12+160],1664525
 add eax,1013904223
 mov [r12+160],eax
 mov esi,[r12+296]
 test eax,0x8000
 jnz .positive
 neg esi
.positive:
 mov rcx,r11
 imul rcx,[r12+168]
 add rcx,r10
 mov [r15+rcx*2],si
 inc r11
 cmp r11d,[r12+248]
 jb .noise
.next_block:
 inc r10
 cmp r10,[r12+168]
 jb .block
 cmp dword [r12+312],0
 je .next_channel
 mov rdi,r15
 mov esi,[r12+256]
 call moac_normalise
.next_channel:
 inc rbp
 cmp rbp,[r12+136]
 jb .channel
 inc rbx
 jmp .band
.publish:
 mov rsi,r14
 mov rdi,[r12+192]
 mov rcx,[r12+184]
 rep movsw
 xor eax,eax
 jmp .done
.bad:
 mov rax,-1
.done:
 add rsp,456
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 cld
 ret
moac_bad:
 mov rax,-1
 ret
align 2
moac_ebands:
 dw 0,1,2,3,4,5,6,7,8,10,12,14,16,20,24,28,34,40,48,60,78,100
moac_alignments:
 db 1,0,3,1,1,1,1
