;; MODULE media/opus_deemphasis
;; LAYER 4
;; EXPORTS media_opus_deemphasis
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
;
; UNWIRED exact standard fixed-point celt_decoder.c deemphasis.
; RDI=readonly config80* ->RAX0/-1;10fullwidthu64fields:
; N,C,downsample,accum,input*,input_bytes,output*,output_bytes,mem*,mem_bytes.
; N1..960,C1/2,ds1/2/3/4/6 dividesN,accum0/1. Input readonly i32[C][N]
; abs<=2^27;initial feedback i32[C] abs<=2^30. Actual mode coef27853.
; Output interleaved i16[C*N/ds];mem persistent i32[C]. Minbytes4NC,2NC/ds,4C.
; Config align8,input/mem4,out2. All4 full declared spans disjoint,
; lowercanonical/nonwrapping,truthful/stable/mapped and caller serialized.
; Private bounded staging. All refusals preserve every caller span/tail.
; Fixed-point recurrence,rounded signed saturating PCM,optional saturating
; accumulation and exact sample decimation. SysV/FP preserved,DF0.
; No allocator/caller scratch/globals/device/entropy/runtime/fullPCM decoder.
; Retain LICENSES/XIPH_OPUS_DEEMPHASIS.txt and docs/OPUS_NATIVE_DEEMPHASIS.md.
;
; Xiph Opus1.5.2 — standard fixed-point deemphasis and PCM conversion
; Archive SHA256: 65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1
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
; fixed_generic.h
; /* Copyright (C) 2007-2009 Xiph.Org Foundation
;    Copyright (C) 2003-2008 Jean-Marc Valin
;    Copyright (C) 2007-2008 CSIRO */
; /**
;    @file fixed_generic.h
;    @brief Generic fixed-point operations
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
;

modem_span:
 test rdi,rdi
 jz modem_bad
 test rdi,rdx
 jnz modem_bad
 mov rax,rdi
 add rax,rsi
 jc modem_bad
 mov r9,rax
 dec r9
 shr r9,47
 jnz modem_bad
 mov [r8],rdi
 mov [r8+8],rax
 xor eax,eax
 ret

media_opus_deemphasis:
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,4008
 mov r12,rsp
 mov r13,rdi
 mov esi,80
 mov edx,7
 lea r8,[r12+3928]
 call modem_span
 test rax,rax
 jnz .bad
 mov rsi,r13
 lea rdi,[r12+3848]
 mov ecx,10
 rep movsq
 mov rax,[r12+3848]
 dec rax
 cmp rax,959
 ja .bad
 mov rax,[r12+3856]
 dec rax
 cmp rax,1
 ja .bad
 cmp qword [r12+3872],1
 ja .bad
 mov rcx,[r12+3864]
 cmp rcx,1
 je .ds_ok
 cmp rcx,2
 je .ds_ok
 cmp rcx,3
 je .ds_ok
 cmp rcx,4
 je .ds_ok
 cmp rcx,6
 jne .bad
.ds_ok:
 mov rax,[r12+3848]
 xor edx,edx
 div rcx
 test rdx,rdx
 jnz .bad
 mov [r12+3992],rax
 imul rax,[r12+3856]
 mov [r12+4000],rax
 mov rdi,[r12+3880]
 mov rsi,[r12+3888]
 mov rax,[r12+3848]
 imul rax,[r12+3856]
 shl rax,2
 cmp rsi,rax
 jb .bad
 mov edx,3
 lea r8,[r12+3944]
 call modem_span
 test rax,rax
 jnz .bad
 mov rdi,[r12+3896]
 mov rsi,[r12+3904]
 mov rax,[r12+4000]
 add rax,rax
 cmp rsi,rax
 jb .bad
 mov edx,1
 lea r8,[r12+3960]
 call modem_span
 test rax,rax
 jnz .bad
 mov rdi,[r12+3912]
 mov rsi,[r12+3920]
 mov rax,[r12+3856]
 shl rax,2
 cmp rsi,rax
 jb .bad
 mov edx,3
 lea r8,[r12+3976]
 call modem_span
 test rax,rax
 jnz .bad
 xor ebx,ebx
.outer:
 lea r8,[rbx+1]
 mov rax,rbx
 shl rax,4
 lea r9,[r12+3928+rax]
.inner:
 cmp r8,4
 jae .next_outer
 mov rax,r8
 shl rax,4
 lea r10,[r12+3928+rax]
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
 cmp rbx,4
 jb .outer
 ; Input/feedback magnitudes make all recurrence sums and PCM bias defined.
 mov r13,[r12+3880]
 mov rbp,[r12+3848]
 imul rbp,[r12+3856]
 xor ebx,ebx
.admit_input:
 movsxd rax,dword [r13+rbx*4]
 test rax,rax
 jns .input_abs
 neg rax
.input_abs:
 cmp rax,134217728
 ja .bad
 inc rbx
 cmp rbx,rbp
 jb .admit_input
 mov r13,[r12+3912]
 xor ebx,ebx
.admit_memory:
 movsxd rax,dword [r13+rbx*4]
 mov [r12+3840+rbx*4],eax
 test rax,rax
 jns .memory_abs
 neg rax
.memory_abs:
 cmp rax,1073741824
 ja .bad
 inc rbx
 cmp rbx,[r12+3856]
 jb .admit_memory
 xor ebx,ebx
.channel:
 mov r13,rbx
 imul r13,[r12+3848]
 shl r13,2
 add r13,[r12+3880]
 movsxd r15,dword [r12+3840+rbx*4]
 xor ebp,ebp
 xor r8d,r8d
 mov r9,rbx
.sample:
 movsxd rax,dword [r13+rbp*4]
 add rax,r15
 imul r15,rax,27853
 sar r15,15
 test r8,r8
 jnz .advance
 add eax,2048
 sar eax,12
 mov edx,-32768
 cmp eax,edx
 cmovl eax,edx
 mov edx,32767
 cmp eax,edx
 cmovg eax,edx
 cmp qword [r12+3872],0
 je .store
 mov r14,[r12+3896]
 movsx edx,word [r14+r9*2]
 add eax,edx
 mov edx,-32768
 cmp eax,edx
 cmovl eax,edx
 mov edx,32767
 cmp eax,edx
 cmovg eax,edx
.store:
 mov [r12+r9*2],ax
 add r9,[r12+3856]
.advance:
 inc r8
 cmp r8,[r12+3864]
 jb .phase_ok
 xor r8d,r8d
.phase_ok:
 inc rbp
 cmp rbp,[r12+3848]
 jb .sample
 mov [r12+3840+rbx*4],r15d
 inc rbx
 cmp rbx,[r12+3856]
 jb .channel
 mov rsi,r12
 mov rdi,[r12+3896]
 mov rcx,[r12+4000]
 rep movsw
 lea rsi,[r12+3840]
 mov rdi,[r12+3912]
 mov rcx,[r12+3856]
 rep movsd
 xor eax,eax
 jmp .done
.bad:
 mov rax,-1
.done:
 add rsp,4008
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
modem_bad:
 mov rax,-1
 ret
