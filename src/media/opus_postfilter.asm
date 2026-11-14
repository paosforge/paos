;; MODULE media/opus_postfilter
;; LAYER 4
;; EXPORTS media_opus_postfilter
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
;
; UNWIRED exact scalar fixed-point Opus1.5.2 celt.c in-place comb_filter.
; RDI=readonly config88*, eleven u64: samples i32*,sample_bytes,history,N,
; T0,T1,g0,g1,tapset0,tapset1,overlap. Gains are sign-extended signed16.
; N1..960; history17..1026 and >=max(15,T0,T1)+2; T0/T1 0..1024;
; tapsets0..2; overlap0..min(N,120), standard120 window. abs samples
; <=300000000 throughout history+N. Sample buffer align4, config align8.
; Full declared buffer and config spans disjoint mapped lower-canonical.
; Stable truthful spans/caller serialization required. 0/-1; all failures
; leave caller memory unchanged. Only N output samples published on success;
; history and capacity tails retained. Private8088 stack + return addresses.
; No entropy/allocator/globals/FP/devices/runtime; SysV preserved, DF clear.
; See docs/OPUS_NATIVE_POSTFILTER.md;LICENSES/XIPH_OPUS_POSTFILTER.txt.
;
; Xiph Opus 1.5.2 fixed-point CELT postfilter derivation
; https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz
;
; celt/celt.c
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
; celt/fixed_generic.h
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
; celt/arch.h
; /* Copyright (c) 2003-2008 Jean-Marc Valin
;    Copyright (c) 2007-2008 CSIRO
;    Copyright (c) 2007-2009 Xiph.Org Foundation
;    Written by Jean-Marc Valin */
; /**
;    @file arch.h
;    @brief Various architecture definitions for CELT
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
; celt/modes.c (standard generated window)
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

media_opus_postfilter:
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8088
 mov rbp,rdi
 test rdi,rdi
 jz .bad
 test dil,7
 jnz .bad
 mov rax,0x800000000000
 cmp rdi,rax
 jae .bad
 lea r13,[rdi+88]
 cmp r13,rax
 ja .bad
 mov rsi,rdi
 mov rdi,rsp
 mov ecx,11
 rep movsq                       ; private immutable config snapshot
 mov rax,[rsp+16]                ; history
 sub rax,17
 cmp rax,1009
 ja .bad
 mov rax,[rsp+24]                ; N
 dec rax
 cmp rax,959
 ja .bad
 cmp qword [rsp+32],1024
 ja .bad
 cmp qword [rsp+40],1024
 ja .bad
 mov rax,[rsp+48]                ; full64 signed gain, no truncation
 add rax,32768
 cmp rax,65535
 ja .bad
 mov rax,[rsp+56]
 add rax,32768
 cmp rax,65535
 ja .bad
 cmp qword [rsp+64],2
 ja .bad
 cmp qword [rsp+72],2
 ja .bad
 mov rax,[rsp+80]
 cmp rax,120
 ja .bad
 cmp rax,[rsp+24]
 ja .bad
 mov ecx,32
.period:
 mov rax,[rsp+rcx]
 cmp rax,15
 jae .clamped
 mov eax,15
 mov [rsp+rcx],rax
.clamped:
 add rax,2
 cmp rax,[rsp+16]
 ja .bad
 add ecx,8
 cmp ecx,48
 jb .period
 mov r12,[rsp]                  ; original full declared buffer
 test r12,r12
 jz .bad
 test r12b,3
 jnz .bad
 mov rax,0x800000000000
 cmp r12,rax
 jae .bad
 mov r8,[rsp+8]
 add r8,r12
 jc .bad
 cmp r8,rax
 ja .bad
 mov rcx,[rsp+16]
 add rcx,[rsp+24]
 lea rax,[rcx*4]
 cmp [rsp+8],rax
 jb .bad
 cmp r12,r13
 jae .disjoint
 cmp r8,rbp
 ja .bad
.disjoint:
 lea rdi,[rsp+128]
 xor edx,edx
.copy:
 movsxd rax,dword [r12+rdx*4]
 cmp rax,-300000000
 jl .bad
 cmp rax,300000000
 jg .bad
 mov [rdi+rdx*4],eax
 inc edx
 cmp rdx,rcx
 jb .copy
 ; Exact MULT16_16_P15 gain coefficients, including signed rounding.
 lea r10,[rel mopf_gains]
 xor ecx,ecx
.coeffs:
 mov rdx,[rsp+64+rcx*8]           ; tapset0/1
 imul edx,edx,12
 lea rsi,[r10+rdx]
 mov edi,[rsp+48+rcx*8]           ; g0/1
 imul r8d,ecx,12
 xor edx,edx
.coeff:
 mov eax,[rsi+rdx*4]
 imul eax,edi
 add eax,16384
 sar eax,15
 mov [rsp+88+r8],eax
 add r8d,4
 inc edx
 cmp edx,3
 jb .coeff
 inc ecx
 cmp ecx,2
 jb .coeffs
 mov r15,[rsp+80]                ; effective overlap
 mov rax,[rsp+32]
 cmp rax,[rsp+40]
 jne .different
 mov rax,[rsp+48]
 cmp rax,[rsp+56]
 jne .different
 mov rax,[rsp+64]
 cmp rax,[rsp+72]
 jne .different
 xor r15d,r15d                   ; unchanged filter skips interpolation
.different:
 ; Both zero is the exact bypass, even if periods/tapsets differ.
 mov rax,[rsp+48]
 or rax,[rsp+56]
 jnz .filter
 xor r15d,r15d
.filter:
 mov rax,[rsp+16]
 lea r12,[rsp+128+rax*4]          ; staged current signal, causal lag>=15
 mov r13,[rsp+24]
 xor r14d,r14d
.sample:
 cmp r14,r15
 jae .constant
 movsxd rbx,dword [r12+r14*4]
 lea r10,[rel mopf_window]
 movzx eax,word [r10+r14*2]
 imul eax,eax
 shr eax,15                      ; MULT16_16_Q15(window,window)
 mov [rsp+112],eax
 mov edx,32767
 sub edx,eax
 mov r8,[rsp+32]
 lea r9,[rsp+88]
 call .apply
 mov edx,[rsp+112]
 mov r8,[rsp+40]
 lea r9,[rsp+100]
 call .apply
 jmp .saturate
.constant:
 cmp qword [rsp+56],0
 je .publish                     ; exact zero-g1 tail bypass
 movsxd rbx,dword [r12+r14*4]
 mov edx,32768                   ; identity scaling of already-rounded gains
 mov r8,[rsp+40]
 lea r9,[rsp+100]
 call .apply
.saturate:
 mov eax,300000000
 cmp rbx,rax
 cmovg rbx,rax
 mov rax,-300000000
 cmp rbx,rax
 cmovl rbx,rax
 mov [r12+r14*4],ebx
 inc r14
 cmp r14,r13
 jb .sample
.publish:
 mov rdi,[rsp]
 mov rax,[rsp+16]
 lea rdi,[rdi+rax*4]
 mov rsi,r12
 mov rcx,r13
 rep movsd
 xor eax,eax
 jmp .done
.bad:
 mov rax,-1
.done:
 add rsp,8088
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.apply:                          ; RBX += three exact Q15 tap products
 mov r10,r14
 sub r10,r8
 lea rsi,[r12+r10*4]
 movsxd rax,dword [r9+0]
 imul rax,rdx
 sar rax,15
 movsxd rcx,dword [rsi]
 imul rax,rcx
 sar rax,15
 add rbx,rax
 movsxd rax,dword [r9+4]
 imul rax,rdx
 sar rax,15
 movsxd rcx,dword [rsi-4]
 movsxd r11,dword [rsi+4]
 add rcx,r11
 imul rax,rcx
 sar rax,15
 add rbx,rax
 movsxd rax,dword [r9+8]
 imul rax,rdx
 sar rax,15
 movsxd rcx,dword [rsi-8]
 movsxd r11,dword [rsi+8]
 add rcx,r11
 imul rax,rcx
 sar rax,15
 add rbx,rax
 ret
align 4
mopf_gains: dd 10048,7112,4248,15200,8784,0,26208,3280,0
align 2
mopf_window:
 dw 2,20,55,108,178,266,372,494,635,792
 dw 966,1157,1365,1590,1831,2089,2362,2651,2956,3276
 dw 3611,3961,4325,4703,5094,5499,5916,6346,6788,7241
 dw 7705,8179,8663,9156,9657,10167,10684,11207,11736,12271
 dw 12810,13353,13899,14447,14997,15547,16098,16648,17197,17744
 dw 18287,18827,19363,19893,20418,20936,21447,21950,22445,22931
 dw 23407,23874,24330,24774,25208,25629,26039,26435,26819,27190
 dw 27548,27893,28224,28541,28845,29135,29411,29674,29924,30160
 dw 30384,30594,30792,30977,31151,31313,31463,31602,31731,31849
 dw 31958,32057,32148,32229,32303,32370,32429,32481,32528,32568
 dw 32604,32634,32661,32683,32701,32717,32729,32740,32748,32754
 dw 32758,32762,32764,32766,32767,32767,32767,32767,32767,32767
