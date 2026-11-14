;; MODULE media/opus_denorm
;; LAYER 4
;; EXPORTS media_opus_denormalise_bands
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
;
; UNWIRED exact fixed-point bands.c denormalise_bands, standard21band mode.
; RDI=readonly config104* ->0/-1; u64 LM,start,end,downsample,silence,
; input i16*,logE i16*,output i32*,input_bytes,log_bytes,output_bytes,
; scratch i32*,scratch_bytes. LM0..3;0<=start<=end<=21;ds1/2/3/4/6;
; silence0/1;N=120<<LM; minimum sizes2N,42,4N,4N respectively.
; Config align8; input/logE align2; output/scratch align4. All five full
; declared spans disjoint, stable truthful mapped lower-canonical memory.
; Caller owns spans and serializes. Refusal changes no spans incl scratch.
; Stage complete N i32 spectrum then publish. Full signed16 inputs/logE.
; No allocator/globals/entropy/FP/devices/runtime;SysV preserved,DF0.
; See docs/OPUS_NATIVE_DENORM.md; retain LICENSES/XIPH_OPUS_DENORM.txt.
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
; quant_bands.c
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

; RDI nonempty span,RSI full size,EDX alignment mask,R8 descriptor pair.
moden_span:
 test rdi,rdi
 jz moden_bad
 test rdi,rdx
 jnz moden_bad
 mov rax,rdi
 add rax,rsi
 jc moden_bad
 mov r9,rax
 dec r9
 shr r9,47
 jnz moden_bad
 mov [r8],rdi
 mov [r8+8],rax
 xor eax,eax
 ret

; EDI Q10 fraction0..1023 -> EAX exact positive Q14 exp2 fractional gain.
moden_exp2_frac:
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

media_opus_denormalise_bands:
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,232
 mov r12,rsp
 mov r13,rdi
 mov esi,104
 mov edx,7
 mov r8,r12
 call moden_span
 test rax,rax
 jnz .bad
 mov rcx,[r13]
 cmp rcx,3
 ja .bad
 mov eax,1
 shl eax,cl
 mov [r12+88],rax                ; M
 imul rbp,rax,120                ; complete spectrum length N
 mov rax,[r13+8]
 cmp rax,21
 ja .bad
 mov [r12+104],rax
 mov rcx,[r13+16]
 cmp rcx,21
 ja .bad
 cmp rax,rcx
 ja .bad
 mov [r12+112],rcx
 mov rax,[r13+24]
 cmp rax,1
 je .ds_ok
 cmp rax,2
 je .ds_ok
 cmp rax,3
 je .ds_ok
 cmp rax,4
 je .ds_ok
 cmp rax,6
 jne .bad
.ds_ok:
 mov [r12+120],rax
 mov rax,[r13+32]
 cmp rax,1
 ja .bad
 mov [r12+128],rax
 lea rax,[rbp*2]
 cmp [r13+64],rax
 jb .bad
 cmp qword [r13+72],42
 jb .bad
 add rax,rax
 cmp [r13+80],rax
 jb .bad
 cmp [r13+96],rax
 jb .bad
 mov rdi,[r13+40]
 mov [r12+136],rdi
 mov rsi,[r13+64]
 mov edx,1
 lea r8,[r12+16]
 call moden_span
 test rax,rax
 jnz .bad
 mov rdi,[r13+48]
 mov [r12+144],rdi
 mov rsi,[r13+72]
 lea r8,[r12+32]
 call moden_span
 test rax,rax
 jnz .bad
 mov rdi,[r13+56]
 mov [r12+152],rdi
 mov rsi,[r13+80]
 mov edx,3
 lea r8,[r12+48]
 call moden_span
 test rax,rax
 jnz .bad
 mov rdi,[r13+88]
 mov [r12+160],rdi
 mov rsi,[r13+96]
 lea r8,[r12+64]
 call moden_span
 test rax,rax
 jnz .bad
 xor ebx,ebx
.outer:
 lea r8,[rbx+1]
 mov rax,rbx
 shl rax,4
 lea r9,[r12+rax]
.inner:
 cmp r8,5
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
 cmp rbx,5
 jb .outer
 ; No possible refusal after this boundary. Initialize the entire staged frame.
 mov r14,[r12+136]
 mov r15,[r12+160]
 mov rdi,r15
 mov rcx,rbp
 xor eax,eax
 rep stosd
 cmp qword [r12+128],0
 jne .publish
 lea r11,[rel moden_ebands]
 mov rax,[r12+112]
 movzx eax,word [r11+rax*2]
 imul rax,[r12+88]
 mov [r12+168],rax               ; bound=M*eBands[end]
 mov rax,rbp
 xor edx,edx
 div qword [r12+120]
 cmp [r12+168],rax
 jbe .bound_ok
 mov [r12+168],rax
.bound_ok:
 mov rbx,[r12+104]
.band:
 cmp rbx,[r12+112]
 jae .clear_tail
 lea r11,[rel moden_ebands]
 movzx eax,word [r11+rbx*2]
 imul rax,[r12+88]
 mov [r12+184],rax
 movzx eax,word [r11+rbx*2+2]
 imul rax,[r12+88]
 mov [r12+192],rax
 mov rsi,[r12+144]
 movsx eax,word [rsi+rbx*2]
 lea r11,[rel moden_means]
 movzx edx,byte [r11+rbx]
 shl edx,6
 add eax,edx
 mov edx,32767
 cmp eax,edx
 cmovg eax,edx
 mov edx,-32768
 cmp eax,edx
 cmovl eax,edx
 mov ecx,eax
 sar ecx,10
 mov edx,16
 sub edx,ecx
 mov [r12+204],edx               ; shift=16-(lg>>10)
 cmp edx,31
 jg .underflow
 mov edi,eax
 and edi,1023
 call moden_exp2_frac
 cmp dword [r12+204],-2
 jg .gain_ready
 mov eax,16384
 mov dword [r12+204],-2
 jmp .gain_ready
.underflow:
 xor eax,eax
 mov dword [r12+204],0
.gain_ready:
 mov [r12+200],eax
 mov rdx,[r12+184]
.coeff:
 movsx eax,word [r14+rdx*2]
 imul eax,[r12+200]
 mov ecx,[r12+204]
 test ecx,ecx
 js .left_shift
 sar eax,cl
 jmp .store
.left_shift:
 neg ecx
 shl eax,cl
.store:
 mov [r15+rdx*4],eax
 inc rdx
 cmp rdx,[r12+192]
 jb .coeff
 inc rbx
 jmp .band
.clear_tail:
 mov rax,[r12+168]
 lea rdi,[r15+rax*4]
 mov rcx,rbp
 sub rcx,rax
 xor eax,eax
 rep stosd
.publish:
 mov rsi,r15
 mov rdi,[r12+152]
 mov rcx,rbp
 rep movsd
 xor eax,eax
 jmp .done
.bad:
 mov rax,-1
.done:
 add rsp,232
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 cld
 ret
moden_bad:
 mov rax,-1
 ret
align 2
moden_ebands:
 dw 0,1,2,3,4,5,6,7,8,10,12,14,16,20,24,28,34,40,48,60,78,100
moden_means:
 db 103,100,92,85,81,77,72,70,78,75,73,71,78,74,69,72,70,74,76,71,60
