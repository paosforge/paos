;; MODULE media/opus_theta
;; LAYER 4
;; EXPORTS media_opus_theta_decode
;; IMPORTS media_opus_range_bit, media_opus_range_uint, media_opus_range_decode, media_opus_range_update, media_opus_range_tell, media_opus_range_tell_frac
;; CAPS
;; OWNER rc-codex-av
;
; UNWIRED Opus1.5.2 bands.c compute_theta decode, compute_qn and exact math.
; RDI=range64*,RSI=readonly config128* ->0/-1. Config16qwords/result8i32.
; N2..176,b/remaining0..81600,B/B0 powers1..16,LM signed-1..3,
; stereo/disable_inv0/1,band0..20,intensity0..21,fill0..65535.
; Config fields N,b,B,B0,LM,stereo,band,intensity,disable_inv,remaining,fill,
; cumulative fractional cap,output*,output_bytes>=32,reserved0=0,reserved1=0.
; Result inv,imid,iside,delta,itheta,qalloc,b_after,fill_after.
; Full64 scalars/spans. State/config align8,output4,readonly frame byte.
; All declared spans pairwise disjoint. Stable truthful mapped spans and
; serialization required. Local stage; refusal changes no caller storage.
; Cap<=frame bytes*64; require final whole/fractional budgets and error0.
; All3 PDFs; triangular CDF inversion by bounded exact interval scan.
; No vectors/encode/allocator/globals/FP/device/PCM/runtime wiring.
; SysV nonvolatiles preserved,DF0. Retain XIPH_OPUS_THETA.txt.
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
; entcode.h
; /* Copyright (c) 2001-2011 Timothy B. Terriberry
;    Copyright (c) 2008-2009 Xiph.Org Foundation */
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

; RDI span,RSI positive size,EDX alignment mask,R8 descriptor pair.
motheta_span:
 test rdi,rdi
 jz motheta_bad
 test rdi,rdx
 jnz motheta_bad
 mov rax,rdi
 add rax,rsi
 jc motheta_bad
 mov r9,rax
 dec r9
 shr r9,47
 jnz motheta_bad
 mov [r8],rdi
 mov [r8+8],rax
 xor eax,eax
 ret
; EDI angle1..16383 -> exact bitexact_cos.
motheta_cos:
 mov ecx,edi
 imul ecx,edi
 add ecx,4096
 sar ecx,13
 imul eax,ecx,-626
 add eax,16384
 sar eax,15
 add eax,8277
 imul eax,ecx
 add eax,16384
 sar eax,15
 sub eax,7651
 imul eax,ecx
 add eax,16384
 sar eax,15
 sub eax,ecx
 add eax,32768
 movsx eax,ax
 ret
; EDI/ESI positive sine/cosine1..32767; exact signed log2tan.
motheta_logtan:
 bsr r8d,edi
 inc r8d
 mov ecx,15
 sub ecx,r8d
 shl edi,cl
 mov r9d,edi
 bsr r10d,esi
 inc r10d
 mov ecx,15
 sub ecx,r10d
 shl esi,cl
 sub r8d,r10d
 shl r8d,11
 imul eax,r9d,-2597
 add eax,16384
 sar eax,15
 add eax,7932
 imul eax,r9d
 add eax,16384
 sar eax,15
 mov r11d,eax
 imul eax,esi,-2597
 add eax,16384
 sar eax,15
 add eax,7932
 imul eax,esi
 add eax,16384
 sar eax,15
 sub r11d,eax
 lea eax,[r11+r8]
 ret

media_opus_theta_decode:
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,360
 mov r12,rsp
 mov r13,rsi
 mov r14,rdi
 mov rdi,r13
 mov esi,128
 mov edx,7
 lea r8,[r12+96]
 call motheta_span
 test rax,rax
 jnz .bad
 mov rsi,r13
 lea rdi,[r12+160]
 mov ecx,12
 rep movsq
 mov rax,[r12+160]
 sub rax,2
 cmp rax,174
 ja .bad
 cmp qword [r12+168],81600
 ja .bad
 mov rax,[r12+176]
 test rax,rax
 jz .bad
 cmp rax,16
 ja .bad
 lea rcx,[rax-1]
 test rax,rcx
 jnz .bad
 mov rax,[r12+184]
 test rax,rax
 jz .bad
 cmp rax,16
 ja .bad
 lea rcx,[rax-1]
 test rax,rcx
 jnz .bad
 mov rax,[r12+192]
 cmp rax,-1
 jl .bad
 cmp rax,3
 jg .bad
 cmp qword [r12+200],1
 ja .bad
 cmp qword [r12+208],20
 ja .bad
 cmp qword [r12+216],21
 ja .bad
 cmp qword [r12+224],1
 ja .bad
 cmp qword [r12+232],81600
 ja .bad
 cmp qword [r12+240],65535
 ja .bad
 cmp qword [r13+112],0
 jne .bad
 cmp qword [r13+120],0
 jne .bad
 mov rdi,r14
 mov esi,64
 mov edx,7
 lea r8,[r12+112]
 call motheta_span
 test rax,rax
 jnz .bad
 call media_opus_range_tell_frac
 test rax,rax
 js .bad
 cmp rax,[r12+248]
 ja .bad
 cmp dword [r14+48],0
 jne .bad
 mov rax,[r14+8]
 shl rax,6
 cmp [r12+248],rax
 ja .bad
 mov rdi,[r13+96]
 mov [r12+256],rdi
 mov rsi,[r13+104]
 cmp rsi,32
 jb .bad
 mov [r12+264],rsi
 mov edx,3
 lea r8,[r12+128]
 call motheta_span
 test rax,rax
 jnz .bad
 mov qword [r12+272],3
 mov rsi,[r14+8]
 test rsi,rsi
 jz .aliases
 mov rdi,[r14]
 xor edx,edx
 lea r8,[r12+144]
 call motheta_span
 test rax,rax
 jnz .bad
 mov qword [r12+272],4
.aliases:
 xor ebx,ebx
.outer:
 lea r8,[rbx+1]
 mov rax,rbx
 shl rax,4
 lea r9,[r12+rax+96]
.inner:
 cmp r8,[r12+272]
 jae .next_outer
 mov rax,r8
 shl rax,4
 lea r10,[r12+rax+96]
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
 cmp rbx,[r12+272]
 jb .outer
 mov rsi,r14
 mov rdi,r12
 mov ecx,8
 rep movsq
 lea rdi,[r12+64]
 xor eax,eax
 mov ecx,4
 rep stosq
 mov rdi,r12
 call media_opus_range_tell_frac
 mov [r12+280],rax
 ; pulse_cap=actual mode logN[band]+LM*8.
 lea rsi,[rel motheta_logn]
 mov rax,[r12+208]
 movsx edx,word [rsi+rax*2]
 mov eax,[r12+192]
 lea edx,[rdx+rax*8]
 mov [r12+336],edx
 mov esi,edx
 sar esi,1
 sub esi,4
 mov ecx,[r12+160]
 lea ecx,[rcx*2-1]
 cmp qword [r12+200],0
 je .resolution
 cmp qword [r12+160],2
 jne .resolution
 dec ecx
 sub esi,12
.resolution:
 mov eax,esi
 imul eax,ecx
 add eax,[r12+168]
 cdq
 idiv ecx
 mov edx,[r12+168]
 sub edx,[r12+336]
 sub edx,32
 cmp eax,edx
 cmovg eax,edx
 mov edx,64
 cmp eax,edx
 cmovg eax,edx
 mov edx,1
 cmp eax,4
 jl .qn_ready
 mov edx,eax
 and edx,7
 lea rsi,[rel motheta_exp2]
 movzx edx,word [rsi+rdx*2]
 sar eax,3
 mov ecx,14
 sub ecx,eax
 shr edx,cl
 inc edx
 shr edx,1
 add edx,edx
.qn_ready:
 cmp qword [r12+200],0
 je .qn_store
 mov rax,[r12+208]
 cmp rax,[r12+216]
 jb .qn_store
 mov edx,1
.qn_store:
 mov [r12+288],edx
 cmp edx,1
 je .single
 cmp qword [r12+200],0
 je .select_pdf
 cmp qword [r12+160],2
 ja .step_pdf
.select_pdf:
 cmp qword [r12+184],1
 ja .uniform
 cmp qword [r12+200],0
 jne .uniform
 ; Symmetric triangular PDF; scan cumulative intervals exactly, max257.
 mov eax,edx
 shr eax,1
 inc eax
 imul eax,eax
 mov [r12+304],eax
 mov rdi,r12
 mov esi,eax
 call media_opus_range_decode
 test rax,rax
 js .bad
 mov ebx,eax
 xor ebp,ebp
 xor r15d,r15d
.triangle_interval:
 mov ecx,[r12+288]
 shr ecx,1
 lea edx,[rbp+1]
 cmp ebp,ecx
 jle .triangle_width
 mov edx,[r12+288]
 inc edx
 sub edx,ebp
.triangle_width:
 add edx,r15d
 cmp ebx,edx
 jb .triangle_found
 mov r15d,edx
 inc ebp
 jmp .triangle_interval
.triangle_found:
 mov [r12+296],ebp
 mov [r12+312],r15d
 mov [r12+320],edx
 jmp .update
.step_pdf:
 mov eax,edx
 shr eax,1
 mov ebp,eax
 lea esi,[rax*4+3]
 mov [r12+304],esi
 mov rdi,r12
 call media_opus_range_decode
 test rax,rax
 js .bad
 lea ecx,[rbp+1]
 imul ecx,3
 cmp eax,ecx
 jae .step_tail
 xor edx,edx
 mov ecx,3
 div ecx
 mov [r12+296],eax
 imul eax,3
 mov [r12+312],eax
 add eax,3
 mov [r12+320],eax
 jmp .update
.step_tail:
 mov [r12+312],eax
 inc eax
 mov [r12+320],eax
 dec eax
 sub eax,ecx
 lea eax,[rax+rbp+1]
 mov [r12+296],eax
.update:
 mov rdi,r12
 mov esi,[r12+312]
 mov edx,[r12+320]
 mov ecx,[r12+304]
 call media_opus_range_update
 test rax,rax
 js .bad
 mov eax,[r12+296]
 jmp .scale_angle
.uniform:
 mov rdi,r12
 mov esi,[r12+288]
 inc esi
 call media_opus_range_uint
 test rax,rax
 js .bad
.scale_angle:
 shl eax,14
 xor edx,edx
 div dword [r12+288]
 mov [r12+80],eax
 jmp .cost
.single:
 cmp qword [r12+200],0
 je .cost
 cmp qword [r12+168],16
 jbe .cost
 cmp qword [r12+232],16
 jbe .cost
 mov rdi,r12
 mov esi,2
 call media_opus_range_bit
 test rax,rax
 js .bad
 cmp qword [r12+224],0
 je .store_inv
 xor eax,eax
.store_inv:
 mov [r12+64],eax
.cost:
 mov rdi,r12
 call media_opus_range_tell_frac
 test rax,rax
 js .bad
 sub rax,[r12+280]
 mov [r12+84],eax
 mov edx,[r12+168]
 sub edx,eax
 mov [r12+88],edx
 mov eax,[r12+240]
 mov [r12+92],eax
 mov eax,[r12+80]
 test eax,eax
 jnz .side_or_split
 mov dword [r12+68],32767
 mov dword [r12+76],-16384
 mov ecx,[r12+176]
 mov eax,1
 shl eax,cl
 dec eax
 and [r12+92],eax
 jmp .finish
.side_or_split:
 cmp eax,16384
 jne .split
 mov dword [r12+72],32767
 mov dword [r12+76],16384
 mov ecx,[r12+176]
 mov eax,1
 shl eax,cl
 dec eax
 shl eax,cl
 and [r12+92],eax
 jmp .finish
.split:
 mov edi,eax
 call motheta_cos
 mov [r12+68],eax
 mov edi,16384
 sub edi,[r12+80]
 call motheta_cos
 mov [r12+72],eax
 mov edi,eax
 mov esi,[r12+68]
 call motheta_logtan
 movsx eax,ax
 mov ecx,[r12+160]
 dec ecx
 shl ecx,7
 imul eax,ecx
 add eax,16384
 sar eax,15
 mov [r12+76],eax
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
 cmp rax,[r12+248]
 ja .bad
 lea rsi,[r12+64]
 mov rdi,[r12+256]
 mov ecx,8
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
 add rsp,360
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
motheta_bad:
 mov rax,-1
 ret
motheta_logn:
 dw 0,0,0,0,0,0,0,0,8,8,8,8,16,16,16,21,21,24,29,34,36
motheta_exp2:
 dw 16384,17866,19483,21247,23170,25267,27554,30048
