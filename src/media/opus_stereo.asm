;; MODULE media/opus_stereo
;; LAYER 4
;; EXPORTS media_opus_stereo_merge
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
;
; UNWIRED exact Opus1.5.2 fixed-point bands.c stereo_merge.
; RDI=readonly config64* ->0/-1; u64 N,mid,left*,right*,left_bytes,
; right_bytes,scratch*,scratch_bytes. N1..176,mid0..32767 Q15.
; In-place channels i16 Q14, each input energy <=2^29; scratch >=4*N bytes.
; Config align8, arrays align2. All four full declared spans disjoint,
; truthful stable mapped lower-canonical storage, caller serialization.
; Refusal changes nothing including scratch. Stage both channels then publish.
; No entropy/globals/allocator/FP/devices/runtime. SysV preserved, DF0.
; See docs/OPUS_NATIVE_STEREO.md and LICENSES/XIPH_OPUS_STEREO.txt.
;
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
; RDI nonempty span,RSI size,EDX alignment mask,R8 descriptor pair.
most_span:
 test rdi,rdi
 jz most_bad
 test rdi,rdx
 jnz most_bad
 mov rax,rdi
 add rax,rsi
 jc most_bad
 mov r9,rax
 dec r9
 shr r9,47
 jnz most_bad
 mov [r8],rdi
 mov [r8+8],rax
 xor eax,eax
 ret

; EDI normalized Q16 -> EAX signed Q14; exact upstream int16 casts.
most_rsqrt:
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


media_opus_stereo_merge:
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,200
 mov r12,rsp
 mov r13,rdi
 mov esi,64
 mov edx,7
 mov r8,r12
 call most_span
 test rax,rax
 jnz .bad
 mov rbp,[r13]
 lea rax,[rbp-1]
 cmp rax,175
 ja .bad
 mov rax,[r13+8]
 cmp rax,32767
 ja .bad
 mov [r12+72],eax
 lea rax,[rbp*2]
 cmp [r13+32],rax
 jb .bad
 cmp [r13+40],rax
 jb .bad
 add rax,rax
 cmp [r13+56],rax
 jb .bad
 mov rdi,[r13+16]
 mov [r12+80],rdi
 mov rsi,[r13+32]
 mov edx,1
 lea r8,[r12+16]
 call most_span
 test rax,rax
 jnz .bad
 mov rdi,[r13+24]
 mov [r12+88],rdi
 mov rsi,[r13+40]
 lea r8,[r12+32]
 call most_span
 test rax,rax
 jnz .bad
 mov rdi,[r13+48]
 mov [r12+96],rdi
 mov rsi,[r13+56]
 lea r8,[r12+48]
 call most_span
 test rax,rax
 jnz .bad
 xor ebx,ebx
.outer:
 lea r8,[rbx+1]
 mov rax,rbx
 shl rax,4
 lea r9,[r12+rax]
.inner:
 cmp r8,4
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
 cmp rbx,4
 jb .outer
 mov r14,[r12+80]
 mov r15,[r12+88]
 xor ebx,ebx
 xor r8d,r8d                    ; input X energy, wide prevalidation
 xor r9d,r9d                    ; input Y energy (side)
 xor r10d,r10d                  ; signed cross product
.energy:
 movsx rax,word [r14+rbx*2]
 movsx rdx,word [r15+rbx*2]
 mov rsi,rax
 imul rsi,rax
 add r8,rsi
 mov rsi,rdx
 imul rsi,rdx
 add r9,rsi
 imul rax,rdx
 add r10,rax
 inc rbx
 cmp rbx,rbp
 jb .energy
 cmp r8,536870912
 ja .bad
 cmp r9,536870912
 ja .bad
 mov eax,[r12+72]
 imul r10,rax
 sar r10,15
 sar eax,1
 imul eax,eax
 add eax,r9d
 mov edx,r10d
 add edx,edx
 mov edi,eax
 sub edi,edx                    ; El
 add eax,edx                    ; Er
 cmp edi,161061
 jl .copy
 cmp eax,161061
 jl .copy
 mov [r12+124],eax
 bsr ecx,edi
 shr ecx,1
 mov [r12+112],ecx
 sub ecx,7
 add ecx,ecx
 sar edi,cl
 call most_rsqrt
 mov [r12+104],eax
 mov edi,[r12+124]
 bsr ecx,edi
 shr ecx,1
 mov [r12+116],ecx
 sub ecx,7
 add ecx,ecx
 sar edi,cl
 call most_rsqrt
 mov [r12+108],eax
 xor ebx,ebx
 mov r11,[r12+96]
.merge:
 movsx eax,word [r14+rbx*2]
 imul eax,[r12+72]
 add eax,16384
 sar eax,15
 movsx eax,ax                    ; l, P15 signed rounding
 movsx edx,word [r15+rbx*2]
 mov esi,eax
 sub esi,edx
 movsx esi,si                    ; SUB16 wraps before gain
 add eax,edx
 movsx edi,ax                    ; ADD16 wraps before gain
 imul esi,[r12+104]
 mov ecx,[r12+112]
 mov edx,1
 shl edx,cl
 add esi,edx
 inc ecx
 sar esi,cl
 mov [r11+rbx*2],si
 imul edi,[r12+108]
 mov ecx,[r12+116]
 mov edx,1
 shl edx,cl
 add edi,edx
 inc ecx
 sar edi,cl
 lea rax,[rbp+rbx]
 mov [r11+rax*2],di
 inc rbx
 cmp rbx,rbp
 jb .merge
 jmp .publish
.copy:
 mov rsi,r14
 mov rdi,[r12+96]
 mov rcx,rbp
 rep movsw
 mov rsi,r14
 mov rcx,rbp
 rep movsw
.publish:
 mov rsi,[r12+96]
 mov rdi,r14
 mov rcx,rbp
 rep movsw
 mov rdi,r15
 mov rcx,rbp
 rep movsw
 xor eax,eax
 jmp .done
.bad:
 mov rax,-1
.done:
 add rsp,200
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 cld
 ret
most_bad:
 mov rax,-1
 ret
