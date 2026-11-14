;; MODULE media/opus_tf_shape
;; LAYER 4
;; EXPORTS media_opus_tf_shape
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
;
; UNWIRED exact fixed-point bands.c haar1 and Hadamard de/interleave.
; RDI=readonly config80* ->0/-1; u64 N0,stride,op,hadamard,input i16*,
; output i16*,exact input/output bytes2*N0*stride,scratch*,exact scratch bytes,0.
; N0>=1,stride1/2/4/8/16,total<=176; op0haar/1deinterleave/2interleave.
; hadamard0/1; op0 requires0; hadamard1 requiresstride>=2.
; Config align8, all arrays align2, truthful stable mapped lower-canonical spans.
; Exact inplace input/output allowed; partial overlap refused. Output/scratch
; disjoint from config; scratch disjoint from both arrays. Caller serialization.
; Structural refusal changes no data. Bounded scratch stages before publication.
; No allocator/globals/FP/devices/entropy/runtime; SysV preserved,DF0,FP untouched.
; See OPUS_NATIVE_TF_SHAPE.md.
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

; RDI span,RSI positive size,EDX alignment mask,ECX mutable,R8 triple.
motfs_span:
 test rdi,rdi
 jz motfs_bad
 test rdi,rdx
 jnz motfs_bad
 mov rax,rdi
 add rax,rsi
 jc motfs_bad
 mov r9,rax
 dec r9
 shr r9,47
 jnz motfs_bad
 mov [r8],rdi
 mov [r8+8],rax
 mov [r8+16],rcx
 xor eax,eax
 ret
media_opus_tf_shape:
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
 mov esi,80
 mov edx,7
 xor ecx,ecx
 mov r8,r12
 call motfs_span
 test rax,rax
 jnz .bad
 mov rax,[r13]
 lea rcx,[rax-1]
 cmp rcx,175
 ja .bad
 mov [r12+96],rax
 mov rcx,[r13+8]
 cmp rcx,1
 je .stride
 cmp rcx,2
 je .stride
 cmp rcx,4
 je .stride
 cmp rcx,8
 je .stride
 cmp rcx,16
 jne .bad
.stride:
 mov [r12+104],rcx
 imul rax,rcx
 cmp rax,176
 ja .bad
 mov [r12+128],rax
 add rax,rax
 mov [r12+136],rax
 cmp rax,[r13+48]
 jne .bad
 cmp rax,[r13+64]
 jne .bad
 mov rax,[r13+16]
 cmp rax,2
 ja .bad
 mov [r12+112],rax
 mov rdx,[r13+24]
 cmp rdx,1
 ja .bad
 mov [r12+120],rdx
 test rdx,rdx
 jz .mode
 test rax,rax
 jz .bad
 cmp rcx,1
 je .bad
.mode:
 cmp qword [r13+72],0
 jne .bad
 mov rdi,[r13+32]
 mov [r12+144],rdi
 mov rsi,[r12+136]
 mov edx,1
 xor ecx,ecx
 lea r8,[r12+24]
 call motfs_span
 test rax,rax
 jnz .bad
 mov rdi,[r13+40]
 mov [r12+152],rdi
 mov ecx,1
 lea r8,[r12+48]
 call motfs_span
 test rax,rax
 jnz .bad
 mov rdi,[r13+56]
 mov [r12+160],rdi
 lea r8,[r12+72]
 call motfs_span
 test rax,rax
 jnz .bad
 xor ebx,ebx
.outer:
 lea r8,[rbx+1]
 imul rax,rbx,24
 lea r9,[r12+rax]
.inner:
 cmp r8,4
 jae .next_outer
 imul rax,r8,24
 lea r10,[r12+rax]
 ; The only mutable/read-only alias exception is exact same-sized input/output.
 cmp rbx,1
 jne .ordinary
 cmp r8,2
 jne .ordinary
 mov rax,[r9]
 cmp rax,[r10]
 je .next_pair
.ordinary:
 mov rax,[r9+16]
 or rax,[r10+16]
 jz .next_pair
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
 mov r14,[r12+144]
 mov r15,[r12+160]
 cmp qword [r12+112],0
 jne .reorder
 mov rsi,r14
 mov rdi,r15
 mov rcx,[r12+128]
 rep movsw
 xor ebx,ebx                    ; stride lane
 mov rbp,[r12+104]
 mov r10,[r12+96]
 shr r10,1                      ; odd N0 final row remains copied unchanged
.haar_lane:
 xor r8d,r8d
.haar_pair:
 cmp r8,r10
 jae .next_lane
 mov rax,r8
 shl rax,1
 imul rax,rbp
 add rax,rbx
 lea rdx,[rax+rbp]
 movsx ecx,word [r15+rax*2]
 movsx esi,word [r15+rdx*2]
 imul ecx,23170
 imul esi,23170
 mov edi,ecx
 add edi,esi
 sub ecx,esi
 add edi,16384
 sar edi,15
 add ecx,16384
 sar ecx,15
 mov [r15+rax*2],di
 mov [r15+rdx*2],cx
 inc r8
 jmp .haar_pair
.next_lane:
 inc rbx
 cmp rbx,rbp
 jb .haar_lane
 jmp .publish
.reorder:
 lea r11,[rel motfs_ordery]
 mov r9,[r12+104]
 mov r10,[r12+96]
 cmp qword [r12+120],0
 je .natural_order
 lea r11,[r11+r9-2]
.natural_order:
 xor ebx,ebx
.reorder_lane:
 mov rbp,rbx
 cmp qword [r12+120],0
 je .ordered
 movzx ebp,byte [r11+rbx]
.ordered:
 imul rbp,r10
 xor r8d,r8d
.reorder_entry:
 mov rax,r8
 imul rax,r9
 add rax,rbx                    ; natural j*stride+i
 lea rdx,[rbp+r8]               ; ordered ordery[i]*N0+j
 cmp qword [r12+112],1
 jne .interleave
 mov cx,[r14+rax*2]
 mov [r15+rdx*2],cx
 jmp .next_entry
.interleave:
 mov cx,[r14+rdx*2]
 mov [r15+rax*2],cx
.next_entry:
 inc r8
 cmp r8,r10
 jb .reorder_entry
 inc rbx
 cmp rbx,r9
 jb .reorder_lane
.publish:
 mov rsi,r15
 mov rdi,[r12+152]
 mov rcx,[r12+128]
 rep movsw
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
 ret
motfs_bad:
 mov rax,-1
 ret

; Exact inverted bit-reversed Gray ordering from bands.c; offset=stride-2.
motfs_ordery:
 db 1,0
 db 3,0,2,1
 db 7,0,4,3,6,1,5,2
 db 15,0,8,7,12,3,11,4,14,1,9,6,13,2,10,5
