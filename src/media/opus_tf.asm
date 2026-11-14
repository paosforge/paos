;; MODULE media/opus_tf
;; LAYER 4
;; EXPORTS media_opus_tf_decode
;; IMPORTS media_opus_range_bit, media_opus_range_tell, media_opus_range_tell_frac
;; CAPS
;; OWNER rc-codex-av
;
; UNWIRED exact Opus1.5.2 tf_decode and tf_select_table.
; decode(RDI=range64*,RSI=readonly config64*) ->0/-1.
; Config u64: start0..20,end(start+1)..21,transient0/1,LM0..3,
; cumulative eighth-bit cap, output i32[end-start]*, exact bytes4*(end-start),0.
; Config/state align8,output align4; truthful stable mapped lower-canonical
; spans, caller serialization; mutable state/output disjoint from each other
; and readonly config/nonempty frame. Full64,carry/canonical/alias checks.
; Physical storage*8 governs upstream reservation/gates; caller fractional cap
; only admits/refuses the whole result. State/output unchanged on all refusals.
; Bounded local stage, no scratch/allocator/globals/FP/devices/runtime wiring.
; SysV nonvolatiles preserved,DF0,FP untouched. See OPUS_NATIVE_TF.md.
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

; RDI span,RSI size>0,EDX alignment mask,ECX mutable,R8 triple.
motf_span:
 test rdi,rdi
 jz motf_bad
 test rdi,rdx
 jnz motf_bad
 mov rax,rdi
 add rax,rsi
 jc motf_bad
 mov r9,rax
 dec r9
 shr r9,47
 jnz motf_bad
 mov [r8],rdi
 mov [r8+8],rax
 mov [r8+16],rcx
 xor eax,eax
 ret

media_opus_tf_decode:
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,392
 mov r12,rsp
 mov r13,rsi
 mov r14,rdi
 mov rdi,r13
 mov esi,64
 mov edx,7
 xor ecx,ecx
 lea r8,[r12+152]
 call motf_span
 test rax,rax
 jnz .bad
 mov rax,[r13]
 cmp rax,20
 ja .bad
 mov [r12+248],rax
 mov rcx,[r13+8]
 cmp rcx,21
 ja .bad
 cmp rcx,rax
 jbe .bad
 mov [r12+256],rcx
 sub rcx,rax
 mov [r12+296],rcx
 mov rax,[r13+16]
 cmp rax,1
 ja .bad
 mov [r12+264],rax
 mov rax,[r13+24]
 cmp rax,3
 ja .bad
 mov [r12+272],rax
 mov rax,[r13+32]
 mov [r12+280],rax
 cmp qword [r13+56],0
 jne .bad
 mov rdi,r14
 mov esi,64
 mov edx,7
 mov ecx,1
 lea r8,[r12+176]
 call motf_span
 test rax,rax
 jnz .bad
 call media_opus_range_tell_frac
 test rax,rax
 js .bad
 cmp rax,[r12+280]
 ja .bad
 cmp dword [r14+48],0
 jne .bad
 mov rax,[r14+8]
 mov rsi,rax
 shl rax,6
 cmp [r12+280],rax
 ja .bad
 mov rax,rsi
 shl rax,3
 mov [r12+304],rax              ; upstream storage*8, whole bits
 mov rdi,[r13+40]
 mov [r12+288],rdi
 mov rsi,[r12+296]
 shl rsi,2
 cmp rsi,[r13+48]
 jne .bad
 mov edx,3
 lea r8,[r12+200]
 call motf_span
 test rax,rax
 jnz .bad
 mov qword [r12+368],3
 mov rsi,[r14+8]
 test rsi,rsi
 jz .aliases
 mov rdi,[r14]
 xor edx,edx
 xor ecx,ecx
 lea r8,[r12+224]
 call motf_span
 test rax,rax
 jnz .bad
 mov qword [r12+368],4
.aliases:
 xor ebx,ebx
.outer:
 lea r8,[rbx+1]
 imul rax,rbx,24
 lea r9,[r12+rax+152]
.inner:
 cmp r8,[r12+368]
 jae .next_outer
 imul rax,r8,24
 lea r10,[r12+rax+152]
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
 cmp rbx,[r12+368]
 jb .outer
 mov rsi,r14
 mov rdi,r12
 mov ecx,8
 rep movsq
 mov rdi,r12
 call media_opus_range_tell
 test rax,rax
 js .bad
 mov [r12+312],rax
 mov ebp,4
 cmp qword [r12+264],0
 je .first_logp
 mov ebp,2
.first_logp:
 mov [r12+320],rbp
 mov qword [r12+328],0         ; tf_select_rsv
 cmp qword [r12+272],0
 je .reserved
 lea rax,[rax+rbp+1]
 cmp rax,[r12+304]
 ja .reserved
 mov qword [r12+328],1
 dec qword [r12+304]
.reserved:
 mov qword [r12+336],0         ; curr
 mov qword [r12+344],0         ; tf_changed
 lea r15,[rel motf_table]
 mov rax,[r12+272]
 lea r15,[r15+rax*8]
 mov rax,[r12+264]
 lea r15,[r15+rax*4]
 xor ebx,ebx
.flag:
 mov rax,[r12+312]
 add rax,[r12+320]
 cmp rax,[r12+304]
 ja .retain
 mov rdi,r12
 mov rsi,[r12+320]
 call media_opus_range_bit
 test rax,rax
 js .bad
 xor [r12+336],rax
 mov rdi,r12
 call media_opus_range_tell
 test rax,rax
 js .bad
 mov [r12+312],rax
 mov rax,[r12+336]
 or [r12+344],rax
.retain:
 mov eax,[r12+336]
 mov [r12+rbx*4+64],eax
 mov ebp,5
 cmp qword [r12+264],0
 je .later_logp
 mov ebp,4
.later_logp:
 mov [r12+320],rbp
 inc rbx
 cmp rbx,[r12+296]
 jb .flag
 mov qword [r12+376],0         ; tf_select
 cmp qword [r12+328],0
 je .map
 mov rax,[r12+344]
 mov cl,[r15+rax]
 cmp cl,[r15+rax+2]
 je .map
 mov rdi,r12
 mov esi,1
 call media_opus_range_bit
 test rax,rax
 js .bad
 mov [r12+376],rax
.map:
 mov rax,[r12+376]
 lea r15,[r15+rax*2]
 xor ebx,ebx
.map_flag:
 mov eax,[r12+rbx*4+64]
 movsx eax,byte [r15+rax]
 mov [r12+rbx*4+64],eax
 inc rbx
 cmp rbx,[r12+296]
 jb .map_flag
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
 cmp rax,[r12+280]
 ja .bad
 lea rsi,[r12+64]
 mov rdi,[r12+288]
 mov rcx,[r12+296]
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
 add rsp,392
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
motf_bad:
 mov rax,-1
 ret

; Exact celt.c signed TF selection table:4*transient+2*select+flag.
motf_table:
 db 0,-1,0,-1,0,-1,0,-1
 db 0,-1,0,-2,1,0,1,-1
 db 0,-2,0,-3,2,0,1,-1
 db 0,-2,0,-3,3,0,1,-1
