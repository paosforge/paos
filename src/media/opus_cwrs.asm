;; MODULE media/opus_cwrs
;; LAYER 4
;; EXPORTS media_opus_cwrs_count, media_opus_cwrs_unrank, media_opus_cwrs_decode
;; IMPORTS media_opus_range_uint, media_opus_range_tell, media_opus_range_tell_frac
;; CAPS
;; OWNER rc-codex-av
;
; Private UNWIRED integer CWRS/PVQ pulse helper, Opus 1.5.2 celt/cwrs.c.
; Exact SMALL_FOOTPRINT U recurrence and signed codebook ordering. Admitted:
; N=1..176, K=1..128, V(N,K)<=UINT32_MAX. N=1 is the upstream documented
; U base case/sign codebook, not a claim that CELT's outer decoder uses it.
; No allocation, mutable globals, FP, devices, normalization or synthesis.
;
; count(RDI=N,RSI=K,RDX=u32 scratch*,RCX=exact 4*(K+2) bytes) -> V/-1.
; unrank(RDI=readonly config64*) -> 0/-1.
; decode(RDI=range64*,RSI=readonly config64*) -> 0/-1.
; Config eight u64: N,K,index OR cumulative budget in eighth-bits,
; output i32*, exact output bytes 4*N, norm u32*, scratch u32*, exact scratch
; bytes 4*(N+K+2). Scratch holds U row then staged vector. Norm=sum(y*y).
; Pointers are truthful stable mapped lower-canonical caller spans; config
; and range align8, other mutable spans align4. Mutable spans are pairwise
; disjoint and disjoint from config and immutable entropy frame. Config and
; frame may overlap. All structural validation precedes scratch writes.
; Invalid/index/overflow/entropy-error/budget refusal preserves public state,
; output and norm; scratch residuals may remain. No pointer-mapping probe.
; Entropy zero padding remains Xiph-compatible: explicit cumulative budget
; must be <=physical storage bits; it is a bound, not a truncation detector.
; SysV nonvolatiles preserved, DF0 on every exit, FP untouched.
;
; Copyright (c) 2007-2008 CSIRO
; Copyright (c) 2007-2009 Xiph.Org Foundation
; Copyright (c) 2007-2009 Timothy B. Terriberry
; Written by Timothy B. Terriberry and Jean-Marc Valin.
;
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that the following conditions are met:
; - Redistributions of source code must retain the above copyright notice,
;   this list of conditions and the following disclaimer.
; - Redistributions in binary form must reproduce the above copyright notice,
;   this list of conditions and the following disclaimer in the documentation
;   and/or other materials provided with the distribution.
; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
; ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
; LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
; CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
; SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
; INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
; CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
; ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
; POSSIBILITY OF SUCH DAMAGE.

; Bounded row builder. Checked N,K and writable row at RDX; only volatile
; registers changed. Every U term and the final V are checked before narrowing.
mpcw_count_row:
 mov dword [rdx],0
 mov dword [rdx+4],1
 lea r9,[rsi+2]
 mov r11d,2
.fill:
 mov eax,1
 cmp edi,1
 je .store
 lea eax,[r11*2-1]
.store:
 mov [rdx+r11*4],eax
 inc r11
 cmp r11,r9
 jb .fill
 mov r8d,2
 cmp edi,2
 jbe .sum
.row:
 mov r10d,1
 mov r11d,2
.next:
 mov eax,[rdx+r11*4]
 mov ecx,[rdx+r11*4-4]
 add rax,rcx
 add rax,r10
 mov rcx,rax
 shr rcx,32
 jnz mpcw_bad
 mov [rdx+r11*4-4],r10d
 mov r10,rax
 inc r11
 cmp r11,r9
 jb .next
 mov [rdx+r11*4-4],r10d
 inc r8d
 cmp r8d,edi
 jb .row
.sum:
 mov eax,[rdx+rsi*4]
 mov ecx,[rdx+rsi*4+4]
 add rax,rcx
 mov rcx,rax
 shr rcx,32
 jnz mpcw_bad
 ret

media_opus_cwrs_count:
 cld
 lea rax,[rdi-1]
 cmp rax,175
 ja mpcw_bad
 lea rax,[rsi-1]
 cmp rax,127
 ja mpcw_bad
 lea rax,[rsi*4+8]
 cmp rcx,rax
 jne mpcw_bad
 test rdx,rdx
 jz mpcw_bad
 test dl,3
 jnz mpcw_bad
 add rax,rdx
 jc mpcw_bad
 dec rax
 shr rax,47
 jnz mpcw_bad
 jmp mpcw_count_row

; Span builder: RDI base,RSI positive length,EDX alignment mask,ECX writable,
; R8 destination triple. Returns 0/-1; no caller span reads or writes.
mpcw_span:
 test rdi,rdi
 jz mpcw_bad
 test rdi,rdx
 jnz mpcw_bad
 mov rax,rdi
 add rax,rsi
 jc mpcw_bad
 mov r9,rax
 dec r9
 shr r9,47
 jnz mpcw_bad
 mov [r8],rdi
 mov [r8+8],rax
 mov [r8+16],rcx
 xor eax,eax
 ret

media_opus_cwrs_unrank:
 cld
 mov rsi,rdi
 xor edi,edi
 xor eax,eax
 jmp mpcw_transaction
media_opus_cwrs_decode:
 cld
 mov eax,1
mpcw_transaction:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,312
 mov r12,rsp
 mov r13,rsi
 mov r14,rdi
 mov r15,rax
 ; config first, before dereference
 mov rdi,r13
 mov esi,64
 mov edx,7
 xor ecx,ecx
 lea r8,[r12+64]
 call mpcw_span
 test rax,rax
 jnz .bad
 mov rax,[r13]
 lea rcx,[rax-1]
 cmp rcx,175
 ja .bad
 mov [r12+224],rax
 mov rbx,[r13+8]
 lea rcx,[rbx-1]
 cmp rcx,127
 ja .bad
 mov [r12+232],rbx
 mov rcx,[r13+16]
 mov [r12+240],rcx
 lea rsi,[rax*4]
 cmp rsi,[r13+32]
 jne .bad
 mov rdi,[r13+24]
 mov [r12+248],rdi
 mov edx,3
 mov ecx,1
 lea r8,[r12+88]
 call mpcw_span
 test rax,rax
 jnz .bad
 mov rdi,[r13+40]
 mov [r12+256],rdi
 mov esi,4
 lea r8,[r12+112]
 call mpcw_span
 test rax,rax
 jnz .bad
 mov rsi,[r12+224]
 add rsi,rbx
 lea rsi,[rsi*4+8]
 cmp rsi,[r13+56]
 jne .bad
 mov rdi,[r13+48]
 mov [r12+264],rdi
 lea r8,[r12+136]
 call mpcw_span
 test rax,rax
 jnz .bad
 lea rax,[rdi+rbx*4+8]
 mov [r12+272],rax
 mov qword [r12+296],4
 test r15,r15
 jz .aliases
 ; range pointer structural validation, then accepted read-only validation
 mov rdi,r14
 mov esi,64
 mov edx,7
 mov ecx,1
 lea r8,[r12+160]
 call mpcw_span
 test rax,rax
 jnz .bad
 call media_opus_range_tell_frac
 test rax,rax
 js .bad
 cmp dword [r14+48],0
 jne .bad
 cmp rax,[r12+240]
 ja .bad
 mov rsi,[r14+8]
 mov rax,rsi
 shl rax,6
 cmp [r12+240],rax
 ja .bad
 mov qword [r12+296],5
 test rsi,rsi
 jz .aliases
 mov rdi,[r14]
 xor edx,edx
 xor ecx,ecx
 lea r8,[r12+184]
 call mpcw_span
 test rax,rax
 jnz .bad
 mov qword [r12+296],6
.aliases:
 ; At most six spans; readonly/readonly overlap is permitted.
 xor ebx,ebx
.outer:
 lea r8,[rbx+1]
 imul rax,rbx,24
 lea r9,[r12+rax+64]
.inner:
 cmp r8,[r12+296]
 jae .outer_next
 imul rax,r8,24
 lea r10,[r12+rax+64]
 mov rax,[r9+16]
 or rax,[r10+16]
 jz .pair_next
 mov rax,[r9]
 cmp rax,[r10+8]
 jae .pair_next
 mov rax,[r10]
 cmp rax,[r9+8]
 jb .bad
.pair_next:
 inc r8
 jmp .inner
.outer_next:
 inc rbx
 cmp rbx,[r12+296]
 jb .outer
 ; All caller pointer/size/alias validation is now complete.
 mov rdi,[r12+224]
 mov rsi,[r12+232]
 mov rdx,[r12+264]
 call mpcw_count_row
 test rax,rax
 js .bad
 mov [r12+304],rax
 test r15,r15
 jz .index
 ; Borrow only the immutable frame; entropy writes go to the stack copy.
 mov rsi,r14
 mov rdi,r12
 mov ecx,8
 rep movsq
 mov rdi,r12
 mov rsi,[r12+304]
 call media_opus_range_uint
 test rax,rax
 js .bad
 cmp dword [r12+48],0
 jne .bad
 mov [r12+240],rax
 mov rdi,r12
 call media_opus_range_tell
 test rax,rax
 js .bad
 mov rcx,[r12+8]
 shl rcx,3
 cmp rax,rcx
 ja .bad
 mov rdi,r12
 call media_opus_range_tell_frac
 test rax,rax
 js .bad
 cmp rax,[r13+16]
 ja .bad
.index:
 mov rbx,[r12+240]
 cmp rbx,[r12+304]
 jae .bad
 mov rbp,[r12+232]
 mov rsi,[r12+264]
 mov rdi,[r12+272]
 xor r8d,r8d                     ; coordinate
 xor r9d,r9d                     ; squared norm
.coordinate:
 mov eax,[rsi+rbp*4+4]
 xor r10d,r10d                   ; sign mask
 cmp rbx,rax
 jb .sign_done
 mov r10d,-1
 sub rbx,rax
.sign_done:
 mov r11,rbp                     ; old remaining K
.find:
 mov eax,[rsi+rbp*4]
 cmp rax,rbx
 jbe .found
 test rbp,rbp
 jz .bad
 dec rbp
 jmp .find
.found:
 sub rbx,rax
 sub r11,rbp
 mov eax,r11d
 add eax,r10d
 xor eax,r10d
 mov [rdi+r8*4],eax
 imul eax,eax
 add r9,rax
 inc r8
 cmp r8,[r12+224]
 jae .vector_done
 ; Previous U row, shortened to remaining K+2. No unused final uprev.
 xor r10d,r10d
 mov ecx,1
.previous:
 mov eax,[rsi+rcx*4]
 sub eax,[rsi+rcx*4-4]
 jc .bad
 sub eax,r10d
 jc .bad
 mov [rsi+rcx*4-4],r10d
 mov r10d,eax
 inc rcx
 lea r11,[rbp+2]
 cmp rcx,r11
 jb .previous
 mov [rsi+rcx*4-4],r10d
 jmp .coordinate
.vector_done:
 test rbp,rbp
 jnz .bad
 test rbx,rbx
 jnz .bad
 mov rax,[r12+232]
 imul rax,rax
 cmp r9,rax
 ja .bad
 mov [r12+288],r9d
 ; Publish only after every possible refusal. No subsequent failure branch.
 mov rsi,[r12+272]
 mov rdi,[r12+248]
 mov rcx,[r12+224]
 rep movsd
 mov rdi,[r12+256]
 mov eax,[r12+288]
 mov [rdi],eax
 test r15,r15
 jz .success
 mov rsi,r12
 mov rdi,r14
 mov ecx,8
 rep movsq
.success:
 xor eax,eax
 jmp .done
.bad:
 mov rax,-1
.done:
 add rsp,312
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
mpcw_bad:
 mov rax,-1
 ret
