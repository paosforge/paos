;; MODULE media/opus_pvq
;; LAYER 4
;; EXPORTS media_opus_pvq_shape, media_opus_pvq_decode
;; IMPORTS media_opus_cwrs_count, media_opus_cwrs_decode, media_opus_range_tell_frac
;; CAPS
;; OWNER rc-codex-av
;
; UNWIRED Opus1.5.2 vq.c normalise_residual, inverse exp_rotation and collapse.
; Fixed-point mathops.c rsqrt/rcp/cos, exact generic LP64 integer semantics.
; No allocation, globals, FP, devices or synthesis. See OPUS_NATIVE_PVQ.md.
; shape(RDI=readonly config96*) ->0/-1, validates caller i32 pulse vector.
; decode(RDI=range64*,RSI=readonly config96*) ->0/-1, composes CWRS on a copy.
; Config u64 fields: N,K,gain Q15,spread,B,cumulative eighth-bit budget,
; pulse pointer(shape) OR zero(decode), output i16*, exact output bytes2*N,
; collapse u32*, scratch*, exact scratch bytes10*N+4*K+12.
; N2..176,K1..128,Vfitsu32; B1/2/4/8/16 divides N; gain0..32767,spread0..3.
; Config/state align8; pulses/scratch/mask align4; output align2. Stable mapped
; lower-canonical truthful spans, caller serialization, mutable spans disjoint
; from each other and all readonly spans. Readonly spans may overlap each other.
; All refusal paths preserve public state/output/mask and inputs. Scratch may
; retain intermediate U/pulses/norm/shape on late refusal. DF0, FP untouched,
; SysV nonvolatiles preserved. No full frame validity or concurrent atomicity.
;
; Copyright (c) 2002-2008 Jean-Marc Valin
; Copyright (c) 2007-2008 CSIRO
; Copyright (c) 2007-2009 Xiph.Org Foundation
; Written by Jean-Marc Valin.
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

; EDI normalized Q16 [16384,65535] -> EAX signed Q14 reciprocal square root.
; Exact upstream polynomial/Householder iteration, including int16 casts.
mopvq_rsqrt:
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

; EDI positive rotation divisor -> EAX exact upstream Q16 reciprocal.
mopvq_rcp:
 bsr r11d,edi
 mov ecx,15
 sub ecx,r11d
 mov r9d,edi
 shl r9d,cl
 sub r9d,32768                  ; n
 imul eax,r9d,-15420
 sar eax,15
 add eax,30840
 movsx r8d,ax                   ; r
 mov eax,r8d
 imul eax,r9d
 sar eax,15
 lea eax,[rax+r8-32768]
 movsx eax,ax
 imul eax,r8d
 sar eax,15
 sub r8d,eax
 movsx r8d,r8w
 mov eax,r8d
 imul eax,r9d
 sar eax,15
 lea eax,[rax+r8-32768]
 movsx eax,ax
 imul eax,r8d
 sar eax,15
 add eax,1
 movsx eax,ax
 sub r8d,eax
 movsx eax,r8w
 mov ecx,16
 sub ecx,r11d
 shl eax,cl
 ret

; EDI in [0,32767], the only cosine quadrant used here -> Q15 cosine.
mopvq_cos:
 test edi,edi
 jz .one
 mov eax,edi
 imul eax,eax
 add eax,16384
 sar eax,15
 mov r8d,eax                    ; x2
 imul eax,r8d,-626
 add eax,16384
 sar eax,15
 add eax,8277
 imul eax,r8d
 add eax,16384
 sar eax,15
 sub eax,7651
 imul eax,r8d
 add eax,16384
 sar eax,15
 mov ecx,32767
 sub ecx,r8d
 add eax,ecx
 mov ecx,32766
 cmp eax,ecx
 cmovg eax,ecx
 inc eax
 ret
.one:
 mov eax,32767
 ret

; exp_rotation1: RDI=i16 X,RSI=len,RDX=stride,ECX=c,R8D=s.
; Only integer multiply/round/extract; both sweeps preserve original pair values.
mopvq_rotation1:
 push rbx
 push rbp
 mov r9,rsi
 sub r9,rdx
.forward:
 test r9,r9
 jle .back_start
 call .pair
 add rdi,2
 dec r9
 jmp .forward
.back_start:
 mov r9,rsi
 sub r9,rdx
 sub r9,rdx
 lea rax,[rdx*2+2]
 sub rdi,rax
.backward:
 test r9,r9
 jle .done
 call .pair
 sub rdi,2
 dec r9
 jmp .backward
.done:
 pop rbp
 pop rbx
 ret
.pair:
 lea rbp,[rdi+rdx*2]
 movsx r10d,word [rdi]
 movsx r11d,word [rbp]
 mov eax,ecx
 imul eax,r11d
 mov ebx,r8d
 imul ebx,r10d
 add eax,ebx
 add eax,16384
 sar eax,15
 mov [rbp],ax
 mov eax,ecx
 imul eax,r10d
 mov ebx,r8d
 imul ebx,r11d
 sub eax,ebx
 add eax,16384
 sar eax,15
 mov [rdi],ax
 ret

; RDI base,RSI positive size,EDX alignment mask,ECX mutable,R8 span triple.
mopvq_span:
 test rdi,rdi
 jz mopvq_bad
 test rdi,rdx
 jnz mopvq_bad
 mov rax,rdi
 add rax,rsi
 jc mopvq_bad
 mov r9,rax
 dec r9
 shr r9,47
 jnz mopvq_bad
 mov [r8],rdi
 mov [r8+8],rax
 mov [r8+16],rcx
 xor eax,eax
 ret

media_opus_pvq_shape:
 cld
 mov rsi,rdi
 xor edi,edi
 xor eax,eax
 jmp mopvq_transaction
media_opus_pvq_decode:
 cld
 mov eax,1
mopvq_transaction:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,488
 mov r12,rsp
 mov r13,rsi
 mov r14,rdi
 mov r15,rax
 mov rdi,r13
 mov esi,96
 mov edx,7
 xor ecx,ecx
 lea r8,[r12+128]
 call mopvq_span
 test rax,rax
 jnz .bad
 mov rax,[r13]
 lea rcx,[rax-2]
 cmp rcx,174
 ja .bad
 mov [r12+296],rax
 mov rbx,[r13+8]
 lea rcx,[rbx-1]
 cmp rcx,127
 ja .bad
 mov [r12+304],rbx
 mov rax,[r13+16]
 cmp rax,32767
 ja .bad
 mov [r12+312],rax
 mov rax,[r13+24]
 cmp rax,3
 ja .bad
 mov [r12+320],rax
 mov rcx,[r13+32]
 cmp rcx,1
 je .blocks
 cmp rcx,2
 je .blocks
 cmp rcx,4
 je .blocks
 cmp rcx,8
 je .blocks
 cmp rcx,16
 jne .bad
.blocks:
 mov [r12+328],rcx
 mov rax,[r12+296]
 xor edx,edx
 div rcx
 test rdx,rdx
 jnz .bad
 mov [r12+448],rax             ; segment length N/B
 mov rax,[r13+40]
 mov [r12+336],rax
 mov rax,[r13+48]
 mov [r12+392],rax
 test r15,r15
 jz .pulse_arg
 test rax,rax
 jnz .bad
 jmp .output
.pulse_arg:
 cmp qword [r12+336],0         ; shape has no entropy budget
 jne .bad
.output:
 mov rsi,[r12+296]
 add rsi,rsi
 cmp rsi,[r13+64]
 jne .bad
 mov rdi,[r13+56]
 mov [r12+344],rdi
 mov edx,1
 mov ecx,1
 lea r8,[r12+152]
 call mopvq_span
 test rax,rax
 jnz .bad
 mov rdi,[r13+72]
 mov [r12+352],rdi
 mov esi,4
 mov edx,3
 lea r8,[r12+176]
 call mopvq_span
 test rax,rax
 jnz .bad
 mov rax,[r12+296]
 imul rsi,rax,10
 lea rsi,[rsi+rbx*4+12]
 cmp rsi,[r13+88]
 jne .bad
 mov rdi,[r13+80]
 mov [r12+360],rdi
 lea r8,[r12+200]
 call mopvq_span
 test rax,rax
 jnz .bad
 mov rax,[r12+296]
 add rax,rbx
 lea rax,[rdi+rax*4+8]        ; decoded iy beyond CWRS scratch
 mov [r12+368],rax
 mov rcx,[r12+296]
 lea rax,[rax+rcx*4]
 mov [r12+376],rax            ; norm u32
 add rax,4
 mov [r12+384],rax            ; staged i16 shape
 mov qword [r12+400],5
 test r15,r15
 jnz .state
 mov rdi,[r12+392]
 mov rsi,[r12+296]
 shl rsi,2
 xor ecx,ecx
 lea r8,[r12+224]
 call mopvq_span
 test rax,rax
 jnz .bad
 jmp .aliases
.state:
 mov rdi,r14
 mov esi,64
 mov edx,7
 mov ecx,1
 lea r8,[r12+224]
 call mopvq_span
 test rax,rax
 jnz .bad
 call media_opus_range_tell_frac
 test rax,rax
 js .bad
 cmp dword [r14+48],0
 jne .bad
 cmp rax,[r12+336]
 ja .bad
 mov rsi,[r14+8]
 mov rax,rsi
 shl rax,6
 cmp [r12+336],rax
 ja .bad
 test rsi,rsi
 jz .aliases
 mov rdi,[r14]
 xor edx,edx
 xor ecx,ecx
 lea r8,[r12+248]
 call mopvq_span
 test rax,rax
 jnz .bad
 mov qword [r12+400],6
.aliases:
 xor ebx,ebx
.outer:
 lea r8,[rbx+1]
 imul rax,rbx,24
 lea r9,[r12+rax+128]
.inner:
 cmp r8,[r12+400]
 jae .next_outer
 imul rax,r8,24
 lea r10,[r12+rax+128]
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
 cmp rbx,[r12+400]
 jb .outer
 ; Structural checks complete; late failures may leave scratch residuals.
 test r15,r15
 jnz .decode
 mov rdi,[r12+296]
 mov rsi,[r12+304]
 mov rdx,[r12+360]
 lea rcx,[rsi*4+8]
 call media_opus_cwrs_count
 test rax,rax
 js .bad
 mov rsi,[r12+392]
 mov rdi,[r12+368]
 mov rcx,[r12+296]
 xor r8d,r8d                   ; L1
 xor r9d,r9d                   ; squared norm
.copy_pulses:
 movsxd rax,dword [rsi]
 mov [rdi],eax
 test rax,rax
 jns .absolute
 neg rax
.absolute:
 cmp rax,[r12+304]
 ja .bad
 add r8,rax
 imul rax,rax
 add r9,rax
 add rsi,4
 add rdi,4
 loop .copy_pulses
 cmp r8,[r12+304]
 jne .bad
 mov [r12+408],r9d
 jmp .mask
.decode:
 mov rsi,r14
 mov rdi,r12
 mov ecx,8
 rep movsq
 mov rax,[r12+296]
 mov [r12+64],rax
 mov rbx,[r12+304]
 mov [r12+72],rbx
 mov rcx,[r12+336]
 mov [r12+80],rcx
 mov rcx,[r12+368]
 mov [r12+88],rcx
 lea rcx,[rax*4]
 mov [r12+96],rcx
 mov rcx,[r12+376]
 mov [r12+104],rcx
 mov rcx,[r12+360]
 mov [r12+112],rcx
 add rax,rbx
 lea rax,[rax*4+8]
 mov [r12+120],rax
 mov rdi,r12
 lea rsi,[r12+64]
 call media_opus_cwrs_decode
 test rax,rax
 jnz .bad
 mov rax,[r12+376]
 mov eax,[rax]
 mov [r12+408],eax
.mask:
 ; Collapse uses original integer pulses, even when gain zero erases X.
 xor r8d,r8d
 xor r9d,r9d
 mov rsi,[r12+368]
.block_mask:
 xor eax,eax
 mov rcx,[r12+448]
.mask_entry:
 or eax,[rsi]
 add rsi,4
 loop .mask_entry
 test eax,eax
 setnz al
 movzx eax,al
 mov ecx,r8d
 shl eax,cl
 or r9d,eax
 inc r8
 cmp r8,[r12+328]
 jb .block_mask
 mov [r12+416],r9d
 mov eax,[r12+408]
 test eax,eax
 jz .bad
 mov rcx,[r12+304]
 imul rcx,rcx
 cmp rax,rcx
 ja .bad
 bsr ebp,eax
 shr ebp,1                     ; k=ilog2(Ryy)>>1
 mov ecx,14
 sub ecx,ebp
 sub ecx,ebp
 shl eax,cl
 mov edi,eax
 call mopvq_rsqrt
 imul eax,[r12+312]
 add eax,16384
 sar eax,15
 movsx r8d,ax                  ; g
 mov rsi,[r12+368]
 mov rdi,[r12+384]
 lea ecx,[rbp+1]
 mov ebx,1
 shl ebx,cl
 shr ebx,1                     ; PSHR rounding constant
 mov r9,[r12+296]
.normalize:
 mov eax,[rsi]
 imul eax,r8d
 add eax,ebx
 sar eax,cl
 mov [rdi],ax
 add rsi,4
 add rdi,2
 dec r9
 jnz .normalize
 ; Inverse exp_rotation, including both sweeps and optional second stride.
 mov rax,[r12+304]
 add rax,rax
 cmp rax,[r12+296]
 jae .publish
 cmp qword [r12+320],0
 je .publish
 mov edi,15
 cmp qword [r12+320],1
 je .factor
 mov edi,10
 cmp qword [r12+320],2
 je .factor
 mov edi,5
.factor:
 imul edi,[r12+304]
 add edi,[r12+296]
 call mopvq_rcp
 mov ecx,[r12+296]
 imul ecx,32767
 imul rax,rcx
 sar rax,31                     ; exact LP64 celt_div
 imul eax,eax
 sar eax,16                     ; HALF16(MULT16_16_Q15(gain,gain))
 mov [r12+424],eax
 mov edi,eax
 call mopvq_cos
 mov [r12+432],eax
 mov edi,32767
 sub edi,[r12+424]
 call mopvq_cos
 mov [r12+436],eax
 mov qword [r12+440],0
 mov rax,[r12+328]
 shl rax,3
 cmp [r12+296],rax
 jb .rotation
 mov r8d,1
.stride2:
 mov rax,r8
 imul rax,r8
 add rax,r8
 imul rax,[r12+328]
 mov rcx,[r12+328]
 shr rcx,2
 add rax,rcx
 cmp rax,[r12+296]
 jae .stride_done
 inc r8
 jmp .stride2
.stride_done:
 mov [r12+440],r8
.rotation:
 xor ebx,ebx
.rotate_block:
 cmp qword [r12+440],0
 je .stride1
 mov rdi,rbx
 imul rdi,[r12+448]
 shl rdi,1
 add rdi,[r12+384]
 mov rsi,[r12+448]
 mov rdx,[r12+440]
 mov ecx,[r12+436]
 mov r8d,[r12+432]
 call mopvq_rotation1
.stride1:
 mov rdi,rbx
 imul rdi,[r12+448]
 shl rdi,1
 add rdi,[r12+384]
 mov rsi,[r12+448]
 mov edx,1
 mov ecx,[r12+432]
 mov r8d,[r12+436]
 call mopvq_rotation1
 inc rbx
 cmp rbx,[r12+328]
 jb .rotate_block
.publish:
 mov rsi,[r12+384]
 mov rdi,[r12+344]
 mov rcx,[r12+296]
 rep movsw
 mov rdi,[r12+352]
 mov eax,[r12+416]
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
 add rsp,488
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
mopvq_bad:
 mov rax,-1
 ret
