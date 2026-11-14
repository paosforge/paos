;; MODULE media/opus_allocation
;; LAYER 4
;; EXPORTS media_opus_celt_allocation_decode
;; IMPORTS media_opus_range_bit, media_opus_range_uint, media_opus_range_tell, media_opus_range_tell_frac
;; CAPS
;; OWNER rc-codex-av
;
; UNWIRED exact Opus1.5.2 standard48k CELT allocation decode.
; decode(RDI=range64*,RSI=readonly config96*) ->0/-1.
; Config12u64: start0..20,end(start+1)..21,C1/2,LM0..3,trim0..10,
; total eighthbits0..81600,cumulative entropy cap eighthbits,offsets i32[21]*,
; exact84bytes,output288*,exact288bytes,reserved0.
; Offsets all0..81600. Config/state/output align8,offsets align4.
; Output:4qword codedBands,signed balance,intensity,dual; i32[21] pulses at32,
; finebits at116,priority at200; trailing4zero. Outside selected bands zero.
; Truthful mapped stable lower-canonical spans and caller serialization required.
; Mutable state/output disjoint from each other and readonly config/offsets/frame.
; Readonly spans may overlap. Full64/carry/canonical/scalar/alias validation.
; Range state copied and all output staged; any refusal preserves caller bytes.
; Caller cap only admits/refuses result; total is not an entropy reservation.
; Bounded local state, no scratch/allocator/globals/FP/device/runtime wiring.
; SysV nonvolatiles preserved,DF0,FP untouched. See OPUS_NATIVE_ALLOCATION.md.
; No complete band/PVQ recursion,frame/PCM/synthesis/runtime qualification.
;
; Additional modes.c/celt.c attribution:
; Copyright (c) 2007-2010 Xiph.Org Foundation
; Copyright (c) 2008 Gregory Maxwell
; Written by Jean-Marc Valin and Gregory Maxwell
;
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

; Local frame: range[64], output[288], five i32[21] working arrays,
; offsets snapshot[21], admitted scalars, five alias triples, loop scalars.
%define MA_START 856
%define MA_END 860
%define MA_C 864
%define MA_LM 868
%define MA_TRIM 872
%define MA_TOTAL 876
%define MA_CAP 880
%define MA_OUT 888
%define MA_SPANS 896
%define MA_NS 1016
%define MA_FLOOR 1024
%define MA_STEREO 1028
%define MA_SKIP_START 1032
%define MA_SKIP_RSV 1036
%define MA_INT_RSV 1040
%define MA_DUAL_RSV 1044
%define MA_LO 1048
%define MA_HI 1052
%define MA_MID 1056
%define MA_ITER 1060
%define MA_PSUM 1064
%define MA_DONE 1068
%define MA_CODED 1072
%define MA_PER 1076
%define MA_LEFT 1080
%define MA_BAND 1084
%define MA_BAL 1088
%define MA_N 1092
%define MA_DEN 1096
%define MA_LOG 1100
%define MA_OFFSET 1104
%define MA_EXCESS 1108

; Span RDI,size RSI,alignment mask EDX,mutable ECX,triple R8.
moalloc_span:
 test rdi,rdi
 jz moalloc_bad
 test rdi,rdx
 jnz moalloc_bad
 mov rax,rdi
 add rax,rsi
 jc moalloc_bad
 mov r9,rax
 dec r9
 shr r9,47
 jnz moalloc_bad
 mov [r8],rdi
 mov [r8+8],rax
 mov [r8+16],rcx
 xor eax,eax
 ret

media_opus_celt_allocation_decode:
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,1128
 mov r12,rsp
 mov r13,rsi
 mov r14,rdi
 mov rdi,r13
 mov esi,96
 mov edx,7
 xor ecx,ecx
 lea r8,[r12+MA_SPANS]
 call moalloc_span
 test rax,rax
 jnz .bad
 mov rax,[r13]
 cmp rax,20
 ja .bad
 mov [r12+MA_START],eax
 mov [r12+MA_SKIP_START],eax
 mov rcx,[r13+8]
 cmp rcx,21
 ja .bad
 cmp rcx,rax
 jbe .bad
 mov [r12+MA_END],ecx
 mov rax,[r13+16]
 dec rax
 cmp rax,1
 ja .bad
 mov [r12+MA_STEREO],eax
 inc eax
 mov [r12+MA_C],eax
 shl eax,3
 mov [r12+MA_FLOOR],eax
 mov rax,[r13+24]
 cmp rax,3
 ja .bad
 mov [r12+MA_LM],eax
 mov rax,[r13+32]
 cmp rax,10
 ja .bad
 mov [r12+MA_TRIM],eax
 mov rax,[r13+40]
 cmp rax,81600
 ja .bad
 mov [r12+MA_TOTAL],eax
 mov rax,[r13+48]
 mov [r12+MA_CAP],rax
 cmp qword [r13+64],84
 jne .bad
 cmp qword [r13+80],288
 jne .bad
 cmp qword [r13+88],0
 jne .bad
 mov rdi,r14
 mov esi,64
 mov edx,7
 mov ecx,1
 lea r8,[r12+MA_SPANS+24]
 call moalloc_span
 test rax,rax
 jnz .bad
 call media_opus_range_tell_frac
 test rax,rax
 js .bad
 cmp rax,[r12+MA_CAP]
 ja .bad
 cmp dword [r14+48],0
 jne .bad
 mov rax,[r14+8]
 shl rax,6
 cmp [r12+MA_CAP],rax
 ja .bad
 mov rdi,[r13+56]
 mov esi,84
 mov edx,3
 xor ecx,ecx
 lea r8,[r12+MA_SPANS+48]
 call moalloc_span
 test rax,rax
 jnz .bad
 mov rdi,[r13+72]
 mov [r12+MA_OUT],rdi
 mov esi,288
 mov edx,7
 mov ecx,1
 lea r8,[r12+MA_SPANS+72]
 call moalloc_span
 test rax,rax
 jnz .bad
 mov qword [r12+MA_NS],4
 mov rsi,[r14+8]
 test rsi,rsi
 jz .aliases
 mov rdi,[r14]
 xor edx,edx
 xor ecx,ecx
 lea r8,[r12+MA_SPANS+96]
 call moalloc_span
 test rax,rax
 jnz .bad
 mov qword [r12+MA_NS],5
.aliases:
 xor ebx,ebx
.outer:
 lea r8,[rbx+1]
 imul rax,rbx,24
 lea r9,[r12+rax+MA_SPANS]
.inner:
 cmp r8,[r12+MA_NS]
 jae .next_outer
 imul rax,r8,24
 lea r10,[r12+rax+MA_SPANS]
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
 cmp rbx,[r12+MA_NS]
 jb .outer
 ; All caller spans are admitted. Offset range is checked before any mutation.
 mov rsi,[r13+56]
 xor ebx,ebx
.offsets:
 mov eax,[rsi+rbx*4]
 cmp eax,81600
 ja .bad
 mov [r12+rbx*4+772],eax
 inc ebx
 cmp ebx,21
 jb .offsets
 lea rdi,[r12+64]
 xor eax,eax
 mov ecx,36
 rep stosq
 mov rsi,r14
 mov rdi,r12
 mov ecx,8
 rep movsq
 lea r15,[rel moalloc_ebands]
 mov eax,[r12+MA_TOTAL]
 xor edx,edx
 cmp eax,8
 jb .skip_reserved
 mov edx,8
.skip_reserved:
 mov [r12+MA_SKIP_RSV],edx
 sub eax,edx
 mov [r12+MA_TOTAL],eax
 mov dword [r12+MA_INT_RSV],0
 mov dword [r12+MA_DUAL_RSV],0
 cmp dword [r12+MA_C],2
 jne .reservations_done
 mov ecx,[r12+MA_END]
 sub ecx,[r12+MA_START]
 lea rdx,[rel moalloc_log2frac]
 movzx edx,byte [rdx+rcx]
 cmp edx,eax
 ja .reservations_done
 mov [r12+MA_INT_RSV],edx
 sub eax,edx
 xor edx,edx
 cmp eax,8
 jb .dual_reserved
 mov edx,8
.dual_reserved:
 mov [r12+MA_DUAL_RSV],edx
 sub eax,edx
 mov [r12+MA_TOTAL],eax
.reservations_done:
 mov ebx,[r12+MA_START]
.setup_band:
 movzx ebp,word [r15+rbx*2+2]
 movzx eax,word [r15+rbx*2]
 sub ebp,eax                    ; N0
 mov edx,ebp
 mov ecx,[r12+MA_LM]
 shl edx,cl                    ; N=N0<<LM
 lea eax,[rdx+rdx*2]
 shr eax,1                     ; (3*N<<3)>>4
 cmp eax,[r12+MA_FLOOR]
 cmovl eax,[r12+MA_FLOOR]
 mov [r12+rbx*4+520],eax
 mov eax,[r12+MA_TRIM]
 sub eax,5
 sub eax,ecx
 imul eax,ebp
 imul eax,[r12+MA_C]
 mov esi,[r12+MA_END]
 sub esi,ebx
 dec esi
 imul eax,esi
 add ecx,3
 shl eax,cl
 sar eax,6
 cmp edx,1
 jne .trim_ready
 sub eax,[r12+MA_FLOOR]
.trim_ready:
 mov [r12+rbx*4+604],eax
 mov eax,[r12+MA_LM]
 lea eax,[rax*2]
 add eax,[r12+MA_C]
 dec eax
 imul eax,21
 add eax,ebx
 lea rsi,[rel moalloc_caps]
 movzx eax,byte [rsi+rax]
 add eax,64
 imul eax,[r12+MA_C]
 imul eax,edx
 shr eax,2
 mov [r12+rbx*4+688],eax
 inc ebx
 cmp ebx,[r12+MA_END]
 jb .setup_band
 mov dword [r12+MA_LO],1
 mov dword [r12+MA_HI],10
.vector_search:
 mov edi,[r12+MA_LO]
 add edi,[r12+MA_HI]
 shr edi,1
 mov [r12+MA_MID],edi
 mov dword [r12+MA_PSUM],0
 mov dword [r12+MA_DONE],0
 mov ebx,[r12+MA_END]
.vector_sum:
 dec ebx
 mov edi,[r12+MA_MID]
 call moalloc_vector
 add eax,[r12+rbx*4+772]
 call moalloc_clip
 add [r12+MA_PSUM],eax
 cmp ebx,[r12+MA_START]
 ja .vector_sum
 mov eax,[r12+MA_PSUM]
 cmp eax,[r12+MA_TOTAL]
 jle .vector_below
 mov eax,[r12+MA_MID]
 dec eax
 mov [r12+MA_HI],eax
 jmp .vector_next
.vector_below:
 mov eax,[r12+MA_MID]
 inc eax
 mov [r12+MA_LO],eax
.vector_next:
 mov eax,[r12+MA_LO]
 cmp eax,[r12+MA_HI]
 jle .vector_search
 mov [r12+MA_HI],eax
 dec dword [r12+MA_LO]
 mov ebx,[r12+MA_START]
.bracket:
 mov edi,[r12+MA_LO]
 call moalloc_vector
 cmp dword [r12+MA_LO],0
 je .low_ready
 add eax,[r12+rbx*4+772]
.low_ready:
 mov [r12+rbx*4+352],eax
 mov edi,[r12+MA_HI]
 cmp edi,11
 jb .high_vector
 mov eax,[r12+rbx*4+688]
 call moalloc_trim
 jmp .high_ready
.high_vector:
 call moalloc_vector
.high_ready:
 add eax,[r12+rbx*4+772]
 cmp dword [r12+rbx*4+772],0
 je .skip_start_ready
 mov [r12+MA_SKIP_START],ebx
.skip_start_ready:
 sub eax,[r12+rbx*4+352]
 xor edx,edx
 test eax,eax
 cmovs eax,edx
 mov [r12+rbx*4+436],eax
 inc ebx
 cmp ebx,[r12+MA_END]
 jb .bracket
 ; Six fixed interpolation bisections, then final lower endpoint.
 mov dword [r12+MA_LO],0
 mov dword [r12+MA_HI],64
 mov dword [r12+MA_ITER],6
.interp_search:
 mov eax,[r12+MA_LO]
 add eax,[r12+MA_HI]
 shr eax,1
 mov [r12+MA_MID],eax
 mov dword [r12+MA_PSUM],0
 mov dword [r12+MA_DONE],0
 mov ebx,[r12+MA_END]
.interp_sum:
 dec ebx
 mov eax,[r12+rbx*4+436]
 imul eax,[r12+MA_MID]
 sar eax,6
 add eax,[r12+rbx*4+352]
 call moalloc_clip
 add [r12+MA_PSUM],eax
 cmp ebx,[r12+MA_START]
 ja .interp_sum
 mov eax,[r12+MA_MID]
 mov edx,[r12+MA_PSUM]
 cmp edx,[r12+MA_TOTAL]
 jle .interp_below
 mov [r12+MA_HI],eax
 jmp .interp_next
.interp_below:
 mov [r12+MA_LO],eax
.interp_next:
 dec dword [r12+MA_ITER]
 jnz .interp_search
 mov dword [r12+MA_PSUM],0
 mov dword [r12+MA_DONE],0
 mov ebx,[r12+MA_END]
.final_sum:
 dec ebx
 mov eax,[r12+rbx*4+436]
 imul eax,[r12+MA_LO]
 sar eax,6
 add eax,[r12+rbx*4+352]
 call moalloc_clip
 mov [r12+rbx*4+96],eax
 add [r12+MA_PSUM],eax
 cmp ebx,[r12+MA_START]
 ja .final_sum
 mov eax,[r12+MA_END]
 mov [r12+MA_CODED],eax
.skip:
 mov ebx,[r12+MA_CODED]
 dec ebx
 cmp ebx,[r12+MA_SKIP_START]
 jbe .refund_skip
 call moalloc_remaining
 ; EDX remainder, denominator coeff count in ECX, EAX percoeff.
 movzx esi,word [r15+rbx*2]
 mov edi,[r12+MA_START]
 movzx edi,word [r15+rdi*2]
 sub esi,edi
 sub edx,esi
 xor esi,esi
 test edx,edx
 cmovs edx,esi
 mov ecx,[r12+MA_CODED]
 movzx esi,word [r15+rcx*2]
 movzx ecx,word [r15+rbx*2]
 sub esi,ecx
 imul eax,esi
 add eax,edx
 add eax,[r12+rbx*4+96]
 mov [r12+MA_BAND],eax
 mov edx,[r12+MA_FLOOR]
 add edx,8
 cmp edx,[r12+rbx*4+520]
 cmovl edx,[r12+rbx*4+520]
 cmp eax,edx
 jl .reclaim
 mov rdi,r12
 mov esi,1
 call media_opus_range_bit
 test rax,rax
 js .bad
 test eax,eax
 jnz .stereo
 add dword [r12+MA_PSUM],8
 sub dword [r12+MA_BAND],8
.reclaim:
 mov eax,[r12+rbx*4+96]
 add eax,[r12+MA_INT_RSV]
 sub [r12+MA_PSUM],eax
 cmp dword [r12+MA_INT_RSV],0
 jle .intensity_reclaimed
 mov eax,ebx
 sub eax,[r12+MA_START]
 lea rdx,[rel moalloc_log2frac]
 movzx eax,byte [rdx+rax]
 mov [r12+MA_INT_RSV],eax
.intensity_reclaimed:
 mov eax,[r12+MA_INT_RSV]
 add [r12+MA_PSUM],eax
 xor eax,eax
 mov edx,[r12+MA_FLOOR]
 cmp [r12+MA_BAND],edx
 cmovge eax,edx
 add [r12+MA_PSUM],eax
 mov [r12+rbx*4+96],eax
 dec dword [r12+MA_CODED]
 jmp .skip
.refund_skip:
 mov eax,[r12+MA_SKIP_RSV]
 add [r12+MA_TOTAL],eax
.stereo:
 cmp dword [r12+MA_INT_RSV],0
 jle .intensity_ready
 mov esi,[r12+MA_CODED]
 inc esi
 sub esi,[r12+MA_START]
 mov rdi,r12
 call media_opus_range_uint
 test rax,rax
 js .bad
 add eax,[r12+MA_START]
 mov [r12+80],rax
.intensity_ready:
 mov eax,[r12+MA_START]
 cmp [r12+80],rax
 ja .dual
 mov eax,[r12+MA_DUAL_RSV]
 add [r12+MA_TOTAL],eax
 mov dword [r12+MA_DUAL_RSV],0
.dual:
 cmp dword [r12+MA_DUAL_RSV],0
 jle .distribute
 mov rdi,r12
 mov esi,1
 call media_opus_range_bit
 test rax,rax
 js .bad
 mov [r12+88],rax
.distribute:
 call moalloc_remaining
 mov [r12+MA_PER],eax
 mov [r12+MA_LEFT],edx
 mov ebx,[r12+MA_START]
.per_coefficient:
 movzx edx,word [r15+rbx*2+2]
 movzx eax,word [r15+rbx*2]
 sub edx,eax
 mov eax,[r12+MA_PER]
 imul eax,edx
 add [r12+rbx*4+96],eax
 inc ebx
 cmp ebx,[r12+MA_CODED]
 jb .per_coefficient
 mov ebx,[r12+MA_START]
.remainder:
 movzx edx,word [r15+rbx*2+2]
 movzx eax,word [r15+rbx*2]
 sub edx,eax
 cmp edx,[r12+MA_LEFT]
 cmovg edx,[r12+MA_LEFT]
 add [r12+rbx*4+96],edx
 sub [r12+MA_LEFT],edx
 inc ebx
 cmp ebx,[r12+MA_CODED]
 jb .remainder
 mov dword [r12+MA_BAL],0
 mov ebx,[r12+MA_START]
.fine:
 movzx eax,word [r15+rbx*2+2]
 movzx edx,word [r15+rbx*2]
 sub eax,edx
 mov ecx,[r12+MA_LM]
 shl eax,cl
 mov [r12+MA_N],eax
 mov ebp,[r12+rbx*4+96]
 add ebp,[r12+MA_BAL]          ; bit
 cmp eax,1
 jle .single_coefficient
 mov edx,ebp
 sub edx,[r12+rbx*4+688]
 xor ecx,ecx
 test edx,edx
 cmovs edx,ecx
 mov [r12+MA_EXCESS],edx
 sub ebp,edx
 mov [r12+rbx*4+96],ebp
 imul eax,[r12+MA_C]
 cmp dword [r12+MA_C],2
 jne .den_ready
 cmp dword [r12+MA_N],2
 jle .den_ready
 cmp qword [r12+88],0
 jne .den_ready
 cmp ebx,[r12+80]
 jge .den_ready
 inc eax
.den_ready:
 mov [r12+MA_DEN],eax
 lea rdx,[rel moalloc_logn]
 movzx edx,word [rdx+rbx*2]
 mov ecx,[r12+MA_LM]
 shl ecx,3
 add edx,ecx
 imul edx,eax
 mov [r12+MA_LOG],edx
 sar edx,1
 imul ecx,eax,21
 sub edx,ecx
 cmp dword [r12+MA_N],2
 jne .curve
 lea edx,[rdx+rax*2]
.curve:
 mov ecx,eax
 shl ecx,4                    ; den*2<<3
 lea esi,[rbp+rdx]
 cmp esi,ecx
 jge .third_bit_curve
 mov ecx,[r12+MA_LOG]
 sar ecx,2
 add edx,ecx
 jmp .offset_ready
.third_bit_curve:
 lea ecx,[rax+rax*2]
 shl ecx,3
 cmp esi,ecx
 jge .offset_ready
 mov ecx,[r12+MA_LOG]
 sar ecx,3
 add edx,ecx
.offset_ready:
 mov [r12+MA_OFFSET],edx
 lea eax,[rbp+rdx]
 mov edx,[r12+MA_DEN]
 lea eax,[rax+rdx*4]
 xor ecx,ecx
 test eax,eax
 cmovs eax,ecx
 xor edx,edx
 div dword [r12+MA_DEN]
 shr eax,3
 mov edx,eax
 imul edx,[r12+MA_C]
 mov ecx,ebp
 sar ecx,3
 cmp edx,ecx
 jle .fine_cap
 mov eax,ebp
 mov ecx,[r12+MA_STEREO]
 sar eax,cl
 sar eax,3
.fine_cap:
 mov edx,8
 cmp eax,edx
 cmovg eax,edx
 mov [r12+rbx*4+180],eax
 mov edx,[r12+MA_DEN]
 shl edx,3
 imul edx,eax
 mov ecx,ebp
 add ecx,[r12+MA_OFFSET]
 cmp edx,ecx
 setge dl
 movzx edx,dl
 mov [r12+rbx*4+264],edx
 imul eax,[r12+MA_C]
 shl eax,3
 sub [r12+rbx*4+96],eax
 jmp .extra_fine
.single_coefficient:
 mov eax,ebp
 sub eax,[r12+MA_FLOOR]
 xor edx,edx
 test eax,eax
 cmovs eax,edx
 mov [r12+MA_EXCESS],eax
 sub ebp,eax
 mov [r12+rbx*4+96],ebp
 mov dword [r12+rbx*4+180],0
 mov dword [r12+rbx*4+264],1
.extra_fine:
 mov eax,[r12+MA_EXCESS]
 test eax,eax
 jle .balance
 mov ecx,[r12+MA_STEREO]
 add ecx,3
 sar eax,cl
 mov edx,8
 sub edx,[r12+rbx*4+180]
 cmp eax,edx
 cmovg eax,edx
 add [r12+rbx*4+180],eax
 imul eax,[r12+MA_C]
 shl eax,3
 mov edx,[r12+MA_EXCESS]
 sub edx,[r12+MA_BAL]
 cmp eax,edx
 setge dl
 movzx edx,dl
 mov [r12+rbx*4+264],edx
 sub [r12+MA_EXCESS],eax
.balance:
 mov eax,[r12+MA_EXCESS]
 mov [r12+MA_BAL],eax
 inc ebx
 cmp ebx,[r12+MA_CODED]
 jb .fine
 movsxd rax,dword [r12+MA_BAL]
 mov [r12+72],rax
 mov eax,[r12+MA_CODED]
 mov [r12+64],rax
 cmp ebx,[r12+MA_END]
 jae .final_budget
.skipped_fine:
 mov eax,[r12+rbx*4+96]
 mov ecx,[r12+MA_STEREO]
 sar eax,cl
 sar eax,3
 mov [r12+rbx*4+180],eax
 mov dword [r12+rbx*4+96],0
 cmp eax,1
 setl al
 movzx eax,al
 mov [r12+rbx*4+264],eax
 inc ebx
 cmp ebx,[r12+MA_END]
 jb .skipped_fine
.final_budget:
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
 cmp rax,[r12+MA_CAP]
 ja .bad
 lea rsi,[r12+64]
 mov rdi,[r12+MA_OUT]
 mov ecx,36
 rep movsq
 mov rsi,r12
 mov rdi,r14
 mov ecx,8
 rep movsq
 xor eax,eax
 jmp .done
.bad:
 mov rax,-1
.done:
 add rsp,1128
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
moalloc_bad:
 mov rax,-1
 ret

; EDI allocation vector0..10,EBX band. Exact positive-only trim.
moalloc_vector:
 imul edi,21
 add edi,ebx
 lea rsi,[rel moalloc_alloc]
 movzx eax,byte [rsi+rdi]
 movzx edx,word [r15+rbx*2+2]
 movzx ecx,word [r15+rbx*2]
 sub edx,ecx
 imul eax,edx
 imul eax,[r12+MA_C]
 mov ecx,[r12+MA_LM]
 shl eax,cl
 sar eax,2
moalloc_trim:
 test eax,eax
 jle .done
 add eax,[r12+rbx*4+604]
 xor edx,edx
 test eax,eax
 cmovs eax,edx
.done:
 ret

; Backwards threshold traversal, done flag sticky across lower bands.
moalloc_clip:
 cmp eax,[r12+rbx*4+520]
 jge .active
 cmp dword [r12+MA_DONE],0
 jne .active
 cmp eax,[r12+MA_FLOOR]
 jge .floor
 xor eax,eax
 ret
.floor:
 mov eax,[r12+MA_FLOOR]
 ret
.active:
 mov dword [r12+MA_DONE],1
 cmp eax,[r12+rbx*4+688]
 cmovg eax,[r12+rbx*4+688]
 ret

; EAX=floor((total-psum)/number of coded coefficients),EDX=remainder.
; Mandatory unsigned celt_udiv, nonzero denominator: codedBands>start.
moalloc_remaining:
 mov ecx,[r12+MA_CODED]
 movzx ecx,word [r15+rcx*2]
 mov esi,[r12+MA_START]
 movzx esi,word [r15+rsi*2]
 sub ecx,esi
 mov eax,[r12+MA_TOTAL]
 sub eax,[r12+MA_PSUM]
 xor edx,edx
 div ecx
 ret

moalloc_ebands:
 dw 0,1,2,3,4,5,6,7,8,10,12,14,16,20,24,28
 dw 34,40,48,60,78,100
moalloc_alloc:
 db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
 db 0,0,0,0,0,90,80,75,69,63,56,49,40,34,29,20
 db 18,10,0,0,0,0,0,0,0,0,110,100,90,84,78,71
 db 65,58,51,45,39,32,26,20,12,0,0,0,0,0,0,118
 db 110,103,93,86,80,75,70,65,59,53,47,40,31,23,15,4
 db 0,0,0,0,126,119,112,104,95,89,83,78,72,66,60,54
 db 47,39,32,25,17,12,1,0,0,134,127,120,114,103,97,91
 db 85,78,72,66,60,54,47,41,35,29,23,16,10,1,144,137
 db 130,124,113,107,101,95,88,82,76,70,64,57,51,45,39,33
 db 26,15,1,152,145,138,132,123,117,111,105,98,92,86,80,74
 db 67,61,55,49,43,36,20,1,162,155,148,142,133,127,121,115
 db 108,102,96,90,84,77,71,65,59,53,46,30,1,172,165,158
 db 152,143,137,131,125,118,112,106,100,94,87,81,75,69,63,56
 db 45,20,200,200,200,200,200,200,200,200,198,193,188,183,178,173
 db 168,163,158,153,148,129,104
moalloc_caps:
 db 224,224,224,224,224,224,224,224,160,160,160,160,185,185,185,178
 db 178,168,134,61,37,224,224,224,224,224,224,224,224,240,240,240
 db 240,207,207,207,198,198,183,144,66,40,160,160,160,160,160,160
 db 160,160,185,185,185,185,193,193,193,183,183,172,138,64,38,240
 db 240,240,240,240,240,240,240,207,207,207,207,204,204,204,193,193
 db 180,143,66,40,185,185,185,185,185,185,185,185,193,193,193,193
 db 193,193,193,183,183,172,138,65,39,207,207,207,207,207,207,207
 db 207,204,204,204,204,201,201,201,188,188,176,141,66,40,193,193
 db 193,193,193,193,193,193,193,193,193,193,194,194,194,184,184,173
 db 139,65,39,204,204,204,204,204,204,204,204,201,201,201,201,198
 db 198,198,187,187,175,140,66,40
moalloc_logn:
 dw 0,0,0,0,0,0,0,0,8,8,8,8,16,16,16,21
 dw 21,24,29,34,36
moalloc_log2frac:
 db 0,8,13,16,19,21,23,24,26,27,28,29,30,31,32,32
 db 33,34,34,35,36,36,37,37
