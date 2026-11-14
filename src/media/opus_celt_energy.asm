;; MODULE media/opus_celt_energy
;; LAYER 4
;; EXPORTS media_opus_celt_energy, media_opus_laplace
;; IMPORTS media_opus_range_decode, media_opus_range_update, media_opus_range_bit, media_opus_range_icdf, media_opus_range_bits, media_opus_range_tell
;; CAPS
;; OWNER rc-codex-av
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

; Laplace source copyright (c) 2007 CSIRO; written by Jean-Marc Valin.
;
; Fixed-point CELT energy stage, Xiph Opus 1.5.2 quant_bands.c/laplace.c.
; Private UNWIRED; standard 48kHz mode only (21 bands), C1..2, LM0..3.
; No PCM, allocation, mutable globals, floating point, synthesis or device use.
;
; laplace(RDI=range64*,RSI=fs0 1..32736,RDX=decay Q14 0..16384):
; returns ZERO-EXTENDED signed int32 delta in RAX, or full64 -1 on refusal.
; Thus delta -1 is 0x00000000ffffffff and distinct from refusal. Sticky errors
; and implicit zero padding match the entropy primitives; caller owns budgets.
;
; celt_energy(RDI=range64*,RSI=int16 history[C*21],RDX=config64*) ->0/-1.
; history is log2 energy Q10, channel-major, updated only in [start,end).
; Config is eight u64: fine_quant*,priority*,stage,start,end,C,option,intra.
; stage0 coarse: option=LM0..3, intra0/1 already decoded by caller, pointers0.
; stage1 fine: int32 fine_quant[21] in0..8, priority0, option0,intra0.
; stage2 final: fine_quant[21],int32 priority[21] in0..1, option=bits_left
; 0..10200, intra0. Tables are immutable, can alias each other/other read spans.
; Each exact span must be stably mapped for the whole serialized call; full64
; lower-canonical, history aligned2, tables aligned4, range/config aligned8.
; Mutable state/history disjoint from each other and all read spans/frame.
; Every entry validates all21 table entries, even outside the selected bands.
; Initial/final tell<=8*storage, error0 required. Stage copies state+history to
; bounded stack storage before decoding; all failure paths publish nothing.
; Mathematical intermediates must fit int32 and history int16; malformed
; extremes refuse instead of relying on C overflow/conversion behavior.
; SysV preserved nonvolatiles/RSP; DF0; FP untouched. Caller truthfully supplies
; mapped extents; canonical arithmetic checks cannot establish mapped memory.

; Laplace decoder, the minimum-probability tail is computed in constant time.
media_opus_laplace:
 cld
 cmp rsi,1
 jb moce_bad
 cmp rsi,32736
 ja moce_bad
 cmp rdx,16384
 ja moce_bad
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8
 mov rbx,rdi
 mov r12d,esi
 mov r13d,edx
 mov esi,32768
 call media_opus_range_decode
 test rax,rax
 js .bad
 mov r14d,eax
 xor r15d,r15d                    ; val
 xor ebp,ebp                      ; low
 cmp r14d,r12d
 jb .update
 mov r15d,1
 mov ebp,r12d
 mov eax,32736
 sub eax,r12d
 mov ecx,16384
 sub ecx,r13d
 imul eax,ecx
 shr eax,15
 lea r12d,[rax+1]
.loop:
 cmp r12d,1
 jbe .tail
 lea eax,[r12*2]
 add eax,ebp
 cmp r14d,eax
 jb .sign
 shl r12d,1
 add ebp,r12d
 sub r12d,2
 imul r12d,r13d
 shr r12d,15
 inc r12d
 inc r15d
 jmp .loop
.tail:
 mov eax,r14d
 sub eax,ebp
 shr eax,1
 add r15d,eax
 lea ebp,[rbp+rax*2]
.sign:
 lea eax,[rbp+r12]
 cmp r14d,eax
 jae .positive
 neg r15d
 jmp .update
.positive:
 add ebp,r12d
.update:
 mov rdi,rbx
 mov esi,ebp
 lea edx,[rbp+r12]
 mov ecx,32768
 cmp edx,ecx
 cmova edx,ecx
 call media_opus_range_update
 test rax,rax
 js .bad
 mov eax,r15d                     ; zero-extended signed result, not failure
 jmp .done
.bad:
 mov rax,-1
.done:
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; Check a nonempty lower-canonical span: RDI start,RSI bytes,RDX alignment mask.
; Returns end/-1, preserves arguments, clobbers R8.
moce_span:
 test rdi,rdi
 jz moce_bad
 test rdi,rdx
 jnz moce_bad
 mov rax,rdi
 add rax,rsi
 jc moce_bad
 mov r8,rax
 dec r8
 shr r8,47
 jnz moce_bad
 ret

; A read span must not overlap the ORIGINAL mutable range or history. rbp owns
; the local frame, rbx original range, r12 original history, [rbp+336] its bytes.
moce_read_span:
 call moce_span
 test rax,rax
 js moce_bad
 cmp rbx,rax
 jae .history
 lea r8,[rbx+64]
 cmp rdi,r8
 jb moce_bad
.history:
 cmp r12,rax
 jae .ok
 mov r8,[rbp+336]
 add r8,r12
 cmp rdi,r8
 jb moce_bad
.ok:
 ret

media_opus_celt_energy:
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,360
 mov rbp,rsp
 mov rbx,rdi
 mov r12,rsi
 mov [rbp+232],rdx                ; original config
 mov esi,64
 mov edx,7
 call moce_span
 test rax,rax
 js .bad
 mov rdi,[rbp+232]
 call moce_span
 test rax,rax
 js .bad
 lea r14,[rbp+152]
 mov rsi,rdi
 mov rdi,r14
 mov ecx,8
 rep movsq                       ; config snapshot before any mutable operation
 cmp qword [r14+16],2
 ja .bad
 mov rax,[r14+24]
 cmp rax,[r14+32]
 ja .bad
 cmp qword [r14+32],21
 ja .bad
 mov rax,[r14+40]
 cmp rax,1
 jb .bad
 cmp rax,2
 ja .bad
 imul rsi,rax,42
 mov [rbp+336],rsi
 mov rdi,r12
 mov edx,1
 call moce_span
 test rax,rax
 js .bad
 cmp rbx,rax
 jae .history_ok
 lea r8,[rbx+64]
 cmp r12,r8
 jb .bad
.history_ok:
 mov rdi,[rbp+232]
 mov esi,64
 mov edx,7
 call moce_read_span
 test rax,rax
 js .bad
 mov rdi,rbx
 call media_opus_range_tell      ; validates full original range and frame span
 test rax,rax
 js .bad
 cmp dword [rbx+48],0
 jne .bad
 mov rcx,[rbx+8]
 shl rcx,3
 mov [rbp+312],rcx
 cmp rax,rcx
 ja .bad
 mov rsi,[rbx+8]
 test rsi,rsi
 jz .frame_ok
 mov rdi,[rbx]
 xor edx,edx
 call moce_read_span
 test rax,rax
 js .bad
.frame_ok:
 cmp qword [r14+16],0
 jne .fine_config
 cmp qword [r14],0
 jne .bad
 cmp qword [r14+8],0
 jne .bad
 cmp qword [r14+48],3
 ja .bad
 cmp qword [r14+56],1
 ja .bad
 jmp .copy
.fine_config:
 cmp qword [r14+56],0
 jne .bad
 mov rdi,[r14]
 mov esi,84
 mov edx,3
 call moce_read_span
 test rax,rax
 js .bad
 xor ecx,ecx
.check_fine:
 cmp dword [rdi+rcx*4],8
 ja .bad
 inc ecx
 cmp ecx,21
 jb .check_fine
 cmp qword [r14+16],2
 je .final_config
 cmp qword [r14+48],0
 jne .bad
 cmp qword [r14+8],0
 jne .bad
 jmp .copy
.final_config:
 cmp qword [r14+48],10200
 ja .bad
 mov rdi,[r14+8]
 call moce_read_span
 test rax,rax
 js .bad
 xor ecx,ecx
.check_priority:
 cmp dword [rdi+rcx*4],1
 ja .bad
 inc ecx
 cmp ecx,21
 jb .check_priority
.copy:
 mov rsi,rbx
 mov rdi,rbp
 mov ecx,8
 rep movsq
 lea r13,[rbp+64]
 mov rdi,r13
 mov rsi,r12
 mov rcx,[rbp+336]
 shr rcx,1
 rep movsw
 cmp qword [r14+16],0
 je .coarse
 cmp qword [r14+16],1
 je .fine
 jmp .final

.coarse:
 mov qword [rbp+240],0
 mov qword [rbp+248],0
 xor eax,eax
 mov edx,4915
 cmp qword [r14+56],0
 jne .coefficients
 lea rcx,[rel moce_pred]
 mov rsi,[r14+48]
 movzx eax,word [rcx+rsi*2]
 lea rcx,[rel moce_beta]
 movzx edx,word [rcx+rsi*2]
.coefficients:
 mov [rbp+256],rax
 mov [rbp+264],rdx
 mov rax,[r14+48]
 shl rax,1
 add rax,[r14+56]
 imul rax,42
 lea rcx,[rel moce_prob]
 add rax,rcx
 mov [rbp+272],rax
 mov r15,[r14+24]
.coarse_band:
 cmp r15,[r14+32]
 jae .commit_check
 mov qword [rbp+288],0
.coarse_channel:
 mov rdi,rbp
 call media_opus_range_tell
 mov rcx,[rbp+312]
 sub rcx,rax
 cmp rcx,15
 jb .small
 mov rcx,[rbp+272]
 movzx esi,byte [rcx+r15*2]
 movzx edx,byte [rcx+r15*2+1]
 shl esi,7
 shl edx,6
 mov rdi,rbp
 call media_opus_laplace
 test rax,rax
 js .bad
 movsxd rax,eax
 jmp .reconstruct
.small:
 cmp rcx,2
 jb .one_bit
 mov rdi,rbp
 lea rsi,[rel moce_small]
 mov edx,3
 mov ecx,2
 call media_opus_range_icdf
 test rax,rax
 js .bad
 mov edx,eax
 and edx,1
 neg edx
 shr eax,1
 xor eax,edx
 movsxd rax,eax
 jmp .reconstruct
.one_bit:
 mov rax,-1
 cmp rcx,1
 jb .reconstruct
 mov rdi,rbp
 mov esi,1
 call media_opus_range_bit
 test rax,rax
 js .bad
 neg rax
.reconstruct:
 mov r9,rax
 shl r9,10                        ; q in Q10
 mov r10,[rbp+288]
 imul rcx,r10,21
 add rcx,r15
 movsx rax,word [r13+rcx*2]
 mov rdx,-9216
 cmp rax,rdx
 cmovl rax,rdx
 imul rax,[rbp+256]
 add rax,128
 sar rax,8
 add rax,[rbp+r10*8+240]
 mov rdx,r9
 shl rdx,7
 add rax,rdx
 movsxd rdx,eax
 cmp rax,rdx
 jne .bad
 mov rdx,-3670016                 ; -28 in Q17
 cmp rax,rdx
 cmovl rax,rdx
 add rax,64
 sar rax,7                        ; PSHR32(tmp,7), Q10
 cmp rax,-32768
 jl .bad
 cmp rax,32767
 jg .bad
 mov [r13+rcx*2],ax
 mov rax,r9
 add rax,128
 sar rax,8
 imul rax,[rbp+264]
 shl r9,7
 sub r9,rax
 add r9,[rbp+r10*8+240]
 movsxd rax,r9d
 cmp rax,r9
 jne .bad
 mov [rbp+r10*8+240],r9
 inc qword [rbp+288]
 mov rax,[rbp+288]
 cmp rax,[r14+40]
 jb .coarse_channel
 inc r15
 jmp .coarse_band

.fine:
 mov r15,[r14+24]
.fine_band:
 cmp r15,[r14+32]
 jae .commit_check
 mov rcx,[r14]
 mov esi,[rcx+r15*4]
 test esi,esi
 jz .fine_next
 mov qword [rbp+288],0
.fine_channel:
 mov rcx,[r14]
 mov esi,[rcx+r15*4]
 mov rdi,rbp
 call media_opus_range_bits
 test rax,rax
 js .bad
 mov rdx,[r14]
 mov ecx,[rdx+r15*4]
 shl eax,10
 add eax,512
 shr eax,cl
 sub eax,512
 call moce_add_energy
 test rax,rax
 js .bad
 inc qword [rbp+288]
 mov rax,[rbp+288]
 cmp rax,[r14+40]
 jb .fine_channel
.fine_next:
 inc r15
 jmp .fine_band

.final:
 mov rax,[r14+48]
 mov [rbp+304],rax
 mov qword [rbp+296],0
.final_priority:
 mov r15,[r14+24]
.final_band:
 cmp r15,[r14+32]
 jae .next_priority
 mov rax,[rbp+304]
 cmp rax,[r14+40]
 jb .next_priority
 mov rcx,[r14]
 cmp dword [rcx+r15*4],8
 jae .final_next
 mov rcx,[r14+8]
 mov eax,[rcx+r15*4]
 cmp rax,[rbp+296]
 jne .final_next
 mov qword [rbp+288],0
.final_channel:
 mov rdi,rbp
 mov esi,1
 call media_opus_range_bits
 test rax,rax
 js .bad
 mov rdx,[r14]
 mov ecx,[rdx+r15*4]
 inc ecx
 shl eax,10
 sub eax,512
 sar eax,cl
 call moce_add_energy
 test rax,rax
 js .bad
 dec qword [rbp+304]
 inc qword [rbp+288]
 mov rax,[rbp+288]
 cmp rax,[r14+40]
 jb .final_channel
.final_next:
 inc r15
 jmp .final_band
.next_priority:
 inc qword [rbp+296]
 cmp qword [rbp+296],2
 jb .final_priority

.commit_check:
 mov rdi,rbp
 call media_opus_range_tell
 test rax,rax
 js .bad
 cmp rax,[rbp+312]
 ja .bad
 cmp dword [rbp+48],0
 jne .bad
 mov rsi,rbp
 mov rdi,rbx
 mov ecx,8
 rep movsq
 mov rsi,r13
 mov rdi,r12
 mov rcx,[rbp+336]
 shr rcx,1
 rep movsw
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

; Add signed Q10 offset EAX to the selected staged band, checking int16 range.
moce_add_energy:
 mov rcx,[rbp+288]
 imul rcx,21
 add rcx,r15
 movsx edx,word [r13+rcx*2]
 add eax,edx
 cmp eax,-32768
 jl moce_bad
 cmp eax,32767
 jg moce_bad
 mov [r13+rcx*2],ax
 xor eax,eax
 ret

moce_bad:
 mov rax,-1
 ret

align 2
moce_pred: dw 29440,26112,21248,16384
moce_beta: dw 30147,22282,12124,6554
moce_small: db 2,1,0
; Exact Q8 probability model, each first probability <<7 (Q15) and decay <<6
; (Q14), indexed [LM][intra][band][2]. Standard bands0..20 only.
moce_prob:
 db 72,127,65,129,66,128,65,128,64,128,62,128,64,128
 db 64,128,92,78,92,79,92,78,90,79,116,41,115,40
 db 114,40,132,26,132,26,145,17,161,12,176,10,177,11
 db 24,179,48,138,54,135,54,132,53,134,56,133,55,132
 db 55,132,61,114,70,96,74,88,75,88,87,74,89,66
 db 91,67,100,59,108,50,120,40,122,37,97,43,78,50
 db 83,78,84,81,88,75,86,74,87,71,90,73,93,74
 db 93,74,109,40,114,36,117,34,117,34,143,17,145,18
 db 146,19,162,12,165,10,178,7,189,6,190,8,177,9
 db 23,178,54,115,63,102,66,98,69,99,74,89,71,91
 db 73,91,78,89,86,80,92,66,93,64,102,59,103,60
 db 104,60,117,52,123,44,138,35,133,31,97,38,77,45
 db 61,90,93,60,105,42,107,41,110,45,116,38,113,38
 db 112,38,124,26,132,27,136,19,140,20,155,14,159,16
 db 158,18,170,13,177,10,187,8,192,6,175,9,159,10
 db 21,178,59,110,71,86,75,85,84,83,91,66,88,73
 db 87,72,92,75,98,72,105,58,107,54,115,52,114,55
 db 112,56,129,51,132,40,150,33,140,29,98,35,77,42
 db 42,121,96,66,108,43,111,40,117,44,123,32,120,36
 db 119,33,127,33,134,34,139,21,147,23,152,20,158,25
 db 154,26,166,21,173,16,184,13,184,10,150,13,139,15
 db 22,178,63,114,74,82,84,83,92,82,103,62,96,72
 db 96,67,101,73,107,72,113,55,118,52,125,52,118,52
 db 117,55,135,49,137,39,157,32,145,29,97,33,77,40
