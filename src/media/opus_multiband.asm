;; MODULE media/opus_multiband
;; LAYER 4
;; EXPORTS media_opus_multiband_decode
;; IMPORTS media_opus_band_decode, media_opus_stereo_band_decode, media_opus_range_bits, media_opus_range_tell, media_opus_range_tell_frac
;; CAPS
;; OWNER rc-codex-av
; UNWIRED Opus1.5.2 quant_all_bands decode consumer. OPUS_NATIVE_MULTIBAND.md.
; RDI=range64*,RSI=readonly config192*. RAX=0/-1; whole staged transaction.
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
; vq.c
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

momb_span:
 test rdi,rdi
 jz momb_bad
 test rdi,rdx
 jnz momb_bad
 mov rax,rdi
 add rax,rsi
 jc momb_bad
 mov r9,rax
 dec r9
 shr r9,47
 jnz momb_bad
 mov [r8],rdi
 mov [r8+8],rax
 xor eax,eax
 ret
media_opus_multiband_decode:
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8808
 mov r12,rsp
 mov r13,rsi
 mov r14,rdi
 mov rdi,r13
 mov esi,192
 mov edx,7
 lea r8,[r12+8448]
 call momb_span
 test rax,rax
 jnz .bad
 mov rsi,r13
 lea rdi,[r12+64]
 mov ecx,24
 rep movsq
 cmp qword [r12+64],20
 ja .bad
 mov rax,[r12+72]
 cmp rax,[r12+64]
 jbe .bad
 cmp rax,21
 ja .bad
 ; Upstream special_hybrid_folding for start19/end21 copies past its
 ; M*(ebands[20]-ebands[start]) normalization history. Refuse that slice
 ; instead of reproducing its out-of-bounds cross-channel scratch alias.
 cmp qword [r12+64],19
 jne .hybrid_geometry_ok
 cmp rax,21
 je .bad
.hybrid_geometry_ok:
 mov rax,[r12+80]
 dec rax
 cmp rax,1
 ja .bad
 cmp qword [r12+88],3
 ja .bad
 cmp qword [r12+96],1
 ja .bad
 cmp qword [r12+104],3
 ja .bad
 cmp qword [r12+112],81600
 ja .bad
 mov eax,0xffffffff
 cmp [r12+120],rax
 ja .bad
 cmp qword [r12+128],1
 ja .bad
 cmp qword [r12+240],0
 jne .bad
 cmp qword [r12+248],0
 jne .bad
 mov ecx,[r12+88]
 mov eax,1
 shl eax,cl
 mov [r12+8192],rax
 mov qword [r12+8200],1
 cmp qword [r12+96],0
 je .B_ready
 mov [r12+8200],rax
.B_ready:
 lea rsi,[rel momb_ebands]
 mov rcx,[r12+64]
 movzx edx,word [rsi+rcx*2]
 imul rdx,rax
 mov [r12+8208],rdx
 mov [r12+8336],rdx
 mov rcx,[r12+72]
 movzx ecx,word [rsi+rcx*2]
 imul rcx,rax
 sub rcx,rdx
 mov [r12+8328],rcx
 mov rdi,r14
 mov esi,64
 mov edx,7
 lea r8,[r12+8464]
 call momb_span
 test rax,rax
 jnz .bad
 call media_opus_range_tell_frac
 test rax,rax
 js .bad
 cmp rax,[r12+136]
 ja .bad
 cmp dword [r14+48],0
 jne .bad
 mov rax,[r14+8]
 shl rax,6
 cmp [r12+136],rax
 ja .bad
 mov qword [r12+8600],2
 mov rdi,[r12+144]
 mov rsi,[r12+152]
 mov eax,288
 cmp rsi,rax
 jb .bad
 mov edx,7
 mov rax,[r12+8600]
 shl rax,4
 lea r8,[r12+8448+rax]
 call momb_span
 test rax,rax
 jnz .bad
 inc qword [r12+8600]
 mov rdi,[r12+160]
 mov rsi,[r12+168]
 mov rax,[r12+72]
 sub rax,[r12+64]
 shl rax,2
 cmp rsi,rax
 jb .bad
 mov edx,3
 mov rax,[r12+8600]
 shl rax,4
 lea r8,[r12+8448+rax]
 call momb_span
 test rax,rax
 jnz .bad
 inc qword [r12+8600]
 mov rdi,[r12+176]
 mov rsi,[r12+184]
 mov rax,[r12+8328]
 add rax,rax
 cmp rsi,rax
 jb .bad
 mov edx,1
 mov rax,[r12+8600]
 shl rax,4
 lea r8,[r12+8448+rax]
 call momb_span
 test rax,rax
 jnz .bad
 inc qword [r12+8600]
 mov rdi,[r12+192]
 mov rsi,[r12+200]
 cmp qword [r12+80],1
 jne .right_present
 test rdi,rdi
 jnz .bad
 test rsi,rsi
 jnz .bad
 jmp .right_done
.right_present:
 mov rax,[r12+8328]
 add rax,rax
 cmp rsi,rax
 jb .bad
 mov edx,1
 mov rax,[r12+8600]
 shl rax,4
 lea r8,[r12+8448+rax]
 call momb_span
 test rax,rax
 jnz .bad
 inc qword [r12+8600]
.right_done:
 mov rdi,[r12+208]
 mov rsi,[r12+216]
 mov rax,[r12+72]
 sub rax,[r12+64]
 imul rax,[r12+80]
 cmp rsi,rax
 jb .bad
 mov edx,0
 mov rax,[r12+8600]
 shl rax,4
 lea r8,[r12+8448+rax]
 call momb_span
 test rax,rax
 jnz .bad
 inc qword [r12+8600]
 mov rdi,[r12+224]
 mov rsi,[r12+232]
 mov eax,32
 cmp rsi,rax
 jb .bad
 mov edx,3
 mov rax,[r12+8600]
 shl rax,4
 lea r8,[r12+8448+rax]
 call momb_span
 test rax,rax
 jnz .bad
 inc qword [r12+8600]
 mov rsi,[r14+8]
 test rsi,rsi
 jz .aliases
 mov rdi,[r14]
 xor edx,edx
 mov rax,[r12+8600]
 shl rax,4
 lea r8,[r12+8448+rax]
 call momb_span
 test rax,rax
 jnz .bad
 inc qword [r12+8600]
.aliases:
 xor ebx,ebx
.outer:
 lea r8,[rbx+1]
 mov rax,rbx
 shl rax,4
 lea r9,[r12+8448+rax]
.inner:
 cmp r8,[r12+8600]
 jae .next_outer
 mov rax,r8
 shl rax,4
 lea r10,[r12+8448+rax]
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
 cmp rbx,[r12+8600]
 jb .outer
 mov rsi,r14
 mov rdi,r12
 mov ecx,8
 rep movsq
 mov rsi,[r12+144]
 lea rdi,[r12+256]
 mov ecx,36
 rep movsq
 mov rax,[r12+256]
 cmp rax,[r12+64]
 jbe .bad
 cmp rax,[r12+72]
 ja .bad
 mov rax,[r12+264]
 cmp rax,-81600
 jl .bad
 cmp rax,81600
 jg .bad
 mov [r12+8272],rax
 mov rax,[r12+272]
 cmp rax,21
 ja .bad
 mov rax,[r12+280]
 cmp rax,1
 ja .bad
 mov [r12+8296],rax
 cmp qword [r12+80],1
 jne .arrays
 test rax,rax
 jnz .bad
.arrays:
 ; Validate the actual allocation record, including inactive zero entries.
 xor ecx,ecx
.alloc_loop:
 mov eax,[r12+288+rcx*4]
 cmp eax,81600
 ja .bad
 cmp dword [r12+372+rcx*4],8
 ja .bad
 cmp dword [r12+456+rcx*4],1
 ja .bad
 cmp rcx,[r12+64]
 jb .inactive
 cmp rcx,[r12+72]
 jb .next_alloc
.inactive:
 or eax,[r12+372+rcx*4]
 or eax,[r12+456+rcx*4]
 jnz .bad
.next_alloc:
 inc ecx
 cmp ecx,21
 jb .alloc_loop
 cmp dword [r12+540],0
 jne .bad
 lea rdi,[r12+544]
 xor eax,eax
 mov ecx,21
 rep stosd
 mov rsi,[r12+160]
 mov rcx,[r12+72]
 sub rcx,[r12+64]
 mov rax,[r12+64]
 lea rdi,[r12+544+rax*4]
 rep movsd
 mov rcx,[r12+64]
.tf_loop:
 movsxd rax,dword [r12+544+rcx*4]
 cmp rax,-3
 jl .bad
 cmp rax,3
 jg .bad
 inc rcx
 cmp rcx,[r12+72]
 jb .tf_loop
 lea rdi,[r12+640]
 xor eax,eax
 mov ecx,800
 rep stosq                    ; X/Y/norm/norm2, four800-i16 arrays
 lea rdi,[r12+7040]
 mov ecx,6
 rep stosq                    ; full42-byte collapse mask array + padding
 mov qword [r12+8216],0        ; lowband_offset
 mov qword [r12+8224],1        ; update_lowband
 mov rax,[r12+120]
 mov [r12+8288],rax            ; seed
 mov rax,[r12+64]
 mov [r12+8232],rax            ; i
.band:
 mov qword [r12+8240],0
 mov rax,[r12+8232]
 inc rax
 cmp rax,[r12+72]
 sete byte [r12+8240]
 mov rbx,[r12+8232]
 lea rsi,[rel momb_ebands]
 movzx eax,word [rsi+rbx*2+2]
 movzx ecx,word [rsi+rbx*2]
 sub eax,ecx
 imul rax,[r12+8192]
 mov [r12+8248],rax
 imul rcx,[r12+8192]
 mov [r12+8384],rcx            ; absolute coefficient offset
 mov rdi,r12
 call media_opus_range_tell_frac
 test rax,rax
 js .bad
 mov [r12+8256],rax
 mov rcx,[r12+112]
 sub rcx,rax
 dec rcx
 mov [r12+8280],rcx            ; exact signed shared remaining
 mov rbx,[r12+8232]
 cmp rbx,[r12+64]
 je .balance_ready
 sub [r12+8272],rax
.balance_ready:
 xor eax,eax
 cmp rbx,[r12+256]
 jae .budget_ready
 mov rcx,[r12+256]
 sub rcx,rbx
 cmp rcx,3
 jbe .divisor_ready
 mov ecx,3
.divisor_ready:
 mov rax,[r12+8272]
 cqo
 idiv rcx
 movsxd rcx,dword [r12+288+rbx*4]
 add rax,rcx
 mov rcx,[r12+8280]
 inc rcx
 cmp rax,rcx
 cmovg rax,rcx
 mov ecx,16383
 cmp rax,rcx
 cmovg rax,rcx
 xor ecx,ecx
 test rax,rax
 cmovs rax,rcx
.budget_ready:
 mov [r12+8264],rax
 ; Update folding position and apply Opus1.5.2 special hybrid copying.
 mov rax,[r12+8384]
 sub rax,[r12+8248]
 cmp rax,[r12+8208]
 jae .can_update
 mov rax,[r12+64]
 inc rax
 cmp rbx,rax
 jne .hybrid
.can_update:
 cmp qword [r12+8224],0
 jne .update
 cmp qword [r12+8216],0
 jne .hybrid
.update:
 mov [r12+8216],rbx
.hybrid:
 mov rax,[r12+64]
 inc rax
 cmp rbx,rax
 jne .fold
 ; n1=M*width(start),n2=M*width(start+1). Copy n2-n1 if positive.
 lea rsi,[rel momb_ebands]
 movzx eax,word [rsi+rbx*2]
 movzx ecx,word [rsi+rbx*2-2]
 sub eax,ecx
 imul rax,[r12+8192]
 movzx edx,word [rsi+rbx*2+2]
 movzx ecx,word [rsi+rbx*2]
 sub edx,ecx
 imul rdx,[r12+8192]
 mov rcx,rdx
 sub rcx,rax
 jle .fold
 mov r8,rax
 add r8,rax
 sub r8,rdx
 lea rsi,[r12+3840+r8*2]
 lea rdi,[r12+3840+rax*2]
 mov r9,rcx
 rep movsw
 cmp qword [r12+8296],0
 je .fold
 lea rsi,[r12+5440+r8*2]
 lea rdi,[r12+5440+rax*2]
 mov rcx,r9
 rep movsw
.fold:
 mov qword [r12+8304],-1       ; effective_lowband
 mov rax,[r12+8200]
 mov ecx,eax
 mov eax,1
 shl eax,cl
 dec eax
 mov [r12+8312],rax
 mov [r12+8320],rax
 mov rbx,[r12+8232]
 movsxd rax,dword [r12+544+rbx*4]
 mov [r12+8344],rax
 cmp qword [r12+8216],0
 je .transition
 cmp qword [r12+104],3
 jne .fold_masks
 cmp qword [r12+8200],1
 ja .fold_masks
 test rax,rax
 jns .transition
.fold_masks:
 mov rcx,[r12+8216]
 lea rsi,[rel momb_ebands]
 movzx eax,word [rsi+rcx*2]
 imul rax,[r12+8192]
 sub rax,[r12+8208]
 sub rax,[r12+8248]
 xor edx,edx
 test rax,rax
 cmovs rax,rdx
 mov [r12+8304],rax
 add rax,[r12+8208]            ; fold begin absolute coefficient
 mov r8,rcx
.find_start:
 dec r8
 movzx edx,word [rsi+r8*2]
 imul rdx,[r12+8192]
 cmp rdx,rax
 ja .find_start
 mov r9,rcx
 dec r9
 add rax,[r12+8248]            ; fold exclusive absolute end
.find_end:
 inc r9
 cmp r9,rbx
 jae .mask_loop_start
 movzx edx,word [rsi+r9*2]
 imul rdx,[r12+8192]
 cmp rdx,rax
 jb .find_end
.mask_loop_start:
 xor eax,eax
 xor edx,edx
.mask_loop:
 mov rcx,r8
 imul rcx,[r12+80]
 movzx edi,byte [r12+7040+rcx]
 or eax,edi
 add rcx,[r12+80]
 movzx edi,byte [r12+7039+rcx]
 or edx,edi
 inc r8
 cmp r8,r9
 jb .mask_loop
 mov [r12+8312],rax
 mov [r12+8320],rdx
.transition:
 cmp qword [r12+8296],0
 je .choose
 mov rax,[r12+8232]
 cmp rax,[r12+272]
 jne .choose
 mov qword [r12+8296],0
 mov rcx,[r12+8384]
 sub rcx,[r12+8208]
 xor ebx,ebx
.average:
 cmp rbx,rcx
 jae .choose
 movsx eax,word [r12+3840+rbx*2]
 movsx edx,word [r12+5440+rbx*2]
 add eax,edx
 sar eax,1
 mov [r12+3840+rbx*2],ax
 inc rbx
 jmp .average
.choose:
 cmp qword [r12+8296],0
 je .joint
 mov qword [r12+8360],1
 mov rax,[r12+8264]
 shr rax,1
 mov [r12+8368],rax
 call momb_channel
 test rax,rax
 js .bad
 mov [r12+8312],rax
 mov qword [r12+8360],2
 call momb_channel
 test rax,rax
 js .bad
 mov [r12+8320],rax
 jmp .after_channels
.joint:
 mov qword [r12+8360],0
 cmp qword [r12+80],2
 je .joint_budget
 mov qword [r12+8360],1
.joint_budget:
 mov rax,[r12+8264]
 mov [r12+8368],rax
 mov rax,[r12+8312]
 or rax,[r12+8320]
 mov [r12+8312],rax
 call momb_channel
 test rax,rax
 js .bad
 mov [r12+8312],rax
 mov [r12+8320],rax
.after_channels:
 mov rcx,[r12+8232]
 imul rcx,[r12+80]
 mov eax,[r12+8312]
 mov [r12+7040+rcx],al
 add rcx,[r12+80]
 mov eax,[r12+8320]
 mov [r12+7039+rcx],al
 mov rcx,[r12+8232]
 movsxd rax,dword [r12+288+rcx*4]
 add rax,[r12+8256]
 add [r12+8272],rax
 mov rax,[r12+8248]
 shl rax,3
 cmp [r12+8264],rax
 setg byte [r12+8224]          ; previous qword is0/1 already
 inc qword [r12+8232]
 mov rax,[r12+8232]
 cmp rax,[r12+72]
 jb .band
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
 cmp rax,[r12+136]
 ja .bad
 mov [r12+8392],rax
 mov eax,[r12+64]
 mov [r12+7088],eax
 mov eax,[r12+72]
 mov [r12+7092],eax
 mov eax,[r12+80]
 mov [r12+7096],eax
 mov eax,[r12+8328]
 mov [r12+7100],eax
 mov eax,[r12+8288]
 mov [r12+7104],eax
 mov eax,[r12+8272]
 mov [r12+7108],eax
 mov eax,[r12+8392]
 mov [r12+7112],eax
 mov eax,[r12+8296]
 mov [r12+7116],eax
 mov rax,[r12+8336]
 lea rsi,[r12+640+rax*2]
 mov rdi,[r13+112]
 mov rcx,[r12+8328]
 rep movsw
 cmp qword [r12+80],2
 jne .publish_masks
 mov rax,[r12+8336]
 lea rsi,[r12+2240+rax*2]
 mov rdi,[r13+128]
 mov rcx,[r12+8328]
 rep movsw
.publish_masks:
 mov rax,[r12+64]
 imul rax,[r12+80]
 lea rsi,[r12+7040+rax]
 mov rdi,[r13+144]
 mov rcx,[r12+72]
 sub rcx,[r12+64]
 imul rcx,[r12+80]
 rep movsb
 lea rsi,[r12+7088]
 mov rdi,[r13+160]
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
 add rsp,8808
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; Private channel: mode0=joint stereo,1=mono X,2=mono Y.
; RAX collapse mask or-1; exact signed shared remaining/seed updated privately.
momb_channel:
 sub rsp,8
 cmp qword [r12+8248],1
 je .n1
 lea rdi,[r12+7168]
 xor eax,eax
 mov ecx,24
 rep stosq
 mov rax,[r12+8232]
 mov [r12+7168],rax
 mov rax,[r12+88]
 mov [r12+7176],rax
 mov rax,[r12+8368]
 mov [r12+7184],rax
 mov rax,[r12+8200]
 mov [r12+7192],rax
 mov rax,[r12+104]
 mov [r12+7200],rax
 cmp qword [r12+8360],0
 je .gain_ready
 mov qword [r12+7208],32767
.gain_ready:
 mov rax,[r12+8280]
 xor edx,edx
 test rax,rax
 cmovs rax,rdx
 mov [r12+7216],rax
 mov rax,[r12+8288]
 mov [r12+7224],rax
 mov rax,[r12+8312]
 cmp qword [r12+8360],2
 jne .fill_ready
 mov rax,[r12+8320]
.fill_ready:
 mov [r12+7232],rax
 mov rax,[r12+136]
 mov [r12+7240],rax
 mov rax,[r12+8384]
 lea rdx,[r12+640+rax*2]
 cmp qword [r12+8360],2
 jne .out_ready
 lea rdx,[r12+2240+rax*2]
.out_ready:
 mov [r12+7248],rdx
 mov rax,[r12+8248]
 add rax,rax
 mov [r12+7256],rax
 lea rax,[r12+7360]
 mov [r12+7280],rax
 mov qword [r12+7288],24
 mov rax,[r12+8344]
 mov [r12+7296],rax
 mov rax,[r12+8304]
 cmp rax,-1
 je .foldout
 lea rsi,[r12+3840+rax*2]
 cmp qword [r12+8360],2
 jne .low_ready
 lea rsi,[r12+5440+rax*2]
.low_ready:
 lea rdi,[r12+7392]
 mov rcx,[r12+8248]
 rep movsw
 lea rax,[r12+7392]
 mov [r12+7264],rax
 mov rax,[r12+8248]
 add rax,rax
 mov [r12+7272],rax
.foldout:
 cmp qword [r12+8240],0
 jne .right
 mov rax,[r12+8384]
 sub rax,[r12+8208]
 lea rdx,[r12+3840+rax*2]
 cmp qword [r12+8360],2
 jne .foldout_ready
 lea rdx,[r12+5440+rax*2]
.foldout_ready:
 mov [r12+7304],rdx
 mov rax,[r12+8248]
 add rax,rax
 mov [r12+7312],rax
.right:
 cmp qword [r12+8360],0
 jne .mono
 mov rax,[r12+8384]
 lea rax,[r12+2240+rax*2]
 mov [r12+7328],rax
 mov rax,[r12+8248]
 add rax,rax
 mov [r12+7336],rax
 mov rax,[r12+272]
 mov [r12+7344],rax
 mov rax,[r12+128]
 mov [r12+7352],rax
 mov rdi,r12
 lea rsi,[r12+7168]
 call media_opus_stereo_band_decode
 jmp .returned
.mono:
 mov rdi,r12
 lea rsi,[r12+7168]
 call media_opus_band_decode
.returned:
 test rax,rax
 js .done
 mov eax,[r12+7368]
 sub [r12+8280],rax
 mov eax,[r12+7376]
 mov [r12+8288],rax
 mov eax,[r12+7380]
 jmp .done
.n1:
 ; quant_band_n1 ignores b,TF,fill,lowband; one sign iff remaining>=8.
 mov rax,[r12+8384]
 lea rbx,[r12+640+rax*2]
 cmp qword [r12+8360],2
 jne .n1_count
 lea rbx,[r12+2240+rax*2]
.n1_count:
 mov ebp,1
 cmp qword [r12+8360],0
 jne .n1_sign
 inc ebp
.n1_sign:
 mov word [rbx],16384
 cmp qword [r12+8280],8
 jl .n1_next
 mov rdi,r12
 mov esi,1
 call media_opus_range_bits
 test rax,rax
 js .done
 sub qword [r12+8280],8
 test eax,eax
 jz .n1_next
 mov word [rbx],-16384
.n1_next:
 dec ebp
 jz .n1_fold
 mov rax,[r12+8384]
 lea rbx,[r12+2240+rax*2]
 jmp .n1_sign
.n1_fold:
 cmp qword [r12+8240],0
 jne .n1_success
 mov rax,[r12+8384]
 lea rsi,[r12+640+rax*2]
 sub rax,[r12+8208]
 lea rdi,[r12+3840+rax*2]
 cmp qword [r12+8360],2
 jne .n1_fold_ready
 add rsi,1600
 add rdi,1600
.n1_fold_ready:
 movsx eax,word [rsi]
 sar eax,4
 mov [rdi],ax
.n1_success:
 mov eax,1
.done:
 add rsp,8
 ret
momb_bad:
 mov rax,-1
 ret
momb_ebands:
 dw 0,1,2,3,4,5,6,7,8,10,12,14,16,20,24,28,34,40,48,60,78,100
