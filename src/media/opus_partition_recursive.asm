;; MODULE media/opus_partition_recursive
;; LAYER 4
;; EXPORTS media_opus_partition_recursive_decode
;; IMPORTS media_opus_partition_decode, media_opus_theta_decode, media_opus_rate_bits_to_pulses, media_opus_rate_pulses_to_bits, media_opus_range_tell, media_opus_range_tell_frac
;; CAPS
;; OWNER rc-codex-av
;
; UNWIRED bounded fixed-point Opus1.5.2 quant_partition recursive consumer.
; Same config128/range64 and six-u32 output ABI as unsplit partition.
; Existing unsplit ABI is retained. Split metadata q=UINT32_MAX and cost
; =total theta plus leaf charge; remaining_after is signed int32 bits.
; Root b/remaining0..81600,LM-1..3,N2..176,B1/2/4/8/16 dividesN.
; Actual standard-mode/cache geometry only. Depth<=4 splits,<=16 leaves.
; All declared caller spans validated before work; private range/vector/meta
; staging ensures pure refusal even after one or more successful children.
; Each active folded leaf retains original sum((abs(low)+4)^2)<=2^29 fence.
; Caller mapped/stable/disjoint storage and serialization required.
; SysV nonvolatiles/FP preserved;DF0. See OPUS_NATIVE_PARTITION_RECURSIVE.md.
;
; Xiph Opus1.5.2 — fixed-point unsplit partition decoding and renormalization
; Archive SHA256: 65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1
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
moprec_span:
 test rdi,rdi
 jz moprec_bad
 test rdi,rdx
 jnz moprec_bad
 mov rax,rdi
 add rax,rsi
 jc moprec_bad
 mov r9,rax
 dec r9
 shr r9,47
 jnz moprec_bad
 mov [r8],rdi
 mov [r8+8],rax
 xor eax,eax
 ret

media_opus_partition_recursive_decode:
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,3144
 mov r12,rsp
 mov r13,rsi
 mov r14,rdi
 mov rdi,r13
 mov esi,128
 mov edx,7
 lea r8,[r12+2848]
 call moprec_span
 test rax,rax
 jnz .bad
 mov rsi,r13
 lea rdi,[r12+2944]
 mov ecx,16
 rep movsq
 cmp qword [r12+2944],20
 ja .bad
 mov rax,[r12+2952]
 cmp rax,-1
 jl .bad
 cmp rax,3
 jg .bad
 cmp qword [r12+2960],81600
 ja .bad
 mov rax,[r12+2968]
 test rax,rax
 jz .bad
 cmp rax,16
 ja .bad
 lea rcx,[rax-1]
 test rax,rcx
 jnz .bad
 cmp qword [r12+2976],3
 ja .bad
 cmp qword [r12+2984],32767
 ja .bad
 cmp qword [r12+2992],81600
 ja .bad
 mov eax,0xffffffff
 cmp [r12+3000],rax
 ja .bad
 cmp qword [r12+3008],65535
 ja .bad
 lea rsi,[rel moprec_ebands]
 mov rax,[r12+2944]
 movzx edx,word [rsi+rax*2+2]
 movzx eax,word [rsi+rax*2]
 sub edx,eax
 mov rcx,[r12+2952]
 cmp rcx,-1
 jne .scale_N
 shr edx,1
 jmp .N_ready
.scale_N:
 shl edx,cl
.N_ready:
 cmp edx,2
 jb .bad
 cmp edx,176
 ja .bad
 mov [r12+3072],rdx
 mov eax,edx
 xor edx,edx
 div dword [r12+2968]
 test edx,edx
 jnz .bad
 mov rdi,r14
 mov esi,64
 mov edx,7
 lea r8,[r12+2864]
 call moprec_span
 test rax,rax
 jnz .bad
 call media_opus_range_tell_frac
 test rax,rax
 js .bad
 cmp rax,[r12+3016]
 ja .bad
 cmp dword [r14+48],0
 jne .bad
 mov rax,[r14+8]
 shl rax,6
 cmp [r12+3016],rax
 ja .bad
 mov rdi,[r12+3024]
 mov rsi,[r12+3032]
 mov rax,[r12+3072]
 add rax,rax
 cmp rsi,rax
 jb .bad
 mov edx,1
 lea r8,[r12+2880]
 call moprec_span
 test rax,rax
 jnz .bad
 mov rdi,[r12+3056]
 mov rsi,[r12+3064]
 cmp rsi,24
 jb .bad
 mov edx,3
 lea r8,[r12+2896]
 call moprec_span
 test rax,rax
 jnz .bad
 mov qword [r12+3112],4
 mov rsi,[r14+8]
 test rsi,rsi
 jz .lowband_span
 mov rdi,[r14]
 xor edx,edx
 lea r8,[r12+2912]
 call moprec_span
 test rax,rax
 jnz .bad
 inc qword [r12+3112]
.lowband_span:
 mov rdi,[r12+3040]
 mov rsi,[r12+3048]
 test rdi,rdi
 jnz .lowband_present
 test rsi,rsi
 jnz .bad
 jmp .aliases
.lowband_present:
 mov rax,[r12+3072]
 add rax,rax
 cmp rsi,rax
 jb .bad
 mov edx,1
 mov rax,[r12+3112]
 shl rax,4
 lea r8,[r12+2848+rax]
 call moprec_span
 test rax,rax
 jnz .bad
 inc qword [r12+3112]
.aliases:
 xor ebx,ebx
.outer:
 lea r8,[rbx+1]
 mov rax,rbx
 shl rax,4
 lea r9,[r12+2848+rax]
.inner:
 cmp r8,[r12+3112]
 jae .next_outer
 mov rax,r8
 shl rax,4
 lea r10,[r12+2848+rax]
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
 cmp rbx,[r12+3112]
 jb .outer
 ; Stage the complete caller transaction before recursive work.
 mov rsi,r14
 mov rdi,r12
 mov ecx,8
 rep movsq
 mov rax,[r12+2992]
 mov [r12+3096],rax
 mov eax,[r12+3000]
 mov [r12+80],eax
 lea rax,[r12+192]
 mov [r12+3024],rax
 mov rax,[r12+3072]
 add rax,rax
 mov [r12+3032],rax
 lea rax,[r12+64]
 mov [r12+3056],rax
 mov qword [r12+3064],24
 mov rdi,r12
 lea rsi,[r12+2944]
 call moprec_node
 test rax,rax
 js .bad
 mov [r12+84],eax
 mov [r12+68],edx
 mov eax,[r12+3072]
 mov [r12+64],eax
 mov rax,[r12+3096]
 mov [r12+76],eax
 mov rcx,[r12+2992]
 sub rcx,rax
 mov [r12+72],ecx
 ; Restore original publication destinations from readonly caller config.
 mov rax,[r13+80]
 mov [r12+3024],rax
 mov rax,[r13+112]
 mov [r12+3056],rax
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
 cmp rax,[r12+3016]
 ja .bad
 lea rsi,[r12+192]
 mov rdi,[r12+3024]
 mov rcx,[r12+3072]
 rep movsw
 lea rsi,[r12+64]
 mov rdi,[r12+3056]
 mov ecx,6
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
 add rsp,3144
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; Internal bounded recursion. RDI=private root context, RSI=node config.
; Returns RAX=collapse mask or -1, EDX=q (UINT32_MAX for a split).
; Root context owns shared range, signed remaining and seed. Each activation
; owns its config/theta/result and child bookkeeping. 440+48 saved bytes.
moprec_node:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,440
 mov r12,rdi
 mov r13,rsp
 mov rdi,r13
 mov ecx,16
 rep movsq
 mov rax,[r12+3096]
 xor edx,edx
 test rax,rax
 cmovs rax,rdx
 mov [r13+48],rax
 mov eax,[r12+80]
 mov [r13+56],rax
 ; Recompute source-derived N for this LM; split descendants inherit valid
 ; cache entries, geometry and capacities from their validated root.
 lea rsi,[rel moprec_ebands]
 mov rax,[r13]
 movzx edx,word [rsi+rax*2+2]
 movzx eax,word [rsi+rax*2]
 sub edx,eax
 mov rcx,[r13+8]
 cmp rcx,-1
 jne .scale
 shr edx,1
 jmp .geometry
.scale:
 shl edx,cl
.geometry:
 mov [r13+320],rdx
 mov rdi,[r13]
 mov rsi,[r13+8]
 mov edx,81600
 call media_opus_rate_bits_to_pulses
 test rax,rax
 js .bad
 mov rdx,rax
 mov rdi,[r13]
 mov rsi,[r13+8]
 call media_opus_rate_pulses_to_bits
 test rax,rax
 js .bad
 cmp qword [r13+8],-1
 je .leaf
 cmp qword [r13+320],2
 jbe .leaf
 add rax,11
 cmp [r13+16],rax
 ja .split
.leaf:
 lea rax,[r13+288]
 mov [r13+112],rax
 mov qword [r13+120],24
 mov rdi,r12
 mov rsi,r13
 call media_opus_partition_decode
 test rax,rax
 js .bad
 mov eax,[r13+296]             ; leaf cost, zero if remaining was negative
 sub [r12+3096],rax
 mov eax,[r13+304]
 mov [r12+80],eax
 mov eax,[r13+308]
 mov edx,[r13+292]
 jmp .done
.split:
 shr qword [r13+320],1
 dec qword [r13+8]
 mov rax,[r13+24]
 mov [r13+336],rax             ; B0
 mov ecx,eax
 mov edx,1
 shl edx,cl
 dec edx
 and [r13+64],rdx             ; inactive high fill bits never reach a child
 cmp eax,1
 jne .blocks
 mov rdx,[r13+64]
 mov rcx,rdx
 and edx,1
 shl rcx,1
 or rdx,rcx
 mov [r13+64],rdx
.blocks:
 inc eax
 shr eax,1
 mov [r13+24],rax
 ; Exact mono compute_theta configuration, using the accepted public helper.
 lea rdi,[r13+128]
 xor eax,eax
 mov ecx,16
 rep stosq
 mov rax,[r13+320]
 mov [r13+128],rax
 mov rax,[r13+16]
 mov [r13+136],rax
 mov rax,[r13+24]
 mov [r13+144],rax
 mov rax,[r13+336]
 mov [r13+152],rax
 mov rax,[r13+8]
 mov [r13+160],rax
 mov rax,[r13]
 mov [r13+176],rax
 mov rax,[r13+48]
 mov [r13+200],rax
 mov rax,[r13+64]
 mov [r13+208],rax
 mov rax,[r13+72]
 mov [r13+216],rax
 lea rax,[r13+256]
 mov [r13+224],rax
 mov qword [r13+232],32
 mov rdi,r12
 lea rsi,[r13+128]
 call media_opus_theta_decode
 test rax,rax
 js .bad
 movsxd rax,dword [r13+276]    ; qalloc
 sub [r12+3096],rax
 mov eax,[r13+272]             ; itheta
 mov [r13+368],rax
 mov edx,[r13+268]             ; delta
 cmp qword [r13+336],1
 jbe .allocation
 test eax,0x3fff
 jz .allocation
 cmp eax,8192
 jbe .forward_mask
 mov ecx,4
 sub ecx,[r13+8]
 mov eax,edx
 sar eax,cl
 sub edx,eax
 jmp .allocation
.forward_mask:
 mov eax,[r13+320]
 shl eax,3
 mov ecx,5
 sub ecx,[r13+8]
 sar eax,cl
 add edx,eax
 xor eax,eax
 test edx,edx
 cmovg edx,eax
.allocation:
 mov eax,[r13+280]             ; b after theta
 mov ebx,eax
 sub eax,edx
 cdq
 mov ecx,2
 idiv ecx                     ; C signed /2 truncates toward zero
 xor edx,edx
 test eax,eax
 cmovs eax,edx
 cmp eax,ebx
 cmovg eax,ebx
 mov [r13+344],rax             ; mbits
 sub ebx,eax
 mov [r13+352],rbx             ; sbits
 mov rax,[r12+3096]
 mov [r13+360],rax             ; saved remaining after angle
 mov rax,[r13+80]
 mov [r13+408],rax
 mov rax,[r13+96]
 mov [r13+416],rax
 mov eax,[r13+284]
 mov [r13+424],rax             ; fill after theta
 mov eax,[r13+40]
 imul eax,[r13+260]
 add eax,16384
 sar eax,15
 mov [r13+392],rax
 mov eax,[r13+40]
 imul eax,[r13+264]
 add eax,16384
 sar eax,15
 mov [r13+400],rax
 xor eax,eax
 mov rcx,[r13+344]
 cmp rcx,[r13+352]
 setb al
 mov [r13+376],rax             ; larger allocation child first; ties mid
 call .child
 test rax,rax
 js .bad
 mov [r13+384],rax
 mov rax,[r13+360]
 sub rax,[r12+3096]            ; charge of first child
 mov rcx,[r13+376]
 mov rdx,[r13+344+rcx*8]
 sub rdx,rax                  ; unused allocation
 cmp rdx,24
 jle .second
 cmp rcx,0
 jne .first_side
 cmp qword [r13+368],0
 je .second
 sub rdx,24
 add [r13+352],rdx
 jmp .second
.first_side:
 cmp qword [r13+368],16384
 je .second
 sub rdx,24
 add [r13+344],rdx
.second:
 mov rax,[r13+376]
 xor eax,1
 call .child
 test rax,rax
 js .bad
 or rax,[r13+384]
 mov edx,0xffffffff
 jmp .done
; RAX=side selector. Prepare child config in this activation. The child
; copies it before making any changes. Collapse side bits shift by B0/2.
.child:
 sub rsp,8
 mov r15,rax
 mov rdx,[r13+344+rax*8]
 mov [r13+16],rdx
 mov rdx,[r13+392+rax*8]
 mov [r13+40],rdx
 imul rax,[r13+320]
 add rax,rax
 mov rdx,[r13+408]
 add rdx,rax
 mov [r13+80],rdx
 mov rdx,[r13+320]
 add rdx,rdx
 mov [r13+88],rdx
 mov rdx,[r13+416]
 test rdx,rdx
 jz .child_low
 add rdx,rax
.child_low:
 mov [r13+96],rdx
 xor ecx,ecx
 test rdx,rdx
 jz .child_low_cap
 mov rcx,[r13+88]
.child_low_cap:
 mov [r13+104],rcx
 mov rax,[r13+424]
 test r15,r15
 jz .child_fill
 mov ecx,[r13+24]
 shr rax,cl
.child_fill:
 mov [r13+64],rax
 mov rdi,r12
 mov rsi,r13
 call moprec_node
 test rax,rax
 js .child_done
 test r15,r15
 jz .child_done
 mov ecx,[r13+336]
 shr ecx,1
 shl eax,cl
.child_done:
 add rsp,8
 ret
.bad:
 mov rax,-1
.done:
 add rsp,440
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
moprec_bad:
 mov rax,-1
 ret
moprec_ebands:
 dw 0,1,2,3,4,5,6,7,8,10,12,14,16,20,24,28,34,40,48,60,78,100
