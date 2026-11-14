;; MODULE media/opus_stereo_band
;; LAYER 4
;; EXPORTS media_opus_stereo_band_decode
;; IMPORTS media_opus_band_decode, media_opus_theta_decode, media_opus_stereo_merge, media_opus_range_bits, media_opus_range_tell, media_opus_range_tell_frac
;; CAPS
;; OWNER rc-codex-av
; UNWIRED Opus1.5.2 quant_band_stereo consumer. See OPUS_NATIVE_STEREO_BAND.md.
; RDI=range64*,RSI=readonly config192*; returns0/-1, full staged transaction.
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
mostband_span:
 test rdi,rdi
 jz mostband_bad
 test rdi,rdx
 jnz mostband_bad
 mov rax,rdi
 add rax,rsi
 jc mostband_bad
 mov r9,rax
 dec r9
 shr r9,47
 jnz mostband_bad
 mov [r8],rdi
 mov [r8+8],rax
 xor eax,eax
 ret

media_opus_stereo_band_decode:
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,4328
 mov r12,rsp
 mov r13,rsi
 mov r14,rdi
 mov rdi,r13
 mov esi,192
 mov edx,7
 lea r8,[r12+2848]
 call mostband_span
 test rax,rax
 jnz .bad
 mov rsi,r13
 lea rdi,[r12+3200]
 mov ecx,24
 rep movsq
 cmp qword [r12+3200],20
 ja .bad
 mov rax,[r12+3208]
 cmp rax,-1
 jl .bad
 cmp rax,3
 jg .bad
 cmp qword [r12+3216],81600
 ja .bad
 mov rax,[r12+3224]
 test rax,rax
 jz .bad
 cmp rax,8
 ja .bad
 lea rcx,[rax-1]
 test rax,rcx
 jnz .bad
 cmp qword [r12+3232],3
 ja .bad
 cmp qword [r12+3240],0
 jne .bad
 cmp qword [r12+3248],81600
 ja .bad
 mov eax,0xffffffff
 cmp [r12+3256],rax
 ja .bad
 cmp qword [r12+3264],65535
 ja .bad
 lea rsi,[rel mostband_ebands]
 mov rax,[r12+3200]
 movzx edx,word [rsi+rax*2+2]
 movzx eax,word [rsi+rax*2]
 sub edx,eax
 mov rcx,[r12+3208]
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
 mov [r12+4000],rdx
 mov eax,edx
 xor edx,edx
 div dword [r12+3224]
 test edx,edx
 jnz .bad
 mov rdi,r14
 mov esi,64
 mov edx,7
 lea r8,[r12+2864]
 call mostband_span
 test rax,rax
 jnz .bad
 call media_opus_range_tell_frac
 test rax,rax
 js .bad
 cmp rax,[r12+3272]
 ja .bad
 cmp dword [r14+48],0
 jne .bad
 mov rax,[r14+8]
 shl rax,6
 cmp [r12+3272],rax
 ja .bad
 mov rdi,[r12+3280]
 mov rsi,[r12+3288]
 mov rax,[r12+4000]
 add rax,rax
 cmp rsi,rax
 jb .bad
 mov edx,1
 lea r8,[r12+2880]
 call mostband_span
 test rax,rax
 jnz .bad
 mov rdi,[r12+3312]
 mov rsi,[r12+3320]
 cmp rsi,24
 jb .bad
 mov edx,3
 lea r8,[r12+2896]
 call mostband_span
 test rax,rax
 jnz .bad
 mov qword [r12+3400],4
 mov rsi,[r14+8]
 test rsi,rsi
 jz .lowband_span
 mov rdi,[r14]
 xor edx,edx
 lea r8,[r12+2912]
 call mostband_span
 test rax,rax
 jnz .bad
 inc qword [r12+3400]
.lowband_span:
 mov rdi,[r12+3296]
 mov rsi,[r12+3304]
 test rdi,rdi
 jnz .lowband_present
 test rsi,rsi
 jnz .bad
 jmp .foldout_span
.lowband_present:
 mov rax,[r12+4000]
 add rax,rax
 cmp rsi,rax
 jb .bad
 mov edx,1
 mov rax,[r12+3400]
 shl rax,4
 lea r8,[r12+2848+rax]
 call mostband_span
 test rax,rax
 jnz .bad
 inc qword [r12+3400]
.foldout_span:
 cmp qword [r12+3352],0
 jne .bad
 mov rax,[r12+3328]
 cmp rax,-3
 jl .bad
 cmp rax,3
 jg .bad
 mov rdi,[r12+3336]
 mov rsi,[r12+3344]
 test rdi,rdi
 jnz .foldout_present
 test rsi,rsi
 jnz .bad
 jmp .right_span
.foldout_present:
 mov rax,[r12+4000]
 add rax,rax
 cmp rsi,rax
 jb .bad
 mov edx,1
 mov rax,[r12+3400]
 shl rax,4
 lea r8,[r12+2848+rax]
 call mostband_span
 test rax,rax
 jnz .bad
 inc qword [r12+3400]
.right_span:
 cmp qword [r12+3376],21
 ja .bad
 cmp qword [r12+3384],1
 ja .bad
 mov rcx,[r12+3224]
 mov eax,1
 shl eax,cl
 dec eax
 cmp [r12+3264],rax
 ja .bad
 mov rdi,[r12+3360]
 mov rsi,[r12+3368]
 mov rax,[r12+4000]
 add rax,rax
 cmp rsi,rax
 jb .bad
 mov edx,1
 mov rax,[r12+3400]
 shl rax,4
 lea r8,[r12+2848+rax]
 call mostband_span
 test rax,rax
 jnz .bad
 inc qword [r12+3400]
.aliases:
 xor ebx,ebx
.outer:
 lea r8,[rbx+1]
 mov rax,rbx
 shl rax,4
 lea r9,[r12+2848+rax]
.inner:
 cmp r8,[r12+3400]
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
 cmp rbx,[r12+3400]
 jb .outer


 ; Entire caller transaction remains private through both channel decodes.
 mov rsi,r14
 mov rdi,r12
 mov ecx,8
 rep movsq
 mov rax,[r12+3248]
 mov [r12+4008],rax             ; signed shared remaining
 mov [r12+4096],rax             ; initial remaining for total charge
 mov rax,[r12+3256]
 mov [r12+4016],rax             ; shared unsigned seed
 mov qword [r12+4024],0         ; collapse mask
 mov qword [r12+4144],0         ; normal channel policy
 lea rdi,[r12+1800]
 xor eax,eax
 mov ecx,16
 rep stosq
 mov rax,[r12+4000]
 mov [r12+1800],rax
 mov rax,[r12+3216]
 mov [r12+1808],rax
 mov rax,[r12+3224]
 mov [r12+1816],rax
 mov [r12+1824],rax
 mov rax,[r12+3208]
 mov [r12+1832],rax
 mov qword [r12+1840],1
 mov rax,[r12+3200]
 mov [r12+1848],rax
 mov rax,[r12+3376]
 mov [r12+1856],rax
 mov rax,[r12+3384]
 mov [r12+1864],rax
 mov rax,[r12+4008]
 mov [r12+1872],rax
 mov rax,[r12+3264]
 mov [r12+1880],rax
 mov rax,[r12+3272]
 mov [r12+1888],rax
 lea rax,[r12+1928]
 mov [r12+1896],rax
 mov qword [r12+1904],32
 mov rdi,r12
 lea rsi,[r12+1800]
 call media_opus_theta_decode
 test rax,rax
 js .bad
 mov eax,[r12+1928]
 mov [r12+4088],rax             ; inv
 mov eax,[r12+1932]
 mov [r12+4072],rax             ; mid
 mov eax,[r12+1936]
 mov [r12+4080],rax             ; side
 mov eax,[r12+1944]
 mov [r12+4064],rax             ; itheta
 movsxd rax,dword [r12+1948]
 sub [r12+4008],rax             ; qalloc charged once
 movsxd rax,dword [r12+1952]
 mov [r12+4032],rax             ; b_after, later mbits
 mov eax,[r12+1956]
 mov [r12+3264],rax             ; fill after theta
 cmp qword [r12+4000],2
 jne .normal
 ; N=2 uses one raw orthogonal-sign bit for an interior angle.
 mov qword [r12+4144],1
 mov qword [r12+4104],1         ; sign=+1 by default
 mov rax,[r13+64]
 mov [r12+3264],rax             ; dominant vector uses original fill
 cmp qword [r12+4064],0
 je .n2_decode
 cmp qword [r12+4064],16384
 je .n2_decode
 sub qword [r12+4032],8
 sub qword [r12+4008],8
 mov rdi,r12
 mov esi,1
 call media_opus_range_bits
 test rax,rax
 js .bad
 add eax,eax
 mov ecx,1
 sub ecx,eax
 movsxd rcx,ecx
 mov [r12+4104],rcx
.n2_decode:
 xor edi,edi
 cmp qword [r12+4064],8192
 seta dil
 mov [r12+4056],rdi             ; dominant vector is Y iff theta>8192
 mov rsi,[r12+4032]
 mov edx,32767
 call mostband_channel
 test rax,rax
 js .bad
 lea rsi,[r12+192]
 lea rdi,[r12+896]
 cmp qword [r12+4056],0
 je .n2_orthogonal
 xchg rsi,rdi
.n2_orthogonal:
 movsx eax,word [rsi+2]
 imul eax,[r12+4104]
 neg eax
 mov [rdi],ax
 movsx eax,word [rsi]
 imul eax,[r12+4104]
 mov [rdi+2],ax
 xor ecx,ecx
.n2_mix:
 movsx eax,word [r12+192+rcx*2]
 imul eax,[r12+4072]
 sar eax,15
 movsx eax,ax
 movsx edx,word [r12+896+rcx*2]
 imul edx,[r12+4080]
 sar edx,15
 movsx edx,dx
 mov esi,eax
 sub eax,edx
 add esi,edx
 mov [r12+192+rcx*2],ax
 mov [r12+896+rcx*2],si
 inc ecx
 cmp ecx,2
 jb .n2_mix
 jmp .invert
.normal:
 ; mbits=max(0,min(b,(b-delta)/2)); signed C division truncates toward zero.
 mov rax,[r12+4032]
 movsxd rcx,dword [r12+1940]
 sub rax,rcx
 cqo
 mov ecx,2
 idiv rcx
 mov rcx,[r12+4032]
 cmp rax,rcx
 cmovg rax,rcx
 xor edx,edx
 test rax,rax
 cmovs rax,rdx
 mov [r12+4032],rax
 sub rcx,rax
 mov [r12+4040],rcx
 xor edi,edi
 cmp rax,rcx
 setl dil
 mov [r12+4056],rdi             ; ties decode mid first
 mov rax,[r12+4008]
 mov [r12+4048],rax
 test edi,edi
 jnz .side_first
 mov rsi,[r12+4032]
 mov edx,32767
 call mostband_channel
 test rax,rax
 js .bad
 mov rax,[r12+4048]
 sub rax,[r12+4008]
 mov rcx,[r12+4032]
 sub rcx,rax
 cmp rcx,24
 jle .decode_side
 cmp qword [r12+4064],0
 je .decode_side
 sub rcx,24
 add [r12+4040],rcx
.decode_side:
 mov edi,1
 mov rsi,[r12+4040]
 mov edx,[r12+4080]
 call mostband_channel
 test rax,rax
 js .bad
 jmp .merge
.side_first:
 mov rsi,[r12+4040]
 mov edx,[r12+4080]
 call mostband_channel
 test rax,rax
 js .bad
 mov rax,[r12+4048]
 sub rax,[r12+4008]
 mov rcx,[r12+4040]
 sub rcx,rax
 cmp rcx,24
 jle .decode_mid
 cmp qword [r12+4064],16384
 je .decode_mid
 sub rcx,24
 add [r12+4032],rcx
.decode_mid:
 xor edi,edi
 mov rsi,[r12+4032]
 mov edx,32767
 call mostband_channel
 test rax,rax
 js .bad
.merge:
 lea rdi,[r12+2664]
 mov rax,[r12+4000]
 mov [rdi],rax
 mov rax,[r12+4072]
 mov [rdi+8],rax
 lea rax,[r12+192]
 mov [rdi+16],rax
 lea rax,[r12+896]
 mov [rdi+24],rax
 mov rax,[r12+4000]
 add rax,rax
 mov [rdi+32],rax
 mov [rdi+40],rax
 add rax,rax
 mov [rdi+56],rax
 lea rax,[r12+1960]
 mov [rdi+48],rax
 call media_opus_stereo_merge
 test rax,rax
 js .bad
.invert:
 cmp qword [r12+4088],0
 je .finish
 xor ecx,ecx
.invert_loop:
 neg word [r12+896+rcx*2]
 inc rcx
 cmp rcx,[r12+4000]
 jb .invert_loop
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
 cmp rax,[r12+3272]
 ja .bad
 mov eax,[r12+4000]
 mov [r12+64],eax
 mov eax,[r12+4064]
 mov [r12+68],eax
 mov rax,[r12+4096]
 sub rax,[r12+4008]
 mov [r12+72],eax
 mov eax,[r12+4008]
 mov [r12+76],eax
 mov eax,[r12+4016]
 mov [r12+80],eax
 mov eax,[r12+4024]
 mov [r12+84],eax
 lea rsi,[r12+192]
 mov rdi,[r13+80]
 mov rcx,[r12+4000]
 rep movsw
 lea rsi,[r12+896]
 mov rdi,[r13+160]
 mov rcx,[r12+4000]
 rep movsw
 cmp qword [r13+136],0
 je .publish_meta
 lea rsi,[r12+1248]
 mov rdi,[r13+136]
 mov rcx,[r12+4000]
 rep movsw
.publish_meta:
 lea rsi,[r12+64]
 mov rdi,[r13+112]
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
 add rsp,4328
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; Private channel adapter: EDI=destination side0/1,RSI=signed b,EDX=gain.
; Translate negative b/remaining to zero for the public mono domain. They
; select exactly q0 with zero leaf charge. Subtract returned charge from
; the original signed shared remaining; never replace it with clamped state.
mostband_channel:
 mov [r12+4120],rdi
 mov [r12+4128],rsi
 mov [r12+4136],rdx
 lea rsi,[r12+3200]
 lea rdi,[r12+1600]
 mov ecx,20
 rep movsq
 mov rax,[r12+4128]
 xor edx,edx
 test rax,rax
 cmovs rax,rdx
 mov [r12+1616],rax
 mov rax,[r12+4136]
 mov [r12+1640],rax
 mov rax,[r12+4008]
 test rax,rax
 cmovs rax,rdx
 mov [r12+1648],rax
 mov rax,[r12+4016]
 mov [r12+1656],rax
 lea rax,[r12+192]
 cmp qword [r12+4120],0
 je .destination
 lea rax,[r12+896]
.destination:
 mov [r12+1680],rax
 mov rax,[r12+4000]
 add rax,rax
 mov [r12+1688],rax
 lea rax,[r12+1760]
 mov [r12+1712],rax
 mov qword [r12+1720],24
 cmp qword [r12+4144],0
 jne .mid_policy
 cmp qword [r12+4120],0
 je .mid_policy
 mov qword [r12+1696],0         ; side never folds lowband
 mov qword [r12+1704],0
 mov qword [r12+1736],0
 mov qword [r12+1744],0
 mov rcx,[r12+3224]
 shr qword [r12+1664],cl
 jmp .decode
.mid_policy:
 cmp qword [r13+136],0
 je .decode
 lea rax,[r12+1248]
 mov [r12+1736],rax
 mov rax,[r12+4000]
 add rax,rax
 mov [r12+1744],rax
.decode:
 mov rdi,r12
 lea rsi,[r12+1600]
 sub rsp,8
 call media_opus_band_decode
 add rsp,8
 test rax,rax
 js .done
 mov eax,[r12+1768]
 sub [r12+4008],rax
 mov eax,[r12+1776]
 mov [r12+4016],rax
 mov eax,[r12+1780]
 or [r12+4024],rax
 xor eax,eax
.done:
 ret
mostband_bad:
 mov rax,-1
 ret
mostband_ebands:
 dw 0,1,2,3,4,5,6,7,8,10,12,14,16,20,24,28,34,40,48,60,78,100
