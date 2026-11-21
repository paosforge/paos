; Native IPv4 peer classification. EAX=wire-order peer, EDX=selected source,
; ECX=selected mask (zero for class-only preflight). Returns EAX boolean;
; clobbers R8D only. Never reads memory or treats the next hop as the peer.
%ifndef PAOS_GUEST_DESTINATION_INC
%define PAOS_GUEST_DESTINATION_INC
%macro HV_GUEST_PUBLIC_IP 0
    test al,al
    jz %%bad
    cmp al,10
    je %%bad
    cmp al,127
    je %%bad
    cmp al,224
    jae %%bad
    mov r8d,eax
    and r8d,0x0000ffff
    cmp r8d,0x0000fea9                 ; 169.254/16
    je %%bad
    cmp r8d,0x0000a8c0                 ; 192.168/16
    je %%bad
    mov r8d,eax
    and r8d,0x0000f0ff
    cmp r8d,0x000010ac                 ; 172.16/12
    je %%bad
    test edx,edx
    jz %%public
    cmp eax,edx
    je %%bad
    ; An endpoint-bound source requires a coherent ordinary subnet. Unknown
    ; route facts are class-only only when the caller supplies source zero.
    test ecx,ecx
    jz %%bad
    mov r8d,ecx
    bswap r8d
    not r8d
    cmp r8d,3
    jb %%bad                          ; /31 and /32 are not this route profile
    cmp r8d,0x7fffffff
    ja %%bad                          ; /0 is not LAN authority
    push rcx
    lea ecx,[r8d+1]
    test ecx,r8d
    pop rcx
    jnz %%bad                         ; noncontiguous mask
    xor eax,edx
    test eax,ecx
    jz %%bad                          ; selected LAN, even public-numbered
%%public:
    mov eax,1
    ret
%%bad:
    xor eax,eax
    ret
%endmacro
%endif
