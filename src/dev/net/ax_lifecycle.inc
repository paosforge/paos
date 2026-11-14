%ifndef PAOS_AX_LIFECYCLE_INC
%define PAOS_AX_LIFECYCLE_INC
; Class-private storage. All calls require that class's nonblocking runtime owner.
struc ax_lifetime
 .hc: resq 1
 .ops: resq 1
 .root: resd 1
 .generation: resd 1
 .topo: resb 16
 .incarnation: resq 1
 .phase: resd 1 ; 0 unavailable,1 bound,2 confirmed retired waiting,3 spent/unknown
 .reserved: resd 1
 .bind: resq 1 ; (inventory index, expected original MAC*) -> 0 actual wire bind/-1
 .member: resq 1
 .descriptor: resb 18
 .padding: resb 6
 .mac: resb 6
 .padding2: resb 2
 .next_ms: resq 1
 .retired: resq 1
 .rebound: resq 1
 .refused: resq 1
 .reserved2: resq 1
endstruc
%endif
