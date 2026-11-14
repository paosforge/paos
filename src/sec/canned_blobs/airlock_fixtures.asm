;; MODULE sec/canned_blobs/airlock_fixtures
;; LAYER 5
;; EXPORTS air_blob_hostile_code, air_blob_benign_code, air_blob_hang_code
;; IMPORTS
;; CAPS
;; OWNER task:1056
; Canned AIRLOCK fixture bodies are restored below from the prior build attempt.

; Contract 1056 canned native fixtures. These bytes execute only as VMX guests
; behind the airlock EPT; no fixture is ever called as an in-keep function.

air_blob_hostile_code:
    mov  rax, AIR_HOSTILE_SENTINEL
    mov  [qword AIR_DENIED_GPA], rax      ; absent EPT leaf -> hardware violation
    hlt                                  ; unreachable when denial works
air_blob_hostile_len equ $ - air_blob_hostile_code

air_blob_benign_code:
    mov  esi, AIR_MAILBOX_IN_GPA
    mov  edi, AIR_MAILBOX_OUT_GPA
    mov  ecx, AIR_CANARY_BYTES
    rep  movsb                           ; result must be read through EPT backing
    hlt
air_blob_benign_len equ $ - air_blob_benign_code

air_blob_hang_code:
    mov  ecx, 0x10000000                 ; proven bounded fallback safety belt
.spin:
    pause                                ; timer must reap before this expires
    dec  ecx
    jnz  .spin
    hlt                                  ; timer failure degrades, never host-hangs
air_blob_hang_len equ $ - air_blob_hang_code
