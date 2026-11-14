;; MODULE core/lock
;; LAYER 1
;; EXPORTS spin_acquire, spin_try_acquire, spin_release
;; IMPORTS
;; CAPS
;; OWNER saga:core
; ============================================================================
; core/lock.asm — THE single reusable SMP spinlock primitive (1003 lock
; discipline, extracted so the pre-C3 subsystems retro-declaring lock SITES
; (1075) reuse ONE test-and-set implementation, never a bus-/netdev-local copy).
;
; PARAMETERIZED on the lock byte address (RDI) so every declared lock instance
; (rq_locks[], hal_lock, netdev_lock, ...) shares this one body. Each protected
; object owns its own lock byte; at scale-1 the acquire never spins (the SITE is
; the non-retrofittable part, per REQUIREMENTS §1 / FOUNDATION_CHECKLIST §2).
; The lock BYTE lives with each protected structure; only the ALGORITHM is here.
; ============================================================================

; spin_acquire(RDI = addr of a 1-byte lock) -> lock held. clobbers RAX.
spin_acquire:
    mov  al, 1
.spin:
    xchg al, byte [rdi]                     ; xchg r/m is implicitly LOCKed
    test al, al
    jz   .held
    pause
    jmp  .spin
.held:
    ret

; spin_try_acquire(RDI = addr of a 1-byte lock) -> EAX=1 held, EAX=0 busy.
; Exactly one atomic exchange: IRQ/fault callers can prove they never enter the
; blocking PAUSE/back-edge above while an interrupted context owns the lock.
spin_try_acquire:
    mov  al, 1
    xchg al, byte [rdi]                     ; same canonical atomic operation
    test al, al
    setz al
    movzx eax, al
    ret

; spin_release(RDI = addr of a 1-byte lock) -> lock free.
spin_release:
    mov  byte [rdi], 0
    ret
