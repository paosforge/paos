; R26A v1: RAM-only RTL8126 attach trace, copied by rtl8126_attach_snapshot.
; All fields little endian. Entries in actual execution order, not proof of wire health.
%ifndef PAOS_RTL8126_ATTACH_ABI
%define PAOS_RTL8126_ATTACH_ABI 1
R26A_MAGIC equ 0x41363252                 ; R26A
R26A_VERSION equ 1
R26A_HEADER equ 128
R26A_CAPACITY equ 640
R26A_SIZE equ R26A_HEADER + R26A_CAPACITY * 8
; Header: 0 magic:u32;4 version:u16;6 size:u16;8 count:u32;12 overflow:u32;
;16 fatal reset:u32;20 HWREV:u32;24 MAC firmware words:u32;28 PHY words:u32;
;32 PHY transport failures:u32;36 final phase:u32;40 trace generation:u64;
;48 MAC firmware mismatches:u32;52 PHY reset timeout:u32;
;56 first MAC firmware mismatch observed:u32;60 first mismatch register:u32.
;64 RX frames;72 TX completed;80 TX timeout;88 TX drops;96 RX drops;
;104 owner mismatches;112 RX overflow acknowledgements;120 recovery successes (u64).
; Entry:0 kind:u8;1 status:u8;2 register:u16;4 observed:u32.
; Kinds:1 MMIO;2 MAC-OCP;3 PHY-OCP;4 CSI;5 delay;6 patch handshake;
;7 PHY stream write (transport latch, avoids advancing the data-port cursor);
;12 TWI readiness (bounded).
;8 MAC firmware batch;9 PHY firmware batch;10 command reset;11 PHY reset wait.
; Status:0 completed/read;1 observed mismatch;2 bounded transport/poll timeout;
;4 command/stream completion only (not an exact-register-value assertion).
%endif
