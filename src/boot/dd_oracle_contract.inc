; U4b driver-domain boot oracle: the shared byte contract (BOOT; LEDGER 106350/106354/106359).
; PDO1 is the owner-signed one-shot request (VM PDO1_ABI 190d427c + amend 1 a7e23381):
; 1024 B, RSA-2048 PKCS#1 v1.5 SHA-256 over [0,768) with the key that verified this boot's PBMF.
; PDS1 is the Manager's consumed record inside the PBSJ journal, written in the SAME attempt
; journal_commit. PDH1 is the Manager-to-PaOS copy of the verified request, published as one EFI
; configuration table; PBH1 v1 stays byte-identical. Every PDH1 field is a claim: PaOS verifies
; the PDO1 signature itself (SEC 106354 K1) and the grader credits only a saved journal PDS1 (K2).
%ifndef PAOS_DD_ORACLE_CONTRACT
%define PAOS_DD_ORACLE_CONTRACT 1

%define PDO1_MAGIC              0x314F4450 ; "PDO1" little-endian
%define PDO1_VERSION            1
%define PDO1_SIZE               1024
%define PDO1_SIGNED_SIZE        768
%define PDO1_SIGNATURE_OFF      768
%define PDO1_CONTEXT_OFF        8
%define PDO1_CONTEXT_SIZE       32
%define PDO1_MANIFEST_SEQ_OFF   40
%define PDO1_ORACLE_SEQ_OFF     48
%define PDO1_BUILD_SHA_OFF      56
%define PDO1_PIN_OFF            88
%define PDO1_NONCE_OFF          120
%define PDO1_NONCE_SIZE         32
%define PDO1_URL_LEN_OFF        152
%define PDO1_NONCE_FORM_OFF     154
%define PDO1_NONCE_URL_OFF      156
%define PDO1_PAD_OFF            158
%define PDO1_URL_OFF            160
%define PDO1_URL_FIELD          256
%define PDO1_URL_MIN            12
%define PDO1_URL_MAX            255
%define PDO1_URL_PREFIX_SIZE    8      ; "https://"
%define PDO1_RESERVED_OFF       416
%define PDO1_NONCE_FORM_HEX     1      ; the 32 ASCII hex bytes verbatim
%define PDO1_NONCE_FORM_B64     2      ; RFC 4648 s5 base64url WITH padding of those 32 bytes
%define PDO1_NONCE_HEX_LEN      32
%define PDO1_NONCE_B64_LEN      44

; PDS1 journal tail. Free after R5_STATE_END (recovery_contract.inc); [392,508) stays free.
%define PDS1_MAGIC_OFF          328
%define PDS1_MAGIC              0x31534450 ; "PDS1" little-endian
%define PDS1_STATUS_OFF         332
%define PDS1_STATUS_CONSUMED    2
%define PDS1_ORACLE_SEQ_OFF     336
%define PDS1_RECORD_SHA_OFF     344
%define PDS1_NONCE_OFF          376
%define PDS1_GEN_OFF            384
%define PDS1_END                392

; PDH1 table payload: 128 B header, then the exact verified 1024 B PDO1.
%define PDH1_MAGIC              0x31484450 ; "PDH1" little-endian
%define PDH1_VERSION            1
%define PDH1_SIZE               1152
%define PDH1_HEADER_SIZE        128
%define PDH1_NONCE_OFF          8      ; = PBH1 PBM_HANDOFF_ATTEMPT_NONCE_OFF
%define PDH1_GEN_OFF            16     ; = PBH1 PBM_HANDOFF_STATE_GEN_OFF (committed generation)
%define PDH1_MANAGER_SEQ_OFF    24     ; = PBH1 PBM_HANDOFF_MANAGER_SEQ_OFF
%define PDH1_ORACLE_SEQ_OFF     32
%define PDH1_PAYLOAD_SHA_OFF    40     ; = PBH1 PBM_HANDOFF_PAYLOAD_SHA_OFF
%define PDH1_RECORD_SHA_OFF     72
%define PDH1_CRC32              124    ; IEEE CRC32 over [0,124)
%define PDH1_RECORD_OFF         128
; Configuration table GUID 5d3c0b7e-2f61-4c8a-9e14-6a70d2b81f45 (EFI_GUID byte order).
%define PDH1_GUID_D1            0x5d3c0b7e
%define PDH1_GUID_D2            0x2f61
%define PDH1_GUID_D3            0x4c8a
%define PDH1_GUID_D4            0x9e, 0x14, 0x6a, 0x70, 0xd2, 0xb8, 0x1f, 0x45

%endif
