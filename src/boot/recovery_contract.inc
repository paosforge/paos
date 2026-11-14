; R5 owner grant v1. Signed bytes are domain separated by the full 8-byte
; PAOSR5G1 magic. RSA-2048 PKCS#1/SHA256 uses the enrolled Boot-v2 owner key.
; File: same-medium \EFI\PaOS\state\recovery-grant.bin. Optional; absence OFF.
; All unused bytes, including component and path tails, MUST be zero.
%ifndef PAOS_RECOVERY_CONTRACT
%define PAOS_RECOVERY_CONTRACT 1
%define R5_GRANT_SIZE 4096
%define R5_SIGNED_SIZE 3840
%define R5_SIGNATURE_OFF 3840
%define R5_MAGIC 0x31473552534f4150
%define R5_VERSION 1
%define R5_CURRENT 1
%define R5_NEXT 2
%define R5_OP 16
%define R5_EXPECTED_GEN 24
%define R5_NONCE 32
%define R5_SEQUENCE 40
%define R5_SOFT 48
%define R5_HARD 52
%define R5_HEARTBEAT 56
%define R5_BOOTNUM 60
%define R5_DP_LEN 62
%define R5_NODE_UUID 64
%define R5_MANIFEST_SHA 80
%define R5_PAYLOAD_SHA 112
%define R5_DESCRIPTOR_SHA 144
%define R5_RESCUE_SHA 176
%define R5_RESCUE_SIZE 208
%define R5_MEDIUM_LEN 216
%define R5_OPTION_LEN 218
%define R5_MEDIUM 224
%define R5_OPTION 736
%define R5_COMPONENTS 1504
%define R5_COMPONENT_SIZE 304
%define R5_COMPONENT_COUNT 4
%define R5_SOFT_SECONDS 180
%define R5_HARD_SECONDS 1800
%define R5_HEARTBEAT_SECONDS 30
%define R5_QUIESCE_US 10000000
%define R5_RESET_US 5000000
; Distinct CRC-covered extension, after B1's [152,264) policy extension.
%define R5_STATE_MAGIC_OFF 264
%define R5_STATE_MAGIC 0x31503552
%define R5_STATE_STATUS 268
%define R5_STATE_BOUND 1
%define R5_STATE_CONSUMED 2
%define R5_STATE_OP 272
%define R5_STATE_DIGEST 280
%define R5_STATE_NONCE 312
%define R5_STATE_GEN 320
%define R5_STATE_END 328
%define R5_REQUEST_SIZE 4608
%define R5_REQUEST_MAGIC 0x31513552534f4150
%define R5_REQUEST_GRANT 512
%define R5_REQUEST_CRC 508
%define R5_EFI_NOT_FOUND 0x800000000000000e
%define R5_EFI_BUFFER_SMALL 0x8000000000000005
%endif
