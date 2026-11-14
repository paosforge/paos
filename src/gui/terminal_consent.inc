; Codex / rc-live-claude. Native-only UI adapter; NEVER a guest wire record.
%ifndef PAOS_TERMINAL_CONSENT_INC
%define PAOS_TERMINAL_CONSENT_INC 1
TC_STATE_BYTES equ 1088          ; header64 + eight exact scope128 selections
TC_ST_VERSION equ 0             ; u64 1
TC_ST_SESSION equ 8             ; current native owner epoch
TC_ST_POLICY equ 16             ; nonzero grant generation
TC_ST_COUNT equ 24              ; 0..8 active scopes
TC_ST_SAVED equ 32              ; 0 session-only, 1 verified saved, 2 save failed
TC_ST_FLAGS equ 40              ; zero; header48..63 reserved zero
TC_DESC_BYTES equ 256           ; SEC ABI_V1 descriptor, copied in full
TC_TEXT_BYTES equ 1024          ; printable ASCII, terminating NUL, zero tail
TC_SCOPE_BYTES equ 128          ; SEC ABI_V1 exact immutable scope
TC_CB_STATE equ 0               ; (RDI out1088)->EAX1 current state, else0
TC_CB_PENDING equ 8             ; (RDI out256,RSI out1024,EDX1024)->RAX id or0
TC_CB_APPROVE equ 16            ; (RDI id,RSI owner token)->EAX1; exact action
TC_CB_DENY equ 24               ; (RDI id)->void, never resumes an effect
TC_CB_REVOKE equ 32             ; (RDI owner token)->EAX1 saved,2 session-only,0 failed
TC_CB_PREPARE equ 40            ; (EDI op,ESI slot,EDX fullgen,RCX out128)->EAX1
TC_CB_GRANT equ 48              ; (RDI exact scope128,RSI owner token)->EAX1 saved,2 session-only,0 failed
TC_CALLBACK_BYTES equ 56
%endif
