%ifndef PAOS_AML_BINDINGS_INC
%define PAOS_AML_BINDINGS_INC 1
%include "bus/aml_namespace.inc"
AML_BIND_DUPLICATE equ -6
AML_BIND_NOT_FOUND equ -7
AML_BIND_STATE     equ -8
AML_BIND_MAX      equ 4096
AML_BIND_TABLES   equ 16
AML_BIND_OPAQUE    equ 1
AML_BIND_METHOD    equ 2
AML_BIND_INTEGER   equ 3
AML_BIND_SCOPE     equ 4
AML_BIND_DEVICE    equ 5
AML_BIND_MUTEX     equ 6
AML_BIND_REGION    equ 7
AML_BIND_EXTERNAL  equ 8
struc aml_binding
 .name: resb aml_name_size           ; canonical definition: flags MUST be zero
 .kind: resd 1
 .metadata: resd 1                   ; opaque loader metadata, e.g. MethodFlags
 .value: resq 1                      ; opaque immediate/loader data
 .definition: resq 1                 ; opaque admitted-table reference
 .body: resq 1
 .end: resq 1
 .source_id: resd 1                  ; loader-assigned table identity, 1..16
 .reserved: resd 1                  ; must be zero
endstruc
struc aml_bindings
 .start: resq 1
 .end: resq 1
 .count: resd 1
 .capacity: resd 1
endstruc
%endif
