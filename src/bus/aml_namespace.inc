%ifndef PAOS_AML_NAMESPACE_INC
%define PAOS_AML_NAMESPACE_INC 1
; Pure AML declaration reader ABI. The caller owns mapped immutable input spans
; and complete writable output records. No numerical address is an I/O grant.
AML_READ_OK          equ 0
AML_READ_BOUNDS      equ -1
AML_READ_ENCODING    equ -2
AML_READ_UNSUPPORTED equ -3
AML_READ_BUDGET      equ -4
AML_READ_SCOPE       equ -5
AML_READ_MAX_BYTES   equ 1048576
AML_NAME_MAX_SEGS    equ 32
AML_NAME_ROOT        equ 1
AML_NAME_PARENT      equ 2
AML_NAME_NULL        equ 4
; Metadata for a later *reference* lookup, never ancestor search on definition.
AML_NAME_SEARCH      equ 8
struc aml_name
 .count: resd 1
 .flags: resd 1
 .segments: resd AML_NAME_MAX_SEGS
endstruc
struc aml_method
 .name: resb aml_name_size
 .flags: resd 1                       ; ArgCount[2:0], Serialized[3], SyncLevel[7:4]
 .reserved: resd 1
 .body: resq 1
 .end: resq 1
endstruc
%endif
