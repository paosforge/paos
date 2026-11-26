; Paired only with the fixed image reader's private transient-scratch lease.
; Default images emit no instruction and retain the ordinary synchronous ABI.
; A suspended image reader yields only after native device calls return; no UDP
; dispatch, writer frame or block-device operation is reentered by this hook.
%ifndef PAOS_IMAGE_READ_IDLE_INC
%define PAOS_IMAGE_READ_IDLE_INC 1
%macro FD_IMAGE_READ_STEP 0
%ifdef PAOS_IMG_COLD_FAT
    call img_cold_fat_checkpoint
%endif
%endmacro
; Only the fixed cold reader narrows a request. Ordinary readers retain their
; eight-sector batching. One NVMe sector means one accepted hardware command,
; not eight independent completion polls hidden inside one blk_read call.
%macro FD_IMAGE_READ_COUNT 1
%ifdef PAOS_IMG_COLD_FAT
    pushfq
    cmp byte [rel img_cold_fat_active],1
    jne %%ordinary
    mov %1,1
%%ordinary:
    popfq
%endif
%endmacro
; The device has returned and custody has been rechecked before this seam.
; Never suspend a driver, pending DMA, recovery or a command-dispatch frame.
%macro FD_IMAGE_READ_COMPLETE 0
%ifdef PAOS_IMG_COLD_FAT
    call img_cold_fat_read_complete
%endif
%endmacro
%endif
