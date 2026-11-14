;; MODULE gui/netmon_app
;; LAYER 6
;; EXPORTS
;; IMPORTS
;; CAPS
;; OWNER saga:gui_foundation_ladder
;; RETIRED by GUI F2 contract 2111.
;;
;; The task-1035 private painter and NETMON_TICK_MS loop were never included in
;; the product image. Network Monitor now lives in gui/forms/netmon.frm, loads
;; through gui/form_loader.asm, renders only through stock widgets, and refreshes
;; through netmon.refresh in the single core cadence registry. NETMON_STAT and
;; LAUNCH compatibility are provided by gui/netmon_form.asm.
;;
;; This notice intentionally contains no code and no framebuffer primitive call;
;; keeping the historical path lets source-census tooling prove the retirement.
