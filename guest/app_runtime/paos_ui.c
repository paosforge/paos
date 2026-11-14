/* Fixed entry point for isolated apps. UI retains its existing native checks;
 * MAIL permanently drops privileges. General Terminal/GUEST is unreachable.
 * No exec, arbitrary PIO, pathname, credential or raw-frame operation exists here.
 */
#define main paos_general_main_not_an_entry
#include "../../tools/browser/browser_appliance/agent/paos.c"
#undef main
#include "isolation.h"
#include "mail_public.h"
int main(int argc, char **argv) {
    if (argc < 2) return 125;
    if (!strcmp(argv[1], "MAIL")) return app_mail_public_cli(argc-2, argv+2);
    int kind;
    if (!strcmp(argv[1], "WINDOW") && argc == 2) kind = 1;
    else if (!strcmp(argv[1], "WIDGET") && argc >= 3) kind = 1;
    else if (!strcmp(argv[1], "FORM") && argc >= 3) kind = 1;
    else if (!strcmp(argv[1], "READER") && argc >= 3) kind = 1;
    else if (!strcmp(argv[1], "WAIT") && argc >= 3) kind = 2;
    else if (!strcmp(argv[1], "SNAPSHOT") && argc >= 3) kind = 3;
    else return 125;
    if (app_ui_prepare()) return 125;
    int rc = kind == 1 ? widget_live(argc-1, argv+1) :
             kind == 2 ? live(argc-1, argv+1) : snapshot_live(argc-1, argv+1);
    if (rc < 0 || fflush(stdout) || ferror(stdout)) return 2;
    return rc;
}
