#include "nightshift.h"

/*  Pont d'integration du moteur NightShift dans MonNouvelApp.exe.
    Reimplementation de la boucle principale de nightshift\src\main.c sans
    dependre de main() : tout passe par l'API publique ns_* exposee par le
    module nuit (voir C:\client_simulator\nightshift).

    - ns_app_run_chain : identique a ns_execute_chain de main.c (chaine de
      commandes separees par ';', CMD_TERMINATE => retour 0).
    - ns_app_repl      : lit stdin ligne par ligne (REPL equivalent piped).
*/

int ns_app_run_chain(NSContext *ctx, const char *input) {
    char work[NS_MAX_CMD_LEN];
    char *cmd_str;
    char *save;
    NSParsedCommand cmd;
    int result = 0;

    if (!input || !*input) return 0;

    strncpy(work, input, NS_MAX_CMD_LEN - 1);
    work[NS_MAX_CMD_LEN - 1] = '\0';

    cmd_str = strtok_r(work, ";", &save);
    while (cmd_str) {
        char *trimmed = ns_trim(cmd_str);
        if (*trimmed != '\0') {
            if (ns_parse_command(trimmed, &cmd) != -1) {
                if (cmd.type == CMD_TERMINATE) {
                    ns_execute_command(ctx, &cmd);
                    return 0;
                }
                result = ns_execute_command(ctx, &cmd);
            } else {
                result = -1;
            }
        }
        cmd_str = strtok_r(NULL, ";", &save);
    }
    return result;
}

int ns_app_repl(NSContext *ctx) {
    char input[NS_MAX_CMD_LEN];

    printf("NightShift v%s - REPL integre (stdin): 'terminate' pour quitter.\n",
           NS_VERSION);

    while (fgets(input, sizeof(input), stdin)) {
        char *trimmed = ns_trim(input);
        if (*trimmed == '\0') continue;
        ns_app_run_chain(ctx, trimmed);
    }
    return 0;
}