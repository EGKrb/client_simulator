#include "nightshift.h"

static int char_batch_file(const char *path) {
    size_t len;
    FILE *f;

    if (!path || !*path) return 0;

    f = fopen(path, "rb");
    if (!f) return 0;
    fclose(f);

    len = strlen(path);
    if (len >= 4 && (_stricmp(path + len - 4, ".bat") == 0 ||
                     _stricmp(path + len - 4, ".txt") == 0))
        return 1;

    return 0;
}

static int ns_execute_chain(NSContext *ctx, const char *input) {
    char work[NS_MAX_CMD_LEN];
    char *cmd_str;
    char *save;
    NSParsedCommand cmd;
    int result = 0;

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

int main(int argc, char *argv[]) {
    NSContext ctx;
    NSParsedCommand cmd;

    ns_context_init(&ctx);
    ns_alias_reload(&ctx);

    if (argc > 1) {
        int i;
        char combined[NS_MAX_CMD_LEN] = {0};

        if (_stricmp(argv[1], "-c") == 0 && argc > 2) {
            for (i = 2; i < argc; i++) {
                if (i > 2) strcat(combined, " ");
                strcat(combined, argv[i]);
            }
            int result = ns_execute_chain(&ctx, combined);
            ns_context_cleanup(&ctx);
            return result;
        }

        if (argc == 2 && char_batch_file(argv[1])) {
            int result = ns_batch_process(&ctx, argv[1]);
            ns_context_cleanup(&ctx);
            return result;
        }

        for (i = 1; i < argc; i++) {
            if (i > 1) strcat(combined, " ");
            strcat(combined, argv[i]);
        }

        if (ns_parse_command(combined, &cmd) != -1) {
            int result = ns_execute_command(&ctx, &cmd);
            ns_context_cleanup(&ctx);
            return result;
        }

        ns_context_cleanup(&ctx);
        return -1;
    }

    printf("NightShift v%s - Type 'help' for commands, 'terminate' to exit.\n\n", NS_VERSION);

    while (1) {
        char input[NS_MAX_CMD_LEN];

        printf("nightshift> ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin))
            break;

        char *trimmed = ns_trim(input);
        if (*trimmed == '\0') continue;

        ns_execute_chain(&ctx, trimmed);
    }

    ns_context_cleanup(&ctx);
    return 0;
}
