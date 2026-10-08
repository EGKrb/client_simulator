#include "nightshift.h"

int ns_batch_process(NSContext *ctx, const char *filepath) {
    FILE *f;
    char line[NS_MAX_LINE_LEN];
    int line_num = 0;
    int errors = 0;

    f = fopen(filepath, "r");
    if (!f) {
        fprintf(stderr, "%s Cannot open batch file: %s\n", NS_FAIL, filepath);
        return -1;
    }

    printf("--- Processing batch: %s ---\n", filepath);

    while (fgets(line, sizeof(line), f)) {
        char *trimmed = ns_trim(line);
        line_num++;

        if (*trimmed == '\0' || *trimmed == '#')
            continue;

        if (strncmp(trimmed, "SQL:", 4) == 0) {
            char *query = ns_trim(trimmed + 4);
            printf("[%d] SQL: %s\n", line_num, query);
            if (ns_sql_execute(ctx, query) != 0) {
                errors++;
                fprintf(stderr, "%s Line %d: SQL execution failed\n", NS_FAIL, line_num);
            }
        }
        else if (strncmp(trimmed, "LOGIN:", 6) == 0) {
            char *alias_name = ns_trim(trimmed + 6);
            NSAlias *alias;
            printf("[%d] LOGIN: %s\n", line_num, alias_name);

            ns_alias_reload(ctx);
            alias = ns_alias_find(ctx, alias_name);
            if (alias) {
                if (ns_gp_login(ctx, alias->username, alias->password, alias->company) != 0) {
                    errors++;
                    fprintf(stderr, "%s Line %d: Login failed for alias '%s'\n", NS_FAIL, line_num, alias_name);
                }
            } else {
                errors++;
                fprintf(stderr, "%s Line %d: Alias '%s' not found\n", NS_FAIL, line_num, alias_name);
            }
        }
        else if (strncmp(trimmed, "CMD:", 4) == 0) {
            char *cmd = ns_trim(trimmed + 4);
            NSParsedCommand pcmd;
            printf("[%d] CMD: %s\n", line_num, cmd);
            if (ns_parse_command(cmd, &pcmd) != -1) {
                if (ns_execute_command(ctx, &pcmd) != 0) {
                    errors++;
                }
            }
        }
        else if (strncmp(trimmed, "WAIT:", 5) == 0) {
            int ms = atoi(trimmed + 5);
            if (ms > 0) {
                printf("[%d] WAIT: %d ms\n", line_num, ms);
                Sleep(ms);
            }
        }
        else {
            fprintf(stderr, "%s Line %d: Unknown command: %s\n", NS_FAIL, line_num, trimmed);
            errors++;
        }
    }

    fclose(f);
    printf("--- Batch complete: %d error(s) ---\n", errors);
    return errors > 0 ? -1 : 0;
}
