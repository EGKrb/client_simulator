#include "nightshift.h"
#include "dll_loader.h"
#include "internal_cmds.h"

static NSDllHandle g_dll = {0};

static NSCommandType ns_identify_command(const char *cmd) {
    if (_stricmp(cmd, "help") == 0)        return CMD_HELP;
    if (_stricmp(cmd, "version") == 0)     return CMD_VERSION;
    if (_stricmp(cmd, "reset") == 0)       return CMD_RESET;
    if (_stricmp(cmd, "terminate") == 0)   return CMD_TERMINATE;
    if (_stricmp(cmd, "aliases") == 0)     return CMD_LIST_ALIASES;
    if (_stricmp(cmd, "sql") == 0)         return CMD_SQL;
    if (_stricmp(cmd, "batch") == 0)       return CMD_BATCH;
    if (_stricmp(cmd, "login") == 0)       return CMD_LOGIN;
    if (_stricmp(cmd, "load") == 0)        return CMD_LOAD_DLL;
    if (_stricmp(cmd, "unload") == 0)      return CMD_UNLOAD_DLL;
    if (_stricmp(cmd, "mapload") == 0)     return CMD_MAPLOAD_DLL;
    if (_stricmp(cmd, "map") == 0)         return CMD_MAP;
    if (_stricmp(cmd, "call") == 0)        return CMD_CALL;
    if (_stricmp(cmd, "calladdr") == 0)    return CMD_CALL_ADDR;
    if (_stricmp(cmd, "inspect") == 0)     return CMD_INSPECT;
    if (_stricmp(cmd, "peinfo") == 0)      return CMD_PEINFO;
    if (_stricmp(cmd, "sections") == 0)    return CMD_SECTIONS;
    if (_stricmp(cmd, "resource") == 0)    return CMD_RESOURCE;
    if (_stricmp(cmd, "hexdump") == 0)     return CMD_HEXDUMP;
    if (_stricmp(cmd, "dumpsec") == 0)     return CMD_DUMPSEC;
    if (_stricmp(cmd, "symbols") == 0)     return CMD_SYMBOLS;
    return CMD_UNKNOWN;
}

int ns_parse_command(const char *input, NSParsedCommand *cmd) {
    char work[NS_MAX_CMD_LEN];
    char *token;
    char *saveptr;

    memset(cmd, 0, sizeof(NSParsedCommand));
    strncpy(work, input, NS_MAX_CMD_LEN - 1);
    strncpy(cmd->raw, input, NS_MAX_CMD_LEN - 1);

    token = strtok_r(work, " \t", &saveptr);
    if (!token) return -1;

    cmd->type = ns_identify_command(token);

    switch (cmd->type) {
        case CMD_SQL: {
            char *rest = ns_trim(saveptr);
            if (*rest == '"') {
                rest++;
                char *end_quote = strchr(rest, '"');
                if (end_quote) {
                    *end_quote = '\0';
                    strncpy(cmd->arg1, rest, NS_MAX_CMD_LEN - 1);
                } else {
                    strncpy(cmd->arg1, rest, NS_MAX_CMD_LEN - 1);
                }
            } else {
                strncpy(cmd->arg1, rest, NS_MAX_CMD_LEN - 1);
            }
            break;
        }
        case CMD_BATCH:
        case CMD_LOGIN:
            token = strtok_r(NULL, " \t", &saveptr);
            if (token) strncpy(cmd->arg1, token, NS_MAX_CMD_LEN - 1);
            if (cmd->type == CMD_LOGIN) {
                token = strtok_r(NULL, " \t", &saveptr);
                if (token) strncpy(cmd->arg2, token, NS_MAX_CMD_LEN - 1);
                token = strtok_r(NULL, " \t", &saveptr);
                if (token) {
                    strcat(cmd->arg2, "|");
                    strcat(cmd->arg2, token);
                }
            }
            break;
        case CMD_CALL:
            token = strtok_r(NULL, " \t", &saveptr);
            if (token) strncpy(cmd->arg1, token, NS_MAX_CMD_LEN - 1);
            token = strtok_r(NULL, "", &saveptr);
            if (token) strncpy(cmd->arg2, token, NS_MAX_CMD_LEN - 1);
            break;
        default:
            token = strtok_r(NULL, " \t", &saveptr);
            if (token) strncpy(cmd->arg1, token, NS_MAX_CMD_LEN - 1);
            token = strtok_r(NULL, "", &saveptr);
            if (token) strncpy(cmd->arg2, token, NS_MAX_CMD_LEN - 1);
            break;
    }

    return 0;
}

int ns_execute_command(NSContext *ctx, const NSParsedCommand *cmd) {
    switch (cmd->type) {
        case CMD_HELP:
            ns_print_help();
            return 0;

        case CMD_VERSION:
            ns_print_version();
            return 0;

        case CMD_LIST_ALIASES: {
            int i;
            ns_alias_reload(ctx);
            printf("Configured aliases (%d):\n", ctx->alias_count);
            for (i = 0; i < ctx->alias_count; i++) {
                printf("  %-20s -> %s @ %s\n",
                    ctx->aliases[i].name,
                    ctx->aliases[i].username,
                    ctx->aliases[i].company[0] ? ctx->aliases[i].company : "(default)");
            }
            return 0;
        }

        case CMD_LOGIN: {
            NSAlias *alias = ns_alias_find(ctx, cmd->arg1);
            if (alias) {
                return ns_gp_login(ctx, alias->username, alias->password, alias->company);
            } else {
                char user[NS_MAX_NAME_LEN] = {0};
                char pass[NS_MAX_NAME_LEN] = {0};
                char company[NS_MAX_NAME_LEN] = {0};
                strncpy(user, cmd->arg1, NS_MAX_NAME_LEN - 1);

                char *pipe = strchr(cmd->arg2, '|');
                if (pipe) {
                    strncpy(pass, cmd->arg2, pipe - cmd->arg2);
                    strncpy(company, pipe + 1, NS_MAX_NAME_LEN - 1);
                } else {
                    strncpy(pass, cmd->arg2, NS_MAX_NAME_LEN - 1);
                }

                return ns_gp_login(ctx, user, pass, company[0] ? company : NULL);
            }
        }

        case CMD_SQL:
            return ns_sql_execute(ctx, cmd->arg1);

        case CMD_BATCH:
            return ns_batch_process(ctx, cmd->arg1);

        case CMD_RESET:
            ns_gp_terminate(ctx);
            printf("%s Session reset\n", NS_SUCCESS);
            return 0;

        case CMD_TERMINATE:
            return ns_gp_terminate(ctx);

        case CMD_LOAD_DLL:
            if (cmd->arg1[0] == '\0') {
                fprintf(stderr, "Usage: load <dll_path>\n");
                return -1;
            }
            return ns_cmd_load(&g_dll, cmd->arg1);

        case CMD_UNLOAD_DLL:
            return ns_cmd_unload(&g_dll);

        case CMD_MAPLOAD_DLL:
            if (cmd->arg1[0] == '\0') {
                fprintf(stderr, "Usage: mapload <dll_path>\n");
                return -1;
            }
            return ns_cmd_mapload(&g_dll, cmd->arg1);

        case CMD_MAP:
            if (cmd->arg1[0] == '\0') {
                fprintf(stderr, "Usage: map <mapfile>\n");
                return -1;
            }
            return ns_cmd_map(&g_dll, cmd->arg1);

        case CMD_CALL:
        case CMD_CALL_ADDR: {
            DWORD_PTR a1 = 0, a2 = 0, a3 = 0;
            const char *rest = cmd->arg2;
            char *tok;
            char *save;
            char work2[NS_MAX_CMD_LEN];

            if (cmd->arg1[0] == '\0') {
                fprintf(stderr, "Usage: call <func_name|0xADDRESS> [arg1] [arg2] [arg3]\n");
                return -1;
            }

            if (rest[0]) {
                strncpy(work2, rest, NS_MAX_CMD_LEN - 1);
                tok = strtok_r(work2, " \t,", &save);
                if (tok) a1 = _strtoui64(tok, NULL, 0);
                tok = strtok_r(NULL, " \t,", &save);
                if (tok) a2 = _strtoui64(tok, NULL, 0);
                tok = strtok_r(NULL, " \t,", &save);
                if (tok) a3 = _strtoui64(tok, NULL, 0);
            }

            if (cmd->type == CMD_CALL_ADDR) {
                DWORD_PTR addr = ns_resolve_arg(&g_dll, cmd->arg1);
                return ns_cmd_call_addr(&g_dll, addr, a1, a2, a3);
            }

            if (cmd->arg1[0] == '0' && (cmd->arg1[1] == 'x' || cmd->arg1[1] == 'X')) {
                DWORD_PTR addr = _strtoui64(cmd->arg1, NULL, 16);
                return ns_cmd_call_addr(&g_dll, addr, a1, a2, a3);
            }

            {
                /* Try symbol map (Ghidra dump) before export lookup */
                DWORD_PTR map_addr = ns_resolve_arg(&g_dll, cmd->arg1);
                if (map_addr != 0) {
                    return ns_cmd_call_addr(&g_dll, map_addr, a1, a2, a3);
                }
            }
            return ns_cmd_call(&g_dll, cmd->arg1, a1, a2, a3);
        }

        case CMD_INSPECT:
            if (cmd->arg1[0] == '\0') {
                fprintf(stderr, "Usage: inspect <symbol_name|0xADDRESS>\n");
                return -1;
            }
            return ns_cmd_inspect(&g_dll, cmd->arg1);

        case CMD_PEINFO:
            return ns_cmd_peinfo(&g_dll);

        case CMD_SECTIONS:
            return ns_cmd_sections(&g_dll);

        case CMD_RESOURCE: {
            int offset = -1, length = 64;
            if (cmd->arg1[0]) offset = (int)strtoul(cmd->arg1, NULL, 0);
            if (cmd->arg2[0]) length = (int)strtoul(cmd->arg2, NULL, 0);
            return ns_cmd_resource(&g_dll, offset, length);
        }

        case CMD_HEXDUMP: {
            DWORD_PTR addr = 0;
            int len = 64;
            if (cmd->arg1[0]) addr = ns_resolve_arg(&g_dll, cmd->arg1);
            if (cmd->arg2[0]) len = (int)strtoul(cmd->arg2, NULL, 0);
            return ns_cmd_hexdump(&g_dll, addr, len);
        }

        case CMD_DUMPSEC:
            if (cmd->arg1[0] == '\0' || cmd->arg2[0] == '\0') {
                fprintf(stderr, "Usage: dumpsec <section> <file>\n");
                return -1;
            }
            return ns_cmd_dumpsec(&g_dll, cmd->arg1, cmd->arg2);

        case CMD_SYMBOLS:
            return ns_cmd_symbols(&g_dll, cmd->arg1);

        case CMD_UNKNOWN:
        default:
            fprintf(stderr, "%s Unknown command: %s\n", NS_FAIL, cmd->arg1);
            fprintf(stderr, "Type 'help' for available commands.\n");
            return -1;
    }
}
