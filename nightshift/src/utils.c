#include "nightshift.h"

void ns_context_init(NSContext *ctx) {
    memset(ctx, 0, sizeof(NSContext));
    ctx->verbose = 0;
    ctx->gp_module = NULL;
    strcpy(ctx->alias_file, "aliases.txt");
}

void ns_context_cleanup(NSContext *ctx) {
    if (ctx->gp_module) {
        FreeLibrary(ctx->gp_module);
        ctx->gp_module = NULL;
    }
}

char* ns_trim(char *str) {
    char *end;
    while (*str == ' ' || *str == '\t' || *str == '\r' || *str == '\n')
        str++;
    if (*str == '\0') return str;
    end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n'))
        end--;
    *(end + 1) = '\0';
    return str;
}
