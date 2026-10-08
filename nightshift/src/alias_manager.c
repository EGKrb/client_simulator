#include "nightshift.h"

int ns_alias_load(NSContext *ctx, const char *filepath) {
    FILE *f;
    char line[NS_MAX_LINE_LEN];
    char *token;
    char *saveptr;

    f = fopen(filepath, "r");
    if (!f) {
        if (ctx->verbose)
            fprintf(stderr, "%s Alias file not found: %s\n", NS_FAIL, filepath);
        return -1;
    }

    ctx->alias_count = 0;

    while (fgets(line, sizeof(line), f) && ctx->alias_count < NS_MAX_ALIASES) {
        char *trimmed = ns_trim(line);

        if (*trimmed == '\0' || *trimmed == '#')
            continue;

        token = strtok_r(trimmed, "|", &saveptr);
        if (!token) continue;
        strncpy(ctx->aliases[ctx->alias_count].name, ns_trim(token), NS_MAX_NAME_LEN - 1);

        token = strtok_r(NULL, "|", &saveptr);
        if (!token) continue;
        strncpy(ctx->aliases[ctx->alias_count].username, ns_trim(token), NS_MAX_NAME_LEN - 1);

        token = strtok_r(NULL, "|", &saveptr);
        if (!token) continue;
        strncpy(ctx->aliases[ctx->alias_count].password, ns_trim(token), NS_MAX_NAME_LEN - 1);

        token = strtok_r(NULL, "|", &saveptr);
        if (token)
            strncpy(ctx->aliases[ctx->alias_count].company, ns_trim(token), NS_MAX_NAME_LEN - 1);
        else
            ctx->aliases[ctx->alias_count].company[0] = '\0';

        ctx->alias_count++;
    }

    fclose(f);

    if (ctx->verbose)
        printf("%s Loaded %d alias(es) from %s\n", NS_SUCCESS, ctx->alias_count, filepath);

    return 0;
}

int ns_alias_reload(NSContext *ctx) {
    return ns_alias_load(ctx, ctx->alias_file);
}

NSAlias* ns_alias_find(NSContext *ctx, const char *name) {
    int i;
    for (i = 0; i < ctx->alias_count; i++) {
        if (_stricmp(ctx->aliases[i].name, name) == 0)
            return &ctx->aliases[i];
    }
    return NULL;
}
