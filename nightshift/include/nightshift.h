#ifndef NIGHTSHIFT_H
#define NIGHTSHIFT_H

#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE

#include <windows.h>
#include <sql.h>
#include <sqlext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _MSC_VER
#define strtok_r strtok_s
#define strcasecmp _stricmp
#endif

/* Forward declare to avoid circular include */
typedef struct NSDllHandle NSDllHandle;

#define NS_VERSION "1.0.0"
#define NS_MAX_CMD_LEN 4096
#define NS_MAX_LINE_LEN 8192
#define NS_MAX_PATH_LEN 1024
#define NS_MAX_ALIASES 256
#define NS_MAX_NAME_LEN 128

#define NS_SUCCESS "\x1b[32m" "[OK]" "\x1b[0m"
#define NS_FAIL    "\x1b[31m" "[FAIL]" "\x1b[0m"

typedef struct {
    char name[NS_MAX_NAME_LEN];
    char username[NS_MAX_NAME_LEN];
    char password[NS_MAX_NAME_LEN];
    char company[NS_MAX_NAME_LEN];
} NSAlias;

typedef struct {
    char alias_file[NS_MAX_PATH_LEN];
    NSAlias aliases[NS_MAX_ALIASES];
    int alias_count;
    int verbose;
    HMODULE gp_module;
    void *dll_handle; /* NSDllHandle* - opaque here to avoid circular include */
} NSContext;

typedef enum {
    CMD_HELP,
    CMD_LOGIN,
    CMD_LOGIN_ALIAS,
    CMD_SQL,
    CMD_BATCH,
    CMD_RESET,
    CMD_TERMINATE,
    CMD_LIST_ALIASES,
    CMD_VERSION,
    CMD_LOAD_DLL,
    CMD_UNLOAD_DLL,
    CMD_MAPLOAD_DLL,
    CMD_MAP,
    CMD_CALL,
    CMD_CALL_ADDR,
    CMD_INSPECT,
    CMD_PEINFO,
    CMD_SECTIONS,
    CMD_RESOURCE,
    CMD_HEXDUMP,
    CMD_SYMBOLS,
    CMD_DUMPSEC,
    CMD_UNKNOWN
} NSCommandType;

typedef struct {
    NSCommandType type;
    char arg1[NS_MAX_CMD_LEN];
    char arg2[NS_MAX_CMD_LEN];
    char raw[NS_MAX_CMD_LEN];
} NSParsedCommand;

void ns_context_init(NSContext *ctx);
void ns_context_cleanup(NSContext *ctx);

int ns_parse_command(const char *input, NSParsedCommand *cmd);
int ns_execute_command(NSContext *ctx, const NSParsedCommand *cmd);

int ns_alias_load(NSContext *ctx, const char *filepath);
int ns_alias_reload(NSContext *ctx);
NSAlias* ns_alias_find(NSContext *ctx, const char *name);

int ns_gp_login(NSContext *ctx, const char *username, const char *password, const char *company);
int ns_gp_terminate(NSContext *ctx);

int ns_sql_execute(NSContext *ctx, const char *query);
int ns_sql_connect(NSContext *ctx, const char *dsn, const char *user, const char *pass);
int ns_sql_disconnect(NSContext *ctx);

int ns_batch_process(NSContext *ctx, const char *filepath);

void ns_print_help(void);
void ns_print_version(void);

char* ns_trim(char *str);

#endif
