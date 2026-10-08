#include "nightshift.h"

typedef BOOL (WINAPI *GPInitializeFunc)(DWORD);
typedef BOOL (WINAPI *GPLogonFunc)(LPCWSTR, LPCWSTR, LPCWSTR);
typedef BOOL (WINAPI *GPLogoffFunc)(void);
typedef BOOL (WINAPI *GPExecuteFunc)(LPCWSTR);

static GPInitializeFunc pInitialize = NULL;
static GPLogonFunc pLogon = NULL;
static GPLogoffFunc pLogoff = NULL;
static GPExecuteFunc pExecute = NULL;
static BOOL gp_logged_in = FALSE;

static int ns_gp_resolve_functions(NSContext *ctx) {
    if (ctx->gp_module) return 0;

    ctx->gp_module = LoadLibraryA("Dynamics.set");
    if (!ctx->gp_module) {
        ctx->gp_module = LoadLibraryA("Dynamics.exe");
    }
    if (!ctx->gp_module) {
        ctx->gp_module = LoadLibraryA("GPCommon.dll");
    }
    if (!ctx->gp_module) {
        fprintf(stderr, "%s Cannot load Dynamics GP library\n", NS_FAIL);
        return -1;
    }

    pInitialize = (GPInitializeFunc)GetProcAddress(ctx->gp_module, "Initialize");
    pLogon = (GPLogonFunc)GetProcAddress(ctx->gp_module, "LogonUser");
    pLogoff = (GPLogoffFunc)GetProcAddress(ctx->gp_module, "LogoffUser");
    pExecute = (GPExecuteFunc)GetProcAddress(ctx->gp_module, "ExecuteCommand");

    return 0;
}

int ns_gp_login(NSContext *ctx, const char *username, const char *password, const char *company) {
    wchar_t wuser[NS_MAX_NAME_LEN];
    wchar_t wpass[NS_MAX_NAME_LEN];
    wchar_t wcomp[NS_MAX_NAME_LEN];

    if (gp_logged_in) {
        printf("Already logged in. Use 'reset' first.\n");
        return -1;
    }

    MultiByteToWideChar(CP_UTF8, 0, username, -1, wuser, NS_MAX_NAME_LEN);
    MultiByteToWideChar(CP_UTF8, 0, password, -1, wpass, NS_MAX_NAME_LEN);
    MultiByteToWideChar(CP_UTF8, 0, company ? company : "", -1, wcomp, NS_MAX_NAME_LEN);

    if (ns_gp_resolve_functions(ctx) != 0)
        return -1;

    if (pInitialize) {
        pInitialize(0);
    }

    if (pLogon) {
        if (pLogon(wuser, wpass, wcomp)) {
            gp_logged_in = TRUE;
            printf("%s Logged in as: %s\n", NS_SUCCESS, username);
            return 0;
        } else {
            fprintf(stderr, "%s Login failed for: %s\n", NS_FAIL, username);
            return -1;
        }
    }

    fprintf(stderr, "%s GP Logon function not available\n", NS_FAIL);
    return -1;
}

int ns_gp_terminate(NSContext *ctx) {
    if (gp_logged_in && pLogoff) {
        pLogoff();
        gp_logged_in = FALSE;
    }

    if (ctx->gp_module) {
        FreeLibrary(ctx->gp_module);
        ctx->gp_module = NULL;
    }

    printf("%s Session terminated\n", NS_SUCCESS);
    return 0;
}
