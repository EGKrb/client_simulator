#include "nightshift.h"

static SQLHENV sql_env = SQL_NULL_HENV;
static SQLHDBC sql_conn = SQL_NULL_HDBC;
static int sql_connected = 0;

int ns_sql_connect(NSContext *ctx, const char *dsn, const char *user, const char *pass) {
    SQLRETURN ret;

    if (sql_connected) return 0;

    ret = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &sql_env);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        fprintf(stderr, "%s Failed to allocate SQL environment\n", NS_FAIL);
        return -1;
    }

    SQLSetEnvAttr(sql_env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0);

    ret = SQLAllocHandle(SQL_HANDLE_DBC, sql_env, &sql_conn);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        fprintf(stderr, "%s Failed to allocate SQL connection\n", NS_FAIL);
        return -1;
    }

    ret = SQLConnectA(sql_conn,
        (SQLCHAR*)dsn, SQL_NTS,
        (SQLCHAR*)(user ? user : ""), SQL_NTS,
        (SQLCHAR*)(pass ? pass : ""), SQL_NTS);

    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        fprintf(stderr, "%s Failed to connect to database: %s\n", NS_FAIL, dsn);
        return -1;
    }

    sql_connected = 1;
    if (ctx->verbose)
        printf("%s Connected to database: %s\n", NS_SUCCESS, dsn);

    return 0;
}

int ns_sql_disconnect(NSContext *ctx) {
    (void)ctx;
    if (!sql_connected) return 0;

    if (sql_conn != SQL_NULL_HDBC) {
        SQLDisconnect(sql_conn);
        SQLFreeHandle(SQL_HANDLE_DBC, sql_conn);
        sql_conn = SQL_NULL_HDBC;
    }
    if (sql_env != SQL_NULL_HENV) {
        SQLFreeHandle(SQL_HANDLE_ENV, sql_env);
        sql_env = SQL_NULL_HENV;
    }
    sql_connected = 0;
    return 0;
}

int ns_sql_execute(NSContext *ctx, const char *query) {
    SQLHSTMT stmt;
    SQLRETURN ret;
    SQLCHAR col_name[256];
    SQLSMALLINT col_type;
    SQLSMALLINT col_count;
    SQLSMALLINT i;
    char value_buf[4096];
    SQLLEN value_len;
    int row_count = 0;

    if (!sql_connected) {
        fprintf(stderr, "%s Not connected to database. Use 'connect' first.\n", NS_FAIL);
        return -1;
    }

    ret = SQLAllocHandle(SQL_HANDLE_STMT, sql_conn, &stmt);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        fprintf(stderr, "%s Failed to allocate statement\n", NS_FAIL);
        return -1;
    }

    ret = SQLExecDirectA(stmt, (SQLCHAR*)query, SQL_NTS);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO && ret != SQL_NO_DATA) {
        SQLCHAR sqlstate[6], msg[SQL_MAX_MESSAGE_LENGTH];
        SQLINTEGER native_err;
        SQLSMALLINT msg_len;
        SQLGetDiagRecA(SQL_HANDLE_STMT, stmt, 1, sqlstate, &native_err, msg, sizeof(msg), &msg_len);
        fprintf(stderr, "%s SQL Error [%s]: %s\n", NS_FAIL, sqlstate, msg);
        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
        return -1;
    }

    SQLNumResultCols(stmt, &col_count);

    if (col_count > 0) {
        for (i = 1; i <= col_count; i++) {
            SQLDescribeColA(stmt, i, col_name, sizeof(col_name), NULL, &col_type, NULL, NULL, NULL);
            if (i > 1) printf(" | ");
            printf("%-20s", col_name);
        }
        printf("\n");

        for (i = 1; i <= col_count; i++) {
            if (i > 1) printf(" + ");
            printf("%-20s", "--------------------");
        }
        printf("\n");

        while (SQLFetch(stmt) != SQL_NO_DATA) {
            for (i = 1; i <= col_count; i++) {
                ret = SQLGetData(stmt, i, SQL_C_CHAR, value_buf, sizeof(value_buf), &value_len);
                if (i > 1) printf(" | ");
                if (value_len == SQL_NULL_DATA) {
                    printf("%-20s", "NULL");
                } else {
                    printf("%-20s", value_buf);
                }
            }
            printf("\n");
            row_count++;
        }
    }

    printf("%s Query executed. %d row(s) affected.\n", NS_SUCCESS, row_count);
    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    return 0;
}
