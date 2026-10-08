#include "mock_controller.hpp"
#include "Luau/Compiler.h"
#include "lua.h"
#include "lualib.h"
#include <fstream>
#include <iterator>
#include <cstdio>

namespace localgate {

static int lua_respond(lua_State* L) {
    auto* ctx = static_cast<http1::Response*>(lua_touserdata(L, lua_upvalueindex(1)));
    ctx->code = (int)luaL_checkinteger(L, 1);
    if (lua_istable(L, 2)) {
        lua_pushnil(L);
        while (lua_next(L, 2)) {
            const char* k = lua_tostring(L, -2);
            ctx->set(k, lua_tostring(L, -1));
            lua_pop(L, 1);
        }
    }
    ctx->body = luaL_optstring(L, 3, "");
    ctx->set("content-length", std::to_string(ctx->body.size()));
    ctx->reason = http1::status_reason(ctx->code);
    return 0;
}

static int lua_log(lua_State* L) {
    fprintf(stderr, "[ltg-mock] %s\n", lua_tostring(L, 1));
    return 0;
}

static void push_request(lua_State* L, const http1::Request& r) {
    lua_newtable(L);
    lua_pushstring(L, r.method.c_str()); lua_setfield(L, -2, "method");
    lua_pushstring(L, r.target.c_str()); lua_setfield(L, -2, "target");
    lua_pushstring(L, r.get("host").c_str()); lua_setfield(L, -2, "host");
    lua_pushstring(L, r.body.c_str()); lua_setfield(L, -2, "body");
    lua_newtable(L);
    for (auto& [k, v] : r.headers) { lua_pushstring(L, v.c_str()); lua_setfield(L, -2, k.c_str()); }
    lua_setfield(L, -2, "headers");
    lua_setglobal(L, "req");
}

MockController::MockController() {
    L = luaL_newstate();
    luaL_openlibs((lua_State*)L);
    lua_pushcfunction((lua_State*)L, lua_log, "ltg_log");
    lua_setglobal((lua_State*)L, "mock_log");
}

MockController::~MockController() { if (L) lua_close((lua_State*)L); }

bool MockController::eval_script(const std::string& source, const http1::Request& req,
                                 const std::string& reason, http1::Response& out) {
    lua_State* L = (lua_State*)this->L;

    out = http1::Response{};
    push_request(L, req);

    lua_newtable(L);
    lua_pushlightuserdata(L, &out);
    lua_pushcclosure(L, lua_respond, "ltg_respond", 1);
    lua_setfield(L, -2, "respond");
    lua_pushstring(L, reason.c_str());
    lua_setfield(L, -2, "fail_reason");
    lua_setglobal(L, "mock");

    try {
        std::string bc = Luau::compile(source, {});
        if (luau_load(L, "@fallback", bc.data(), bc.size(), 0) != 0) return false;
        if (lua_pcall(L, 0, 0, 0) != 0) { lua_pop(L, 1); return false; }
    } catch (...) { return false; }

    return out.code >= 100 && out.code <= 999;
}

bool MockController::try_script(const std::string& path, const http1::Request& req,
                                const std::string& reason, http1::Response& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        fprintf(stderr, "[ltg-mock] script introuvable: %s\n", path.c_str());
        return false;
    }
    std::string src((std::istreambuf_iterator<char>(in)), {});
    return eval_script(src, req, reason, out);
}

bool MockController::try_fallback(const http1::Request& req, const std::string& reason, http1::Response& out) {
    // Le script par défaut vit dans ./fallback.luau (dossier courant du gateway).
    return try_script("fallback.luau", req, reason, out);
}

} // namespace localgate