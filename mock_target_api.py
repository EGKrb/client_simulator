#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mock serveur des endpoints Target pour le mode sandbox de MonNouvelApp.exe.

En mode --sandbox, TOUS les domaines Target sont rediriges vers localhost:8080 :
le Host d'origine est perdu, on route donc uniquement sur le chemin HTTP.

Endpoints couverts (acheminement web --buy-*) :
  GET  /v1/users/authenticated                       (users.target.com)
  POST /v2/logout                                    (auth.target.com)  -> X-CSRF-TOKEN
  GET  /v1/users/<id>/currency                       (economy.target.com)
  GET  /game-passes/v1/game-passes/<id>/product-info (apis.target.com)
  GET  /marketplace-service/v1/products/<id>/details (apis.target.com)
  GET  /v2/assets/<id>/details                       (economy.target.com)
  POST /v1/purchases/products/<productId>            (economy.target.com)

Usage :
  python mock_target_api.py [port]      (defaut 8080)
"""

import json
import re
import select
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# Etat simule (modifiable ici avant demarrage)
# ---------------------------------------------------------------------------
USER_ID = 1234567
USER_NAME = "SandboxUser"
DISPLAY_NAME = "Sandbox User"
BALANCE = 1_000_000
CSRF_TOKEN = "MOCK-CSRF-TOKEN-mock-target-api-0001"

# Tarifs par <id> de produit ; defaut si absent.
PRICES = {
    6738811: 100,  # exemple : le gamepass teste
}
DEFAULT_PRICE = 150
DEVPRODUCT_DEFAULT_PRICE = 200


# ---------------------------------------------------------------------------
# Routeur : (regex chemin) -> (methode, handler)
# ---------------------------------------------------------------------------
class TargetMockState:
    def __init__(self):
        self.balance = BALANCE

    def reset(self):
        self.balance = BALANCE


def tg_json(**kw):
    return json.dumps(kw, ensure_ascii=False).encode("utf-8")


def make_routes(state):
    """Retourne une liste de (pattern_regex, methodes, handler(handler, match, body) -> dict)."""

    def route_auth(h, m, body):
        h.ok_json({"id": USER_ID, "name": USER_NAME, "displayName": DISPLAY_NAME,
                   "created": "2020-01-01T00:00:00.000Z",
                   "isBanned": False, "isUnder13": False})

    def route_logout(h, m, body):
        # Le POST auth.target.com/v2/logout est utilise pour voler le token CSRF.
        h.ok_json({})

    def route_currency(h, m, body):
        h.ok_json({"robux": state.balance, "pendingRobux": 0, "credit": 0,
                   "premiumPayouts": 0})

    def route_gamepass_info(h, m, body):
        gid = int(m.group("id"))
        price = PRICES.get(gid, DEFAULT_PRICE)
        h.ok_json({
            "Name": "Sandbox Gamepass #%d" % gid,
            "Description": "Gamepass simule par mock_target_api.py",
            "PriceInRobux": price,
            "ProductId": gid * 10 + 1,
            "IsOwned": False,
            "Creator": {"Id": USER_ID, "Name": USER_NAME,
                        "CreatorTargetId": USER_ID, "CreatorType": "User"},
        })

    def route_devproduct_info(h, m, body):
        pid = int(m.group("id"))
        h.ok_json({
            "id": pid,
            "name": "Sandbox DevProduct #%d" % pid,
            "priceInRobux": DEVPRODUCT_DEFAULT_PRICE,
            "sellerId": USER_ID,
            "creatorId": USER_ID,
        })

    def route_asset_details(h, m, body):
        aid = int(m.group("id"))
        price = PRICES.get(aid, DEFAULT_PRICE)
        h.ok_json({
            "ProductId": aid * 10 + 1,
            "PriceInRobux": price,
            "Price": price,
            "Name": "Sandbox Asset #%d" % aid,
            "AssetTypeId": 19,
            "Creator": {"Id": USER_ID, "Name": USER_NAME,
                        "CreatorTargetId": USER_ID, "CreatorType": "User"},
        })

    def route_purchase(h, m, body):
        price = DEFAULT_PRICE
        if body:
            try:
                price = int(json.loads(body).get("expectedPrice", DEFAULT_PRICE))
            except Exception:
                pass
        if state.balance >= price:
            state.balance -= price
            h.ok_json({"purchased": True, "status": 1,
                       "statusMessage": "Sandbox purchase reussi (-%d R$)" % price,
                       "receipt": "SANDBOX-RECEIPT-%d" % (price * 31)})
        else:
            h.ok_json({"purchased": False, "status": 0,
                       "statusMessage": "Solde insuffisant en sandbox"})

    return [
        (re.compile(r"^/v1/users/authenticated$"),               ["GET"],    route_auth),
        (re.compile(r"^/v2/logout$"),                            ["POST"],   route_logout),
        (re.compile(r"^/v1/users/(?P<id>\d+)/currency$"),        ["GET"],    route_currency),
        (re.compile(r"^/game-passes/v1/game-passes/(?P<id>\d+)/product-info$"),
                                                                 ["GET"],    route_gamepass_info),
        (re.compile(r"^/marketplace-service/v1/products/(?P<id>\d+)/details$"),
                                                                 ["GET"],    route_devproduct_info),
        (re.compile(r"^/v2/assets/(?P<id>\d+)/details$"),        ["GET"],    route_asset_details),
        (re.compile(r"^/v1/purchases/products/(?P<pid>\d+)$"),   ["POST"],   route_purchase),
    ]


# ---------------------------------------------------------------------------
# Handler HTTP
# ---------------------------------------------------------------------------
class MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "TargetMock/1.0"
    state = None          # defini par le serveur
    routes = None

    # --- helpers ------------------------------------------------------------
    def log_message(self, fmt, *args):
        sys.stderr.write("[mock] %s - %s\n" % (self.address_string(), fmt % args))

    def read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def ok_json(self, obj):
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self._common_headers(len(payload))
        self.end_headers()
        self.wfile.write(payload)

    def not_found(self, method, path):
        payload = tg_json(error="Route sandbox inconnue", method=method, path=path)
        self.send_response(404)
        self._common_headers(len(payload))
        self.end_headers()
        self.wfile.write(payload)

    def _common_headers(self, content_length):
        self.send_header("Content-Type", "application/json; charset=utf-8")
        # L'exe recupere le jeton CSRF depuis l'header de CHAQUE reponse.
        self.send_header("X-CSRF-Token", CSRF_TOKEN)
        self.send_header("Content-Length", str(content_length))
        self.send_header("Connection", "keep-alive")

    # --- dispatch ------------------------------------------------------------
    def _dispatch(self, method):
        path = self.path.split("?")[0]
        body = self.read_body()
        for pattern, methods, handler in self.routes:
            m = pattern.match(path)
            if m and method in methods:
                handler(self, m, body)
                return
            if m:
                self.not_found(method, path)  # route connue mais mauvaise methode
                return
        self.not_found(method, path)

    def do_CONNECT(self):
        host, _, port = self.path.partition(":")
        port = int(port) if port else 443
        try:
            remote = socket.create_connection((host, port), timeout=10)
        except OSError as exc:
            self.send_error(502, "Bad Gateway: %s" % exc)
            return
        self.send_response(200, "Connection Established")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.connection.setblocking(False)
        remote.setblocking(False)
        try:
            self._tunnel(self.connection, remote)
        finally:
            remote.close()

    @staticmethod
    def _tunnel(client, remote):
        sockets = [client, remote]
        timeout = 30
        while True:
            readable, _, errors = select.select(sockets, [], sockets, timeout)
            if errors:
                break
            if not readable:
                break
            for sock in readable:
                try:
                    data = sock.recv(8192)
                except OSError:
                    data = b""
                if not data:
                    return
                other = remote if sock is client else client
                try:
                    other.sendall(data)
                except OSError:
                    return

    do_GET = lambda self: self._dispatch("GET")      # noqa: E731
    do_POST = lambda self: self._dispatch("POST")    # noqa: E731
    do_PUT = lambda self: self._dispatch("PUT")      # noqa: E731
    do_DELETE = lambda self: self._dispatch("DELETE")  # noqa: E731


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    state = TargetMockState()
    MockHandler.state = state
    MockHandler.routes = make_routes(state)
    httpd = ThreadingHTTPServer(("localhost", port), MockHandler)
    print("Mock Target API sur http://localhost:%d (balance %d R$)"
          % (port, state.balance))
    print("Renseigner --sandbox a MonNouvelApp.exe : tous les appels passent ici.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nArret du mock.")
    httpd.server_close()


if __name__ == "__main__":
    main()