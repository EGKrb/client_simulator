#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Serveur de sandbox generique pour test_commands.ps1 (mode --sandbox de
MonNouvelApp.exe). Repond 200 + JSON sur n'importe quel chemin/methode,
pour valider les commandes --sim-* sans acces reseau externe.

Usage :
  python serve_sandbox.py [port]      (defaut 8080)
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class GenericHandler(BaseHTTPRequestHandler):
    def _answer(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = ""
        if length:
            body = self.rfile.read(length).decode("utf-8", "replace")
        payload = {
            "ok": True,
            "method": self.command,
            "path": self.path,
            "received": body,
        }
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._answer()

    def do_POST(self):
        self._answer()

    def do_PUT(self):
        self._answer()

    def do_DELETE(self):
        self._answer()

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    httpd = ThreadingHTTPServer(("localhost", port), GenericHandler)
    print("Generic sandbox HTTP sur http://localhost:%d" % port, flush=True)
    httpd.serve_forever()