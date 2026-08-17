#!/usr/bin/env python3
"""
web-search-bridge.py — dialect-reshape bridge for DSH web_search

DSH's built-in web-search-deepseek provider speaks the DeepSeek-native
Anthropic dialect (web_search_tool_result blocks). This bridge lets that
provider run its native web_search_20250305 tool against OpenRouter's
Anthropic-compatible /api/v1/messages endpoint, which actually executes the
search but answers in the Anthropic server-tool dialect (server_tool_use +
text.citations).

Flow:
  provider --POST /messages (x-api-key: <k>)--> bridge -> OpenRouter
  OpenRouter (server_tool_use + text.citations) -> bridge reshape
      -> {type:"web_search_tool_result", content:[{type:"web_search_result",url,title}]}
         + {type:"text", citations:[{type:"web_search_result_location",url,title,cited_text}]}
      -> provider ({source,url,title,snippet})

The incoming x-api-key / authorization header is the provider's resolved
credential (e.g. OPENROUTER_API_KEY from the dsh process env) and is forwarded
unchanged — the bridge stores no secrets.

Stdlib only. Bind localhost. No deps.
"""

import json
import os
import sys
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = os.environ.get("UPSTREAM_URL", "https://openrouter.ai/api/v1/messages")
HOST = os.environ.get("BRIDGE_HOST", "127.0.0.1")
PORT = int(os.environ.get("BRIDGE_PORT", "8091"))


def reshape(upstream_body):
    """Convert OpenRouter's Anthropic-dialect response to DeepSeek dialect."""
    content = upstream_body.get("content") or []
    citations = []      # {url,title,cited_text} — deduped by url
    text_parts = []
    for block in content:
        if block.get("type") != "text":
            continue
        text_parts.append(block.get("text") or "")
        for cite in block.get("citations") or []:
            url = (cite.get("url") or "").strip()
            if not url:
                continue
            if any(c["url"] == url for c in citations):
                continue
            citations.append({
                "url": url,
                "title": (cite.get("title") or "").strip() or None,
                "cited_text": (cite.get("cited_text") or "").strip() or None,
            })

    # Preserve the upstream envelope fields the provider's parser ignores but
    # keeps the response well-formed.
    out = {
        "id": upstream_body.get("id") or "msg_bridge",
        "type": upstream_body.get("type") or "message",
        "role": upstream_body.get("role") or "assistant",
        "model": upstream_body.get("model"),
        "content": [
            {
                "type": "web_search_tool_result",
                "content": [
                    {"type": "web_search_result", "url": c["url"], **({"title": c["title"]} if c["title"] else {})}
                    for c in citations
                ],
            },
            {
                "type": "text",
                "text": " ".join(p for p in text_parts if p),
                "citations": [
                    {"type": "web_search_result_location", "url": c["url"], **({"title": c["title"]} if c["title"] else {}), **({"cited_text": c["cited_text"]} if c["cited_text"] else {})}
                    for c in citations
                ],
            },
        ],
    }
    for key in ("stop_reason", "usage"):
        if key in upstream_body:
            out[key] = upstream_body[key]
    return out


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quiet
        sys.stderr.write("[bridge] %s\n" % (fmt % args))

    def _send(self, status, payload, ctype="application/json"):
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path not in ("/messages", "/v1/messages"):
            self._send(404, {"error": {"message": "not found"}})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception as exc:  # bad body
            self._send(400, {"error": {"message": "invalid JSON body: %s" % exc}})
            return

        # Forward with the provider's credential pass-through.
        req_headers = {
            "x-api-key": self.headers.get("x-api-key") or "",
            "authorization": self.headers.get("authorization") or "",
            "anthropic-version": self.headers.get("anthropic-version") or "2023-06-01",
            "content-type": "application/json",
            "accept": "application/json",
            "user-agent": "deepseek-harness/0.0.1",
        }
        request = urllib.request.Request(
            UPSTREAM,
            data=json.dumps(body).encode("utf-8"),
            headers=req_headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as resp:
                upstream = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            try:
                payload = json.loads(raw)
            except Exception:
                payload = {"error": {"message": raw or ("upstream HTTP %d" % exc.code)}}
            self._send(exc.code, payload)
            return
        except Exception as exc:
            self._send(502, {"error": {"message": "upstream failure: %s" % exc}})
            return

        self._send(200, reshape(upstream))


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    sys.stderr.write("[bridge] listening on http://%s:%d -> %s\n" % (HOST, PORT, UPSTREAM))
    sys.stderr.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()