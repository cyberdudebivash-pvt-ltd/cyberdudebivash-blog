#!/usr/bin/env python3
"""
One-time helper to mint a fresh BLOGGER_REFRESH_TOKEN after Google revokes or
expires the current one (syndication pipeline logs show "invalid_grant" on
token refresh). Run this LOCALLY — it needs a browser and access to
localhost — signed in as the Google account that owns the Blogger blog.

Usage:
    BLOGGER_CLIENT_ID=xxx BLOGGER_CLIENT_SECRET=yyy python3 scripts/blogger_oauth_reauth.py

(Reuses the existing BLOGGER_CLIENT_ID / BLOGGER_CLIENT_SECRET — the same
values already stored as GitHub Actions secrets. Only the refresh token
needs replacing.)

If Google rejects the redirect with "redirect_uri_mismatch": the OAuth
client is registered as a "Web application" type, which requires the exact
redirect URI to be pre-authorized. Add http://localhost:8765 under
"Authorized redirect URIs" for this client in Google Cloud Console
(APIs & Services > Credentials), or set BLOGGER_OAUTH_PORT to a port that's
already authorized for this client.

On success, prints the new refresh token — copy it into the
BLOGGER_REFRESH_TOKEN secret at:
    https://github.com/cyberdudebivash/cyberdudebivash-blog/settings/secrets/actions
"""
import http.server
import os
import sys
import urllib.parse
import webbrowser

import requests

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
SCOPE = "https://www.googleapis.com/auth/blogger"
PORT = int(os.environ.get("BLOGGER_OAUTH_PORT", "8765"))
REDIRECT_URI = f"http://localhost:{PORT}"

_result = {}


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        _result["code"] = params.get("code", [None])[0]
        _result["error"] = params.get("error", [None])[0]
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        msg = "Authorization failed — you can close this tab." if _result.get("error") \
            else "Authorized — you can close this tab and return to the terminal."
        self.wfile.write(f"<html><body><p>{msg}</p></body></html>".encode())

    def log_message(self, *args):
        pass  # keep stdout clean — only our own prints matter


def main() -> int:
    client_id = os.environ.get("BLOGGER_CLIENT_ID") or input("BLOGGER_CLIENT_ID: ").strip()
    client_secret = os.environ.get("BLOGGER_CLIENT_SECRET") or input("BLOGGER_CLIENT_SECRET: ").strip()

    auth_url = AUTH_URL + "?" + urllib.parse.urlencode({
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": SCOPE,
        "access_type": "offline",
        "prompt": "consent",  # force a NEW refresh_token even if one exists already
    })

    server = http.server.HTTPServer(("localhost", PORT), _CallbackHandler)
    server.timeout = 300  # handle_request() gives up after 5 minutes of no callback

    print(f"\nOpen this URL and sign in as the Google account that owns the Blogger blog:\n\n{auth_url}\n")
    try:
        webbrowser.open(auth_url)
    except Exception:
        pass
    print(f"Waiting for the redirect to {REDIRECT_URI} (5 min timeout)...")

    server.handle_request()
    server.server_close()

    if _result.get("error"):
        print(f"Google returned an error: {_result['error']}", file=sys.stderr)
        return 1
    code = _result.get("code")
    if not code:
        print("Timed out waiting for authorization — no code received.", file=sys.stderr)
        return 1

    resp = requests.post(TOKEN_URL, data={
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
    }, timeout=15)

    if not resp.ok:
        print(f"Token exchange failed {resp.status_code}: {resp.text}", file=sys.stderr)
        return 1

    data = resp.json()
    refresh_token = data.get("refresh_token")
    if not refresh_token:
        print(
            "Google did not return a refresh_token even with prompt=consent. "
            "Revoke this app's access at https://myaccount.google.com/permissions "
            "and re-run this script.",
            file=sys.stderr,
        )
        return 1

    print("\nSuccess — new refresh token:\n")
    print(refresh_token)
    print(
        "\nUpdate the BLOGGER_REFRESH_TOKEN secret at:\n"
        "https://github.com/cyberdudebivash/cyberdudebivash-blog/settings/secrets/actions\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
