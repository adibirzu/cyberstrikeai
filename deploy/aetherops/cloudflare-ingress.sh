#!/bin/sh
# Attach cyberstrike.<region>.pentforge.app to a remotely managed tunnel.
# The live adi1 connector is token-managed (langfuse cloudflared, host
# network). It does not read a local ingress file. This script updates the
# Cloudflare configuration and leaves the existing hostnames in place.
#
# Required, and never printed:
#   CLOUDFLARE_API_TOKEN   Account Tunnel write
#   CLOUDFLARE_ACCOUNT_ID
#   CLOUDFLARE_TUNNEL_ID
# Optional:
#   AETHEROPS_REGION=eu
#   AETHEROPS_CYBERSTRIKE_PORT=18080
set -eu

token=${CLOUDFLARE_API_TOKEN:-}
account=${CLOUDFLARE_ACCOUNT_ID:-}
tunnel=${CLOUDFLARE_TUNNEL_ID:-}
region=${AETHEROPS_REGION:-eu}
port=${AETHEROPS_CYBERSTRIKE_PORT:-18080}

if [ -z "$token" ] || [ -z "$account" ] || [ -z "$tunnel" ]; then
  echo "CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, and CLOUDFLARE_TUNNEL_ID are required." >&2
  echo "The origin can listen on 127.0.0.1:${port} before those are set." >&2
  exit 2
fi

case "$region" in
  eu) host=cyberstrike.eu.pentforge.app ;;
  us) host=cyberstrike.us.pentforge.app ;;
  *) echo "AETHEROPS_REGION must be eu or us" >&2; exit 2 ;;
esac

python3 - "$account" "$tunnel" "$host" "$port" <<'PY'
import json, os, sys, urllib.request
account, tunnel, host, port = sys.argv[1:5]
token = os.environ["CLOUDFLARE_API_TOKEN"]
url = f"https://api.cloudflare.com/client/v4/accounts/{account}/cfd_tunnel/{tunnel}/configurations"
req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
with urllib.request.urlopen(req, timeout=30) as resp:
    body = json.load(resp)
if not body.get("success"):
    raise SystemExit("cloudflare read failed")
config = (body.get("result") or {}).get("config") or {}
ingress = list(config.get("ingress") or [])
origin = f"http://127.0.0.1:{port}"
kept = []
replaced = False
for rule in ingress:
    if rule.get("hostname") == host:
        rule = {
            "hostname": host,
            "service": origin,
            "originRequest": {"httpHostHeader": host, "noTLSVerify": False},
        }
        replaced = True
    kept.append(rule)
if not replaced:
    catch = [rule for rule in kept if not rule.get("hostname")]
    named = [rule for rule in kept if rule.get("hostname")]
    named.append({
        "hostname": host,
        "service": origin,
        "originRequest": {"httpHostHeader": host, "noTLSVerify": False},
    })
    kept = named + (catch or [{"service": "http_status:404"}])
config["ingress"] = kept
payload = json.dumps({"config": config}).encode()
put = urllib.request.Request(url, data=payload, method="PUT", headers=req.headers)
with urllib.request.urlopen(put, timeout=30) as resp:
    result = json.load(resp)
if not result.get("success"):
    raise SystemExit("cloudflare update failed")
print(f"ingress set {host} -> {origin}")
PY
