#!/bin/sh
# Install CyberStrike as the EU node on this host. Loopback only.
# The public name is cyberstrike.eu.pentforge.app. cloudflared, already
# running with host networking for lf.pentforge.app, is what publishes it.
# This script does not open an inbound port and does not print secrets.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
DATA=${AETHEROPS_DATA_ROOT:-/home/adi/aetherops-data}
APP=/opt/pentforge/cyberstrike-eu
ENV_FILE=$DATA/configs/common.env
UNIT_DST=/etc/systemd/system/cyberstrike-eu.service
GO_VER=1.25.0
GO_SHA=05de75d6994a2783699815ee553bd5a9327d8b79991de36e38b66862782f54ae
GO_HOME=${HOME}/sdk/go${GO_VER}

if [ "$(id -u)" -eq 0 ]; then
  echo "Run as the operator user. The script calls sudo for /opt and systemd." >&2
  exit 2
fi

mkdir -p "$DATA/configs" "$DATA/secrets" "$DATA/cyberstrike-eu"
chmod 700 "$DATA/secrets"

if [ ! -f "$ENV_FILE" ]; then
  umask 077
  cat > "$ENV_FILE" <<'EOF'
# Shared by AetherOps, CyberStrike, vulnerability management, and patching.
# Project-specific names are aliases. See aetherops platform/variables.py.
AETHEROPS_REGION=eu
AETHEROPS_CYBERSTRIKE_URL=http://127.0.0.1:18080
AETHEROPS_CYBERSTRIKE_PORT=18080
AETHEROPS_CYBERSTRIKE_PUBLIC_HOST=cyberstrike.eu.pentforge.app
AETHEROPS_CYBERSTRIKE_DATA=/home/adi/aetherops-data/cyberstrike-eu
AETHEROPS_VULN_API_URL=http://127.0.0.1:18080
AETHEROPS_PATCH_API_URL=http://127.0.0.1:18080
AETHEROPS_REDAMON_URL=
AETHEROPS_LLM_BASE_URL=http://127.0.0.1:11434/v1
AETHEROPS_LLM_API_KEY=local
AETHEROPS_LLM_MODEL=ministral-3:14b
AETHEROPS_LANGFUSE_BASE_URL=https://lf.pentforge.app
EOF
  # Fill the model from the local Ollama tags when one is already loaded.
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY' || true
import json, urllib.request
from pathlib import Path
path = Path("/home/adi/aetherops-data/configs/common.env")
try:
    raw = urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=3).read()
    names = [m.get("name", "") for m in json.loads(raw).get("models", [])]
except Exception:
    names = []
prefer = next((n for n in names if n.startswith("ministral")), names[0] if names else "")
if not prefer:
    raise SystemExit(0)
text = path.read_text()
text = text.replace("AETHEROPS_LLM_MODEL=ministral-3:14b", f"AETHEROPS_LLM_MODEL={prefer}")
path.write_text(text)
print(f"llm model set to {prefer}")
PY
  fi
fi

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a
export AETHEROPS_CYBERSTRIKE_DATA=${AETHEROPS_CYBERSTRIKE_DATA:-$DATA/cyberstrike-eu}

sudo install -d -o "$(id -un)" -g "$(id -gn)" /opt/pentforge
if [ "$ROOT" != "$APP" ]; then
  sudo mkdir -p "$APP"
  sudo chown "$(id -un)":"$(id -gn)" "$APP"
  # Keep the data directory out of the tree. Do not delete a running database.
  tar -C "$ROOT" --exclude data --exclude firebase-debug.log -cf - . | tar -C "$APP" -xf -
fi

if ! "$GO_HOME/bin/go" version 2>/dev/null | grep -q "go${GO_VER}"; then
  mkdir -p "$(dirname "$GO_HOME")"
  tmp=$(mktemp)
  curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-arm64.tar.gz" -o "$tmp"
  echo "$GO_SHA  $tmp" | sha256sum -c -
  rm -rf "$GO_HOME"
  mkdir -p "$GO_HOME"
  tar -C "$GO_HOME" --strip-components=1 -xzf "$tmp"
  rm -f "$tmp"
fi

(
  cd "$APP"
  if ! command -v gcc >/dev/null 2>&1; then
    echo "gcc is required because go-sqlite3 needs cgo" >&2
    exit 1
  fi
  PATH="$GO_HOME/bin:$PATH" GOROOT="$GO_HOME" CGO_ENABLED=1 GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}" \
    go build -o cyberstrike-ai ./cmd/server
)

python3 "$APP/deploy/aetherops/render-config.py" "$DATA/cyberstrike-eu/config.yaml"
sudo cp "$APP/deploy/aetherops/cyberstrike-eu.service" "$UNIT_DST"
sudo systemctl daemon-reload
sudo systemctl enable --now cyberstrike-eu.service
sleep 2
if ! curl -fsS -o /dev/null --max-time 5 "http://127.0.0.1:${AETHEROPS_CYBERSTRIKE_PORT:-18080}/"; then
  # A 401 or 302 still means the process answered. curl -f treats those as failure.
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://127.0.0.1:${AETHEROPS_CYBERSTRIKE_PORT:-18080}/" || true)
  case "$code" in
    200|301|302|303|307|308|401|403) ;;
    *) echo "cyberstrike-eu did not answer on loopback (http $code)" >&2; sudo systemctl status cyberstrike-eu.service --no-pager >&2 || true; exit 1 ;;
  esac
fi

python3 - <<'PY'
import pathlib, subprocess
secret = pathlib.Path("/home/adi/aetherops-data/secrets/cyberstrike-eu-admin.txt")
if secret.exists() and secret.stat().st_size > 0:
    print(f"admin password already stored at {secret}")
    raise SystemExit(0)
log = subprocess.run(
    ["sudo", "-n", "journalctl", "-u", "cyberstrike-eu.service", "-n", "200", "--no-pager", "-o", "cat"],
    check=False, capture_output=True, text=True,
).stdout
password = ""
for raw in log.splitlines():
    line = __import__("re").sub(r"\x1b\[[0-9;]*m", "", raw)
    marker = "Password"
    if marker in line and "Store this password" not in line:
        password = line.split(marker, 1)[1].strip().strip("│").strip()
if not password:
    print("service is up; no new admin password was printed")
    raise SystemExit(0)
secret.parent.mkdir(parents=True, exist_ok=True)
secret.write_text("username=admin\n", encoding="utf-8")
secret.chmod(0o600)
# Append without echoing.
with secret.open("a", encoding="utf-8") as fh:
    fh.write("password=" + password + "\n")
print(f"admin password stored at {secret}")
PY

echo "EU origin listening on 127.0.0.1:${AETHEROPS_CYBERSTRIKE_PORT:-18080}"
echo "Public hostname cyberstrike.eu.pentforge.app is attached by deploy/aetherops/cloudflare-ingress.sh"
