#!/usr/bin/env python3
"""Write a CyberStrike config.yaml from AETHEROPS_* variables.

Reads the shared names. Does not print secret values.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def yaml_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: render-config.py DEST.yaml", file=sys.stderr)
        return 2
    dest = Path(sys.argv[1])
    region = (os.environ.get("AETHEROPS_REGION") or "eu").strip().lower()
    if region != "eu":
        print("AETHEROPS_REGION must be eu. This demo has no US console.", file=sys.stderr)
        return 2
    port = (os.environ.get("AETHEROPS_CYBERSTRIKE_PORT") or "18080").strip()
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        print("AETHEROPS_CYBERSTRIKE_PORT is not a port", file=sys.stderr)
        return 2
    data_dir = (os.environ.get("AETHEROPS_CYBERSTRIKE_DATA") or "").strip()
    if not data_dir:
        print("AETHEROPS_CYBERSTRIKE_DATA is required", file=sys.stderr)
        return 2
    llm = (os.environ.get("AETHEROPS_LLM_BASE_URL") or "http://127.0.0.1:11434/v1").strip()
    model = (os.environ.get("AETHEROPS_LLM_MODEL") or "ministral-3:14b").strip()
    key = (os.environ.get("AETHEROPS_LLM_API_KEY") or "local").strip() or "local"
    public = "cyberstrike.pentforge.app"
    db = str(Path(data_dir) / "conversations.db")
    text = f"""# Generated from AETHEROPS_* variables. Do not commit.
version: "v1.7.24"
server:
  host: 127.0.0.1
  port: {port}
  tls_enabled: false
  tls_auto_self_sign: false
  cors_allowed_origins:
    - https://pentforge.app
    - https://{public}
auth:
  session_duration_hours: 12
log:
  level: info
  output: stdout
audit:
  enabled: true
database:
  path: {yaml_string(db)}
ai:
  default_channel: aetherops
  channels:
    aetherops:
      name: AetherOps shared model
      provider: openai_compatible
      base_url: {yaml_string(llm)}
      api_key: {yaml_string(key)}
      model: {yaml_string(model)}
      max_total_tokens: 32000
      max_completion_tokens: 4096
vision:
  enabled: false
mcp:
  enabled: false
  host: 127.0.0.1
  port: 18081
external_mcp:
  servers: {{}}
c2:
  enabled: false
knowledge:
  enabled: false
"""
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    os.chmod(dest, 0o600)
    print(f"wrote {dest} region={region} port={port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
