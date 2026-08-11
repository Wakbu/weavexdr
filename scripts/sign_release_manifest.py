from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main() -> int:
    manifest_path = Path(sys.argv[1]).resolve()
    encoded_key = os.environ.get("WEAVEXDR_UPDATE_PRIVATE_KEY", "").strip()
    if not encoded_key:
        raise RuntimeError("WEAVEXDR_UPDATE_PRIVATE_KEY is not configured")
    private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(encoded_key, validate=True))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    # 서명 필드는 서명 대상에서 제외하고 키 순서를 고정해 클라이언트와 동일한
    # 바이트열을 검증하도록 한다. 개인 키는 파일에 기록하지 않는다.
    payload = {key: value for key, value in manifest.items() if key != "signature"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest["signature"] = base64.b64encode(private_key.sign(canonical)).decode("ascii")
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
