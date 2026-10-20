#!/usr/bin/env bash
# 上传升级包到 MinIO（幂等）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# 从 compose/.env 读凭据
if [ -f "$ROOT/compose/.env" ]; then
  set -a
  source "$ROOT/compose/.env"
  set +a
fi

echo "=== 上传升级包到 MinIO（幂等） ==="

if ! docker ps --format '{{.Names}}' | grep -q ota-minio; then
  echo "[FAIL] ota-minio 容器未运行"
  exit 1
fi

cat > /tmp/upload_to_minio.py <<'PY'
import hashlib
import sys
from pathlib import Path
from minio import Minio
from minio.error import S3Error

import os
client = Minio("ota-minio:9000",
               access_key=os.environ["MINIO_ROOT_USER"],
               secret_key=os.environ["MINIO_ROOT_PASSWORD"],
               secure=False)

BUCKET = "ota-packages"


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def upload_idempotent(obj_name: str, local_path: Path) -> str:
    """
    幂等上传：
    - 本地不存在 → 报错
    - 远端不存在 → 上传
    - 远端存在且 content-sha256 一致 → SKIP
    - 远端存在但不一致 → 覆盖上传
    """
    if not local_path.exists():
        print(f"  [FAIL] {obj_name}: 本地文件不存在 {local_path}")
        return "failed"

    local_size = local_path.stat().st_size
    local_sha = sha256_of_file(local_path)

    try:
        stat = client.stat_object(BUCKET, obj_name)
        md = stat.metadata or {}
        remote_sha = (md.get("x-amz-meta-content-sha256")
                      or md.get("X-Amz-Meta-Content-Sha256")
                      or md.get("content-sha256")
                      or "")
        if remote_sha == local_sha:
            print(f"  [SKIP]   {obj_name} 已存在且 hash 一致 ({local_size:,} bytes)")
            return "skipped"
        print(f"  [UPDATE] {obj_name} hash 变化 "
              f"({remote_sha[:12] or 'N/A'}... → {local_sha[:12]}...)")
    except S3Error:
        print(f"  [NEW]    {obj_name} 首次上传")

    client.fput_object(BUCKET, obj_name, str(local_path),
                       metadata={"content-sha256": local_sha})
    print(f"  [OK]     {obj_name} 上传完成 ({local_size:,} bytes)")
    return "uploaded"


# 1. 确保 bucket 存在
if not client.bucket_exists(BUCKET):
    client.make_bucket(BUCKET)
    print(f"[准备] 创建 bucket: {BUCKET}")
else:
    print(f"[准备] bucket 已存在: {BUCKET}")

print()

# 2. 幂等上传
targets = [
    ("payload.enc", Path("/data/packages/source/payload.enc")),
    ("payload.bin", Path("/data/packages/source/payload.bin")),
    ("manifests/manifest-v1.json",
     Path("/data/packages/manifests/manifest-v1.json")),
    ("manifests/manifest-canonical.json",
     Path("/data/packages/manifests/manifest-canonical.json")),
    ("manifests/manifest-v1.sig",
     Path("/data/packages/manifests/manifest-v1.sig")),
]

stats = {"uploaded": 0, "skipped": 0, "failed": 0}
for obj, local in targets:
    s = upload_idempotent(obj, local)
    stats[s] = stats.get(s, 0) + 1

print()
print(f"[汇总] uploaded={stats.get('uploaded',0)}  "
      f"skipped={stats.get('skipped',0)}  "
      f"failed={stats.get('failed',0)}")

# 3. 列出 bucket 内容
print("\n--- bucket 内容 ---")
for obj in client.list_objects(BUCKET, recursive=True):
    print(f"  {obj.object_name:40s}  {obj.size:>12,d}  {obj.etag[:12]}")

if stats.get("failed", 0) > 0:
    sys.exit(1)
PY

docker cp /tmp/upload_to_minio.py ota-api:/tmp/upload_to_minio.py
docker exec -e MINIO_ROOT_USER="$MINIO_ROOT_USER" -e MINIO_ROOT_PASSWORD="$MINIO_ROOT_PASSWORD" ota-api python3 /tmp/upload_to_minio.py

echo
echo "[OK] 上传完成（幂等：相同内容自动 SKIP）"
