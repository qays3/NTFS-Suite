#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
index="$root/assets/samples-index.json"
samples_dir_name="$(jq -r '.samples_dir // "samples"' "$index")"
samples="$root/$samples_dir_name"

missing=0
count=0
while IFS= read -r rel; do
  [ -z "$rel" ] && continue
  count=$((count + 1))
  if [ ! -f "$samples/$rel" ]; then
    echo "missing: $rel"
    missing=1
  fi
done < <(jq -r '.cases[] as $c | $c.files[] | "\($c.dir)/\(.name)"' "$index")

if [ "$missing" -eq 0 ]; then
  echo "samples check passed, $count files present"
else
  echo "samples check failed"
  exit 1
fi
