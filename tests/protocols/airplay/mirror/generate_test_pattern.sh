#!/usr/bin/env bash
# Regenerates test_pattern.h264. Requires ffmpeg in PATH.
# The output is checked into the repo so contributors do NOT need ffmpeg
# installed to run tests — only to regenerate the asset.
set -euo pipefail
cd "$(dirname "$0")"
ffmpeg -y -f lavfi -i "testsrc=size=1280x720:rate=30" -t 5 \
    -c:v libx264 -profile:v baseline \
    -g 30 -keyint_min 30 -sc_threshold 0 -bf 0 -pix_fmt yuv420p \
    -f h264 test_pattern.h264
echo "Generated $(stat -f%z test_pattern.h264 2>/dev/null || stat -c%s test_pattern.h264) bytes"
