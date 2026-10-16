#!/usr/bin/env bash
# Regenerates .github/assets/demo.gif with one command, from the repository root:
#
#   .github/assets/build-demo.sh
#
# Requires: go, vhs (https://github.com/charmbracelet/vhs, which needs ttyd and
# ffmpeg on PATH) and ffmpeg.
#
# Segment 1 (terminal): `vhs demo.tape` runs the real gosqlx CLI (validate,
#   format, lint) on demo.sql.
# Segment 2 (playground): playground.png, a 960x540 screenshot of
#   https://gosqlx.dev/playground/, shown for PLAYGROUND_SECONDS. Replace the
#   PNG when the playground UI changes.
set -euo pipefail

cd "$(dirname "$0")/../.."
A=.github/assets
PLAYGROUND_SECONDS=${PLAYGROUND_SECONDS:-3}
work=$(mktemp -d)
trap 'rm -rf "$work"; rm -f "$A/demo-terminal.gif"' EXIT

# Put the freshly built CLI on PATH for the tape.
GOBIN="$work/bin" go install ./cmd/gosqlx
PATH="$work/bin:$PATH" vhs "$A/demo.tape"

# Append the playground still, then re-quantize into one optimized palette.
ffmpeg -v error -y -i "$A/demo-terminal.gif" -loop 1 -t "$PLAYGROUND_SECONDS" -i "$A/playground.png" \
  -filter_complex "[0:v]fps=12,scale=960:540:flags=lanczos,setsar=1[a];[1:v]fps=12,scale=960:540:flags=lanczos,setsar=1[b];[a][b]concat=n=2:v=1:a=0,split[x][y];[y]palettegen=max_colors=128[p];[x][p]paletteuse=dither=bayer:bayer_scale=4" \
  "$A/demo.gif"

ls -l "$A/demo.gif"
