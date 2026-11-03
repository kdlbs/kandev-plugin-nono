#!/bin/sh
set -eu

plugin_root=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
consumer_root=$(mktemp -d)
trap 'rm -rf "$consumer_root"' EXIT HUP INT TERM
cp "$plugin_root/go.mod" "$plugin_root/go.sum" "$consumer_root/"
cp -R "$plugin_root/server" "$consumer_root/server"
cd "$consumer_root"
export GOWORK=off
go list -mod=readonly -m -json github.com/kdlbs/kandev/pluginsdk > sdk.json
python3 - <<'PY'
import json
with open('sdk.json') as source:
    sdk = json.load(source)
if sdk.get('Replace') or not sdk.get('Version'):
    raise SystemExit('SDK consumer requires a pinned public module without a replacement')
PY
go build -mod=readonly -trimpath -o plugin ./server
printf 'Standalone SDK consumer build passed.\n'
