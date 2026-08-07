#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    printf '%s\n' "usage: $0 FROZEN_ENGINE TEMPORARY_DIRECTORY PORT" >&2
    exit 2
fi

engine=$1
temporary_directory=$2
port=$3
case "$temporary_directory" in
    ""|.|..|/) printf '%s\n' "unsafe temporary directory" >&2; exit 2 ;;
esac
mkdir -p "$temporary_directory"
chmod 700 "$temporary_directory"
database="$temporary_directory/workspace.sqlite3"
rm -f "$database" "$database.worker.lock"

synthetic_password=synthetic-validation-password
printf '%s\n%s\n' "$synthetic_password" "$synthetic_password" \
    | "$engine" workspace init "$database" sample-org owner \
        >/dev/null 2>"$temporary_directory/init.log"

"$engine" web "$database" --port "$port" >"$temporary_directory/server.log" 2>&1 &
server_pid=$!
cleanup() {
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

ready=false
for _attempt in 1 2 3 4 5 6 7 8 9 10; do
    if curl --fail --silent "http://127.0.0.1:$port/health" \
        | grep -q '"status":"ok"'; then
        ready=true
        break
    fi
    sleep 1
done
if [ "$ready" != true ]; then
    printf '%s\n' "frozen web server did not become healthy" >&2
    sed -n '1,120p' "$temporary_directory/server.log" >&2
    exit 1
fi
