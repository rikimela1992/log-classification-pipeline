#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
    printf '%s\n' "usage: $0 STAGE_DIRECTORY OUTPUT_FILE APPIMAGETOOL RUNTIME" >&2
    exit 2
fi

stage_directory=$1
output_file=$2
appimagetool=$3
runtime=$4
appdir=$(mktemp -d)
trap 'rm -rf -- "$appdir"' EXIT HUP INT TERM
cp -a "$stage_directory/." "$appdir/"
rm -rf "$appdir/DEBIAN" "$appdir/usr/lib/systemd" "$appdir/var"
cp packaging/linux/log-classification-pipeline.desktop "$appdir/"
cp packaging/linux/log-classification-pipeline.svg "$appdir/"
cp packaging/linux/AppRun "$appdir/"
ln -s log-classification-pipeline.svg "$appdir/.DirIcon"
chmod 755 "$appdir/AppRun"
mkdir -p "$(dirname "$output_file")"
ARCH=x86_64 "$appimagetool" --runtime-file "$runtime" "$appdir" "$output_file"
chmod 755 "$output_file"
