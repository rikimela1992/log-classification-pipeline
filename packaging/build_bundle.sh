#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    printf '%s\n' "usage: $0 BUILD_DIRECTORY OUTPUT_DIRECTORY" >&2
    exit 2
fi

build_directory=$1
output_directory=$2
case "$build_directory" in
    ""|.|..|/) printf '%s\n' "unsafe build directory" >&2; exit 2 ;;
esac
case "$output_directory" in
    ""|.|..|/) printf '%s\n' "unsafe output directory" >&2; exit 2 ;;
esac
rm -rf -- "$build_directory" "$output_directory/log-classify"
mkdir -p -- "$build_directory" "$output_directory"

pyinstaller \
    --clean \
    --noconfirm \
    --onedir \
    --name log-classify \
    --distpath "$output_directory" \
    --workpath "$build_directory/work" \
    --specpath "$build_directory/spec" \
    --collect-data log_classification_pipeline \
    --collect-submodules uvicorn \
    --copy-metadata log-classification-pipeline \
    --exclude-module gradio \
    --exclude-module readline \
    --exclude-module setuptools \
    --exclude-module torch \
    --exclude-module transformers \
    packaging/pyinstaller_entry.py

"$output_directory/log-classify/log-classify" doctor --require web
