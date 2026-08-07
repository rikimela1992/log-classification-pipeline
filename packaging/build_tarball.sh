#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    printf '%s\n' "usage: $0 STAGE_DIRECTORY OUTPUT_FILE RELEASE_VERSION" >&2
    exit 2
fi

stage_directory=$1
output_file=$2
version=$3
archive_root="log-classification-pipeline-$version-linux-x86_64"
temporary_directory=$(mktemp -d)
trap 'rm -rf -- "$temporary_directory"' EXIT HUP INT TERM
mkdir -p "$temporary_directory/$archive_root"
cp -a "$stage_directory/." "$temporary_directory/$archive_root/"
rm -rf "$temporary_directory/$archive_root/DEBIAN"
mkdir -p "$(dirname "$output_file")"
tar \
    --sort=name \
    --mtime="@${SOURCE_DATE_EPOCH:-0}" \
    --owner=0 --group=0 --numeric-owner \
    -C "$temporary_directory" \
    -czf "$output_file" \
    "$archive_root"
