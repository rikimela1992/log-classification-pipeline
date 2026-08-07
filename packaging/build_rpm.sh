#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    printf '%s\n' "usage: $0 STAGE_DIRECTORY OUTPUT_DIRECTORY" >&2
    exit 2
fi

stage_directory=$1
output_directory=$2
rpm_root=$(mktemp -d)
trap 'rm -rf -- "$rpm_root"' EXIT HUP INT TERM
mkdir -p "$rpm_root"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS} "$output_directory"
archive_root=$(mktemp -d)
trap 'rm -rf -- "$rpm_root" "$archive_root"' EXIT HUP INT TERM
mkdir -p "$archive_root/stage"
cp -a "$stage_directory/." "$archive_root/stage/"
rm -rf "$archive_root/stage/DEBIAN"
tar \
    --sort=name \
    --mtime="@${SOURCE_DATE_EPOCH:-0}" \
    --owner=0 --group=0 --numeric-owner \
    -C "$archive_root" \
    -czf "$rpm_root/SOURCES/log-classification-pipeline-stage.tar.gz" \
    stage
cp packaging/linux/log-classification-pipeline.spec "$rpm_root/SPECS/"
rpmbuild --define "_topdir $rpm_root" -bb "$rpm_root/SPECS/log-classification-pipeline.spec"
find "$rpm_root/RPMS" -type f -name '*.rpm' -exec cp {} "$output_directory/" \;
