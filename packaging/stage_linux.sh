#!/bin/sh
set -eu

if [ "$#" -lt 2 ]; then
    printf '%s\n' "usage: $0 BUNDLE_DIRECTORY STAGE_DIRECTORY [SBOM ...]" >&2
    exit 2
fi

bundle_directory=$1
stage_directory=$2
shift 2
case "$stage_directory" in
    ""|.|..|/) printf '%s\n' "unsafe stage directory" >&2; exit 2 ;;
esac
rm -rf -- "$stage_directory"
mkdir -p \
    "$stage_directory/usr/bin" \
    "$stage_directory/usr/lib/log-classification-pipeline" \
    "$stage_directory/usr/share/applications" \
    "$stage_directory/usr/share/doc/log-classification-pipeline" \
    "$stage_directory/usr/share/icons/hicolor/scalable/apps" \
    "$stage_directory/usr/share/metainfo" \
    "$stage_directory/usr/lib/systemd/system" \
    "$stage_directory/var/lib/log-classification-pipeline"

cp -a "$bundle_directory/." "$stage_directory/usr/lib/log-classification-pipeline/"
cp packaging/linux/log-classification-pipeline "$stage_directory/usr/bin/"
cp packaging/linux/log-classification-pipeline.desktop "$stage_directory/usr/share/applications/"
cp packaging/linux/log-classification-pipeline.svg "$stage_directory/usr/share/icons/hicolor/scalable/apps/"
cp packaging/linux/io.github.rikimela1992.log-classification-pipeline.metainfo.xml \
    "$stage_directory/usr/share/metainfo/"
cp packaging/linux/log-classification-pipeline.service "$stage_directory/usr/lib/systemd/system/"
cp LICENSE README.md "$stage_directory/usr/share/doc/log-classification-pipeline/"
cp docs/web-workspace.md "$stage_directory/usr/share/doc/log-classification-pipeline/WEB_WORKSPACE.md"
for document in "$@"; do
    cp -a "$document" "$stage_directory/usr/share/doc/log-classification-pipeline/"
done
chmod -R go-w "$stage_directory"
chmod 755 "$stage_directory/usr/bin/log-classification-pipeline"
chmod 700 "$stage_directory/var/lib/log-classification-pipeline"
