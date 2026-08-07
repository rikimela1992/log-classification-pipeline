#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    printf '%s\n' "usage: $0 STAGE_DIRECTORY OUTPUT_FILE DEBIAN_VERSION" >&2
    exit 2
fi

stage_directory=$1
output_file=$2
version=$3
control_directory="$stage_directory/DEBIAN"
mkdir -p "$control_directory" "$(dirname "$output_file")"
installed_size=$(du -sk "$stage_directory" | cut -f1)
sed \
    -e "s/@VERSION@/$version/g" \
    -e "s/@INSTALLED_SIZE@/$installed_size/g" \
    packaging/debian/control > "$control_directory/control"
cp packaging/debian/postinst packaging/debian/prerm packaging/debian/postrm "$control_directory/"
chmod 755 "$control_directory/postinst" "$control_directory/prerm" "$control_directory/postrm"
find "$stage_directory" -type d -exec chmod 755 {} +
chmod 700 "$stage_directory/var/lib/log-classification-pipeline"
dpkg-deb --root-owner-group --build "$stage_directory" "$output_file"
