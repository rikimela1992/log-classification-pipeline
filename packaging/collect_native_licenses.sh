#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    printf '%s\n' "usage: $0 BUNDLE_DIRECTORY OUTPUT_DIRECTORY" >&2
    exit 2
fi

bundle_directory=$1
output_directory=$2
case "$output_directory" in
    ""|.|..|/) printf '%s\n' "unsafe license output directory" >&2; exit 2 ;;
esac
rm -rf "$output_directory"
mkdir -p "$output_directory"
inventory=$(mktemp)
trap 'rm -f "$inventory"' EXIT HUP INT TERM
ldconfig_command=$(command -v ldconfig || true)
if [ -z "$ldconfig_command" ] && [ -x /sbin/ldconfig ]; then
    ldconfig_command=/sbin/ldconfig
fi
if [ -z "$ldconfig_command" ]; then
    printf '%s\n' "ldconfig is required to resolve native libraries" >&2
    exit 1
fi
find "$bundle_directory/_internal" -maxdepth 1 -type f -name '*.so*' \
    -printf '%f\n' | LC_ALL=C sort -u > "$inventory"

while IFS= read -r library; do
    case "$library" in
        libpython*) continue ;;
    esac
    system_library=$($ldconfig_command -p | awk -v name="$library" '$1 == name {print $NF; exit}')
    if [ -z "$system_library" ]; then
        printf '%s\n' "cannot resolve native library: $library" >&2
        exit 1
    fi
    system_library=$(readlink -f "$system_library")

    if command -v dpkg-query >/dev/null 2>&1; then
        package=$(dpkg-query -S "$system_library" 2>/dev/null | sed -n '1s/: .*//p')
        package=${package%%:*}
        copyright="/usr/share/doc/$package/copyright"
        if [ -z "$package" ] || [ ! -f "$copyright" ]; then
            printf '%s\n' "cannot locate Debian license for $library" >&2
            exit 1
        fi
        cp "$copyright" "$output_directory/$package.txt"
    elif command -v rpm >/dev/null 2>&1; then
        package=$(rpm -qf "$system_library")
        license_files=$(rpm -ql "$package" | awk '/^\/usr\/share\/licenses\//')
        if [ -z "$license_files" ]; then
            source_rpm=$(rpm -q --queryformat '%{SOURCERPM}' "$package")
            sibling_packages=$(
                rpm -qa --queryformat '%{NAME}\t%{SOURCERPM}\n' \
                    | awk -F '\t' -v source="$source_rpm" '$2 == source {print $1}'
            )
            for sibling_package in $sibling_packages; do
                sibling_licenses=$(
                    rpm -ql "$sibling_package" \
                        | awk '/^\/usr\/share\/licenses\//'
                )
                if [ -n "$sibling_licenses" ]; then
                    license_files=$(
                        printf '%s\n%s\n' "$license_files" "$sibling_licenses" \
                            | awk 'NF && !seen[$0]++'
                    )
                fi
            done
            if [ -z "$license_files" ]; then
                printf '%s\n' "cannot locate RPM license for $library" >&2
                exit 1
            fi
        fi
        destination="$output_directory/$package.txt"
        : > "$destination"
        for license_file in $license_files; do
            if [ -f "$license_file" ]; then
                printf '\n===== %s =====\n' "$license_file" >> "$destination"
                cat "$license_file" >> "$destination"
            fi
        done
        if [ ! -s "$destination" ]; then
            printf '%s\n' "RPM license files were unreadable for $library" >&2
            exit 1
        fi
    else
        printf '%s\n' "no supported package database for native licenses" >&2
        exit 1
    fi
done < "$inventory"

if ! find "$output_directory" -type f -name '*.txt' -print -quit | grep -q .; then
    printf '%s\n' "native license inventory is empty" >&2
    exit 1
fi
