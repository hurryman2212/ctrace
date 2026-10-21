#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu

module_dir=$1
shared_include=$2
output=$3

# Canonical labels make repository, staged DKMS and out-of-tree builds agree.
# Generated hash values and build/package versions are deliberately not inputs.
manifest=$(mktemp)
temporary=
trap 'rm -f "$manifest" ${temporary:+"$temporary"}' EXIT HUP INT TERM
{
	for name in core.c probe.S probe.h target.c target.h generate-contract.sh; do
		digest=$(sha256sum <"$module_dir/$name")
		printf 'module/%s %s\n' "$name" "${digest%% *}"
	done
	digest=$(sha256sum <"$module_dir/include/uapi/linux/kctrace.h")
	printf 'uapi/linux/kctrace.h %s\n' "${digest%% *}"
	for path in "$shared_include"/kctrace/*.h; do
		name=${path##*/}
		digest=$(sha256sum <"$path")
		printf 'include/kctrace/%s %s\n' "$name" "${digest%% *}"
	done
} >"$manifest"
LC_ALL=C sort -o "$manifest" "$manifest"
contract_hash=$(sha256sum <"$manifest")
contract_hash=${contract_hash%% *}
mkdir -p "$(dirname "$output")"
temporary=$(mktemp "${output}.XXXXXX")
printf '%s\n' "$contract_hash" >"$temporary"
if ! cmp -s "$temporary" "$output"; then
	mv "$temporary" "$output"
fi
