#!/bin/sh

# Needed to remove the new line when echoing the version
nl='
'

VERSION=

usage="\
Usage: $0 version_file
Print a version string.
"

version_file="$1"
if test -z "$version_file"; then
  echo "$usage"
  exit 1
fi
if test -f $version_file; then
  . ./$version_file
else
  echo "Version file $version_file not found"
  exit 1
fi

if test -z $PKG_VERSION; then
  echo "No version found in $version_file"
  exit 1
fi

# Omit the trailing newline
echo "$PKG_VERSION" | tr -d "$nl"
