#!/bin/bash

set -e

ARCH='amd64'

NAME=veer

for os in linux darwin windows; do
    name="$NAME-$os-$ARCH"
    if [ "$os" == "windows" ]; then
        name="$name.exe"
    fi
    GOOS=$os GOARCH=$ARCH go build -o "$name"
    sha256sum "$name" >"$name.sha256"
done
