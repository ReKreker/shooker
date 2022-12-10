#!/usr/bin/bash
shooker "$1" "$1/patched"
pushd "$1" 1>/dev/null
LD_LIBRARY_PATH=./patched:${LD_LIBRARY_PATH} ./check
popd 1>/dev/null
