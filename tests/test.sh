#!/usr/bin/bash
TEST_ID=$(basename "$1" | cut -b -3)
check_error() {
    if [[ "$?" -ne "0" ]]; then
        echo "test.sh: Error occurred in $1"
        exit 1
    fi
}

pushd "$1" 1>/dev/null

shooker . ./patched
check_error hooking
LD_LIBRARY_PATH=./patched:${LD_LIBRARY_PATH} ./${TEST_ID}Bin
check_error executing

popd 1>/dev/null
