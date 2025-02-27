#!/bin/bash

# Compile Falcon-1024 library for ARM64 Linux

# Ensure you're in the correct directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/sip_connect/PQClean/crypto_sign/falcon-1024/aarch64"

# Compile object files
gcc -c *.c -fPIC -O3 -march=armv8-a+crypto

# Create shared library
gcc -shared *.o -o libfalcon-1024_aarch64.so

# Set appropriate permissions
chmod 755 libfalcon-1024_aarch64.so

# Verify the library
echo "Library compilation complete:"
file libfalcon-1024_aarch64.so