#!/bin/sh

set -e
afl-clang -o insane-triangle-banana insane-triangle-banana.c pubkey.c -Wall -Wextra -pedantic `pkg-config --cflags --libs nss`
afl-fuzz -i indir/ -o outdir/ -f key.pub ./insane-triangle-banana
