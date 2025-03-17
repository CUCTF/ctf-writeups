#!/bin/sh
exec timeout --foreground 300 \
    ./lkvm-static run \
    -c 1 \
    -m 128 \
    -k ./bzImage \
    -i ./initramfs.cpio.gz \
    --rng \
    --console virtio \
    --balloon
