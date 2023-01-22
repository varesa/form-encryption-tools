#!/usr/bin/bash
set -euo pipefail

CACHE_DIR=".podman_cache"

if [[ -d ${CACHE_DIR} ]]; then
    echo "Using $(readlink -f ${CACHE_DIR}) as cache"
    [[ -d ${CACHE_DIR}/registry ]] || mkdir ${CACHE_DIR}/registry

    PODMAN_BUILD_OPTS="-v ${PWD}/${CACHE_DIR}/registry:/root/.cargo/registry:Z"
else
    echo "Warning: Building without cache. Optimize compile times by running: ln -s \$(mktemp -d) ${CACHE_DIR}"
fi

podman run --rm -ti ${PODMAN_BUILD_OPTS:-} -v "$PWD:/app:Z" -v "$PWD/el7-target:/app/target:Z" rust-el7 bash -c "
    cd /app
    cargo build --release
"
