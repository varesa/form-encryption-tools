#!/usr/bin/bash
set -euo pipefail

CACHE_DIR=".podman_cache"
BUILDER_IMAGE="localhost/form-encryption-tools-build"

build_image() {
    podman build -f Dockerfile.build_el7 -t "${BUILDER_IMAGE}"
}

if ! podman image inspect "${BUILDER_IMAGE}" >/dev/null 2>&1; then
    build_image
else
    built="$(date -d "$(podman image inspect "${BUILDER_IMAGE}" | jq -r '.[0].Created')" +%s)"
    modified="$(date -r Dockerfile.build +%s)"
    if [[ $modified -gt $built ]]; then
        echo "Build image out of date, rebuilding"
        build_image
    fi
fi

if [[ -d ${CACHE_DIR} ]]; then
    echo "Using $(readlink -f ${CACHE_DIR}) as cache"
    [[ -d ${CACHE_DIR}/registry ]] || mkdir ${CACHE_DIR}/registry
    PODMAN_BUILD_OPTS="-v ${PWD}/${CACHE_DIR}/registry:/root/.cargo/registry:Z"
else
    echo "Warning: Building without cache. Optimize compile times by running: ln -s \$(mktemp -d) ${CACHE_DIR}"
fi

podman run --rm -ti ${PODMAN_BUILD_OPTS:-} -v "$PWD:/app:Z" -v "$PWD/el7-target:/app/target:Z" "${BUILDER_IMAGE}" bash -c "
    cd /app
    cargo build --release
"
