#!/bin/sh
set -eu

exec \
    /usr/local/sbin/router-machine-git-publish.sh \
    "$@"
