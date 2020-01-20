#!/bin/bash
set -e

sudo LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service
source /opt/intel/sgxsdk/environment

COMMAND=$@
. /home/user/.nix-profile/etc/profile.d/nix.sh && \
    nix-shell /home/user/shell.nix --command " \
    $COMMAND"