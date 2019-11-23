#!/bin/bash
set -e

COMMAND=$@
source /home/user/.nix-profile/etc/profile.d/nix.sh && nix-shell /home/user/shell.nix --command "$COMMAND"