#!/bin/bash
set -e

echo "--command $@ $PWD"

. /home/user/.nix-profile/etc/profile.d/nix.sh && nix-shell /home/user/shell.nix --command "$@"