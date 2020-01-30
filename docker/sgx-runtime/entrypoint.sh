#!/bin/bash

export PS1='[\$ENV_VAR] \W # '

source /root/.bashrc

sleep 1

exec "$@"


