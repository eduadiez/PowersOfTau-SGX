#!/bin/bash

export PS1='[\$ENV_VAR] \W # '

source /root/.bashrc

sleep 1

echo "Generating..."

./compute_constrained_sgx >/dev/null 2>&1

curl -i -s -X POST https://api.trustedservices.intel.com/sgx/dev/attestation/v3/report \
    -H 'Content-Type: application/json' \
    -H 'Ocp-Apim-Subscription-Key: bc6ef22000ff41aca23ee0469c988821' \
    -d @quote.json -o attestation.json && \
    cat attestation.json && \
    echo "" && \
    echo -ne "\x1b[32mResult:\x1b[0m " && \
    cat attestation.json | awk '/^{/{print $0}' | jq .isvEnclaveQuoteStatus
