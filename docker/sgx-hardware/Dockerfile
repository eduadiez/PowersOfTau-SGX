FROM alpine:latest

RUN apk add -U build-base git bash && \
    git clone https://github.com/intel/sgx-software-enable.git && \
    cd sgx-software-enable && \
    make && \
    cp sgx_enable /usr/local/bin

FROM alpine:latest

RUN apk add -U perl

COPY --from=0 /usr/local/bin/sgx_enable /usr/local/bin/sgx_enable
COPY entrypoint.sh /usr/local/bin/

ENTRYPOINT ["sgx_enable"]