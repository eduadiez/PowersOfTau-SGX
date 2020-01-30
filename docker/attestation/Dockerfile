FROM ubuntu:18.04@sha256:6e9f67fa63b0323e9a1e587fd71c561ba48a034504fb804fd26fd8800039835d

ENV SGX_TAG sgx_2.7.1
ENV SGX_BIN sgx_linux_x64_sdk_2.7.101.3.bin
ENV DEBIAN_FRONTEND=noninteractive

ENV sdk_bin https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.7.101.3.bin
ENV psw_deb https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/ubuntu18.04-server/libsgx-enclave-common_2.7.101.3-bionic1_amd64.deb
ENV psw_dev_deb https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/ubuntu18.04-server/libsgx-enclave-common-dev_2.7.101.3-bionic1_amd64.deb
ENV psw_dbgsym_deb https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/ubuntu18.04-server/libsgx-enclave-common-dbgsym_2.7.101.3-bionic1_amd64.ddeb

WORKDIR /home/user/mesatee-sgx/code/build

RUN apt update && apt install -y curl jq wget sudo libprotobuf10 make

RUN wget -O /tmp/psw.deb ${psw_deb} && \
    wget -O /tmp/psw_dev.deb ${psw_dev_deb} && \
    wget -O /tmp/psw_dbgsym.deb ${psw_dbgsym_deb} && \
    wget -O /tmp/sdk.bin ${sdk_bin} && \
    cd /tmp && \
    sudo dpkg -i /tmp/psw.deb && \
    sudo dpkg -i /tmp/psw_dev.deb && \
    sudo dpkg -i /tmp/psw_dbgsym.deb && \
    chmod +x /tmp/sdk.bin && \
    echo -e 'no\n/opt' | /tmp/sdk.bin && \
    echo 'source /opt/sgxsdk/environment' >> /root/.bashrc && \
    echo 'LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service'  >> /root/.bashrc && \
    rm -rf /tmpr/sgx/*
ADD . . 
#RUN echo 'export PS1="[\$ENV_VAR] \W # "' >> /root/.bashrc
ENV PS1='[\$ENV_VAR] \W # '
CMD ./entrypoint.sh
