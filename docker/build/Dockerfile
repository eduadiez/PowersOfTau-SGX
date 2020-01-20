FROM ubuntu:18.04@sha256:6e9f67fa63b0323e9a1e587fd71c561ba48a034504fb804fd26fd8800039835d

ENV MESATEE_SGX_COMMIT 5929e2fa2cd247bf29640d6353e2bc79d4bc87f1
ENV RUST_VERSION nightly-2019-11-25
ENV SGX_TAG sgx_2.7.1
ENV SGX_BIN sgx_linux_x64_sdk_2.7.101.3.bin
ENV DEBIAN_FRONTEND=noninteractive

ENV psw_deb https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/ubuntu18.04-server/libsgx-enclave-common_2.7.101.3-bionic1_amd64.deb
ENV psw_dev_deb https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/ubuntu18.04-server/libsgx-enclave-common-dev_2.7.101.3-bionic1_amd64.deb
ENV psw_dbgsym_deb https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/ubuntu18.04-server/libsgx-enclave-common-dbgsym_2.7.101.3-bionic1_amd64.ddeb

RUN apt-get update \
        && apt-get install -y curl git wget sudo nano xz-utils python  \
        && mkdir -p /nix /etc/nix \
        && chmod a+rwx /nix \
        && echo 'sandbox = false' > /etc/nix/nix.conf \
        && rm -rf /var/lib/apt/lists/*

#add a user for Nix
RUN adduser user --home /home/user --disabled-password --gecos "" --shell /bin/bash
RUN echo "user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
CMD /bin/bash -l
USER user
ENV USER user
WORKDIR /home/user

#create the shell config
RUN echo "{ pkgs ? import <nixpkgs> {} }: \n\
with pkgs; \n\
\n\
gcc7Stdenv.mkDerivation { \n\
\tname = \"sgx-build-nix\"; \n\
\tbuildInputs = [ \n\
\t\t/nix/store/raiq8qv61rc66arg3vzyfr9kw83s7dwv-autoconf-2.69 \n\
\t\t/nix/store/7bsq9c4z657hddv60hpks48ws699y0fc-automake-1.16.1 \n\
\t\t/nix/store/idj0yrdlk8x49f3gyl4sb8divwhfgjvp-libtool-2.4.6 \n\
\t\t/nix/store/68yb6ams241kf5pjyxiwd7a98xxcbx0r-ocaml-4.06.1 \n\
\t\t/nix/store/ncqmw9iybd6iwxd4yk1x57gvs76k1sq4-ocamlbuild-0.12.0 \n\
\t\t/nix/store/9dkhfaw1qsmvw4rv1z1fqgwhfpbdqrn0-file-5.35 \n\
\t\t/nix/store/xg29vpnqlg5xigdpv4g7i5p9cn9b4nw2-cmake-3.16.2 \n\
\t\t/nix/store/d0fv0g4vcv4s0ysa81pn9sf6fy4zzjcv-gnum4-1.4.18 \n\
\t\t/nix/store/pm4rg0bdiaj5b748kncp9vf7n3x446sd-gcc-7.4.0 \n\
\t\t/nix/store/ljvpvjh36h9x2aaqzaby5clclq4mgdmc-openssl-1.1.1b \n\
\t\t/nix/store/5lyvydxv0w4f2s1ba84pjlbpvqkgn1ni-linux-headers-4.19.16 \n\
\t\t/nix/store/681354n3k44r8z90m35hm8945vsp95h1-glibc-2.27 \n\
\t\t/nix/store/0klr6d4k2g0kabkamfivg185wpx8biqv-openssl-1.1.1b-dev \n\
\t\t/nix/store/plfjikpsq548dlvsv9k8zmqqrpa8vkyj-numactl-2.0.12 \n\
\t\t/nix/store/1kl6ms8x56iyhylb2r83lq7j3jbnix7w-binutils-2.31.1 \n\
\t\t/nix/store/yg76yir7rkxkfz6p77w4vjasi3cgc0q6-gnumake-4.2.1 \n\
\t\t/nix/store/5lyvydxv0w4f2s1ba84pjlbpvqkgn1ni-linux-headers-4.19.16 \n\
\t\t/nix/store/hjn55shjnsmnv35vcl91brf7jx0mlbjg-protobuf-3.10.0 \n\
\t\t/nix/store/zsfayw1hr64lz0j1na8jsiv5dznzlll9-rustup-1.20.2 \n\
\t]; \n\
\n\
\tshellHook = '' \n\
\techo \"SGX build enviroment\" \n\
\t''; \n\
} \n\
" > /home/user/shell.nix

#install the required software
RUN touch .bash_profile \
&& curl https://nixos.org/releases/nix/nix-2.3.2/install | sh \
&& . /home/user/.nix-profile/etc/profile.d/nix.sh \
&& nix-env -i /nix/store/1kl6ms8x56iyhylb2r83lq7j3jbnix7w-binutils-2.31.1 \
&& nix-env -i /nix/store/raiq8qv61rc66arg3vzyfr9kw83s7dwv-autoconf-2.69 \
&& nix-env -i /nix/store/7bsq9c4z657hddv60hpks48ws699y0fc-automake-1.16.1 \
&& nix-env -i /nix/store/idj0yrdlk8x49f3gyl4sb8divwhfgjvp-libtool-2.4.6 \
&& nix-env -i /nix/store/68yb6ams241kf5pjyxiwd7a98xxcbx0r-ocaml-4.06.1 \
&& nix-env -i /nix/store/ncqmw9iybd6iwxd4yk1x57gvs76k1sq4-ocamlbuild-0.12.0 \
&& nix-env -i /nix/store/9dkhfaw1qsmvw4rv1z1fqgwhfpbdqrn0-file-5.35 \
&& nix-env -i /nix/store/xg29vpnqlg5xigdpv4g7i5p9cn9b4nw2-cmake-3.16.2 \
&& nix-env -i /nix/store/d0fv0g4vcv4s0ysa81pn9sf6fy4zzjcv-gnum4-1.4.18 \
&& nix-env -i /nix/store/pm4rg0bdiaj5b748kncp9vf7n3x446sd-gcc-7.4.0 \
&& nix-env -i /nix/store/ljvpvjh36h9x2aaqzaby5clclq4mgdmc-openssl-1.1.1b \
&& nix-env -i /nix/store/5lyvydxv0w4f2s1ba84pjlbpvqkgn1ni-linux-headers-4.19.16 \
&& nix-env -i /nix/store/681354n3k44r8z90m35hm8945vsp95h1-glibc-2.27 \
&& nix-env -i /nix/store/0klr6d4k2g0kabkamfivg185wpx8biqv-openssl-1.1.1b-dev \
&& nix-env -i /nix/store/yg76yir7rkxkfz6p77w4vjasi3cgc0q6-gnumake-4.2.1 \
&& nix-env -i /nix/store/plfjikpsq548dlvsv9k8zmqqrpa8vkyj-numactl-2.0.12 \
&& nix-env -i /nix/store/hjn55shjnsmnv35vcl91brf7jx0mlbjg-protobuf-3.10.0 \
&& nix-env -i /nix/store/zsfayw1hr64lz0j1na8jsiv5dznzlll9-rustup-1.20.2

#config nix-shell
RUN . /home/user/.nix-profile/etc/profile.d/nix.sh \
&& nix-shell

RUN git clone -b ${SGX_TAG} https://github.com/intel/linux-sgx.git /home/user/linux-sgx

RUN . /home/user/.nix-profile/etc/profile.d/nix.sh \ 
        && nix-shell shell.nix --command " \
        cd /home/user/linux-sgx && \
	make dcap_source && \
	./download_prebuilt.sh && \
        cd /home/user/linux-sgx/sdk && \
        make && \
        /home/user/linux-sgx/linux/installer/bin/build-installpkg.sh sdk && \
        sudo PATH=$PATH:/nix/store/7rrhnhca34zq420nsinggp48p1bx8awr-gnumake-4.2.1/bin/make /home/user/linux-sgx/linux/installer/bin/${SGX_BIN} --prefix=/opt/intel"
RUN sudo apt update && sudo apt install libprotobuf10
RUN mkdir /home/user/sgx && \
    sudo mkdir /etc/init && \
    wget -O /home/user/psw.deb ${psw_deb} && \
    wget -O /home/user/psw_dev.deb ${psw_dev_deb} && \
    wget -O /home/user/psw_dbgsym.deb ${psw_dbgsym_deb} && \
    cd /home/user && \
    sudo dpkg -i /home/user/psw.deb && \
    sudo dpkg -i /home/user/psw_dev.deb && \
    sudo dpkg -i /home/user/psw_dbgsym.deb && \
    rm -rf /home/user/sgx/*

RUN . /home/user/.nix-profile/etc/profile.d/nix.sh \ 
        && nix-shell shell.nix --command "rustup default ${RUST_VERSION}"

RUN git clone https://github.com/apache/mesatee-sgx.git /home/user/mesatee-sgx && \
        cd /home/user/mesatee-sgx && \
        git checkout ${MESATEE_SGX_COMMIT}

WORKDIR /home/user/mesatee-sgx/code/build
COPY entrypoint.sh /usr/local/bin/entrypoint

ENTRYPOINT ["entrypoint"]