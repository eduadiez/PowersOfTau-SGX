# Pending tasks

- [ ] Remove deprecated launch token
- [ ] Add more comments to the modifications
- [x] Make the build reproducible
- [ ] Generate a release binary 
- [ ] Sign the binary with an SGX license (0KIMS) to be able to run it on release mode
- [ ] Generate an attestation proof inside the enclave (Intel SGX verificable)
- [ ] Improve README.md and instructions
- [ ] Write a Medium post explaining all the steps and implications

# Clon the repo
```
$ git https://github.com/eduadiez/PowersOfTau-SGX.git
$ cd PowersOfTau-SGX
```

# Build the docker image  
```
$ docker build -t powersoftau docker
```

# Build the binary
```
$ chmod a+w -R .
$ docker run --rm -ti -v $PWD:/home/user/mesatee-sgx/code/build powersoftau make
```

# Build the binary (SIM MODE)
```
$ chmod a+w -R .
$ docker run --rm -ti -v $PWD:/home/user/mesatee-sgx/code/build powersoftau SGX_MODE=SW make
```

# Check the result:
```
$ docker run --rm -ti -v $PWD:/home/user/mesatee-sgx/code/build powersoftau md5sum bin/*
SGX build enviroment
2264709bba34069da8fb1e0d94f4c6db  bin/compute_constrained_sgx
773970b269c602ad51010906179f12ff  bin/enclave.signed.so
```

# Clean the results:
```
$ docker run --rm -ti -v $PWD:/home/user/mesatee-sgx/code/build powersoftau make clean
```

# RUN
## Docker
### Inside docker (HW Mode)
```
$ chmod +x ./bin/compute_constrained_sgx
$ docker run --device /dev/isgx --device /dev/mei0 -v $PWD/bin:/home/user/mesatee-sgx/code/build -ti powersoftau "./compute_constrained_sgx"
```
### Inside docker (SW Mode)
```
$ chmod +x ./bin/compute_constrained_sgx
$ docker run -v $PWD/bin:/home/user/mesatee-sgx/code/build -ti powersoftau "./compute_constrained_sgx"
```
## Without docker
```
$ chmod +x ./bin/compute_constrained_sgx
$ cd bin && ./compute_constrained_sgx
```

