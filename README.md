# Pending tasks

- [ ] Remove deprecated launch token
- [ ] Add more comments to the modifications
- [ ] Make the build reproducible
- [ ] Generate a release binary 
- [ ] Sign the binary with an SGX license (0KIMS) to be able to run it on release mode
- [ ] Generate an attestation proof inside the enclave (Intel SGX verificable)
- [ ] Improve README.md
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

# Check the result:
```
$ docker run --rm -ti -v $PWD:/home/user/mesatee-sgx/code/build powersoftau md5sum bin/*
SGX build enviroment
2264709bba34069da8fb1e0d94f4c6db  bin/compute_constrained_sgx
773970b269c602ad51010906179f12ff  bin/enclave.signed.so
```

# Run the binary (SIM MODE):
```
$ cd bin
$ chmod +x ./compute_constrained_sgx

```

# Clean the results:
```
$ docker run --rm -ti -v $PWD:/home/user/mesatee-sgx/code/build powersoftau make clean
```

# RUN
## Inside docker
```
$ docker build -t compute_constrained_sgx -f docker/Dockerfile_run docker/
$ docker run --device /dev/isgx --device /dev/mei0 -v $PWD/bin:/app -ti compute_constrained_sgx
```
