* Build

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
$ docker run --rm -ti -v $PWD:/home/user/mesatee-sgx/code/build powersoftau make
```

# Check the result:
```
$ docker run --rm -ti -v $PWD:/home/user/mesatee-sgx/code/build powersoftau md5sum bin/*
SGX build enviroment
905b5bbf61fde9f2c39118fdb016aa88  bin/compute_constrained_sgx
773970b269c602ad51010906179f12ff  bin/enclave.signed.so
```
