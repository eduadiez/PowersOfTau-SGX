* Build

```
$ git https://github.com/eduadiez/PowersOfTau-SGX.git
$ cd PowersOfTau-SGX

# Build the docker image  
$ docker build -t powersoftau .

# Build the binary
$ docker run --rm -v $PWD:/home/user/mesatee-sgx/code/build powersoftau

# Check the result:
$ md5 compute_constrained_sgx 
MD5 (compute_constrained_sgx) = 905b5bbf61fde9f2c39118fdb016aa88
$ md5 enclave.signed.so
MD5 (enclave.signed.so) = 379cba8f38ee0d2c8bafb17f896c1213
```
