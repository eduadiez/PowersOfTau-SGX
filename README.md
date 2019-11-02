* Build

```
$ git https://github.com/eduadiez/PowersOfTau-SGX.git
$ cd PowersOfTau-SGX
$ docker build -t powersoftau .
$ docker run --rm -v $PWD:/home/user/mesatee-sgx/code/build powersoftau
```