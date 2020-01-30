This image allows you to verify the quote of your response

Based on https://github.com/kudelskisecurity/sgxfun

## Build
```
$ docker build -t eduadiez/sgx-fun . 
```

## Run
```
$ docker run --rm -v $PWD/quote.bin:/app/quote.bin eduadiez/sgx-fun
```
