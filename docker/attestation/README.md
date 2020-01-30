This image allows you to verify if your CPU is ready to generate a valid response from Intel Attestation Services

## Build
```
$ docker build -t eduadiez/sgx-attestation . 
```

## Run
```
$ docker run --rm  --device /dev/isgx --device /dev/mei0 eduadiez/sgx-attestation
```
