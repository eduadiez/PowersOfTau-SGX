# Pending tasks

- [ ] Remove deprecated launch token
- [ ] Add more comments to the modifications
- [x] Make the build reproducible
- [ ] Generate a release binary 
- [ ] Sign the binary with an SGX license (0KIMS) to be able to run it on release mode
- [x] Generate an attestation proof inside the enclave (Intel SGX verificable)
- [ ] Improve README.md and instructions
- [ ] Write a verification tool
- [ ] Add SGX installation instructions
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

# Check the quote
## Intel
```
curl -i -X POST \
>         https://api.trustedservices.intel.com/sgx/dev/attestation/v3/report \
>         -H 'Content-Type: application/json' \
>         -H 'Ocp-Apim-Subscription-Key: bc6ef22000ff41aca23ee0469c988821' \
>         -d @quote.json
HTTP/1.1 100 Continue

HTTP/1.1 200 OK
Content-Length: 731
Content-Type: application/json
Request-ID: 93b4108ff9344f1696d3f3712cc75b46
X-IASReport-Signature: efcP4pACRf7FQQlLz6x+YzGsZDm/4ncc0ScYpVknkoxSiNqJ0/+mRHr5ZVrGRmxtiOtlOdDGzj4JWlDGhCd803pxljqJwL0dG/Uv5zeudfeIeQtIt981ARU9WEo8kFmUQ5ctqDanYr6cUsP4fS8SrDr16Ih+QUey8a6KQ0NhiMc5sSogDNvyWuIDKZPsSc/gXjAz0LQ2pXrc6gTmeu4Yr43asoMvufN39PUeYKhXxkPVQ8xMfjReFp8fDFwPK6zh3tvfnH+t7TVxJZzJ2OigXuXzz1RhXAuaObKenRfkX9gjrAkwxMiOm3bBiGznMWg1T8xCQORvBMHVmRifzbeUew==
X-IASReport-Signing-Certificate: -----BEGIN%20CERTIFICATE-----%0AMIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV%0ABAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV%0ABAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0%0AYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIw%0AMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1Nh%0AbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwk%0ASW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG%0A9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA%2Bt%0AbeCTUR106AL1ENcWA4FX3K%2BE9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtId%0Acv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuv%0ALUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV%2BW9tOhA%0AImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt%2B%2BqO/6%2BKAXJuKwZqjRlEtSEz8%0AgZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGh%0AMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN%2Bs1fDuHAVE8MA4GA1UdDwEB/wQEAwIG%0AwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVk%0Ac2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJl%0AcG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4r%0ARq%2BZKE%2B7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9%0AlpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYv%0AWLrtXXfFBSSPD4Afn7%2B3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUd%0AZseZCcaZZZn65tdqee8UXZlDvx0%2BNdO0LR%2B5pFy%2BjuM0wWbu59MvzcmTXbjsi7HY%0A6zd53Yq5K244fwFHRQ8eOB0IWB%2B4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW7%0A2uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN%2BKwPbpA39%2BxOsStjhP9N1Y1a2%0AtQAVo%2ByVgLgV2Hws73Fc0o3wC78qPEA%2Bv2aRs/Be3ZFDgDyghc/1fgU%2B7C%2BP6kbq%0Ad4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA%3D%3D%0A-----END%20CERTIFICATE-----%0A-----BEGIN%20CERTIFICATE-----%0AMIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV%0ABAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV%0ABAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0%0AYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy%0AMzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL%0AU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD%0ADCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G%0ACSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR%2BtXc8u1EtJzLA10Feu1Wg%2Bp7e%0ALmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh%0ArgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT%0AL/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe%0ANpEJUmg4ktal4qgIAxk%2BQHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ%0AbyinkNndn%2BBgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H%0AafuVeLHcDsRp6hol4P%2BZFIhu8mmbI1u0hH3W/0C2BuYXB5PC%2B5izFFh/nP0lc2Lf%0A6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM%0ARoOaX4AS%2B909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX%0AMFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50%0AL0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW%0ABBR4Q3t2pn680K9%2BQjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9%2BQjfr%0ANXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq%0AhkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir%0AIEqucRiJSSx%2BHjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi%2BripMtPZ%0AsFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi%0AzLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra%0AUd4APK0wZTGtfPXU7w%2BIBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA%0A152Sq049ESDz%2B1rRGc2NVEqh1KaGXmtXvqxXcTB%2BLjy5Bw2ke0v8iGngFBPqCTVB%0A3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5%2BxmBc388v9Dm21HGfcC8O%0ADD%2BgT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R%2BmJTLwPXVMrv%0ADaVzWh5aiEx%2BidkSGMnX%0A-----END%20CERTIFICATE-----%0A
Date: Sat, 16 Nov 2019 17:23:27 GMT

{"id":"221964965504293408825451095104791908906","timestamp":"2019-11-16T17:23:27.854380","version":3,"isvEnclaveQuoteStatus":"OK","isvEnclaveQuoteBody":"AgAAAFwLAAAIAAcAAAAAAIOUfHZJS/EfsaFSa4nXWiXHSjFurU+LCogpHEgqUkWLBgb//wECAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAHR5UrjjIKIzjqVb/OfIKNEdQh5whWOzH+IeoolHLih8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDtAp0EV+vfEjzDtMirTOyKEBGHlQaC1c5mlXbuBImA1NrRG8Uaj+DJnfNC5cpI4LZKsLVHXxaYt9oThv7+3q"}
```
## SGX-fun 
https://github.com/kudelskisecurity/sgxfun
```
# Get the public key from the response
$ xxd  -s 393312 -ps -c 1000 response 
# Get the sha256 hash of public key from the response
$ shasum -a 256 <(xxd  -s 393312 -ps response | tr -d \\n )

$ git clone https://github.com/kudelskisecurity/sgxfun
$ ./sgxfun/parse_quote.py quote.bin 
               QUOTE
             version    2
           sign_type    0
       epid_group_id    5c0b0000
             isv_svn    0000
            reserved    070000000000
            basename    83947c76494bf11fb1a1526b89d75a25a5db738198e40fc07effe79b08d89d99
              report    0606ffff010201000000000000000000000000000000000000000000000000000000000000000000000000000000000007000000000000000700000000000000006e7f3d1bf272b613a2074d3ec7e7a8b5634c2821b3bc2da9d984647defe130000000000000000000000000000000000000000000000000000000000000000083d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003227602e4e64eefc9d110ea4dc6d5f658dddd40c93b24b352b9db5cf5f460daf0d4dad11bc51a8fe0c99df342e5ca48e0b64ab0b5475f1698b7da1386fefedea
              siglen    680
              rsaenc    9e6a22349633fafa1da5f749bbc9cada1fc405bf27241fb44fabfe82569a83c3fe59d3558e49d7589a0dd3a0adc4fe76fbb4f8af5df0d5d1891ad3bd10489840baaba4451bf73416b1aac111661524608dab46c78061199060c6bf9a275c02a7b32536f0901214795dcd7d31a513ec5a4094845638973eecc5817caa1cd42e0900e2f4e832e2843143d90fc0510999803e9fc399a545f481f031ca81003fc55bc791d246fbdca0d537e1751099f9fd641b1b31910452b23abd543c003fe58b8600924de1b18739eaec069a7f8a9fa3626a485d38897f1026ea6e3e76f8891a5c661cef2bde8133bffcd726c573f7576d872fc72e60fee08845f6a48b0ad1ec06
             keyhash    c9ee22e594cd277e863899135a31dd9cb53372550e87316bdf51462bc4371c35
                  iv    0d675f644870266eab4c6a4b
              enclen    360
              sigenc    2021e8bb35df93edd9bb28769c35583bcaae430f54c2269e20a3dfd0d5f23ebaf4e09f326908e8d95b8d98ad5856cbe8ef827ba8a0f1eaf65d76d221429c01123f4f0ffc0f35594225552248af35443b07422e1ea076b175f8b865d7fbf812d932d5a6a6df8fe32c5cf9e9234e4e84f36afc088a0fa0d922cbfdc339e49535b2e63713ef11ee3a1108efbb18bd92193ee63f3ab34d245c50070e72b6dbd57edf246d20e26412e2c4ef69bd27ee38bcd3fb0ea5b0195b7e538a55e8e316c2dadff8d994d187ee151bfe58330bccc2f5396cdffb390d374b57f19518cd18d67fc78e5178eddde60943b98a7af6f47e05a75db21f7bd559eacd94e2cfbb8d60c13764ac09831e5fb4a03be377b9f751c639b4adddf0f2b4adf9e9c9f9e4e59b362a3093554fbaddf6be6314a44ab36de74e3207925924f63b4a7ba685840296ed9bdfb8600b64b17b19a96ac5c59e942012261c930d463e8010816833e41363ddf7
           rl_verenc    ae76a09d
               n2enc    a690d740
                 tag    7939b0f0504b3167f8870a738d9eaf04

              REPORT
             cpu_svn    0606ffff010201000000000000000000
         misc_select    00000000
          attributes    07000000000000000700000000000000
          mr_enclave    006e7f3d1bf272b613a2074d3ec7e7a8b5634c2821b3bc2da9d984647defe130
           mr_signer    83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e
         isv_prod_id    0000
             isv_svn    0000
         report_data    3227602e4e64eefc9d110ea4dc6d5f658dddd40c93b24b352b9db5cf5f460daf0d4dad11bc51a8fe0c99df342e5ca48e0b64ab0b5475f1698b7da1386fefedea

          ATTRIBUTES
               debug    True
           mode64bit    True
        provisionkey    False
       einittokenkey    False
```