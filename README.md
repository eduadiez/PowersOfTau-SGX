
Perpetual Powers of Tau Ceremony on an Intel SGX

This work is based on the perpetualpowersoftau from [here](https://github.com/weijiekoh/perpetualpowersoftau)

# Instructions

1. [Check SGX compatibility](https://github.com/eduadiez/PowersOfTau-SGX#check-sgx-compatibility)  (If it isn't compatible you can only run it in simulation mode)
2. [Check if SGX is enable](https://github.com/intel/sgx-software-enable)
3. Download the [binary](https://github.com/eduadiez/PowersOfTau-SGX/releases/download/1.0.0/compute_constrained_sgx) and the [enclave](https://github.com/eduadiez/PowersOfTau-SGX/releases/download/1.0.0/enclave.signed.so)
4. Download the [challenge_nnnn](https://github.com/weijiekoh/perpetualpowersoftau) file from the coordinator. The filename might be something like challenge_0004. Rename it to challenge:
```
mv challenge_nnnn challenge
```
5. Run the computation with challenge in your working directory: 

(if you don't have the intel SGX driver installed you can run it in [this](https://github.com/eduadiez/PowersOfTau-SGX#inside-docker-hw-mode) way)
```
./compute_constrained_sgx
```
You will see this prompt:
```
Will contribute to accumulator for 2^28 powers of tau
In total will generate up to 536870912 powers
Type some random text and press [ENTER] to provide additional entropy...
```
Make sure that it says 2^28 powers of tau, and then enter random text as prompted.

The compuation will run for about 24 hours on a fast machine. Please try your best to avoid electronic surveillance or tampering during this time.

When it is done, you will see something like this:
```
Finihsing writing your contribution to `./response`...
Done!

Your contribution has been written to `./response`

The BLAKE2b hash of `./response` is:
        12345678 90123456 78901234 56789012 
        12345678 90123456 78901234 56789012 
        0b5337cd bb05970d 4045a88e 55fe5b1d 
        507f5f0e 5c87d756 85b487ed 89a6fb50 
Thank you for your participation, much appreciated! :)
```

You also get two more files `quote.json` and `quote.bin` you can validated following this [instructions](https://github.com/eduadiez/PowersOfTau-SGX#check-the-generated-quote)

As a summary, you can obtain proof signed by Intel that you have generated this response with its corresponding public key within the enclave and that it has been executed in a correct environment.

You should follow https://github.com/weijiekoh/perpetualpowersoftau steeps to sumit the response.

# Check the generated quote
## Intel
### Request
```
curl -i -X POST \
        https://api.trustedservices.intel.com/sgx/attestation/v3/report \
        -H 'Content-Type: application/json' \
        -H 'Ocp-Apim-Subscription-Key: 55aad22ed260486685fab7237d0c7915' \
        -d @quote.json
```
### Response
```
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

[Repository](https://github.com/kudelskisecurity/sgxfun)


```
# Sample, waiting for results
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
               debug    False
           mode64bit    True
        provisionkey    False
       einittokenkey    False
```

The first part of the report_data must be equal to the hash of the public key used to generate the parameters, the second part its sha256 hash of the challange used.

```
         report_data    3227602e4e64eefc9d110ea4dc6d5f658dddd40c93b24b352b9db5cf5f460daf0d4dad11bc51a8fe0c99df342e5ca48e0b64ab0b5475f1698b7da1386fefedea

# Get the public key from the response file
$ xxd  -s 393312 -ps -c 1000 response 

# Get the sha256 hash of public key from the response file
$ shasum -a 256 <(xxd  -s 393312 -ps response | tr -d \\n )
```

# How to build it to verify the binary

## Clon the repo
```
$ git https://github.com/eduadiez/PowersOfTau-SGX.git
$ cd PowersOfTau-SGX
```

## Build the docker image  
```
$ docker build -t powersoftau docker/build
```

## Build the binary
### HW Mode
```
$ chmod a+w -R .
$ docker run --rm -ti -v $PWD:/home/user/mesatee-sgx/code/build powersoftau make
```

### SW Mode
```
$ chmod a+w -R .
$ docker run --rm -ti -v $PWD:/home/user/mesatee-sgx/code/build powersoftau SGX_MODE=SW make
```

# Check the result *(Pending to update to the latest build)*
```
$ docker run --rm -ti -v $PWD:/home/user/mesatee-sgx/code/build powersoftau md5sum bin/*
SGX build enviroment
2264709bba34069da8fb1e0d94f4c6db  bin/compute_constrained_sgx
773970b269c602ad51010906179f12ff  bin/enclave.signed.so
$ sgx_sign dump -enclave enclave.signed.so -dumpfile metadata_info.txt
$ cat metadata_info.txt | grep -A 2 hash
metadata->enclave_css.body.enclave_hash.m:
0x00 0x6e 0x7f 0x3d 0x1b 0xf2 0x72 0xb6 0x13 0xa2 0x07 0x4d 0x3e 0xc7 0xe7 0xa8 
0xb5 0x63 0x4c 0x28 0x21 0xb3 0xbc 0x2d 0xa9 0xd9 0x84 0x64 0x7d 0xef 0xe1 0x3
```

This enclave_hash must match with mr_enclave on the qoute.bin

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

### Without docker (you should have de intel sgx drivers installed)
```
$ chmod +x ./bin/compute_constrained_sgx
$ cd bin && ./compute_constrained_sgx
```

# Check SGX compatibility 

[SGX-hardware](https://github.com/ayeks/SGX-hardware)

```
$ git clone https://github.com/ayeks/SGX-hardware
$ gcc test-sgx.c -o test-sgx
$ ./test-sgx
```
### SGX is available for your CPU but not enabled in BIOS
```
...
Extended feature bits (EAX=07H, ECX=0H)
eax: 0 ebx: 29c6fbf ecx: 0 edx: 0
sgx available: 1

CPUID Leaf 12H, Sub-Leaf 0 of Intel SGX Capabilities (EAX=12H,ECX=0)
eax: 0 ebx: 0 ecx: 0 edx: 0
sgx 1 supported: 0
sgx 2 supported: 0
MaxEnclaveSize_Not64: 0
MaxEnclaveSize_64: 0
...
```

You will need to enable it in the bios or through software.

[sgx-software-enable](https://github.com/intel/sgx-software-enable)


### CPU SGX functions are deactivated or SGX is not supported
```
...
Extended feature bits (EAX=07H, ECX=0H)
eax: 0 ebx: d19f4fbb ecx: 8 edx: 0
sgx available: 0

CPUID Leaf 12H, Sub-Leaf 0 of Intel SGX Capabilities (EAX=12H,ECX=0)
eax: 2ff ebx: a80 ecx: a88 edx: 0
sgx 1 supported: 1
sgx 2 supported: 1
MaxEnclaveSize_Not64: 0
MaxEnclaveSize_64: 0
...
```

### SGX is available for your CPU and enabled in BIOS
```
...
Extended feature bits (EAX=07H, ECX=0H)
eax: 0 ebx: 29c6fbf ecx: 0 edx: 0
sgx available: 1

CPUID Leaf 12H, Sub-Leaf 0 of Intel SGX Capabilities (EAX=12H,ECX=0)
eax: 1 ebx: 0 ecx: 0 edx: 241f
sgx 1 supported: 1
sgx 2 supported: 0
MaxEnclaveSize_Not64: 1f
MaxEnclaveSize_64: 24
...
```

# Try the 2^11 powers of tau version

Since processing the 2^28 powers of tau takes around 24 hours and we've to download a 97G challange file, I have created a binary (debug mode; simulation and hardware modes) to be able to test it.

To run it you must download this [file](https://github.com/eduadiez/PowersOfTau-SGX/releases/download/test_11/compute_constrained_sgx_11.tar.gz) or [SIM](https://github.com/eduadiez/PowersOfTau-SGX/releases/download/test_11/compute_constrained_sgx_11_SIM.tar.gz) version in case you don't have a Intel SGX compatible CPU.


```
$ wget https://github.com/eduadiez/PowersOfTau-SGX/releases/download/test_11/compute_constrained_sgx_11.tar.gz

# SIM MODE 
# $ wget https://github.com/eduadiez/PowersOfTau-SGX/releases/download/test_11/compute_constrained_sgx_11_SIM.tar.gz

$ tar -zxvf compute_constrained_sgx_11.tar.gz

$ docker run --device /dev/isgx --device /dev/mei0 -v $PWD/bin:/home/user/mesatee-sgx/code/build -ti powersoftau "./compute_constrained_sgx_11"

# SIM MODE 
# $ docker run -v $PWD/bin:/home/user/mesatee-sgx/code/build -ti powersoftau "./compute_constrained_sgx_11"

aesm_service[38]: [ADMIN]White List update requested
aesm_service[38]: [ADMIN]Platform Services initializing
aesm_service[38]: [ADMIN]Platform Services initialization failed due to DAL error
aesm_service[38]: The server sock is 0x5574bdfe3ef0
SGX build enviroment
[+] Init Enclave Successful 2!
Will contribute to accumulator for 2^11 powers of tau
In total will generate up to 4095 powers
Calculating previous contribution hash...
`challenge` file contains decompressed points and has a hash:
        e778ddf5 7120714d 0a7a8841 13aac0db 
        0c37dee0 d580dcb4 b3794fe5 b2b68875 
        c32f0275 9a860990 bec44cbd 38a86fea 
        abea62ea 9a0b682b 3c076003 c80042fd 
`challenge` file claims (!!! Must not be blindly trusted) that it was based on the original contribution with a hash:
        786a02f7 42015903 c6c6fd85 2552d272 
        912f4740 e1584761 8a86e217 f71f5419 
        d25e1031 afee5853 13896444 934eb04b 
        903a685b 1448b755 d56f701a fe9be2ce 
Type some random text and press [ENTER] to provide additional entropy...
aesm_service[38]: [ADMIN]White list update request successful for Version: 65
adasd
[+] Entering ocall_sgx_init_quote...
aesm_service[38]: [ADMIN]EPID Provisioning initiated
aesm_service[38]: The Request ID is a370c654d8444081bd11909f68d6154d
aesm_service[38]: The Request ID is daef856c48f74574a5ac30142284c95f
aesm_service[38]: [ADMIN]EPID Provisioning successful
[-] Report creation => success
[+] Entering ocall_get_quote
[-] rsgx_verify_report passed!
[-] qe_report check passed
Computing and writing your contribution, this could take a while...
Done processing 2047 powers of tau
Done processing 4094 powers of tau
Finihsing writing your contribution to `./response`...
Done!

Your contribution has been written to `./response`

The BLAKE2b hash of `./response` is:
        bb246102 842c4e32 7266c580 e5b81a83 
        b9a36939 58497722 5b50c336 07778939 
        9a75809c 94195d4c 1274726b 60a1055d 
        5b955b36 37c73609 b9b97df9 b22852e0 
Thank you for your participation, much appreciated! :)
[+] run_enclave success!
```

You can also validate the dev qoute generated (HW MODE):
```
curl -i -X POST \
        https://api.trustedservices.intel.com/sgx/dev/attestation/v3/report \
        -H 'Content-Type: application/json' \
        -H 'Ocp-Apim-Subscription-Key: bc6ef22000ff41aca23ee0469c988821' \
        -d @bin/quote.json
```

# Troubleshooting

Pending