## Perpetual Powers of Tau Ceremony on an Intel SGX enclave

This work is based on the Perpetual Powers of Tau from [here](https://github.com/weijiekoh/perpetualpowersoftau) and this [code](https://github.com/kobigurk/phase2-bn254/tree/ppot_ceremony) from [Kobi Gurkan](https://github.com/kobigurk)

Index:
  * Instructions (Ubuntu)
  * Pre-requisites
  * Generating a production ready contribution (HWMODE - 2^28 powers of tau)
  * Tested Hardware
  * Troubleshooting
  * Generating a test contribution (HWMODE/SWMODE - 2^11 powers of tau)
  * How to build and verify the binary

## Instructions (Ubuntu)

***Note 1**: This guide is still a WIP, any suggestions or comments are really appreciated*  

***Note 2**: The process described here includes the use of Docker for convenience although it is possible to generate a contribution through this method without using it. If you would like instructions on do it you can send me an email to edu@dappnode.io*

## Pre-requisites

  * Docker. If you don't have docker installed on your system you need to follow this [instructions](https://docs.docker.com/install/linux/docker-ce/ubuntu/).

  * Check SGX compatibility and enable it

      ```
      $ docker run --rm eduadiez/sgx-hardware
      ```

  * SGX Drivers
      
      [Intel_SGX_Installation_Guide_Linux_2.8_Open_Source.pdf](https://download.01.org/intel-sgx/sgx-linux/2.8/docs/Intel_SGX_Installation_Guide_Linux_2.8_Open_Source.pdf)
      ```
      $ sudo apt install linux-headers-$(uname -r)
      $ wget https://download.01.org/intel-sgx/sgx-linux/2.8/distro/ubuntu18.04-server/sgx_linux_x64_driver_2.6.0_51c4821.bin
      $ chmod +x sgx_linux_x64_driver_2.6.0_51c4821.bin
      $ sudo ./sgx_linux_x64_driver.bin
      ```

      Check if the Intel SGX is installed on your system
      ```
      $ ls -lrt /dev/isgx
      crw-rw-rw- 1 root root 10, 58 Jan 25 16:47 /dev/isgx
      ```

  * Check the CPU status and Intel Attestation Services

    ```
    $ docker run --rm  --device /dev/isgx --device /dev/mei0 eduadiez/sgx-attestation
    "OK"
    ```

    If you don't get an __"OK"__ response please refer to the troubleshooting guide below.


## Generating a production ready contribution (HWMODE - 2^28 powers of tau )

1. Download the [binary](https://github.com/eduadiez/PowersOfTau-SGX/releases/download/1.0.0/compute_constrained_sgx) and the [enclave](https://github.com/eduadiez/PowersOfTau-SGX/releases/download/1.0.0/enclave.signed.so)

    ```
    $ wget https://github.com/eduadiez/PowersOfTau-SGX/releases/download/1.0.0/compute_constrained_sgx
    $ wget https://github.com/eduadiez/PowersOfTau-SGX/releases/download/1.0.0/enclave.signed.so
    ```
2. Download the [challenge_nnnn](https://github.com/weijiekoh/perpetualpowersoftau) file from the ceremony coordinator (you will need to have a slot assigned). The filename might be something like challenge_0004. Rename it to challenge:
    ```
    $ mv challenge_nnnn challenge
    ```
3. Running compute_constrained_sgx
    ```
    $ chmod +x ./bin/compute_constrained_sgx
    $ docker run --device /dev/isgx --device /dev/mei0 -v $PWD/bin:/home/user/mesatee-sgx/code/build -ti eduadiez/sgx-runtime "./compute_constrained_sgx"
    ```

    You will see this prompt:
    ```
    Will contribute to accumulator for 2^28 powers of tau
    In total will generate up to 536870912 powers
    Type some random text and press [ENTER] to provide additional entropy...
    ```
    Make sure that it says 2^28 powers of tau, and then enter random text as prompted.

    The compuation will run for about 24 hours on a fast machine. Please try your best to avoid electronic surveillance or tampering during this time. If possible, leave the machine offline. 

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
4. Checking and validating the results

    The result of the execution will generate the following files
      * _response_

          49GB file with the result of the computation. You should follow [these steps (link)](https://github.com/weijiekoh/perpetualpowersoftau) to sumit the response.
      * _quote.json_ 

          Quote in json format to use for validating the result with the Intel Atesttation services
      * _quote.bin_

          Quote in binary format to use with the parse_quote.py

      With the quote files you can use Intel's Attestation Services to obtain a proof signed by Intel that you have generated this response with its corresponding public key within the enclave and that it has been executed in the correct environment.

    __Get an Intel Attestation proof:__
    ```
    $ curl -i -X POST \
    >         https://api.trustedservices.intel.com/sgx/attestation/v3/report \
    >         -H 'Content-Type: application/json' \
    >         -H 'Ocp-Apim-Subscription-Key: 55aad22ed260486685fab7237d0c7915' \
    >         -d @quote.json
    HTTP/1.1 100 Continue

    HTTP/1.1 200 OK
    Content-Length: 730
    Content-Type: application/json
    Request-ID: 0f59aadf10794b4d9d204da80a10bfac
    X-IASReport-Signature: GPsPq1kHuFOt/lOdMZsMclL75CzYOROEWPhsMPiyX626gwmQiIQSAEl5Bf5THr36QL4btvUDc9oLUFaUuM0xgoLcBywihLOyzoWZf66sAJLG/YKqzn/88Zn/bOWiVtAmAwBgq8FbnfmJX+wl/0W6zEnrZwxkAmIoU0R6vokhrKl/cMaCHQ++Drt72hkG5wzYI3sjGJQzVdcnK5NV0Gx5SZLBz+4D+nhhow7CYxcJKXyrmY3tueeqs20sFH7ZI5vcBOHp1gOIkz8rChC54p8DARvoTGnoQTTyMB6Nnn7YbynU7MBo2AR3O3Vi0hqwRZ65pLwC8DSdirzHUU0ZVSyagA==
    X-IASReport-Signing-Certificate: -----BEGIN%20CERTIFICATE-----%0AMIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV%0ABAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV%0ABAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0%0AYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIw%0AMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1Nh%0AbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwk%0ASW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG%0A9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA%2Bt%0AbeCTUR106AL1ENcWA4FX3K%2BE9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtId%0Acv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuv%0ALUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV%2BW9tOhA%0AImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt%2B%2BqO/6%2BKAXJuKwZqjRlEtSEz8%0AgZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGh%0AMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN%2Bs1fDuHAVE8MA4GA1UdDwEB/wQEAwIG%0AwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVk%0Ac2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJl%0AcG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4r%0ARq%2BZKE%2B7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9%0AlpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYv%0AWLrtXXfFBSSPD4Afn7%2B3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUd%0AZseZCcaZZZn65tdqee8UXZlDvx0%2BNdO0LR%2B5pFy%2BjuM0wWbu59MvzcmTXbjsi7HY%0A6zd53Yq5K244fwFHRQ8eOB0IWB%2B4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW7%0A2uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN%2BKwPbpA39%2BxOsStjhP9N1Y1a2%0AtQAVo%2ByVgLgV2Hws73Fc0o3wC78qPEA%2Bv2aRs/Be3ZFDgDyghc/1fgU%2B7C%2BP6kbq%0Ad4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA%3D%3D%0A-----END%20CERTIFICATE-----%0A-----BEGIN%20CERTIFICATE-----%0AMIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV%0ABAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV%0ABAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0%0AYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy%0AMzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL%0AU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD%0ADCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G%0ACSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR%2BtXc8u1EtJzLA10Feu1Wg%2Bp7e%0ALmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh%0ArgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT%0AL/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe%0ANpEJUmg4ktal4qgIAxk%2BQHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ%0AbyinkNndn%2BBgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H%0AafuVeLHcDsRp6hol4P%2BZFIhu8mmbI1u0hH3W/0C2BuYXB5PC%2B5izFFh/nP0lc2Lf%0A6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM%0ARoOaX4AS%2B909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX%0AMFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50%0AL0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW%0ABBR4Q3t2pn680K9%2BQjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9%2BQjfr%0ANXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq%0AhkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir%0AIEqucRiJSSx%2BHjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi%2BripMtPZ%0AsFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi%0AzLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra%0AUd4APK0wZTGtfPXU7w%2BIBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA%0A152Sq049ESDz%2B1rRGc2NVEqh1KaGXmtXvqxXcTB%2BLjy5Bw2ke0v8iGngFBPqCTVB%0A3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5%2BxmBc388v9Dm21HGfcC8O%0ADD%2BgT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R%2BmJTLwPXVMrv%0ADaVzWh5aiEx%2BidkSGMnX%0A-----END%20CERTIFICATE-----%0A
    Date: Thu, 30 Jan 2020 11:00:39 GMT

    {"id":"87128901495989080043954525461315810896","timestamp":"2020-01-30T11:00:39.307778","version":3,"isvEnclaveQuoteStatus":"OK","isvEnclaveQuoteBody":"AgAAAIYLAAAKAAkAAAAAAODpGN28hJIVaOQDutDJ/Ah17UYs7+opWcNky9jY4V16AgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAAADAAAAAAAAAFezT7RffLAzldx+6OtJPKYG0p1OtHfZ92R5aJyM/rvqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAw56oBvWVB3AC6ZGkHrQLUnWvkTcvZllW8HAzyCD0ZOgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC9/XWWRh64ji3oG5Bx3J8jX33ExQkpMJhutfOjzaxfTAR1fRt1sRSWNBRrBauzj655gRAkNpHhynhAe9mjB0fi"}
    ```

    As you can see in the response we get a `"isvEnclaveQuoteStatus":"OK"` which validates the result of the `isvEnclaveQuoteBody`. On the other hand Intel signs the response obtained with the `X-IASReport-Signature` and `X-IASReport-Signing-Certificate` headers.

    __Verifying the quote and the response:__

    Run the parse_quote.py from https://github.com/kudelskisecurity/sgxfun:
    ```
    $ docker run --rm -v $PWD/quote.bin:/app/quote.bin eduadiez/sgx-fun
               QUOTE
             version	2
           sign_type	0
       epid_group_id	860b0000
             isv_svn	0000
            reserved	090000000000
            basename	e0e918ddbc84921568e403bad0c9fc0875ed462cefea2959c364cbd8d8e15d7a
              report	0202000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000500000000000000030000000000000057b34fb45f7cb03395dc7ee8eb493ca606d29d4eb477d9f76479689c8cfebbea000000000000000000000000000000000000000000000000000000000000000030e7aa01bd6541dc00ba646907ad02d49d6be44dcbd99655bc1c0cf2083d193a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bdfd7596461eb88e2de81b9071dc9f235f7dc4c5092930986eb5f3a3cdac5f4c04757d1b75b1149634146b05abb38fae798110243691e1ca78407bd9a30747e2
              siglen	680
              rsaenc	73ce0d84a809d92b0e0d03f1a28fb783e4e9482983f2cda3de9c4952fed52b39df8bfc6e40b07bf55646c37e0ae5182f277d38d087d8deca222a09615515fc435c6888491433f14926ef47ee43d435b1fa1581ac31a9ce7b99374cb5e1b6d319e6928b2e1c357ca59e2ff66c4cf9cd3318da4a4fcd8345539440dc5e5a9b31b4eb72907d2226e76766d552ee507bfb5d8a59c38624f59e8dc3f003ab794c6298170da2f392350f6a065bd2418dd94b094e051c8f25ed752f00ebaefc28e450440915f615fa6e224e1466271edb926662c4af5d91b26603775b64b75b33d22d8d14feeca3ecf712ec48a1f8c656776f3142d9765d1272f105dd5f4d512e93ac74
             keyhash	416848c7059e600c45785eb2857dcfe77d569b0c9e119b8a76316e27be7f1a0a
                  iv	e0979bba4d7ec43b1ff39874
              enclen	360
              sigenc	45026a68e6bcee2ef0dcc3bee929cf4ed534fd42d37e0b0b8009e9f6f834e2ae6fa4095e9f5a612f531e077ef04de8cfb85622915b4ade22aec345dd0bfc404635aab19013f125236eb8d1db7ccbde891333a0b92dc00a73954fe5eac2a96ec3b2d30a0f2d246b212560568cfe1a4404add86abeb5b5eec2956647bff499dae59ed0e8f7c377f217cf175f5ce7f5429233f0b68ce2593557cc8f47f73115b53d59391f506d4e89bf60d29991839444394ae530227b62519366e0acaa8158b49a88bd245ee3eea0e72c1b93c35394564de7b9c4051ab2a63f0d44a9b6e666f48fc5cd8ad882154a0a277c56d5ed93523aea4ca6dd1ee810207b3a2fde4cc946cab0cb59ddf7e12534e6d451417d6ffef9d5cd28a3b66416cedf8ef56219a915c3d61045691d802ba287b97772fd45dd9dfcc14f3de28925c1aac61917827e865e7b6329e19448848e1e753488ad82a3288b4e09fab80e7b910b5cae622ae364b9
           rl_verenc	e916ba07
               n2enc	35a4219f
                 tag	7ef3415cd2cedf2570b6aa5158e87aeb

              REPORT
             cpu_svn	02020000000000000000000000000000
         misc_select	00000000
          attributes	05000000000000000300000000000000
          mr_enclave	57b34fb45f7cb03395dc7ee8eb493ca606d29d4eb477d9f76479689c8cfebbea
           mr_signer	30e7aa01bd6541dc00ba646907ad02d49d6be44dcbd99655bc1c0cf2083d193a
         isv_prod_id	0000
             isv_svn	0000
         report_data	bdfd7596461eb88e2de81b9071dc9f235f7dc4c5092930986eb5f3a3cdac5f4c04757d1b75b1149634146b05abb38fae798110243691e1ca78407bd9a30747e2

          ATTRIBUTES
               debug	False
           mode64bit	True
        provisionkey	False
       einittokenkey	False

    ```

    Please verify that the values `mr_enclave` and `mr_signer` are the same as listed below. If you get other values you have NOT used the application signed by 0KIMS since these values identify the enclave and who signs it.

    ```
      mr_enclave	57b34fb45f7cb03395dc7ee8eb493ca606d29d4eb477d9f76479689c8cfebbea
      mr_signer	  30e7aa01bd6541dc00ba646907ad02d49d6be44dcbd99655bc1c0cf2083d193a
    ```
    
    On the other hand, the first part of the `report_data` must be equal to the hash of the public key used to generate the parameters. The second part must be the sha256 hash of the challange used to generate it

    ```
    report_data	        bdfd7596461eb88e2de81b9071dc9f235f7dc4c5092930986eb5f3a3cdac5f4c04757d1b75b1149634146b05abb38fae798110243691e1ca78407bd9a30747e2
    ``` 

    so:
    ```
    $ shasum -a 256 <(xxd -s -768 -ps response | tr -d \\n)
      bdfd7596461eb88e2de81b9071dc9f235f7dc4c5092930986eb5f3a3cdac5f4c  /dev/fd/63
    $ echo -n "5bfc69715a5f57d29170410c04cfb19db079de9da94f9b81770d7cfd6cfb7b14d05e3268596722a6546a40b679194ce9682d395623a664a9a7d836c967a41d7d" | shasum -a 256
      04757d1b75b1149634146b05abb38fae798110243691e1ca78407bd9a30747e2  -
    ```


## Tested Hardware

| Product Name | Bios version | Result |
| -------- | -------- | -------- |
| NUC7CJYH     | JYGLKCPX.86A.0053.2019.1015.1510 | OK |


## Troubleshooting
  * When I try to check the CPU status and Intel Attestation Services I get this response:

    * GROUP_OUT_OF_DATE

      This usually means that you don't have the latest BIOS on your system. To be able to get an OK response from the Intel Attestation services you need to install the latest version from the manufacturer of your device.
   
      You can get more info about the reaseon if you check the Advisory-IDs on the [Intel Security Center](https://www.intel.com/content/www/us/en/security-center/default.html)

      ```
      Advisory-IDs: INTEL-SA-00220,INTEL-SA-00270,INTEL-SA-00293
      ```

## Generating a test contribution (HWMODE/SWMODE - 2^11 powers of tau)

Since processing the 2^28 powers of tau takes around 24 hours and it requires the download of a 97G challange file, I have created a binary (debug mode; simulation and hardware modes) to test it using less resources. 

To run it you must download this [file](https://github.com/eduadiez/PowersOfTau-SGX/releases/download/test_11/compute_constrained_sgx_11.tar.gz)

```
$ wget https://github.com/eduadiez/PowersOfTau-SGX/releases/download/test_11/compute_constrained_sgx_11.tar.gz
$ tar -zxvf compute_constrained_sgx_11.tar.gz && cd compute_constrained_sgx_11
```
 * HW Mode
```
$ docker run --device /dev/isgx --device /dev/mei0 -v $PWD/bin_11:/home/user/mesatee-sgx/code/build -ti eduadiez/sgx-runtime "./compute_constrained_sgx"
```

```
$ curl -i -X POST \
        https://api.trustedservices.intel.com/sgx/dev/attestation/v3/report \
        -H 'Content-Type: application/json' \
        -H 'Ocp-Apim-Subscription-Key: bc6ef22000ff41aca23ee0469c988821' \
        -d @bin_11/quote.json
```
 * SIM Mode 
```
$ docker run -v $PWD/bin_sim:/home/user/mesatee-sgx/code/build -ti eduadiez/sgx-runtime "./compute_constrained_sgx"
```

## How to build and verify the binary

  * Clone the repo
  ```
  $ git clone https://github.com/eduadiez/PowersOfTau-SGX.git
  $ cd PowersOfTau-SGX
  ```

  * Build the docker image  
  ```
  $ docker build -t eduadiez/powersoftau docker/build
  ```

  * Build the binary
    * HW Mode
      ```
      $ chmod a+w -R .
      $ docker run --rm -ti -v $PWD:/home/user/mesatee-sgx/code/build eduadiez/powersoftau make
      ```
    * SW Mode (Only for testing or in case you don't have an Intel SGX-enabled machine)
      ```
      $ chmod a+w -R .
      $ docker run --rm -ti -v $PWD:/home/user/mesatee-sgx/code/build eduadiez/powersoftau SGX_MODE=SW make
      ```

  * Check the result
      ```
      $ docker run --rm -ti -v $PWD:/home/user/mesatee-sgx/code/build eduadiez/powersoftau md5sum bin/*
      SGX build enviroment
      4adf87bd613dfec058334762b5de8703  bin/compute_constrained_sgx
      e67d835416b617d6d214b7c8fe6ebc8a  bin/enclave.signed.so
      ```

      The enclave.signed.so md5sum is different from the release version since release is signed with the 0Kims private key: For the test we should verify the enclave hash as follows:

      ```
      $ docker run --rm -ti -v $PWD:/home/user/mesatee-sgx/code/build eduadiez/powersoftau sgx_sign dump -enclave bin/enclave.signed.so -dumpfile bin/metadata_info.txt
      $ cat bin/metadata_info.txt | grep -A 2 hash | head -3
        metadata->enclave_css.body.enclave_hash.m:
        0x57 0xb3 0x4f 0xb4 0x5f 0x7c 0xb0 0x33 0x95 0xdc 0x7e 0xe8 0xeb 0x49 0x3c 0xa6 
        0x06 0xd2 0x9d 0x4e 0xb4 0x77 0xd9 0xf7 0x64 0x79 0x68 0x9c 0x8c 0xfe 0xbb 0xea 
      ```
  * check the enclave.signed.so file
    ```
    $ docker run --rm -v $PWD/bin/enclave.signed.so:/app/enclave.signed.so eduadiez/sgx-fun ./parse_enclave.py enclave.signed.so
      Enclave file: enclave.signed.so
      Enclave size: 1336368 bytes
      SIGSTRUCT found at 0x770e5
      RSA parameters valid

              HEADER	06000000e10000000000010000000000
              VENDOR	00000000
                DATE	20200130
             HEADER2	01010000600000006000000001000000
           SWDEFINED	00000000
            RESERVED	000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
             MODULUS	3960387756473297000687856488531774029344593345119626416649636843980331851504763807909149409642839186131976326094886491509703121261171904326398760152778035627398603286430779359277359669822993178819498070277858021285953880433235281871184344943580883032040703032671086827829549248679405172134684614302557227869220943766834877614946098020074864298207333795126238479481613287604622381609130656824865656549671896110460699799096098473344198065201626753881401309970718027367970013413753227981302963685977216052120532666696539262656999211130643610246013913423874179516894803063062461207793591904527119355231662162728306224131653998899418761095164592291974823106229813515994559583959355536879399278740865187022948991861049155258946286465600484750406718118825308129597424239945454688980578282673265787746063042884273538088576675805670605901892330780689741660474848770492247547354144520007901398041994841272274864390370029149467583535091
            EXPONENT	3
           SIGNATURE	3642782810255072771931625496569359119381752233205431972815504415251009480980578222879050343837914808795679157073241464582369295852094980884397795636208337700393185914661934569047201036072886686534712799980955342330385134104784933857383869243617776433934865312794967129339896948780211026618523451051705024626471931794663988091205461250507807701554934794599419380172983860304836734607668396820587877713025042952432931518736296806194586281526351029641884811570387610778265181418076402845939378245738979917237747808733287707794659693312097622354225637403033849778304298674049639414212581433965605997314485733705229383772923825799320033723948936600021960724140361604252796944898489538714564747162365137695661203256838015079944919131965170212338375423956404586455641911364309414547624253392570709069950521549142839309370238488390272169838480824751670785741651605619867612758197104817698161248598960462967519122589070809081853351459
          MISCSELECT	00000000
            MISCMASK	ffffffff
            RESERVED	0000000000000000000000000000000000000000
          ATTRIBUTES	04000000000000000300000000000000
       ATTRIBUTEMASK	ffffffffffffffff1bffffffffffffff
         ENCLAVEHASH	57b34fb45f7cb03395dc7ee8eb493ca606d29d4eb477d9f76479689c8cfebbea
            RESERVED	0000000000000000000000000000000000000000000000000000000000000000
           ISVPRODID	0000
              ISVSVN	0000
            RESERVED	000000000000000000000000
                  Q1	3350648325028301525547017323221511690443649743149365433213885095066493491043495307448003891399502989662915416781614969719113405784081596632537501842604360574854942144851200735718460442600905339890546001732387246578056822984428966778127836179828095751505018720083156910454766411912675852993258250432967980060413926072571894228646187028085950226509820248204379755792303986082834616084650684752987128040856753321520131888647340714481226968661949185710040387944045374971849154793053055049994308403848696103470086606396551166376612843976910960360811605874673581746729235268425503293830112882372328043874554640641951879879352225094556301581740615078006703520201659147160472665108044825880700474038975554794079558741076343496150073211682632058197630404633340951948660407500057330724815557620440627149184076663269054398714703520772296323842805289781437463587480810813500202400856879961046146648908799190321642446824378012177401250923
                  Q2	475084249327893195420839680565009502465495473058130555179340595246501998509308634001993538207990812066231137268176306509218905892706040129299970805206741465509752974244897555603779443301707621460374245255485403029850080761072100746017610877669925889905992295829083761855170779946089717385685278818099002396171471634176787682268120710730176228643422503883974140510115007450878083757647887470825026056138033291939197950109915497484132989551671318311058076010829784868469980114041490130247492464969001947285733666835704544353540070653596466073103406785781136992752606928966910947506764418439196520033573763905157848519260040264491951577904840839309579278548050408192166746140159493791916679311052810983902752686017681928568305696955240831538326789481239141538433329854884526850118836204906404186225645802461398925009794836833286171717629939258005178283634887648744776019103023146965392308355051339201145587735151103067384581616


    # ATTRIBUTES

                  DEBUG	  0
              MODE64BIT	  1
            PROVISIONKEY	0
              EINITTOKEN	0

    # sgxmeta not found

    # ECALLs table found at 0x73e80
                      0	vaddr: 0x42f0
                      1	vaddr: 0x42a0
                      2	vaddr: 0x4250
                      3	vaddr: 0x4200
                      4	vaddr: 0x41b0
                      5	vaddr: 0x40c0
                      6	vaddr: 0x40a0

    ```

The `ENCLAVEHASH` should be match with `metadata->enclave_css.body.enclave_hash.m`

