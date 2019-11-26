
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
$ ./parse_quote.py quote.bin 
               QUOTE
             version	2
           sign_type	0
       epid_group_id	5c0b0000
             isv_svn	0000
            reserved	070000000000
            basename	83947c76494bf11fb1a1526b89d75a25a1299026e0d51e2c5f7c2dd3f44f8a93
              report	0606ffff010201000000000000000000000000000000000000000000000000000000000000000000000000000000000005000000000000000700000000000000e5eb4e5bea68fc6059c0878006e2ca1d7dd693ec09b0ea6ee2951949d04b9114000000000000000000000000000000000000000000000000000000000000000030e7aa01bd6541dc00ba646907ad02d49d6be44dcbd99655bc1c0cf2083d193a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000024c0de380eaabc3b2f56542ea3e05a1eb9279febf027cf0fa0e9b27833613ea340cb1d58088fedbc667081bd4a33504ba0d4e45f3fcff2009af5df106fb239cb
              siglen	680
              rsaenc	4279093422cda38449abb10e0ed1a91b4b28486394271cbb6349fa96c9562b9a46c7def4bd52889ce957bae927fc4fd56ab4b34e93b9fa0cd9a29101f323f1a74fbba457aa52712d8272323a1448f1167aa1f2a03e732f8ff3fec639722edd4ef1616f1f8e8a7bba4059a5b314c55f37a4d2c3edb1fe974b7ae4f9868c069622d4b6da29b38f3687b5120895955b50860342899658dfbb32068dedb79fde8a5eefc3f7575331d95c73b58fb14b0dbfa61064901f802a0f1051b3dde4383a12def980090c05f01be3816757a8ce690332e6b26f250a31b29017e5346d5a6af0f841bb056b35d4f446d67609b73601f26c6542bfd6e643c1a48521bd83b88330e7
             keyhash	2a184d49b8afaf45b3ae93ddf362651e1c79679acdf798e6201a0b12abd46a49
                  iv	77d0b01ae4cfd0e63e637d7d
              enclen	360
              sigenc	005146a5401c5e10fc52de524325ccd9eb77ec1e6a5a22edb62aee1b8f6b58fc703a57757c6ec27bba679113811ea8ba46a4d52681a2c310e48bbb2193c715b6b7288a090f9a865cdfcb7c10c38aadd992046080e9f0ebcecf502c6f51c36fa8f339fe3f0b15ad31a5fa011b643e0d6030b65ec992a129d4734a13807ec4169cdfde9e651a7933194cd67546ca5c9fe995544e5d19935f4867a6542cccecbaf08083bc3480d415f45552465876193d8c27857f03fe9be3cfc3b93d3de9075c5d48fa902bed33f6815e29acedfd7dfe104b294a968b4544056626bbeec09f396ee139683d64f48ec0791031859bb50d5485a6b88a34da885d692d07357c20ca68b3d6e80f78b643c3e81dfb90018c8e909df2bbde7f7db278237f5018f445be9640c788a8ae03b8279b4810aad8da106a0cbbc1b63f451a962b54e55a10f1a76a17ccc51d18e122a0f1279f2c855212afbc2cbc86fc80b61f11a51448137cab93
           rl_verenc	aa8049c8
               n2enc	6ed93974
                 tag	c97b68b78c647c2f24aa20359b76a7c9

              REPORT
             cpu_svn	0606ffff010201000000000000000000
         misc_select	00000000
          attributes	05000000000000000700000000000000
          mr_enclave	e5eb4e5bea68fc6059c0878006e2ca1d7dd693ec09b0ea6ee2951949d04b9114
           mr_signer	30e7aa01bd6541dc00ba646907ad02d49d6be44dcbd99655bc1c0cf2083d193a
         isv_prod_id	0000
             isv_svn	0000
         report_data	24c0de380eaabc3b2f56542ea3e05a1eb9279febf027cf0fa0e9b27833613ea340cb1d58088fedbc667081bd4a33504ba0d4e45f3fcff2009af5df106fb239cb

          ATTRIBUTES
               debug	False
           mode64bit	True
        provisionkey	False
       einittokenkey	False
```

`mr_enclave	e5eb4e5bea68fc6059c0878006e2ca1d7dd693ec09b0ea6ee2951949d04b9114`
`mr_signer	30e7aa01bd6541dc00ba646907ad02d49d6be44dcbd99655bc1c0cf2083d193a`

The first part of the report_data must be equal to the hash of the public key used to generate the parameters, the second part its sha256 hash of the challange used.

`
report_data	        24c0de380eaabc3b2f56542ea3e05a1eb9279febf027cf0fa0e9b27833613ea340cb1d58088fedbc667081bd4a33504ba0d4e45f3fcff2009af5df106fb239cb
`

```
# Get the public key from the response file
$ xxd  -s 393312 -ps -c 1000 response 

# Get the sha256 hash of public key from the response file
$ shasum -a 256 <(xxd  -s 393312 -ps response | tr -d \\n )
```


```
$ parse_enclave.py enclave.signed.so 
Enclave file: enclave.signed.so
Enclave size: 1231280 bytes
SIGSTRUCT found at 0x64111
RSA parameters valid

              HEADER    06000000e10000000000010000000000
              VENDOR    00000000
                DATE    20191126
             HEADER2    01010000600000006000000001000000
           SWDEFINED    00000000
            RESERVED    000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
             MODULUS    3960387756473297000687856488531774029344593345119626416649636843980331851504763807909149409642839186131976326094886491509703121261171904326398760152778035627398603286430779359277359669822993178819498070277858021285953880433235281871184344943580883032040703032671086827829549248679405172134684614302557227869220943766834877614946098020074864298207333795126238479481613287604622381609130656824865656549671896110460699799096098473344198065201626753881401309970718027367970013413753227981302963685977216052120532666696539262656999211130643610246013913423874179516894803063062461207793591904527119355231662162728306224131653998899418761095164592291974823106229813515994559583959355536879399278740865187022948991861049155258946286465600484750406718118825308129597424239945454688980578282673265787746063042884273538088576675805670605901892330780689741660474848770492247547354144520007901398041994841272274864390370029149467583535091
            EXPONENT    3
           SIGNATURE    2305321283448438473443438330472913210699983186812009537703614096033836589952876592395166359942017174388536267302166976637398363912474454894111260930104532431675444967825163573200144288860850524971620296303259212908434517360331241512350116977987474432726969545539199709169996725916224545896460866775340791162747757179499092767796983691637652541924839921421000506711141191913580506615729334446745221661686800345555258679380921774146910804357913923228424558003917471484841453233208933593711938198851607336026952727670561040247901660804791863966249464961899292004560469556617044301686594729912441712390055726059709524304826536069792404547303538469099005829384905793362325631441631545852388696512625288119002299290720727485658668426874440338641833980028824872327295745570849364485058866249206666192265174191489547047815964652656503843533831608689227344994112048294646907355721869009828352621131231977761294716915057316109131612161
          MISCSELECT    00000000
            MISCMASK    ffffffff
            RESERVED    0000000000000000000000000000000000000000
          ATTRIBUTES    04000000000000000300000000000000
       ATTRIBUTEMASK    ffffffffffffffff1bffffffffffffff
         ENCLAVEHASH    b1de642a41bd99668f0c3057202ef6cb083d099a660ff2db804282513f463c33
            RESERVED    0000000000000000000000000000000000000000000000000000000000000000
           ISVPRODID    0000
              ISVSVN    0000
            RESERVED    000000000000000000000000
                  Q1    1341915627133665686848706256974944832330432083437956537669149618939866746494675087669167931867885160283164307670349057428403917041032247972867917000176206100467384549008324518298473361269219200514552054701443188437004224713681157754417197002517238699309743596726401993867929617982063184123785735341801456171099721137155705738698611177415426922369969809526274346423785078241205625794760501116227199228472271561849572247611704315826533414095331627280915390042898020291011790480387159374210856080898764696125847555837012257295286841226685897208758274624213481743668483741206097982864268637772207646261376507205406557554374157775581677570541224212107662634428582255963917494129766270440170418907484554438246466221014577719646761600361930336764501743442350733582542507963967939771792946005467129964346594207983029913207106018416014363382296622607869550803975980823338943969032996709866012798395496159739894276375934682073684584808
                  Q2    436403613500299442823600358301165946849674795351228666152465167317015543767891561600627950954153406320486651685046330051005451374910374064964278586579941591383046039889392469573189054780534157734579573435773679182801395113056741666405641343009756871655454592174315216389615833010329358878663012819829233074551973563600895211673055955504270195693553458521622795088909523717677841226017335835038015360570022526209073017027861588879120422528419004237217530527440780669087063068942815914819756809372396950322070652801123586901888635983847075167703363697633265200573069795618825077598558552163739714166377138039857997051227064337821981356886683833273671893987749248383869575698002502118543946439702747265603049200652281094118167296787514703066606995812603251434027984041000378054255093780734645096352571193841408055022894660723482068143507004022549429708445861285915228062642112420388403429782745414861383303830429710257875053998


# ATTRIBUTES

               DEBUG    0
           MODE64BIT    1
        PROVISIONKEY    0
          EINITTOKEN    0

# sgxmeta not found

# ECALLs table found at 0x61140
                   0    vaddr: 0x4310
                   1    vaddr: 0x42d0
                   2    vaddr: 0x4280
                   3    vaddr: 0x4230
                   4    vaddr: 0x41e0
                   5    vaddr: 0x4190
                   6    vaddr: 0x40c0
                   7    vaddr: 0x40a0
```

`ENCLAVEHASH	e5eb4e5bea68fc6059c0878006e2ca1d7dd693ec09b0ea6ee2951949d04b9114 `

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