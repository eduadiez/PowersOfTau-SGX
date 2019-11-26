
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
Request-ID: d924c52c45134a6bacea4bbc0245bf26
X-IASReport-Signature: TH+7kiIkMrahqiV931CLlmkxH0zWUV2umVRhSO3fj5MxuA3susI5YsfhKqyBmBGSjwiMVUzAr8aeYGUxcBnlRSoXdEa+cuXpn6lq2oAwtrdewoXMR+L6Qvsq4IcWYBXYr/MYNLn8sJcO9k4UBzB6TAERr/mwxuqUrbvS4lRMopQv2T6qaGwhewD20ZNEJ3dF/fyLJClSkLszM5dWFL2lcbqSZTluZu0csU1vgkRni4OGejP45x8gN6TvGdWvKpj/E3p+ractUzEv8/Q6AVQ/XXlkzZOnDfwijAH4Rdj2EzMSvPzR5R3oZBdKZff+X0DVmrySoqGI+HuSvIRYjkCaVQ==
X-IASReport-Signing-Certificate: -----BEGIN%20CERTIFICATE-----%0AMIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV%0ABAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV%0ABAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0%0AYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIw%0AMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1Nh%0AbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwk%0ASW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG%0A9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA%2Bt%0AbeCTUR106AL1ENcWA4FX3K%2BE9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtId%0Acv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuv%0ALUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV%2BW9tOhA%0AImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt%2B%2BqO/6%2BKAXJuKwZqjRlEtSEz8%0AgZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGh%0AMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN%2Bs1fDuHAVE8MA4GA1UdDwEB/wQEAwIG%0AwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVk%0Ac2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJl%0AcG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4r%0ARq%2BZKE%2B7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9%0AlpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYv%0AWLrtXXfFBSSPD4Afn7%2B3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUd%0AZseZCcaZZZn65tdqee8UXZlDvx0%2BNdO0LR%2B5pFy%2BjuM0wWbu59MvzcmTXbjsi7HY%0A6zd53Yq5K244fwFHRQ8eOB0IWB%2B4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW7%0A2uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN%2BKwPbpA39%2BxOsStjhP9N1Y1a2%0AtQAVo%2ByVgLgV2Hws73Fc0o3wC78qPEA%2Bv2aRs/Be3ZFDgDyghc/1fgU%2B7C%2BP6kbq%0Ad4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA%3D%3D%0A-----END%20CERTIFICATE-----%0A-----BEGIN%20CERTIFICATE-----%0AMIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV%0ABAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV%0ABAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0%0AYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy%0AMzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL%0AU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD%0ADCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G%0ACSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR%2BtXc8u1EtJzLA10Feu1Wg%2Bp7e%0ALmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh%0ArgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT%0AL/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe%0ANpEJUmg4ktal4qgIAxk%2BQHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ%0AbyinkNndn%2BBgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H%0AafuVeLHcDsRp6hol4P%2BZFIhu8mmbI1u0hH3W/0C2BuYXB5PC%2B5izFFh/nP0lc2Lf%0A6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM%0ARoOaX4AS%2B909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX%0AMFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50%0AL0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW%0ABBR4Q3t2pn680K9%2BQjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9%2BQjfr%0ANXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq%0AhkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir%0AIEqucRiJSSx%2BHjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi%2BripMtPZ%0AsFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi%0AzLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra%0AUd4APK0wZTGtfPXU7w%2BIBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA%0A152Sq049ESDz%2B1rRGc2NVEqh1KaGXmtXvqxXcTB%2BLjy5Bw2ke0v8iGngFBPqCTVB%0A3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5%2BxmBc388v9Dm21HGfcC8O%0ADD%2BgT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R%2BmJTLwPXVMrv%0ADaVzWh5aiEx%2BidkSGMnX%0A-----END%20CERTIFICATE-----%0A
Date: Tue, 26 Nov 2019 17:16:06 GMT

{"id":"289202779106051853507035293696979940002","timestamp":"2019-11-26T17:16:07.795139","version":3,"isvEnclaveQuoteStatus":"OK","isvEnclaveQuoteBody":"AgAAAFwLAAAIAAcAAAAAAODpGN28hJIVaOQDutDJ/AhOxp4uFQWEl3YR6ahsAnqyBgb//wECAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAAAHAAAAAAAAALHeZCpBvZlmjwwwVyAu9ssIPQmaZg/y24BCglE/RjwzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAw56oBvWVB3AC6ZGkHrQLUnWvkTcvZllW8HAzyCD0ZOgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC9shr4UEyexPuEduC6wt0ceRRwVPiM1vgZA+5SlE+8LEDLHVgIj+28ZnCBvUozUEug1ORfP8/yAJr13xBvsjnL"}
```

## SGX-fun 

[Repository](https://github.com/kudelskisecurity/sgxfun)


```
# Sample, waiting for results
$ git clone https://github.com/kudelskisecurity/sgxfun 
$ $ ./parse_quote.py quote.bin 
               QUOTE
             version	2
           sign_type	0
       epid_group_id	5c0b0000
             isv_svn	0000
            reserved	070000000000
            basename	e0e918ddbc84921568e403bad0c9fc084ec69e2e150584977611e9a86c027ab2
              report	0606ffff010201000000000000000000000000000000000000000000000000000000000000000000000000000000000005000000000000000700000000000000b1de642a41bd99668f0c3057202ef6cb083d099a660ff2db804282513f463c33000000000000000000000000000000000000000000000000000000000000000030e7aa01bd6541dc00ba646907ad02d49d6be44dcbd99655bc1c0cf2083d193a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bdb21af8504c9ec4fb8476e0bac2dd1c79147054f88cd6f81903ee52944fbc2c40cb1d58088fedbc667081bd4a33504ba0d4e45f3fcff2009af5df106fb239cb
              siglen	680
              rsaenc	9d70eaee297485bf388396673649e88185c473e2fcc078e0f5ce1f034f3d15fa81e38926e92505240a42179d113c5a3d526770811fd6a5b1434e252ed8f206bc4a58a5627c771efb921f768dccccc1834317826399a798a74d1cfdc9460d22258136795940f5ad9fb6f90a2f853fc9690e80923bf1bf7821b98dc112f6fa74196d0ed0dd669276777101e1d4316c4df3ac8c6f75dbc2e9d69e535856bc36b44aa61011783ffd43a4b0a25e905c0d1f4f768a694c88c6a88fb53517f520a977de3997dc7e0734b926b2f8bff4a8b0093c56a516b2ab3b3d4adf262301116d487b46e80d4f626acbdc95d069d1f4c9933981c9a2aee37daf2e7f1638ffb768833c
             keyhash	a2d0572f8713afeaa6341512945bfa36d5a80bfcd063f66e0c2c9fe31781aa82
                  iv	48db34db7895dea96ee430cd
              enclen	360
              sigenc	d3ad990a3d40da4300eaac216f61cdffbfa6eabfdc558bb4b4d99ed27a147b07cf4d843ee43d0382a7128a2cdd282abd7b5e680e9752b8460a29fe9d4012480b25df4fd645fa05766507b91c1dceeab65d190dd2cb9f96053eaa30ee2d40b4893ec3f1c75a740338645e2b62bba36542adcb7beed3ad6cde7611543b2e837bc6087b13f9c1b8e7b3528688b617e033ce3f1db9ec3f651f378fa34e3e517a9b851279b1e378776d1e70cff622668867b915abba86bdaab18d97bfe417b5bc9904fd0f10ece776fc7fc93e466d6564a5c79305a63d2092d9f56c54c8c002042b72a9d8f431d5fe520cad16da1b9b851d1e5e7f510499ba5929831e75183783e1c716025d1a166f3a95c706ba81e377c87bc5ca58ba0af6611f4acb91198349e1d0688e8c433c3bd2509bc9ce92fc3c3f11bf2d52a24c0cc3faebe120b1802a83f413f922118202f055b20f35199703212123c0add9906a753abf4528ce2bf81889
           rl_verenc	46528082
               n2enc	4442cd67
                 tag	77de1827a6e74905eb9a4ed4790714a2

              REPORT
             cpu_svn	0606ffff010201000000000000000000
         misc_select	00000000
          attributes	05000000000000000700000000000000
          mr_enclave	b1de642a41bd99668f0c3057202ef6cb083d099a660ff2db804282513f463c33
           mr_signer	30e7aa01bd6541dc00ba646907ad02d49d6be44dcbd99655bc1c0cf2083d193a
         isv_prod_id	0000
             isv_svn	0000
         report_data	bdb21af8504c9ec4fb8476e0bac2dd1c79147054f88cd6f81903ee52944fbc2c40cb1d58088fedbc667081bd4a33504ba0d4e45f3fcff2009af5df106fb239cb

          ATTRIBUTES
               debug	False
           mode64bit	True
        provisionkey	False
       einittokenkey	False
```

`mr_enclave	b1de642a41bd99668f0c3057202ef6cb083d099a660ff2db804282513f463c33`
`mr_signer	30e7aa01bd6541dc00ba646907ad02d49d6be44dcbd99655bc1c0cf2083d193a`

The first part of the report_data must be equal to the hash of the public key used to generate the parameters, the second part its sha256 hash of the challange used.

`
report_data	        bdb21af8504c9ec4fb8476e0bac2dd1c79147054f88cd6f81903ee52944fbc2c40cb1d58088fedbc667081bd4a33504ba0d4e45f3fcff2009af5df106fb239cb
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

              HEADER	06000000e10000000000010000000000
              VENDOR	00000000
                DATE	20191126
             HEADER2	01010000600000006000000001000000
           SWDEFINED	00000000
            RESERVED	000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
             MODULUS	5004293170712334358531029759621463129675955746521328227628447129014753132299093598553544369741478276038867602831725819898365189753008946373969372384021597375938200174425313841943917515594109451106114082761392632088444413378182122936507059790885806943387884979783852191301811994261063449726920376047202591556145105167429168985666227385051804149833905812435199826397626408556805443021352090036082254604158574079797999562467011210483806862285091973603918557945071058923859636472452824002673468974776602424807906574501583881658925611785965920550610566146278471692275649860789118428788286871947322288828559952857522182254605648484652783365962605484569988528844351011914462074070064359475259016103996293310388708213564879446711053554078087820348451456087523651048271141531850095115213059780028438415437553637191921101686164857976462461750919085251236169268096913429732992793355149924686057898912696945915717676420971636435876522367
            EXPONENT	3
           SIGNATURE	434203502329984858566637046639254705917229733411387156225929671564230167597779047982592794600593337626465893844184848549891151838809783154947464666109290972761172875938658283352240498856187638698364963187582247755317248947078067854240395632616398148291436825962187420957120449829029159329633311223388401279833853583249389576104010731656432991427520221196504336632208776371980223227993694362760046030141121586451526105559498432298755864221588399902734850284549183530577855019919600211649429014816887363942026573774885822283335396590900002413080882647927650293700667545769032561699569990962010124949542228964868197341678311195256855649920744386724954951413645248937418850702913830444960131023975407408185931456430864010101519150475200684144890196499247610556608268090447668636859995673089076195611278550302710353367284202933371581577186916812663620306379179514320032499209919204639515250377595871578262799071868810698623548834
          MISCSELECT	00000000
            MISCMASK	ffffffff
            RESERVED	0000000000000000000000000000000000000000
          ATTRIBUTES	04000000000000000300000000000000
       ATTRIBUTEMASK	ffffffffffffffff1bffffffffffffff
         ENCLAVEHASH	b1de642a41bd99668f0c3057202ef6cb083d099a660ff2db804282513f463c33
            RESERVED	0000000000000000000000000000000000000000000000000000000000000000
           ISVPRODID	0000
              ISVSVN	0000
            RESERVED	000000000000000000000000
                  Q1	37674187943067401864568347358710141173096635463019573575955318208074523021536813230311994048491283606811302774733611229273236827440199499510720967168611736384714059966650114608406346883303026493751208582426809831607637222444203677345882195905836862889761038744487925448402835091501692208173099327696864725939377328937364910485183868575850814190703426879319858858275235710652803984047062069857875904723923651318638162299530156218140198692656898087947897747832673332328890744299213261737849164495929441817124117297081608979761250322856404091751831205140341404617889922564232099305677850083031829423265035603012391795901390828480318226165132334580202260422747243308065396838095322463008141964107571114746407455060684152435099515300225811585537422536397162199119479543798310327706232755287251186926713224145910745073298595417237177980487439420843938893703668110868492048182622496635649723806023401930398922845244380007615056915
                  Q2	394435829213686541519721262881576508132489554545563893553132971160322390679908779366136953895218927659080028674820201307474057751601093542089502690160984296581201601708866725061197899881170246195712903434587873079596199280633639175455032024216918042236441793338631530113757680997785078682199329491733667714306634975737456642426996153450609644598400505053551455389636204613735960591956890703866548081766784171110441827714675210110611147649723859792261474503000558378716323062813607872971706039705504587149240180611942985088155850324918266451279791666080140332450263539509225126075010492183640785603095381849869482075387328419074022665133405025587391861439525907328715980376993228786277733491586271040200293917925926820400509349448563687871707387559845997027544547235363685022236714387046279333192299563198813300215747000200371038667177943351153023006796195068257036960987645838857216945534751968422948735053040637012203089937


# ATTRIBUTES

               DEBUG	0
           MODE64BIT	1
        PROVISIONKEY	0
          EINITTOKEN	0

# sgxmeta not found

# ECALLs table found at 0x61140
                   0	vaddr: 0x4310
                   1	vaddr: 0x42d0
                   2	vaddr: 0x4280
                   3	vaddr: 0x4230
                   4	vaddr: 0x41e0
                   5	vaddr: 0x4190
                   6	vaddr: 0x40c0
                   7	vaddr: 0x40a0
```

`ENCLAVEHASH	b1de642a41bd99668f0c3057202ef6cb083d099a660ff2db804282513f463c33 `

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