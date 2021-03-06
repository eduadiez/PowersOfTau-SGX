// Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

extern crate sgx_types;
extern crate sgx_urts;

use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::io::{Read, Write};
use std::fs;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

extern crate rand;
extern crate blake2;
extern crate memmap;
extern crate typenum;
extern crate byteorder;
extern crate bellman_ce;
extern crate generic_array;

use memmap::*;
use std::slice;

use std::fs::OpenOptions;
use keypair::PublicKey;    

pub mod utils;
pub mod keypair;
pub mod parameters;
pub mod small_bn256;
pub mod batched_accumulator;
use crate::batched_accumulator::BachedAccumulator;
use crate::small_bn256::{Bn256CeremonyParameters};
use crate::parameters::{PowersOfTauParameters, UseCompression, CheckForCorrectness};
use bellman_ce::pairing::bn256::Bn256;

const INPUT_IS_COMPRESSED: UseCompression = UseCompression::No;
const COMPRESS_THE_OUTPUT: UseCompression = UseCompression::Yes;
const CHECK_INPUT_CORRECTNESS: CheckForCorrectness = CheckForCorrectness::No;

use bellman_ce::pairing::CurveAffine;

use bellman_ce::pairing::bn256::{G1Affine,G2Affine};

extern {
    fn init_keypair(eid: sgx_enclave_id_t, retval: *mut sgx_status_t, digest: &u8) -> sgx_status_t;
    fn get_public_key(eid: sgx_enclave_id_t, retval: *mut sgx_status_t, pubkey: &mut u8) -> sgx_status_t;
}

#[no_mangle]
pub extern "C"
fn ocall_sgx_init_quote(ret_ti: *mut sgx_target_info_t,
                        ret_gid : *mut sgx_epid_group_id_t) -> sgx_status_t {
    println!("[+] Entering ocall_sgx_init_quote...");
    unsafe {sgx_init_quote(ret_ti, ret_gid)}
}


#[no_mangle]
pub extern "C"
fn ocall_get_quote (p_sigrl            : *const u8,
                    sigrl_len          : u32,
                    p_report           : *const sgx_report_t,
                    quote_type         : sgx_quote_sign_type_t,
                    p_spid             : *const sgx_spid_t,
                    p_nonce            : *const sgx_quote_nonce_t,
                    p_qe_report        : *mut sgx_report_t,
                    p_quote            : *mut u8,
                    _maxlen            : u32,
                    p_quote_len        : *mut u32) -> sgx_status_t {
    println!("[+] Entering ocall_get_quote");

    let mut real_quote_len : u32 = 0;

    let ret = unsafe {
        sgx_calc_quote_size(p_sigrl, sigrl_len, &mut real_quote_len as *mut u32)
    };

    if ret != sgx_status_t::SGX_SUCCESS {
        println!("[+] sgx_calc_quote_size returned {}", ret);
        return ret;
    }

    unsafe { *p_quote_len = real_quote_len; }

    let ret = unsafe {
        sgx_get_quote(p_report,
                      quote_type,
                      p_spid,
                      p_nonce,
                      p_sigrl,
                      sigrl_len,
                      p_qe_report,
                      p_quote as *mut sgx_quote_t,
                      real_quote_len)
    };

    if ret != sgx_status_t::SGX_SUCCESS {
        println!("[+] sgx_calc_quote_size returned {}", ret);
        return ret;
    }
    
    let quote_vec = unsafe { slice::from_raw_parts(p_quote, real_quote_len as usize)};
    let mut file = fs::File::create("quote.bin").unwrap();
    // Write a slice of bytes to the file
    file.write_all(&quote_vec).expect("unable to write");
    file = fs::File::create("quote.json").unwrap();
    //https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf
    /*
        curl -i -X POST \
        https://api.trustedservices.intel.com/sgx/dev/attestation/v3/report \
        -H 'Content-Type: application/json' \
        -H 'Ocp-Apim-Subscription-Key: bc6ef22000ff41aca23ee0469c988821' \
        -d @quote.json
    */

    let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", base64::encode(&quote_vec));
    file.write_all(encoded_json.as_bytes()).expect("unable to write");
    ret
}

fn init_enclave() -> SgxResult<SgxEnclave> {

    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    
    // Debug Support: set 2nd parameter to 1
    let debug = 0;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    let enclave = try!(SgxEnclave::create(ENCLAVE_FILE,
                                          debug,
                                          &mut launch_token,
                                          &mut launch_token_updated,
                                          &mut misc_attr));

    Ok(enclave)
}

fn main() {

    // Specific code for Intel SGX v
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        },
    };

    // ###########################################################
    // Original code: https://github.com/kobigurk/phase2-bn254/blob/470dff3d9221b4393f50e5fcb82949ef8551e7a4/powersoftau/src/bin/compute_constrained.rs#L26
    // ###########################################################

    println!("Will contribute to accumulator for 2^{} powers of tau", Bn256CeremonyParameters::REQUIRED_POWER);
    println!("In total will generate up to {} powers", Bn256CeremonyParameters::TAU_POWERS_G1_LENGTH);

    // ###########################################################
    // SGX: The RNG generation is moved to within the enclave
    // Create an RNG based on a mixture of system randomness and user provided randomness
    /*
    let mut rng = {
        use byteorder::{ReadBytesExt, BigEndian};
        use blake2::{Blake2b, Digest};
        use rand::{SeedableRng, Rng, OsRng};
        use rand::chacha::ChaChaRng;

        let h = {
            let mut system_rng = OsRng::new().unwrap();
            let mut h = Blake2b::default();

            // Gather 1024 bytes of entropy from the system
            for _ in 0..1024 {
                let r: u8 = system_rng.gen();
                h.input(&[r]);
            }

            // Ask the user to provide some information for additional entropy
            let mut user_input = String::new();
            println!("Type some random text and press [ENTER] to provide additional entropy...");
            std::io::stdin().read_line(&mut user_input).expect("expected to read some random text from the user");

            // Hash it all up to make a seed
            h.input(&user_input.as_bytes());
            h.result()
        };

        let mut digest = &h[..];

        // Interpret the first 32 bytes of the digest as 8 32-bit words
        let mut seed = [0u32; 8];
        for i in 0..8 {
            seed[i] = digest.read_u32::<BigEndian>().expect("digest is large enough for this to work");
        }

        ChaChaRng::from_seed(&seed)
    };*/
    // ###########################################################


    // Try to load `./challenge` from disk.
    let reader = OpenOptions::new()
                            .read(true)
                            .open("challenge").expect("unable open `./challenge` in this directory");
    {
        let metadata = reader.metadata().expect("unable to get filesystem metadata for `./challenge`");
        let expected_challenge_length = match INPUT_IS_COMPRESSED {
            UseCompression::Yes => {
                Bn256CeremonyParameters::CONTRIBUTION_BYTE_SIZE
            },
            UseCompression::No => {
                Bn256CeremonyParameters::ACCUMULATOR_BYTE_SIZE
            }
        };

        if metadata.len() != (expected_challenge_length as u64) {
            panic!("The size of `./challenge` should be {}, but it's {}, so something isn't right.", expected_challenge_length, metadata.len());
        }
    }

    let readable_map = unsafe { MmapOptions::new().map(&reader).expect("unable to create a memory map for input") };

    // Create `./response` in this directory
    let writer = OpenOptions::new()
                            .read(true)
                            .write(true)
                            .create_new(true)
                            .open("response").expect("unable to create `./response` in this directory");

    let required_output_length = match COMPRESS_THE_OUTPUT {
        UseCompression::Yes => {
            Bn256CeremonyParameters::CONTRIBUTION_BYTE_SIZE
        },
        UseCompression::No => {
            Bn256CeremonyParameters::ACCUMULATOR_BYTE_SIZE + Bn256CeremonyParameters::PUBLIC_KEY_SIZE
        }
    };

    writer.set_len(required_output_length as u64).expect("must make output file large enough");

    let mut writable_map = unsafe { MmapOptions::new().map_mut(&writer).expect("unable to create a memory map for output") };

    println!("Calculating previous contribution hash...");

    assert!(UseCompression::No == INPUT_IS_COMPRESSED, "Hashing the compressed file in not yet defined");
  
    let current_accumulator_hash = BachedAccumulator::<Bn256, Bn256CeremonyParameters>::calculate_hash(&readable_map);
  
    {
        println!("`challenge` file contains decompressed points and has a hash:");
        for line in current_accumulator_hash.as_slice().chunks(16) {
            print!("\t");
            for section in line.chunks(4) {
                for b in section {
                    print!("{:02x}", b);
                }
                print!(" ");
            }
            println!("");
        }

        (&mut writable_map[0..]).write(current_accumulator_hash.as_slice()).expect("unable to write a challenge hash to mmap");

        writable_map.flush().expect("unable to write hash to `./response`");
    }

    {
        let mut challenge_hash = [0; 64];
        let memory_slice = readable_map.get(0..64).expect("must read point data from file");
        memory_slice.clone().read_exact(&mut challenge_hash).expect("couldn't read hash of challenge file from response file");

        println!("`challenge` file claims (!!! Must not be blindly trusted) that it was based on the original contribution with a hash:");
        for line in challenge_hash.chunks(16) {
            print!("\t");
            for section in line.chunks(4) {
                for b in section {
                    print!("{:02x}", b);
                }
                print!(" ");
            }
            println!("");
        }
    }

    // #################################################################################
    // SGX: The construct of our keypair using the RNG is moved to within the enclave
    // Construct our keypair using the RNG we created above
    // let (pubkey, privkey) = keypair(&mut rng, current_accumulator_hash.as_ref());

    // SGX: Initialize the keypair inside the enclave
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        init_keypair(
            enclave.geteid(),
            &mut retval,
            &current_accumulator_hash.as_ref()[0]
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }
    // #################################################################################

    // Perform the transformation
    println!("Computing and writing your contribution, this could take a while...");

    // SGX: The prototype of the function is changed since now we don't have the privkey.
    // Instead, the EID of the enclave is sent to be able to invoke it and operate with the private key

    // this computes a transformation and writes it
    BachedAccumulator::<Bn256, Bn256CeremonyParameters>::transform(
        &readable_map, 
        &mut writable_map, 
        INPUT_IS_COMPRESSED, 
        COMPRESS_THE_OUTPUT, 
        CHECK_INPUT_CORRECTNESS, 
        enclave.geteid() //&privkey
    ).expect("must transform with the key");

    println!("Finihsing writing your contribution to `./response`...");

    // SGX: We get the `publicKey', at the moment we do this the private key is destroyed 
    let mut pubkey =  PublicKey::<Bn256> {
            tau_g1: (G1Affine::zero(),G1Affine::zero()),
            alpha_g1: (G1Affine::zero(),G1Affine::zero()),
            beta_g1: (G1Affine::zero(),G1Affine::zero()),
            tau_g2: G2Affine::zero(),
            alpha_g2: G2Affine::zero(),
            beta_g2: G2Affine::zero(),
        };
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        get_public_key(
            enclave.geteid(),
            &mut retval,
            &mut any_as_u8_slice(&mut pubkey)[0]
        )
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL get_public_key Failed {}!", result.as_str());
            return;
        }
    }
   
    // Write the public key
    pubkey.write::<Bn256CeremonyParameters>(&mut writable_map, COMPRESS_THE_OUTPUT).expect("unable to write public key");
    writable_map.flush().expect("must flush a memory map");
  
    // Get the hash of the contribution, so the user can compare later
    let output_readonly = writable_map.make_read_only().expect("must make a map readonly");
    let contribution_hash = BachedAccumulator::<Bn256, Bn256CeremonyParameters>::calculate_hash(&output_readonly);

    print!("Done!\n\n\
              Your contribution has been written to `./response`\n\n\
              The BLAKE2b hash of `./response` is:\n");

    for line in contribution_hash.as_slice().chunks(16) {
        print!("\t");
        for section in line.chunks(4) {
            for b in section {
                print!("{:02x}", b);
            }
            print!(" ");
        }
        println!("");
    }

    println!("Thank you for your participation, much appreciated! :)");
    
    println!("[+] run_enclave success!");

    enclave.destroy();
}

unsafe fn any_as_u8_slice<T: Sized>(p: &mut T) -> &mut [u8] {
    ::std::slice::from_raw_parts_mut(
        (p as *mut T) as *mut u8,
        ::std::mem::size_of::<T>(),
    )
}