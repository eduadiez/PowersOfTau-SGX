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
extern crate dirs;

use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::io::{Read, Write};
use std::fs;
use std::path;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";
static ENCLAVE_TOKEN: &'static str = "enclave.token";

extern crate rand;
extern crate blake2;
extern crate memmap;
extern crate typenum;
extern crate byteorder;
extern crate bellman_ce;
extern crate generic_array;

use memmap::*;
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
    fn clean_keypair(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
    fn get_public_key(eid: sgx_enclave_id_t, retval: *mut sgx_status_t, pubkey: &mut u8) -> sgx_status_t;
}

fn init_enclave() -> SgxResult<SgxEnclave> {

    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // Step 1: try to retrieve the launch token saved by last transaction
    //         if there is no token, then create a new one.
    //
    // try to get the token saved in $HOME */
    let mut home_dir = path::PathBuf::new();
    let use_token = match dirs::home_dir() {
        Some(path) => {
            println!("[+] Home dir is {}", path.display());
            home_dir = path;
            true
        },
        None => {
            println!("[-] Cannot get home dir");
            false
        }
    };

    let token_file: path::PathBuf = home_dir.join(ENCLAVE_TOKEN);;
    if use_token == true {
        match fs::File::open(&token_file) {
            Err(_) => {
                println!("[-] Open token file {} error! Will create one.", token_file.as_path().to_str().unwrap());
            },
            Ok(mut f) => {
                println!("[+] Open token file success! ");
                match f.read(&mut launch_token) {
                    Ok(1024) => {
                        println!("[+] Token file valid!");
                    },
                    _ => println!("[+] Token file invalid, will create new token file"),
                }
            }
        }
    }

    // Step 2: call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    let enclave = try!(SgxEnclave::create(ENCLAVE_FILE,
                                          debug,
                                          &mut launch_token,
                                          &mut launch_token_updated,
                                          &mut misc_attr));

    // Step 3: save the launch token if it is updated
    if use_token == true && launch_token_updated != 0 {
        // reopen the file with write capablity
        match fs::File::create(&token_file) {
            Ok(mut f) => {
                match f.write_all(&launch_token) {
                    Ok(()) => println!("[+] Saved updated launch token!"),
                    Err(_) => println!("[-] Failed to save updated launch token!"),
                }
            },
            Err(_) => {
                println!("[-] Failed to save updated enclave token, but doesn't matter");
            },
        }
    }

    Ok(enclave)
}

fn main() {

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

    println!("Will contribute to accumulator for 2^{} powers of tau", Bn256CeremonyParameters::REQUIRED_POWER);
    println!("In total will generate up to {} powers", Bn256CeremonyParameters::TAU_POWERS_G1_LENGTH);

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

    // Construct our keypair using the RNG we created above
    //let (pubkey, privkey) = keypair(&mut rng, current_accumulator_hash.as_ref());

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

    // Perform the transformation
    println!("Computing and writing your contribution, this could take a while...");

    // this computes a transformation and writes it
    BachedAccumulator::<Bn256, Bn256CeremonyParameters>::transform(
        &readable_map, 
        &mut writable_map, 
        INPUT_IS_COMPRESSED, 
        COMPRESS_THE_OUTPUT, 
        CHECK_INPUT_CORRECTNESS, 
        enclave.geteid()
        //&privkey
    ).expect("must transform with the key");

    println!("Finihsing writing your contribution to `./response`...");

    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut pubkey =  PublicKey::<Bn256> {
            tau_g1: (G1Affine::zero(),G1Affine::zero()),
            alpha_g1: (G1Affine::zero(),G1Affine::zero()),
            beta_g1: (G1Affine::zero(),G1Affine::zero()),
            tau_g2: G2Affine::zero(),
            alpha_g2: G2Affine::zero(),
            beta_g2: G2Affine::zero(),
        };
    unsafe fn any_as_u8_slice<T: Sized>(p: &mut T) -> &mut [u8] {
            ::std::slice::from_raw_parts_mut(
                (p as *mut T) as *mut u8,
                ::std::mem::size_of::<T>(),
            )
    }
    unsafe {
        get_public_key(
            enclave.geteid(),
            &mut retval,
            &mut any_as_u8_slice(&mut pubkey)[0]
        )
    };
    unsafe {
        clean_keypair(
            enclave.geteid(),
            &mut retval
        )
    };
   
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
    
    println!("[+] run_enclave success...");

    enclave.destroy();
}
