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

#![crate_name = "sgxpowersoftau"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_tse;
extern crate sgx_tcrypto;
use sgx_tcrypto::rsgx_sha256_slice;
use sgx_types::*;

#[macro_use]
extern crate lazy_static;
use std::sync::SgxMutex;
use pairing::bn256::Bn256;

extern "C" {
    pub fn ocall_sgx_init_quote ( ret_val : *mut sgx_status_t,
                  ret_ti  : *mut sgx_target_info_t,
                  ret_gid : *mut sgx_epid_group_id_t) -> sgx_status_t;
    pub fn ocall_get_quote (ret_val            : *mut sgx_status_t,
                p_sigrl            : *const u8,
                sigrl_len          : u32,
                p_report           : *const sgx_report_t,
                quote_type         : sgx_quote_sign_type_t,
                p_spid             : *const sgx_spid_t,
                p_nonce            : *const sgx_quote_nonce_t,
                p_qe_report        : *mut sgx_report_t,
                p_quote            : *mut u8,
                maxlen             : u32,
                p_quote_len        : *mut u32) -> sgx_status_t;
}

lazy_static!{
    static ref KEYSTORE: SgxMutex<Keystore<Bn256>> = SgxMutex::new(Keystore::<Bn256>::new());
    static ref DIGEST_HASH: SgxMutex<sgx_sha256_hash_t> = SgxMutex::new([0; 32]);
}

//static SPID: [u8; 16] = [131, 148, 124, 118, 73, 75, 241, 31, 177, 161, 82, 107, 137, 215, 90, 37]; // DEV: 83947C76494BF11FB1A1526B89D75A25
static SPID: [u8; 16] = [224, 233, 24, 221, 188, 132, 146, 21, 104, 228, 3, 186, 208, 201, 252, 8];

extern crate pairing;
pub mod keystore;
pub mod keypair;
pub mod parameters;
pub mod utils;

use keystore::Keystore;

extern crate blake2;
use blake2::{Blake2b, Digest};

extern crate sgx_rand as rand;
use rand::{Rng,os,Rand,SeedableRng, ChaChaRng};
use pairing::Engine;
use keypair::PublicKey;
use keypair::PrivateKey;
extern crate typenum;
use typenum::consts::U64;
use pairing::CurveProjective;
use pairing::CurveAffine;
use utils::hash_to_g2;
extern crate byteorder;
use std::vec::Vec;
use pairing::ff::Field;
use byteorder::BigEndian;
use byteorder::ReadBytesExt;
use blake2::digest::generic_array::GenericArray;
use std::string::String;
use sgx_tse::rsgx_create_report;
use sgx_tse::rsgx_verify_report;
use std::ptr;

#[repr(C)]
pub enum ExpKey{
    KeyAlpha,
    KeyBeta,
}

// Keypar initialization
#[no_mangle]
pub extern "C" fn init_keypair(digest: &GenericArray<u8, U64>) -> sgx_status_t {

    // RAND: https://www.blackhat.com/docs/us-16/materials/us-16-Aumasson-SGX-Secure-Enclaves-In-Practice-Security-And-Crypto-Review-wp.pdf

    let mut ks = KEYSTORE.lock().unwrap();
    *ks = Keystore::new();

    let mut rng = {
        let h = {
            let mut system_rng = os::SgxRng::new().unwrap();
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

        //Interpret the first 32 bytes of the digest as 8 32-bit words
        let mut seed = [0u32; 8];
        for i in 0..8 {
            seed[i] = digest.read_u32::<BigEndian>().expect("digest is large enough for this to work");
        }

        ChaChaRng::from_seed(&seed)
    };

    let mut digest_hash = DIGEST_HASH.lock().unwrap();
    *digest_hash = rsgx_sha256_slice(&hex::encode(&digest)[..].as_bytes()).unwrap();

    *ks = gen_keypair(&mut rng, &digest);
    sgx_status_t::SGX_SUCCESS
}

// This function es resposible of replace this code from batched_accumulator.rs:
/*
    let mut acc = key.tau.pow(&[(start + i * chunk_size) as u64]);

    for t in taupowers {
        *t = acc;
        acc.mul_assign(&key.tau);
    }
*/
#[no_mangle]
pub extern "C" fn construct_exponents(exponent: usize, powersoftaus: *mut pairing::bn256::Fr, size: usize ) -> sgx_status_t {
    let ks = KEYSTORE.lock().unwrap();
    let mut rebuilt = unsafe{ Vec::from_raw_parts(powersoftaus,size as usize,size as usize)} ;
    let mut acc = ks.private_key.tau.pow(&[exponent as u64]);
    for i in 0..size as usize {
       rebuilt[i] = acc;
        acc.mul_assign(&ks.private_key.tau);
    }
    std::mem::forget(rebuilt);
    sgx_status_t::SGX_SUCCESS    
}

// This function es resposible of replace this code from batched_accumulator.rs:
/*
    exp.mul_assign(coeff);
*/
#[no_mangle]
pub extern "C" fn mul_assign(exp: &mut pairing::bn256::Fr, exp_type: &ExpKey ) -> sgx_status_t {
    let ks = KEYSTORE.lock().unwrap();
    match exp_type {
        ExpKey::KeyAlpha => exp.mul_assign(&ks.private_key.alpha),
        ExpKey::KeyBeta => exp.mul_assign(&ks.private_key.beta),
    }
    sgx_status_t::SGX_SUCCESS    
}

// This function replace this code from batched_accumulator.rs:
/*
    accumulator.beta_g2 = accumulator.beta_g2.mul(key.beta).into_affine();
*/
#[no_mangle]
pub extern "C" fn mul_beta(beta_g2: &mut <pairing::bn256::Bn256 as Engine>::G2Affine ) -> sgx_status_t {
    let ks = KEYSTORE.lock().unwrap();
    *beta_g2 = (*beta_g2).mul(ks.private_key.beta).into_affine();
    sgx_status_t::SGX_SUCCESS    
}

#[no_mangle]
pub extern "C" fn get_public_key(pubkey: &mut PublicKey<Bn256>) -> sgx_status_t {
    let mut ks = KEYSTORE.lock().unwrap();
    *pubkey = (*ks).public_key;
    // At the moment you get the public key, 
    // the private key and the public key are destroyed, 
    // this function is called at the end of the process

    // Generate the attestation proof
      let pbk_slice = [
        (pubkey.tau_g1).0.into_uncompressed().as_ref(),
        (pubkey.tau_g1).1.into_uncompressed().as_ref(),
        (pubkey.alpha_g1).0.into_uncompressed().as_ref(),
        (pubkey.alpha_g1).1.into_uncompressed().as_ref(),
        (pubkey.beta_g1).0.into_uncompressed().as_ref(),
        (pubkey.beta_g1).1.into_uncompressed().as_ref(),
        (pubkey.tau_g2).into_uncompressed().as_ref(),   
        (pubkey.alpha_g2).into_uncompressed().as_ref(),
        (pubkey.beta_g2).into_uncompressed().as_ref(),
        ].concat();
    
    let pbk_slice_hash = rsgx_sha256_slice(&hex::encode(&pbk_slice)[..].as_bytes()).unwrap();
    
    match DIGEST_HASH.lock() 
    {
        Ok(digest_hash) => {
            let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
            report_data.d[..32].clone_from_slice(&pbk_slice_hash);
            report_data.d[32..].clone_from_slice(&*digest_hash);
        
            let sign_type = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE;
            match create_attestation_report(sign_type, report_data) {
                Ok(r) => r,
                Err(e) => {
                    println!("Error in create_attestation_report: {:?}", e);
                    return sgx_status_t::SGX_ERROR_UNEXPECTED;
                }
            };
        
            *ks = Keystore::new();
            sgx_status_t::SGX_SUCCESS
        }
        Err(_) => panic!("llvm_gcda_end_file failed!"),
    }


}


/// Constructs a keypair given an RNG and a 64-byte transcript `digest`.
fn gen_keypair<R: Rng, E: Engine>(rng: &mut R, digest: &[u8]) -> Keystore::<E> {
     // tau is a conribution to the "powers of tau", in a set of points of the form "tau^i * G"
    let tau = E::Fr::rand(rng);

    // alpha and beta are a set of conrtibuitons in a form "alpha * tau^i * G" and that are required
    // for construction of the polynomials
    let alpha = E::Fr::rand(rng);
    let beta = E::Fr::rand(rng);

    let mut op = |x: E::Fr, personalization: u8| {
        // Sample random g^s
        let g1_s = E::G1::rand(rng).into_affine();

        // Compute g^{s*x}
        let g1_s_x = g1_s.mul(x).into_affine();

        // Compute BLAKE2b(personalization | transcript | g^s | g^{s*x})
        let h: blake2::digest::generic_array::GenericArray<u8, U64> = {
            let mut h = Blake2b::default();
            h.input(&[personalization]);
            h.input(digest);
            h.input(g1_s.into_uncompressed().as_ref());
            h.input(g1_s_x.into_uncompressed().as_ref());
            h.result()
        };
      
        // Hash into G2 as g^{s'}
        let g2_s: E::G2Affine = hash_to_g2::<E>(h.as_ref()).into_affine();

        // Compute g^{s'*x}
        let g2_s_x = g2_s.mul(x).into_affine();

        ((g1_s, g1_s_x), g2_s_x)
    };
   

    let pk_tau = op(tau, 0);
    let pk_alpha = op(alpha, 1);
    let pk_beta = op(beta, 2);

    Keystore{
        public_key: PublicKey {
            tau_g1: pk_tau.0,
            alpha_g1: pk_alpha.0,
            beta_g1: pk_beta.0,
            tau_g2: pk_tau.1,
            alpha_g2: pk_alpha.1,
            beta_g2: pk_beta.1,
        },
        private_key: PrivateKey {
            tau: tau,
            alpha: alpha,
            beta: beta
        }
    }
}

#[allow(const_err)]
pub fn create_attestation_report(sign_type: sgx_quote_sign_type_t, report_data: sgx_report_data_t) -> Result<(), sgx_status_t> {

    // Workflow:
    // (1) ocall to get the target_info structure (ti) and epid group id (eg)
    // (1.5) get sigrl
    // (2) call sgx_create_report with ti+data, produce an sgx_report_t
    // (3) ocall to sgx_get_quote to generate (*mut sgx-quote_t, uint32_t)

    // (1) get ti + eg
    let mut ti : sgx_target_info_t = sgx_target_info_t::default();
    let mut eg : sgx_epid_group_id_t = sgx_epid_group_id_t::default();
    let mut rt : sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let res = unsafe {
        ocall_sgx_init_quote(&mut rt as *mut sgx_status_t,
                             &mut ti as *mut sgx_target_info_t,
                             &mut eg as *mut sgx_epid_group_id_t)
    };
   
    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    let rep = match rsgx_create_report(&ti, &report_data) {
        Ok(r) =>{
            println!("[-] Report creation => success");
            Some(r)
        },
        Err(e) =>{
            println!("[-] Report creation => failed {:?}", e);
            None
        },
    };

    let mut quote_nonce = sgx_quote_nonce_t { rand : [0;16] };
    let mut os_rng = os::SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut quote_nonce.rand);
    let mut qe_report = sgx_report_t::default();
    const RET_QUOTE_BUF_LEN : u32 = 2048;
    let mut return_quote_buf : [u8; RET_QUOTE_BUF_LEN as usize] = [0;RET_QUOTE_BUF_LEN as usize];
    let mut quote_len : u32 = 0;
    
    let (p_sigrl, sigrl_len) = (ptr::null(), 0);

    // (3) Generate the quote
    // Args:
    //       1. sigrl: ptr + len
    //       2. report: ptr 432bytes
    //       3. linkable: u32, unlinkable=0, linkable=1
    //       4. spid: sgx_spid_t ptr 16bytes
    //       5. sgx_quote_nonce_t ptr 16bytes
    //       6. p_sig_rl + sigrl size ( same to sigrl)
    //       7. [out]p_qe_report need further check
    //       8. [out]p_quote
    //       9. quote_size
    /*
    let (p_sigrl, sigrl_len) =
        if sigrl_vec.len() == 0 {
            (ptr::null(), 0)
        } else {
            (sigrl_vec.as_ptr(), sigrl_vec.len() as u32)
        };
    */
    let p_report = (&rep.unwrap()) as * const sgx_report_t;
    let quote_type = sign_type;

    let mut spid : sgx_spid_t = sgx_spid_t::default();
    spid.id = SPID;

    let p_spid = &spid as *const sgx_spid_t;
    let p_nonce = &quote_nonce as * const sgx_quote_nonce_t;
    let p_qe_report = &mut qe_report as *mut sgx_report_t;
    let p_quote = return_quote_buf.as_mut_ptr();
    let maxlen = RET_QUOTE_BUF_LEN;
    let p_quote_len = &mut quote_len as *mut u32;

    let result = unsafe {
        ocall_get_quote(&mut rt as *mut sgx_status_t,
                p_sigrl,
                sigrl_len,
                p_report,
                quote_type,
                p_spid,
                p_nonce,
                p_qe_report,
                p_quote,
                maxlen,
                p_quote_len)
    };

    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        println!("[-] ocall_get_quote returned {}", rt);
        return Err(rt);
    }

    // Perform a check on qe_report to verify if the qe_report is valid
    match rsgx_verify_report(&qe_report) {
        Ok(()) => println!("[-] rsgx_verify_report passed!"),
        Err(x) => {
            println!("[-] rsgx_verify_report failed with {:?}", x);
            return Err(x);
        },
    }

    // Check if the qe_report is produced on the same platform
    if ti.mr_enclave.m != qe_report.body.mr_enclave.m ||
       ti.attributes.flags != qe_report.body.attributes.flags ||
       ti.attributes.xfrm  != qe_report.body.attributes.xfrm {
        println!("[-] qe_report does not match current target_info!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    println!("[-] qe_report check passed");

    // Check qe_report to defend against replay attack
    // The purpose of p_qe_report is for the ISV enclave to confirm the QUOTE
    // it received is not modified by the untrusted SW stack, and not a replay.
    // The implementation in QE is to generate a REPORT targeting the ISV
    // enclave (target info from p_report) , with the lower 32Bytes in
    // report.data = SHA256(p_nonce||p_quote). The ISV enclave can verify the
    // p_qe_report and report.data to confirm the QUOTE has not be modified and
    // is not a replay. It is optional.
    let mut rhs_vec : Vec<u8> = quote_nonce.rand.to_vec();
    rhs_vec.extend(&return_quote_buf[..quote_len as usize]);
    let rhs_hash = rsgx_sha256_slice(&rhs_vec[..]).unwrap();
    let lhs_hash = &qe_report.body.report_data.d[..32];

    if rhs_hash != lhs_hash {
        println!("[-] Quote is tampered!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }
    Ok(())
}       