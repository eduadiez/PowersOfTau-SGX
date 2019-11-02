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

use sgx_types::*;

#[macro_use]
extern crate lazy_static;
use std::sync::SgxMutex;
use pairing::bn256::Bn256;

lazy_static!{
    static ref KEYSTORE: SgxMutex<Keystore<Bn256>> = SgxMutex::new(Keystore::<Bn256>::new());
}

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
use pairing::ff::PrimeField;
use pairing::CurveProjective;
use pairing::EncodedPoint;
use pairing::CurveAffine;
use utils::hash_to_g2;
extern crate byteorder;
use std::vec::Vec;
use pairing::ff::Field;
use byteorder::BigEndian;
use byteorder::ReadBytesExt;
use blake2::digest::generic_array::GenericArray;

#[repr(C)]
pub enum ExpKey{
    KeyAlpha,
    KeyBeta,
}

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
            use std::string::String;
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

    *ks = gen_keypair(&mut rng, &digest);
    //*ks = gen_keypair_deterministic::<_, Bn256>(&mut rng, &digest);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn clean_keypair() -> sgx_status_t {
    let mut ks = KEYSTORE.lock().unwrap();
    *ks = Keystore::new();
    sgx_status_t::SGX_SUCCESS
}

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


#[no_mangle]
pub extern "C" fn mul_assign(exp: &mut pairing::bn256::Fr, exp_type: &ExpKey ) -> sgx_status_t {
    let ks = KEYSTORE.lock().unwrap();
    match exp_type {
        ExpKey::KeyAlpha => exp.mul_assign(&ks.private_key.alpha),
        ExpKey::KeyBeta => exp.mul_assign(&ks.private_key.beta),
    }
    sgx_status_t::SGX_SUCCESS    
}

#[no_mangle]
pub extern "C" fn mul_beta(beta_g2: &mut <pairing::bn256::Bn256 as Engine>::G2Affine ) -> sgx_status_t {
    let ks = KEYSTORE.lock().unwrap();
    *beta_g2 = (*beta_g2).mul(ks.private_key.beta).into_affine();
    sgx_status_t::SGX_SUCCESS    
}

#[no_mangle]
pub extern "C" fn get_public_key(pubkey: &mut PublicKey<Bn256>) -> sgx_status_t {
    let ks = KEYSTORE.lock().unwrap();
    *pubkey = (*ks).public_key;
    sgx_status_t::SGX_SUCCESS
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

/// Constructs a keypair given an RNG and a 64-byte transcript `digest`.
#[allow(dead_code)]
fn gen_keypair_deterministic<R: Rng, E: Engine>(_rng: &mut R, digest: &[u8]) -> Keystore::<E> {                    
    let tau = E::Fr::from_str("3835875312103070575654265771596533008994514025075239231195226282228457796408").unwrap();
    let alpha = E::Fr::from_str("21109449771018384494667264035729244018277451011524402520704046758348909735302").unwrap();
    let beta = E::Fr::from_str("18583422331330714657970793113818210303531653358343133009054090376308424313344").unwrap();

    let op = |x: E::Fr, personalization: u8| {
        // Sample random g^s
        let uncompressed = [17, 34, 206, 181, 66, 140, 192, 207, 211, 44, 1, 160, 184, 211, 3, 185, 22, 171, 68, 213, 219, 148, 126, 247, 106, 62, 31, 28, 101, 253, 204, 132, 23, 160, 99, 52, 152, 20, 207, 121, 176, 0, 252, 253, 228, 140, 27, 219, 239, 171, 212, 19, 173, 22, 39, 37, 40, 227, 136, 119, 231, 199, 121, 33];       
    
        let mut repr = <E::G1Affine as pairing::CurveAffine>::Uncompressed::empty();
        use std::io::Write;
        repr.as_mut().write(&uncompressed).expect("A panic message to be displayed");
        let g1_s = repr.into_affine().unwrap();
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

        println!("h_digest: {:x}",h);

        // Hash into G2 as g^{s'}   
        let uncompressed_2 = [13, 181, 227, 135, 177, 86, 64, 17, 156, 13, 165, 76, 159, 121, 166, 87, 6, 120, 176, 83, 121, 55, 146, 128, 83, 248, 177, 184, 62, 199, 254, 123, 48, 56, 24, 63, 213, 81, 56, 180, 175, 112, 149, 154, 191, 78, 229, 54, 111, 94, 102, 49, 129, 84, 71, 76, 164, 232, 145, 16, 44, 178, 201, 200, 40, 212, 101, 208, 150, 117, 16, 229, 138, 193, 35, 77, 26, 55, 231, 190, 154, 181, 48, 44, 172, 187, 160, 151, 237, 225, 157, 233, 63, 129, 251, 232, 42, 16, 16, 255, 42, 178, 119, 128, 247, 183, 103, 22, 9, 228, 145, 207, 32, 83, 246, 103, 209, 74, 232, 253, 74, 156, 25, 230, 66, 87, 15, 6];
        let mut repr_2 = <<E as pairing::Engine>::G2Affine as pairing::CurveAffine>::Uncompressed::empty();
        repr_2.as_mut().write(&uncompressed_2).expect("A panic message to be displayed");
        let g2_s = repr_2.into_affine().unwrap();
        
        // Compute g^{s'*x}
        let g2_s_x = g2_s.mul(x).into_affine();

        ((g1_s, g1_s_x), g2_s_x)
    };
   

    let pk_tau = op(tau,0);
    let pk_alpha = op(alpha,1);
    let pk_beta = op(beta,2);

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