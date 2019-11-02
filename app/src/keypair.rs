/*
extern crate rand;
extern crate crossbeam;
extern crate num_cpus;
extern crate blake2;
extern crate generic_array;
extern crate typenum;
extern crate byteorder;
extern crate bellman_ce;
extern crate memmap;
extern crate itertools;

use itertools::Itertools;
use memmap::{Mmap, MmapMut};
use self::bellman_ce::pairing::ff::{Field, PrimeField};
use self::byteorder::{ReadBytesExt, BigEndian};
use self::rand::{SeedableRng, Rng, Rand};
use self::rand::chacha::ChaChaRng;
use self::bellman_ce::pairing::bn256::{Bn256};
use self::bellman_ce::pairing::*;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use self::generic_array::GenericArray;
use self::typenum::consts::U64;
use self::blake2::{Blake2b, Digest};
use std::fmt;

use super::utils::*;
use super::parameters::*;
*/

use std::io::{self, Read, Write};
use super::parameters::*;
use bellman_ce::pairing::Engine;
use utils::write_point;
use bellman_ce::pairing::CurveAffine;
use memmap::MmapMut;
use memmap::Mmap;
use bellman_ce::pairing::EncodedPoint;

/// Contains terms of the form (s<sub>1</sub>, s<sub>1</sub><sup>x</sup>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub><sup>x</sup>)
/// for all x in τ, α and β, and some s chosen randomly by its creator. The function H "hashes into" the group G2. No points in the public key may be the identity.
///
/// The elements in G2 are used to verify transformations of the accumulator. By its nature, the public key proves
/// knowledge of τ, α and β.
///
/// It is necessary to verify `same_ratio`((s<sub>1</sub>, s<sub>1</sub><sup>x</sup>), (H(s<sub>1</sub><sup>x</sup>)<sub>2</sub>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub><sup>x</sup>)).
#[derive(Eq)]
#[repr(C)]
pub struct PublicKey<E: Engine> {
    pub tau_g1: (E::G1Affine, E::G1Affine),
    pub alpha_g1: (E::G1Affine, E::G1Affine),
    pub beta_g1: (E::G1Affine, E::G1Affine),
    pub tau_g2: E::G2Affine,
    pub alpha_g2: E::G2Affine,
    pub beta_g2: E::G2Affine
}

impl<E: Engine> PartialEq for PublicKey<E> {
    fn eq(&self, other: &PublicKey<E>) -> bool {
        self.tau_g1.0 == other.tau_g1.0 &&
        self.tau_g1.1 == other.tau_g1.1 &&
        self.alpha_g1.0 == other.alpha_g1.0 &&
        self.alpha_g1.1 == other.alpha_g1.1 &&
        self.beta_g1.0 == other.beta_g1.0 &&
        self.beta_g1.1 == other.beta_g1.1 &&
        self.tau_g2 == other.tau_g2 &&
        self.alpha_g2 == other.alpha_g2 &&
        self.beta_g2 == other.beta_g2
    }
}

/// Contains the secrets τ, α and β that the participant of the ceremony must destroy.
pub struct PrivateKey<E: Engine> {
    pub tau: E::Fr,
    pub alpha: E::Fr,
    pub beta: E::Fr
}

/*
/// Constructs a keypair given an RNG and a 64-byte transcript `digest`.
pub fn keypair<R: Rng, E: Engine>(rng: &mut R, digest: &[u8]) -> (PublicKey<E>, PrivateKey<E>)
{
    assert_eq!(digest.len(), 64);

    // tau is a conribution to the "powers of tau", in a set of points of the form "tau^i * G"
    let mut tau = E::Fr::rand(rng);
    // alpha and beta are a set of conrtibuitons in a form "alpha * tau^i * G" and that are required
    // for construction of the polynomials
    let mut alpha = E::Fr::rand(rng);
    let mut beta = E::Fr::rand(rng);

    tau = E::Fr::from_str("16383917631990622472796603094026688586750831982454854284810024292706462088844").unwrap();
    alpha = E::Fr::from_str("5281706767944942685315354136352259918620202526311495624983203693486665954394").unwrap();
    beta = E::Fr::from_str("1060381919196104606268951442527498394115945045412491231406889912805588265769").unwrap();
    println!("tau = {}", tau);
    println!("alpha = {}", alpha);
    println!("beta = {}", beta);


    let mut op = |x: E::Fr, personalization: u8| {
        // Sample random g^s
        let mut g1_s = E::G1::rand(rng).into_affine();
            
        let uncompressed = [8, 142, 78, 170, 174, 171, 101, 166, 210, 54, 75, 37, 158, 97, 206, 249, 109, 31, 76, 24, 48, 243, 159, 216, 165, 249, 30, 77, 200, 182, 231, 225, 4, 112, 252, 121, 117, 68, 223, 254, 90, 202, 224, 83, 250, 67, 110, 237, 66, 173, 27, 117, 126, 194, 252, 130, 223, 25, 24, 183, 36, 235, 28, 51];

        let mut repr = <<E as bellman_ce::pairing::Engine>::G1Affine as bellman_ce::pairing::CurveAffine>::Uncompressed::empty();
        use std::io::Write;
        repr.as_mut().write(&uncompressed);
        g1_s = repr.into_affine().unwrap();
        println!("g1_s = {:?}",g1_s);

        // Compute g^{s*x}
        let g1_s_x = g1_s.mul(x).into_affine();
        println!("g1_s_x = {:?}",g1_s_x);


        // Compute BLAKE2b(personalization | transcript | g^s | g^{s*x})
        let h: generic_array::GenericArray<u8, U64> = {
            let mut h = Blake2b::default();
            h.input(&[personalization]);
            h.input(digest);
            h.input(g1_s.into_uncompressed().as_ref());
            h.input(g1_s_x.into_uncompressed().as_ref());
            h.result()
        };
        
        println!("h = {:?}",h);

        // Hash into G2 as g^{s'}
        let mut g2_s: E::G2Affine = hash_to_g2::<E>(h.as_ref()).into_affine();
   

        let uncompressed_2 = [43, 154, 57, 34, 181, 95, 81, 170, 238, 145, 43, 68, 61, 92, 15, 193, 202, 49, 133, 78, 159, 84, 234, 136, 201, 182, 132, 85, 119, 226, 76, 87, 31, 7, 177, 203, 240, 199, 239, 68, 5, 242, 91, 200, 144, 45, 123, 156, 50, 250, 140, 46, 129, 87, 166, 203, 120, 100, 236, 62, 239, 247, 239, 44, 26, 154, 58, 204, 121, 186, 101, 8, 176, 246, 79, 226, 121, 176, 57, 225, 45, 141, 244, 237, 251, 27, 146, 177, 45, 179, 188, 29, 114, 252, 157, 58, 24, 104, 223, 229, 150, 6, 128, 1, 179, 162, 80, 204, 174, 36, 149, 106, 185, 168, 221, 9, 166, 26, 27, 155, 170, 118, 189, 170, 29, 241, 210, 41];
        let mut repr_2 = <<E as bellman_ce::pairing::Engine>::G2Affine as bellman_ce::pairing::CurveAffine>::Uncompressed::empty();
        repr_2.as_mut().write(&uncompressed_2);
        g2_s = repr_2.into_affine().unwrap();
        println!("g2_s = {:?}",g2_s);
        

        // Compute g^{s'*x}
        let g2_s_x = g2_s.mul(x).into_affine();
        println!("g2_s_x = {:?}",g2_s_x);

        ((g1_s, g1_s_x), g2_s_x)
    };

    // these "public keys" are requried for for next participants to check that points are in fact
    // sequential powers
    let pk_tau = op(tau, 0);
    let pk_alpha = op(alpha, 1);
    let pk_beta = op(beta, 2);

    let p: (PublicKey<E>, PrivateKey<E>) = {(
        PublicKey {
            tau_g1: pk_tau.0,
            alpha_g1: pk_alpha.0,
            beta_g1: pk_beta.0,
            tau_g2: pk_tau.1,
            alpha_g2: pk_alpha.1,
            beta_g2: pk_beta.1,
        },
        PrivateKey {
            tau: tau,
            alpha: alpha,
            beta: beta
        }
    )};

        
    println!("PublicKey.tau_g1 = {:?}",p.0.tau_g1);
    println!("PublicKey.alpha_g1 = {:?}",p.0.alpha_g1);
    println!("PublicKey.beta_g1 = {:?}",p.0.beta_g1);
    println!("PublicKey.tau_g2 = {:?}",p.0.tau_g2);
    println!("PublicKey.alpha_g2 = {:?}",p.0.alpha_g2);
    println!("PublicKey.beta_g2 = {:?}",p.0.beta_g2);
    println!("PrivateKey.tau = {:?}",p.1.tau);
    println!("PrivateKey.alpha = {:?}",p.1.alpha);
    println!("PrivateKey.beta = {:?}",p.1.beta);


    (
        PublicKey {
            tau_g1: pk_tau.0,
            alpha_g1: pk_alpha.0,
            beta_g1: pk_beta.0,
            tau_g2: pk_tau.1,
            alpha_g2: pk_alpha.1,
            beta_g2: pk_beta.1,
        },
        PrivateKey {
            tau: tau,
            alpha: alpha,
            beta: beta
        }
    )
}
*/
impl<E: Engine> PublicKey<E> {
    /// Serialize the public key. Points are always in uncompressed form.
    pub fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()>
    {
        write_point(writer, &self.tau_g1.0, UseCompression::No)?;
        write_point(writer, &self.tau_g1.1, UseCompression::No)?;

        write_point(writer, &self.alpha_g1.0, UseCompression::No)?;
        write_point(writer, &self.alpha_g1.1, UseCompression::No)?;

        write_point(writer, &self.beta_g1.0, UseCompression::No)?;
        write_point(writer, &self.beta_g1.1, UseCompression::No)?;

        write_point(writer, &self.tau_g2, UseCompression::No)?;
        write_point(writer, &self.alpha_g2, UseCompression::No)?;
        write_point(writer, &self.beta_g2, UseCompression::No)?;

        Ok(())
    }

    /// Deserialize the public key. Points are always in uncompressed form, and
    /// always checked, since there aren't very many of them. Does not allow any
    /// points at infinity.
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<PublicKey<E>, DeserializationError>
    {
        fn read_uncompressed<EE: Engine, C: CurveAffine<Engine = EE, Scalar = EE::Fr>, R: Read>(reader: &mut R) -> Result<C, DeserializationError> {
            let mut repr = C::Uncompressed::empty();
            reader.read_exact(repr.as_mut())?;
            let v = repr.into_affine()?;

            if v.is_zero() {
                Err(DeserializationError::PointAtInfinity)
            } else {
                Ok(v)
            }
        }

        let tau_g1_s = read_uncompressed::<E, _, _>(reader)?;
        let tau_g1_s_tau = read_uncompressed::<E, _, _>(reader)?;

        let alpha_g1_s = read_uncompressed::<E, _, _>(reader)?;
        let alpha_g1_s_alpha = read_uncompressed::<E, _, _>(reader)?;

        let beta_g1_s = read_uncompressed::<E, _, _>(reader)?;
        let beta_g1_s_beta = read_uncompressed::<E, _, _>(reader)?;

        let tau_g2 = read_uncompressed::<E, _, _>(reader)?;
        let alpha_g2 = read_uncompressed::<E, _, _>(reader)?;
        let beta_g2 = read_uncompressed::<E, _, _>(reader)?;

        Ok(PublicKey {
            tau_g1: (tau_g1_s, tau_g1_s_tau),
            alpha_g1: (alpha_g1_s, alpha_g1_s_alpha),
            beta_g1: (beta_g1_s, beta_g1_s_beta),
            tau_g2: tau_g2,
            alpha_g2: alpha_g2,
            beta_g2: beta_g2
        })
    }
}

impl<E: Engine> PublicKey<E> {

    /// This function is intended to write the key to the memory map and calculates
    /// a position for writing into the file itself based on information whether
    /// contribution was output in compressed on uncompressed form
    pub fn write<P>(
        &self,
        output_map: &mut MmapMut,
        accumulator_was_compressed: UseCompression
    )
    -> io::Result<()>
        where P: PowersOfTauParameters
    {
        let mut position = match accumulator_was_compressed {
            UseCompression::Yes => {
                P::CONTRIBUTION_BYTE_SIZE - P::PUBLIC_KEY_SIZE
            },
            UseCompression::No => {
                P::ACCUMULATOR_BYTE_SIZE
            }
        };

        (&mut output_map[position..]).write(&self.tau_g1.0.into_uncompressed().as_ref())?;
        position += P::G1_UNCOMPRESSED_BYTE_SIZE;

        (&mut output_map[position..]).write(&self.tau_g1.1.into_uncompressed().as_ref())?;
        position += P::G1_UNCOMPRESSED_BYTE_SIZE;

        (&mut output_map[position..]).write(&self.alpha_g1.0.into_uncompressed().as_ref())?;
        position += P::G1_UNCOMPRESSED_BYTE_SIZE;

        (&mut output_map[position..]).write(&self.alpha_g1.1.into_uncompressed().as_ref())?;
        position += P::G1_UNCOMPRESSED_BYTE_SIZE;

        (&mut output_map[position..]).write(&self.beta_g1.0.into_uncompressed().as_ref())?;
        position += P::G1_UNCOMPRESSED_BYTE_SIZE;

        (&mut output_map[position..]).write(&self.beta_g1.1.into_uncompressed().as_ref())?;
        position += P::G1_UNCOMPRESSED_BYTE_SIZE;

        (&mut output_map[position..]).write(&self.tau_g2.into_uncompressed().as_ref())?;
        position += P::G2_UNCOMPRESSED_BYTE_SIZE;

        (&mut output_map[position..]).write(&self.alpha_g2.into_uncompressed().as_ref())?;
        position += P::G2_UNCOMPRESSED_BYTE_SIZE;

        (&mut output_map[position..]).write(&self.beta_g2.into_uncompressed().as_ref())?;

        output_map.flush()?;

        Ok(())
    }

    /// Deserialize the public key. Points are always in uncompressed form, and
    /// always checked, since there aren't very many of them. Does not allow any
    /// points at infinity.
    pub fn read<P>(
        input_map: &Mmap,
        accumulator_was_compressed: UseCompression
    ) -> Result<Self, DeserializationError>
        where P: PowersOfTauParameters
    {
        fn read_uncompressed<EE: Engine, C: CurveAffine<Engine = EE, Scalar = EE::Fr>>(input_map: &Mmap, position: usize) -> Result<C, DeserializationError> {
            let mut repr = C::Uncompressed::empty();
            let element_size = C::Uncompressed::size();
            let memory_slice = input_map.get(position..position+element_size).expect("must read point data from file");
            memory_slice.clone().read_exact(repr.as_mut())?;
            let v = repr.into_affine()?;

            if v.is_zero() {
                Err(DeserializationError::PointAtInfinity)
            } else {
                Ok(v)
            }
        }

        let mut position = match accumulator_was_compressed {
            UseCompression::Yes => {
                P::CONTRIBUTION_BYTE_SIZE - P::PUBLIC_KEY_SIZE
            },
            UseCompression::No => {
                P::ACCUMULATOR_BYTE_SIZE
            }
        };

        let tau_g1_s = read_uncompressed::<E, _>(input_map, position)?;
        position += P::G1_UNCOMPRESSED_BYTE_SIZE;

        let tau_g1_s_tau = read_uncompressed::<E, _>(input_map, position)?;
        position += P::G1_UNCOMPRESSED_BYTE_SIZE;

        let alpha_g1_s = read_uncompressed::<E, _>(input_map, position)?;
        position += P::G1_UNCOMPRESSED_BYTE_SIZE;

        let alpha_g1_s_alpha = read_uncompressed::<E, _>(input_map, position)?;
        position += P::G1_UNCOMPRESSED_BYTE_SIZE;

        let beta_g1_s = read_uncompressed::<E, _>(input_map, position)?;
        position += P::G1_UNCOMPRESSED_BYTE_SIZE;

        let beta_g1_s_beta = read_uncompressed::<E, _>(input_map, position)?;
        position += P::G1_UNCOMPRESSED_BYTE_SIZE;

        let tau_g2 = read_uncompressed::<E, _>(input_map, position)?;
        position += P::G2_UNCOMPRESSED_BYTE_SIZE;

        let alpha_g2 = read_uncompressed::<E, _>(input_map, position)?;
        position += P::G2_UNCOMPRESSED_BYTE_SIZE;

        let beta_g2 = read_uncompressed::<E, _>(input_map, position)?;

        Ok(PublicKey {
            tau_g1: (tau_g1_s, tau_g1_s_tau),
            alpha_g1: (alpha_g1_s, alpha_g1_s_alpha),
            beta_g1: (beta_g1_s, beta_g1_s_beta),
            tau_g2: tau_g2,
            alpha_g2: alpha_g2,
            beta_g2: beta_g2
        })
    }
}
