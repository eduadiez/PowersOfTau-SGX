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
use crate::parameters::UseCompression;
use pairing::CurveAffine;
use parameters::*;
use pairing::EncodedPoint;
use pairing::Engine;


/// Contains terms of the form (s<sub>1</sub>, s<sub>1</sub><sup>x</sup>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub><sup>x</sup>)
/// for all x in τ, α and β, and some s chosen randomly by its creator. The function H "hashes into" the group G2. No points in the public key may be the identity.
///
/// The elements in G2 are used to verify transformations of the accumulator. By its nature, the public key proves
/// knowledge of τ, α and β.
///
/// It is necessary to verify `same_ratio`((s<sub>1</sub>, s<sub>1</sub><sup>x</sup>), (H(s<sub>1</sub><sup>x</sup>)<sub>2</sub>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub><sup>x</sup>)).
#[derive(Eq)]
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

impl<E: Engine> Clone for PublicKey<E> {
      fn clone(&self) -> PublicKey<E> {
        PublicKey {
            tau_g1: (self.tau_g1.0.clone(), self.tau_g1.1.clone()),
            alpha_g1: (self.alpha_g1.0.clone(), self.alpha_g1.1.clone()),
            beta_g1: (self.beta_g1.0.clone(), self.beta_g1.1.clone()),
            tau_g2: self.tau_g2.clone(),
            alpha_g2: self.alpha_g2.clone(),
            beta_g2: self.beta_g2.clone()
        }
    }
}

impl<E: Engine> Copy for PublicKey<E> {}


/// Contains the secrets τ, α and β that the participant of the ceremony must destroy.
pub struct PrivateKey<E: Engine> {
    pub tau: E::Fr,
    pub alpha: E::Fr,
    pub beta: E::Fr
}

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

pub fn write_point<W, G>(
    writer: &mut W,
    p: &G,
    compression: UseCompression
) -> io::Result<()>
    where W: Write,
          G: CurveAffine
{
    match compression {
        UseCompression::Yes => writer.write_all(p.into_compressed().as_ref()),
        UseCompression::No => writer.write_all(p.into_uncompressed().as_ref()),
    }
}
