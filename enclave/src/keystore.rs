use keypair::{PublicKey,PrivateKey};
use pairing::Engine;
use pairing::ff::Field;
use pairing::CurveAffine;

pub struct Keystore<E: Engine>{
    pub public_key: PublicKey<E>,
    pub private_key: PrivateKey<E>
}

impl<E: Engine> Keystore<E> {
    
    pub fn new() -> Keystore<E> {
        Keystore {
            public_key: PublicKey::<E>::default(),
            private_key: PrivateKey::<E>::default()
        }
    }
}

impl<E: Engine>Default for PrivateKey<E> {
    fn default() -> PrivateKey<E>{
         PrivateKey {
            tau: E::Fr::zero(),
            alpha: E::Fr::zero(),
            beta: E::Fr::zero()
        }
    }
}

impl<E: Engine>Default for PublicKey<E> {
    fn default() -> PublicKey<E> {
        PublicKey {
            tau_g1: (E::G1Affine::zero(),E::G1Affine::zero()),
            alpha_g1: (E::G1Affine::zero(),E::G1Affine::zero()),
            beta_g1: (E::G1Affine::zero(),E::G1Affine::zero()),
            tau_g2: E::G2Affine::zero(),
            alpha_g2: E::G2Affine::zero(),
            beta_g2: E::G2Affine::zero(),
        }
    }
}
