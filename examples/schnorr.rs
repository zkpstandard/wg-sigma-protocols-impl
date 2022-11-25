//! Example of running a Schnorr NIZK. WARNING: example may fail if a field element cannot be
//! constructed from the challenge bytes. In which case please re-run the example

use ark_ec::ProjectiveCurve;
use ark_ff::{PrimeField, UniformRand};
use rand::{thread_rng, RngCore};
use sigma_protocol_standard::{
    protocols::{SchnorrDLOG, SchnorrInstance},
    NIZK,
};

// Some short-hand notation for our types
type Hash = blake2::Blake2s;
type G = ark_bls12_377::G1Projective;
type F = ark_bls12_377::Fr;

fn main() {
    let mut rng = thread_rng();

    let mut ctx = vec![0u8; 32];
    rng.fill_bytes(&mut ctx);

    // PROVER ----------------------------------------------------------------
    let generator = G::prime_subgroup_generator();
    let witness = F::rand(&mut rng);
    let claim = generator.mul(witness.into_repr());

    let instance = SchnorrInstance::new(generator, claim);

    let mut schnorr: NIZK<SchnorrDLOG<_>, Hash> = NIZK::new(&instance, &ctx);

    let proof = schnorr.batchable_proof(&witness, None, &mut rng).unwrap();

    // VERIFIER ----------------------------------------------------------------
    let mut schnorr: NIZK<SchnorrDLOG<_>, Hash> = NIZK::new(&instance, &ctx);

    match schnorr.batchable_verify(&proof, None) {
        Ok(_) => println!("Proof is valid."),
        Err(_) => println!("Proof is not valid."),
    }
}
