use ark_ec::ProjectiveCurve;
use ark_ff::{Field, PrimeField};
use ark_std::UniformRand;
use rand::Rng;

use crate::{Challenge, SigmaError, SigmaProtocol, LABEL_LENGTH};

/// Schnorr proof of knowledge of the discrete logarithm.
pub struct SchnorrDLOG<G: ProjectiveCurve> {
    pub instance: SchnorrInstance<G>,
}

#[derive(Debug, Clone, Copy)]
pub struct SchnorrInstance<G: ProjectiveCurve> {
    base: G,
    claim: G,
}

impl<G: ProjectiveCurve> SchnorrInstance<G> {
    pub fn new(base: G, claim: G) -> Self {
        Self { base, claim }
    }
}

pub struct ProverState<F: Field> {
    witness: F,
    random_value: F,
}

impl<G: ProjectiveCurve> SigmaProtocol for SchnorrDLOG<G> {
    type Instance = SchnorrInstance<G>;
    type Commitment = G;
    type ProverState = ProverState<G::ScalarField>;
    type Witness = G::ScalarField;
    type Response = G::ScalarField;

    // TODO: Fix this according to the spec
    fn label(&self) -> [u8; LABEL_LENGTH] {
        [0; LABEL_LENGTH]
    }

    fn new(instance: &SchnorrInstance<G>) -> Self {
        Self {
            instance: *instance,
        }
    }

    fn prover_commit<R: Rng>(
        &self,
        witness: &Self::Witness,
        rng: &mut R,
    ) -> (Self::Commitment, Self::ProverState) {
        let random_value = G::ScalarField::rand(rng); // TODO change this with the seeding from standard
        let commitment = self.instance.base.mul(random_value.into_repr());

        let state = ProverState {
            witness: *witness,
            random_value,
        };

        (commitment, state)
    }

    fn prover_response(
        &self,
        prover_state: &Self::ProverState,
        challenge: &Challenge,
    ) -> Self::Response {
        let challenge_scalar =
            G::ScalarField::from_random_bytes(challenge).expect("Could not compute a challenge"); // TODO: error handling

        prover_state.random_value - challenge_scalar * prover_state.witness
    }

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Challenge,
        response: &Self::Response,
    ) -> Result<(), crate::SigmaError> {
        let challenge_scalar =
            G::ScalarField::from_random_bytes(challenge).expect("Could not compute a challenge"); // TODO: error handling

        if &(self.instance.base.mul(response.into_repr())
            + self.instance.claim.mul(challenge_scalar.into_repr()))
            == commitment
        {
            return Ok(());
        } else {
            return Err(SigmaError::VerificationFailed);
        }
    }

    fn simulate_response<R: Rng>(&self, rng: &mut R) -> Self::Response {
        G::ScalarField::rand(rng)
    }

    fn simulate_commitment(
        &self,
        challenge: &Challenge,
        response: &Self::Response,
    ) -> Self::Commitment {
        let challenge_scalar =
            G::ScalarField::from_random_bytes(challenge).expect("Could not compute a challenge"); // TODO: error handling

        

        self.instance.base.mul(response.into_repr()) + self.instance.claim.mul(challenge_scalar.into_repr())
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::ProjectiveCurve;
    use ark_ff::{PrimeField, UniformRand};
    use blake2::Digest;
    use rand::thread_rng;

    use crate::{SigmaProtocol, NIZK};

    use super::{SchnorrDLOG, SchnorrInstance};

    type G = ark_bls12_377::G1Projective;
    type F = ark_bls12_377::Fr;

    #[test]
    fn test_schnorr_nizk_batchable() {
        let rng = &mut thread_rng();

        let hasher = blake2::Blake2s::new();

        let generator = G::prime_subgroup_generator();

        let witness = F::rand(rng);
        let claim = generator.mul(witness.into_repr());
        let instance = SchnorrInstance::new(generator, claim);

        let interactive_protocol = SchnorrDLOG::new(&instance);

        let mut nizk = NIZK::new(interactive_protocol, hasher, &[]);

        let batchable_proof = nizk.batchable_proof(&witness, None, rng);

        assert!(nizk
            .batchable_verify(&batchable_proof, None)
            .is_ok());

        let wrong_witness = F::rand(rng);
        let bad_proof = nizk.batchable_proof(&wrong_witness, None, rng);

        assert!(nizk.batchable_verify(&bad_proof, None).is_err())
    }

    #[test]
    fn test_schnorr_nizk_short() {
        let rng = &mut thread_rng();

        let hasher = blake2::Blake2s::new();

        let generator = G::prime_subgroup_generator();

        let witness = F::rand(rng);
        let claim = generator.mul(witness.into_repr());
        let instance = SchnorrInstance::new(generator, claim);

        let interactive_protocol = SchnorrDLOG::new(&instance);

        let mut nizk = NIZK::new(interactive_protocol, hasher, &[]);

        let short_proof = nizk.short_proof(&witness, None, rng);

        assert!(nizk
            .short_verify(&short_proof, None)
            .is_ok())
    }
}
