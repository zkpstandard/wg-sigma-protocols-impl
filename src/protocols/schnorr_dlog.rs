use ark_ec::ProjectiveCurve;
use ark_ff::{Field, PrimeField};
use ark_std::UniformRand;
use rand::Rng;

use crate::{Challenge, SigmaError, SigmaProtocol, CHALLENGE_LENGTH};

/// Schnorr proof of knowledge of the discrete logarithm.
pub struct SchnorrDLOG<G: ProjectiveCurve> {
    instance: SchnorrInstance<G>,
}

/// The instance for the DLOG proof. It is composed of two group elements:
/// the prover claims to know the discrete log between the `base` point and the `claim` point
#[derive(Debug, Clone, Copy)]
pub struct SchnorrInstance<G: ProjectiveCurve> {
    base: G,
    claim: G,
}

impl<G: ProjectiveCurve> SchnorrInstance<G> {
    /// Create a new DLOG instance from the provided group elements
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

    // TODO: Fix this according to the spec. Need to decide whether hashing is decided at the interactive stage or later at NIZK
    // Same hash function as for challenge? Domain separation?
    fn label(&self) -> [u8; CHALLENGE_LENGTH] {
        [0; CHALLENGE_LENGTH]
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
        // TODO change this with the seeding from standard. Same hash function as for challenge? Domain separation?
        let random_value = G::ScalarField::rand(rng);

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
    ) -> Result<Self::Response, SigmaError> {
        let challenge_scalar = G::ScalarField::from_random_bytes(challenge)
            .ok_or(SigmaError::ChallengeConversionFailure)?;

        Ok(prover_state.random_value - challenge_scalar * prover_state.witness)
    }

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Challenge,
        response: &Self::Response,
    ) -> Result<(), crate::SigmaError> {
        let challenge_scalar = G::ScalarField::from_random_bytes(challenge)
            .ok_or(SigmaError::ChallengeConversionFailure)?;

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
    ) -> Result<Self::Commitment, SigmaError> {
        let challenge_scalar = G::ScalarField::from_random_bytes(challenge)
            .ok_or(SigmaError::ChallengeConversionFailure)?;

        Ok(self.instance.base.mul(response.into_repr())
            + self.instance.claim.mul(challenge_scalar.into_repr()))
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::ProjectiveCurve;
    use ark_ff::{PrimeField, UniformRand};
    use blake2::Digest;
    use rand::{thread_rng, Rng};

    use crate::{
        nizk_proofs::tests::{run_nizk_batched, run_nizk_short},
        SigmaError,
    };

    use super::{SchnorrDLOG, SchnorrInstance};

    type G = ark_bls12_377::G1Projective;
    type F = ark_bls12_377::Fr;

    fn schnorr_setup<R: Rng>(rng: &mut R) -> (SchnorrInstance<G>, F, F) {
        // Produce witness and instance
        let generator = G::prime_subgroup_generator();
        let witness = F::rand(rng);
        let claim = generator.mul(witness.into_repr());
        let instance = SchnorrInstance::new(generator, claim);
        let wrong_witness = F::rand(rng);

        (instance, witness, wrong_witness)
    }

    #[test]
    fn test_schnorr_accept_valid_batchable() {
        let rng = &mut thread_rng();
        let hasher = blake2::Blake2s::new();
        let mut challenge_failures = 0;

        let (instance, witness, _) = schnorr_setup(rng);

        let mut test_result =
            run_nizk_batched::<_, SchnorrDLOG<_>, _>(&instance, &witness, hasher.clone(), rng);

        while test_result == Err(SigmaError::ChallengeConversionFailure) {
            challenge_failures += 1;
            test_result =
                run_nizk_batched::<_, SchnorrDLOG<_>, _>(&instance, &witness, hasher.clone(), rng)
        }

        println!("Parsing the challenge failed {} times", challenge_failures);
        assert!(test_result.is_ok())
    }

    #[test]
    fn test_schnorr_reject_wrong_batchable() {
        let rng = &mut thread_rng();
        let hasher = blake2::Blake2s::new();
        let mut challenge_failures = 0;

        let (instance, _, wrong_witness) = schnorr_setup(rng);

        let mut test_result = run_nizk_batched::<_, SchnorrDLOG<_>, _>(
            &instance,
            &wrong_witness,
            hasher.clone(),
            rng,
        );

        while test_result == Err(SigmaError::ChallengeConversionFailure) {
            challenge_failures += 1;
            test_result = run_nizk_batched::<_, SchnorrDLOG<_>, _>(
                &instance,
                &wrong_witness,
                hasher.clone(),
                rng,
            )
        }

        println!("Parsing the challenge failed {} times", challenge_failures);

        assert_eq!(test_result, Err(SigmaError::VerificationFailed))
    }

    #[test]
    fn test_schnorr_accept_valid_short() {
        let rng = &mut thread_rng();
        let hasher = blake2::Blake2s::new();
        let mut challenge_failures = 0;

        let (instance, witness, _) = schnorr_setup(rng);

        let mut test_result =
            run_nizk_short::<_, SchnorrDLOG<_>, _>(&instance, &witness, hasher.clone(), rng);

        while test_result == Err(SigmaError::ChallengeConversionFailure) {
            challenge_failures += 1;
            test_result =
                run_nizk_short::<_, SchnorrDLOG<_>, _>(&instance, &witness, hasher.clone(), rng)
        }

        println!("Parsing the challenge failed {} times", challenge_failures);
        assert!(test_result.is_ok())
    }

    #[test]
    fn test_schnorr_reject_wrong_short() {
        let rng = &mut thread_rng();
        let hasher = blake2::Blake2s::new();
        let mut challenge_failures = 0;

        let (instance, _, wrong_witness) = schnorr_setup(rng);

        let mut test_result =
            run_nizk_short::<_, SchnorrDLOG<_>, _>(&instance, &wrong_witness, hasher.clone(), rng);

        while test_result == Err(SigmaError::ChallengeConversionFailure) {
            challenge_failures += 1;
            test_result = run_nizk_short::<_, SchnorrDLOG<_>, _>(
                &instance,
                &wrong_witness,
                hasher.clone(),
                rng,
            )
        }

        println!("Parsing the challenge failed {} times", challenge_failures);

        assert_eq!(test_result, Err(SigmaError::VerificationFailed))
    }
}
