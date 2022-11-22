use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{Challenge, SigmaError, LABEL_LENGTH};

#[allow(missing_docs)]
/// Interface for a Sigma protocol. **WARNING**: As explained in the standard, Sigma protocols are *not* to be used interactively
pub trait SigmaProtocol {
    type Instance;
    type Witness;
    type Commitment: CanonicalSerialize + CanonicalDeserialize;
    type ProverState;
    type Response: CanonicalSerialize + CanonicalDeserialize;

    fn label(&self) -> [u8; LABEL_LENGTH];

    fn new(instance: &Self::Instance) -> Self;

    fn prover_commit(&self, witness: &Self::Witness) -> (Self::Commitment, Self::ProverState);

    fn prover_response(
        &self,
        prover_state: &Self::ProverState,
        challenge: &Challenge,
    ) -> Self::Response;

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Challenge,
        response: &Self::Response,
    ) -> Result<(), SigmaError>;

    fn simulate_response(&self) -> Self::Response;

    fn simulate_commitment(
        &self,
        challenge: &Challenge,
        response: &Self::Response,
    ) -> Self::Commitment;
}
