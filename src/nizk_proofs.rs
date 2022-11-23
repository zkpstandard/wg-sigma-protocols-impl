use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use digest::Digest;
use rand::Rng;

use crate::{Challenge, SigmaError, SigmaProtocol, CHALLENGE_LENGTH, DOMSEP, LABEL_LENGTH};

/// A non-interactive zk (NIZK) proof derived from applying the Fiat-Shamir transformation to a Sigma protocol
pub struct NIZK<S: SigmaProtocol, D: Digest> {
    interactive_protocol: S,
    hasher: D,
    hd: [u8; LABEL_LENGTH],
    ha: [u8; LABEL_LENGTH],
    hctx: [u8; LABEL_LENGTH],
}

/// A batchable proof. The canonical form of proofs.
#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct BatchableProof<S: SigmaProtocol> {
    commitment: S::Commitment,
    response: S::Response,
}

/// A shorter proof. The commitment can be deterministically computed from the challenge and the response.
#[derive(Debug)]
pub struct ShortProof<S: SigmaProtocol> {
    challenge: Challenge,
    response: S::Response,
}

impl<S: SigmaProtocol, D: Digest> NIZK<S, D> {
    /// initialise the NIZK for a given Sigma protocol.
    pub fn new(protocol: S, mut hasher: D, ctx: &[u8]) -> Self {
        hasher.update(DOMSEP);
        let hd_long = hasher.finalize_reset();
        let mut hd = [0u8; LABEL_LENGTH];
        hd.copy_from_slice(&hd_long[..LABEL_LENGTH]); // TODO use last 32 bytes instead

        let ha = protocol.label();

        hasher.update(ctx);
        let hctx_long = hasher.finalize_reset();
        let mut hctx = [0u8; LABEL_LENGTH];
        hctx.copy_from_slice(&hctx_long[..LABEL_LENGTH]);

        Self {
            interactive_protocol: protocol,
            hasher,
            hd,
            ha,
            hctx,
        }
    }

    fn challenge(&mut self, message: Option<&[u8]>, commitment: &S::Commitment) -> Challenge {
        let mut challenge: Challenge = [0; CHALLENGE_LENGTH];

        let mut commitment_bytes = Vec::new();
        commitment.serialize(&mut commitment_bytes).unwrap();

        let hashed = match message {
            Some(msg) => {
                self.hasher.update(msg);
                let hm_long = self.hasher.finalize_reset();
                let hm = &hm_long[..LABEL_LENGTH];

                self.hasher.update(&self.hd);
                self.hasher.update(&self.hctx);
                self.hasher.update(&self.ha);
                self.hasher.update(hm);
                self.hasher.update(&commitment_bytes);
                self.hasher.finalize_reset()
            }
            None => {
                self.hasher.update(&self.hd);
                self.hasher.update(&self.hctx);
                self.hasher.update(&self.ha);
                self.hasher.update(&commitment_bytes);
                self.hasher.finalize_reset()
            }
        };

        challenge.copy_from_slice(&hashed[..CHALLENGE_LENGTH]);

        challenge
    }

    /// Produce a batchable proof for the instance using the provided witness
    pub fn batchable_proof<R: Rng>(
        &mut self,
        witness: &S::Witness,
        message: Option<&[u8]>,
        rng: &mut R,
    ) -> BatchableProof<S> {
        let (commitment, prover_state) = self.interactive_protocol.prover_commit(witness, rng);
        let challenge = self.challenge(message, &commitment);
        let response = self
            .interactive_protocol
            .prover_response(&prover_state, &challenge);

        BatchableProof {
            commitment,
            response,
        }
    }

    /// Verify a batchable proof
    pub fn batchable_verify(
        &mut self,
        proof: &BatchableProof<S>,
        message: Option<&[u8]>,
    ) -> Result<(), SigmaError> {
        let challenge = self.challenge(message, &proof.commitment);
        self.interactive_protocol
            .verifier(&proof.commitment, &challenge, &proof.response)
    }

    /// Produce a short proof for the instance using the provided witness
    pub fn short_proof<R: Rng>(
        &mut self,
        witness: &S::Witness,
        message: Option<&[u8]>,
        rng: &mut R,
    ) -> ShortProof<S> {
        let (commitment, prover_state) = self.interactive_protocol.prover_commit(witness, rng);
        let challenge = self.challenge(message, &commitment);
        let response = self
            .interactive_protocol
            .prover_response(&prover_state, &challenge);

        ShortProof {
            challenge,
            response,
        }
    }

    /// Verify a short proof
    pub fn short_verify(
        &mut self,
        proof: &ShortProof<S>,
        message: Option<&[u8]>,
    ) -> Result<(), SigmaError> {
        let commitment = self
            .interactive_protocol
            .simulate_commitment(&proof.challenge, &proof.response);
        let challenge = self.challenge(message, &commitment);

        if challenge == proof.challenge {
            return Ok(());
        } else {
            return Err(SigmaError::VerificationFailed);
        }
    }
}
