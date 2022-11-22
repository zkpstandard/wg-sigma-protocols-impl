use std::hash::Hasher;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};

use crate::{Challenge, SigmaError, SigmaProtocol, CHALLENGE_LENGTH, DOMSEP, LABEL_LENGTH};

/// A non-interactive zk (NIZK) proof derived from applying the Fiat-Shamir transformation to a Sigma protocol
pub struct NIZK<S: SigmaProtocol, H: Hasher> {
    interactive_protocol: S,
    hasher: H,
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

impl<S: SigmaProtocol, H: Hasher> NIZK<S, H> {
    /// initialise the NIZK for a given Sigma protocol.
    pub fn new(protocol: S, mut hasher: H, ctx: &[u8]) -> Self {
        hasher.write(DOMSEP);
        let hd_long = hasher.finish().to_le_bytes();
        let mut hd = [0u8; LABEL_LENGTH];
        hd.copy_from_slice(&hd_long[hd_long.len() - LABEL_LENGTH..]);

        let ha = protocol.label();

        hasher.write(ctx);
        let hctx_long = hasher.finish().to_le_bytes();
        let mut hctx = [0u8; LABEL_LENGTH];
        hctx.copy_from_slice(&hctx_long[hctx_long.len() - LABEL_LENGTH..]);

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
                self.hasher.write(msg);
                let hm_long = self.hasher.finish().to_be_bytes();
                let hm = &hm_long[hm_long.len() - LABEL_LENGTH..];

                self.hasher.write(&self.hd);
                self.hasher.write(&self.hctx);
                self.hasher.write(&self.ha);
                self.hasher.write(hm);
                self.hasher.write(&commitment_bytes);
                self.hasher.finish().to_le_bytes()
            }
            None => {
                self.hasher.write(&self.hd);
                self.hasher.write(&self.hctx);
                self.hasher.write(&self.ha);
                self.hasher.write(&commitment_bytes);
                self.hasher.finish().to_le_bytes()
            }
        };

        challenge.copy_from_slice(&hashed[hashed.len() - CHALLENGE_LENGTH..]);

        challenge
    }

    /// Produce a batchable proof for the instance using the provided witness
    pub fn batchable_proof(
        &mut self,
        witness: &S::Witness,
        message: Option<&[u8]>,
    ) -> BatchableProof<S> {
        let (commitment, prover_state) = self.interactive_protocol.prover_commit(witness);
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
    pub fn short_proof(&mut self, witness: &S::Witness, message: Option<&[u8]>) -> ShortProof<S> {
        let (commitment, prover_state) = self.interactive_protocol.prover_commit(witness);
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
    pub fn short_verify(&mut self, proof: &ShortProof<S>, message: Option<&[u8]>) -> Result<(), SigmaError> {
        let commitment = self.interactive_protocol.simulate_commitment(&proof.challenge, &proof.response);
        let challenge = self.challenge(message, &commitment);

        if challenge == proof.challenge {
            return Ok(());
        } else {
            return Err(SigmaError::VerificationFailed);
        }
    }
}
