/// All supported hash function
pub enum HashFunction {
    Blake2b,
    SHA3_256,
}

impl HashFunction {
    /// Returns the block size in bytes.
    pub fn block_len(&self) -> usize {
        match self {
            HashFunction::Blake2b => 128,
            HashFunction::SHA3_256 => 136,
        }
    }

    /// Returns the expected hash size in bytes.
    pub fn digest_len(&self) -> usize {
        match self {
            HashFunction::Blake2b => 64,
            HashFunction::SHA3_256 => 32,
        }
    }
}
