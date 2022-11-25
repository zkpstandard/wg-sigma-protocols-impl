# Reference implementation of the ZKProof standard for $\Sigma$-Protocols

A Rust reference implementation for the ZKProof standard for $\Sigma$-protocols, see the working version of the standard [here](https://github.com/zkpstandard/wg-sigma-protocols/tree/build).

**⚠️ The repository is still work in progress and is not up to standard yet. ⚠️**

## Project Structure
Inside the `src` folder, you will find:
- `lib.rs` contains constants and the crate-wide error type.
- `interactive_proofs.rs` contains the trait (interface) that *all* user-defined $\Sigma$-protocols must satisfy.
- `nizk_proofs.rs` contains the universal compiler for $\Sigma$-protocols to NIZK proofs (non-interactive zero knowledge proofs) and some test templates/helper functions.
- `hash_registry` is work in progress. Will contain the list of allowed hash functions and enforce that only those are used.
- `protocols/` contains concrete instantiations of $\Sigma$-protocols.

## Examples
See `examples/` or run: 

```
cargo run --example [example name]
```

WARNING: under the current construction examples may panic. If so please run them again. The reason this happens is because the standard defines a *challenge* to be a vector of 32 bytes but there is no agreed method for converting these bytes to the required type (usually one or many field elements).
