# Efficient Linkable Ring Signatures: New Framework and Post-Quantum Instantiations

This repository contains the implementations of our paper "Efficient Linkable Ring Signatures: New Framework and Post-Quantum Instantiations", which was published at ESORICS 2024.

**WARNING**: This project is for experimental demonstration and efficiency evaluation. The code has not been audited and may contain bugs, vulnerabilities, or other security flaws. This implementation is NOT ready for production use.


## Paper Overview
This paper introduces a new framework for constructing
linkable ring signatures (LRS). Our framework is based purely on signatures of knowledge (SoK) which allows one to issue signatures on behalf
of any NP-statement using the corresponding witness.
To instantiate our framework, we adapt a post-quantum
secure non-interactive argument of knowledge (NIAoK), [ethSTARK](https://eprint.iacr.org/2021/582.pdf), into
an SoK.  

## Implementation Detatils

### Add zero-knowledge to ethSTARK
For the practical implementation, we utilize the [Winterfell](https://github.com/facebook/winterfell) library, which supports the construction of ethSTARK. Note that the current versions of ethSTARK and the winterfell library do not inherently support zero-knowledge properties. To integrate ethSTARK within an SoK framework, we have enhanced it with zero-knowledge capabilities using the similar approach as in [zk-STARK](https://eprint.iacr.org/2018/046.pdf). Detailed methodologies and intuition of security proofs are available in Appendix A of our [paper](https://eprint.iacr.org/2024/553.pdf). 

The zero-knowledge enhancement of ethSTARK is informally outlined as follows:
- Introduce randomness into the execution trace of each register, thereby randomizing the trace polynomials.
- Mask composition polynomial with a random polynomial.
- Mask DEEP composition polynomial with a random polynomial.

### Build SoK from  non-interactive zk-ethSTARK
The non-interaction property is achieved through the use of the Fiat-Shamir transformation, which involves using a hash function $H$ to generate the challenge. In our non-interactive zk-ethSTARK, we extend the input of $H$ to include the message $m$ when generating the challenge, thus turning the resulting scheme into an SoK on the message $m$.

### Construct LRS from SoK
We use SoK to build LRS by demonstrating  the correct
signing process of message $m$.  Also, we crafted the program representation of the execution trace to enhance the efficiency of the signing process. 

## Performance
Our LRS has a signature size of O(polylog(log n)). By comparison,
existing post-quantum ring signatures, regardless of linkability considerations, have signature sizes of O(log n) at best. At 128-bit security, our LRS
has the smallest signature size among all post-quantum LRS when ring size is larger than 32.

Furthermore, leveraging online/offline verification, part of the verification of signatures on the same ring can be shared, resulting in a state-of-the-art amortized verification cost of O(polylog(log n)).

Detailed performance comparison can be found in our full [paper](https://eprint.iacr.org/2024/553.pdf).
###  Influence of Grinding on Proving time 
In the ethSTARK, an optimization technique called grinding is integrated into the Fiat-Shamir Transformation to limit the computational capabilities of a potential cheating prover. Specifically, grinding requires the prover to solve a proof-of-work puzzle as part of the proof generation process.
However, the inclusion of grinding introduces some variability and additional overhead in the proving time. The impact of grinding can, in some instances, exceed the influence of the ring size on the proving time in our instantiation. 

## To run
Parameters:
| Syntax      | Description |
| ----------- | ----------- |
| -q      | Number of queries       |
| -b   | Blowup factor        |
| -f   | Folding factor        |
| -n   | Number of members (exclude signer)        |

For 99-bit security with 64 users:
```
cargo run -- -q 20 -b 16 -f 4 sig-rescue -n 63
```
For 128-bit security with 128 users:
```
cargo run -- -q 32 -b 16 -f 4 sig-rescue -n 127
```


### Benchmarking large rings
Building the full Merkle tree dominates setup for large rings. These benchmarks use 128-bit settings without grinding (33 queries, blowup 16, folding 4, `-g 0`), which gives more stable signing times than the paper's settings above; the paper's example and its defaults are unchanged. `-l <d>` simulates a ring of 2^d keys by generating only the signer's key pair and Merkle path (random siblings hashed up to the root); signing and verification run exactly as with a real tree. `--iters <N>` repeats signing/verification and prints min/median/mean/max:
```
cargo run --release -- -q 33 -b 16 -f 4 -g 0 sig-rescue -l 32 --iters 20
```
For statistics via criterion (setup is done once per ring size, outside the timed loop; proof sizes are printed to stderr):
```
# all default ring sizes (2^5, 2^10, 2^16, 2^20, 2^25, 2^30, 2^32)
cargo bench -p examples --bench sigrescue

# only the ring sizes you choose, here 2^20 and 2^32 (see SIG_DEPTHS below)
SIG_DEPTHS=20,32 cargo bench -p examples --bench sigrescue
```
`SIG_DEPTHS` selects which ring sizes to benchmark: a comma-separated list of log2 ring sizes (Merkle tree depths), so `SIG_DEPTHS=20,32` benchmarks rings of 2^20 and 2^32 members. Each value works like the `-l` flag above and must be between 1 and 63. If unset, it defaults to `5,10,16,20,25,30,32`. Results appear as `sigrescue_sign/log_ring_size/<d>` and `sigrescue_verify/log_ring_size/<d>`.

See `examples/benches/sigrescue.rs` for the other `SIG_*` environment variables.

## References
[Scalable, transparent, and post-quantum secure computational integrity](https://eprint.iacr.org/2018/046.pdf) \
Eli Ben-Sasson, Iddo Bentov, Yinon Horesh, and Michael Riabzev

[ethSTARK Documentation](https://eprint.iacr.org/2021/582.pdf) \
StarkWare

[Efficient Linkable Ring Signatures: New Framework and Post-Quantum Instantiations](https://eprint.iacr.org/2024/553.pdf) \
Yuxi Xue, Xingye Lu, Man Ho Au, and Chengru Zhang