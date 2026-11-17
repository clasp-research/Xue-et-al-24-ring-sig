// Benchmarks online signing (trace generation + proving) and verification of the ring signature
// for large rings. The ring is simulated: only the signer's Merkle path is generated, once per
// ring size, outside the timed loop.
//
// Configuration via environment variables:
//   SIG_DEPTHS        comma-separated log2 ring sizes, i.e. Merkle tree depths; e.g. "20,32"
//                     benchmarks rings of 2^20 and 2^32 members (each 1..=63, default
//                     "5,10,16,20,25,30,32")
//   SIG_QUERIES       number of queries (default 33)
//   SIG_BLOWUP        blowup factor (default 16)
//   SIG_FOLDING       FRI folding factor (default 4)
//   SIG_GRINDING      grinding factor (default 0)
//   SIG_SIZE_SAMPLES  number of proofs generated per ring size to measure proof size
//                     (min/mean/max); not timed (default 100)
//   SIG_SAMPLES       criterion sample size (default 10)
//   SIG_MEASURE_SECS  criterion measurement time per benchmark in seconds (default 20)

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use examples::{sigrescue::RingSigExample, Blake3_256, Example};
use std::{
    env, fs,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};
use winterfell::{FieldExtension, ProofOptions};

fn env_or<T: FromStr>(name: &str, default: T) -> T {
    env::var(name)
        .ok()
        .map(|v| {
            v.parse()
                .unwrap_or_else(|_| panic!("invalid value for {name}: {v}"))
        })
        .unwrap_or(default)
}

fn depths() -> Vec<usize> {
    env::var("SIG_DEPTHS")
        .unwrap_or_else(|_| "5,10,16,20,25,30,32".to_string())
        .split(',')
        .map(|d| d.trim().parse().expect("invalid SIG_DEPTHS"))
        .collect()
}

fn proof_options() -> ProofOptions {
    ProofOptions::new(
        env_or("SIG_QUERIES", 33),
        env_or("SIG_BLOWUP", 16),
        env_or("SIG_GRINDING", 0),
        FieldExtension::Quadratic,
        env_or("SIG_FOLDING", 4),
        31,
    )
}

fn sigrescue(c: &mut Criterion) {
    let options = proof_options();
    let examples: Vec<(usize, RingSigExample<Blake3_256>)> = depths()
        .into_iter()
        .map(|d| (d, RingSigExample::new_simulated(d, options.clone())))
        .collect();

    // proof sizes vary between proofs (the proofs are randomized), so generate several proofs per
    // ring size and report min/mean/max, to stderr and to a CSV next to criterion's results
    let size_samples: usize = env_or("SIG_SIZE_SAMPLES", 100);
    assert!(size_samples > 0, "SIG_SIZE_SAMPLES must be at least 1");
    let mut csv = String::from(
        "log_ring_size,num_proofs,proof_bytes_min,proof_bytes_mean,proof_bytes_max,\
         security_bits,queries,blowup,folding,grinding\n",
    );
    for (depth, example) in examples.iter() {
        let mut sizes = Vec::with_capacity(size_samples);
        let mut security = u32::MAX;
        for _ in 0..size_samples {
            let proof = example.prove();
            sizes.push(proof.to_bytes().len());
            security = security.min(proof.security_level::<Blake3_256>(true));
        }
        let min = *sizes.iter().min().unwrap();
        let max = *sizes.iter().max().unwrap();
        let mean = sizes.iter().sum::<usize>() as f64 / sizes.len() as f64;
        eprintln!(
            "ring size 2^{depth}: proof size over {size_samples} proofs: \
             min {min}, mean {mean:.1}, max {max} bytes; conjectured security {security} bits"
        );
        csv.push_str(&format!(
            "{depth},{size_samples},{min},{mean:.1},{max},{security},{},{},{},{}\n",
            options.num_queries(),
            options.blowup_factor(),
            options.to_fri_options().folding_factor(),
            options.grinding_factor(),
        ));
    }
    let criterion_dir = env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"))
        .join("criterion");
    fs::create_dir_all(&criterion_dir).expect("failed to create criterion output directory");
    let csv_path = criterion_dir
        .canonicalize()
        .unwrap_or(criterion_dir)
        .join("sigrescue_proof_sizes.csv");
    fs::write(&csv_path, csv).expect("failed to write proof sizes");
    eprintln!("proof sizes written to {}", csv_path.display());

    let samples = env_or("SIG_SAMPLES", 10);
    let measure = Duration::from_secs(env_or("SIG_MEASURE_SECS", 20));

    let mut group = c.benchmark_group("sigrescue_sign");
    group.sample_size(samples);
    group.measurement_time(measure);
    for (depth, example) in examples.iter() {
        group.bench_function(BenchmarkId::new("log_ring_size", depth), |bench| {
            bench.iter(|| example.prove());
        });
    }
    group.finish();

    let mut group = c.benchmark_group("sigrescue_verify");
    group.sample_size(samples);
    group.measurement_time(measure);
    for (depth, example) in examples.iter() {
        let proof = example.prove();
        group.bench_function(BenchmarkId::new("log_ring_size", depth), |bench| {
            bench.iter(|| example.verify(proof.clone()).unwrap());
        });
    }
    group.finish();
}

criterion_group!(sigrescue_group, sigrescue);
criterion_main!(sigrescue_group);
