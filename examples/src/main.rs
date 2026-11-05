// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use log::debug;
use std::io::Write;
use std::time::{Duration, Instant};
use structopt::StructOpt;
//use winterfell::StarkProof;
use examples::rescue;
#[cfg(feature = "std")]
use examples::sigrescue;
use examples::{fibonacci, ExampleOptions, ExampleType};
// EXAMPLE RUNNER
// ================================================================================================

fn main() {
    // configure logging
    env_logger::Builder::new()
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .filter_level(log::LevelFilter::Debug)
        .init();

    // read command-line args
    let options = ExampleOptions::from_args();

    debug!("============================================================");

    let iters = match options.example {
        #[cfg(feature = "std")]
        ExampleType::SigRescue { iters, .. } => iters.max(1),
        _ => 1,
    };

    // instantiate and prepare the example
    let example = match options.example {
        ExampleType::Fib { sequence_length } => {
            fibonacci::fib2::get_example(&options, sequence_length)
        }
        ExampleType::Mulfib8 { sequence_length } => {
            fibonacci::mulfib8::get_example(&options, sequence_length)
        }
        ExampleType::Rescue { chain_length } => rescue::get_example(&options, chain_length),
        #[cfg(feature = "std")]
        ExampleType::SigRescue {
            num_signers,
            log_ring_size,
            ..
        } => sigrescue::get_example(&options, num_signers, log_ring_size),
    }
    .expect("The example failed to initialize.");

    let example = example.as_ref();
    let mut prove_times = Vec::with_capacity(iters);
    let mut verify_times = Vec::with_capacity(iters);
    for iter in 0..iters {
        if iters > 1 {
            debug!("---------------------\nIteration {}/{}", iter + 1, iters);
        }

        // generate proof
        let now = Instant::now();
        let proof = example.prove();
        let prove_time = now.elapsed();
        debug!(
            "---------------------\nProof generated in {} ms",
            prove_time.as_millis()
        );
        prove_times.push(prove_time);

        if iter == 0 {
            let proof_bytes = proof.to_bytes();
            debug!(
                "Proof size: {:.1} KB ({} bytes)",
                proof_bytes.len() as f64 / 1024f64,
                proof_bytes.len()
            );
            let conjectured_security_level = options.get_proof_security_level(&proof, true);
            debug!("Proof security: {} bits", conjectured_security_level);
        }

        // verify the proof
        debug!("---------------------");
        let now = Instant::now();
        match example.verify(proof) {
            Ok(_) => {
                let verify_time = now.elapsed();
                debug!(
                    "Proof verified in {:.1} ms",
                    verify_time.as_micros() as f64 / 1000f64
                );
                verify_times.push(verify_time);
            }
            Err(msg) => debug!("Failed to verify proof: {}", msg),
        }
    }

    if iters > 1 {
        debug!("============================================================");
        print_stats("Prove", &mut prove_times);
        print_stats("Verify", &mut verify_times);
    }
    debug!("============================================================");
}

fn print_stats(label: &str, times: &mut [Duration]) {
    if times.is_empty() {
        debug!("{label}: no successful runs");
        return;
    }
    times.sort();
    let ms = |d: Duration| d.as_micros() as f64 / 1000f64;
    let mean = times.iter().map(|&d| ms(d)).sum::<f64>() / times.len() as f64;
    debug!(
        "{label} over {} runs: min {:.1} ms, median {:.1} ms, mean {:.1} ms, max {:.1} ms",
        times.len(),
        ms(times[0]),
        ms(times[times.len() / 2]),
        mean,
        ms(times[times.len() - 1]),
    );
}
