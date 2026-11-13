# /// script
# dependencies = ["matplotlib"]
# ///
"""Plot sigrescue benchmarks (proof size, sign time, verify time) vs log2(ring size).

Usage: python plot.py <run_dir>     e.g. python plot.py 2026-11-05-mentat
Writes proof_size.png, sign_time.png, verify_time.png into <run_dir>.
"""
import csv
import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt


def load_times(run_dir, group):
    """Return sorted [(log_ring_size, mean_ms, lo_ms, hi_ms)] from criterion's estimates.json."""
    rows = []
    for d in (run_dir / group / "log_ring_size").iterdir():
        est = d / "new" / "estimates.json"
        if not est.exists():
            continue
        mean = json.loads(est.read_text())["mean"]
        ci = mean["confidence_interval"]
        rows.append((int(d.name), mean["point_estimate"] / 1e6,
                     ci["lower_bound"] / 1e6, ci["upper_bound"] / 1e6))
    return sorted(rows)


def load_sizes(run_dir):
    with open(run_dir / "sigrescue_proof_sizes.csv") as f:
        rows = [(int(r["log_ring_size"]), float(r["proof_bytes_mean"]) / 1024,
                 float(r["proof_bytes_min"]) / 1024, float(r["proof_bytes_max"]) / 1024)
                for r in csv.DictReader(f)]
    return sorted(rows)


def plot(rows, ylabel, title, out, err_label):
    x = [r[0] for r in rows]
    y = [r[1] for r in rows]
    fig, ax = plt.subplots(figsize=(6, 4))
    if err_label:
        yerr = [[r[1] - r[2] for r in rows], [r[3] - r[1] for r in rows]]
        ax.errorbar(x, y, yerr=yerr, marker="o", capsize=3, label=f"mean ({err_label})")
    else:
        ax.plot(x, y, marker="o", label="mean")
    ax.set_xlabel(r"$\log_2$(ring size)")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_xticks(x)
    ax.set_ylim(bottom=0)
    ax.grid(alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out, dpi=200)
    plt.close(fig)
    print(f"wrote {out}")


def main():
    run_dir = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    plot(load_sizes(run_dir), "proof size (KiB)", "Signature size",
         run_dir / "proof_size.png", "min/max error bars")
    plot(load_times(run_dir, "sigrescue_sign"), "time (ms)", "Signing time",
         run_dir / "sign_time.png", None)
    plot(load_times(run_dir, "sigrescue_verify"), "time (ms)", "Verification time",
         run_dir / "verify_time.png", None)


if __name__ == "__main__":
    main()
