"""
Publication-quality matplotlib visualizations for the research paper.

Generates 4 figures:
  Figure 1: Crypto Benchmark Grouped Bar Chart
  Figure 2: Gas Cost Comparison Bar Chart
  Figure 3: Relay vs Direct Latency Comparison
  Figure 4: Scalability Dual-Axis Line Chart

All figures are saved as both PDF (for LaTeX inclusion) and PNG (for preview).
"""

import json
import os
from pathlib import Path
from typing import Any

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for Docker/headless
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

from shared.config import RESULTS_DIR

__all__ = [
    "generate_all_figures",
    "fig1_crypto_benchmark",
    "fig2_gas_comparison",
    "fig3_relay_latency",
    "fig4_scalability",
]

# ── Academic style ──

# Color palette: distinguishable in print (grayscale-friendly)
COLORS = {
    "Falcon-512": "#2563EB",   # Blue
    "ECDSA":      "#DC2626",   # Red
    "Dilithium2": "#16A34A",   # Green
    "Dilithium3": "#9333EA",   # Purple
}

SCHEME_ORDER = ["ECDSA", "Falcon-512", "Dilithium2", "Dilithium3"]
OPERATION_ORDER = ["keygen", "sign", "verify"]

FIGURE_WIDTH = 7.0   # inches (single column)
FIGURE_HEIGHT = 3.5


def _setup_style():
    """Apply academic publication style."""
    plt.rcParams.update({
        "font.family": "serif",
        "font.size": 10,
        "axes.labelsize": 11,
        "axes.titlesize": 12,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "figure.dpi": 150,
        "savefig.dpi": 300,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.05,
    })


def _save_fig(fig, name: str, results_dir: Path):
    """Save figure as PDF and PNG."""
    results_dir.mkdir(parents=True, exist_ok=True)
    fig.savefig(str(results_dir / f"{name}.pdf"), format="pdf")
    fig.savefig(str(results_dir / f"{name}.png"), format="png")
    plt.close(fig)
    print(f"  Saved: {name}.pdf / {name}.png")


# ── Figure 1: Crypto Benchmark ──

def fig1_crypto_benchmark(results: dict, results_dir: Path) -> str:
    """
    Grouped bar chart comparing keygen/sign/verify times across schemes.

    Args:
        results: Combined results dict with "crypto_benchmark" key.
        results_dir: Directory to save figures.

    Returns:
        Filename base (e.g. "fig1_crypto_benchmark").
    """
    if "crypto_benchmark" not in results:
        print("  Skipping fig1: no crypto_benchmark data")
        return ""

    # Aggregate: mean and std time per (scheme, operation)
    from collections import defaultdict
    scheme_ops = defaultdict(dict)  # scheme -> {op: mean_ms}

    for r in results["crypto_benchmark"]:
        d = r.to_dict() if hasattr(r, "to_dict") else r
        scheme = d["scheme"]
        op = d["operation"]
        # We collect all iteration times and compute mean + std
        key = (scheme, op)
        if "_times" not in scheme_ops[scheme]:
            scheme_ops[scheme]["_times"] = defaultdict(list)
        scheme_ops[scheme]["_times"][op].append(d["time_ms"])

    # Compute means and standard deviations
    agg = {}  # (scheme, op) -> mean_ms
    stds = {}  # (scheme, op) -> std_ms
    for scheme, data in scheme_ops.items():
        for op, times in data.get("_times", {}).items():
            agg[(scheme, op)] = np.mean(times)
            stds[(scheme, op)] = np.std(times) if len(times) > 1 else 0

    _setup_style()

    schemes = [s for s in SCHEME_ORDER if s in scheme_ops]
    n_schemes = len(schemes)
    n_ops = len(OPERATION_ORDER)

    x = np.arange(n_ops)
    width = 0.8 / n_schemes

    fig, ax = plt.subplots(figsize=(FIGURE_WIDTH, FIGURE_HEIGHT))

    # Find global min/max for axis range (with margin for labels)
    all_vals = [v for v in agg.values() if v > 0]
    y_min = min(all_vals) / 3 if all_vals else 0.001
    y_max = max(all_vals) * 10 if all_vals else 10  # extra headroom for value labels

    for i, scheme in enumerate(schemes):
        values = [agg.get((scheme, op), 0) for op in OPERATION_ORDER]
        errors = [stds.get((scheme, op), 0) for op in OPERATION_ORDER]
        offset = (i - n_schemes / 2 + 0.5) * width
        bars = ax.bar(
            x + offset, values, width * 0.9,
            yerr=errors,
            capsize=2,
            error_kw={"linewidth": 0.8, "capthick": 0.8},
            label=scheme,
            color=COLORS.get(scheme, "#888888"),
            edgecolor="white",
            linewidth=0.5,
        )
        # Add value labels on bars
        for bar, val in zip(bars, values):
            if val > 0:
                ax.text(
                    bar.get_x() + bar.get_width() / 2, val * 1.15,
                    f"{val:.2f}",
                    ha="center", va="bottom",
                    fontsize=6, rotation=45,
                )

    ax.set_xlabel("Operation")
    ax.set_ylabel("Time (ms)")
    # No title — caption is in the paper
    ax.set_xticks(x)
    ax.set_xticklabels(["Key Generation", "Signing", "Verification"])
    ax.set_yscale("log")
    ax.set_ylim(y_min, y_max)
    ax.legend(loc="upper right", framealpha=0.9)
    ax.yaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.grid(axis="y", alpha=0.3)

    name = "fig1_crypto_benchmark"
    _save_fig(fig, name, results_dir)
    return name


# ── Figure 2: Gas Cost Comparison ──

def fig2_gas_comparison(results: dict, results_dir: Path) -> str:
    """
    Horizontal bar chart comparing gas costs of different operations.

    Shows: DID Registration, Relay Transaction, ECDSA Direct (verify+store),
    and theoretical on-chain Falcon verification (exceeds block limit).
    """
    _setup_style()

    # Gas data: prefer measured values from experiment results
    ecdsa_gas = 50_000  # default fallback (ECDSA verify + store 64-byte sig)
    relay_gas = 821_563  # default fallback
    did_reg_gas = 771_537  # default fallback
    pk_lookup_gas = 94_084  # default fallback
    did_deact_gas = 25_917  # default fallback

    if results.get("relay_system"):
        relay_data_tmp = results["relay_system"]
        if "direct_ecdsa" in relay_data_tmp and "avg_gas_per_tx" in relay_data_tmp["direct_ecdsa"]:
            ecdsa_gas = int(relay_data_tmp["direct_ecdsa"]["avg_gas_per_tx"])
        if "relay_falcon" in relay_data_tmp and "avg_gas_per_tx" in relay_data_tmp["relay_falcon"]:
            relay_gas = int(relay_data_tmp["relay_falcon"]["avg_gas_per_tx"])

    operations = [
        ("ECDSA Direct\n(verify+store)", ecdsa_gas, "#DC2626"),
        ("DID Registration", did_reg_gas, "#F59E0B"),
        ("Public Key Lookup", pk_lookup_gas, "#6B7280"),
        ("Relay Meta-TX\n(Falcon-512)", relay_gas, "#2563EB"),
        ("DID Deactivation", did_deact_gas, "#6B7280"),
        ("On-chain Falcon\n(theoretical)", 500_000_000, "#991B1B"),
    ]

    labels = [op[0] for op in operations]
    values = [op[1] for op in operations]
    colors = [op[2] for op in operations]

    fig, ax = plt.subplots(figsize=(FIGURE_WIDTH, FIGURE_HEIGHT + 1.0))

    y_pos = np.arange(len(labels))
    bars = ax.barh(y_pos, values, color=colors, edgecolor="white", height=0.6)

    # Add Ethereum block gas limit line
    ax.axvline(x=30_000_000, color="red", linestyle="--", linewidth=1.5,
               label="Ethereum Block Gas Limit (~30M)")

    # Value labels — placed just past bar end on log scale
    for bar, val in zip(bars, values):
        bar_center_y = bar.get_y() + bar.get_height() / 2
        if val < 30_000_000:
            ax.text(val * 1.4, bar_center_y,
                    f"{val:,}", va="center", fontsize=8)
        else:
            # Place label above the bar, same style as others
            ax.text(val * 0.5, bar.get_y(),
                    f"{val:,}", ha="center", va="bottom", fontsize=8)

    ax.set_xlabel("Gas Cost")
    # No title — caption is in the paper
    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels)
    ax.set_xscale("log")
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(
        lambda x, _: f"{x/1e6:.0f}M" if x >= 1e6 else f"{x/1e3:.0f}K"
    ))
    # Legend in upper-right: short bars at top leave empty space
    ax.legend(loc="upper right", fontsize=8)
    ax.grid(axis="x", alpha=0.3)
    ax.invert_yaxis()

    name = "fig2_gas_comparison"
    _save_fig(fig, name, results_dir)
    return name


# ── Figure 4: Scalability ──

def fig4_scalability(results: dict, results_dir: Path) -> str:
    """
    Dual-axis line chart showing gateway verification and blockchain
    submission throughput vs device count.

    X: number of devices, Y1: throughput (TPS), Y2: average latency (ms).
    Shows phase-separated metrics: gateway verification (scales with devices)
    vs blockchain submission (constant-rate bottleneck).
    """
    if "scalability" not in results:
        print("  Skipping fig4: no scalability data")
        return ""

    _setup_style()

    devices = []
    throughput = []
    avg_latency = []
    p99_latency = []
    gw_tps = []
    gw_avg_lat = []
    bc_tps = []
    bc_avg_lat = []

    for d in results["scalability"]:
        devices.append(d["device_count"])
        throughput.append(d["throughput_tps"])
        avg_latency.append(d["avg_latency_ms"])
        p99_latency.append(d["p99_latency_ms"])
        gw_tps.append(d.get("gateway_verify_tps", 0))
        gw_avg_lat.append(d.get("gateway_avg_latency_ms", 0))
        bc_tps.append(d.get("blockchain_submit_tps", 0))
        bc_avg_lat.append(d.get("blockchain_avg_latency_ms", 0))

    fig, ax1 = plt.subplots(figsize=(FIGURE_WIDTH, FIGURE_HEIGHT))

    color_gw = "#2563EB"   # Blue for gateway
    color_bc = "#DC2626"   # Red for blockchain
    color_lat = "#F59E0B"  # Amber for latency

    # Throughput lines (left axis)
    line1 = ax1.plot(devices, gw_tps, "o-", color=color_gw,
                     linewidth=2, markersize=6, label="Gateway Verify TPS")
    has_bc_data = any(t > 0 for t in bc_tps)
    if has_bc_data:
        line2 = ax1.plot(devices, bc_tps, "s--", color=color_bc,
                         linewidth=2, markersize=6, label="Blockchain Submit TPS")
    ax1.set_xlabel("Number of IoT Devices")
    ax1.set_ylabel("Throughput (TPS)", color=color_gw)
    ax1.tick_params(axis="y", labelcolor=color_gw)
    ax1.set_ylim(bottom=0)

    # Latency (right axis) — overall combined
    ax2 = ax1.twinx()
    line3 = ax2.plot(devices, avg_latency, "^:", color=color_lat,
                     linewidth=1.5, markersize=5, label="Overall Avg Latency (ms)")
    line4 = ax2.plot(devices, p99_latency, "D:", color="#9333EA",
                     linewidth=1.5, markersize=4, label="Overall P99 Latency (ms)")
    ax2.set_ylabel("Latency (ms)", color=color_lat)
    ax2.tick_params(axis="y", labelcolor=color_lat)
    ax2.set_ylim(bottom=0)

    # Combined legend — placed below center to avoid covering lines
    all_lines = list(line1)
    if has_bc_data:
        all_lines.extend(list(line2))
    all_lines.extend(list(line3))
    all_lines.extend(list(line4))
    all_labels = [l.get_label() for l in all_lines]
    ax1.legend(all_lines, all_labels, loc="lower right", fontsize=7, framealpha=0.9)

    # No title — caption is in the paper
    ax1.grid(alpha=0.3)

    name = "fig4_scalability"
    _save_fig(fig, name, results_dir)
    return name


# ── Figure 3: Relay vs Direct Latency ──

def fig3_relay_latency(results: dict, results_dir: Path) -> str:
    """
    Bar chart comparing relay-assisted vs direct submission metrics.

    Shows average latency, gas cost, and throughput comparison.
    """
    if "relay_system" not in results:
        print("  Skipping fig3: no relay_system data")
        return ""

    _setup_style()

    relay_data = results["relay_system"]
    comp = relay_data.get("comparison", {})
    direct = relay_data.get("direct_ecdsa", {})
    relay = relay_data.get("relay_falcon", {})

    fig, axes = plt.subplots(1, 3, figsize=(FIGURE_WIDTH + 2, FIGURE_HEIGHT))

    # Subplot 1: Average Latency
    categories = ["Direct ECDSA\n(verify+store)", "Relay-assisted\n(Falcon-512)"]
    latencies = [direct.get("avg_latency_ms", 0), relay.get("avg_latency_ms", 0)]
    colors = ["#DC2626", "#2563EB"]
    axes[0].bar(categories, latencies, color=colors, edgecolor="white", width=0.5)
    axes[0].set_ylabel("Avg Latency (ms)")
    axes[0].set_title("Latency Comparison")
    for i, v in enumerate(latencies):
        axes[0].text(i, v + 0.5, f"{v:.1f}ms", ha="center", fontsize=8)
    axes[0].grid(axis="y", alpha=0.3)

    # Subplot 2: Gas Cost per Transaction
    gas_costs = [direct.get("avg_gas_per_tx", 0), relay.get("avg_gas_per_tx", 0)]
    axes[1].bar(categories, gas_costs, color=colors, edgecolor="white", width=0.5)
    axes[1].set_ylabel("Gas per Transaction")
    axes[1].set_title("Gas Cost Comparison")
    for i, v in enumerate(gas_costs):
        axes[1].text(i, v + 5000, f"{v:,.0f}", ha="center", fontsize=7)
    axes[1].grid(axis="y", alpha=0.3)

    # Subplot 3: Gas Reduction (theoretical Falcon vs relay) — log scale
    theoretical = comp.get("theoretical_falcon_gas", 500_000_000)
    relay_gas = relay.get("avg_gas_per_tx", 0)
    bar_data = [relay_gas / 1_000_000, theoretical / 1_000_000]  # in millions
    bar_labels = ["Relay\n(Falcon-512)", "On-chain Falcon\n(theoretical)"]
    bars3 = axes[2].bar(
        bar_labels,
        bar_data,
        color=["#2563EB", "#991B1B"],
        edgecolor="white",
        width=0.5,
    )
    axes[2].axhline(y=30, color="red", linestyle="--", linewidth=1,
                     label="Block Gas Limit (30M)")
    # Add value labels on bars
    for bar, val in zip(bars3, bar_data):
        axes[2].text(bar.get_x() + bar.get_width() / 2,
                     val * 1.3,
                     f"{val:,.1f}M",
                     ha="center", va="bottom", fontsize=7)
    axes[2].set_ylabel("Gas Cost (millions)")
    axes[2].set_yscale("log")
    axes[2].set_ylim(bottom=0.5, top=2000)
    axes[2].yaxis.set_major_formatter(ticker.FuncFormatter(
        lambda x, _: f"{x:.0f}M"
    ))
    axes[2].set_title("On-chain Falcon vs Relay")
    axes[2].legend(fontsize=7, loc="upper left")
    axes[2].grid(axis="y", alpha=0.3)

    # No suptitle — caption is in the paper
    fig.tight_layout()
    fig.subplots_adjust(top=0.85)

    name = "fig3_relay_comparison"
    _save_fig(fig, name, results_dir)
    return name


# ── Main entry point ──

def generate_all_figures(results: dict, results_dir: Path = None) -> list[str]:
    """Generate all publication figures.

    Args:
        results: Combined experiment results dict.
        results_dir: Directory to save figures. Defaults to RESULTS_DIR/figures.

    Returns:
        List of generated figure names.
    """
    if results_dir is None:
        results_dir = RESULTS_DIR / "figures"

    print("\n" + "=" * 60)
    print("Generating Publication Figures")
    print("=" * 60)

    generated = []
    for func in [fig1_crypto_benchmark, fig2_gas_comparison,
                 fig3_relay_latency, fig4_scalability]:
        try:
            name = func(results, results_dir)
            if name:
                generated.append(name)
        except Exception as e:
            print(f"  ERROR generating {func.__name__}: {e}")

    print(f"\n  Generated {len(generated)} figures in {results_dir}")
    return generated
