"""
Generate presentation-quality charts for slides 8, 9, and 5.
Output: docs/presentation_figures/
"""

import os
import json
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
from pathlib import Path

OUT = Path("docs/presentation_figures")
OUT.mkdir(parents=True, exist_ok=True)

# ── Load real data ──────────────────────────────────────────────────────────
results_path = Path("analysis/results/experiment_results.json")
with open(results_path) as f:
    records = json.load(f)

# Compute per-attack-type stats
from collections import defaultdict
stats = defaultdict(lambda: {"attempts": 0, "blocked": 0})
for r in records:
    if r.get("target") == "gateway":
        atype = r.get("attack_type", "unknown")
        stats[atype]["attempts"] += 1
        if r.get("blocked", False):
            stats[atype]["blocked"] += 1

# ── CHART 1: Slide 8 — Block Rate by Attack Type ───────────────────────────
ATTACK_LABELS = {
    "ddos": "DDoS",
    "sql_injection": "SQL\nInjection",
    "schema_violation": "Schema\nViolation",
    "legitimate": "Legitimate\n(False Pos.)",
    "model_inversion": "Model\nInversion",
}
ORDER = ["ddos", "sql_injection", "schema_violation", "legitimate", "model_inversion"]
COLORS = ["#2ECC71", "#2ECC71", "#2ECC71", "#F39C12", "#E74C3C"]
EDGE_COLORS = ["#27AE60", "#27AE60", "#27AE60", "#D68910", "#C0392B"]

labels = []
rates = []
attempts_list = []
for k in ORDER:
    s = stats.get(k, {"attempts": 0, "blocked": 0})
    a = s["attempts"]
    b = s["blocked"]
    rate = (b / a * 100) if a > 0 else 0
    labels.append(ATTACK_LABELS.get(k, k))
    rates.append(rate)
    attempts_list.append(a)

fig, ax = plt.subplots(figsize=(12, 7))
fig.patch.set_facecolor("#0D1117")
ax.set_facecolor("#0D1117")

x = np.arange(len(labels))
bars = ax.bar(x, rates, color=COLORS, edgecolor=EDGE_COLORS, linewidth=1.5,
              width=0.55, zorder=3)

# Grid
ax.yaxis.grid(True, color="#2A2E35", linewidth=0.8, zorder=0)
ax.set_axisbelow(True)

# Target line at 92% (draft claim) — crossed out effectively by real data
ax.axhline(100, color="#FFFFFF", linewidth=0.5, linestyle="--", alpha=0.2, zorder=2)

# Value labels on bars
for bar, rate, n in zip(bars, rates, attempts_list):
    ypos = bar.get_height() + 1.5
    ax.text(bar.get_x() + bar.get_width() / 2, ypos,
            f"{rate:.1f}%\n(n={n})",
            ha="center", va="bottom", fontsize=13, fontweight="bold",
            color="#FFFFFF", zorder=4)

# Highlight the model inversion bar with annotation
ax.annotate(
    "⚠  2.5% — semantic\nattacks bypass\nstatic rules",
    xy=(4, 2.5), xytext=(3.3, 38),
    fontsize=11, color="#E74C3C", fontweight="bold",
    arrowprops=dict(arrowstyle="->", color="#E74C3C", lw=1.5),
    zorder=5
)

ax.set_xticks(x)
ax.set_xticklabels(labels, fontsize=14, color="#FFFFFF")
ax.set_ylim(0, 118)
ax.set_ylabel("Block Rate (%)", fontsize=14, color="#AAAAAA", labelpad=10)
ax.set_title("Gateway Security Efficacy by Attack Type\n"
             "Green = structural threats (static rules work)  |  Red = semantic AI threat (static rules fail)",
             fontsize=15, color="#FFFFFF", pad=18)
ax.tick_params(colors="#AAAAAA", labelsize=12)
for spine in ax.spines.values():
    spine.set_edgecolor("#2A2E35")

# Legend patches
legend_elements = [
    mpatches.Patch(facecolor="#2ECC71", edgecolor="#27AE60", label="Structural attacks — 100% blocked"),
    mpatches.Patch(facecolor="#F39C12", edgecolor="#D68910", label="False positives — 7.1%"),
    mpatches.Patch(facecolor="#E74C3C", edgecolor="#C0392B", label="Semantic AI attack — 2.5% blocked"),
]
ax.legend(handles=legend_elements, loc="upper right", fontsize=11,
          facecolor="#1A1E24", edgecolor="#444", labelcolor="#FFFFFF")

plt.tight_layout()
out1 = OUT / "slide8_block_rates.png"
plt.savefig(out1, dpi=180, bbox_inches="tight", facecolor="#0D1117")
plt.close()
print(f"[+] Slide 8 chart saved → {out1}")


# ── CHART 2: Slide 9 — Latency Comparison ──────────────────────────────────
direct_latencies = [r["latency_ms"] for r in records
                    if r.get("target") == "direct" and r.get("latency_ms")]
gateway_latencies = [r["latency_ms"] for r in records
                     if r.get("target") == "gateway" and r.get("latency_ms")]

direct_mean = np.mean(direct_latencies)
gateway_mean = np.mean(gateway_latencies)
overhead = gateway_mean - direct_mean

fig, axes = plt.subplots(1, 2, figsize=(14, 7))
fig.patch.set_facecolor("#0D1117")

# Left: horizontal bar comparison
ax = axes[0]
ax.set_facecolor("#0D1117")
categories = ["Direct\nEndpoint", "APIM\nGateway"]
values = [direct_mean, gateway_mean]
colors = ["#2ECC71", "#E74C3C"]
edge_colors = ["#27AE60", "#C0392B"]

bars = ax.barh(categories, values, color=colors, edgecolor=edge_colors,
               linewidth=1.5, height=0.45, zorder=3)
ax.xaxis.grid(True, color="#2A2E35", linewidth=0.8, zorder=0)
ax.set_axisbelow(True)

for bar, val in zip(bars, values):
    ax.text(val + 20, bar.get_y() + bar.get_height() / 2,
            f"{val:.0f} ms", va="center", ha="left",
            fontsize=16, fontweight="bold", color="#FFFFFF")

ax.annotate(
    f"+{overhead:.0f} ms\noverhead\n(18× slower)",
    xy=(gateway_mean / 2, 1), xytext=(gateway_mean / 2, 0.3),
    fontsize=12, color="#F39C12", fontweight="bold", ha="center",
    arrowprops=dict(arrowstyle="->", color="#F39C12", lw=1.5)
)

ax.set_xlabel("Average Latency (ms)", fontsize=13, color="#AAAAAA")
ax.set_title("Latency: Direct vs Gateway", fontsize=14,
             color="#FFFFFF", pad=12)
ax.tick_params(colors="#AAAAAA", labelsize=13)
for spine in ax.spines.values():
    spine.set_edgecolor("#2A2E35")
ax.set_xlim(0, gateway_mean * 1.25)

# Right: stats comparison table
ax2 = axes[1]
ax2.set_facecolor("#0D1117")
ax2.axis("off")

direct_errors = sum(1 for r in records
                    if r.get("target") == "direct" and r.get("error"))
gateway_errors = sum(1 for r in records
                     if r.get("target") == "gateway" and r.get("error"))
total_direct = sum(1 for r in records if r.get("target") == "direct")
total_gateway = sum(1 for r in records if r.get("target") == "gateway")
direct_err_rate = direct_errors / total_direct * 100 if total_direct else 0
gateway_err_rate = gateway_errors / total_gateway * 100 if total_gateway else 0

table_data = [
    ["Metric", "Direct", "APIM Gateway"],
    ["Avg Latency", f"{direct_mean:.0f} ms", f"{gateway_mean:.0f} ms"],
    ["Latency Overhead", "—", f"+{overhead:.0f} ms"],
    ["Throughput ratio", "1×", f"~{gateway_mean/direct_mean:.0f}× slower"],
    ["Error Rate", f"{direct_err_rate:.1f}%", f"{gateway_err_rate:.1f}%"],
    ["Total Requests", str(total_direct), str(total_gateway)],
]

row_colors_bg = ["#1F2937", "#0D1117", "#1A2030", "#0D1117", "#1A2030", "#0D1117"]
header_color = "#1F2937"

y_start = 0.92
row_height = 0.13
col_x = [0.02, 0.42, 0.72]
col_widths = [0.38, 0.28, 0.28]

for i, row in enumerate(table_data):
    bg_color = "#1F2937" if i == 0 else ("#162032" if i % 2 == 0 else "#0D1117")
    ax2.add_patch(FancyBboxPatch(
        (0.01, y_start - i * row_height - row_height + 0.01),
        0.97, row_height - 0.01,
        boxstyle="round,pad=0.005", linewidth=0,
        facecolor=bg_color, zorder=1, transform=ax2.transAxes
    ))
    for j, cell in enumerate(row):
        color = "#FFFFFF" if i == 0 else "#DDDDDD"
        if i > 0 and j == 2:
            if "slower" in cell or "+" in cell:
                color = "#E74C3C"
            elif cell == "—":
                color = "#666"
        fontweight = "bold" if i == 0 else "normal"
        ax2.text(col_x[j] + col_widths[j] / 2,
                 y_start - i * row_height - row_height / 2 + 0.01,
                 cell, ha="center", va="center",
                 fontsize=12, color=color, fontweight=fontweight,
                 transform=ax2.transAxes, zorder=2)

ax2.set_title("Performance Comparison", fontsize=14,
              color="#FFFFFF", pad=12)

plt.suptitle("Security Overhead: What Does Protection Cost?",
             fontsize=16, color="#FFFFFF", y=1.01)
plt.tight_layout()
out2 = OUT / "slide9_latency.png"
plt.savefig(out2, dpi=180, bbox_inches="tight", facecolor="#0D1117")
plt.close()
print(f"[+] Slide 9 chart saved → {out2}")


# ── CHART 3: Slide 5 — Threat Model Visual ─────────────────────────────────
fig, ax = plt.subplots(figsize=(13, 6))
fig.patch.set_facecolor("#0D1117")
ax.set_facecolor("#0D1117")
ax.axis("off")
ax.set_xlim(0, 10)
ax.set_ylim(0, 6)

# Left panel — structural
ax.add_patch(FancyBboxPatch((0.2, 0.3), 4.0, 5.2, boxstyle="round,pad=0.1",
                             linewidth=2, edgecolor="#27AE60",
                             facecolor="#0F2A1A", zorder=1))
ax.text(2.2, 5.2, "STRUCTURAL THREATS", ha="center", va="center",
        fontsize=13, fontweight="bold", color="#2ECC71")
ax.text(2.2, 4.7, "Static rules catch these ✓", ha="center",
        fontsize=11, color="#27AE60", style="italic")

structural = [
    ("🛡", "SQL Injection", "Pattern matching → 100% blocked"),
    ("🛡", "Schema Violation", "JSON schema validation → 100% blocked"),
    ("🛡", "DDoS / Rate Abuse", "Rate limiting → 100% blocked"),
    ("🛡", "Malformed Payloads", "Content validation → ~100% blocked"),
]
for idx, (icon, title, detail) in enumerate(structural):
    y = 3.9 - idx * 0.88
    ax.text(0.6, y, icon, fontsize=16, va="center")
    ax.text(1.2, y + 0.12, title, fontsize=12, fontweight="bold",
            color="#FFFFFF", va="center")
    ax.text(1.2, y - 0.18, detail, fontsize=9.5, color="#7ED49A", va="center")

# Right panel — semantic
ax.add_patch(FancyBboxPatch((5.8, 0.3), 4.0, 5.2, boxstyle="round,pad=0.1",
                             linewidth=2, edgecolor="#C0392B",
                             facecolor="#2A0F0F", zorder=1))
ax.text(7.8, 5.2, "SEMANTIC AI THREATS", ha="center", va="center",
        fontsize=13, fontweight="bold", color="#E74C3C")
ax.text(7.8, 4.7, "Static rules miss these ✗", ha="center",
        fontsize=11, color="#C0392B", style="italic")

semantic = [
    ("⚠", "Model Inversion", "Valid requests, malicious intent → 2.5% blocked"),
    ("⚠", "Prompt Manipulation", "Semantic abuse of LLM context"),
    ("⚠", "Inference Extraction", "Systematic boundary probing"),
    ("⚠", "Adversarial Inputs", "Feature-crafted to mislead model"),
]
for idx, (icon, title, detail) in enumerate(semantic):
    y = 3.9 - idx * 0.88
    ax.text(6.0, y, icon, fontsize=16, va="center")
    ax.text(6.6, y + 0.12, title, fontsize=12, fontweight="bold",
            color="#FFFFFF", va="center")
    ax.text(6.6, y - 0.18, detail, fontsize=9.5, color="#F1948A", va="center")

# Center divider arrow
ax.annotate("", xy=(5.6, 3.0), xytext=(4.4, 3.0),
            arrowprops=dict(arrowstyle="<->", color="#888888", lw=2))
ax.text(5.0, 3.35, "vs", ha="center", fontsize=18,
        color="#AAAAAA", fontweight="bold")
ax.text(5.0, 2.6, "The Gap", ha="center", fontsize=10,
        color="#888888", style="italic")

ax.set_title("AI Threat Model: Where Traditional API Security Succeeds and Fails",
             fontsize=15, color="#FFFFFF", pad=15)
plt.tight_layout()
out3 = OUT / "slide5_threat_model.png"
plt.savefig(out3, dpi=180, bbox_inches="tight", facecolor="#0D1117")
plt.close()
print(f"[+] Slide 5 threat model saved → {out3}")

print("\n✅ All 3 presentation charts generated in docs/presentation_figures/")
print("   slide8_block_rates.png  — for Slide 8 (Security Efficacy)")
print("   slide9_latency.png      — for Slide 9 (Performance Trade-off)")
print("   slide5_threat_model.png — for Slide 5 (AI Threat Model)")
