"""
Generate Research At a Glance - 3 stat boxes for slide 5
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
from pathlib import Path

OUT = Path("docs/presentation_figures")
OUT.mkdir(parents=True, exist_ok=True)

fig, ax = plt.subplots(figsize=(14, 7))
fig.patch.set_facecolor("#FFFFFF")
ax.set_facecolor("#FFFFFF")
ax.axis("off")
ax.set_xlim(0, 14)
ax.set_ylim(0, 7)

# ── Column definitions ──────────────────────────────────────────────────────
cols = [
    {
        "title": "REAL INFRA",
        "title_color": "#1A56DB",
        "border_color": "#1A56DB",
        "bg": "#F0F5FF",
        "header_bg": "#1A56DB",
        "items": [
            ("Azure API Management", "#111827"),
            ("5-layer security policy", "#374151"),
            ("", ""),
            ("Azure Container Apps", "#111827"),
            ("FastAPI + RandomForest", "#374151"),
        ],
    },
    {
        "title": "REAL TRAFFIC",
        "title_color": "#FFFFFF",
        "border_color": "#B91C1C",
        "bg": "#FFF5F5",
        "header_bg": "#B91C1C",
        "items": [
            ("462 attack scenarios", "#111827"),
            ("5 attack types", "#374151"),
            ("", ""),
            ("Automated & concurrent", "#111827"),
            ("GitHub Actions runner", "#374151"),
        ],
    },
    {
        "title": "REAL DATA",
        "title_color": "#FFFFFF",
        "border_color": "#065F46",
        "bg": "#F0FDF4",
        "header_bg": "#065F46",
        "items": [
            ("924 HTTP requests fired", "#111827"),
            ("Both endpoints measured", "#374151"),
            ("", ""),
            ("Simultaneously compared", "#111827"),
            ("Open on GitHub", "#374151"),
        ],
    },
]

box_w = 3.8
box_h = 4.8
gap = 0.55
start_x = 0.55
box_y = 0.7

for i, col in enumerate(cols):
    x = start_x + i * (box_w + gap)

    # Shadow
    ax.add_patch(FancyBboxPatch(
        (x + 0.07, box_y - 0.07), box_w, box_h,
        boxstyle="round,pad=0.1", linewidth=0,
        facecolor="#CCCCCC", zorder=1, transform=ax.transData
    ))

    # Main box
    ax.add_patch(FancyBboxPatch(
        (x, box_y), box_w, box_h,
        boxstyle="round,pad=0.1", linewidth=2.5,
        edgecolor=col["border_color"],
        facecolor=col["bg"], zorder=2, transform=ax.transData
    ))

    # Header band
    ax.add_patch(FancyBboxPatch(
        (x, box_y + box_h - 0.78), box_w, 0.78,
        boxstyle="round,pad=0.05", linewidth=0,
        facecolor=col["header_bg"], zorder=3, transform=ax.transData
    ))

    # Title
    ax.text(x + box_w / 2, box_y + box_h - 0.39,
            col["title"], ha="center", va="center",
            fontsize=14, fontweight="bold",
            color="#FFFFFF", zorder=4)

    # Divider line
    ax.plot([x + 0.2, x + box_w - 0.2],
            [box_y + box_h - 0.85, box_y + box_h - 0.85],
            color=col["border_color"], linewidth=1, alpha=0.4, zorder=4)

    # Items
    item_y_start = box_y + box_h - 1.35
    for j, (text, color) in enumerate(col["items"]):
        if text == "":
            # Subtle separator
            ax.plot([x + 0.3, x + box_w - 0.3],
                    [item_y_start - j * 0.72 + 0.2,
                     item_y_start - j * 0.72 + 0.2],
                    color="#DDDDDD", linewidth=0.8, zorder=4)
            continue
        # Bullet dot
        ax.plot(x + 0.32, item_y_start - j * 0.72,
                "o", markersize=5,
                color=col["border_color"], zorder=4)
        ax.text(x + 0.52, item_y_start - j * 0.72,
                text, ha="left", va="center",
                fontsize=12, color=color,
                fontweight="bold" if j in (0, 3) else "normal",
                zorder=4)

# ── Big numbers row above boxes ─────────────────────────────────────────────
stats = [
    ("462", "attack scenarios"),
    ("924", "HTTP requests"),
    ("5", "attack types"),
    ("2 min", "to run end-to-end"),
]
stat_x_positions = [1.95, 5.35, 8.75, 12.15]
for val, label, sx in zip(
    [s[0] for s in stats],
    [s[1] for s in stats],
    stat_x_positions
):
    ax.text(sx, 6.45, val, ha="center", va="center",
            fontsize=26, fontweight="bold", color="#111827", zorder=5)
    ax.text(sx, 6.05, label, ha="center", va="center",
            fontsize=10, color="#6B7280", zorder=5)

# Separator line under stats
ax.plot([0.4, 13.6], [5.85, 5.85], color="#E5E7EB", linewidth=1.5, zorder=3)

# ── GitHub footer ────────────────────────────────────────────────────────────
ax.add_patch(FancyBboxPatch(
    (1.5, 0.08), 11.0, 0.48,
    boxstyle="round,pad=0.05", linewidth=1.5,
    edgecolor="#D1D5DB", facecolor="#F9FAFB", zorder=3
))
ax.text(7.0, 0.33,
        "Published: IEEE  |  Code: github.com/sid1985/api-centric-ai-security",
        ha="center", va="center", fontsize=12,
        color="#1A56DB", fontweight="bold", zorder=4)

plt.tight_layout(pad=0.2)
out = OUT / "slide5_research_glance.png"
plt.savefig(out, dpi=180, bbox_inches="tight", facecolor="#FFFFFF")
plt.close()
print(f"[+] Saved → {out}")
