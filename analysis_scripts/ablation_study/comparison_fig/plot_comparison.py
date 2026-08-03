#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Draw the comparison figure of FPR, FNR, and New GC for three methods
"""

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# Set the chart style
plt.style.use('default')
plt.rcParams['figure.facecolor'] = 'white'
plt.rcParams['axes.facecolor'] = 'white'
matplotlib.rcParams['pdf.fonttype'] = 42
matplotlib.rcParams['ps.fonttype'] = 42

def read_data(csv_file, column_order=None):
    """Read the CSV data"""
    df = pd.read_csv(csv_file)

    if column_order:
        # Reorder columns according to specified order
        df = df[['Metrics'] + column_order] if 'Metrics' in df.columns else df[['Tool'] + column_order]

    # Get the method name (first row, except the first column)
    methods = df.columns[1:].tolist()

    # Parse the data
    fpr_values = []
    fnr_values = []
    new_gc_values = []

    # Get the data by row index
    fpr_row = df.iloc[0]  # FPR row
    fnr_row = df.iloc[1]  # FNR row
    new_gc_row = df.iloc[2]  # #New_GC row

    for i in range(1, len(fpr_row)):  # Skip the first column (label column)
        # Convert the percentage to a number
        fpr_values.append(float(fpr_row.iloc[i].rstrip('%')))
        fnr_values.append(float(fnr_row.iloc[i].rstrip('%')))
        new_gc_values.append(int(new_gc_row.iloc[i]))

    return methods, fpr_values, fnr_values, new_gc_values

def create_plot(csv_file='ablation.csv', output_file='ablation_comparison.pdf',
                column_order=None, gc_ylim=210, figsize=(7, 3)):
    """Create the comparison figure"""

    # Read the data
    methods, fpr_values, fnr_values, new_gc_values = read_data(csv_file, column_order)

    # Create the figure
    fig, ax1 = plt.subplots(figsize=figsize)

    # Set the x-axis position
    x = np.arange(len(methods))
    width = 0.2  # Decrease the bar width

    # Define the color and fill style
    fpr_color = '#E8E8E8'  # Light gray
    fnr_color = '#D0D0D0'  # Darker gray

    # Create the bar chart - use different fill patterns
    ax1.bar(x - width/2, fpr_values, width,
            label='FPR',
            color=fpr_color,
            hatch='///',  # Slash pattern
            edgecolor='black',
            linewidth=1.5,
            alpha=0.8)

    ax1.bar(x + width/2, fnr_values, width,
            label='FNR',
            color=fnr_color,
            hatch='xxx', # Cross grid
            edgecolor='gray',
            linewidth=1.5,
            alpha=0.8)

    # Set the main coordinate axis
    ax1.set_ylabel('FPR/FNR (%)', fontsize=14, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(methods, fontsize=12, fontweight='bold')
    ax1.set_ylim(0, max(max(fpr_values), max(fnr_values)) * 1.15)

    # Beautiful bar chart labels
    for i, (fpr, fnr) in enumerate(zip(fpr_values, fnr_values)):
        # FPR label
        ax1.text(i - width/2, fpr + 1.5, f'{fpr:.1f}%',
                ha='center', va='bottom', fontweight='bold', fontsize=12)
        # FNR label
        ax1.text(i + width/2, fnr + 1.5, f'{fnr:.1f}%',
                ha='center', va='bottom', fontweight='bold', fontsize=12)

    # Create the secondary coordinate axis
    ax2 = ax1.twinx()

    # Create the line chart - blue line, black data points
    ax2.plot(x, new_gc_values,
             color='blue',
             alpha=0.5,
             linewidth=4,
             marker='o',
             markersize=10,
             markerfacecolor='black',
             markeredgecolor='black',
             markeredgewidth=2,
             label='#New GCs',
             zorder=10)  # Ensure the line is on top

    # Set the secondary coordinate axis
    ax2.set_ylabel('#New GCs', fontsize=14, fontweight='bold')
    ax2.set_ylim(0, gc_ylim)

    # Line chart data point labels (with overlap detection against FPR labels)
    ax1_ylim = ax1.get_ylim()[1]
    for i, gc_count in enumerate(new_gc_values):
        # Compute normalized positions to detect overlap with FPR label
        fpr_label_norm = (fpr_values[i] + 1.5) / ax1_ylim
        gc_label_norm = (gc_count + 8) / gc_ylim
        gc_offset = 8
        if abs(fpr_label_norm - gc_label_norm) < 0.06:
            # Shift GC label higher to avoid overlap
            gc_offset = 8 + (0.06 - abs(fpr_label_norm - gc_label_norm)) * gc_ylim + 5
        ax2.text(i, gc_count + gc_offset, str(gc_count),
                ha='center', va='bottom', fontweight='bold',
                fontsize=12, color='black',)

    # Create the combined legend
    bars_handles, bars_labels = ax1.get_legend_handles_labels()
    line_handles, line_labels = ax2.get_legend_handles_labels()

    # Merge the legend
    all_handles = bars_handles + line_handles
    all_labels = bars_labels + line_labels
    ax1.legend(all_handles, all_labels, loc='upper center',
               bbox_to_anchor=(0.5, 1.2), fontsize=10,
               ncol=3)

    # Add grid
    ax1.grid(True, alpha=0.3, linestyle='--', linewidth=0.5)
    ax1.set_axisbelow(True)

    # Set the coordinate axis style
    for spine in ax1.spines.values():
        spine.set_linewidth(1.5)
    for spine in ax2.spines.values():
        spine.set_linewidth(1.5)

    ax1.spines['top'].set_visible(False)
    ax2.spines['top'].set_visible(False)

    # Set the tick style
    ax1.tick_params(axis='both', which='major', labelsize=11, width=1.5)
    ax2.tick_params(axis='both', which='major', labelsize=11, width=1.5)

    # Adjust the layout
    plt.tight_layout()

    # Save the image
    plt.savefig(output_file, dpi=300, bbox_inches='tight',
                facecolor='white', edgecolor='none')

    plt.close()

    return fig, (ax1, ax2)

if __name__ == "__main__":
    print("Generating comparison charts...")
    print("=" * 50)

    # 1. Ablation study (with specified column order)
    ablation_order = ['SA', 'SA_LLMD', 'SA_SemReach', 'SA_LLMC', 'GadgetHunter']
    create_plot('ablation.csv', 'ablation_comparison.pdf',
                column_order=ablation_order, gc_ylim=220)
    print("Generated: ablation_comparison.pdf")

    # 2. RQ1 FP/FN comparison (7 tools, use CSV original order, wider figure)
    create_plot('RQ1_FP_FN.csv', 'RQ1_FP_FN.pdf', gc_ylim=210, figsize=(9, 3))
    print("Generated: RQ1_FP_FN.pdf")

    print("\nAll charts generated!")
