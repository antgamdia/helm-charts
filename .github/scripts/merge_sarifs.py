#!/usr/bin/env python3
"""
Merge multiple SARIF files into a single SARIF file.
"""

import json
import glob
import os
import sys


def merge_sarifs(input_dir='.', output_file='merged.sarif', pattern='*-trivy-results.sarif'):
    """Merge multiple SARIF files into one."""

    sarif_files = glob.glob(os.path.join(input_dir, pattern))

    if not sarif_files:
        print(f"⚠️  No SARIF files found matching {pattern} in {input_dir}", file=sys.stderr)
        return 1

    print(f"📂 Found {len(sarif_files)} SARIF files to merge")

    # Load first SARIF as base
    with open(sarif_files[0]) as f:
        merged = json.load(f)

    print(f"  ✅ Loaded base: {os.path.basename(sarif_files[0])}")

    # Merge remaining SARIF files
    for sarif_file in sarif_files[1:]:
        with open(sarif_file) as f:
            sarif_data = json.load(f)

        # Merge runs from each SARIF
        if 'runs' in sarif_data:
            merged['runs'].extend(sarif_data['runs'])

        print(f"  ✅ Merged: {os.path.basename(sarif_file)}")

    # Write merged SARIF
    with open(output_file, 'w') as f:
        json.dump(merged, f, indent=2)

    print(f"\n✅ Merged SARIF written to {output_file}")
    print(f"   Total runs: {len(merged.get('runs', []))}")

    return 0


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Merge multiple SARIF files')
    parser.add_argument('--input-dir', default='.', help='Directory containing SARIF files')
    parser.add_argument('--output', default='merged.sarif', help='Output merged SARIF filename')
    parser.add_argument('--pattern', default='*-trivy-results.sarif', help='Glob pattern for SARIF files')
    args = parser.parse_args()

    sys.exit(merge_sarifs(args.input_dir, args.output, args.pattern))


if __name__ == '__main__':
    main()
