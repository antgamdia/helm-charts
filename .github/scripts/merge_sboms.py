#!/usr/bin/env python3
"""
Merge multiple CycloneDX SBOM JSON files into a single SBOM.
"""

import json
import glob
import sys
from pathlib import Path


def merge_sboms(input_dir='.', output_file='sbom.cyclonedx.json', pattern='*-sbom.json'):
    """Merge SBOM files in the given directory."""
    input_path = Path(input_dir)
    sbom_files = sorted(input_path.glob(pattern))

    if not sbom_files:
        print("No SBOM files found")
        return 1

    print(f"Found {len(sbom_files)} SBOM files to merge")

    # Load first SBOM as base
    with open(sbom_files[0]) as f:
        merged = json.load(f)

    print(f"Using {sbom_files[0]} as base")

    # Merge components from remaining SBOMs
    for sbom_file in sbom_files[1:]:
        print(f"Merging {sbom_file}")
        with open(sbom_file) as f:
            sbom_data = json.load(f)
            if 'components' in sbom_data:
                if 'components' not in merged:
                    merged['components'] = []
                merged['components'].extend(sbom_data['components'])

    # Write merged SBOM
    output_path = input_path / output_file
    with open(output_path, 'w') as f:
        json.dump(merged, f, indent=2)

    print(f"✅ Merged {len(sbom_files)} SBOMs into {output_path}")
    return 0


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Merge CycloneDX SBOM files')
    parser.add_argument('--input-dir', default='.', help='Directory containing SBOM files')
    parser.add_argument('--output', default='sbom.cyclonedx.json', help='Output merged SBOM file')
    parser.add_argument('--pattern', default='*-sbom.json', help='Glob pattern for SBOM files')
    args = parser.parse_args()

    return merge_sboms(args.input_dir, args.output, args.pattern)


if __name__ == '__main__':
    sys.exit(main())
