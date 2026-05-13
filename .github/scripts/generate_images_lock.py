#!/usr/bin/env python3
"""
Generate ImagesLock YAML file from SBOM files.
Extracts image digests and chart information to create a lock file.
"""

import yaml
import json
import os
import re
import glob
import sys
from datetime import datetime, timezone
from pathlib import Path


def generate_images_lock(
    sbom_dir='.',
    output_file='images-lock.yaml',
    charts_dir='../charts',
    chart_name_hint='trento-server'
):
    """Generate ImagesLock file from SBOM files."""

    # Extract chart info from Chart.yaml (auto-detect)
    chart_name = 'unknown'
    chart_version = 'unknown'
    app_version = 'unknown'

    charts_path = Path(sbom_dir) / charts_dir

    print(f"Debug: sbom_dir={os.path.abspath(sbom_dir)}")
    print(f"Debug: charts_dir={os.path.abspath(charts_path)}")
    print(f"Debug: charts_dir.exists()={charts_path.exists()}")

    if charts_path.exists():
        # Find all Chart.yaml files
        chart_files = list(charts_path.glob('*/Chart.yaml'))
        print(f"Debug: Found {len(chart_files)} Chart.yaml files")

        if chart_files:
            # Prefer chart_name_hint if it exists
            preferred = [f for f in chart_files if chart_name_hint in str(f)]
            chart_yaml = preferred[0] if preferred else chart_files[0]

            try:
                with open(chart_yaml) as f:
                    chart_data = yaml.safe_load(f)
                    chart_name = chart_data.get('name', 'unknown')
                    chart_version = chart_data.get('version', 'unknown')
                    app_version = chart_data.get('appVersion', 'unknown')
                    print(f"✅ Found chart: {chart_yaml} ({chart_name} {chart_version})")
            except Exception as e:
                print(f"⚠️  Could not read {chart_yaml}: {e}", file=sys.stderr)
        else:
            print(f"⚠️  No Chart.yaml files found in {charts_path}", file=sys.stderr)
    else:
        print(f"⚠️  Charts directory not found at {charts_path}", file=sys.stderr)

    # Extract image info from SBOM files to get all architectures
    image_info = {}
    sbom_pattern = os.path.join(sbom_dir, '*-sbom.json')

    for sbom_file in glob.glob(sbom_pattern):
        if os.path.isfile(sbom_file):
            try:
                with open(sbom_file) as f:
                    sbom_data = json.load(f)

                if 'metadata' in sbom_data and 'component' in sbom_data['metadata']:
                    component = sbom_data['metadata']['component']
                    name = component.get('name')
                    purl = component.get('purl')

                    if name and purl:
                        # Extract arch from purl (e.g., ?arch=amd64)
                        arch_match = re.search(r'arch=([a-z0-9-]+)', purl)
                        arch = arch_match.group(1) if arch_match else 'amd64'

                        # Extract digest from purl
                        digest_match = re.search(r'@(sha256:[a-f0-9]+)', purl)
                        digest = digest_match.group(1) if digest_match else 'sha256:unknown'

                        # Support multiple architectures per image
                        if name not in image_info:
                            image_info[name] = {'digests': []}

                        # Check if this arch already exists
                        arch_exists = any(d['arch'] == f'linux/{arch}' for d in image_info[name]['digests'])
                        if not arch_exists:
                            image_info[name]['digests'].append({
                                'digest': digest,
                                'arch': f'linux/{arch}'
                            })
            except Exception as e:
                print(f"Warning: Failed to parse {sbom_file}: {e}", file=sys.stderr)

    if not image_info:
        print("⚠️  No image information extracted from SBOM files", file=sys.stderr)
        return 1

    # Build ImagesLock
    images_lock = {
        'apiVersion': 'v0',
        'kind': 'ImagesLock',
        'metadata': {
            'generatedAt': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'generatedBy': 'SUSE LLC'
        },
        'chart': {
            'name': chart_name,
            'version': chart_version,
            'appVersion': app_version
        },
        'images': []
    }

    # Add each scanned image
    for original_image in sorted(image_info.keys()):
        # Extract image name for display
        image_name = original_image.split('/')[-1].split(':')[0]
        digests = image_info[original_image]['digests']

        images_lock['images'].append({
            'name': image_name,
            'image': original_image,
            'chart': chart_name,
            'digests': digests
        })

    # Write ImagesLock file
    output_path = os.path.join(sbom_dir, output_file)
    with open(output_path, 'w') as f:
        yaml.dump(images_lock, f, default_flow_style=False, sort_keys=False)

    print(f"✅ Generated {output_path}")
    print(f"   Chart: {chart_name} {chart_version}")
    print(f"   Images: {len(images_lock['images'])}")

    return 0


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Generate ImagesLock file from SBOM files')
    parser.add_argument('--sbom-dir', default='.', help='Directory containing SBOM files')
    parser.add_argument('--output', default='images-lock.yaml', help='Output ImagesLock file')
    parser.add_argument('--charts-dir', default='../charts', help='Path to charts directory (relative to sbom-dir)')
    parser.add_argument('--chart-hint', default='trento-server', help='Preferred chart name to use')
    args = parser.parse_args()

    return generate_images_lock(args.sbom_dir, args.output, args.charts_dir, args.chart_hint)


if __name__ == '__main__':
    sys.exit(main())
