#!/usr/bin/env python3
"""
Parse SARIF files from Trivy scans to extract CVE fix information
and determine target versions for image updates.
"""

import json
import glob
import re
import os
import sys
from pathlib import Path
from packaging import version


def parse_sarif_files(sarif_dir):
    """Parse SARIF files and extract CVE fix information."""
    image_cves = {}  # {image_name: {cve_id: {severity, fixed_version}}}

    for sarif_file in glob.glob(f'{sarif_dir}/*-trivy-results.sarif'):
        filename = Path(sarif_file).stem.replace('-trivy-results', '')

        # Load image reference from metadata file
        info_file = os.path.join(sarif_dir, f'{filename}-image-info.json')
        image_ref = None

        if os.path.exists(info_file):
            try:
                with open(info_file) as f:
                    info = json.load(f)
                    image_ref = info.get('image')
            except Exception as e:
                print(f"⚠️  Could not read metadata file {info_file}: {e}", file=sys.stderr)

        if not image_ref:
            print(f"⚠️  No image metadata found for {sarif_file}, skipping", file=sys.stderr)
            continue

        print(f"Processing {image_ref}")

        with open(sarif_file) as f:
            sarif = json.load(f)

        # Parse vulnerabilities
        if 'runs' not in sarif or not sarif['runs']:
            continue

        run = sarif['runs'][0]
        results = run.get('results', [])

        if image_ref not in image_cves:
            image_cves[image_ref] = {}

        for result in results:
            rule_id = result.get('ruleId', '')
            if not rule_id:
                continue

            # Get severity
            level = result.get('level', 'warning')

            # Find the rule to get fix information
            rule = None
            for r in run.get('tool', {}).get('driver', {}).get('rules', []):
                if r.get('id') == rule_id:
                    rule = r
                    break

            if not rule:
                continue

            # Extract fixed version from rule properties
            fixed_version = None
            if 'properties' in rule:
                props = rule['properties']
                fixed_version = props.get('fixed-version') or props.get('fixedVersion')

                # Sometimes it's in the solution field
                if not fixed_version and 'solution' in props:
                    solution = props['solution']
                    # Try to extract version from solution text
                    match = re.search(r'(?:version\s+)?(\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?)', solution, re.IGNORECASE)
                    if match:
                        fixed_version = match.group(1)

            # Store CVE info
            image_cves[image_ref][rule_id] = {
                'severity': level,
                'fixed_version': fixed_version
            }

            if fixed_version:
                print(f"  {rule_id}: fixed in {fixed_version}")
            else:
                print(f"  {rule_id}: no fix available")

    return image_cves


def determine_target_versions(image_cves):
    """Determine target version for each image based on CVE fixes."""
    image_updates = {}  # {image_ref: {current_version, target_version, cves_fixed}}

    for image_ref, cves in image_cves.items():
        # Extract current version from image reference
        match = re.match(r'(.+):(.+)', image_ref)
        if not match:
            print(f"⚠️  Could not parse version from {image_ref}", file=sys.stderr)
            continue

        base_image = match.group(1)
        current_version = match.group(2)

        # Find all fixable CVEs and their versions
        fixable_versions = []
        cves_with_fixes = []

        for cve_id, cve_data in cves.items():
            fixed_ver = cve_data.get('fixed_version')
            if fixed_ver:
                fixable_versions.append(fixed_ver)
                cves_with_fixes.append(cve_id)

        if not fixable_versions:
            print(f"ℹ️  No fixable CVEs for {image_ref}")
            continue

        # Determine the maximum version (that fixes ALL CVEs)
        try:
            # Parse versions and find max
            parsed_versions = []
            for v in fixable_versions:
                try:
                    parsed_versions.append((v, version.parse(v)))
                except Exception as e:
                    print(f"⚠️  Could not parse version {v}: {e}", file=sys.stderr)

            if not parsed_versions:
                continue

            # Sort and get the highest version
            parsed_versions.sort(key=lambda x: x[1])
            target_version = parsed_versions[-1][0]

            # Only create update if target > current
            try:
                if version.parse(target_version) > version.parse(current_version):
                    image_updates[image_ref] = {
                        'base_image': base_image,
                        'current_version': current_version,
                        'target_version': target_version,
                        'cves_fixed': cves_with_fixes
                    }
                    print(f"✅ Update available: {image_ref} → {base_image}:{target_version} (fixes {len(cves_with_fixes)} CVEs)")
            except Exception as e:
                print(f"⚠️  Could not compare versions for {image_ref}: {e}", file=sys.stderr)
                # If version comparison fails, still suggest the update
                image_updates[image_ref] = {
                    'base_image': base_image,
                    'current_version': current_version,
                    'target_version': target_version,
                    'cves_fixed': cves_with_fixes
                }
        except Exception as e:
            print(f"⚠️  Error processing versions for {image_ref}: {e}", file=sys.stderr)

    return image_updates


def main():
    sarif_dir = sys.argv[1] if len(sys.argv) > 1 else 'sarif-results'
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'image_updates.json'

    print(f"📂 Parsing SARIF files from {sarif_dir}")
    image_cves = parse_sarif_files(sarif_dir)

    print(f"\n🔍 Determining target versions")
    image_updates = determine_target_versions(image_cves)

    # Write results
    with open(output_file, 'w') as f:
        json.dump(image_updates, f, indent=2)

    print(f"\n📊 Summary: {len(image_updates)} image(s) with available updates")
    print(f"📄 Results written to {output_file}")

    # Set GitHub Actions output if running in CI
    if 'GITHUB_OUTPUT' in os.environ:
        has_updates = len(image_updates) > 0
        with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
            f.write(f"has_updates={'true' if has_updates else 'false'}\n")


if __name__ == '__main__':
    main()
