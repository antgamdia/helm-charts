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


def extract_revision(v):
    """
    Extract Alpine-style revision number from version string.
    Examples: 1.2.3-r6 -> 6, 1.2.3-management-r2 -> 2
    Returns: (base_version, revision_number)
    """
    match = re.search(r'-r(\d+)$', v)
    if match:
        revision = int(match.group(1))
        base_version = v[:match.start()]
        return (base_version, revision)
    return (v, 0)


def normalize_version(v):
    """
    Normalize a version string to make it parseable by packaging.version.
    Handles common non-semver patterns like:
    - 3.12.6-management-alpine -> 3.12.6
    - 1.2.4_git20230717-r6 -> 1.2.4
    Returns: (parsed_version, revision_number)
    """
    # Extract revision suffix first (-r1, -r2, etc.)
    base_v, revision = extract_revision(v)

    # Try parsing the base version as-is first
    try:
        return (version.parse(base_v), revision)
    except:
        pass

    # Extract semver-like part (X.Y.Z optionally followed by -prerelease)
    # Match patterns like: 1.2.3, 1.2.3-alpha, 1.2.3-rc.1
    match = re.match(r'^(\d+\.\d+(?:\.\d+)?(?:-(?:alpha|beta|rc)[\w.]*)?)', base_v)
    if match:
        try:
            return (version.parse(match.group(1)), revision)
        except:
            pass

    # If all else fails, return the original string for lexicographic comparison
    return (base_v, revision)


def compare_versions(v1, v2):
    """
    Compare two version strings, with fallback to string comparison.
    Handles Alpine-style revisions (-r1, -r2, etc.)
    Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2
    """
    try:
        norm_v1, rev1 = normalize_version(v1)
        norm_v2, rev2 = normalize_version(v2)

        # If both are Version objects, compare them
        if isinstance(norm_v1, version.Version) and isinstance(norm_v2, version.Version):
            if norm_v1 < norm_v2:
                return -1
            elif norm_v1 > norm_v2:
                return 1
            else:
                # Base versions equal, compare revisions
                if rev1 < rev2:
                    return -1
                elif rev1 > rev2:
                    return 1
                else:
                    return 0
        # Otherwise fall back to string comparison
        else:
            if v1 < v2:
                return -1
            elif v1 > v2:
                return 1
            else:
                return 0
    except:
        # Final fallback: string comparison
        if v1 < v2:
            return -1
        elif v1 > v2:
            return 1
        else:
            return 0


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

            # Extract fixed version from rule
            fixed_version = None

            # Try 1: properties.fixed-version / fixedVersion
            if 'properties' in rule:
                props = rule['properties']
                fixed_version = props.get('fixed-version') or props.get('fixedVersion')

                # Try 2: properties.solution field
                if not fixed_version and 'solution' in props:
                    solution = props['solution']
                    match = re.search(r'(?:version\s+)?(\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?)', solution, re.IGNORECASE)
                    if match:
                        fixed_version = match.group(1)

            # Try 3: rule.help.text (Trivy format)
            if not fixed_version and 'help' in rule:
                help_text = rule['help'].get('text', '')
                match = re.search(r'Fixed Version:\s*([^\s\n]+)', help_text)
                if match:
                    fixed_version = match.group(1)

            # Try 4: result.message.text (Trivy format)
            if not fixed_version:
                msg_text = result.get('message', {}).get('text', '')
                match = re.search(r'Fixed Version:\s*([^\s\n]+)', msg_text)
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
            # Parse and sort versions to find max
            parsed_versions = []
            for v in fixable_versions:
                norm_v, rev = normalize_version(v)
                parsed_versions.append((v, norm_v, rev))

            if not parsed_versions:
                continue

            # Sort by normalized version and revision
            def version_sort_key(item):
                _, norm_v, rev = item
                if isinstance(norm_v, version.Version):
                    return (0, norm_v, rev)  # Version objects sort first
                else:
                    return (1, norm_v, rev)  # Strings sort after

            parsed_versions.sort(key=version_sort_key)
            target_version = parsed_versions[-1][0]

            # Only create update if target > current
            if compare_versions(target_version, current_version) > 0:
                image_updates[image_ref] = {
                    'base_image': base_image,
                    'current_version': current_version,
                    'target_version': target_version,
                    'cves_fixed': cves_with_fixes
                }
                print(f"✅ Update available: {image_ref} → {base_image}:{target_version} (fixes {len(cves_with_fixes)} CVEs)")
            else:
                print(f"ℹ️  Target version {target_version} is not newer than current {current_version}, skipping")
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
