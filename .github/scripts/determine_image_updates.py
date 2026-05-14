#!/usr/bin/env python3
"""
Determine image updates by querying container registries for latest available tags.
This replaces the flawed approach of using CVE "fixed version" (which refers to package versions, not container tags).
"""

import json
import glob
import re
import os
import sys
from pathlib import Path
from packaging import version
import subprocess


def list_image_tags(base_image):
    """List available tags for an image from the registry using skopeo."""
    # Normalize image reference: if no registry specified, assume docker.io
    if '/' not in base_image:
        # Just image name like "rabbitmq" -> docker.io/library/rabbitmq
        base_image = f'docker.io/library/{base_image}'
    elif '.' not in base_image.split('/')[0]:
        # Has namespace but no registry like "myorg/myimage" -> docker.io/myorg/myimage
        base_image = f'docker.io/{base_image}'
    # Otherwise use the registry as-is (registry.suse.com/foo/bar, quay.io/foo/bar, etc.)

    print(f"  🔍 Fetching available tags for {base_image}")

    # Find skopeo command (may be in PATH or in common locations)
    skopeo_cmd = 'skopeo'

    try:
        result = subprocess.run(
            [skopeo_cmd, 'list-tags', f'docker://{base_image}'],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            tags = data.get('Tags', [])
            print(f"  ✅ Found {len(tags)} tags")
            return tags
        else:
            print(f"  ❌ Failed to fetch tags: {result.stderr.strip()}", file=sys.stderr)
            return []
    except FileNotFoundError:
        print(f"  ❌ skopeo not found - please install skopeo", file=sys.stderr)
        return []
    except PermissionError:
        print(f"  ❌ Permission denied running skopeo", file=sys.stderr)
        return []
    except subprocess.TimeoutExpired:
        print(f"  ❌ Timeout fetching tags", file=sys.stderr)
        return []
    except json.JSONDecodeError as e:
        print(f"  ❌ Failed to parse skopeo output: {e}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"  ❌ Error fetching tags: {e}", file=sys.stderr)
        return []


def parse_version_from_tag(tag, suffix_pattern=None):
    """Extract semantic version from a tag, handling common suffixes and prefixes."""
    # If suffix pattern provided, extract version before the suffix
    if suffix_pattern:
        # Support optional 'v' prefix and major-only versions (e.g., "14", "v1")
        match = re.match(rf'^v?([0-9]+(?:\.[0-9]+)?(?:\.[0-9]+)?(?:\.[0-9]+)?){suffix_pattern}', tag)
        if match:
            version_str = match.group(1)
            # Extract the actual suffix from the tag (not the pattern)
            suffix = tag[len(version_str) + (1 if tag.startswith('v') else 0):]
            return version_str, suffix

    # Try to extract version from start of tag
    # Support optional 'v' prefix (kubectl) and major-only versions (postgres:14)
    match = re.match(r'^v?([0-9]+(?:\.[0-9]+)?(?:\.[0-9]+)?(?:\.[0-9]+)?)', tag)
    if match:
        version_str = match.group(1)
        # Extract suffix (everything after version, excluding 'v' prefix)
        offset = len(version_str) + (1 if tag.startswith('v') else 0)
        suffix = tag[offset:]
        return version_str, suffix

    return None, None


def find_latest_compatible_tag(current_tag, available_tags):
    """Find the latest tag that's compatible with (has same suffix as) the current tag."""
    # Parse current tag to get version and suffix
    current_version_str, current_suffix = parse_version_from_tag(current_tag)

    if not current_version_str:
        print(f"  ⚠️  Could not parse version from current tag: {current_tag}", file=sys.stderr)
        return None

    try:
        current_version = version.parse(current_version_str)
    except Exception as e:
        print(f"  ⚠️  Invalid version string '{current_version_str}': {e}", file=sys.stderr)
        return None

    print(f"  📊 Current version: {current_version_str}, suffix: '{current_suffix}'")

    # Find all tags with same suffix
    compatible_tags = []
    for tag in available_tags:
        tag_version_str, tag_suffix = parse_version_from_tag(tag, re.escape(current_suffix) if current_suffix else None)

        if not tag_version_str or tag_suffix != current_suffix:
            continue

        try:
            tag_version = version.parse(tag_version_str)
            if tag_version > current_version:
                compatible_tags.append((tag_version, tag))
        except Exception:
            # Skip unparseable versions
            continue

    if not compatible_tags:
        print(f"  ⚠️  No newer compatible tags found with suffix '{current_suffix}'")
        return None

    # Sort and get the latest
    compatible_tags.sort(reverse=True)
    latest_version, latest_tag = compatible_tags[0]

    print(f"  ✅ Found latest compatible tag: {latest_tag} (version {latest_version})")
    print(f"  📈 Upgrade path: {current_tag} → {latest_tag}")

    return latest_tag


def parse_sarif_for_cves(sarif_dir):
    """Parse SARIF files to extract CVE lists for each image."""
    image_cves = {}  # {image_ref: [cve_id, cve_id, ...]}

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

        cves = []
        for result in results:
            rule_id = result.get('ruleId', '')
            if rule_id:
                cves.append(rule_id)

        image_cves[image_ref] = cves
        print(f"  Found {len(cves)} CVEs")

    return image_cves


def determine_target_versions(image_cves):
    """Determine target version for each image by querying the registry."""
    image_updates = {}

    for image_ref, cves in image_cves.items():
        if not cves:
            print(f"ℹ️  No CVEs found for {image_ref}, skipping")
            continue

        # Extract current version from image reference
        match = re.match(r'(.+):(.+)', image_ref)
        if not match:
            print(f"⚠️  Could not parse version from {image_ref}", file=sys.stderr)
            continue

        base_image = match.group(1)
        current_version = match.group(2)

        print(f"\n🔍 Finding update for {base_image}:{current_version}")

        # Query registry for available tags
        available_tags = list_image_tags(base_image)
        if not available_tags:
            print(f"  ⚠️  Could not fetch tags, skipping")
            continue

        # Find latest compatible tag
        target_version = find_latest_compatible_tag(current_version, available_tags)
        if not target_version:
            print(f"  ℹ️  No newer version found")
            continue

        image_updates[image_ref] = {
            'base_image': base_image,
            'current_version': current_version,
            'target_version': target_version,
            'cves_fixed': cves
        }
        print(f"✅ Update available: {image_ref} → {base_image}:{target_version} (addresses {len(cves)} CVEs)")

    return image_updates


def main():
    sarif_dir = sys.argv[1] if len(sys.argv) > 1 else 'sarif-results'
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'image_updates.json'

    print(f"📂 Parsing SARIF files from {sarif_dir}")
    image_cves = parse_sarif_for_cves(sarif_dir)

    print(f"\n🔍 Querying registries for latest versions")
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
