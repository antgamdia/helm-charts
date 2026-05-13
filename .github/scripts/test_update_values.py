#!/usr/bin/env python3
"""
Test script to verify values.yaml updates work correctly before running in CI.

Usage:
  python .github/scripts/test_update_values.py <base_image> <current_version> <target_version>

Example:
  python .github/scripts/test_update_values.py "docker.io/rabbitmq" "3.12.6-management-alpine" "3.13.0-management-alpine"
"""

import sys
import yaml
from pathlib import Path


def find_and_update_image_tag(data, path, base_image, current_version, target_version):
    """Recursively search for image references and update tags."""
    updates = []

    if isinstance(data, dict):
        # Check if this dict has 'image' or 'repository' field matching our base_image
        if 'repository' in data:
            repo = data['repository']
            # Match either exact repository or full image ref (registry/repo)
            if repo == base_image or base_image.endswith('/' + repo):
                # Check if we have a tag field to update
                if 'tag' in data:
                    old_tag = str(data['tag'])
                    # Only update if it matches current version
                    if old_tag == current_version or old_tag.replace('v', '') == current_version.replace('v', ''):
                        data['tag'] = target_version
                        updates.append((path + ['tag'], old_tag, target_version))

        # Also check for inline image references (e.g., 'image: registry/repo:tag')
        if 'image' in data and isinstance(data['image'], str):
            img = data['image']
            # Check if this is a full image reference containing our base_image
            if base_image in img and ':' in img:
                img_base, img_tag = img.rsplit(':', 1)
                if img_tag == current_version or img_tag.replace('v', '') == current_version.replace('v', ''):
                    data['image'] = img_base + ':' + target_version
                    updates.append((path + ['image'], img, data['image']))

        # Recurse into nested dicts
        for key, value in data.items():
            updates.extend(find_and_update_image_tag(value, path + [key], base_image, current_version, target_version))

    elif isinstance(data, list):
        for idx, item in enumerate(data):
            updates.extend(find_and_update_image_tag(item, path + [f'[{idx}]'], base_image, current_version, target_version))

    return updates


def test_update(base_image, current_version, target_version, charts_dir='charts', dry_run=True):
    """Test updating values.yaml files."""
    charts_path = Path(charts_dir)

    if not charts_path.exists():
        print(f"❌ Charts directory not found: {charts_dir}")
        return 1

    # Find all values.yaml files in charts directory
    values_files = list(charts_path.rglob('values.yaml'))

    print(f"🔍 Searching {len(values_files)} values.yaml files for {base_image}:{current_version}")
    print(f"Target version: {target_version}")
    print(f"Mode: {'DRY RUN' if dry_run else 'LIVE UPDATE'}")
    print()

    total_updates = 0

    for values_file in values_files:
        try:
            with open(values_file, 'r') as f:
                values_data = yaml.safe_load(f)

            # Make a copy for dry run
            import copy
            test_data = copy.deepcopy(values_data)

            # Search and update
            updates = find_and_update_image_tag(test_data, [], base_image, current_version, target_version)

            if updates:
                print(f"📄 {values_file}")
                for path, old_val, new_val in updates:
                    path_str = '.'.join(str(p) for p in path)
                    print(f"  ✏️  {path_str}: {old_val} → {new_val}")
                    total_updates += 1

                if not dry_run:
                    # Write back to file
                    with open(values_file, 'w') as f:
                        yaml.dump(test_data, f, default_flow_style=False, sort_keys=False)
                    print(f"  ✅ Updated {values_file}")
                print()

        except Exception as e:
            print(f"  ⚠️  Failed to process {values_file}: {e}")

    if total_updates == 0:
        print(f"⚠️  No matches found for {base_image}:{current_version}")
        return 1
    else:
        print(f"✅ Found {total_updates} update(s) across {len([f for f in values_files if f])} file(s)")
        if dry_run:
            print()
            print("This was a DRY RUN. To apply changes, run with --apply flag:")
            print(f"  python {sys.argv[0]} {base_image} {current_version} {target_version} --apply")
        return 0


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Test values.yaml image tag updates')
    parser.add_argument('base_image', help='Base image name (e.g., docker.io/rabbitmq)')
    parser.add_argument('current_version', help='Current version tag')
    parser.add_argument('target_version', help='Target version tag')
    parser.add_argument('--charts-dir', default='charts', help='Path to charts directory')
    parser.add_argument('--apply', action='store_true', help='Apply changes (default is dry run)')
    args = parser.parse_args()

    dry_run = not args.apply

    return test_update(args.base_image, args.current_version, args.target_version, args.charts_dir, dry_run)


if __name__ == '__main__':
    sys.exit(main())
