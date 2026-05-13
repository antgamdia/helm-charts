#!/usr/bin/env python3
"""
Manage CVE remediation PRs: check for existing PRs, close outdated ones,
update values.yaml files, and create new PRs.
"""

import json
import subprocess
import re
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


def update_values_files(base_image, current_version, target_version, charts_dir='charts'):
    """Find and update all values.yaml files containing the image reference."""
    values_files_to_update = []
    charts_path = Path(charts_dir)

    # Find all values.yaml files in charts directory
    values_files = list(charts_path.rglob('values.yaml'))

    print(f"  🔍 Searching {len(values_files)} values.yaml files for {base_image}:{current_version}")

    for values_file in values_files:
        try:
            with open(values_file, 'r') as f:
                values_data = yaml.safe_load(f)

            # Search and update
            updates = find_and_update_image_tag(values_data, [], base_image, current_version, target_version)

            if updates:
                # Write back to file
                with open(values_file, 'w') as f:
                    yaml.dump(values_data, f, default_flow_style=False, sort_keys=False)

                for path, old_val, new_val in updates:
                    path_str = '.'.join(str(p) for p in path)
                    print(f"  ✅ Updated {values_file}: {path_str}: {old_val} → {new_val}")

                values_files_to_update.append(str(values_file))
        except Exception as e:
            print(f"  ⚠️  Failed to process {values_file}: {e}", file=sys.stderr)

    return values_files_to_update


def check_existing_prs(pr_label):
    """Check for existing PRs with the given label."""
    result = subprocess.run(
        ['gh', 'pr', 'list', '--label', pr_label, '--state', 'open', '--json', 'number,title,headRefName'],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        return []

    return json.loads(result.stdout)


def close_pr(pr_number, reason):
    """Close a PR with a comment."""
    subprocess.run([
        'gh', 'pr', 'close', str(pr_number),
        '--comment', reason
    ])


def create_pr(branch_name, pr_title, pr_body, labels):
    """Create a new PR."""
    label_args = []
    for label in labels:
        label_args.extend(['--label', label])

    result = subprocess.run([
        'gh', 'pr', 'create',
        '--title', pr_title,
        '--body', pr_body,
        *label_args
    ], capture_output=True, text=True)

    return result


def manage_prs(image_updates_file='image_updates.json', charts_dir='charts', dry_run=False):
    """Main function to manage remediation PRs."""
    # Load image updates
    with open(image_updates_file) as f:
        image_updates = json.load(f)

    if not image_updates:
        print("No updates needed")
        return 0

    for image_ref, update_info in image_updates.items():
        base_image = update_info['base_image']
        current_version = update_info['current_version']
        target_version = update_info['target_version']
        cves_fixed = update_info['cves_fixed']

        # Extract image name (last part after /)
        image_name = base_image.split('/')[-1]

        # Sanitize for label (alphanumeric and hyphens only)
        label_safe_name = re.sub(r'[^a-zA-Z0-9-]', '-', base_image)
        pr_label = f"cve-fix:{label_safe_name}"

        print(f"\n🔍 Checking PRs for {base_image}")

        # Check for existing PRs with this label
        existing_prs = check_existing_prs(pr_label)
        skip_pr_creation = False

        for pr in existing_prs:
            pr_number = pr['number']
            pr_branch = pr['headRefName']

            # Extract version from branch name (format: cve-fix/image-name/version)
            version_match = re.search(r'cve-fix/[^/]+/(.+)$', pr_branch)
            if version_match:
                existing_version = version_match.group(1)

                if existing_version == target_version:
                    print(f"  ✓ PR #{pr_number} already exists for target version {target_version}")
                    skip_pr_creation = True
                    continue
                else:
                    # Close outdated PR
                    print(f"  🗑️  Closing outdated PR #{pr_number} (targets {existing_version}, need {target_version})")
                    if not dry_run:
                        cve_list = ', '.join(cves_fixed[:5])
                        close_pr(pr_number, f"Superseded by requirement to update to {target_version} to fix additional CVEs: {cve_list}")

        if skip_pr_creation:
            continue

        # Create new PR
        branch_name = f"cve-fix/{label_safe_name}/{target_version}"
        print(f"  📝 Creating PR for {base_image}:{target_version}")

        # Update values.yaml file(s)
        values_files_to_update = update_values_files(base_image, current_version, target_version, charts_dir)

        if not values_files_to_update:
            print(f"  ⚠️  No values.yaml files found containing {base_image}:{current_version}, skipping")
            continue

        if dry_run:
            print(f"  [DRY RUN] Would update files: {', '.join(values_files_to_update)}")
            print(f"  [DRY RUN] Would create branch: {branch_name}")
            continue

        # Configure git
        subprocess.run(['git', 'config', 'user.name', 'github-actions[bot]'], check=True)
        subprocess.run(['git', 'config', 'user.email', 'github-actions[bot]@users.noreply.github.com'], check=True)

        # Create and checkout new branch
        subprocess.run(['git', 'checkout', '-b', branch_name], check=True)

        # Stage changes
        for file in values_files_to_update:
            subprocess.run(['git', 'add', file], check=True)

        # Commit
        cve_list = ', '.join(cves_fixed[:5])
        if len(cves_fixed) > 5:
            cve_list += ' and ' + str(len(cves_fixed) - 5) + ' more'

        commit_msg = f'Update {image_name} to {target_version} to fix CVEs\n\n'
        commit_msg += f'Fixes: {cve_list}'

        subprocess.run(['git', 'commit', '-m', commit_msg], check=True)

        # Push branch
        subprocess.run(['git', 'push', 'origin', branch_name], check=True)

        # Create PR
        pr_title = f'[CVE Fix] Update {image_name} to {target_version}'

        # Build PR body
        pr_body = '## Summary\n'
        pr_body += f'Updates `{base_image}` from `{current_version}` to `{target_version}` to address security vulnerabilities.\n\n'
        pr_body += '## CVEs Fixed\n'
        for cve in cves_fixed[:10]:
            pr_body += f'- {cve}\n'
        if len(cves_fixed) > 10:
            pr_body += f'- ...and {len(cves_fixed) - 10} more\n'
        pr_body += '\n## Changes\n'
        for file in values_files_to_update:
            pr_body += f'- Updated `{file}` to use version `{target_version}`\n'
        pr_body += '\n## Test Plan\n'
        pr_body += '- [ ] Verify Helm chart renders correctly\n'
        pr_body += '- [ ] Verify deployment works with new image version\n'
        pr_body += '- [ ] Confirm CVEs are resolved in security scan\n\n'
        pr_body += '🤖 Generated by CVE Scan Workflow'

        result = create_pr(branch_name, pr_title, pr_body, [pr_label, 'security', 'automated'])

        if result.returncode == 0:
            print(f"  ✅ Created PR: {result.stdout.strip()}")
        else:
            print(f"  ❌ Failed to create PR: {result.stderr}", file=sys.stderr)

        # Return to main branch for next iteration
        subprocess.run(['git', 'checkout', 'main'], check=True)

    return 0


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Manage CVE remediation PRs')
    parser.add_argument('--input', default='image_updates.json', help='Input JSON file with image updates')
    parser.add_argument('--charts-dir', default='charts', help='Path to charts directory')
    parser.add_argument('--dry-run', action='store_true', help='Dry run mode (no git operations)')
    args = parser.parse_args()

    sys.exit(manage_prs(args.input, args.charts_dir, args.dry_run))


if __name__ == '__main__':
    main()
