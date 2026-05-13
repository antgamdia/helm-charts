#!/usr/bin/env python3
"""
Manage CVE remediation PRs: check for existing PRs, close outdated ones,
update values.yaml files, and create new PRs.
"""

import json
import os
import subprocess
import re
import sys
import glob
from pathlib import Path


def update_values_files(base_image, current_version, target_version, charts_dir='charts'):
    """Find and update all values.yaml files containing the image reference using regex (preserves comments)."""
    values_files_to_update = []
    charts_path = Path(charts_dir)

    # Find all values.yaml files in charts directory
    values_files = list(charts_path.rglob('values.yaml'))

    print(f"  🔍 Searching {len(values_files)} values.yaml files for {base_image}:{current_version}")

    # Extract just the repository name for matching (e.g., "rabbitmq" from "docker.io/rabbitmq")
    repo_name = base_image.split('/')[-1]

    for values_file in values_files:
        try:
            with open(values_file, 'r') as f:
                content = f.read()

            original_content = content
            updates = []

            # Pattern 1: tag: "version" or tag: version (after repository line)
            # This preserves all formatting, comments, and whitespace
            pattern1 = re.compile(
                r'(repository:\s*["\']?' + re.escape(repo_name) + r'["\']?\s*\n\s*.*?\n\s*tag:\s*["\']?)' +
                re.escape(current_version) + r'(["\']?)',
                re.MULTILINE | re.DOTALL
            )

            # Pattern 2: Simple tag: "version" anywhere (more lenient)
            pattern2 = re.compile(
                r'(\n\s*tag:\s*["\']?)' + re.escape(current_version) + r'(["\']?)',
                re.MULTILINE
            )

            # Try pattern 1 first (more specific - repository + tag)
            new_content, count1 = pattern1.subn(r'\g<1>' + target_version + r'\g<2>', content)
            if count1 > 0:
                content = new_content
                updates.append(('tag (after repository)', current_version, target_version))
            # Try pattern 2 (tag only, less specific)
            elif re.search(repo_name, content, re.IGNORECASE):
                # Only use pattern 2 if the file mentions this image
                new_content, count2 = pattern2.subn(r'\g<1>' + target_version + r'\g<2>', content)
                if count2 > 0:
                    content = new_content
                    updates.append(('tag', current_version, target_version))

            if updates and content != original_content:
                # Write back to file (preserves all comments and formatting)
                with open(values_file, 'w') as f:
                    f.write(content)

                for path, old_val, new_val in updates:
                    print(f"  ✅ Updated {values_file}: {path}: {old_val} → {new_val}")

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
    # Try to create PR with labels first
    label_args = []
    for label in labels:
        label_args.extend(['--label', label])

    result = subprocess.run([
        'gh', 'pr', 'create',
        '--title', pr_title,
        '--body', pr_body,
        *label_args
    ], capture_output=True, text=True)

    # If failed due to labels, retry without labels
    if result.returncode != 0 and 'not found' in result.stderr.lower():
        print(f"    ⚠️  Labels not found, creating PR without labels")
        result = subprocess.run([
            'gh', 'pr', 'create',
            '--title', pr_title,
            '--body', pr_body
        ], capture_output=True, text=True)

    return result


def update_sarif_with_pr(sarif_file, pr_url, cves_fixed):
    """Add PR URL to SARIF file as remediation link."""
    try:
        with open(sarif_file, 'r') as f:
            sarif_data = json.load(f)

        # Add fixes to each result matching the CVEs we're fixing
        if 'runs' in sarif_data and sarif_data['runs']:
            for run in sarif_data['runs']:
                for result in run.get('results', []):
                    cve_id = result.get('ruleId', '')
                    if cve_id in cves_fixed:
                        # Add fixes array with PR link
                        if 'fixes' not in result:
                            result['fixes'] = []
                        result['fixes'].append({
                            'description': {
                                'text': f'Remediation PR: {pr_url}'
                            }
                        })

        # Write updated SARIF
        with open(sarif_file, 'w') as f:
            json.dump(sarif_data, f, indent=2)

        return True
    except Exception as e:
        print(f"  ⚠️  Failed to update SARIF {sarif_file}: {e}", file=sys.stderr)
        return False


def manage_prs(image_updates_file='image_updates.json', charts_dir='charts', dry_run=False, sarif_dir='sarif-results'):
    """Main function to manage remediation PRs."""
    # Load image updates
    with open(image_updates_file) as f:
        image_updates = json.load(f)

    if not image_updates:
        print("No updates needed")
        return 0

    # Get GitHub repository info from environment or git remote
    github_repo = os.environ.get('GITHUB_REPOSITORY')
    if not github_repo:
        # Try to extract from git remote
        result = subprocess.run(['git', 'config', '--get', 'remote.origin.url'], capture_output=True, text=True)
        if result.returncode == 0:
            remote_url = result.stdout.strip()
            # Extract owner/repo from git@github.com:owner/repo.git or https://github.com/owner/repo
            match = re.search(r'github\.com[:/](.+/.+?)(\.git)?$', remote_url)
            if match:
                github_repo = match.group(1)

    github_run_id = os.environ.get('GITHUB_RUN_ID')
    github_server_url = os.environ.get('GITHUB_SERVER_URL', 'https://github.com')

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

        # Ensure we're starting from a clean state on main
        subprocess.run(['git', 'checkout', 'main'], check=True)
        subprocess.run(['git', 'pull', 'origin', 'main'], check=True)

        # Check if branch already exists (locally or remotely)
        local_branch_exists = subprocess.run(['git', 'rev-parse', '--verify', branch_name], capture_output=True).returncode == 0
        remote_branch_exists = subprocess.run(['git', 'ls-remote', '--heads', 'origin', branch_name], capture_output=True, text=True).stdout.strip() != ''

        branch_exists = local_branch_exists or remote_branch_exists

        if branch_exists:
            location = []
            if local_branch_exists:
                location.append('locally')
            if remote_branch_exists:
                location.append('remotely')
            print(f"  ℹ️  Branch '{branch_name}' already exists {' and '.join(location)}, will create PR from existing branch")
        else:
            # Create and checkout new branch
            subprocess.run(['git', 'checkout', '-b', branch_name], check=True)

            # Stage only the values.yaml files we updated
            for file in values_files_to_update:
                subprocess.run(['git', 'add', file], check=True)

            # Verify we're only committing the files we intended
            status_result = subprocess.run(['git', 'status', '--porcelain'], capture_output=True, text=True)
            staged_files = [line[3:] for line in status_result.stdout.split('\n') if line.startswith('A  ') or line.startswith('M  ')]

            unexpected_files = set(staged_files) - set(values_files_to_update)
            if unexpected_files:
                print(f"  ⚠️  Warning: Unexpected files would be committed: {unexpected_files}")
                print(f"  ℹ️  Continuing with only the intended files...")

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

        # Add links to Security alerts
        if github_repo:
            # Link to Code Scanning alerts filtered by this container category
            category = re.sub(r'[^a-zA-Z0-9-]', '-', base_image)
            security_url = f'{github_server_url}/{github_repo}/security/code-scanning?query=is:open+tool:Trivy'
            pr_body += f'📊 **[View Security Alerts]({security_url})**\n\n'

        # Link to workflow run that detected these CVEs
        if github_repo and github_run_id:
            workflow_url = f'{github_server_url}/{github_repo}/actions/runs/{github_run_id}'
            pr_body += f'🔍 **[Workflow Run]({workflow_url})** that detected these vulnerabilities\n\n'

        pr_body += f'## CVEs Fixed ({len(cves_fixed)} total)\n'
        for cve in cves_fixed[:10]:
            # Link each CVE to NVD database
            pr_body += f'- [{cve}](https://nvd.nist.gov/vuln/detail/{cve})\n'
        if len(cves_fixed) > 10:
            pr_body += f'- ...and {len(cves_fixed) - 10} more\n'

        pr_body += '\n## Changes\n'
        for file in values_files_to_update:
            pr_body += f'- Updated `{file}` to use version `{target_version}`\n'

        pr_body += '\n## Test Plan\n'
        pr_body += '- [ ] Verify Helm chart renders correctly\n'
        pr_body += '- [ ] Verify deployment works with new image version\n'
        pr_body += '- [ ] Confirm CVEs are resolved in security scan\n\n'

        pr_body += '---\n'
        pr_body += '🤖 Generated by CVE Scan Workflow'

        result = create_pr(branch_name, pr_title, pr_body, [pr_label, 'security', 'automated'])

        if result.returncode == 0:
            pr_url = result.stdout.strip()
            print(f"  ✅ Created PR: {pr_url}")

            # Update SARIF file to reference this PR
            sarif_pattern = os.path.join(sarif_dir, f'*{label_safe_name}*-trivy-results.sarif')
            sarif_files = glob.glob(sarif_pattern)

            if sarif_files:
                for sarif_file in sarif_files:
                    print(f"  🔗 Linking SARIF {os.path.basename(sarif_file)} to PR")
                    if update_sarif_with_pr(sarif_file, pr_url, cves_fixed):
                        print(f"  ✅ Updated SARIF with PR link")
            else:
                print(f"  ⚠️  No SARIF file found matching {sarif_pattern}", file=sys.stderr)
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
    parser.add_argument('--sarif-dir', default='sarif-results', help='Directory containing SARIF files to update')
    parser.add_argument('--dry-run', action='store_true', help='Dry run mode (no git operations)')
    args = parser.parse_args()

    sys.exit(manage_prs(args.input, args.charts_dir, args.dry_run, args.sarif_dir))


if __name__ == '__main__':
    main()
