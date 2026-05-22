# CVE Remediation Pipeline

Multi-step remediation workflow for automatically fixing container image vulnerabilities.

## Overview

This directory contains a 5-step remediation pipeline that replaces the monolithic `cve-remediation.sh` script. Each step has a single responsibility and clear inputs/outputs, making the workflow observable, debuggable, and testable.

## Architecture

```
Step 1: Analyze SARIF          (SARIF files → CVE list)
   ↓
Step 2: Find Upgrade           (Current version → Target version)
   ↓
Step 3: Verify Image           (Target version → Verified existence)
   ↓
Step 4: Update Values Files    (Target version → Updated YAML files)
   ↓
Step 5: Create/Update PR       (Updated files → GitHub PR)
```

## Scripts

### `common.sh`
Shared utilities and functions used by all scripts.

**Provides:**
- Logging functions: `log_info()`, `log_success()`, `log_error()`, `log_warning()`
- Dependency checking: `check_deps()`
- JSON validation: `validate_json()`, `output_json()`
- Version comparison: `parse_version()`, `compare_semver()`
- Image operations: `list_image_tags()`, `find_latest_compatible_tag()`, `verify_image_exists()`
- SARIF parsing: `extract_cves_from_sarif()`

### `01-analyze-sarif.sh`
**Purpose:** Parse SARIF files and extract vulnerability/image metadata

**Inputs:**
- `sarif-results/` directory (from artifact download)
- `*-image-info.json` (contains original image reference)
- `*-trivy-results.sarif` (contains CVE data)

**Outputs:** `image-analysis.json`
```json
{
  "image_ref": "docker.io/postgres:14",
  "base_image": "docker.io/postgres",
  "current_tag": "14",
  "cves": ["CVE-2024-1234", "CVE-2024-5678"],
  "has_semantic_version": true
}
```

**Exit code:** Always `0` (skips signaled via `$GITHUB_OUTPUT`)  
**Skip condition:** Non-semantic version tags (e.g., "latest", "stable")

### `02-find-upgrade.sh`
**Purpose:** Query container registry for available versions and determine upgrade target

**Inputs:** `image-analysis.json` (from Step 1)

**Outputs:** `upgrade-plan.json`
```json
{
  "target_tag": "15.2",
  "upgrade_available": true,
  "all_tags_count": 47,
  "compatible_tags_count": 12
}
```

**Exit code:** Always `0` (skips signaled via `$GITHUB_OUTPUT`)  
**Skip condition:** Already at latest compatible version  
**Logic:**
- Queries registry using skopeo
- Matches suffix compatibility (e.g., `-alpine`, `-management`)
- Finds highest semantic version

### `03-verify-image.sh`
**Purpose:** Verify the target image exists in registry before proceeding

**Inputs:**
- `image-analysis.json` (base image)
- `upgrade-plan.json` (target tag)

**Outputs:** `verification.json`
```json
{
  "verified": true,
  "full_image_ref": "docker.io/postgres:15.2",
  "digest": "sha256:abc123..."
}
```

**Exit code:**
- `0` = Verified successfully
- `1` = Verification failed

**Tools:** skopeo

### `04-update-values.sh`
**Purpose:** Update Helm chart values.yaml files with new image version

**Inputs:**
- `image-analysis.json` (current version, base image)
- `upgrade-plan.json` (target version)
- `charts/` directory path

**Outputs:** `values-updates.json`
```json
{
  "updated_files": [
    "charts/trento-server/values.yaml"
  ],
  "update_count": 1
}
```

**Exit code:** Always `0`  
**Modifies:** `charts/**/values.yaml` files

**Logic:**
- Finds all values.yaml files containing the base image
- Updates with yq (preferred) or sed fallback
- Creates backups before modification

### `05-manage-pr.sh`
**Purpose:** Create or update pull request with the remediation changes

**Inputs:**
- `image-analysis.json` (image info, CVEs)
- `upgrade-plan.json` (version change)
- `values-updates.json` (changed files)

**Outputs:** `pr-result.json`
```json
{
  "pr_number": 123,
  "pr_url": "https://github.com/org/repo/pull/123",
  "action_taken": "created",
  "branch_name": "cve-fix/postgres-15.2"
}
```

**Exit code:**
- `0` = Success (PR created/updated/already exists)
- `1` = Error (git or gh operation failed)

**Modifies:** Git state (branches, commits, PRs)

**Logic:**
- Creates branch named `cve-fix/{image-name}-{version}`
- Commits values.yaml changes
- Creates PR with CVE details
- Handles existing PRs gracefully

## Workflow Integration

The scripts are called from `.github/workflows/cve-scan.yaml` in the `create-remediation-prs` job:

```yaml
- name: 01 - Analyze SARIF & Extract CVE Info
  id: analyze
  run: |
    .github/scripts/remediation/01-analyze-sarif.sh \
      sarif-results \
      image-analysis.json

- name: 02 - Find Upgrade Version
  if: steps.analyze.outputs.skip != 'true'
  id: upgrade
  run: |
    .github/scripts/remediation/02-find-upgrade.sh \
      image-analysis.json \
      upgrade-plan.json

# ... Steps 3-5 follow same pattern
```

### Skip Conditions

Each step can signal skip conditions via `$GITHUB_OUTPUT`:
- Setting `skip=true` prevents dependent steps from running
- Setting `skip_reason` explains why (logged for debugging)
- All steps always exit with code 0 (no red errors in GitHub Actions)

## Data Flow

```
image-analysis.json
└─ image_ref: full image reference
└─ base_image: registry/name
└─ current_tag: current version
└─ cves: array of CVE IDs
└─ has_semantic_version: boolean

upgrade-plan.json
└─ target_tag: new version to upgrade to
└─ upgrade_available: boolean
└─ all_tags_count: total tags in registry
└─ compatible_tags_count: tags matching suffix

verification.json
└─ verified: boolean
└─ full_image_ref: complete image:tag
└─ digest: sha256 digest

values-updates.json
└─ updated_files: array of modified files
└─ update_count: number of files

pr-result.json
└─ pr_number: GitHub PR number
└─ pr_url: GitHub PR URL
└─ action_taken: created|updated|already_exists|no_changes
└─ branch_name: git branch created
```

## Testing

### Unit Test Example

```bash
# Test SARIF analysis
./01-analyze-sarif.sh test-sarif/ output.json
jq '.' output.json

# Test version finding
./02-find-upgrade.sh test-input.json output.json
jq '.target_tag' output.json

# Test values update (dry-run)
cp -r charts charts.test
./04-update-values.sh image.json upgrade.json charts.test/ output.json
git diff charts.test/ charts/
```

### Integration Test

Run the full pipeline with test data:

```bash
# Create test SARIF files
mkdir test-sarif
echo '{"image": "registry.example.com/postgres:14"}' > test-sarif/image-info.json
echo '{"runs": [{"results": [{"ruleId": "CVE-2024-1234"}]}]}' > test-sarif/results.sarif

# Run full pipeline
./01-analyze-sarif.sh test-sarif/ analysis.json
./02-find-upgrade.sh analysis.json plan.json
./03-verify-image.sh analysis.json plan.json verify.json
./04-update-values.sh analysis.json plan.json charts/ values.json
# Skip 05 for testing (requires git/gh setup)
```

## Error Handling

All scripts:
- Use `set -euo pipefail` for safety
- Log all operations to stderr
- Validate inputs before processing
- Check for required tools
- Handle missing files gracefully

Skip conditions (exit 0):
- Non-semantic version tags in Step 1
- Already latest compatible version in Step 2
- No files to update in Step 4
- No changes to commit in Step 5

Actual errors (exit 1):
- Missing or invalid input files
- Registry access failures
- Git operations failure
- GitHub API failures

## Environment Variables

**Required:**
- `GITHUB_REPOSITORY` - GitHub repository (owner/repo)
- `GITHUB_TOKEN` - GitHub API token (Step 5 only)

**Optional:**
- `GITHUB_OUTPUT` - Path to workflow output file (set by GitHub Actions)
- `DRY_RUN` - Not used in split scripts (can be added per-script if needed)

## Common Issues

### "No semantic version found"
Image tag doesn't start with a digit (e.g., "latest", "stable"). Step 1 skips these.
**Solution:** Use semantic versioning in base images (e.g., "postgres:14.5")

### "Failed to list tags"
Registry unreachable or authentication failed.
**Solution:** Check network access, verify base image is public/accessible

### "No values files found"
Base image not referenced in any values.yaml files.
**Solution:** Check if image is used in the Helm chart

### "PR already exists"
Step 5 detects existing PR for the same branch.
**Solution:** Update existing PR or close if no longer needed

## Deprecation

The monolithic `cve-remediation.sh` script is deprecated in favor of this pipeline. It's kept for reference but should not be used for new workflows.

## Performance Notes

- Trivy database is cached at the matrix level (not per-step)
- Registry queries are performed once per image
- Image verification is optional but recommended
- Early skip conditions prevent unnecessary work

## Future Improvements

- [ ] Parallel Step 2-4 execution for multiple images
- [ ] Caching of registry query results
- [ ] Custom notification channels for PR creation
- [ ] Support for rollback on failed PR merges
- [ ] Metrics collection (upgrade time, success rate)
