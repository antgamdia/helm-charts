# GitHub Workflows Scripts

Python scripts used by GitHub Actions workflows for CVE scanning, SBOM generation, and automated remediation.

## Scripts Overview

| Script | Purpose | Used By |
|--------|---------|---------|
| `merge_sboms.py` | Merge multiple CycloneDX SBOM files | `generate-report` job |
| `generate_images_lock.py` | Generate ImagesLock from SBOMs | `generate-report` job |
| `parse_cve_fixes.py` | Extract CVE fix versions from SARIF | `create-remediation-prs` job |
| `manage_remediation_prs.py` | Create/manage CVE fix PRs | `create-remediation-prs` job |
| `test_update_values.py` | Test values.yaml updates locally | Local testing only |

## Detailed Documentation

### `merge_sboms.py`

Merges multiple CycloneDX SBOM JSON files into a single consolidated SBOM.

**Usage:**
```bash
python merge_sboms.py [--input-dir DIR] [--output FILE] [--pattern GLOB]
```

**Options:**
- `--input-dir`: Directory containing SBOM files (default: current directory)
- `--output`: Output merged SBOM filename (default: `sbom.cyclonedx.json`)
- `--pattern`: Glob pattern for SBOM files (default: `*-sbom.json`)

**Example:**
```bash
python .github/scripts/merge_sboms.py --input-dir reports --output sbom.cyclonedx.json
```

### `generate_images_lock.py`

Generates an ImagesLock YAML file from SBOM files, extracting image digests and chart information.

**Usage:**
```bash
python generate_images_lock.py [--sbom-dir DIR] [--output FILE] [--charts-dir DIR] [--chart-hint NAME]
```

**Options:**
- `--sbom-dir`: Directory containing SBOM files (default: current directory)
- `--output`: Output ImagesLock filename (default: `images-lock.yaml`)
- `--charts-dir`: Path to charts directory relative to sbom-dir (default: `../charts`)
- `--chart-hint`: Preferred chart name (default: `trento-server`)

**Example:**
```bash
python .github/scripts/generate_images_lock.py --sbom-dir reports --charts-dir charts
```

### `parse_cve_fixes.py`

Parses SARIF files from Trivy scans to extract CVE fix information and determine target versions.

**Usage:**
```bash
python parse_cve_fixes.py <sarif_dir> <output_json>
```

**Example:**
```bash
python .github/scripts/parse_cve_fixes.py sarif-results image_updates.json
```

**Output:** JSON file mapping images to their recommended updates:
```json
{
  "docker.io/rabbitmq:3.12.6-management-alpine": {
    "base_image": "docker.io/rabbitmq",
    "current_version": "3.12.6-management-alpine",
    "target_version": "3.13.0-management-alpine",
    "cves_fixed": ["CVE-2024-1234", "CVE-2024-5678"]
  }
}
```

### `manage_remediation_prs.py`

Manages CVE remediation PRs: checks for existing PRs, closes outdated ones, updates values.yaml files, and creates new PRs.

**Usage:**
```bash
python manage_remediation_prs.py [--input FILE] [--charts-dir DIR] [--dry-run]
```

**Options:**
- `--input`: Input JSON file with image updates (default: `image_updates.json`)
- `--charts-dir`: Path to charts directory (default: `charts`)
- `--dry-run`: Dry run mode - no git operations or PR creation

**Example:**
```bash
# Dry run to see what would happen
python .github/scripts/manage_remediation_prs.py --dry-run

# Actually create PRs
python .github/scripts/manage_remediation_prs.py
```

### `test_update_values.py`

Test script to verify values.yaml updates work correctly before running in CI.

**Usage:**
```bash
python test_update_values.py <base_image> <current_version> <target_version> [--apply]
```

**Example:**
```bash
# Dry run - show what would be updated
python .github/scripts/test_update_values.py "docker.io/rabbitmq" "3.12.6-management-alpine" "3.13.0-management-alpine"

# Apply changes
python .github/scripts/test_update_values.py "docker.io/rabbitmq" "3.12.6-management-alpine" "3.13.0-management-alpine" --apply
```

## Testing Locally

### 1. Test values.yaml update logic

Test that the script correctly finds and updates image references:

```bash
cd /path/to/trento-helm-charts

# Test with a known image from your charts
python .github/scripts/test_update_values.py \
  "registry.suse.com/suse/postgres" \
  "14" \
  "15"
```

This will show you which files would be updated without actually modifying them.

### 2. Test CVE parsing (requires SARIF files)

If you have SARIF files from a previous scan:

```bash
# Download artifacts from a previous workflow run
gh run download <run-id> --name scan-results-docker-io-alpine-3-19

# Parse the SARIF
python .github/scripts/parse_cve_fixes.py . test_output.json

# Check the output
cat test_output.json
```

### 3. Test PR management in dry-run mode

```bash
# Create a test image_updates.json manually
cat > test_updates.json << 'EOF'
{
  "docker.io/alpine:3.19": {
    "base_image": "docker.io/alpine",
    "current_version": "3.19",
    "target_version": "3.20",
    "cves_fixed": ["CVE-2024-TEST"]
  }
}
EOF

# Test PR management (dry run - no actual changes)
python .github/scripts/manage_remediation_prs.py \
  --input test_updates.json \
  --dry-run
```

## Dependencies

```bash
pip install packaging pyyaml
```

## How It Works

1. **CVE Scan** → Trivy generates SARIF files with vulnerability information
2. **Parse** → `parse_cve_fixes.py` extracts fix versions and determines target version per image
3. **Update** → `manage_remediation_prs.py` finds image references in values.yaml recursively
4. **PR** → Creates/updates PRs with consolidated fixes for each image

## Design Decisions

### Dynamic values.yaml Discovery

Instead of hardcoding image-to-file mappings, the scripts:
- Recursively search all `values.yaml` files in the charts directory
- Match images by `repository` field or inline `image:` references
- Support nested YAML structures at any depth
- Handle both `repository + tag` and `image: full:tag` formats

This means the scripts automatically adapt to:
- New containers added to charts
- New sub-charts
- Changed YAML structures
- No maintenance needed when chart structure evolves

### Single PR per Image

If an image has multiple CVEs:
- CVE_1 fixed in v2
- CVE_2 fixed in v3

The system creates ONE PR to upgrade to v3 (the maximum version that fixes all CVEs).

If a PR already exists for v2, and a new scan reveals CVE_2 requiring v3, the old PR is automatically closed and superseded.
