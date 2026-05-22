#!/usr/bin/env bash
# Step 1: Analyze SARIF & Extract CVE Info
# Parses SARIF files and extracts vulnerability/image metadata
#
# Exit codes:
#   0 = Success
#   1 = Error (missing files, invalid SARIF)
#   2 = Skip (non-semantic version tag)
#
# Usage: 01-analyze-sarif.sh <sarif-results-dir> <output-json>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

# === INPUT VALIDATION ===
if [ $# -lt 2 ]; then
  log_error "Usage: $0 <sarif-results-dir> <output-json>"
  exit 1
fi

SARIF_DIR="$1"
OUTPUT_FILE="$2"

# Check dependencies
check_deps jq find || exit 1

# Check input directory exists
if [ ! -d "$SARIF_DIR" ]; then
  log_error "SARIF results directory not found: $SARIF_DIR"
  exit 1
fi

# === MAIN LOGIC ===
log_info "Analyzing SARIF files in: $SARIF_DIR"

# Find SARIF file (there should be exactly one per matrix iteration)
mapfile -t sarif_files < <(find "$SARIF_DIR" -name "*.sarif" -type f)

if [ ${#sarif_files[@]} -eq 0 ]; then
  log_error "No SARIF files found in $SARIF_DIR"
  exit 1
fi

# Use the first (and typically only) SARIF file
SARIF_FILE="${sarif_files[0]}"
log_info "Processing: $(basename "$SARIF_FILE")"

# Find image-info.json file
mapfile -t image_info_files < <(find "$SARIF_DIR" -name "*-image-info.json" -type f)

if [ ${#image_info_files[@]} -eq 0 ]; then
  log_error "No image-info.json found in $SARIF_DIR"
  exit 1
fi

IMAGE_INFO_FILE="${image_info_files[0]}"
log_info "Using image info: $(basename "$IMAGE_INFO_FILE")"

# Validate JSON files
validate_json "$SARIF_FILE" "SARIF" || exit 1
validate_json "$IMAGE_INFO_FILE" "Image info" || exit 1

# Extract image reference from image-info.json
IMAGE_REF=$(jq -r '.image' "$IMAGE_INFO_FILE")
log_info "Image reference: $IMAGE_REF"

# Parse image reference into components
# Format: [registry/][repository/]name[:tag]
# Extract everything before the last colon as base, everything after as tag
if [[ "$IMAGE_REF" == *:* ]]; then
  BASE_IMAGE="${IMAGE_REF%:*}"
  CURRENT_TAG="${IMAGE_REF##*:}"
else
  BASE_IMAGE="$IMAGE_REF"
  CURRENT_TAG="latest"
fi

log_info "Parsed: base=$BASE_IMAGE, tag=$CURRENT_TAG"

# Check if tag is a semantic version using parse_version
# This handles v-prefixed tags like v2.53.1 correctly
parsed=$(parse_version "$CURRENT_TAG")
IFS='|' read -r parsed_version parsed_suffix <<< "$parsed"

HAS_SEMANTIC_VERSION="true"
SKIP="false"

# If parse_version returned empty version (invalid), it's not semantic
if [[ -z "$parsed_version" ]] || [[ ! "$parsed_version" =~ ^[0-9] ]]; then
  log_warning "Non-semantic version tag: $CURRENT_TAG (skipping remediation)"
  HAS_SEMANTIC_VERSION="false"
  SKIP="true"
else
  log_info "Semantic version detected: $parsed_version"
fi

# Extract CVEs from SARIF
mapfile -t CVE_ARRAY < <(extract_cves_from_sarif "$SARIF_FILE")

# Convert CVE array to JSON array format
CVE_JSON=$(printf '%s\n' "${CVE_ARRAY[@]}" | jq -Rs 'split("\n") | map(select(length > 0))')

# Build output JSON
OUTPUT_JSON=$(jq -n \
  --arg image_ref "$IMAGE_REF" \
  --arg base_image "$BASE_IMAGE" \
  --arg current_tag "$CURRENT_TAG" \
  --argjson has_semantic "$HAS_SEMANTIC_VERSION" \
  --argjson cves "$CVE_JSON" \
  '{
    "image_ref": $image_ref,
    "base_image": $base_image,
    "current_tag": $current_tag,
    "cves": $cves,
    "has_semantic_version": ($has_semantic | not | not)
  }')

output_json "$OUTPUT_FILE" "$OUTPUT_JSON" || exit 1

log_success "SARIF analysis complete"
log_info "Found $(echo "$OUTPUT_JSON" | jq '.cves | length') CVEs"

# Set output variables for workflow
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "skip=$SKIP" >> "$GITHUB_OUTPUT"
  if [ "$SKIP" = "true" ]; then
    echo "skip_reason=non-semantic-version" >> "$GITHUB_OUTPUT"
  fi
fi

exit 0
