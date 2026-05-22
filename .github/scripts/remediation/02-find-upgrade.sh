#!/usr/bin/env bash
# Step 2: Query Registry for Available Versions
# Queries container registry and determines best upgrade version
#
# Exit codes:
#   0 = Success (upgrade available)
#   1 = Error (registry query failed)
#   2 = No upgrade needed (already latest)
#
# Usage: 02-find-upgrade.sh <image-analysis-json> <output-json>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

# === INPUT VALIDATION ===
if [ $# -lt 2 ]; then
  log_error "Usage: $0 <image-analysis-json> <output-json>"
  exit 1
fi

INPUT_FILE="$1"
OUTPUT_FILE="$2"

# Check dependencies
check_deps jq skopeo || exit 1

# Validate input
validate_json "$INPUT_FILE" "Image analysis" || exit 1

# === EXTRACT INPUT DATA ===
BASE_IMAGE=$(jq -r '.base_image' "$INPUT_FILE")
CURRENT_TAG=$(jq -r '.current_tag' "$INPUT_FILE")

log_info "Finding upgrades for: $BASE_IMAGE:$CURRENT_TAG"

# === QUERY REGISTRY ===
log_info "Querying registry for available tags..."

# Get all available tags
ALL_TAGS=$(list_image_tags "$BASE_IMAGE" 2>/dev/null) || {
  log_error "Failed to query registry for $BASE_IMAGE"
  exit 1
}

# Validate we got some tags
if [ -z "$ALL_TAGS" ]; then
  log_error "No tags returned from registry for $BASE_IMAGE"
  exit 1
fi

# Convert to array for processing
mapfile -t TAG_ARRAY <<< "$ALL_TAGS"
TAG_COUNT=${#TAG_ARRAY[@]}
if [ "$TAG_COUNT" -eq 0 ]; then
  log_error "Failed to parse tags from registry output"
  exit 1
fi
log_info "Found $TAG_COUNT total tags"

# === FIND COMPATIBLE VERSIONS ===
# Parse current tag to get suffix (e.g., "-alpine", "-management")
IFS='|' read -r current_version current_suffix <<< "$(parse_version "$CURRENT_TAG")"

log_info "Current version: $current_version, suffix: '$current_suffix'"

# Find highest compatible tag (matching suffix, higher version)
# Since tags are sorted highest-first, we take the first match
TARGET_TAG=""
CHECKED=0

for tag in "${TAG_ARRAY[@]}"; do
  ((CHECKED++))

  # Parse tag
  tag_version=""
  tag_suffix=""
  IFS='|' read -r tag_version tag_suffix <<< "$(parse_version "$tag")"

  # Skip if version is not numeric
  if [[ ! "$tag_version" =~ ^[0-9] ]]; then
    continue
  fi

  # If current has a suffix, only match tags with same suffix
  if [[ -n "$current_suffix" ]]; then
    if [[ "$tag_suffix" != "$current_suffix" ]]; then
      continue
    fi
  fi

  # Check if this tag is newer than current
  compare_semver "$tag_version" "$current_version"
  cmp_result=$?

  if [ $cmp_result -eq 1 ]; then
    # tag_version > current_version (and tags are sorted descending)
    # So this is the highest compatible version
    TARGET_TAG="$tag"
    break
  fi

  # Stop if we've checked enough tags (optimization for large registries)
  if [ $CHECKED -gt 500 ]; then
    log_warning "Stopped checking after 500 tags (registry has many tags)"
    break
  fi
done

COMPATIBLE_COUNT=0
if [ -n "$TARGET_TAG" ]; then
  COMPATIBLE_COUNT=1
  log_info "Found compatible upgrade: $TARGET_TAG"
else
  log_warning "No compatible upgrades found"
  log_info "  Checked $CHECKED of $TAG_COUNT total tags"
  log_info "  Current: version=$current_version, suffix='$current_suffix'"
  if [ "${#TAG_ARRAY[@]}" -gt 0 ]; then
    log_info "  Sample tags: ${TAG_ARRAY[0]} ${TAG_ARRAY[1]:-} ${TAG_ARRAY[2]:-}"
  fi
fi

# === DETERMINE UPGRADE STATUS ===
UPGRADE_AVAILABLE="false"
SKIP="false"

if [ -n "$TARGET_TAG" ]; then
  UPGRADE_AVAILABLE="true"
  log_success "Upgrade available: $TARGET_TAG"
else
  SKIP="true"
fi

# === OUTPUT RESULT ===
OUTPUT_JSON=$(jq -n \
  --arg target_tag "$TARGET_TAG" \
  --argjson upgrade_available "$UPGRADE_AVAILABLE" \
  --argjson all_tags_count "${#TAG_ARRAY[@]}" \
  --argjson compatible_tags_count "$COMPATIBLE_COUNT" \
  '{
    "target_tag": (($target_tag | length > 0) | if . then $target_tag else null end),
    "upgrade_available": $upgrade_available,
    "all_tags_count": $all_tags_count,
    "compatible_tags_count": $compatible_tags_count
  }')

output_json "$OUTPUT_FILE" "$OUTPUT_JSON" || exit 1

# Set output variables for workflow
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "skip=$SKIP" >> "$GITHUB_OUTPUT"
  if [ "$SKIP" = "true" ]; then
    echo "skip_reason=already-latest" >> "$GITHUB_OUTPUT"
  else
    echo "target_version=$TARGET_TAG" >> "$GITHUB_OUTPUT"
  fi
fi

exit 0
