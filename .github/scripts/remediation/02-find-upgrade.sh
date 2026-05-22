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
if ! ALL_TAGS=$(list_image_tags "$BASE_IMAGE" 2>/dev/null); then
  log_error "Failed to query registry for $BASE_IMAGE"
  exit 1
fi

# Convert to array for processing
mapfile -t TAG_ARRAY <<< "$ALL_TAGS"
log_info "Found ${#TAG_ARRAY[@]} total tags"

# === FIND COMPATIBLE VERSIONS ===
# Parse current tag to get suffix (e.g., "-alpine", "-management")
IFS='|' read -r current_version current_suffix <<< "$(parse_version "$CURRENT_TAG")"

log_info "Current version: $current_version, suffix: '$current_suffix'"

# Find compatible tags (matching suffix, higher version)
COMPATIBLE_TAGS=()
for tag in "${TAG_ARRAY[@]}"; do
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
  if [ $? -eq 1 ]; then
    # tag_version > current_version
    COMPATIBLE_TAGS+=("$tag")
  fi
done

COMPATIBLE_COUNT=${#COMPATIBLE_TAGS[@]}
log_info "Found $COMPATIBLE_COUNT compatible upgrades (matching suffix)"

# === DETERMINE TARGET VERSION ===
TARGET_TAG=""
UPGRADE_AVAILABLE="false"

if [ $COMPATIBLE_COUNT -gt 0 ]; then
  # Take the highest compatible version (first in our sorted list)
  TARGET_TAG="${COMPATIBLE_TAGS[0]}"
  UPGRADE_AVAILABLE="true"
  log_success "Target upgrade: $TARGET_TAG"
else
  log_info "No upgrade available (already latest compatible version)"
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

# Exit with appropriate code
if [ "$UPGRADE_AVAILABLE" = "true" ]; then
  log_success "Upgrade available"
  exit 0
else
  log_info "No upgrade needed"
  exit 2
fi
