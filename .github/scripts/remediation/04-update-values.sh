#!/usr/bin/env bash
# Step 4: Update Chart Files
# Updates all Helm chart files (values.yaml and templates) with new image version
#
# Exit codes:
#   0 = Success (files updated)
#   1 = Error (file not found, sed failed)
#   2 = No files to update (image not referenced in charts)
#
# Usage: 04-update-values.sh <image-analysis-json> <upgrade-plan-json> <charts-dir> <output-json>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

ANALYSIS_FILE="$1"
UPGRADE_FILE="$2"
CHARTS_DIR="$3"
OUTPUT_FILE="$4"

# === EXTRACT DATA ===
BASE_IMAGE=$(jq -r '.base_image' "$ANALYSIS_FILE")
CURRENT_TAG=$(jq -r '.current_tag' "$ANALYSIS_FILE")
TARGET_TAG=$(jq -r '.target_tag' "$UPGRADE_FILE")

if [ -z "$TARGET_TAG" ] || [ "$TARGET_TAG" = "null" ]; then
  log_error "No target tag in upgrade plan"
  exit 1
fi

# Build full image references for search/replace
CURRENT_IMAGE_REF="$BASE_IMAGE:$CURRENT_TAG"
TARGET_IMAGE_REF="$BASE_IMAGE:$TARGET_TAG"

# Extract repository part (after last slash) for matching split image definitions
REPO_ONLY="${BASE_IMAGE##*/}"

log_info "Updating chart files: $CURRENT_TAG → $TARGET_TAG"

# === FIND AND UPDATE CHART FILES ===
UPDATED_FILES=()

# Find all .yaml files in charts directory (values.yaml and templates)
while IFS= read -r -d '' chart_file; do
  log_info "Checking: $chart_file"

  # Check if file references the image (in any format: full or split)
  if ! grep -qE "$BASE_IMAGE|$REPO_ONLY|$CURRENT_TAG" "$chart_file"; then
    log_info "  → Image not referenced, skipping"
    continue
  fi

  log_info "  → Updating image"

  # Create backup
  cp "$chart_file" "${chart_file}.bak"

  # Replace with strict specificity - only update the target image:
  # Strategy 1: Full references (safest - exact match: docker.io/kubectl:v1.33.3)
  # Strategy 2: Split YAML blocks containing the repository (find repo, then update its tag)
  # Uses repository pattern matching to find the RIGHT image block, not just first one

  if sed -i.bak \
    -e "s|$CURRENT_IMAGE_REF|$TARGET_IMAGE_REF|g" \
    -e "/repository:.*$REPO_ONLY/,/^[^ ]/ s|tag: $CURRENT_TAG\$|tag: $TARGET_TAG|g" \
    -e "/repository:.*$REPO_ONLY/,/^[^ ]/ s|tag: \"$CURRENT_TAG\"|tag: \"$TARGET_TAG\"|g" \
    -e "/repository:.*$REPO_ONLY/,/^[^ ]/ s|tag: '$CURRENT_TAG'|tag: '$TARGET_TAG'|g" \
    "$chart_file"; then
    rm "${chart_file}.bak"
    UPDATED_FILES+=("$chart_file")
    log_success "  ✓ Updated: $chart_file"
  else
    # Restore backup on failure
    mv "${chart_file}.bak" "$chart_file"
    log_error "  ✗ Failed to update: $chart_file"
  fi
done < <(find "$CHARTS_DIR" -name "*.yaml" -type f -print0)

# === OUTPUT RESULT ===
UPDATE_COUNT=${#UPDATED_FILES[@]}

if [ $UPDATE_COUNT -gt 0 ]; then
  # Build array of updated files
  OUTPUT_JSON=$(jq -n \
    --arg files "$(printf '%s\n' "${UPDATED_FILES[@]}")" \
    --argjson count "$UPDATE_COUNT" \
    '{
      "updated_files": ($files | split("\n") | map(select(length > 0))),
      "update_count": $count
    }')

  output_json "$OUTPUT_FILE" "$OUTPUT_JSON" || exit 1
  log_success "Updated $UPDATE_COUNT values files"

  # Set output for workflow
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "files_updated=$UPDATE_COUNT" >> "$GITHUB_OUTPUT"
  fi

  exit 0
else
  log_warning "No values files found or no updates needed"

  # Output empty result
  OUTPUT_JSON=$(jq -n '{
    "updated_files": [],
    "update_count": 0
  }')

  output_json "$OUTPUT_FILE" "$OUTPUT_JSON" || exit 1

  # Set output for workflow
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "files_updated=0" >> "$GITHUB_OUTPUT"
  fi

  exit 0
fi
