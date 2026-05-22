#!/usr/bin/env bash
# Step 4: Update Values Files
# Updates Helm chart values.yaml files with new image version
#
# Exit codes:
#   0 = Success (files updated)
#   1 = Error (file not found, yq failed)
#   2 = No files to update (image not referenced in charts)
#
# Usage: 04-update-values.sh <image-analysis-json> <upgrade-plan-json> <charts-dir> <output-json>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

# === INPUT VALIDATION ===
if [ $# -lt 4 ]; then
  log_error "Usage: $0 <image-analysis-json> <upgrade-plan-json> <charts-dir> <output-json>"
  exit 1
fi

ANALYSIS_FILE="$1"
UPGRADE_FILE="$2"
CHARTS_DIR="$3"
OUTPUT_FILE="$4"

# Check dependencies
check_deps jq yq find grep || exit 1

# Validate inputs
validate_json "$ANALYSIS_FILE" "Image analysis" || exit 1
validate_json "$UPGRADE_FILE" "Upgrade plan" || exit 1

if [ ! -d "$CHARTS_DIR" ]; then
  log_error "Charts directory not found: $CHARTS_DIR"
  exit 1
fi

# === EXTRACT DATA ===
BASE_IMAGE=$(jq -r '.base_image' "$ANALYSIS_FILE")
CURRENT_TAG=$(jq -r '.current_tag' "$ANALYSIS_FILE")
TARGET_TAG=$(jq -r '.target_tag' "$UPGRADE_FILE")

if [ -z "$TARGET_TAG" ] || [ "$TARGET_TAG" = "null" ]; then
  log_error "No target tag in upgrade plan"
  exit 1
fi

log_info "Updating values files: $CURRENT_TAG → $TARGET_TAG"

# === FIND AND UPDATE VALUES FILES ===
UPDATED_FILES=()

# Find all values.yaml files in charts directory
while IFS= read -r -d '' values_file; do
  log_info "Checking: $values_file"

  # Check if this file references the base image repository
  if ! grep -q "$BASE_IMAGE" "$values_file"; then
    log_info "  → Image not referenced, skipping"
    continue
  fi

  log_info "  → Updating image tag"

  # Create backup
  cp "$values_file" "${values_file}.bak"

  # Try to update with yq first (structured update)
  if yq eval ".. |= (select(. == \"$CURRENT_TAG\") | \"$TARGET_TAG\")" "$values_file" > "${values_file}.tmp" 2>/dev/null; then
    mv "${values_file}.tmp" "$values_file"
    rm "${values_file}.bak"
    UPDATED_FILES+=("$values_file")
    log_success "  ✓ Updated: $values_file"
  else
    # Fallback to sed for simple tag replacement
    if sed -i.bak "s|$CURRENT_TAG|$TARGET_TAG|g" "$values_file"; then
      rm "${values_file}.bak"
      UPDATED_FILES+=("$values_file")
      log_success "  ✓ Updated (sed): $values_file"
    else
      # Restore backup on failure
      mv "${values_file}.bak" "$values_file"
      log_error "  ✗ Failed to update: $values_file"
    fi
  fi
done < <(find "$CHARTS_DIR" -name "values.yaml" -type f -print0)

# === OUTPUT RESULT ===
UPDATE_COUNT=${#UPDATED_FILES[@]}

if [ $UPDATE_COUNT -gt 0 ]; then
  # Build array of updated files
  FILES_JSON=$(printf '%s\n' "${UPDATED_FILES[@]}" | jq -Rs @json | jq -s '.')

  OUTPUT_JSON=$(jq -n \
    --argjson files "$FILES_JSON" \
    --argjson count "$UPDATE_COUNT" \
    '{
      "updated_files": $files,
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
