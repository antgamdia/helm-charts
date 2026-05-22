#!/usr/bin/env bash
# Step 3: Verify Target Image
# Verifies the target image exists in registry before proceeding
#
# Exit codes:
#   0 = Verified successfully
#   1 = Verification failed (image doesn't exist/unreachable)
#
# Usage: 03-verify-image.sh <image-analysis-json> <upgrade-plan-json> <output-json>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

# === INPUT VALIDATION ===
if [ $# -lt 3 ]; then
  log_error "Usage: $0 <image-analysis-json> <upgrade-plan-json> <output-json>"
  exit 1
fi

ANALYSIS_FILE="$1"
UPGRADE_FILE="$2"
OUTPUT_FILE="$3"

# Check dependencies
check_deps jq skopeo || exit 1

# Validate inputs
validate_json "$ANALYSIS_FILE" "Image analysis" || exit 1
validate_json "$UPGRADE_FILE" "Upgrade plan" || exit 1

# === EXTRACT DATA ===
BASE_IMAGE=$(jq -r '.base_image' "$ANALYSIS_FILE")
TARGET_TAG=$(jq -r '.target_tag' "$UPGRADE_FILE")

if [ -z "$TARGET_TAG" ] || [ "$TARGET_TAG" = "null" ]; then
  log_error "No target tag in upgrade plan"
  exit 1
fi

FULL_IMAGE_REF="$BASE_IMAGE:$TARGET_TAG"
log_info "Verifying image: $FULL_IMAGE_REF"

# === VERIFICATION ===
VERIFIED="false"
DIGEST=""

if verify_image_exists "$FULL_IMAGE_REF"; then
  log_success "Image verified in registry"
  VERIFIED="true"

  # Try to get digest for reference
  DIGEST=$(skopeo inspect "docker://$FULL_IMAGE_REF" 2>/dev/null | jq -r '.Digest' || echo "unknown")
else
  log_error "Image verification failed: $FULL_IMAGE_REF"
  VERIFIED="false"
  DIGEST=""
fi

# === OUTPUT RESULT ===
OUTPUT_JSON=$(jq -n \
  --arg full_ref "$FULL_IMAGE_REF" \
  --argjson verified "$VERIFIED" \
  --arg digest "$DIGEST" \
  '{
    "verified": $verified,
    "full_image_ref": $full_ref,
    "digest": $digest
  }')

output_json "$OUTPUT_FILE" "$OUTPUT_JSON" || exit 1

if [ "$VERIFIED" = "true" ]; then
  log_success "Verification complete"
  exit 0
else
  log_error "Verification failed - image cannot be accessed"
  exit 1
fi
