#!/usr/bin/env bash
# Step 5: Create/Update Pull Request
# Creates or updates PR with the remediation changes
#
# Exit codes:
#   0 = Success (PR created/updated)
#   1 = Error (git/gh operations failed)
#   2 = No action needed (PR already exists with same version)
#
# Usage: 05-manage-pr.sh <image-analysis-json> <upgrade-plan-json> <values-updates-json> <output-json>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

# === INPUT VALIDATION ===
if [ $# -lt 4 ]; then
  log_error "Usage: $0 <image-analysis-json> <upgrade-plan-json> <values-updates-json> <output-json>"
  exit 1
fi

ANALYSIS_FILE="$1"
UPGRADE_FILE="$2"
VALUES_FILE="$3"
OUTPUT_FILE="$4"

# Check environment and dependencies
: "${GITHUB_REPOSITORY:?Error: GITHUB_REPOSITORY environment variable not set}"
: "${GITHUB_TOKEN:?Error: GITHUB_TOKEN environment variable not set}"

check_deps jq git gh || exit 1

# Validate inputs
validate_json "$ANALYSIS_FILE" "Image analysis" || exit 1
validate_json "$UPGRADE_FILE" "Upgrade plan" || exit 1
validate_json "$VALUES_FILE" "Values updates" || exit 1

# === EXTRACT DATA ===
IMAGE_REF=$(jq -r '.image_ref' "$ANALYSIS_FILE")
BASE_IMAGE=$(jq -r '.base_image' "$ANALYSIS_FILE")
CURRENT_TAG=$(jq -r '.current_tag' "$ANALYSIS_FILE")
TARGET_TAG=$(jq -r '.target_tag' "$UPGRADE_FILE")
CVE_ARRAY=$(jq -r '.cves[]?' "$ANALYSIS_FILE" | head -c 500)
UPDATED_FILES=$(jq -r '.updated_files[]?' "$VALUES_FILE")

if [ -z "$TARGET_TAG" ] || [ "$TARGET_TAG" = "null" ]; then
  log_error "No target tag in upgrade plan"
  exit 1
fi

# Extract image name (last component after /)
IMAGE_NAME="${BASE_IMAGE##*/}"

log_info "Creating PR for: $IMAGE_NAME ($CURRENT_TAG → $TARGET_TAG)"

# === GIT SETUP ===
log_info "Configuring git..."

git config --local user.name "github-actions[bot]" 2>/dev/null || true
git config --local user.email "github-actions[bot]@users.noreply.github.com" 2>/dev/null || true

# Ensure we're on a clean main branch
git checkout main >/dev/null 2>&1 || {
  log_error "Failed to checkout main branch"
  exit 1
}

git pull origin main >/dev/null 2>&1 || {
  log_warning "Could not pull latest main"
}

# === BRANCH MANAGEMENT ===
# Create a safe branch name from the image and version
BRANCH_NAME="cve-fix/${IMAGE_NAME}-${TARGET_TAG//[^a-zA-Z0-9.-]/-}"
# Remove multiple consecutive dashes and trim trailing dashes
BRANCH_NAME=$(echo "$BRANCH_NAME" | sed 's/-\+/-/g' | sed 's/-$//')

log_info "Using branch: $BRANCH_NAME"

# Check if branch already exists locally
if git rev-parse --verify "$BRANCH_NAME" >/dev/null 2>&1; then
  log_info "Branch exists locally, checking for existing PR"
  git checkout "$BRANCH_NAME" >/dev/null 2>&1 || {
    log_error "Failed to checkout existing branch"
    exit 1
  }
else
  log_info "Creating new branch"
  git checkout -b "$BRANCH_NAME" >/dev/null 2>&1 || {
    log_error "Failed to create branch"
    exit 1
  }
fi

# === COMMIT CHANGES ===
if [ -z "$UPDATED_FILES" ]; then
  log_warning "No files to update in PR"
  git checkout main >/dev/null 2>&1 || true
  git branch -D "$BRANCH_NAME" >/dev/null 2>&1 || true

  OUTPUT_JSON=$(jq -n '{
    "pr_number": null,
    "pr_url": null,
    "action_taken": "no_changes",
    "branch_name": null
  }')

  output_json "$OUTPUT_FILE" "$OUTPUT_JSON" || exit 1
  exit 0
fi

# Stage updated files
while IFS= read -r file; do
  [ -n "$file" ] && git add "$file"
done <<< "$UPDATED_FILES"

# Build commit message
COMMIT_MSG="[CVE Fix] Update $IMAGE_NAME to $TARGET_TAG"

CVE_COUNT=$(jq '.cves | length' "$ANALYSIS_FILE")
if [ "$CVE_COUNT" -gt 0 ]; then
  COMMIT_MSG+="

Addresses $CVE_COUNT security vulnerabilities"
fi

# Commit changes
if ! git commit -m "$COMMIT_MSG" >/dev/null 2>&1; then
  log_warning "Nothing to commit (no changes)"
  git checkout main >/dev/null 2>&1 || true
  git branch -D "$BRANCH_NAME" >/dev/null 2>&1 || true

  OUTPUT_JSON=$(jq -n '{
    "pr_number": null,
    "pr_url": null,
    "action_taken": "no_changes",
    "branch_name": null
  }')

  output_json "$OUTPUT_FILE" "$OUTPUT_JSON" || exit 1
  exit 0
fi

# Push branch
if ! git push -u origin "$BRANCH_NAME" >/dev/null 2>&1; then
  log_error "Failed to push branch"
  git checkout main >/dev/null 2>&1
  git branch -D "$BRANCH_NAME" >/dev/null 2>&1 || true
  exit 1
fi

log_success "Branch pushed"

# === PR CREATION/UPDATE ===
log_info "Checking for existing PR..."

# Check if PR already exists for this branch
EXISTING_PR=$(gh pr list --head "$BRANCH_NAME" --json number --jq '.[0].number' 2>/dev/null || echo "")

if [ -n "$EXISTING_PR" ] && [ "$EXISTING_PR" != "null" ]; then
  log_info "PR #$EXISTING_PR already exists for this branch"

  OUTPUT_JSON=$(jq -n \
    --argjson pr_num "$EXISTING_PR" \
    --arg branch "$BRANCH_NAME" \
    '{
      "pr_number": $pr_num,
      "pr_url": "https://github.com/'"$GITHUB_REPOSITORY"'/pull/\($pr_num)",
      "action_taken": "already_exists",
      "branch_name": $branch
    }')

  output_json "$OUTPUT_FILE" "$OUTPUT_JSON" || exit 1
  exit 2
fi

# Create new PR
PR_TITLE="[CVE Fix] Update $IMAGE_NAME to $TARGET_TAG"
LABEL_SAFE="${BASE_IMAGE//[^a-zA-Z0-9-]/-}"

# Build PR body
PR_BODY="## Summary
Updates \`$BASE_IMAGE\` from \`$CURRENT_TAG\` to \`$TARGET_TAG\` to address security vulnerabilities.
"

if [ "$CVE_COUNT" -gt 0 ]; then
  PR_BODY+="
## 🔒 Vulnerabilities Fixed ($CVE_COUNT total)

This update addresses the following CVEs:
"
  jq -r '.cves[]?' "$ANALYSIS_FILE" | head -10 | while read -r cve; do
    PR_BODY+="- [\`$cve\`](https://nvd.nist.gov/vuln/detail/$cve)
"
  done
  if [ "$CVE_COUNT" -gt 10 ]; then
    PR_BODY+="- ... and $((CVE_COUNT - 10)) more CVEs
"
  fi
fi

PR_BODY+="
## Changes

Updated files:
"
echo "$UPDATED_FILES" | while read -r file; do
  [ -n "$file" ] && PR_BODY+="- \`$file\`
"
done

PR_BODY+="
---
Generated by automated CVE remediation workflow"

# Create PR
log_info "Creating PR: $PR_TITLE"

if PR_OUTPUT=$(gh pr create --title "$PR_TITLE" --body "$PR_BODY" \
     --label "cve-fix" --label "security" --label "automated" 2>/dev/null); then
  PR_NUM=$(echo "$PR_OUTPUT" | grep -oE '#[0-9]+' | head -1 | tr -d '#')
  PR_URL="https://github.com/$GITHUB_REPOSITORY/pull/$PR_NUM"

  log_success "Created PR #$PR_NUM"

  OUTPUT_JSON=$(jq -n \
    --argjson pr_num "$PR_NUM" \
    --arg pr_url "$PR_URL" \
    --arg branch "$BRANCH_NAME" \
    '{
      "pr_number": $pr_num,
      "pr_url": $pr_url,
      "action_taken": "created",
      "branch_name": $branch
    }')

  output_json "$OUTPUT_FILE" "$OUTPUT_JSON" || exit 1
  exit 0
else
  log_error "Failed to create PR"
  exit 1
fi
