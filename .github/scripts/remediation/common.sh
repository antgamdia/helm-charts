#!/usr/bin/env bash
# Shared utilities for CVE remediation scripts
# Provides: logging, version comparison, JSON validation

set -euo pipefail

# Validate if a tag is a valid semantic version using semver-tool
# Uses semver --coerce to normalize X.Y to X.Y.0 format
is_valid_semver() {
  local tag="$1"
  local version="${tag#v}"

  # Use semver --coerce to normalize to X.Y.Z format
  local coerced
  coerced=$(semver --coerce "$version" 2>/dev/null)

  # If coerce succeeded and produced output, it's valid
  [ -n "$coerced" ]
}

# Coerce tag to X.Y.Z format using semver binary
coerce_to_semver() {
  local tag="$1"
  local version="${tag#v}"

  # Use semver --coerce to convert X.Y to X.Y.0, etc.
  semver --coerce "$version" 2>/dev/null || echo "$version"
}

# === LOGGING FUNCTIONS ===
log_info() { echo "ℹ️  $*" >&2; }
log_success() { echo "✅ $*" >&2; }
log_error() { echo "❌ $*" >&2; }
log_warning() { echo "⚠️  $*" >&2; }

# === JSON OUTPUT ===
output_json() {
  local file="$1"
  local json="$2"

  echo "$json" | jq . > "$file" 2>/dev/null || {
    log_error "Failed to write JSON to $file"
    return 1
  }

  log_info "Output: $file"
}

# === VERSION COMPARISON FUNCTIONS ===

# Parse version and suffix from tag
# Input: tag (e.g., "3.12.6-management-alpine" or "v3.12.6")
# Output: "3.12.6|−management-alpine"
parse_version() {
  local tag="$1"

  # Remove optional 'v' prefix
  tag="${tag#v}"

  # Extract version (major.minor.patch or major.minor or major)
  # Handles up to 4 components for build versions
  if [[ "$tag" =~ ^([0-9]+(\.[0-9]+)?(\.[0-9]+)?(\.[0-9]+)?) ]]; then
    local version="${BASH_REMATCH[1]}"
    local suffix="${tag#$version}"
    echo "$version|$suffix"
  else
    echo "|$tag"
  fi
}

# Compare two semantic versions using semver tool
# Input: v1 v2 (e.g., "3.12.6" "3.13.0" or "1.2" "1.3")
# Returns: 0 if equal, 1 if v1 > v2, 2 if v1 < v2
compare_semver() {
  local v1="$1"
  local v2="$2"

  # Handle empty/invalid versions
  if [[ -z "$v1" || -z "$v2" ]]; then
    return 0
  fi

  # Use semver to sort both versions (outputs in ascending order)
  local sorted
  sorted=$(semver --coerce "$v1" "$v2" 2>/dev/null)

  # Parse sorted output (first line is lowest, second is highest)
  local lowest
  lowest=$(echo "$sorted" | head -1)

  if [ "$lowest" = "$v1" ]; then
    # v1 was lowest
    if [ "$v1" = "$v2" ]; then
      return 0  # equal
    else
      return 2  # v1 < v2
    fi
  else
    # v2 was lowest, so v1 > v2
    return 1
  fi
}

# List all tags for a container image (newest first)
# Uses skopeo to query registry
# Input: image_ref (e.g., "docker.io/library/busybox")
# Output: newline-separated tags (one per line, sorted newest first)
list_image_tags() {
  local image_ref="$1"

  # Use skopeo to list tags and filter to valid semantic versions only
  # This rejects: latest, main, SHA digests, build IDs (07486), branch names, etc.
  if ! skopeo list-tags "docker://${image_ref}" 2>/dev/null | \
       jq -r '.Tags[]' | while read -r tag; do
    # Check if tag is a valid semantic version (with optional v prefix)
    if is_valid_semver "$tag"; then
      echo "$tag"
    fi
  done | sort -V -r; then
    log_warning "Failed to list tags for $image_ref"
    return 1
  fi
}

