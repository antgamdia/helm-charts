#!/usr/bin/env bash
# Shared utilities for CVE remediation scripts
# Provides: logging, version comparison, JSON validation

set -euo pipefail

# === LOGGING FUNCTIONS ===
log_info() { echo "ℹ️  $*" >&2; }
log_success() { echo "✅ $*" >&2; }
log_error() { echo "❌ $*" >&2; }
log_warning() { echo "⚠️  $*" >&2; }

# === DEPENDENCY CHECK ===
check_deps() {
  local missing=()
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done
  if [ ${#missing[@]} -gt 0 ]; then
    log_error "Missing required tools: ${missing[*]}"
    return 1
  fi
}

# === JSON VALIDATION ===
validate_json() {
  local json_file="$1"
  local description="${2:-JSON}"

  if [ ! -f "$json_file" ]; then
    log_error "JSON file not found: $json_file"
    return 1
  fi

  if ! jq empty "$json_file" 2>/dev/null; then
    log_error "Invalid $description: $json_file"
    return 1
  fi
}

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

# Compare two semantic versions
# Input: v1 v2 (e.g., "3.12.6" "3.13.0")
# Returns: 0 if equal, 1 if v1 > v2, 2 if v1 < v2
compare_semver() {
  local v1="$1"
  local v2="$2"

  # Handle empty/invalid versions
  if [[ -z "$v1" || -z "$v2" ]]; then
    return 0
  fi

  # Split into components
  IFS='.' read -ra V1 <<< "$v1"
  IFS='.' read -ra V2 <<< "$v2"

  # Pad arrays to same length
  local max_len=$((${#V1[@]} > ${#V2[@]} ? ${#V1[@]} : ${#V2[@]}))

  for ((i=0; i<max_len; i++)); do
    local num1=$((${V1[i]:-0}))
    local num2=$((${V2[i]:-0}))

    if ((num1 > num2)); then
      return 1
    elif ((num1 < num2)); then
      return 2
    fi
  done

  return 0
}

# List all tags for a container image (newest first)
# Uses skopeo to query registry
# Input: image_ref (e.g., "docker.io/library/busybox")
# Output: newline-separated tags (one per line)
list_image_tags() {
  local image_ref="$1"

  # Use skopeo to list tags from the registry
  if ! skopeo list-tags "docker://${image_ref}" 2>/dev/null | \
       jq -r '.Tags | reverse | .[]' | sort -V; then
    log_warning "Failed to list tags for $image_ref"
    return 1
  fi
}

# Find latest compatible tag (same suffix, highest version)
# Input: current_tag, available_tags...
# Output: latest compatible tag (or empty if none found)
find_latest_compatible_tag() {
  local current_tag="$1"
  shift
  local available_tags=("$@")

  if [ ${#available_tags[@]} -eq 0 ]; then
    log_warning "No available tags provided"
    return 1
  fi

  # Parse current tag
  IFS='|' read -r current_version current_suffix <<< "$(parse_version "$current_tag")"

  # If current version is not numeric, return empty (non-semantic version)
  if [[ ! "$current_version" =~ ^[0-9] ]]; then
    log_warning "Non-semantic version tag: $current_tag"
    return 1
  fi

  local best_tag=""
  local best_version=""

  for tag in "${available_tags[@]}"; do
    IFS='|' read -r tag_version tag_suffix <<< "$(parse_version "$tag")"

    # Skip if suffix doesn't match (unless current has no suffix)
    if [[ -n "$current_suffix" ]] && [[ "$tag_suffix" != "$current_suffix" ]]; then
      continue
    fi

    # Skip if version is not numeric
    if [[ ! "$tag_version" =~ ^[0-9] ]]; then
      continue
    fi

    # Compare versions
    compare_semver "$tag_version" "$current_version"
    local cmp_result=$?

    # cmp_result: 0 = equal, 1 = tag > current, 2 = tag < current
    if [[ $cmp_result -eq 1 ]]; then
      # tag_version > current_version
      if [[ -z "$best_version" ]]; then
        best_version="$tag_version"
        best_tag="$tag"
      else
        # Compare with best so far
        compare_semver "$tag_version" "$best_version"
        local best_cmp=$?
        if [[ $best_cmp -eq 1 ]]; then
          # tag_version > best_version
          best_version="$tag_version"
          best_tag="$tag"
        fi
      fi
    fi
  done

  if [[ -n "$best_tag" ]]; then
    echo "$best_tag"
    return 0
  fi

  return 1
}

# Verify image exists in registry
# Input: full_image_ref (e.g., "docker.io/library/busybox:1.35")
# Output: JSON with digest if successful
verify_image_exists() {
  local full_image_ref="$1"

  # Use docker buildx imagetools to verify (or skopeo inspect)
  if skopeo inspect "docker://${full_image_ref}" >/dev/null 2>&1; then
    return 0
  else
    log_error "Cannot access image: $full_image_ref"
    return 1
  fi
}

# Extract SARIF results and CVE IDs
# Input: sarif_file path
# Output: JSON array of CVE IDs
extract_cves_from_sarif() {
  local sarif_file="$1"

  if [ ! -f "$sarif_file" ]; then
    log_error "SARIF file not found: $sarif_file"
    return 1
  fi

  jq -r '.runs[]? | .results[]? | .ruleId' "$sarif_file" 2>/dev/null | \
    grep -E '^CVE-' | sort -u || echo ""
}
