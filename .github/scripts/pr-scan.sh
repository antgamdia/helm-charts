#!/usr/bin/env bash
# Detect changed images in PR and generate CVE comment
set -euo pipefail

MODE="${1:-detect}"
OUTPUT_IMAGES_FILE="changed_images.json"
OUTPUT_COMMENT_FILE="comment.md"

log_info() { echo "ℹ️  $*"; }
log_success() { echo "✅ $*"; }
log_warning() { echo "⚠️  $*"; }
log_error() { echo "❌ $*" >&2; }
log_debug() { [ "${DEBUG:-0}" = "1" ] && echo "🔍 $*" || true; }

sanitize_image_name() {
  local image="$1"
  echo -n "$image" | md5sum | cut -c1-12
}

find_scan_file_for_image() {
  local image="$1"
  local safe_name=$(sanitize_image_name "$image")
  find scan-results -path "*trivy-scan-${safe_name}/*-trivy-results.json" -type f | head -1
}

extract_images() {
  helm template trento charts/trento-server/ \
    --set prometheus.server.auth.type=none \
    | grep -E "^\s+image:" | awk '{gsub(/"/, "", $2); print $2}' | sort -u
}

detect_changed_images() {
  local pr_images_file="$1"
  local main_images_file="$2"

  log_info "Detecting changed images"

  # Build image objects with version info (deduplicated by image name)
  declare -A images_map

  # Extract images that are in PR but not in main (new)
  local new_images=$(comm -23 "$pr_images_file" "$main_images_file")
  while IFS= read -r image; do
    [ -z "$image" ] && continue
    images_map["$image"]='{"image":"'"$image"'","type":"new"}'
  done <<< "$new_images"

  # Extract images with changed tags (updated) - only if not already marked as new
  local base_changed=$(comm -12 \
    <(cat "$pr_images_file" | sed -E 's/:.*//g' | sort -u) \
    <(cat "$main_images_file" | sed -E 's/:.*//g' | sort -u))

  while IFS= read -r base_image; do
    [ -z "$base_image" ] && continue
    local pr_tag=$(grep -F "${base_image}:" "$pr_images_file" | head -1 || true)
    local main_tag=$(grep -F "${base_image}:" "$main_images_file" | head -1 || true)
    if [ "$pr_tag" != "$main_tag" ] && [ -n "$pr_tag" ] && [ -z "${images_map[$pr_tag]}" ]; then
      images_map["$pr_tag"]='{"image":"'"$pr_tag"'","type":"updated","old_version":"'"$main_tag"'"}'
    fi
  done <<< "$base_changed"

  # Convert map to array
  local images_array="["
  local first=true
  for image_entry in "${!images_map[@]}"; do
    if [ "$first" = true ]; then
      images_array="${images_array}${images_map[$image_entry]}"
      first=false
    else
      images_array="${images_array},${images_map[$image_entry]}"
    fi
  done
  images_array="${images_array}]"

  local total=$(echo "$images_array" | jq 'length')

  if [ "$total" -eq 0 ]; then
    echo '{"has_changes": false, "images_metadata": []}' > "$OUTPUT_IMAGES_FILE"
    echo "has_changes=false" >> "$GITHUB_OUTPUT"
    echo "images=[]" >> "$GITHUB_OUTPUT"
    log_info "No changed images detected"
    return 1
  else
    # Save full metadata for later use in comment generation
    echo "{\"has_changes\": true, \"images_metadata\": $images_array}" > "$OUTPUT_IMAGES_FILE"

    # Extract just image strings for the GitHub Actions matrix output
    local images_only=$(echo "$images_array" | jq -c '[.[].image]')
    echo "has_changes=true" >> "$GITHUB_OUTPUT"
    echo "images=$images_only" >> "$GITHUB_OUTPUT"

    log_success "Found $total changed images"
    echo ""
    echo "Changed images:"
    echo "$images_array" | jq -r '.[] | "  - \(.image) (\(.type))\(if .old_version then " [from: \(.old_version)]" else "" end)"'
    echo ""
    return 0
  fi
}

generate_comment() {
  log_info "Generating PR comment"

  {
    echo "## CVE Scan Results"
    echo ""
  } > "$OUTPUT_COMMENT_FILE"

  local total_cves=0

  # Get images metadata from changed_images.json (created by detect mode)
  if [ ! -f "$OUTPUT_IMAGES_FILE" ]; then
    log_error "No image metadata found: $OUTPUT_IMAGES_FILE"
    return 1
  fi

  local images_metadata=$(jq -c '.images_metadata' "$OUTPUT_IMAGES_FILE" 2>/dev/null)
  if [ -z "$images_metadata" ] || [ "$images_metadata" = "null" ]; then
    log_error "Invalid image metadata in $OUTPUT_IMAGES_FILE"
    return 1
  fi

  # Process each image from metadata
  while IFS= read -r image_json; do
    [ -z "$image_json" ] && continue

    local image=$(echo "$image_json" | jq -r '.image')
    local image_type=$(echo "$image_json" | jq -r '.type')
    local old_version=$(echo "$image_json" | jq -r '.old_version // empty')

    log_info "Processing: $image"

    # Find the scan file for this image by hash
    local scan_file=$(find_scan_file_for_image "$image")

    if [ -z "$scan_file" ] || [ ! -f "$scan_file" ]; then
      log_error "Scan file not found for: $image"
      continue
    fi

    local cve_count=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$scan_file" 2>/dev/null || echo "0")
    total_cves=$((total_cves + cve_count))

    if [ "$cve_count" -gt 0 ]; then
      {
        echo ""
        if [ "$image_type" = "new" ]; then
          echo "### 🆕 NEW: \`${image}\`"
        elif [ -n "$old_version" ]; then
          echo "### 📦 \`${image}\`"
          echo "**Updated from:** \`${old_version}\`"
        else
          echo "### 📦 \`${image}\`"
        fi
        echo ""
        echo "**Found $cve_count CVEs**"
        echo ""
      } >> "$OUTPUT_COMMENT_FILE"

      # Group by severity
      for severity in "CRITICAL" "HIGH" "MEDIUM" "LOW"; do
        local severity_count=$(jq "[.Results[]?.Vulnerabilities[]? | select(.Severity == \"$severity\")] | length" "$scan_file" 2>/dev/null || echo "0")
        if [ "$severity_count" -gt 0 ]; then
          {
            echo "<details><summary><strong>$severity ($severity_count)</strong></summary>"
            echo ""
            echo "| CVE ID | Package | Installed | Fixed |"
            echo "|--------|---------|-----------|-------|"
          } >> "$OUTPUT_COMMENT_FILE"

          jq -r ".Results[]?.Vulnerabilities[]? | select(.Severity == \"$severity\") | \"| [\(.VulnerabilityID)](https://nvd.nist.gov/vuln/detail/\(.VulnerabilityID)) | \(.PkgName) | \(.InstalledVersion) | \(.FixedVersion // \"N/A\") |\"" "$scan_file" >> "$OUTPUT_COMMENT_FILE"

          {
            echo ""
            echo "</details>"
            echo ""
          } >> "$OUTPUT_COMMENT_FILE"
        fi
      done
    else
      {
        echo ""
        if [ "$image_type" = "new" ]; then
          echo "### ✅ NEW: \`${image}\`"
        elif [ -n "$old_version" ]; then
          echo "### ✅ \`${image}\`"
          echo "**Updated from:** \`${old_version}\`"
        else
          echo "### ✅ \`${image}\`"
        fi
        echo ""
        echo "No CVEs found."
      } >> "$OUTPUT_COMMENT_FILE"
    fi
  done < <(echo "$images_metadata" | jq -c '.[]')

  if [ "$total_cves" -gt 0 ]; then
    {
      echo ""
      echo "### Summary"
      echo "**⚠️ Total: $total_cves CVEs detected**"
    } | cat - "$OUTPUT_COMMENT_FILE" > comment_temp.md
    mv comment_temp.md "$OUTPUT_COMMENT_FILE"
  else
    {
      echo ""
      echo "✅ **No CVEs detected in changed images**"
      echo ""
    } >> "$OUTPUT_COMMENT_FILE"
  fi

  # Add content hash for change detection
  local content_hash=$(sha256sum "$OUTPUT_COMMENT_FILE" | cut -c1-8)
  {
    echo ""
    echo "<!-- CVE scan hash: $content_hash -->"
  } >> "$OUTPUT_COMMENT_FILE"

  log_success "Generated comment in $OUTPUT_COMMENT_FILE"
}

detect_mode() {
  log_info "Starting PR image detection"

  local pr_images
  local main_images

  pr_images=$(mktemp) || return 1
  main_images=$(mktemp) || return 1

  log_info "Setting up Helm repositories"
  grep "repository: http" charts/trento-server/Chart.yaml | sed 's/.*repository: //' | sort -u | while read -r repo_url; do
    if ! helm repo add "repo-$(echo "$repo_url" | md5sum | cut -c1-8)" "$repo_url" 2>/dev/null; then
      log_error "Failed to add Helm repo: $repo_url"
      exit 1
    fi
  done

  if ! helm dependency build charts/trento-server/ --skip-refresh; then
    log_error "Failed to build Helm dependencies"
    rm -f "$pr_images" "$main_images" 2>/dev/null || true
    return 1
  fi

  log_info "Extracting images from PR branch"
  extract_images > "$pr_images"
  echo "PR images:"
  cat "$pr_images" | sed 's/^/  /'
  echo ""

  # Get images from main branch for comparison
  log_info "Extracting images from main branch"

  # Check if there are uncommitted changes to stash
  local has_changes=0
  if ! git diff --quiet; then
    has_changes=1
    if ! git stash push -m "pr-scan-tmp"; then
      log_error "Failed to stash changes"
      rm -f "$pr_images" "$main_images" 2>/dev/null || true
      return 1
    fi
  fi

  if ! git checkout origin/main; then
    log_error "Failed to checkout main branch"
    if [ $has_changes -eq 1 ]; then
      git stash pop 2>/dev/null || log_warning "Failed to restore stashed changes"
    fi
    rm -f "$pr_images" "$main_images" 2>/dev/null || true
    return 1
  fi

  if ! helm template trento charts/trento-server/ \
    --set prometheus.server.auth.type=none 2>/dev/null \
    | grep -E "^\s+image:" | awk '{gsub(/"/, "", $2); print $2}' | sort -u > "$main_images"; then
    log_error "Failed to extract images from main branch"
    git checkout - || log_warning "Failed to return to PR branch"
    if [ $has_changes -eq 1 ]; then
      git stash pop 2>/dev/null || log_warning "Failed to restore stashed changes"
    fi
    rm -f "$pr_images" "$main_images" 2>/dev/null || true
    return 1
  fi

  echo "Main branch images:"
  cat "$main_images" | sed 's/^/  /'
  echo ""

  if ! git checkout -; then
    log_error "Failed to return to PR branch"
    if [ $has_changes -eq 1 ]; then
      git stash pop 2>/dev/null || log_warning "Failed to restore stashed changes"
    fi
    rm -f "$pr_images" "$main_images" 2>/dev/null || true
    return 1
  fi

  if [ $has_changes -eq 1 ]; then
    if ! git stash pop; then
      log_error "Failed to restore stashed changes"
      rm -f "$pr_images" "$main_images" 2>/dev/null || true
      return 1
    fi
  fi

  detect_changed_images "$pr_images" "$main_images"

  rm -f "$pr_images" "$main_images" 2>/dev/null || true

  log_success "PR image detection completed"
}

comment_mode() {
  log_info "Generating comment from images"
  generate_comment
  log_success "Comment generated"
}

post_mode() {
  log_info "Posting comment to PR"

  if [ ! -s comment.md ]; then
    log_info "No comment to post"
    exit 0
  fi

  PR_NUMBER="${PR_NUMBER:-}"
  if [ -z "$PR_NUMBER" ]; then
    log_error "PR_NUMBER not set"
    exit 1
  fi

  local new_hash=$(grep "CVE scan hash:" comment.md | grep -oP '\b[a-f0-9]{8}\b' | tail -1)

  # Check if bot already commented with CVE Scan Results
  COMMENT_ID=$(gh pr view "$PR_NUMBER" \
    --json comments \
    --jq '.comments[] | select(.author.isBot and .body | contains("CVE Scan Results")) | .id' 2>/dev/null | head -1 || echo "")

  if [ -n "$COMMENT_ID" ]; then
    # Check if content actually changed by comparing hashes
    local existing_hash=$(gh pr view "$PR_NUMBER" \
      --json comments \
      --jq ".comments[] | select(.id == $COMMENT_ID) | .body" 2>/dev/null | grep -oP '(?<=CVE scan hash: )[a-f0-9]{8}' | tail -1 || echo "")

    if [ "$new_hash" != "$existing_hash" ]; then
      if gh pr comment "$PR_NUMBER" --edit "$COMMENT_ID" --body-file comment.md; then
        log_success "Updated existing comment (content changed)"
      else
        log_error "Failed to update existing comment"
        return 1
      fi
    else
      log_info "No changes detected, skipping update"
    fi
  else
    if gh pr comment "$PR_NUMBER" --body-file comment.md; then
      log_success "Created new comment"
    else
      log_error "Failed to post comment"
      return 1
    fi
  fi
}

case "$MODE" in
  detect) detect_mode ;;
  comment) comment_mode ;;
  post) post_mode ;;
  *) log_error "Unknown mode: $MODE. Use 'detect', 'comment', or 'post'"; exit 1 ;;
esac
