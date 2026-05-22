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

extract_images() {
  helm template trento charts/trento-server/ \
    --set prometheus.server.auth.type=none \
    | grep -E "^\s+image:" | awk '{gsub(/"/, "", $2); print $2}' | sort -u
}

detect_changed_images() {
  local pr_images_file="$1"
  local main_images_file="$2"

  log_info "Detecting changed images"

  # Extract images that are in PR but not in main (new), or have different tags
  local new_images=$(comm -23 "$pr_images_file" "$main_images_file")

  local base_changed=$(comm -12 \
    <(cat "$pr_images_file" | sed -E 's/:.*//g' | sort -u) \
    <(cat "$main_images_file" | sed -E 's/:.*//g' | sort -u))

  local updated_images=""
  while IFS= read -r base_image; do
    [ -z "$base_image" ] && continue
    local pr_tag=$(grep -F "${base_image}:" "$pr_images_file" | head -1 || true)
    local main_tag=$(grep -F "${base_image}:" "$main_images_file" | head -1 || true)
    if [ "$pr_tag" != "$main_tag" ] && [ -n "$pr_tag" ]; then
      updated_images+="$pr_tag"$'\n'
    fi
  done <<< "$base_changed"

  local all_changed
  all_changed=$(printf "%s\n" "$new_images" "$updated_images" | grep -v '^$' | sort -u)

  if [ -z "$all_changed" ]; then
    echo '{"has_changes": false, "images": []}' > "$OUTPUT_IMAGES_FILE"
    return 1
  else
    local images_json=$(echo "$all_changed" | jq -R . | jq -s -c .)
    echo "{\"has_changes\": true, \"images\": $images_json}" > "$OUTPUT_IMAGES_FILE"
    log_success "Found $(echo "$all_changed" | wc -l) changed images"
    return 0
  fi
}

generate_comment() {
  log_info "Generating PR comment"

  {
    echo "## 🔒 CVE Scan Results"
    echo ""
  } > "$OUTPUT_COMMENT_FILE"

  local total_cves=0

  # Find all scan result files in the directory
  while IFS= read -r scan_file; do
    [ -z "$scan_file" ] && continue

    log_info "Processing: $scan_file"

    if [ ! -f "$scan_file" ]; then
      continue
    fi

    # Extract image name from filename
    local image=$(basename "$(dirname "$scan_file")" | sed 's/trivy-scan-//')

    local cve_count=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$scan_file" 2>/dev/null || echo "0")
    total_cves=$((total_cves + cve_count))

    if [ "$cve_count" -gt 0 ]; then
      {
        echo ""
        echo "### 📦 \`${image}\`"
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
        echo "### ✅ \`${image}\`"
        echo ""
        echo "No CVEs found."
      } >> "$OUTPUT_COMMENT_FILE"
    fi
  done < <(find scan-results -name "*-trivy-results.json" -type f)

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

  local has_changes
  detect_changed_images "$pr_images" "$main_images"
  has_changes=$?

  local images
  images=$(jq -c '.images' "$OUTPUT_IMAGES_FILE")
  echo "has_changes=$([ $has_changes -eq 0 ] && echo 'true' || echo 'false')" >> "$GITHUB_OUTPUT"
  echo "images=$images" >> "$GITHUB_OUTPUT"

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

  # Check if bot already commented with CVE Scan Results
  COMMENT_ID=$(gh pr view "$PR_NUMBER" \
    --json comments \
    --jq '.comments[] | select(.author.isBot and .body | contains("CVE Scan Results")) | .id' 2>/dev/null | head -1 || echo "")

  if [ -n "$COMMENT_ID" ]; then
    if gh pr comment "$PR_NUMBER" --edit "$COMMENT_ID" --body-file comment.md; then
      log_success "Updated existing comment"
    else
      log_error "Failed to update existing comment"
      return 1
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
