#!/usr/bin/env bash
# Detect changed images in PR and generate CVE comment
set -euo pipefail

SCAN_RESULTS_DIR="${1:-scan-results}"
OUTPUT_IMAGES_FILE="${2:-changed_images.json}"
OUTPUT_COMMENT_FILE="${3:-comment.md}"
MODE="${4:-detect}"

log_info() { echo "ℹ️  $*"; }
log_success() { echo "✅ $*"; }
log_error() { echo "❌ $*" >&2; }

extract_images() {
  helm template trento charts/trento-server/ \
    --set prometheus.server.auth.type=none \
    | grep -E "^\s+image:" | awk '{gsub(/"/, "", $2); print $2}' | sort -u
}

detect_changed_images() {
  local pr_images_file="$1"
  local main_images_file="$2"

  log_info "Detecting changed images"

  local new_images=$(comm -23 "$pr_images_file" "$main_images_file")

  local base_changed=$(comm -12 \
    <(cat "$pr_images_file" | sed -E 's/:.*//g' | sort -u) \
    <(cat "$main_images_file" | sed -E 's/:.*//g' | sort -u))

  local updated_images=""
  while IFS= read -r base_image; do
    [ -z "$base_image" ] && continue
    local pr_tag=$(grep "^${base_image}:" "$pr_images_file" | head -1 || true)
    local main_tag=$(grep "^${base_image}:" "$main_images_file" | head -1 || true)
    if [ "$pr_tag" != "$main_tag" ] && [ -n "$pr_tag" ]; then
      updated_images="${updated_images}${pr_tag}"$'\n'
    fi
  done <<< "$base_changed"

  local all_changed=$(echo -e "${new_images}${updated_images}" | grep -v '^$' | sort -u)

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
  local images_json=$(jq -r '.images[]?' "$OUTPUT_IMAGES_FILE")

  log_info "Generating PR comment"

  {
    echo "## 🔒 CVE Scan Results"
    echo ""
  } > "$OUTPUT_COMMENT_FILE"

  local total_cves=0

  while IFS= read -r image; do
    [ -z "$image" ] && continue

    log_info "Scanning: $image"

    # Run trivy scan on the image
    local scan_output
    scan_output=$(trivy image "$image" --format json --severity CRITICAL,HIGH,MEDIUM 2>/dev/null || echo "{}")

    local cve_count
    cve_count=$(echo "$scan_output" | jq '[.Results[]?.Vulnerabilities[]?] | length' 2>/dev/null || echo "0")
    total_cves=$((total_cves + cve_count))

    if [ "$cve_count" -gt 0 ]; then
      {
        echo ""
        echo "### 📦 \`${image}\`"
        echo ""
        echo "**Found $cve_count CVEs (CRITICAL/HIGH/MEDIUM):**"
        echo ""
        echo "| CVE ID | Severity | Package | Installed | Fixed |"
        echo "|--------|----------|---------|-----------|-------|"
      } >> "$OUTPUT_COMMENT_FILE"

      echo "$scan_output" | jq -r '.Results[]?.Vulnerabilities[]? | "| [\(.VulnerabilityID)](https://nvd.nist.gov/vuln/detail/\(.VulnerabilityID)) | \(.Severity) | \(.PkgName) | \(.InstalledVersion) | \(.FixedVersion // "N/A") |"' >> "$OUTPUT_COMMENT_FILE" 2>/dev/null || true
    else
      {
        echo ""
        echo "### ✅ \`${image}\`"
        echo ""
        echo "No CVEs found (CRITICAL/HIGH/MEDIUM)."
      } >> "$OUTPUT_COMMENT_FILE"
    fi
  done <<< "$images_json"

  if [ "$total_cves" -gt 0 ]; then
    {
      echo ""
      echo "### Summary"
      echo "**⚠️ Total: $total_cves CVEs detected in changed images**"
    } | cat - "$OUTPUT_COMMENT_FILE" > comment_temp.md
    mv comment_temp.md "$OUTPUT_COMMENT_FILE"
  fi

  log_success "Generated comment in $OUTPUT_COMMENT_FILE"
}

detect_mode() {
  log_info "Starting PR image detection"

  local pr_images
  local main_images
  local main_chart

  pr_images=$(mktemp) || return 1
  main_images=$(mktemp) || return 1
  main_chart=$(mktemp -d) || return 1

  # Add Helm chart repositories from Chart.yaml
  grep "repository: http" charts/trento-server/Chart.yaml | sed 's/.*repository: //' | sort -u | while read -r repo_url; do
    helm repo add "repo-$(echo "$repo_url" | md5sum | cut -c1-8)" "$repo_url" 2>/dev/null || true
  done

  helm dependency build charts/trento-server/ --skip-refresh 2>/dev/null || true

  log_info "Extracting images from PR branch"
  extract_images > "$pr_images"

  # Extract main branch chart without checking out
  log_info "Extracting chart from main branch"

  # Ensure main branch is available (may be shallow clone in PR)
  git fetch origin main 2>/dev/null || true

  git show origin/main:charts/trento-server/Chart.yaml > "$main_chart/Chart.yaml" 2>/dev/null || {
    log_error "Failed to fetch Chart.yaml from main branch"
    rm -f "$pr_images" "$main_images" 2>/dev/null || true
    rm -rf "$main_chart" 2>/dev/null || true
    return 1
  }

  git show origin/main:charts/trento-server/values.yaml > "$main_chart/values.yaml" 2>/dev/null || {
    log_error "Failed to fetch values.yaml from main branch"
    rm -f "$pr_images" "$main_images" 2>/dev/null || true
    rm -rf "$main_chart" 2>/dev/null || true
    return 1
  }

  mkdir -p "$main_chart/templates"

  # Build dependencies for main branch chart (skip repo update - already done)
  helm dependency build "$main_chart" --skip-refresh 2>/dev/null || true

  # Template main branch chart
  helm template trento "$main_chart" \
    --set prometheus.server.auth.type=none \
    2>/dev/null | grep -E "^\s+image:" | awk '{gsub(/"/, "", $2); print $2}' | sort -u > "$main_images"

  local has_changes
  detect_changed_images "$pr_images" "$main_images"
  has_changes=$?

  local images
  images=$(jq -c '.images' "$OUTPUT_IMAGES_FILE")
  echo "has_changes=$([ $has_changes -eq 0 ] && echo 'true' || echo 'false')" >> "$GITHUB_OUTPUT"
  echo "images=$images" >> "$GITHUB_OUTPUT"

  log_success "PR image detection completed"
}

comment_mode() {
  log_info "Generating comment from images"
  generate_comment
  log_success "Comment generated"
}

case "$MODE" in
  detect) detect_mode ;;
  comment) comment_mode ;;
  *) log_error "Unknown mode: $MODE. Use 'detect' or 'comment'"; exit 1 ;;
esac
