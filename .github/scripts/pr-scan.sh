#!/usr/bin/env bash
# Detect changed images in PR and generate CVE comment
set -euo pipefail

SCAN_RESULTS_DIR="${1:-scan-results}"
OUTPUT_IMAGES_FILE="${2:-changed_images.json}"
OUTPUT_COMMENT_FILE="${3:-comment.md}"
MODE="${4:-comment}"  # "detect" for GitHub Output, "comment" for file output

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

is_new_image() {
  local image="$1"
  local base_image=$(echo "$image" | sed -E 's/:.*//g')

  if ! gh api repos/$GITHUB_REPOSITORY/contents/charts/trento-server/values.yaml?ref=main --jq .content 2>/dev/null | base64 -d | grep -q "$base_image"; then
    return 0
  fi
  return 1
}

generate_comment() {
  local images_json=$(jq -r '.images[]' "$OUTPUT_IMAGES_FILE")

  log_info "Generating PR comment"

  {
    echo "## 🔒 CVE Scan Results"
    echo ""
  } > "$OUTPUT_COMMENT_FILE"

  local total_cves=0
  local new_image_count=0
  local updated_image_count=0

  while IFS= read -r image; do
    [ -z "$image" ] && continue
    local safe_name=$(echo "$image" | sed 's/[/:.]/-/g')
    local scan_file="${SCAN_RESULTS_DIR}/trivy-scan-${safe_name}/${safe_name}-trivy-results.json"

    if [ ! -f "$scan_file" ]; then
      log_error "Scan file not found for $image"
      continue
    fi

    local is_new="false"
    if is_new_image "$image"; then
      is_new="true"
      new_image_count=$((new_image_count + 1))
    else
      updated_image_count=$((updated_image_count + 1))
    fi

    local cve_count=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL" or .Severity == "HIGH" or .Severity == "MEDIUM")] | length' "$scan_file" || echo "0")
    total_cves=$((total_cves + cve_count))

    if [ "$cve_count" -gt 0 ]; then
      if [ "$is_new" = "true" ]; then
        {
          echo ""
          echo "### 🆕 NEW IMAGE: \`${image}\`"
          echo ""
          echo "⚠️ **This is a new image being added to the chart with CVEs detected.**"
          echo ""
          echo "**Found $cve_count CVEs (CRITICAL/HIGH/MEDIUM):**"
          echo ""
          echo "| CVE ID | Severity | Package | Installed | Fixed |"
          echo "|--------|----------|---------|-----------|-------|"
        } >> "$OUTPUT_COMMENT_FILE"
      else
        {
          echo ""
          echo "### 📦 \`${image}\`"
          echo ""
          echo "**Found $cve_count CVEs (CRITICAL/HIGH/MEDIUM):**"
          echo ""
          echo "| CVE ID | Severity | Package | Installed | Fixed |"
          echo "|--------|----------|---------|-----------|-------|"
        } >> "$OUTPUT_COMMENT_FILE"
      fi

      jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL" or .Severity == "HIGH" or .Severity == "MEDIUM") | "| [\(.VulnerabilityID)](https://nvd.nist.gov/vuln/detail/\(.VulnerabilityID)) | \(.Severity) | \(.PkgName) | \(.InstalledVersion) | \(.FixedVersion // "N/A") |"' "$scan_file" >> "$OUTPUT_COMMENT_FILE"
    else
      {
        echo ""
        echo "### ✅ \`${image}\`"
        echo ""
        echo "No CVEs found (CRITICAL/HIGH/MEDIUM)."
      } >> "$OUTPUT_COMMENT_FILE"
    fi
  done <<< "$images_json"

  if [ $total_cves -gt 0 ]; then
    {
      echo ""
      echo "### Summary"
      echo "**⚠️ Total: $total_cves CVEs detected**"
      [ $new_image_count -gt 0 ] && echo "- 🆕 $new_image_count new image(s) with CVEs"
      [ $updated_image_count -gt 0 ] && echo "- 📦 $updated_image_count updated image(s) with CVEs"
      echo ""
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
  local main_chart

  pr_images=$(mktemp)
  main_images=$(mktemp)
  main_chart=$(mktemp -d)

  cleanup() {
    rm -rf "$pr_images" "$main_images" "$main_chart" 2>/dev/null || true
  }
  trap cleanup EXIT ERR

  # Setup helm if not done already
  if ! helm repo list 2>/dev/null | grep -q prometheus-community; then
    log_info "Adding prometheus-community Helm repo"
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts/
  fi

  helm dependency build charts/trento-server/ 2>/dev/null || true

  log_info "Extracting images from PR branch"
  extract_images > "$pr_images"

  # Extract main branch chart without checking out
  log_info "Extracting chart from main branch"

  gh api "repos/$GITHUB_REPOSITORY/contents/charts/trento-server/Chart.yaml?ref=main" --jq .content 2>/dev/null | base64 -d > "$main_chart/Chart.yaml" || {
    log_error "Failed to fetch Chart.yaml from main branch"
    rm -rf "$main_chart"
    return 1
  }

  gh api "repos/$GITHUB_REPOSITORY/contents/charts/trento-server/values.yaml?ref=main" --jq .content 2>/dev/null | base64 -d > "$main_chart/values.yaml" || {
    log_error "Failed to fetch values.yaml from main branch"
    rm -rf "$main_chart"
    return 1
  }

  mkdir -p "$main_chart/templates"

  # Template main branch chart
  helm template trento "$main_chart" \
    --set prometheus.server.auth.type=none \
    | grep -E "^\s+image:" | awk '{gsub(/"/, "", $2); print $2}' | sort -u > "$main_images"

  rm -rf "$main_chart"

  local has_changes
  detect_changed_images "$pr_images" "$main_images"
  has_changes=$?

  local images=$(jq -c '.images' "$OUTPUT_IMAGES_FILE")
  echo "has_changes=$([ $has_changes -eq 0 ] && echo 'true' || echo 'false')" >> "$GITHUB_OUTPUT"
  echo "images=$images" >> "$GITHUB_OUTPUT"

  rm -f "$pr_images" "$main_images"

  log_success "PR image detection completed"
}

comment_mode() {
  log_info "Starting PR comment generation"

  generate_comment

  log_success "PR comment generation completed"
}

main() {
  case "$MODE" in
    detect)
      detect_mode
      ;;
    comment)
      comment_mode
      ;;
    *)
      log_error "Unknown mode: $MODE. Use 'detect' or 'comment'"
      exit 1
      ;;
  esac
}

main "$@"
