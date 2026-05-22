#!/usr/bin/env bash
# Generate SBOM and ImagesLock reports from scan artifacts
set -euo pipefail

REPORTS_DIR="${1:-reports}"
CHARTS_DIR="${2:-charts}"

log_info() { echo "ℹ️  $*"; }
log_success() { echo "✅ $*"; }
log_error() { echo "❌ $*" >&2; }

# Merge individual SBOM files into consolidated CycloneDX format
merge_sboms() {
  local sbom_dir="$1"
  local output_file="$2"

  cd "$sbom_dir"
  local sbom_files=(*.sbom.json)

  [ -e "${sbom_files[0]}" ] || { log_error "No SBOM files found in $sbom_dir"; return 1; }

  log_info "Found ${#sbom_files[@]} SBOM files to merge"

  cp "${sbom_files[0]}" "$output_file"

  for sbom in "${sbom_files[@]:1}"; do
    log_info "Merging $sbom"
    jq -s '.[0].components += .[1].components | .[0]' \
      "$output_file" "$sbom" > temp.json
    mv temp.json "$output_file"
  done

  log_success "Merged ${#sbom_files[@]} SBOMs into $output_file"
}

# Generate ImagesLock YAML file
generate_images_lock() {
  local sbom_dir="$1"
  local charts_dir="$2"
  local output_file="$3"

  log_info "Generating ImagesLock file"

  local chart_name=$(yq '.name' "${charts_dir}/trento-server/Chart.yaml")
  local chart_version=$(yq '.version' "${charts_dir}/trento-server/Chart.yaml")

  cat > "$output_file" << EOF
apiVersion: v0
kind: ImagesLock
metadata:
  generatedAt: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
  generatedBy: SUSE LLC
chart:
  name: $chart_name
  version: $chart_version
images: []
EOF

  cd "$sbom_dir"
  for sbom in *-sbom.json; do
    local image_name=$(jq -r '.metadata.component.name' "$sbom")
    local purl=$(jq -r '.metadata.component.purl' "$sbom")
    local digest=$(echo "$purl" | sed -n 's/.*@\([^?]*\).*/\1/p')
    local arch=$(echo "$purl" | sed -n 's/.*arch=\([^&]*\).*/\1/p')
    [ -z "$arch" ] && arch="amd64"

    if [ -z "$digest" ]; then
      log_error "No digest found for $image_name, skipping"
      continue
    fi

    yq -i ".images += [{\"name\": \"$image_name\", \"image\": \"$image_name\", \"chart\": \"$chart_name\", \"digests\": [{\"digest\": \"$digest\", \"arch\": \"linux/$arch\"}]}]" "$output_file"
  done

  log_success "Generated $output_file"
}

main() {
  log_info "Starting report generation"

  merge_sboms "$REPORTS_DIR" "${REPORTS_DIR}/sbom.cyclonedx.json"
  generate_images_lock "$REPORTS_DIR" "$CHARTS_DIR" "${REPORTS_DIR}/images-lock.yaml"

  log_success "Report generation completed"
}

main "$@"
