#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

CHART_DIR="${CHART_DIR:-charts/trento-server}"
TRENTO_NAMESPACE="${TRENTO_NAMESPACE:-trento}"
PORT_FORWARD_PIDS=()

section() {
  printf '\n%s\n' "$1"
}

banner() {
  printf '%s\n' "╔════════════════════════════════════════════════════════════════════════╗"
  printf '%s\n' "║$1║"
  printf '%s\n' "╚════════════════════════════════════════════════════════════════════════╝"
}

emit_output() {
  local name="$1"
  local value="$2"

  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf '%s=%s\n' "$name" "$value" >> "$GITHUB_OUTPUT"
  else
    printf '%s=%s\n' "$name" "$value"
  fi
}

wait_for_port() {
  local host="$1"
  local port="$2"
  local label="$3"
  local attempt=1

  while [ "$attempt" -le 30 ]; do
    if (echo > "/dev/tcp/${host}/${port}") >/dev/null 2>&1; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done

  printf 'Timed out waiting for %s on %s:%s\n' "$label" "$host" "$port" >&2
  return 1
}

start_port_forward() {
  local resource="$1"
  local local_port="$2"
  local remote_port="$3"
  local log_file="$4"

  kubectl port-forward -n "$TRENTO_NAMESPACE" "$resource" "${local_port}:${remote_port}" >"$log_file" 2>&1 &
  PORT_FORWARD_PIDS+=("$!")
}

cleanup_port_forwards() {
  local pid

  for pid in "${PORT_FORWARD_PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done

  for pid in "${PORT_FORWARD_PIDS[@]:-}"; do
    wait "$pid" 2>/dev/null || true
  done

  PORT_FORWARD_PIDS=()
}

post_install_diagnostics() {
  banner "                      POST-INSTALL DIAGNOSTICS                          "
  section "=== All pods ==="
  kubectl get pods -n "$TRENTO_NAMESPACE" -o wide

  section "=== Pods not running ==="
  kubectl get pods -n "$TRENTO_NAMESPACE" --field-selector=status.phase!=Running -o custom-columns=NAME:.metadata.name,STATUS:.status.phase,REASON:.status.reason 2>/dev/null || echo "✓ All pods running"

  section "=== Recent events (last 30) ==="
  kubectl get events -n "$TRENTO_NAMESPACE" --sort-by='.lastTimestamp' | tail -30

  section "=== Logs for failed/pending pods ==="
  local failed_pods
  failed_pods=$(kubectl get pods -n "$TRENTO_NAMESPACE" --field-selector=status.phase!=Running -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
  if [ -n "$failed_pods" ]; then
    for pod in $failed_pods; do
      echo ""
      echo "────────────────────────────────────────────────────────────────────────"
      echo "Pod: $pod (last 100 lines)"
      echo "────────────────────────────────────────────────────────────────────────"
      kubectl logs -n "$TRENTO_NAMESPACE" "$pod" --all-containers=true --tail=100 --ignore-errors=true || echo "No logs available"
    done
  else
    echo "✓ No failed or pending pods"
  fi

  echo ""
  banner "                      DIAGNOSTICS COMPLETE                              "
}

compare_container_versions() {
  local current_chart=""
  local chart_dir chart_name display_name img_full img_registry img_name img_tag old_line old_full old_registry old_tag img

  section "=== Extracting current deployed images ==="
  kubectl get pods -n "$TRENTO_NAMESPACE" -o json | \
    jq -r '
      .items[] |
      .metadata.labels."app.kubernetes.io/name" as $chart |
      (
        ((.spec.initContainers // [])[] |
        "\($chart)|\(.name)|init|\(.image)"),
        ((.spec.containers // [])[] |
        "\($chart)|\(.name)|container|\(.image)")
      )
    ' | sort > /tmp/current-images.txt

  echo "Current images found:"
  cat /tmp/current-images.txt

  section "=== Extracting new chart images ==="
  helm template trento "$CHART_DIR" ${HELM_COMMON_FLAGS} | \
    grep -E "^\s+image:" | \
    awk '{gsub(/"/, "", $2); print $2}' | \
    sort -u > /tmp/new-images-raw.txt

  : > /tmp/new-images.txt
  for chart_dir in "$CHART_DIR"/charts/*/; do
    if [ -d "$chart_dir" ]; then
      chart_name=$(basename "$chart_dir")
      display_name=$(echo "$chart_name" | sed 's/^trento-//')

      helm template trento "$CHART_DIR" \
        ${HELM_COMMON_FLAGS} \
        -s "charts/${chart_name}/templates/*.yaml" 2>/dev/null | \
        grep -E "^\s+image:" | \
        awk -v chart="$display_name" '{gsub(/"/, "", $2); print chart "|" $2}' >> /tmp/new-images.txt || true
    fi
  done

  while read -r img; do
    if ! grep -q "|${img}$" /tmp/new-images.txt; then
      echo "main|${img}" >> /tmp/new-images.txt
    fi
  done < /tmp/new-images-raw.txt

  sort -u /tmp/new-images.txt -o /tmp/new-images.txt

  echo "New images found:"
  cat /tmp/new-images.txt

  echo ""
  banner "                    CONTAINER VERSION COMPARISON                        "
  echo ""

  current_chart=""
  while IFS='|' read -r chart_name img_full; do
    img_registry=$(echo "$img_full" | sed -E 's|/.*||')
    img_name=$(echo "$img_full" | sed -E 's|.*/||; s|:.*||')
    img_tag=$(echo "$img_full" | sed -E 's|.*:||')

    if [ "$chart_name" != "$current_chart" ]; then
      if [ -n "$current_chart" ]; then echo ""; fi
      echo "📦 Chart: ${chart_name}"
      echo "────────────────────────────────────────────────────────────────────────"
      current_chart="$chart_name"
    fi

    old_line=$(grep "|[^|]*${img_name}:" /tmp/current-images.txt | head -1)

    if [ -n "$old_line" ]; then
      old_full=$(echo "$old_line" | cut -d'|' -f4)
      old_registry=$(echo "$old_full" | sed -E 's|/.*||')
      old_tag=$(echo "$old_full" | sed -E 's|.*:||')

      if [ "$old_tag" != "$img_tag" ] || [ "$old_registry" != "$img_registry" ]; then
        echo -n "  🔄 ${img_name}: "

        if [ "$old_registry" != "$img_registry" ]; then
          echo -n "${old_registry}→${img_registry} "
        fi

        if [ "$old_tag" != "$img_tag" ]; then
          echo "${old_tag} → ${img_tag}"
        else
          echo "${img_tag}"
        fi
      else
        echo "  ✓ ${img_name}: ${img_tag}"
      fi
    else
      echo "  🆕 ${img_name}: ${img_tag} (new)"
    fi
  done < /tmp/new-images.txt

  echo ""
  echo "────────────────────────────────────────────────────────────────────────"
}

post_upgrade_diagnostics() {
  banner "                         POST-UPGRADE DIAGNOSTICS                       "
  section "=== All pods ==="
  kubectl get pods -n "$TRENTO_NAMESPACE" -o wide

  section "=== Pods not running ==="
  kubectl get pods -n "$TRENTO_NAMESPACE" --field-selector=status.phase!=Running -o custom-columns=NAME:.metadata.name,STATUS:.status.phase,REASON:.status.reason 2>/dev/null || echo "✓ All pods running"

  section "=== Recent events (last 30) ==="
  kubectl get events -n "$TRENTO_NAMESPACE" --sort-by='.lastTimestamp' | tail -30

  section "=== Web init container logs (DB migration) ==="
  local web_pod
  web_pod=$(kubectl get pod -n "$TRENTO_NAMESPACE" \
    -l "app.kubernetes.io/name=web,app.kubernetes.io/instance=trento-server" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  if [ -n "$web_pod" ]; then
    kubectl logs "$web_pod" -n "$TRENTO_NAMESPACE" -c init || echo "Failed to get web init logs"
  else
    echo "Failed to find web pod"
  fi

  section "=== All pod logs (last 30 lines each) ==="
  local pod
  for pod in $(kubectl get pods -n "$TRENTO_NAMESPACE" -o jsonpath='{.items[*].metadata.name}'); do
    echo ""
    echo "────────────────────────────────────────────────────────────────────────"
    echo "Pod: $pod"
    echo "────────────────────────────────────────────────────────────────────────"
    kubectl logs -n "$TRENTO_NAMESPACE" "$pod" --all-containers=true --tail=30 --ignore-errors=true || echo "No logs available"
  done

  echo ""
  banner "                      DIAGNOSTICS COMPLETE                              "
}

verify_api() {
  local web_port_forward_log
  local wanda_port_forward_log
  local mcp_port_forward_log

  banner "                         API FUNCTIONALITY TEST                         "
  echo ""
  section "=== Starting port-forwards ==="

  web_port_forward_log=$(mktemp)
  wanda_port_forward_log=$(mktemp)
  mcp_port_forward_log=$(mktemp)

  start_port_forward svc/trento-server-web 4000 4000 "$web_port_forward_log"
  start_port_forward svc/trento-server-wanda 4001 4000 "$wanda_port_forward_log"
  start_port_forward svc/trento-server-mcp-server 5000 5000 "$mcp_port_forward_log"

  trap cleanup_port_forwards EXIT

  wait_for_port 127.0.0.1 4000 web
  wait_for_port 127.0.0.1 4001 wanda
  wait_for_port 127.0.0.1 5000 mcp

  section "=== Testing Trento API endpoints ==="
  WEB_BASE_URL=http://127.0.0.1:4000 \
  WANDA_BASE_URL=http://127.0.0.1:4001 \
  MCP_BASE_URL=http://127.0.0.1:5000 \
    bash "$REPO_ROOT/.github/scripts/upgrade-test-api.sh"

  trap - EXIT
  cleanup_port_forwards
  rm -f "$web_port_forward_log" "$wanda_port_forward_log" "$mcp_port_forward_log"
}

failure_diagnostics() {
  banner "                    FAILURE DIAGNOSTICS - FULL LOGS                     "
  echo ""
  section "=== All pods ==="
  kubectl get pods -n "$TRENTO_NAMESPACE" -o wide

  section "=== All events ==="
  kubectl get events -n "$TRENTO_NAMESPACE" --sort-by='.lastTimestamp'

  section "=== Full container logs (all pods) ==="
  local pod
  for pod in $(kubectl get pods -n "$TRENTO_NAMESPACE" -o jsonpath='{.items[*].metadata.name}'); do
    echo ""
    echo "════════════════════════════════════════════════════════════════════════"
    echo "Pod: $pod (FULL LOGS)"
    echo "════════════════════════════════════════════════════════════════════════"
    kubectl logs -n "$TRENTO_NAMESPACE" "$pod" --all-containers=true --ignore-errors=true || echo "No logs available"

    echo ""
    echo "--- $pod (previous) ---"
    kubectl logs -n "$TRENTO_NAMESPACE" "$pod" --all-containers=true --previous --ignore-errors=true 2>/dev/null || echo "No previous logs"
  done
}

main() {
  case "${1:-}" in
    post-install-diagnostics)
      post_install_diagnostics
      ;;
    compare-container-versions)
      compare_container_versions
      ;;
    post-upgrade-diagnostics)
      post_upgrade_diagnostics
      ;;
    verify-api)
      verify_api
      ;;
    failure-diagnostics)
      failure_diagnostics
      ;;
    *)
      printf '%s\n' "Usage: upgrade-test.sh <command>" >&2
      printf '%s\n' "" >&2
      printf '%s\n' "Commands:" >&2
      printf '%s\n' "  post-install-diagnostics" >&2
      printf '%s\n' "  compare-container-versions" >&2
      printf '%s\n' "  post-upgrade-diagnostics" >&2
      printf '%s\n' "  verify-api" >&2
      printf '%s\n' "  failure-diagnostics" >&2
      exit 1
      ;;
  esac
}

main "$@"
