#!/usr/bin/env bash
set -euo pipefail

# Defaults
NAMESPACE="default"
LATEST_VERSION="v0.2.0"

# Components to check
DEPLOYMENTS=(
  "sbomscanner-controller:app.kubernetes.io/component=controller"
  "sbomscanner-worker:app.kubernetes.io/component=worker"
  "sbomscanner-storage:app.kubernetes.io/component=storage"
)
STATEFULSETS=(
  "sbomscanner-nats:app.kubernetes.io/component=nats"
)

# Colors & Symbols
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
NC="\033[0m"
OK="✅"
FAIL="❌"

log() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

usage() {
  echo "Usage:"
  echo "  $0 verify"
  echo "    [--namespace <namespace>] Namespace where to run the verification. Default: default"
  echo
  echo "  $0 collect"
  echo "    [--namespace <namespace>] Namespace where to run the collection. Default: default"
  echo "    [--compress-results] Compress results into a tar.gz file."
  exit 1
}

verify_version() {
  local version
  version=$(helm list -n "$NAMESPACE" -o json | jq -r '.[] | select(.name=="sbomscanner") | .app_version')
  if [[ -z "$version" ]]; then
    echo -e "$FAIL Helm release 'sbomscanner' not found in namespace $NAMESPACE."
    return 1
  fi
  if [[ "$version" == "$LATEST_VERSION" ]]; then
    echo -e "$OK sbomscanner Helm version is latest ($version)"
    return 0
  else
    echo -e "$FAIL sbomscanner Helm version is $version (expected $LATEST_VERSION)"
    return 1
  fi
}

verify_resources() {
  local kind=$1
  shift
  local resources=("$@")
  local all_ok=0

  for res in "${resources[@]}"; do
    local name="${res%%:*}"
    local label="${res##*:}"

    if ! kubectl -n "$NAMESPACE" get "$kind" -l "$label" >/dev/null 2>&1; then
      echo -e "$FAIL $kind '$name' with label '$label' not found."
      all_ok=1
      continue
    fi

    local pods
    pods=$(kubectl -n "$NAMESPACE" get pods -l "$label" -o jsonpath='{.items[*].metadata.name}')
    if [[ -z "$pods" ]]; then
      echo -e "$FAIL No pods found for $kind '$name'."
      all_ok=1
      continue
    fi

    local not_ready=false
    for pod in $pods; do
      local status ready
      status=$(kubectl -n "$NAMESPACE" get pod "$pod" -o jsonpath='{.status.phase}')
      ready=$(kubectl -n "$NAMESPACE" get pod "$pod" -o jsonpath='{range .status.conditions[?(@.type=="Ready")]}{.status}{end}')
      if [[ "$status" != "Running" || "$ready" != "True" ]]; then
        not_ready=true
        break
      fi
    done

    if [[ "$not_ready" == false ]]; then
      echo -e "$OK $kind '$name' is running and all pods are ready."
    else
      echo -e "$FAIL $kind '$name' has pods not ready."
      all_ok=1
    fi
  done

  return $all_ok
}

collect_data() {
  local compress=$1
  local ts
  ts=$(date +%Y%m%d_%H%M%S)
  local base_dir="sbomscanner-debug-${ts}"
  local logs_dir="${base_dir}/logs"
  local manifests_dir="${base_dir}/manifests"

  mkdir -p "$logs_dir" "$manifests_dir"

  log "Collecting logs..."
  for label in \
    "app.kubernetes.io/component=controller" \
    "app.kubernetes.io/component=worker" \
    "app.kubernetes.io/component=storage" \
    "app.kubernetes.io/component=nats"; do
    local pods
    pods=$(kubectl -n "$NAMESPACE" get pods -l "$label" -o jsonpath='{.items[*].metadata.name}')
    for pod in $pods; do
      log "  → Pod $pod"
      kubectl -n "$NAMESPACE" logs "$pod" > "${logs_dir}/${pod}.log" 2>&1 || warn "Failed to get logs for $pod"
    done
  done

  log "Collecting applied manifests..."
  for kind in registry vexhub scanjob images vulnerabilityreport; do
    log "  → $kind"
    kubectl -n "$NAMESPACE" get "$kind" -o yaml > "${manifests_dir}/${kind}.yaml" 2>/dev/null || warn "No $kind resources found"
  done

  if [[ "$compress" == true ]]; then
    local tar_file="${base_dir}.tar.gz"
    log "Compressing results into $tar_file..."
    tar -czf "$tar_file" "$base_dir"
    rm -rf "$base_dir"
    log "Results compressed successfully: $tar_file"
  else
    log "Data collected in: $base_dir"
  fi
}

cmd_verify() {
  local ns="$NAMESPACE"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --namespace)
        ns="$2"
        shift 2
        ;;
      *)
        error "Unknown argument for verify: $1"
        usage
        ;;
    esac
  done
  NAMESPACE="$ns"

  local ok=true
  verify_version || ok=false
  verify_resources "deployment" "${DEPLOYMENTS[@]}" || ok=false
  verify_resources "statefulset" "${STATEFULSETS[@]}" || ok=false

  if [[ "$ok" == true ]]; then
    log "Verification completed successfully."
    exit 0
  else
    error "Verification failed."
    exit 1
  fi
}

cmd_collect() {
  local compress=false
  local ns="$NAMESPACE"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --namespace)
        ns="$2"
        shift 2
        ;;
      --compress-results)
        compress=true
        shift
        ;;
      *)
        error "Unknown argument for collect: $1"
        usage
        ;;
    esac
  done
  NAMESPACE="$ns"
  collect_data "$compress"
}

main() {
  if [[ $# -lt 1 ]]; then
    usage
  fi

  local cmd=$1
  shift
  case "$cmd" in
    verify)
      cmd_verify "$@"
      ;;
    collect)
      cmd_collect "$@"
      ;;
    *)
      error "Unknown subcommand: $cmd"
      usage
      ;;
  esac
}

main "$@"

