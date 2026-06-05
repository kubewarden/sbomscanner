#!/usr/bin/env bash
set -euo pipefail

# Defaults
NAMESPACE="default"
NAMESPACE_EXPLICIT=false
CNPG_NAMESPACE=""
COLLECT_ALL_MANIFESTS=false
OUTPUT_DIR="."

# Chart names we recognise as "sbomscanner" across distribution channels
# (kubewarden OSS chart + SUSE Application Collection chart).
CHART_PATTERNS='sbomscanner|suse-security-vulnerability-scanner'

# Components to check
DEPLOYMENTS=(
  "sbomscanner-controller:app.kubernetes.io/component=controller"
  "sbomscanner-worker:app.kubernetes.io/component=worker"
  "sbomscanner-storage:app.kubernetes.io/component=storage"
)
STATEFULSETS=(
  "sbomscanner-nats:app.kubernetes.io/component=nats"
)

# ─── Styling ─────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  BOLD=$'\033[1m'
  DIM=$'\033[2m'
  GREEN=$'\033[0;32m'
  RED=$'\033[0;31m'
  YELLOW=$'\033[1;33m'
  BLUE=$'\033[0;34m'
  CYAN=$'\033[0;36m'
  NC=$'\033[0m'
else
  BOLD=""; DIM=""; GREEN=""; RED=""; YELLOW=""; BLUE=""; CYAN=""; NC=""
fi
OK="✅"
FAIL="❌"
ARROW="➜"
BULLET="•"

hr()       { printf "${DIM}%s${NC}\n" "────────────────────────────────────────────────────────────────────"; }
section()  { printf "\n${BOLD}${BLUE}== %s ==${NC}\n" "$*"; }
log()      { printf "${GREEN}[INFO]${NC}  %b\n" "$*"; }
step()     { printf "  ${CYAN}${ARROW}${NC} %b\n" "$*"; }
warn()     { printf "${YELLOW}[WARN]${NC}  %b\n" "$*"; }
error()    { printf "${RED}[ERROR]${NC} %b\n" "$*" >&2; }
ok_line()  { printf "  ${GREEN}${OK}${NC} %b\n" "$*"; }
fail_line(){ printf "  ${RED}${FAIL}${NC} %b\n" "$*"; }
kv()       { printf "  ${DIM}%-18s${NC} ${BOLD}%s${NC}\n" "$1" "$2"; }

usage() {
  cat <<EOF
${BOLD}sbomscanner-debug.sh${NC} — verify and collect debug data for SBOMscanner

${BOLD}Usage:${NC}
  $0 verify  [flags]
  $0 collect [flags]

${BOLD}Flags:${NC}
  --namespace <ns>        SBOMscanner install namespace (auto-discovered if omitted)
  --cnpg-namespace <ns>   Namespace of the CNPG operator (collect only; logs skipped if omitted)
  --manifests             Also dump SBOMscanner/CNPG CRs, events and pod descriptions (collect only)
  --output-dir <dir>      Directory where the bundle is written (collect only, default: .)
  --compress-results      Tar+gzip the output directory (collect only)
  -h, --help              Show this help
EOF
  exit "${1:-1}"
}

# Require an argument for a flag; aborts via usage() if missing.
require_value() {
  local flag="$1"
  local value="${2-}"
  if [[ -z "$value" || "$value" == --* ]]; then
    error "Flag $flag requires a value."
    usage
  fi
}

# ─── Auto-discovery ──────────────────────────────────────────────────────────
# Sets globals: REL_NAME REL_NAMESPACE REL_CHART REL_APP_VERSION
discover_release() {
  local json
  json=$(helm list -A -o json 2>/dev/null) || {
    error "Failed to run 'helm list -A'."
    return 1
  }

  # Prefer a release whose chart matches a known sbomscanner chart name.
  local match
  match=$(jq -r --arg pat "$CHART_PATTERNS" \
    '[.[] | select(.chart | test($pat))] | .[0] // empty' <<<"$json")

  if [[ -z "$match" || "$match" == "null" ]]; then
    REL_NAME=""; REL_NAMESPACE=""; REL_CHART=""; REL_APP_VERSION=""
    return 1
  fi

  REL_NAME=$(jq -r '.name'         <<<"$match")
  REL_NAMESPACE=$(jq -r '.namespace'<<<"$match")
  REL_CHART=$(jq -r '.chart'       <<<"$match")
  REL_APP_VERSION=$(jq -r '.app_version' <<<"$match")
  return 0
}

verify_version() {
  if discover_release; then
    ok_line "Found SBOMscanner Helm release"
    kv "Release name"  "$REL_NAME"
    kv "Namespace"     "$REL_NAMESPACE"
    kv "Chart"         "$REL_CHART"
    kv "App version"   "$REL_APP_VERSION"
    # If the user explicitly passed --namespace, warn if it differs.
    if [[ "$NAMESPACE_EXPLICIT" == true && "$NAMESPACE" != "$REL_NAMESPACE" ]]; then
      warn "Release lives in '$REL_NAMESPACE' but --namespace is '$NAMESPACE'."
      warn "Using '$REL_NAMESPACE' for pod/resource checks."
    fi
    NAMESPACE="$REL_NAMESPACE"
    return 0
  else
    fail_line "No Helm release matching /${CHART_PATTERNS}/ found in any namespace."
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
      fail_line "$kind '$name' with label '$label' not found."
      all_ok=1
      continue
    fi

    local pods
    pods=$(kubectl -n "$NAMESPACE" get pods -l "$label" -o jsonpath='{.items[*].metadata.name}')
    if [[ -z "$pods" ]]; then
      fail_line "No pods found for $kind '$name'."
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
      ok_line "$kind '$name' running, all pods ready."
    else
      fail_line "$kind '$name' has pods not ready."
      all_ok=1
    fi
  done

  return $all_ok
}

# ─── Collect ─────────────────────────────────────────────────────────────────
collect_pod_logs() {
  local ns="$1" label="$2" out_dir="$3"
  local pods
  pods=$(kubectl -n "$ns" get pods -l "$label" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)
  if [[ -z "$pods" ]]; then
    step "(no pods for label '$label' in ns '$ns')"
    return
  fi
  for pod in $pods; do
    step "$ns/$pod"
    kubectl -n "$ns" logs --all-containers --prefix "$pod" \
      > "${out_dir}/${ns}_${pod}.log" 2>&1 \
      || warn "Failed to get logs for $ns/$pod"
    # Previous logs (crash loops) — ignore if absent.
    kubectl -n "$ns" logs --all-containers --prefix --previous "$pod" \
      > "${out_dir}/${ns}_${pod}.previous.log" 2>/dev/null \
      || rm -f "${out_dir}/${ns}_${pod}.previous.log"
  done
}

collect_data() {
  local compress=$1
  local ts
  ts=$(date +%Y%m%d_%H%M%S)
  local base_dir="${OUTPUT_DIR%/}/sbomscanner-debug-${ts}"
  local logs_dir="${base_dir}/logs"
  local manifests_dir="${base_dir}/manifests"

  mkdir -p "$OUTPUT_DIR" "$logs_dir" "$manifests_dir"

  section "Discovering release"
  if discover_release; then
    kv "Release"     "$REL_NAME"
    kv "Namespace"   "$REL_NAMESPACE"
    kv "Chart"       "$REL_CHART"
    kv "App version" "$REL_APP_VERSION"
    if [[ "$NAMESPACE_EXPLICIT" == true && "$NAMESPACE" != "$REL_NAMESPACE" ]]; then
      warn "Overriding --namespace '$NAMESPACE' with discovered '$REL_NAMESPACE'."
    fi
    NAMESPACE="$REL_NAMESPACE"
    # Persist helm metadata to the bundle.
    helm get values   "$REL_NAME" -n "$NAMESPACE" > "${manifests_dir}/helm-values.yaml"   2>/dev/null || warn "helm get values failed"
    helm get manifest "$REL_NAME" -n "$NAMESPACE" > "${manifests_dir}/helm-manifest.yaml" 2>/dev/null || warn "helm get manifest failed"
    helm history      "$REL_NAME" -n "$NAMESPACE" > "${manifests_dir}/helm-history.txt"   2>/dev/null || true
  else
    warn "No SBOMscanner release auto-discovered; falling back to --namespace '$NAMESPACE'."
  fi

  section "Collecting SBOMscanner pod logs (ns: $NAMESPACE)"
  for label in \
    "app.kubernetes.io/component=controller" \
    "app.kubernetes.io/component=worker" \
    "app.kubernetes.io/component=storage" \
    "app.kubernetes.io/component=nats"; do
    collect_pod_logs "$NAMESPACE" "$label" "$logs_dir"
  done

  section "Collecting CNPG cluster pod logs (ns: $NAMESPACE)"
  collect_pod_logs "$NAMESPACE" "cnpg.io/podRole=instance" "$logs_dir"

  if [[ -n "$CNPG_NAMESPACE" ]]; then
    section "Collecting CNPG operator logs (ns: $CNPG_NAMESPACE)"
    collect_pod_logs "$CNPG_NAMESPACE" "app.kubernetes.io/name=cloudnative-pg" "$logs_dir"
  else
    warn "Skipping CNPG operator logs (pass --cnpg-namespace to include)."
  fi

  if [[ "$COLLECT_ALL_MANIFESTS" == true ]]; then
    section "Collecting cluster-scoped manifests"
    for kind in vexhub workloadscanconfiguration; do
      step "$kind"
      kubectl get "$kind" -o yaml > "${manifests_dir}/cluster_${kind}.yaml" 2>/dev/null \
        || warn "No $kind resources found"
    done

    section "Collecting namespaced manifests (all namespaces)"
    for kind in registry scanjob images vulnerabilityreport workloadscanreport; do
      step "$kind"
      kubectl get "$kind" -A -o yaml \
        > "${manifests_dir}/all-ns_${kind}.yaml" 2>/dev/null \
        || warn "No $kind resources found cluster-wide"
    done

    section "Collecting CNPG resources (ns: $NAMESPACE)"
    for kind in cluster.postgresql.cnpg.io pooler.postgresql.cnpg.io backup.postgresql.cnpg.io scheduledbackup.postgresql.cnpg.io; do
      step "$kind"
      kubectl -n "$NAMESPACE" get "$kind" -o yaml > "${manifests_dir}/${kind%%.*}.yaml" 2>/dev/null \
        || warn "No $kind resources found"
    done

    section "Collecting events & pod descriptions (ns: $NAMESPACE)"
    kubectl -n "$NAMESPACE" get events --sort-by=.lastTimestamp \
      > "${manifests_dir}/events.txt" 2>/dev/null || warn "Failed to collect events"
    kubectl -n "$NAMESPACE" describe pods \
      > "${manifests_dir}/pods-describe.txt" 2>/dev/null || warn "Failed to describe pods"
  else
    section "Skipping manifest collection"
    step "Pass --manifests to also dump SBOMscanner/CNPG CRs, events and pod descriptions."
  fi

  if [[ "$compress" == true ]]; then
    local tar_file="${base_dir}.tar.gz"
    local parent_dir bundle_name
    parent_dir=$(dirname "$base_dir")
    bundle_name=$(basename "$base_dir")
    section "Compressing results"
    tar -czf "$tar_file" -C "$parent_dir" "$bundle_name"
    rm -rf "$base_dir"
    ok_line "Bundle written: ${BOLD}$tar_file${NC}"
  else
    section "Done"
    ok_line "Data collected in: ${BOLD}$base_dir${NC}"
  fi
}

# ─── Subcommands ─────────────────────────────────────────────────────────────
cmd_verify() {
  local ns="$NAMESPACE"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --namespace) require_value --namespace "${2-}"; ns="$2"; NAMESPACE_EXPLICIT=true; shift 2 ;;
      *) error "Unknown argument for verify: $1"; usage ;;
    esac
  done
  NAMESPACE="$ns"

  section "Helm release"
  local ok=true
  verify_version || ok=false

  section "Deployments"
  verify_resources "deployment" "${DEPLOYMENTS[@]}" || ok=false

  section "StatefulSets"
  verify_resources "statefulset" "${STATEFULSETS[@]}" || ok=false

  hr
  if [[ "$ok" == true ]]; then
    printf "${GREEN}${BOLD}${OK} Verification passed.${NC}\n"
    exit 0
  else
    printf "${RED}${BOLD}${FAIL} Verification failed.${NC}\n" >&2
    exit 1
  fi
}

cmd_collect() {
  local compress=false
  local ns="$NAMESPACE"
  local cnpg_ns="$CNPG_NAMESPACE"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --namespace)         require_value --namespace "${2-}";      ns="$2"; NAMESPACE_EXPLICIT=true; shift 2 ;;
      --cnpg-namespace)    require_value --cnpg-namespace "${2-}"; cnpg_ns="$2"; shift 2 ;;
      --manifests)         COLLECT_ALL_MANIFESTS=true; shift ;;
      --output-dir)        require_value --output-dir "${2-}";     OUTPUT_DIR="$2"; shift 2 ;;
      --compress-results)  compress=true; shift ;;
      *) error "Unknown argument for collect: $1"; usage ;;
    esac
  done
  NAMESPACE="$ns"
  CNPG_NAMESPACE="$cnpg_ns"
  collect_data "$compress"
}

main() {
  if [[ $# -lt 1 ]]; then
    usage
  fi

  local cmd=$1
  shift
  case "$cmd" in
    verify)  cmd_verify  "$@" ;;
    collect) cmd_collect "$@" ;;
    -h|--help) usage 0 ;;
    *) error "Unknown subcommand: $cmd"; usage ;;
  esac
}

main "$@"
