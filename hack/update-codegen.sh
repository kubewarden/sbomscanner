#!/usr/bin/env bash

# Copyright 2017 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail


# This script is adapted from k8s.io/sample-apiserver
# Instead of vendoring the code-generator, we use `go env GOPATH` to find the code-generator package
SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..
CODE_GENERATOR_VERSION=$(go list -m k8s.io/code-generator | awk '{print $2}')
GOPATH=$(go env GOPATH)
CODEGEN_PKG="$GOPATH/pkg/mod/k8s.io/code-generator@$CODE_GENERATOR_VERSION"

source "${CODEGEN_PKG}/kube_codegen.sh"

THIS_PKG="github.com/kubewarden/sbomscanner"

kube::codegen::gen_helpers \
    --boilerplate "${SCRIPT_ROOT}/hack/boilerplate.go.txt" \
    "${SCRIPT_ROOT}/api/storage"

if [[ -n "${API_KNOWN_VIOLATIONS_DIR:-}" ]]; then
    report_filename="${API_KNOWN_VIOLATIONS_DIR}/sample_apiserver_violation_exceptions.list"
    if [[ "${UPDATE_API_KNOWN_VIOLATIONS:-}" == "true" ]]; then
        update_report="--update-report"
    fi
fi

# Generate OpenAPI definitions (without model name file — that's done separately below).
kube::codegen::gen_openapi \
    --output-dir "${SCRIPT_ROOT}/pkg/generated/openapi" \
    --output-pkg "${THIS_PKG}/pkg/generated/openapi" \
    --report-filename "${report_filename:-"/dev/null"}" \
    ${update_report:+"${update_report}"} \
    --boilerplate "${SCRIPT_ROOT}/hack/boilerplate.go.txt" \
    "${SCRIPT_ROOT}/api/storage"

# Generate model name accessors for our local API package only.
# We call openapi-gen directly instead of using kube::codegen::gen_openapi with --output-model-name-file 
# because gen_openapi hardcodes k8s.io/apimachinery packages as inputs 
# and openapi-gen tries to write model name files into all input packages, including the read-only Go module cache. 
# Running it with only our local packages avoids this.
local_api_pkgs=()
while read -r dir; do
    pkg="$(cd "${dir}" && GO111MODULE=on go list -find .)"
    local_api_pkgs+=("${pkg}")
done < <(
    grep -rl '+k8s:openapi-model-package' "${SCRIPT_ROOT}/api/storage" --include '*.go' \
        | while read -r f; do dirname "$f"; done \
        | LC_ALL=C sort -u
)
"${GOBIN}/openapi-gen" \
    --output-model-name-file="zz_generated.model_name.go" \
    --output-file zz_generated.model_name_tmp.go \
    --output-dir "${SCRIPT_ROOT}/pkg/generated/openapi" \
    --output-pkg "${THIS_PKG}/pkg/generated/openapi" \
    --go-header-file "${SCRIPT_ROOT}/hack/boilerplate.go.txt" \
    "${local_api_pkgs[@]}"
rm -f "${SCRIPT_ROOT}/pkg/generated/openapi/zz_generated.model_name_tmp.go"

kube::codegen::gen_client \
    --with-watch \
    --with-applyconfig \
    --output-dir "${SCRIPT_ROOT}/pkg/generated" \
    --output-pkg "${THIS_PKG}/pkg/generated" \
    --boilerplate "${SCRIPT_ROOT}/hack/boilerplate.go.txt" \
    "${SCRIPT_ROOT}/api"
