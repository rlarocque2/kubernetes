#!/bin/bash

# Copyright 2014 Google Inc. All rights reserved.
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

# Pushes an official release to our official release location

set -o errexit
set -o nounset
set -o pipefail

KUBE_RELEASE_VERSION=${1-}

[[ -n ${KUBE_RELEASE_VERSION} ]] || {
  echo "!!! You must specify the version you are releasing in the form of vX.Y.Z" >&2
  exit 1
}

KUBE_GCS_NO_CACHING=n
KUBE_GCS_MAKE_PUBLIC=y
KUBE_GCS_UPLOAD_RELEASE=y
KUBE_GCS_RELEASE_BUCKET=kubernetes-release
KUBE_GCS_PROJECT=google-containers
KUBE_GCS_RELEASE_PREFIX=release/${KUBE_RELEASE_VERSION}

KUBE_ROOT=$(dirname "${BASH_SOURCE}")/..
source "$KUBE_ROOT/build/common.sh"


kube::release::gcs::release
