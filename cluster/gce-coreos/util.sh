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

# A library of helper functions and constant for the local config.

# Use the config file specified in $KUBE_CONFIG_FILE, or default to
# config-default.sh.
KUBE_ROOT=$(dirname "${BASH_SOURCE}")/../..
source "${KUBE_ROOT}/cluster/gce-coreos/${KUBE_CONFIG_FILE-"config-default.sh"}"

# Verify prereqs
function verify-prereqs {
  local cmd
  for cmd in gcloud gsutil; do
    which "${cmd}" >/dev/null || {
      echo "Can't find ${cmd} in PATH, please fix and retry. The Google Cloud "
      echo "SDK can be downloaded from https://cloud.google.com/sdk/."
      exit 1
    }
  done
}

# Create a temp dir that'll be deleted at the end of this bash session.
#
# Vars set:
#   KUBE_TEMP
function ensure-temp-dir {
  if [[ -z ${KUBE_TEMP-} ]]; then
    KUBE_TEMP=$(mktemp -d -t kubernetes.XXXXXX)
    trap 'rm -rf "${KUBE_TEMP}"' EXIT
  fi
}

# Verify and find the various tar files that we are going to use on the server.
#
# Vars set:
#   SERVER_BINARY_TAR
#   SALT_TAR
function find-release-tars {
  SERVER_BINARY_TAR="${KUBE_ROOT}/server/kubernetes-server-linux-amd64.tar.gz"
  if [[ ! -f "$SERVER_BINARY_TAR" ]]; then
    SERVER_BINARY_TAR="${KUBE_ROOT}/_output/release-tars/kubernetes-server-linux-amd64.tar.gz"
  fi
  if [[ ! -f "$SERVER_BINARY_TAR" ]]; then
    echo "!!! Cannot find kubernetes-server-linux-amd64.tar.gz"
    exit 1
  fi
}

# Use the gcloud defaults to find the project.  If it is already set in the
# environment then go with that.
#
# Vars set:
#   PROJECT
function detect-project () {
  if [[ -z "${PROJECT-}" ]]; then
    PROJECT=$(gcloud config list project | tail -n 1 | cut -f 3 -d ' ')
  fi

  if [[ -z "${PROJECT-}" ]]; then
    echo "Could not detect Google Cloud Platform project.  Set the default project using " >&2
    echo "'gcloud config set project <PROJECT>'" >&2
    exit 1
  fi
  echo "Project: $PROJECT (autodetected from gcloud config)"
}

# Take the local tar files and upload them to Google Storage.  They will then be
# downloaded by the master as part of the start up script for the master.
#
# Assumed vars:
#   PROJECT
#   SERVER_BINARY_TAR
#   SALT_TAR
# Vars set:
#   SERVER_BINARY_TAR_URL
#   SALT_TAR_URL
function upload-server-tars() {
  SERVER_BINARY_TAR_URL=
  SALT_TAR_URL=

  local project_hash
  if which md5 > /dev/null 2>&1; then
    project_hash=$(md5 -q -s "$PROJECT")
  else
    project_hash=$(echo -n "$PROJECT" | md5sum | awk '{ print $1 }')
  fi
  project_hash=${project_hash:0:5}

  local -r staging_bucket="gs://kubernetes-staging-${project_hash}"

  # Ensure the bucket is created
  if ! gsutil ls "$staging_bucket" > /dev/null 2>&1 ; then
    echo "Creating $staging_bucket"
    gsutil mb "${staging_bucket}"
  fi

  local -r staging_path="${staging_bucket}/devel"

  echo "+++ Staging server tars to Google Storage: ${staging_path}"
  local server_binary_gs_url="${staging_path}/${SERVER_BINARY_TAR##*/}"
  gsutil -q -h "Cache-Control:private, max-age=0" cp "${SERVER_BINARY_TAR}" "${server_binary_gs_url}"
  gsutil acl ch -g all:R "${server_binary_gs_url}" >/dev/null 2>&1

  # Convert from gs:// URL to an https:// URL
  SERVER_BINARY_TAR_URL="${server_binary_gs_url/gs:\/\//https://storage.googleapis.com/}"
}

# Detect the information about the minions
#
# Assumed vars:
#   MINION_NAMES
#   ZONE
# Vars set:
#   KUBE_MINION_IP_ADDRESS (array)
function detect-minions () {
  detect-project
  KUBE_MINION_IP_ADDRESSES=()
  for (( i=0; i<${#MINION_NAMES[@]}; i++)); do
    local minion_ip=$(gcloud compute instances describe --project "${PROJECT}" --zone "${ZONE}" \
      "${MINION_NAMES[$i]}" --fields networkInterfaces[0].accessConfigs[0].natIP \
      --format=text | awk '{ print $2 }')
    if [[ -z "${minion_ip-}" ]] ; then
      echo "Did not find ${MINION_NAMES[$i]}" >&2
    else
      echo "Found ${MINION_NAMES[$i]} at ${minion_ip}"
      KUBE_MINION_IP_ADDRESSES+=("${minion_ip}")
    fi
  done
  if [[ -z "${KUBE_MINION_IP_ADDRESSES-}" ]]; then
    echo "Could not detect Kubernetes minion nodes.  Make sure you've launched a cluster with 'kube-up.sh'" >&2
    exit 1
  fi
}

# Detect the IP for the master
#
# Assumed vars:
#   MASTER_NAME
#   ZONE
# Vars set:
#   KUBE_MASTER
#   KUBE_MASTER_IP
#   KUBERNETES_MASTER
function detect-master () {
  detect-project
  KUBE_MASTER=${MASTER_NAME}
  if [[ -z "${KUBE_MASTER_IP-}" ]]; then
    KUBE_MASTER_IP=$(gcloud compute instances describe --project "${PROJECT}" --zone "${ZONE}" \
      "${MASTER_NAME}" --fields networkInterfaces[0].accessConfigs[0].natIP \
      --format=text | awk '{ print $2 }')
  fi
  if [[ -z "${KUBE_MASTER_IP-}" ]]; then
    echo "Could not detect Kubernetes master node.  Make sure you've launched a cluster with 'kube-up.sh'" >&2
    exit 1
  fi
  echo "Using master: $KUBE_MASTER (external IP: $KUBE_MASTER_IP)"
  export KUBERNETES_MASTER="http://${KUBE_MASTER_IP}:8080"
}

# Ensure that we have a password created for validating to the master.  Will
# read from $HOME/.kubernetres_auth if available.
#
# Vars set:
#   KUBE_USER
#   KUBE_PASSWORD
function get-password {
  # TODO: Add some security.
  KUBE_USER=""
  KUBE_PASSWORD=""
}

# Generate authentication token for admin user. Will
# read from $HOME/.kubernetes_auth if available.
#
# Vars set:
#   KUBE_ADMIN_TOKEN
function get-admin-token {
  # TODO: Add some security.
  KUBE_ADMIN_TOKEN=""
}

# Requires:
#  PROJECT, ZONE, MASTER_NAME,
#  and an up-and-running master.
# Provides:
#  KUBE_MASTER_INTERNAL_IP
function detect-master-internal-ip {
  KUBE_MASTER_INTERNAL_IP=$(gcloud compute instances describe \
    --project "${PROJECT}" --zone "${ZONE}" "${MASTER_NAME}" \
    --fields networkInterfaces[0].networkIP --format=text \
    | awk '{ print $2 }')
}

# Arguments:
#   i (Specifying the i'th minion)
# Prereqs:
#   upload-server-tars
#   ensure-temp-dir
#   detect-master-internal-ip
# Provides:
#   KUBERNETES_MINION_PARAMS_TMP[$i] and related file.
function ensure-minion-i-metadata {
  ensure-temp-dir
  i="$1"
  KUBERNETES_MINION_PARAMS_TMP[$i]="${KUBE_TEMP}/kubernetes-minion-params-${i}"
  (
    echo "#! /bin/bash"
    echo "ZONE='${ZONE}'"
    echo "MASTER_NAME='${MASTER_NAME}'"
    echo "MINION_IP_RANGE='${MINION_IP_RANGES[$i]}'"
    echo "EXTRA_DOCKER_OPTS='${EXTRA_DOCKER_OPTS}'"
    echo "ENABLE_DOCKER_REGISTRY_CACHE='${ENABLE_DOCKER_REGISTRY_CACHE:-false}'"
    echo "SERVER_BINARY_TAR_URL='${SERVER_BINARY_TAR_URL}'"
    echo "KUBE_MASTER_INTERNAL_IP=${KUBE_MASTER_INTERNAL_IP}"
  ) > "${KUBERNETES_MINION_PARAMS_TMP[$i]}"
}

# Prereqs:
#   upload-server-tars
#   ensure-temp-dir
# Provides:
#   KUBERNETES_MASTER_PARAMS_TMP and related file.
function ensure-master-metadata {
  export KUBERNETES_MASTER_PARAMS_TMP="${KUBE_TEMP}/kubernetes-master-params"
  (
    echo "MASTER_NAME='${MASTER_NAME}'"
    echo "NODE_INSTANCE_PREFIX='${INSTANCE_PREFIX}-minion'"
    echo "SERVER_BINARY_TAR_URL='${SERVER_BINARY_TAR_URL}'"
    echo "PORTAL_NET='${PORTAL_NET}'"
    echo "ENABLE_NODE_MONITORING='${ENABLE_NODE_MONITORING:-false}'"
    echo "ENABLE_NODE_LOGGING='${ENABLE_NODE_LOGGING:-false}'"
    echo "LOGGING_DESTINATION='${LOGGING_DESTINATION:-}'"
  ) > "$KUBERNETES_MASTER_PARAMS_TMP"
}

# Instantiate a kubernetes cluster
#
# Assumed vars
#   KUBE_ROOT
#   <Various vars set in config file>
function kube-up {
  # Detect the project into $PROJECT if it isn't set
  detect-project

  # Make sure we have the tar files staged on Google Storage
  find-release-tars
  upload-server-tars

  ensure-temp-dir

  if ! gcloud compute networks describe --project ${PROJECT} "${NETWORK}" &>/dev/null; then
    echo "Creating new network: ${NETWORK}"
    # The network needs to be created synchronously or we have a race. The
    # firewalls can be added concurrent with instance creation.
    gcloud compute networks create --project ${PROJECT} "${NETWORK}" --range "10.240.0.0/16"
  fi

  if ! gcloud compute firewall-rules describe --project ${PROJECT} "${NETWORK}-default-internal" &>/dev/null; then
    gcloud compute firewall-rules create "${NETWORK}-default-internal" \
      --project "${PROJECT}" \
      --network "${NETWORK}" \
      --source-ranges "10.0.0.0/8" \
      --allow "tcp:1-65535" "udp:1-65535" "icmp" &
  fi

  if ! gcloud compute firewall-rules describe --project "${PROJECT}" "${NETWORK}-default-ssh" &>/dev/null; then
    gcloud compute firewall-rules create "${NETWORK}-default-ssh" \
      --project "${PROJECT}" \
      --network "${NETWORK}" \
      --source-ranges "0.0.0.0/0" \
      --allow "tcp:22" &
  fi

  echo "Starting VMs and configuring firewalls"
  gcloud compute firewall-rules create "${MASTER_NAME}-https" \
    --project "${PROJECT}" \
    --network "${NETWORK}" \
    --target-tags "${MASTER_TAG}" \
    --allow tcp:443 &

  # FIXME / HACK: IP-based security is a lot weaker than PKI, but it's a lot
  # easier to set up for now.  This needs to be replaced with something safer.
  MY_IP=$(curl -s -4 http://icanhazip.com)
  gcloud compute firewall-rules create "${MASTER_NAME}-http" \
    --project "${PROJECT}" \
    --network "${NETWORK}" \
    --target-tags "${MASTER_TAG}" \
    --source-ranges "${MY_IP}/32" \
    --allow tcp:8080 &

  ensure-master-metadata

  # TODO: Support ENABLE_NODE_LOGGING ?

  gcloud compute instances create "${MASTER_NAME}" \
    --project "${PROJECT}" \
    --zone "${ZONE}" \
    --machine-type "${MASTER_SIZE}" \
    --image-project="${IMAGE_PROJECT}" \
    --image "${IMAGE}" \
    --tags "${MASTER_TAG}" \
    --network "${NETWORK}" \
    --scopes "storage-ro" "compute-rw" \
    --metadata-from-file "kubernetes-master-params=${KUBERNETES_MASTER_PARAMS_TMP}" \
                         "user-data=${KUBE_ROOT}/cluster/gce-coreos/master.yaml"

  detect-master-internal-ip

  for (( i=0; i<${#MINION_NAMES[@]}; i++)); do
    ensure-minion-i-metadata $i

    gcloud compute firewall-rules create "${MINION_NAMES[$i]}-all" \
      --project "${PROJECT}" \
      --network "${NETWORK}" \
      --source-ranges "${MINION_IP_RANGES[$i]}" \
      --allow tcp udp icmp esp ah sctp &

    local -a scope_flags=()
    if (( "${#MINION_SCOPES[@]}" > 0 )); then
      scope_flags=("--scopes" "${MINION_SCOPES[@]}")
    else
      scope_flags=("--no-scopes")
    fi
    gcloud compute instances create ${MINION_NAMES[$i]} \
      --project "${PROJECT}" \
      --zone "${ZONE}" \
      --machine-type "${MINION_SIZE}" \
      --image-project="${IMAGE_PROJECT}" \
      --image "${IMAGE}" \
      --tags "${MINION_TAG}" \
      --network "${NETWORK}" \
      "${scope_flags[@]}" \
      --can-ip-forward \
      --metadata-from-file "kubernetes-minion-params=${KUBERNETES_MINION_PARAMS_TMP}" \
                           "user-data=${KUBE_ROOT}/cluster/gce-coreos/minion.yaml"

    gcloud compute routes create "${MINION_NAMES[$i]}" \
      --project "${PROJECT}" \
      --destination-range "${MINION_IP_RANGES[$i]}" \
      --network "${NETWORK}" \
      --next-hop-instance "${MINION_NAMES[$i]}" \
      --next-hop-instance-zone "${ZONE}" &
  done

  local fail=0
  local job
  for job in $(jobs -p); do
      wait "${job}" || fail=$((fail + 1))
  done
  if (( $fail != 0 )); then
    echo "${fail} commands failed.  Exiting." >&2
    exit 2
  fi

  detect-master

  echo "Waiting for cluster initialization."
  echo
  echo "  This will continually check to see if the API for kubernetes is reachable."
  echo "  This might loop forever if there was some uncaught error during start"
  echo "  up."
  echo

  until curl --max-time 5 \
          --fail --output /dev/null --silent "${KUBERNETES_MASTER}/api/v1beta1/pods"; do
      printf "."
      sleep 2
  done

  echo "Kubernetes cluster created."
  echo "Sanity checking cluster..."

  sleep 5

  # Basic sanity checking
  local i
  local rc # Capture return code without exiting because of errexit bash option
  for (( i=0; i<${#MINION_NAMES[@]}; i++)); do
      # Make sure docker is installed
      gcloud compute ssh --project "${PROJECT}" --zone "$ZONE" "${MINION_NAMES[$i]}" --command "which docker" >/dev/null || {
        echo "Docker failed to install on ${MINION_NAMES[$i]}. Your cluster is unlikely" >&2
        echo "to work correctly. Please run ./cluster/kube-down.sh and re-create the" >&2
        echo "cluster. (sorry!)" >&2
        exit 1
      }
  done

  echo
  echo "Kubernetes cluster is running.  The master is running at:"
  echo
  echo " ${KUBERNETES_MASTER}"
  echo
  echo "There is no authentication aside from your IP.  You have no security."
  echo
}

# Delete a kubernetes cluster.
#
# Assumed vars:
#   MASTER_NAME
#   INSTANCE_PREFIX
#   ZONE
#   PROJECT
# This function tears down cluster resources 10 at a time to avoid issuing too many
# API calls and exceeding API quota. It is important to bring down the instances before bringing
# down the firewall rules and routes.
function kube-down {
  # Detect the project into $PROJECT
  detect-project

  echo "Bringing down cluster"

  # First delete the master (if it exists).
  gcloud compute instances delete \
    --project "${PROJECT}" \
    --quiet \
    --delete-disks all \
    --zone "${ZONE}" \
    "${MASTER_NAME}" || true
  # Find out what minions are running.
  local -a minions
  minions=( $(gcloud compute instances list \
                --project "${PROJECT}" --zone "${ZONE}" \
                --regexp "${INSTANCE_PREFIX}-minion-[0-9]+" \
                | awk 'NR >= 2 { print $1 }') )
  # If any minions are running, delete them in batches.
  while (( "${#minions[@]}" > 0 )); do
    echo Deleting nodes "${minions[*]::10}"
    gcloud compute instances delete \
      --project "${PROJECT}" \
      --quiet \
      --delete-disks boot \
      --zone "${ZONE}" \
      "${minions[@]::10}" || true
    minions=( "${minions[@]:10}" )
  done

  # Delete firewall rule for the master.
  gcloud compute firewall-rules delete  \
    --project "${PROJECT}" \
    --quiet \
    "${MASTER_NAME}-https" || true
  gcloud compute firewall-rules delete  \
    --project "${PROJECT}" \
    --quiet \
    "${MASTER_NAME}-http" || true

  # Delete firewall rules for minions.
  # TODO(satnam6502): Adjust this if we move to just one big firewall rule.\
  local -a firewall_rules
  firewall_rules=( $(gcloud compute firewall-rules list --project "${PROJECT}" \
                       --regexp "${INSTANCE_PREFIX}-minion-[0-9]+-all" \
                       | awk 'NR >= 2 { print $1 }') )
  while (( "${#firewall_rules[@]}" > 0 )); do
    echo Deleting firewall rules "${firewall_rules[*]::10}"
    gcloud compute firewall-rules delete  \
      --project "${PROJECT}" \
      --quiet \
      "${firewall_rules[@]::10}" || true
    firewall_rules=( "${firewall_rules[@]:10}" )
  done

  # Delete routes.
  local -a routes
  routes=( $(gcloud compute routes list --project "${PROJECT}" \
              --regexp "${INSTANCE_PREFIX}-minion-[0-9]+" | awk 'NR >= 2 { print $1 }') )
  while (( "${#routes[@]}" > 0 )); do
    echo Deleting routes "${routes[*]::10}"
    gcloud compute routes delete \
      --project "${PROJECT}" \
      --quiet \
      "${routes[@]::10}" || true
    routes=( "${routes[@]:10}" )
  done
}

# Update a kubernetes cluster with latest source
function kube-push {
  detect-project
  detect-master

  # Make sure we have the tar files staged on Google Storage
  find-release-tars
  upload-server-tars

  # Re-upload the metadata
  ensure-temp-dir
  detect-master-internal-ip

  ensure-master-metadata
  gcloud compute instances add-metadata \
      "${KUBE_MASTER}" --project "$PROJECT" --zone "$ZONE" \
    --metadata-from-file kubernetes-master-params="${KUBERNETES_MASTER_PARAMS_TMP}"
  gcloud compute instances add-metadata \
      "${KUBE_MASTER}" --project "$PROJECT" --zone "$ZONE" \
    --metadata-from-file user-data="${KUBE_ROOT}/cluster/gce-coreos/master.yaml"

  for (( i=0; i<${#MINION_NAMES[@]}; i++)); do
    ensure-minion-i-metadata $i
    gcloud compute instances add-metadata \
      "${MINION_NAMES[$i]}" --project "$PROJECT" --zone "$ZONE" \
      --metadata-from-file kubernetes-minion-params="${KUBERNETES_MINION_PARAMS_TMP[$i]}"
    gcloud compute instances add-metadata \
      "${MINION_NAMES[$i]}" --project "$PROJECT" --zone "$ZONE" \
      --metadata-from-file user-data="${KUBE_ROOT}/cluster/gce-coreos/minion.yaml"

    # Rebooting on CoreOS kills the shell before a successful return is received.
    # Hence the need to swallow non-zero exit values.
    gcloud compute ssh --project "$PROJECT" --zone "$ZONE" "${MINION_NAMES[$i]}" \
         --command "sudo reboot" >/dev/null 2>&1 || :
  done;

  # Rebooting on CoreOS kills the shell before a successful return is received.
  # Hence the need to swallow non-zero exit values.
  gcloud compute ssh --project "$PROJECT" --zone "$ZONE" "$KUBE_MASTER" \
         --command "sudo reboot" >/dev/null 2>&1 || :

  get-password

  echo
  echo "Kubernetes cluster is running.  The master is running at:"
  echo
  echo "  ${KUBERNETES_MASTER}"
  echo
  echo "There is no authentication aside from your IP.  You have no security."
  echo
}

# -----------------------------------------------------------------------------
# Cluster specific test helpers used from hack/e2e-test.sh

# Execute prior to running tests to build a release if required for env.
#
# Assumed Vars:
#   KUBE_ROOT
function test-build-release {
  # Make a release
  "${KUBE_ROOT}/build/release.sh"
}

# Execute prior to running tests to initialize required structure. This is
# called from hack/e2e-test.sh.
#
# Assumed vars:
#   PROJECT
#   Variables from config.sh
function test-setup {

  # Detect the project into $PROJECT if it isn't set
  # gce specific
  detect-project

  # Open up port 80 & 8080 so common containers on minions can be reached
  gcloud compute firewall-rules create \
    --project "${PROJECT}" \
    --target-tags "${MINION_TAG}" \
    --allow tcp:80 tcp:8080 \
    --network "${NETWORK}" \
    "${MINION_TAG}-${INSTANCE_PREFIX}-http-alt"
}

# Execute after running tests to perform any required clean-up.  This is called
# from hack/e2e-test.sh
#
# Assumed Vars:
#   PROJECT
function test-teardown {
  echo "Shutting down test cluster in background."
  gcloud compute firewall-rules delete  \
    --project "${PROJECT}" \
    --quiet \
    "${MINION_TAG}-${INSTANCE_PREFIX}-http-alt" || true
  "${KUBE_ROOT}/cluster/kube-down.sh"
}

# SSH to a node by name ($1) and run a command ($2).
function ssh-to-node {
  local node="$1"
  local cmd="$2"
  gcloud compute ssh --ssh-flag="-o LogLevel=quiet" --project ${PROJECT} --zone="${ZONE}" "${node}" --command "${cmd}"
}

# Restart the kube-proxy on a node ($1)
function restart-kube-proxy {
  ssh-to-node "$1" "sudo systemctl restart kube-proxy"
}

# Setup monitoring using heapster and InfluxDB
function setup-monitoring {
  # TODO: Here's where we would set up cluster monitoring, if we actually
  # supported ENABLE_CLUSTER_MONITORING.
  true
}

function teardown-monitoring {
  # TODO: Here's where we would tear down cluster monitoring, if we
  # actually supported ENABLE_CLUSTER_MONITORING.
  true
}

# Perform preparations required to run e2e tests
function prepare-e2e() {
  detect-project
}
