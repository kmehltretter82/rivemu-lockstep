#!/usr/bin/env bash
# Paste this script directly into Google Cloud Shell (>_ icon in Google Cloud Console).
# It creates 3 Ubuntu 24.04 LTS VMs (<= $3/day each using Spot provisioning + STOP on preemption),
# installs your Mac's SSH public key, and prints the 3 External IP addresses at the end.
set -euo pipefail

ZONE="${ZONE:-us-central1-a}"
SSH_KEY="kmehltretter:ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKZJc8BYBLOto+YpbS9Zm8EfBgv+xnREem2uV2Nl3qDx kmehltretter"

echo "=== Enabling Compute Engine API (if not already enabled) ==="
gcloud services enable compute.googleapis.com

echo "=== Creating rivemu-x86-1 (8 vCPU, 32 GB RAM, Ubuntu 24.04 x86_64, Spot ~$2.05/day) ==="
gcloud compute instances create rivemu-x86-1 \
  --zone="$ZONE" \
  --machine-type=e2-standard-8 \
  --provisioning-model=SPOT \
  --instance-termination-action=STOP \
  --maintenance-policy=TERMINATE \
  --image-family=ubuntu-2404-lts-amd64 \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=50GB \
  --boot-disk-type=pd-standard \
  --metadata="ssh-keys=${SSH_KEY}"

echo "=== Creating rivemu-x86-2 (8 vCPU, 32 GB RAM, Ubuntu 24.04 x86_64, Spot ~$2.05/day) ==="
gcloud compute instances create rivemu-x86-2 \
  --zone="$ZONE" \
  --machine-type=e2-standard-8 \
  --provisioning-model=SPOT \
  --instance-termination-action=STOP \
  --maintenance-policy=TERMINATE \
  --image-family=ubuntu-2404-lts-amd64 \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=50GB \
  --boot-disk-type=pd-standard \
  --metadata="ssh-keys=${SSH_KEY}"

echo "=== Creating rivemu-arm64-1 (4 vCPU, 16 GB RAM, Ubuntu 24.04 ARM64, Spot ~$1.45/day) ==="
gcloud compute instances create rivemu-arm64-1 \
  --zone="$ZONE" \
  --machine-type=t2a-standard-4 \
  --provisioning-model=SPOT \
  --instance-termination-action=STOP \
  --maintenance-policy=TERMINATE \
  --image-family=ubuntu-2404-lts-arm64 \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=50GB \
  --boot-disk-type=pd-standard \
  --metadata="ssh-keys=${SSH_KEY}"

echo ""
echo "=== ALL 3 INSTANCES CREATED — COPY THESE IPS INTO CHAT ==="
gcloud compute instances list \
  --filter="name=(rivemu-x86-1,rivemu-x86-2,rivemu-arm64-1)" \
  --format="table(name,zone,machineType.basename(),status,networkInterfaces[0].accessConfigs[0].natIP:label=EXTERNAL_IP)"
