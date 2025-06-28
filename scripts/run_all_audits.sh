#!/bin/bash

set -euxo pipefail

# Create report directories
mkdir -p reports/kube-bench
mkdir -p reports/trivy
mkdir -p reports/kubescape
mkdir -p reports/prowler

# Install tools
echo "Installing tools..."

# Install minikube
if ! command -v minikube &> /dev/null
then
    curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
    sudo install minikube-linux-amd64 /usr/local/bin/minikube
fi

# Install kubectl
if ! command -v kubectl &> /dev/null
then
    sudo apt-get update && sudo apt-get install -y kubectl
fi

# Install trivy
if ! command -v trivy &> /dev/null
then
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
fi

# Install kubescape
if ! command -v kubescape &> /dev/null
then
    curl -s https://raw.githubusercontent.com/armosec/kubescape/master/install.sh | /bin/bash
fi

echo "Tools installed."

# Start Minikube
echo "Starting Minikube..."
minikube start --driver=docker
echo "Minikube started."

# Run kube-bench
echo "Running kube-bench..."
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
sleep 10 # Give some time for the job to complete
JOB_NAME=$(kubectl get jobs -l app=kube-bench -o jsonpath='{.items[0].metadata.name}')
kubectl logs -l job-name=${JOB_NAME} > reports/kube-bench/kube-bench-report.txt
kubectl delete -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
echo "kube-bench finished. Report saved to reports/kube-bench/kube-bench-report.txt"

# Run trivy
echo "Running trivy..."
trivy k8s cluster --report summary --format json > reports/trivy/trivy-report.json
echo "trivy finished. Report saved to reports/trivy/trivy-report.json"

# Run kubescape
echo "Running kubescape..."
kubescape scan framework nsa --format json --output reports/kubescape/kubescape-report.json
echo "kubescape finished. Report saved to reports/kubescape/kubescape-report.json"

# Run Prowler via Docker
echo "Running Prowler..."
# Create a dummy AWS credentials file for Prowler to run
mkdir -p ~/.aws
echo "[default]" > ~/.aws/credentials
echo "aws_access_key_id = AKIAIOSFODNN7EXAMPLE" >> ~/.aws/credentials
echo "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" >> ~/.aws/credentials

docker run -t --rm \
  -v ~/.aws:/root/.aws \
  -v "$(pwd)"/reports/prowler:/prowler/output \
  ghcr.io/prowler-cloud/prowler \
  -M html,csv,json -S -n

echo "Prowler finished. Reports saved to reports/prowler/"

echo "All audits completed."
