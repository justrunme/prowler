#!/bin/bash

set -euxo pipefail

# Debugging: Print current working directory and list contents
pwd
ls -la

DATE=$(date +%Y-%m-%d)

# Create report directories
mkdir -p reports/{prowler,kubescape,kube-bench,trivy}

echo "Report directories created:"
find reports -type d

# Install tools
echo "Installing tools..."

# Install minikube
if ! command -v minikube &> /dev/null
then
    echo "[*] Installing minikube..."
    curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
    sudo install minikube-linux-amd64 /usr/local/bin/minikube
    echo "[✓] minikube installed."
else
    echo "[✓] minikube already installed."
fi

# Install kubectl
if ! command -v kubectl &> /dev/null
then
    echo "[*] Installing kubectl..."
    sudo apt-get update && sudo apt-get install -y kubectl
    echo "[✓] kubectl installed."
else
    echo "[✓] kubectl already installed."
fi

# Install trivy
if ! command -v trivy &> /dev/null
then
    echo "[*] Installing trivy..."
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
    echo "[✓] trivy installed."
else
    echo "[✓] trivy already installed."
fi

# Install kubescape
if ! command -v kubescape &> /dev/null
then
    echo "[*] Installing kubescape..."
    curl -s https://raw.githubusercontent.com/armosec/kubescape/master/install.sh | /bin/bash
    sudo mv ~/.kubescape/bin/kubescape /usr/local/bin/
    echo "[✓] kubescape installed."
else
    echo "[✓] kubescape already installed."
fi

# Install jq (for parsing JSON reports)
if ! command -v jq &> /dev/null
then
    echo "[*] Installing jq..."
    sudo apt-get update && sudo apt-get install -y jq
    echo "[✓] jq installed."
else
    echo "[✓] jq already installed."
fi

echo "Tools installation complete."

# Start Minikube
echo "[*] Starting Minikube..."
minikube start --driver=docker
if [ $? -eq 0 ]; then
    echo "[✓] Minikube started."
else
    echo "[!] Minikube failed to start."
    exit 1
fi

# Run kube-bench
echo "[*] Running kube-bench..."
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml

echo "[*] Waiting for kube-bench pod to appear..."
for i in {1..15}; do
  if kubectl get pod -l job-name=kube-bench | grep kube-bench; then
    echo "[✓] Pod found"
    break
  fi
  echo "[.] Still waiting for kube-bench pod..."
  sleep 5
done

echo "[*] Waiting for kube-bench pod to be ready..."
kubectl wait --for=condition=ready pod -l job-name=kube-bench --timeout=60s || {
  echo "[!] kube-bench pod not ready in time."
  kubectl get pods -l job-name=kube-bench -o wide
  exit 1
}

kubectl logs -l job-name=kube-bench > reports/kube-bench/kube-bench-report-${DATE}.txt || echo "[!] Failed to get kube-bench logs"

kubectl delete -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
echo "[✓] kube-bench completed"

# Prepare Trivy...
echo "[*] Preparing Trivy..."
export KUBECONFIG=$HOME/.kube/config
kubectl config rename-context minikube cluster || true # Rename minikube context to cluster for Trivy compatibility
kubectl config use-context cluster
kubectl get nodes
if [ $? -eq 0 ]; then
    echo "[✓] Trivy context prepared."
else
    echo "[!] Failed to prepare Trivy context."
    exit 1
fi

echo "[*] Running trivy..."
trivy k8s cluster --report summary --format json > reports/trivy/cluster-report-${DATE}.json
if [ $? -eq 0 ]; then
    echo "[✓] trivy completed. Report saved to reports/trivy/cluster-report-${DATE}.json"
else
    echo "[!] trivy failed."
fi

# Run kubescape
echo "[*] Running kubescape..."
kubescape scan framework nsa --format json --output reports/kubescape/kubescape-report-${DATE}.json
if [ $? -eq 0 ]; then
    echo "[✓] kubescape completed. Report saved to reports/kubescape/kubescape-report-${DATE}.json"
else
    echo "[!] kubescape failed."
fi

# Run Prowler CLI
echo "[*] Running Prowler..."
# Create a dummy AWS credentials file for Prowler to run
mkdir -p $HOME/.aws
echo "[default]" > $HOME/.aws/credentials
echo "aws_access_key_id = ${AWS_ACCESS_KEY_ID}" >> $HOME/.aws/credentials
echo "aws_secret_access_key = ${AWS_SECRET_ACCESS_KEY}" >> $HOME/.aws/credentials

cd prowler
pip install . --quiet
cd ..
mkdir -p reports/prowler
prowler -M html,csv,json -S -n --output-path reports/prowler/prowler-report-${DATE}
if [ $? -eq 0 ]; then
    echo "[✓] Prowler completed. Reports saved to reports/prowler/"
else
    echo "[!] Prowler failed."
fi

echo "All audits completed."

# Generate SECURITY-REPORT.md
echo "[*] Generating SECURITY-REPORT.md..."

echo "# Kubernetes Security Audit Summary" > SECURITY-REPORT.md
echo "" >> SECURITY-REPORT.md
echo "_Last run: ${DATE}_" >> SECURITY-REPORT.md
echo "" >> SECURITY-REPORT.md

# Kube-bench (CIS Benchmark) - Placeholder for now, as it's a text report
# For a more detailed summary, parsing the text report would be needed.
echo "## CIS Benchmark (kube-bench)" >> SECURITY-REPORT.md
echo "- Status: See reports/kube-bench/kube-bench-report-${DATE}.txt" >> SECURITY-REPORT.md
echo "" >> SECURITY-REPORT.md

# Trivy
TRIVY_REPORT="reports/trivy/cluster-report-${DATE}.json"
if [ -f "$TRIVY_REPORT" ]; then
    CRITICAL_VULNS=$(jq '.vulnerabilities | map(select(.Severity == "CRITICAL")) | length' "$TRIVY_REPORT")
    HIGH_VULNS=$(jq '.vulnerabilities | map(select(.Severity == "HIGH")) | length' "$TRIVY_REPORT")
    MEDIUM_VULNS=$(jq '.vulnerabilities | map(select(.Severity == "MEDIUM")) | length' "$TRIVY_REPORT")
    LOW_VULNS=$(jq '.vulnerabilities | map(select(.Severity == "LOW")) | length' "$TRIVY_REPORT")
    UNKNOWN_VULNS=$(jq '.vulnerabilities | map(select(.Severity == "UNKNOWN")) | length' "$TRIVY_REPORT")

    echo "## Trivy Vulnerability Scan" >> SECURITY-REPORT.md
    echo "- Critical: ${CRITICAL_VULNS}" >> SECURITY-REPORT.md
    echo "- High: ${HIGH_VULNS}" >> SECURITY-REPORT.md
    echo "- Medium: ${MEDIUM_VULNS}" >> SECURITY-REPORT.md
    echo "- Low: ${LOW_VULNS}" >> SECURITY-REPORT.md
    echo "- Unknown: ${UNKNOWN_VULNS}" >> SECURITY-REPORT.md
    echo "" >> SECURITY-REPORT.md
else
    echo "## Trivy Vulnerability Scan" >> SECURITY-REPORT.md
    echo "- Status: Report not found or failed to generate." >> SECURITY-REPORT.md
    echo "" >> SECURITY-REPORT.md
fi

# Kubescape
KUBESCAPE_REPORT="reports/kubescape/kubescape-report-${DATE}.json"
if [ -f "$KUBESCAPE_REPORT" ]; then
    NSA_SCORE=$(jq '.summary.frameworks[] | select(.name == "NSA") | .score' "$KUBESCAPE_REPORT")
    MITRE_SCORE=$(jq '.summary.frameworks[] | select(.name == "MITRE") | .score' "$KUBESCAPE_REPORT")

    echo "## Kubescape Compliance" >> SECURITY-REPORT.md
    echo "- NSA Framework Score: ${NSA_SCORE}%" >> SECURITY-REPORT.md
    echo "- MITRE ATT&CK Score: ${MITRE_SCORE}%" >> SECURITY-REPORT.md
    echo "" >> SECURITY-REPORT.md
else
    echo "## Kubescape Compliance" >> SECURITY-REPORT.md
    echo "- Status: Report not found or failed to generate." >> SECURITY-REPORT.md
    echo "" >> SECURITY-REPORT.md
fi

# Prowler (assuming HTML report is generated, parsing JSON would be better if available)
# Prowler generates HTML, CSV, JSON. We'll try to parse the JSON if it's there.
PROWLER_JSON_REPORT="reports/prowler/prowler-report-${DATE}.json"
if [ -f "$PROWLER_JSON_REPORT" ]; then
    # Prowler JSON structure can be complex, this is a simplified example
    # You might need to adjust this based on the actual JSON output structure
    TOTAL_FINDINGS=$(jq '.findings | length' "$PROWLER_JSON_REPORT")
    echo "## Prowler AWS Security Audit" >> SECURITY-REPORT.md
    echo "- Total Findings: ${TOTAL_FINDINGS}" >> SECURITY-REPORT.md
    echo "- Status: See reports/prowler/prowler-report-${DATE}.html for details." >> SECURITY-REPORT.md
    echo "" >> SECURITY-REPORT.md
else
    echo "## Prowler AWS Security Audit" >> SECURITY-REPORT.md
    echo "- Status: Report not found or failed to generate." >> SECURITY-REPORT.md
    echo "" >> SECURITY-REPORT.md
fi

echo "[✓] SECURITY-REPORT.md generated."

echo "Report folders created:"
find reports -type f || echo "⚠️ No reports found!"
