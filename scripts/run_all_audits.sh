#!/bin/bash

set -euxo pipefail

DATE=$(date +%Y-%m-%d)

# Create report directories
mkdir -p reports/{prowler,kubescape,kube-bench,trivy}

echo "Report directories created:"
find reports -type d

# Install tools
echo "Installing tools..."

# Install minikube
if ! command -v minikube &> /dev/null; then
    echo "[*] Installing minikube..."
    curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
    sudo install minikube-linux-amd64 /usr/local/bin/minikube
    echo "[✓] minikube installed."
else
    echo "[✓] minikube already installed."
fi

# Install kubectl
if ! command -v kubectl &> /dev/null; then
    echo "[*] Installing kubectl..."
    sudo apt-get update && sudo apt-get install -y kubectl
    echo "[✓] kubectl installed."
else
    echo "[✓] kubectl already installed."
fi

# Install trivy
if ! command -v trivy &> /dev/null; then
    echo "[*] Installing trivy..."
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
    echo "[✓] trivy installed."
else
    echo "[✓] trivy already installed."
fi

# Install kubescape
if ! command -v kubescape &> /dev/null; then
    echo "[*] Installing kubescape..."
    curl -s https://raw.githubusercontent.com/armosec/kubescape/master/install.sh | /bin/bash
    sudo mv ~/.kubescape/bin/kubescape /usr/local/bin/
    echo "[✓] kubescape installed."
else
    echo "[✓] kubescape already installed."
fi

# Install jq
if ! command -v jq &> /dev/null; then
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
echo "[✓] Minikube started."

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

# Trivy
echo "[*] Preparing Trivy..."
export KUBECONFIG=$HOME/.kube/config
kubectl config rename-context minikube cluster || true
kubectl config use-context cluster

kubectl get nodes
echo "[✓] Trivy context prepared."

echo "[*] Running trivy..."
trivy k8s cluster --report summary --format json > reports/trivy/cluster-report-${DATE}.json || echo "[!] trivy failed."
echo "[✓] trivy completed."

# Kubescape
echo "[*] Running kubescape..."
kubescape scan framework nsa --format json --output reports/kubescape/kubescape-report-${DATE}.json || echo "[!] kubescape failed."
echo "[✓] kubescape completed."

# Prowler
echo "[*] Running Prowler..."
mkdir -p $HOME/.aws
echo "[default]" > $HOME/.aws/credentials
echo "aws_access_key_id = ${AWS_ACCESS_KEY_ID}" >> $HOME/.aws/credentials
echo "aws_secret_access_key = ${AWS_SECRET_ACCESS_KEY}" >> $HOME/.aws/credentials

cd prowler
pip install . --quiet
cd ..

mkdir -p reports/prowler

prowler aws --no-banner --output-formats html --output-formats csv --output-formats json-asff \
  --output-directory reports/prowler --output-filename prowler-report-${DATE} || \
  echo "[!] Prowler finished with compliance issues (exit code ignored)"

echo "[✓] Prowler completed. Reports saved to reports/prowler/"

# Report summary
echo "[*] Generating SECURITY-REPORT.md..."
echo "# Kubernetes Security Audit Summary" > SECURITY-REPORT.md
echo "" >> SECURITY-REPORT.md
echo "_Last run: ${DATE}_" >> SECURITY-REPORT.md
echo "" >> SECURITY-REPORT.md

echo "## CIS Benchmark (kube-bench)" >> SECURITY-REPORT.md
echo "- Status: See reports/kube-bench/kube-bench-report-${DATE}.txt" >> SECURITY-REPORT.md
echo "" >> SECURITY-REPORT.md

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

PROWLER_JSON_REPORT="reports/prowler/prowler-report-${DATE}.json"
if [ -f "$PROWLER_JSON_REPORT" ]; then
    TOTAL_FINDINGS=$(jq '.findings | length' "$PROWLER_JSON_REPORT")
    echo "## Prowler AWS Security Audit" >> SECURITY-REPORT.md
    echo "- Total Findings: ${TOTAL_FINDINGS}" >> SECURITY-REPORT.md
    echo "- Status: See HTML report for details." >> SECURITY-REPORT.md
    echo "" >> SECURITY-REPORT.md
else
    echo "## Prowler AWS Security Audit" >> SECURITY-REPORT.md
    echo "- Status: Report not found or failed to generate." >> SECURITY-REPORT.md
    echo "" >> SECURITY-REPORT.md
fi

echo "[✓] SECURITY-REPORT.md generated."
echo "Report folders created:"
find reports -type f || echo "⚠️ No reports found!"

# Автогенерация SECURITY-REPORT.md
echo "[*] Generating SECURITY-REPORT.md..."

SECURITY_REPORT="SECURITY-REPORT.md"

{
echo "# Kubernetes Security Audit Summary"
echo ""
echo "_Last run: ${DATE}_"
echo ""
echo "## CIS Benchmark (kube-bench)"
echo "- Status: See reports/kube-bench/kube-bench-report-${DATE}.txt"
echo ""

echo "## Trivy Vulnerability Scan"
TRIVY_JSON="reports/trivy/cluster-report-${DATE}.json"
if [ -f "$TRIVY_JSON" ]; then
    echo "- Critical: $(jq '.vulnerabilities | map(select(.Severity == "CRITICAL")) | length' "$TRIVY_JSON")"
    echo "- High: $(jq '.vulnerabilities | map(select(.Severity == "HIGH")) | length' "$TRIVY_JSON")"
    echo "- Medium: $(jq '.vulnerabilities | map(select(.Severity == "MEDIUM")) | length' "$TRIVY_JSON")"
    echo "- Low: $(jq '.vulnerabilities | map(select(.Severity == "LOW")) | length' "$TRIVY_JSON")"
    echo "- Unknown: $(jq '.vulnerabilities | map(select(.Severity == "UNKNOWN")) | length' "$TRIVY_JSON")"
else
    echo "- Status: Report not found or failed to generate."
fi
echo ""

echo "## Kubescape Compliance"
KUBESCAPE_JSON="reports/kubescape/kubescape-report-${DATE}.json"
if [ -f "$KUBESCAPE_JSON" ]; then
    NSA_SCORE=$(jq '.summary.frameworks[] | select(.name == "NSA") | .score' "$KUBESCAPE_JSON")
    MITRE_SCORE=$(jq '.summary.frameworks[] | select(.name == "MITRE") | .score' "$KUBESCAPE_JSON")
    echo "- NSA Framework Score: ${NSA_SCORE}%"
    echo "- MITRE ATT&CK Score: ${MITRE_SCORE}%"
else
    echo "- Status: Report not found or failed to generate."
fi
echo ""

echo "## Prowler AWS Security Audit"
PROWLER_JSON="reports/prowler/prowler-report-${DATE}.json"
if [ -f "$PROWLER_JSON" ]; then
    TOTAL_FINDINGS=$(jq '.findings | length' "$PROWLER_JSON")
    echo "- Total Findings: ${TOTAL_FINDINGS}"
    echo "- Status: See reports/prowler/prowler-report-${DATE}.html for details."
else
    echo "- Status: Report not found or failed to generate."
fi
echo ""
} > "$SECURITY_REPORT"

echo "[✓] SECURITY-REPORT.md generated."
