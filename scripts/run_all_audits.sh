#!/bin/bash
set -euxo pipefail

DATE=$(date +%Y-%m-%d)

# Create report directories
mkdir -p reports/{prowler,kubescape,kube-bench,trivy}

# Tool installation checks (minikube, kubectl, trivy, kubescape, jq) — опущены здесь для краткости

# Start Minikube
minikube start --driver=docker

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

# Run Trivy
echo "[*] Running trivy..."
export KUBECONFIG=$HOME/.kube/config
kubectl config rename-context minikube cluster || true
kubectl config use-context cluster

trivy k8s cluster --report summary --format json > reports/trivy/cluster-report-${DATE}.json || echo "[!] Trivy failed"

# Run Kubescape
echo "[*] Running kubescape..."
kubescape scan framework nsa --format json --output reports/kubescape/kubescape-report-${DATE}.json || echo "[!] Kubescape failed"

# Run Prowler
echo "[*] Running Prowler..."
mkdir -p $HOME/.aws
echo "[default]" > $HOME/.aws/credentials
echo "aws_access_key_id = ${AWS_ACCESS_KEY_ID}" >> $HOME/.aws/credentials
echo "aws_secret_access_key = ${AWS_SECRET_ACCESS_KEY}" >> $HOME/.aws/credentials

cd prowler
pip install . --quiet
cd ..

mkdir -p reports/prowler
prowler aws --no-banner \
  --output-formats html --output-formats csv --output-formats json-asff \
  --output-directory reports/prowler --output-filename prowler-report-${DATE} \
  || echo "[!] Prowler finished with compliance issues (exit code ignored)"

echo "[✓] Prowler completed. Reports saved to reports/prowler/"

# Generate SECURITY-REPORT.md
echo "[*] Generating SECURITY-REPORT.md..."

SECURITY_MD="reports/SECURITY-REPORT.md"
echo "# Kubernetes Security Audit Summary" > "$SECURITY_MD"
echo "" >> "$SECURITY_MD"
echo "_Last run: ${DATE}_" >> "$SECURITY_MD"
echo "" >> "$SECURITY_MD"

# Kube-bench
echo "## CIS Benchmark (kube-bench)" >> "$SECURITY_MD"
echo "- Status: See reports/kube-bench/kube-bench-report-${DATE}.txt" >> "$SECURITY_MD"
echo "" >> "$SECURITY_MD"

# Trivy
TRIVY_REPORT="reports/trivy/cluster-report-${DATE}.json"
if [ -s "$TRIVY_REPORT" ]; then
    CRITICAL_VULNS=$(jq '.vulnerabilities // [] | map(select(.Severity == "CRITICAL")) | length' "$TRIVY_REPORT" || echo "N/A")
    HIGH_VULNS=$(jq '.vulnerabilities // [] | map(select(.Severity == "HIGH")) | length' "$TRIVY_REPORT" || echo "N/A")
    MEDIUM_VULNS=$(jq '.vulnerabilities // [] | map(select(.Severity == "MEDIUM")) | length' "$TRIVY_REPORT" || echo "N/A")
    LOW_VULNS=$(jq '.vulnerabilities // [] | map(select(.Severity == "LOW")) | length' "$TRIVY_REPORT" || echo "N/A")
    UNKNOWN_VULNS=$(jq '.vulnerabilities // [] | map(select(.Severity == "UNKNOWN")) | length' "$TRIVY_REPORT" || echo "N/A")

    echo "## Trivy Vulnerability Scan" >> "$SECURITY_MD"
    echo "- Critical: ${CRITICAL_VULNS}" >> "$SECURITY_MD"
    echo "- High: ${HIGH_VULNS}" >> "$SECURITY_MD"
    echo "- Medium: ${MEDIUM_VULNS}" >> "$SECURITY_MD"
    echo "- Low: ${LOW_VULNS}" >> "$SECURITY_MD"
    echo "- Unknown: ${UNKNOWN_VULNS}" >> "$SECURITY_MD"
    echo "" >> "$SECURITY_MD"
else
    echo "## Trivy Vulnerability Scan" >> "$SECURITY_MD"
    echo "- Status: Report not found or failed to generate." >> "$SECURITY_MD"
    echo "" >> "$SECURITY_MD"
fi

# Kubescape
KUBESCAPE_REPORT="reports/kubescape/kubescape-report-${DATE}.json"
if [ -s "$KUBESCAPE_REPORT" ]; then
    NSA_SCORE=$(jq -r '.summary.frameworks[]? | select(.name=="NSA") | .score // "N/A"' "$KUBESCAPE_REPORT")
    MITRE_SCORE=$(jq -r '.summary.frameworks[]? | select(.name=="MITRE") | .score // "N/A"' "$KUBESCAPE_REPORT")

    echo "## Kubescape Compliance" >> "$SECURITY_MD"
    echo "- NSA Framework Score: ${NSA_SCORE}%" >> "$SECURITY_MD"
    echo "- MITRE ATT&CK Score: ${MITRE_SCORE}%" >> "$SECURITY_MD"
    echo "" >> "$SECURITY_MD"
else
    echo "## Kubescape Compliance" >> "$SECURITY_MD"
    echo "- Status: Report not found or failed to generate." >> "$SECURITY_MD"
    echo "" >> "$SECURITY_MD"
fi

# Prowler
PROWLER_JSON="reports/prowler/prowler-report-${DATE}.json"
if [ -s "$PROWLER_JSON" ]; then
    FINDINGS=$(jq '.findings | length' "$PROWLER_JSON" || echo "N/A")
    echo "## Prowler AWS Security Audit" >> "$SECURITY_MD"
    echo "- Total Findings: ${FINDINGS}" >> "$SECURITY_MD"
    echo "- Status: See reports/prowler/prowler-report-${DATE}.html for details." >> "$SECURITY_MD"
    echo "" >> "$SECURITY_MD"
else
    echo "## Prowler AWS Security Audit" >> "$SECURITY_MD"
    echo "- Status: Report not found or failed to generate." >> "$SECURITY_MD"
    echo "" >> "$SECURITY_MD"
fi

echo "[✓] SECURITY-REPORT.md generated at $SECURITY_MD"
