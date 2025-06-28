# Generate SECURITY-REPORT.md
echo "Generating SECURITY-REPORT.md..."

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

echo "SECURITY-REPORT.md generated."