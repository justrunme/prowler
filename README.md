# Kubernetes Security Audit with Open-Source Tools

This project demonstrates an automated security audit of a Kubernetes cluster (Minikube) using a combination of open-source security tools: `kube-bench`, `trivy`, `kubescape`, and `prowler`.

## Project Goal

The primary goal is to simulate cloud security scanning locally within a Kubernetes environment and provide a comprehensive security audit, generating detailed reports for various security aspects. This setup is ideal for DevSecOps portfolios, showcasing expertise in cloud security, best practices, and automated analysis.

## Project Structure

```
prowler-k8s-security/
├── README.md
├── .github/workflows/k8s-audit.yml
├── manifests/
│   └── prowler-pod.yaml          # Prowler pod definition (optional, for in-cluster run)
├── scripts/
│   └── run_all_audits.sh         # Wrapper script to run all audit tools
├── reports/
│   └── prowler/
│   └── kube-bench/
│   └── trivy/
│   └── kubescape/
└── SECURITY-REPORT.md            # Automated security summary
```

## Tools Used

*   **Minikube**: A tool that runs a single-node Kubernetes cluster locally.
*   **kube-bench**: Checks whether Kubernetes is deployed securely by running the checks documented in the CIS Kubernetes Benchmark.
*   **Trivy**: A comprehensive security scanner for vulnerabilities in container images, filesystems, and Git repositories. Used here for Kubernetes cluster scanning.
*   **Kubescape**: An open-source tool for testing Kubernetes clusters against various security frameworks (e.g., NSA, MITRE ATT&CK).
*   **Prowler**: An open-source tool for security auditing, hardening, and incident response in cloud environments (AWS, Azure, GCP). Used here to simulate AWS security checks within the CI/CD pipeline.

## Getting Started

### Prerequisites

*   Docker (for Minikube driver)
*   `git`

### Local Execution

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/justrunme/prowler.git
    cd prowler
    ```
2.  **Run the audit script:**
    ```bash
    bash scripts/run_all_audits.sh
    ```

    This script will:
    *   Install necessary tools (`minikube`, `kubectl`, `trivy`, `kubescape`, `awscli`).
    *   Start a Minikube cluster.
    *   Execute `kube-bench`, `trivy`, `kubescape`, and `prowler`.
    *   Generate reports in the `reports/` directory.

### CI/CD with GitHub Actions

The `k8s-audit.yml` workflow automates the audit process on every `push` to the `main` branch and can also be triggered manually via `workflow_dispatch`.

To run the GitHub Actions workflow:
1.  Push your code to your GitHub repository.
2.  Navigate to the "Actions" tab in your repository.
3.  Select the "K8s Audit on Minikube" workflow and observe its execution.

## Reports

Audit reports will be generated in the `reports/` directory, with filenames including the current date for better organization:

*   `reports/prowler/prowler-report-YYYY-MM-DD.html`
*   `reports/kube-bench/kube-bench-report-YYYY-MM-DD.txt`
*   `reports/trivy/cluster-report-YYYY-MM-DD.json`
*   `reports/kubescape/kubescape-report-YYYY-MM-DD.json`

Additionally, a summarized security report will be available at `SECURITY-REPORT.md` in the project root.

To view the full reports from GitHub Actions, download the `audit-reports` artifact from the completed workflow run.

## Security Considerations

**AWS Credentials:** This project uses dummy AWS credentials for Prowler's execution. For real-world scenarios, it is crucial to use actual AWS credentials configured as [GitHub Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets) and ensure they have the minimum necessary permissions (e.g., `SecurityAudit` IAM policy).

## Future Enhancements

*   **Automated PASS/FAIL checks:** Implement logic to parse report results and fail the CI pipeline based on defined thresholds (e.g., critical vulnerabilities, low compliance scores).
*   **HTML Dashboard:** Generate a simple HTML dashboard with links to all reports, potentially hosted via GitHub Pages.
*   **Notification Integration:** Send alerts to Slack/Telegram for critical findings.
*   **Custom Checks:** Develop custom checks for Prowler or other tools.
*   **Multi-Cloud Support:** Extend auditing to Azure or GCP.