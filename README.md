# Wiz SBOM Version Gate 🛡️

A GitHub Action and CLI utility that leverages **Wiz CLI** to generate a **CycloneDX SBOM** and fails or passes CI/CD builds based on detected library/package versions.

---

## Features

- 📦 **Automated SBOM Generation**: Generates standard CycloneDX JSON SBOMs from repositories or Docker images.
- 🎯 **Version Policy Gating**: Block builds on specific package thresholds (e.g., `< 2.17.1`) or exact banned releases.
- ⚙️ **SemVer Aware**: Uses `sort -V` version sorting to evaluate semantic versions and pre-releases.
- 🚀 **Dual Usage**: Use as a native GitHub Action (`uses: ...`) or run the standalone Bash script anywhere (GitLab CI, Jenkins, Azure DevOps).

---

## Quickstart (GitHub Actions)

### 1. Add Secrets
Configure `WIZ_CLIENT_ID` and `WIZ_CLIENT_SECRET` in **Settings > Secrets and variables > Actions**.

### 2. Add Workflow Step

#### Using a Rules File:
```yaml
- name: Wiz SBOM Version Gate
  uses: sebastian-kunze/wiz-sbom-version-gate@v1
  with:
    wiz_client_id: ${{ secrets.WIZ_CLIENT_ID }}
    wiz_client_secret: ${{ secrets.WIZ_CLIENT_SECRET }}
    rules_file: 'rules.example.txt'
