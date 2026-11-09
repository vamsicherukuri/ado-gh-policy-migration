# GitHub Enterprise Organization Governance Audit Report

- **Target Organizations**: ADO2GHEC
- **Applied At**: 2026-11-09 20:54:03 UTC
- **Source of Truth**: C:\Users\vcherukuri\factory\ado to gh branch policies\org\config\ado-to-ghec-crosswalk.csv
- **Rollback Available**: 05_Rollback-GitHubOrgPolicies.ps1

---

## Applied Organization Policies

| Policy Key | Property Name | Applied Value | Status |
| :--- | :--- | :---: | :---: |
| GH-GOVERNANCE | members_allowed_repository_creation_type | private | Verified |
| GH-GOVERNANCE | members_can_create_public_repositories | False | Verified |
| GH-GOVERNANCE | members_can_fork_private_repositories | False | Verified |

---

## Rollback Command

To instantly revert all settings back to the exact pre-flight snapshot:
```powershell
pwsh .\05_Rollback-GitHubOrgPolicies.ps1
```
