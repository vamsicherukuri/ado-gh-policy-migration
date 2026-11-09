# Migration Utility Execution Guide

This document gives instructions to migrate policies from Azure DevOps to GitHub Enterprise Cloud.
The text follows the ASD-STE100 specification for Simplified Technical English.

---

## 1. Prerequisites

Make sure you have these prerequisites before you start:

1. **PowerShell 7.0 or higher**
   - Run `$PSVersionTable.PSVersion` to verify the version.

2. **Azure DevOps Personal Access Token (PAT)**
   - Required scope: `Code (Read)`, `Project and Team (Read)`.
   - Set the environment variable:
     ```powershell
     $env:ADO_PAT = "your_ado_pat_value"
     ```

3. **GitHub Personal Access Token (PAT)**
   - Required scope: `admin:org`, `repo`.
   - Set the environment variable:
     ```powershell
     $env:GH_PAT = "your_github_pat_value"
     ```

4. **Configuration Files**
   - Verify that these files contain your source and target names:
     - `org/config/orgs.txt` and `org/config/org-mapping.csv`
     - `project/config/projects.txt` and `project/config/project-mapping.csv`
     - `repo/config/repos.txt` and `repo/config/repo-mapping.csv`

---

## 2. Phase 1: Organization Policies

### Step 1: Capture Azure DevOps Organization Policies

Run this command:
```powershell
pwsh .\org\01_Capture-AdoOrgPolicies.ps1
```
**Expected Output:**
- Raw policy JSON file saved to `org/output/<timestamp>/`.
- Progress and success messages shown in the terminal.

---

### Step 2: Group and Crosswalk Organization Policies

Run this command:
```powershell
pwsh .\org\02_Group-AdoOrgPolicies.ps1
```
**Expected Output:**
- Matrix CSV file saved to `org/output/<timestamp>/ado-org-policy-matrix.csv`.
- Summary counts of applicable policies shown in the terminal.

---

### Step 3: Snapshot Existing GitHub Organization Settings

Run this command:
```powershell
pwsh .\org\03_Snapshot-GitHubOrgPolicies.ps1
```
**Expected Output:**
- Pre-flight snapshot saved to `org/output/snapshots/<org>-latest-preflight.json`.
- Terminal confirms the snapshot file creation.

---

### Step 4: Apply Organization Policies to GitHub

Run this command:
```powershell
pwsh .\org\04_Apply-GitHubOrgPolicies.ps1
```
> **Note:** To preview changes without applying them, add the `-WhatIf` parameter.

**Expected Output:**
- Policies applied to the target GitHub organization.
- Audit log saved to `org/output/<timestamp>/execution.log`.
- Success confirmation shown in the terminal.

---

## 3. Phase 2: Project Policies

### Step 1: Capture Azure DevOps Project Policies

Run this command:
```powershell
pwsh .\project\01_Capture-AdoProjectPolicies.ps1
```
**Expected Output:**
- JSON file saved for each project in `project/output/<timestamp>/`.
- Count of captured policies shown in the terminal.

---

### Step 2: Group and Crosswalk Project Policies

Run this command:
```powershell
pwsh .\project\02_Group-AdoProjectPolicies.ps1
```
**Expected Output:**
- Matrix CSV file saved to `project/output/<timestamp>/project-policy-matrix.csv`.
- Matrix summary displayed in the terminal.

---

### Step 3: Snapshot Existing GitHub Rulesets

Run this command:
```powershell
pwsh .\project\03_Snapshot-GitHubRulesets.ps1
```
**Expected Output:**
- Pre-flight snapshot saved to `project/output/snapshots/<org>-latest-rulesets-preflight.json`.
- Terminal shows count of existing rulesets saved.

---

### Step 4: Apply Project Rulesets to GitHub

Run this command to create rulesets in evaluation mode:
```powershell
pwsh .\project\04_Apply-GitHubRulesets.ps1 -Enforcement evaluate -Scope Repo
```
> **Note:** To preview changes without applying them, add the `-WhatIf` parameter.

**Expected Output:**
- Rulesets created on target GitHub repositories in `evaluate` mode.
- Audit log saved to `project/output/<timestamp>/execution.log`.
- Success status shown for each repository in the terminal.

---

## 4. Phase 3: Repository and Branch Policies

### Step 1: Capture Azure DevOps Repository and Branch Policies

Run this command:
```powershell
pwsh .\repo\01_Capture-AdoRepoPolicies.ps1
```
**Expected Output:**
- Policy JSON files saved for each repository in `repo/output/<timestamp>/`.
- Detailed log saved to `repo/output/<timestamp>/execution.log`.
- Minimal progress updates shown in the terminal.

---

### Step 2: Group and Crosswalk Repository Policies

Run this command:
```powershell
pwsh .\repo\02_Group-AdoRepoPolicies.ps1
```
**Expected Output:**
- Matrix CSV file saved to `repo/output/<timestamp>/repo-policy-matrix.csv`.
- Detailed analysis saved to `repo/output/<timestamp>/execution.log`.
- Policy summary count shown in the terminal.

---

### Step 3: Snapshot Existing GitHub Repository Rulesets

Run this command:
```powershell
pwsh .\repo\03_Snapshot-GitHubRepoRulesets.ps1
```
**Expected Output:**
- Pre-flight snapshot saved to `repo/output/snapshots/<org>-repo-rulesets-snapshot-<timestamp>.json`.
- Latest pointer updated at `repo/output/snapshots/<org>-latest-repo-rulesets-preflight.json`.
- Terminal confirms the snapshot file creation.

---

### Step 4: Apply Repository and Branch Rulesets to GitHub

Run this command to create rulesets in evaluation mode:
```powershell
pwsh .\repo\04_Apply-GitHubRepoRulesets.ps1 -Enforcement evaluate
```
> **Note:** To preview changes without applying them, add the `-WhatIf` parameter.

**Expected Output:**
- Branch and tag rulesets created on target GitHub repositories.
- Audit log saved to `repo/output/<timestamp>/execution.log`.
- Terminal shows concise status for each target branch.

---

## 5. Phase 4: Verification and Mode Control

### Step 1: Run Automated Verification Tests

Run this command:
```powershell
pwsh .\test_suite\Run-AllTests.ps1
```
**Expected Output:**
- Terminal shows test results for all phases.
- Result line confirms: `ALL PHASES PASSED`.

---

### Step 2: Switch Ruleset Enforcement Mode

When evaluation is complete, switch rulesets to active enforcement:

To activate all rulesets:
```powershell
pwsh .\Set-GitHubPolicyMode.ps1 -TargetOrg "ADO2GHEC" -Mode active
```

To switch rulesets back to evaluation:
```powershell
pwsh .\Set-GitHubPolicyMode.ps1 -TargetOrg "ADO2GHEC" -Mode evaluate
```

To disable all rulesets:
```powershell
pwsh .\Set-GitHubPolicyMode.ps1 -TargetOrg "ADO2GHEC" -Mode disabled
```

**Expected Output:**
- Terminal shows count of updated rulesets and their new enforcement mode.

---

## 6. Rollback Procedures

Use these procedures if you must restore original settings.

### Rollback Organization Policies

Run this command:
```powershell
pwsh .\org\05_Rollback-GitHubOrgPolicies.ps1
```
**Expected Output:**
- Terminal confirms organization settings restored to pre-flight snapshot.

---

### Rollback Project Rulesets

Run this command:
```powershell
pwsh .\project\05_Rollback-GitHubRulesets.ps1
```
**Expected Output:**
- Terminal confirms project rulesets restored to pre-flight snapshot.

---

### Rollback Repository Rulesets

Run this command:
```powershell
pwsh .\repo\05_Rollback-GitHubRepoRulesets.ps1
```
**Expected Output:**
- Terminal confirms repository rulesets restored to pre-flight snapshot.
