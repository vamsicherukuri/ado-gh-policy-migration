# ADO to GitHub Policy Migration Report

## Migration Overview
- **Source ADO Organization:** ado-policy-testing
- **Source ADO Project:** project1
- **Total Policies Captured:** 26
- **Active/Evaluated Policies Processed:** 26
- **Sub-Org Config File:** .github/suborgs/project1.yml (governs 4 repositories: project1, sample2, sample3, sample4)
- **Repository-specific Override Files:** 1 (under .github/repos/)

---

## Parity & Mapping Status

| ADO Policy Type | Safe-Settings Status | GitHub Equivalent | Parity Notes |
|---|---|---|---|
| Commit author email validation | **Mapped** | Dedicated Ruleset (	arget: branch, ~ALL) | Preserves all patterns; maps to nds_with, quals, or egex |
| File size restriction | **Mapped** | Push Ruleset: max_file_size | Converted from bytes to MB |
| Path Length restriction | **Mapped** | Push Ruleset: max_file_path_length | Exact character count |
| File name restriction | **Mapped** | Push Ruleset: ile_path_restriction | fnmatch file patterns |
| Minimum number of reviewers | **Mapped** | Branch Ruleset: pull_request approvals | Approver count, reset-on-push, and last-pusher blocking |
| Comment requirements | **Mapped** | Branch Ruleset: equired_review_thread_resolution | Unresolved threads block merge |
| Require a merge strategy | **Mapped (Behavioral Delta)** | Ruleset llowed_merge_methods + Repo settings | **Note:** Applying allowed merge methods via GitHub ruleset mandates a PR requirement even with 0 approvals |
| Build validation | **Mapped (Action Needed)** | Branch Ruleset: equired_status_checks | **Confirm check context matches GitHub Actions workflow** |
| Status checks | **Mapped (Action Needed)** | Branch Ruleset: equired_status_checks | Verify publisher App / context string |
| Required reviewers | **Partial / Manual Configuration Required** | CODEOWNERS + equire_code_owner_review | ADO path/identity reviewers require a CODEOWNERS file in the repo to bind identities to paths |
| Work item linking | **Unsupported / Custom Action Required** | Custom Status Check / GHA | Informational only in native GitHub; require custom Action if blocking |
| Case enforcement | **No Direct Equivalent** | None | Enforce via client-side git configuration or CI linting |
| Reserved names restriction | **Partial / Workaround** | Push Ruleset: ile_path_restriction | Enumerate OS reserved names (CON, NUL, COM1) if blocking pushes |

---

## Action Checklist for Reviewers
1. [ ] **Verify Sub-Org Target Repos:** Check .github/suborgs/project1.yml to ensure all target repositories are listed under suborgrepos:.
2. [ ] **Provision CODEOWNERS Files:** For repositories with 'Required reviewers' policies in ADO, ensure a corresponding .github/CODEOWNERS file is committed to map path filters to GitHub teams/users.
3. [ ] **Confirm Status Check Contexts:** Verify that GitHub Actions workflows emit check runs matching the contexts declared in equired_status_checks.
4. [ ] **Review Dry-Run Output:** Review the Safe-Settings bot comment on the Pull Request to verify expected live diffs.
