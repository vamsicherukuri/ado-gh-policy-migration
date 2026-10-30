# ADO to GitHub Policy Migration Report

## Migration Overview
- **Source ADO Organization:** ado-policy-testing
- **Source ADO Project:** project1
- **Total Policies Captured:** 26
- **Policies Processed into Safe-Settings:** 26
- **Sub-Org Config File:** .github/suborgs/project1.yml (governs 4 repositories: project1, sample2, sample3, sample4)
- **Repository-specific Override Files:** 1 (under .github/repos/)

---

## Parity & Mapping Summary

| ADO Policy Name | Scope | Safe-Settings Mapping Status | GitHub Equivalent Feature | Action Required |
|---|---|---|---|---|
| Commit author email validation | Project & Repo | **Mapped (Close)** | Ruleset: `commit_author_email_pattern` | Verify domain pattern |
| File size restriction | Project & Repo | **Mapped (Exact)** | Ruleset: `max_file_size` | Converted from bytes to MB |
| Path Length restriction | Project & Repo | **Mapped (Exact)** | Ruleset: `max_file_path_length` | Exact match |
| File name restriction | Project & Repo | **Mapped (Exact)** | Ruleset: `file_path_restriction` | Uses fnmatch path patterns |
| Minimum number of reviewers | Project & Repo | **Mapped (Close)** | Ruleset: `pull_request` approvals | Approver count & reset-on-push mapped |
| Comment requirements | Project & Repo | **Mapped (Exact)** | Ruleset: `required_review_thread_resolution` | Blocks merge until threads resolved |
| Require a merge strategy | Project & Repo | **Mapped (Exact)** | Ruleset `allowed_merge_methods` & Repo settings | Squash / Merge / Rebase toggles |
| Build validation | Project & Repo | **Mapped (Action Needed)** | Ruleset: `required_status_checks` | **Confirm check context matches GitHub Actions workflow** |
| Status checks | Project & Repo | **Mapped (Action Needed)** | Ruleset: `required_status_checks` | Verify publisher App/status name |
| Work item linking | Project & Repo | **Gap / Custom Implementation** | Custom Status Check / GHA | Informational only in native GitHub; require GHA if blocking |
| Reserved names restriction | Project & Repo | **Partial / Workaround** | Ruleset: `file_path_restriction` | Enumerate OS reserved names (CON, NUL) if required |
| Git repository settings (Case enforcement) | Project & Repo | **No Direct Equivalent** | Not supported natively | Catch via pre-commit or CI linting |

---

## Action Checklist for Pull Request Reviewers
1. [ ] **Verify Sub-Org Target Repos:** Check `.github/suborgs/project1.yml` to ensure all migrated repos are listed under `repos:`.
2. [ ] **Confirm Build Check Names:** In ADO, builds used pipeline names (e.g., `policy-lab-sample2`). Ensure the corresponding GitHub Actions workflow job is named identically so status checks unblock merges.
3. [ ] **Review Dry-Run Output:** Review the Safe-Settings bot comment on this Pull Request to inspect the exact API changes before merging.
