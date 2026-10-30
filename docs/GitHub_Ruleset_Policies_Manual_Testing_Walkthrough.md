# GitHub Ruleset Policies — Manual Testing Walkthrough

This documents the step-by-step manual verification of each GitHub ruleset policy from
[GitHub_Ruleset_Policies.csv](../config/GitHub_Ruleset_Policies.csv), applied one at a time using
[Invoke-GitHubRulesetPolicies.ps1](../scripts/github/Invoke-GitHubRulesetPolicies.ps1) against a dedicated test branch.

**Test repo:** `ADO2GH-Migration/StarReads`
**Test branch:** `policy-walkthrough-test` (created off `master`, used only for this walkthrough)
**Test CSV:** `GitHub_Ruleset_Policies.walkthrough.csv` (a copy of the main CSV where only one policy
is flagged `Yes` at a time, so the main CSV's defaults stay untouched)
**Ruleset name prefix used:** `walkthrough` (keeps these test rulesets clearly separate from any
real `ado-migrated-policy-*` rulesets)

## How each policy is tested

1. Flip exactly one row in `GitHub_Ruleset_Policies.walkthrough.csv` to `Yes` (leave the rest `No`).
2. Apply it to the test branch only:
   ```powershell
   .\scripts\github\Invoke-GitHubRulesetPolicies.ps1 -PolicyCsvPath .\config\GitHub_Ruleset_Policies.walkthrough.csv `
     -Repos "ADO2GH-Migration/StarReads" -DefaultBranchPattern "refs/heads/policy-walkthrough-test" `
     -RulesetNamePrefix "walkthrough" -UseGhCliAuth
   ```
3. Perform the manual git/GitHub actions described for that policy and confirm the expected pass/fail behavior.
4. Record the result below, then move to the next policy.

---

## 1. Block force pushes

**Rule type:** `non_fast_forward` (target: branch)
**What it does:** Prevents users with push access from force-pushing to matching branches.

### Steps performed

```powershell
git clone https://github.com/ADO2GH-Migration/StarReads.git
cd StarReads
git fetch origin
git checkout policy-walkthrough-test

# Normal push - should succeed
"test file <timestamp>" | Out-File -Encoding utf8 test-normal-push.txt
git add test-normal-push.txt
git commit -m "Normal push test"
git push origin policy-walkthrough-test

# Force push - should be blocked
git reset --hard HEAD~1
git commit --allow-empty -m "Rewritten history"
git push --force origin policy-walkthrough-test
```

### Expected result
- Normal push: succeeds ✅
- Force push: rejected (`! [remote rejected] ... (protected branch hook declined)`) ❌ blocked

### Actual result
**PASSED** — normal push succeeded, force push was rejected by the branch protection rule as expected.

---

## 2. Restrict branch deletion

**Rule type:** `deletion` (target: branch)
**What it does:** Only allows users with bypass permission to delete matching branches.

### Steps performed

```powershell
# In the local clone, on policy-walkthrough-test
git push origin --delete policy-walkthrough-test
```

### Expected result
- Delete attempt is rejected.

### Actual result
**PASSED** — rejected with:
```
remote: error: GH013: Repository rule violations found for refs/heads/policy-walkthrough-test.
remote: - Cannot delete this branch
! [remote rejected] policy-walkthrough-test (push declined due to repository rule violations)
```

---

## 3. Commit author email pattern

**Rule type:** `commit_author_email_pattern` (target: branch)
**What it does:** Blocks pushes containing commits whose author email does not match the configured pattern (`ends_with @contoso.com`).

### Steps performed
Skipped by request — no second GitHub account was available at the time. Note this test does not
actually require a second GitHub account (the rule only checks the commit's Git `author` email
metadata, not an authenticated identity), so it can be revisited later with the same commands:

```powershell
git commit --allow-empty -m "Bad email test" --author="Test User <test@example.com>"
git push origin policy-walkthrough-test   # expected: rejected

git reset --hard origin/policy-walkthrough-test
git commit --allow-empty -m "Good email test" --author="Test User <test@contoso.com>"
git push origin policy-walkthrough-test   # expected: succeeds
```

### Actual result
**SKIPPED** (not verified in this session).

---

## 4. Restrict file paths

**Rule type:** `file_path_restriction` (target: push — applies repo-wide, not just to one branch)
**What it does:** Blocks pushes that add or modify files matching restricted patterns (`*.exe`, `*.dll`).

### Steps performed

```powershell
# Blocked file type - should be BLOCKED
"fake binary" | Out-File -Encoding ascii blocked-file.exe
git add blocked-file.exe
git commit -m "Add blocked exe file"
git push origin policy-walkthrough-test

# Allowed file type - should SUCCEED
git reset --hard origin/policy-walkthrough-test
"allowed content" | Out-File -Encoding utf8 allowed-file.txt
git add allowed-file.txt
git commit -m "Add allowed txt file"
git push origin policy-walkthrough-test
```

### Expected result
- `.exe` push: rejected (`GH013` rule violation)
- `.txt` push: succeeds

### Actual result
**PASSED** — verified via the GitHub API that `allowed-file.txt` is present on `policy-walkthrough-test`
and `blocked-file.exe` never made it to the branch (the exe push was rejected before the txt push).

---

## 5. Restrict file path length

**Rule type:** `max_file_path_length` (target: push — applies repo-wide, limit set to 248 characters)
**What it does:** Blocks pushes containing file paths that exceed the configured character limit.

### Steps performed
Attempting this via a local `git push` failed before even reaching GitHub — Windows itself has a
~260-character path limit, so `New-Item`/`git add` failed locally with `Filename too long` before any
network call was made. Switched to pushing directly via the GitHub Contents API (bypasses the local
filesystem entirely) to isolate and test the actual GitHub-side rule:

```powershell
# Blocked: path far exceeds 248 characters - pushed via GitHub API (create_or_update_file / push_files)
# path: "aaa...(60 chars)/aaa.../aaa.../aaa.../toolong.txt"

# Allowed: short path - pushed via GitHub API
# path: "short-path.txt"
```

### Expected result
- Long path: rejected
- Short path: succeeds

### Actual result
**PASSED**
- Long path push failed with: `Repository rule violations found - File paths can not be greater than 248 characters.`
- Short path (`short-path.txt`) pushed successfully (visible on `policy-walkthrough-test`).

**Note:** If you need to test long-path scenarios via local `git`, either enable Windows long path
support (`git config --system core.longpaths true` plus the `LongPathsEnabled` registry key) or push
via the GitHub API/UI as done here.

---

## 6. Restrict file size

**Rule type:** `max_file_size` (target: push — applies repo-wide, limit set to 100 MB)
**What it does:** Blocks pushes containing individual files larger than the configured size.

### Steps performed

```powershell
# Oversized file (110 MB) - should be BLOCKED
fsutil file createnew big-file.bin 115343360
git add big-file.bin
git commit -m "Add oversized file"
git push origin policy-walkthrough-test

# Small file (1 MB) - should SUCCEED
git reset --hard origin/policy-walkthrough-test
fsutil file createnew small-file.bin 1048576
git add small-file.bin
git commit -m "Add small file"
git push origin policy-walkthrough-test
```

### Expected result
- 110 MB file: rejected
- 1 MB file: succeeds

### Actual result
**PASSED**
- Large file rejected with: `error: File big-file.bin is 110.00 MB; this exceeds GitHub's file size limit of 100.00 MB` /
  `GH001: Large files detected` (pre-receive hook declined). Note: since our configured limit (100 MB)
  matches GitHub's own built-in hard limit, this rejection could be either GitHub's default limit or
  our custom rule firing - functionally indistinguishable at this threshold, but the blocking behavior
  is confirmed either way.
- Small file (1 MB) pushed and synced successfully (commit `594cc77`).

**Tip:** to unambiguously prove the *custom* rule (not GitHub's built-in limit) is what's blocking,
temporarily lower `max_file_size` in the CSV to something well under 100 MB (e.g. 10) and retest with
a file sized between the two thresholds (e.g. 20 MB).

---

## 7. Require minimum reviewers

**Rule type:** `pull_request` (`required_approving_review_count: 1`, target: branch)
**What it does:** Requires at least 1 approving review before a pull request can merge.

### Steps performed

```powershell
# Create a feature branch and PR targeting policy-walkthrough-test
git checkout -b feature/test-min-reviewers
"pr test content" | Out-File -Encoding utf8 pr-test-file.txt
git add pr-test-file.txt
git commit -m "Test PR for min reviewers policy"
git push origin feature/test-min-reviewers
```
Then created PR #38 (`feature/test-min-reviewers` -> `policy-walkthrough-test`) and attempted to
merge it immediately, with zero approvals.

### Expected result
- Merge attempt with 0 approvals: rejected.
- Merge attempt with >=1 approval from a different account: succeeds. **(Not verified — no second
  GitHub account was available in this session; see note below.)**

### Actual result
**PASSED (blocking side only)** — merge attempt failed with:
```
405 Repository rule violations found
At least 1 approving review is required by reviewers with write access.
```
The "passes once approved" side was not verified since it requires an approval from a GitHub user
other than the PR author. To verify later: have a second collaborator (or alt account) approve PR
#38 (or a new test PR), then retry the merge - it should succeed once the required count is met.

---

## 8. Dismiss stale reviews on new push

**Rule type:** `pull_request` (`dismiss_stale_reviews_on_push: true`, target: branch)
**What it does:** Automatically dismisses existing approvals when new commits are pushed to the PR's source branch.

### Steps performed
Attempted to submit a self-approval on PR #38 to then push a new commit and observe the dismissal:
```
POST /repos/ADO2GH-Migration/StarReads/pulls/38/reviews  { "event": "APPROVE" }
```

### Expected result
An approval review is dismissed automatically after a new commit is pushed to the PR branch.

### Actual result
**NOT VERIFIED** — GitHub itself hard-blocks self-approval (this is a GitHub platform rule, not
something our ruleset/script controls):
```
422 Unprocessable Entity
"Review Can not approve your own pull request"
```
Since no approval could be created in the first place, there was nothing to dismiss on push. This
requires a second GitHub account to approve, then push a commit, then confirm (via
`GET /pulls/38/reviews`) that the approval's state changes to `DISMISSED`.

---

## 9. Require conversation resolution before merging

**Rule type:** `pull_request` (`required_review_thread_resolution: true`, target: branch)
**What it does:** Requires all review comment threads to be resolved before a PR can merge.
*(Note: "Require minimum reviewers" was temporarily disabled during this step to isolate the test,
since it would otherwise also block the merge for an unrelated reason.)*

### Steps performed
1. Added a line-level review comment on PR #38 (`pr-test-file.txt` line 1), left unresolved.
2. Attempted to merge — expected to fail.
3. Resolved the review thread.
4. Attempted to merge again — expected to succeed.

### Expected result
- Merge with an unresolved conversation: rejected.
- Merge after resolving the conversation: succeeds.

### Actual result
**PASSED**
- Merge attempt with unresolved comment failed with: `405 Repository rule violations found - A conversation must be resolved before this pull request can be merged.`
- After resolving the thread, merge succeeded: PR #38 merged as commit `701849e`.

---

## 10. Restrict allowed merge methods

**Rule type:** `pull_request` (`allowed_merge_methods: ["squash"]`, target: branch)
**What it does:** Restricts PR completion to only the squash merge method.

### Steps performed
1. Created PR #39 (`feature/test-merge-methods` -> `policy-walkthrough-test`).
2. Attempted to merge using the `merge` (merge commit) method — expected to fail.
3. Attempted to merge using `squash` — expected to succeed.

### Expected result
- Merge commit method: rejected.
- Squash method: succeeds.

### Actual result
**PASSED**
- Merge-commit attempt failed with: `405 Merge commits are not allowed on this repository.`
- Squash attempt succeeded: PR #39 merged as commit `6ab53dc`.

---

## 11. Require status checks to pass before merging

**Rule type:** `required_status_checks` (`context: "build"`, `strict_required_status_checks_policy: false`, target: branch)
**What it does:** Requires the named status check to report success before a PR can merge.

### Steps performed
1. Created PR #40 (`feature/test-status-checks` -> `policy-walkthrough-test`).
2. Attempted merge with **no status posted** at all — expected to fail.
3. Posted a **failing** `build` status via the Commit Status API — attempted merge again, expected to fail.
4. Posted a **passing** `build` status via the Commit Status API — attempted merge again, expected to succeed.

### Expected result
- No status: rejected (check missing).
- Failing status: rejected (check failing).
- Passing status: succeeds.

### Actual result
**PASSED**
- No status: `405 Repository rule violations found - Required status check "build" is expected.`
- Failing status: `405 Repository rule violations found - Required status check "build" is failing.`
- Passing status: merge succeeded — PR #40 merged as commit `db66bb1`.

---

## Summary

| # | Policy | Result |
|---|--------|--------|
| 1 | Block force pushes | ✅ PASSED |
| 2 | Restrict branch deletion | ✅ PASSED |
| 3 | Commit author email pattern | ⏭️ SKIPPED (no second account needed, but not run) |
| 4 | Restrict file paths | ✅ PASSED |
| 5 | Restrict file path length | ✅ PASSED (via GitHub API, local Windows path limit interfered with `git`) |
| 6 | Restrict file size | ✅ PASSED |
| 7 | Require minimum reviewers | ✅ PASSED (blocking side only — approval side needs a 2nd account) |
| 8 | Dismiss stale reviews on push | ⚠️ NOT VERIFIED (GitHub blocks self-approval entirely) |
| 9 | Require conversation resolution | ✅ PASSED (both sides) |
| 10 | Restrict allowed merge methods | ✅ PASSED (both sides) |
| 11 | Require status checks to pass | ✅ PASSED (all 3 sides) |

**Known limitation across this walkthrough:** policies #7 and #8 can only be partially verified without
a second GitHub account/collaborator, since GitHub does not allow a PR author to approve their own
pull request (this is a GitHub platform restriction, not something the ruleset script controls). To
fully close out #7 and #8, repeat the "Require minimum reviewers" and "Dismiss stale reviews" steps
with a second collaborator account approving PR reviews.

**Test artifacts created:** branch `policy-walkthrough-test`, ruleset `walkthrough-branch` /
`walkthrough-push` on `ADO2GH-Migration/StarReads`, merged PRs #38, #39, #40, and the feature
branches `feature/test-min-reviewers`, `feature/test-merge-methods`, `feature/test-status-checks`.
Clean these up with `-Undo` and by deleting the merged feature branches once done reviewing.
