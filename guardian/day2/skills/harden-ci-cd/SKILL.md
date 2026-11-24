---
name: harden-ci-cd
description: Harden a GitHub Actions workflow that exposes secrets or runs untrusted code (pull_request_target checking out PR code, missing permissions, unpinned third-party actions, secrets in PR jobs).
allowed_files: .github/workflows/*.yml, .github/workflows/*.yaml
---
# Harden a CI/CD workflow

## When to use
- `pull_request_target` together with a checkout of the PR head (`github.event.pull_request.head.sha`).
- No `permissions:` block (the token defaults to broad write access).
- Secrets passed to jobs that run PR code; third-party actions pinned by tag instead of a commit SHA.

## Steps
1. `read_file` the workflow.
2. Switch `pull_request_target:` to `pull_request:` unless the job needs secrets for trusted code only.
3. Remove the explicit checkout of the PR head ref.
4. Add a top-level `permissions:` block with `contents: read`.
5. Do not invent commit SHAs for actions: list them in the notes for a human to pin.

## Patch rules
- Only the workflow file. Keep job names and steps; change triggers, permissions and checkout refs only.

## Compatibility notes to give
- PRs from forks run without repository secrets; jobs that need secrets move to a separate trusted workflow.

## Rollback
`git revert` of the fix commit.
