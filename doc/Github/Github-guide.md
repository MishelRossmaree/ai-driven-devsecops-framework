# GitHub Setup Guide for Test Repositories

This guide explains how to use the framework template and configure GitHub settings so security checks work correctly for both direct pushes and pull requests.

## 1. Use the Workflow Template

Template file in this repository:

- [doc/Github/template/run-ai-devsecops-security-scan.yml](doc/Github/template/run-ai-devsecops-security-scan.yml)

In your test repository, create:

- `.github/workflows/security.yml`

Copy the template content into that file.

## 2. What Your Workflow Must Include

### Required triggers

- `push` on `main` for reactive detection.
- `pull_request` for preventive gating.
- optional `workflow_dispatch` for manual testing.

### Required checkout behavior

Use:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
```

This is important because ML1 uses git diff history for changed file and changed function analysis.

### Required framework call

```yaml
- name: Run AI DevSecOps Framework
  uses: MishelRossmaree/ai-driven-devsecops-framework@main
  with:
    scan-path: "."
```

## 3. Validation of Your Previous Snippet

Your previous setup direction is correct overall. These are the important corrections and confirmations:

1. Path filters
- Use `**/*.c` not `**.c`.
- Same for all extensions: `**/*.cpp`, `**/*.cc`, `**/*.cxx`, `**/*.h`, `**/*.hpp`.

2. Input names
- Use the current action input names from [action.yml](action.yml):
  - `ml1-high-threshold`
  - `ml1-medium-threshold`
  - `ml1-review-confidence-threshold`
  - `ml3-min-rows`
- Do not use old names like `risk-threshold-high`, `risk-threshold-medium`, or `confidence-threshold` because those are not defined inputs.

3. Permissions
- If you want ML3 state persistence commit behavior on non-main push runs, use:
  - `permissions: contents: write`
- If you do not want automated write-back behavior, you can use read-only permissions, but ML3 persistence step will not be able to push updates.

4. Job name for required check
- If your job is named `security-scan`, your branch protection required check should match that exact check name.

## 4. Recommended Test Repo Workflow

```yaml
name: security-scan

on:
  push:
    branches: [main]
    paths:
      - '**/*.c'
      - '**/*.cpp'
      - '**/*.cc'
      - '**/*.cxx'
      - '**/*.h'
      - '**/*.hpp'

  pull_request:
    paths:
      - '**/*.c'
      - '**/*.cpp'
      - '**/*.cc'
      - '**/*.cxx'
      - '**/*.h'
      - '**/*.hpp'

  workflow_dispatch:

permissions:
  contents: write

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout target project
        uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref || github.ref_name }}
          fetch-depth: 0

      - name: Run AI DevSecOps Framework
        uses: MishelRossmaree/ai-driven-devsecops-framework@main
        with:
          scan-path: "."
          ml3-min-rows: "5"
          # Optional ML1 tuning:
          # ml1-high-threshold: "70"
          # ml1-medium-threshold: "40"
          # ml1-review-confidence-threshold: "0.2"
```

## 5. GitHub Branch Protection Settings

Configure in the test repo:

- Settings -> Rules -> Rulesets or Branch protection -> `main`

Enable:

- Require a pull request before merging
- Require status checks to pass before merging
- Require branches to be up to date before merging
- Required check: `security-scan`

This is what prevents merging when framework decision is `BLOCK` on PR workflows.

## 6. Direct Push vs Pull Request Behavior

### Direct push to main

- Commit is already integrated.
- Framework runs and can fail CI if decision is `BLOCK`.
- This is reactive detection.

### Pull request

- Framework runs before merge.
- If decision is `BLOCK`, check fails.
- With required checks enabled, merge is prevented.
- This is preventive governance.

## 7. ML3 State Commit Policy

Recommended practice:

- Do not rely on PR runs to commit ML3 history.
- Allow ML3 persistence only for push-based runs where appropriate.

The framework already limits ML3 persistence to push events on non-main branches.

## 8. Trigger Expectations

Because triggers use C/C++ path filters:

- C/C++ changes trigger workflow.
- README/docs-only changes do not trigger workflow.

## 9. Suggested Validation Order

Run these in your test repo:

1. Safe C/C++ change -> expect PASS.
2. Medium-risk change -> expect REVIEW.
3. High-risk vulnerable change -> expect BLOCK.
4. Non-C/C++ change only -> workflow skipped.

## 10. Quick Troubleshooting

### Workflow not triggered

- Check event filters and path patterns.
- Ensure changed files match configured extensions.

### PR merged despite security issue

- Verify branch protection requires the correct check name.
- Verify job/check name matches `security-scan`.

### ML1 seems skipped unexpectedly

- Ensure `fetch-depth: 0` is set.
- Ensure commit history exists for diff resolution.

### Input not applied

- Confirm input key names match [action.yml](action.yml).
