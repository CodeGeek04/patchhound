# Running Patchhound as a GitHub Action

Add one workflow to a repo, and Patchhound scans it on a schedule, alerts on what your code exposes, and keeps one pull request open that fixes what it can.

## Quick start

You need Node 20 or later, git, the GitHub CLI signed in as an owner or admin of the repo (`gh auth login`), Claude Code for the Claude token (or an Anthropic API key: add `--api-key`), a Jev (TypeSafe) API key, and a Slack incoming webhook for alerts. In your repo's folder:

```
npx patchhound init
```

`init` does all of the setup below:
- stores the Claude token, the Jev key and the Slack webhook as repo secrets (gh asks for each and does not show it);
- writes the workflow, and a `.patchhound.yml` that turns Slack alerts on (and, for a repo that deploys on Vercel, makes the person who starts a run the author of the fix commits);
- turns GitHub Actions on if it is off, says what to allow if the repo limits which actions may run, and lets Actions open pull requests;
- opens a pull request with the files and offers to merge it, which starts the first run.

Your checkout is not touched. Run it again at any time: it does only what is still missing, and updates its own pull request if that is still open.

The rest of this page is what `init` sets up, for doing it by hand or changing it.

## 1. The workflow

The workflow has three jobs, each holding only what it needs. A fix runs your project's installs, install scripts and tests, and a coding agent: code you do not fully control. So the job that does it holds no write access and no secret but Claude's sign-in, and hands each pull request off as a git bundle. A separate job, which runs nothing from your project, checks each bundle and pushes it.

`.github/workflows/patchhound.yml`:

```yaml
name: patchhound
on:
  schedule:
    - cron: "17 */4 * * *"   # every 4 hours
  workflow_dispatch:          # "Run workflow" in the Actions tab starts one any time
  push:                       # and the first one starts when this file is merged
    branches: [main]
    paths: [.github/workflows/patchhound.yml]

concurrency: patchhound

jobs:
  scan:                       # alerts; never runs your project's code
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: CodeGeek04/patchhound@v0
        with:
          mode: scan
          claude-code-oauth-token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
          typesafe-api-key: ${{ secrets.TYPESAFE_API_KEY }}
          slack-webhook-url: ${{ secrets.SLACK_WEBHOOK_URL }}

  fix:                        # installs, checks and Claude Code; read-only
    needs: scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false   # keeps the token out of .git/config, where installs and tests could read it
      - uses: CodeGeek04/patchhound@v0
        with:
          mode: fix
          claude-code-oauth-token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
        # env: variables your build or code generation needs (placeholders are enough for a build that does not connect)

  publish:                    # checks each bundle and pushes it; runs nothing from your project
    needs: fix
    if: always() && needs.fix.result != 'cancelled'
    runs-on: ubuntu-latest
    permissions:
      contents: write          # push the fix branch
      pull-requests: write     # open and update the fix PR
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: CodeGeek04/patchhound@v0
        with:
          mode: publish
```

`publish` runs even when `fix` fails, so that a malware PR is still pushed when the fix step goes red because a malicious package is left.

Each job writes its report (what it found, fixed, kept out, and the PR) to the run's **Summary** page in the Actions tab; the job logs hold the details. Lines starting with `patchhound:` in the `fix` log show its progress while it runs.

## 2. The secrets

| Secret | Needed for | How to get it |
| --- | --- | --- |
| `CLAUDE_CODE_OAUTH_TOKEN` | Triage and the coding agent, on your Claude subscription | Run `claude setup-token` and paste what it prints. Or set `anthropic-api-key` with an API key instead. |
| `TYPESAFE_API_KEY` | Jev answers most triage questions first, faster and cheaper than Claude, which then judges only what Jev is unsure of. Without it, Claude judges every finding. | console.typesafe.ai |
| `SLACK_WEBHOOK_URL` | Alerts. Slack also needs `.patchhound.yml` to list it and turn dry run off (below); without a channel, alerts only show on each run's Summary page. | A Slack incoming webhook (api.slack.com/messaging/webhooks) |

`gh secret set CLAUDE_CODE_OAUTH_TOKEN` (and the others) from the repo's folder asks for the value, so it is never typed on the command line or pasted into a web page.

For Slack, `.patchhound.yml` at the repo root:

```yaml
dry_run: false
notify:
  channels:
    - type: slack
```

Then, in the repo's Settings > Actions > General > Workflow permissions, tick **Allow GitHub Actions to create and approve pull requests**: without it, `publish` cannot open the PR. In an organization, an owner may have to allow it for the organization first.

## 3. Settings

Optional: `patchhound init` writes a `.patchhound.yml` with every setting and its default: the alert threshold, the repo's exposure, which findings Claude checks, the checks a fix must pass (`fix.checks`, detected from the build, typecheck and test scripts when empty), what runs after each install before the checks (`fix.setup`, `prisma generate` when the project uses Prisma), and the most Claude Code may spend on one run (`fix.budget_usd`, $10 by default).

The checks run with the job's environment, minus Patchhound's and GitHub's tokens. If your build or code generation needs variables (a database URL that Prisma's config reads, say), set them in the workflow's `env`; placeholders are enough for a build that does not connect. Checks that fail before any change are not required, and with none passing, major upgrades stay out of the PR. The PR and the run's summary show why each of those failed. A build that reads a database (a page that queries it while pre-rendering) needs one: add a `postgres` service to the `fix` job, point the database variables at it, and set `fix.setup` to generate and migrate (`npx prisma generate`, `npx prisma migrate deploy`).

The PR's commits come from `github-actions[bot]`. Vercel builds a private repo's previews only for commits by members of its team, so it skips such a PR: set `fix.commit_as: actor` to make the person GitHub names as the run's actor (who started it) the author. `github-actions[bot]` stays the committer, which is how Patchhound tells its own commits from a person's.

## What a run does

1. **Scan and triage** the lockfile and the code; alert on what is new or worse (once, then again only when it gets worse); a weekly digest of the rest.
2. **Fix** what triage would open a PR for, on the branch `patchhound/fixes`:
   - skips the whole step when the open PR already covers the same findings, so a scheduled run pays for a fix once (`fix --force` on the command line redoes it);
   - installs the project and runs its build, type check and tests first, so that only checks that already pass count;
   - applies the safe changes (lockfile refreshes, patch and minor bumps, scoped overrides), then plans again for any advisory the new versions bring, and runs the checks;
   - then the major upgrades, and the checks again;
   - when a step breaks a check, tries its changes in smaller groups (plain code, no model) to keep those that pass and find the ones that break it;
   - one Claude Code session for the whole repo then adapts the code to those, within the budget (at most one session per step, so two per run). It may undo a single upgrade it cannot make work, and the PR says which and why;
   - a change that still breaks a check is left out, and the PR lists the findings it would have fixed and why they wait;
   - hands the result to the publish job, which checks it and opens the PR, or updates the one already open, with every advisory, why it matters, what changed and the checks before and after. The PR only ever holds changes that pass every check that passed before.
3. A malicious package gets a PR of its own, `patchhound/fixes-malware`, at once.

Nothing is ever merged by Patchhound in this version.

The fix step fails (a red run) when it needs a person: a malicious package is still in the lockfile, or the project does not install as it is. A run that keeps nothing, because every change broke a check, is not a failure; the next run tries again when there are new findings, or a day later on a new commit. The publish job fails when it refuses a bundle.

## What it will not do

- Install, build or test a commit that has a known malicious package: the malware PR is made with lockfile changes only, and every install first checks that no malicious version came in.
- Give your project's code a secret it does not need: the job that installs, tests and runs Claude Code holds Claude's sign-in and a read-only GitHub token, and nothing else (the alert secrets stay in `scan`, the write token in `publish`). Within that job, installs, scripts, checks and Claude Code's tools also run without those tokens in their environment.
- Push what it did not check: `publish` takes only commits Patchhound made, on the base they declare, and refuses one that changes `.github/` or Patchhound's config (a malware PR: anything but manifests and lockfiles).
- Push anywhere but `patchhound/fixes` (and `-malware`) in this repository, or over commits someone else pushed there: such a branch is left alone, and the run says so.
- Let Claude Code change `.github/` or Patchhound's own config (such edits are put back) or use web tools. It is allowed file tools, read-only git, your checks and the package manager's install, update, remove and run commands (not `npx`, `exec` or `dlx`). That narrows what it reaches for; it is not a sandbox: it can edit and run your project's scripts, as any change to the code could.
- Merge anything.

## What GitHub does

- A PR opened with the workflow's own `GITHUB_TOKEN` does not start other workflows, so your CI does not run on it until someone pushes to it or reopens it. Patchhound runs your checks itself and lists the result in the PR. To have CI run too, pass a personal access token or a GitHub App token as `github-token`: Patchhound pushes and opens the PR with it.
- Scheduled workflows stop after 60 days without activity in the repo; GitHub sends an email first.
- Caches: your project's code runs in the fix job with the runner's own rights, so a determined dependency could still write a cache entry under any key. The scan job reading only scan caches keeps an honest mistake or a simple attack out of it; it is not a hard boundary. Upgrading to this version starts the caches afresh, so the first run alerts, triages and fixes again once.
- Private repos get a monthly allowance of Actions minutes (2,000 on GitHub Free), and every job counts at least one minute. A run is three jobs: about 3 to 5 minutes when nothing is new, 10 to 30 when it fixes something. Every 4 hours is about 180 runs a month per repo; spread it out further (once a day: `17 3 * * *`) when several private repos share the allowance. Public repos run free.
