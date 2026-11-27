# Patchhound

Patchhound watches your npm dependencies for security advisories, works out which ones your code actually exposes, and keeps one pull request open that fixes what it can. It runs in your repo's own GitHub Actions: there is no service to sign up for, and your code never leaves GitHub's runners.

## Set it up

You need:

- Node.js 20 or later, and git
- the GitHub CLI, signed in as an owner or admin of the repo: `gh auth login`
- a Claude subscription with [Claude Code](https://claude.com/claude-code) installed, or an Anthropic API key
- a Jev API key from [TypeSafe](https://console.typesafe.ai): Jev answers most triage questions faster and cheaper than Claude, which then judges only what Jev is unsure of
- a Slack incoming webhook, for alerts ([how to make one](https://api.slack.com/messaging/webhooks))

Then, in your repo's folder:

```
npx patchhound init
```

1. It asks whether the repo deploys on Vercel. Answer yes if it does: Vercel builds a private repo's previews only for its team members' commits, so Patchhound then makes you the author of its fix commits.
2. It offers to make a Claude token with `claude setup-token`. Sign in in the browser, copy the token it prints, and paste it at the next prompt. It is stored as the repo secret `CLAUDE_CODE_OAUTH_TOKEN` and never shown. To use an API key instead: `npx patchhound init --api-key`.
3. It asks for the Jev key, then the Slack webhook, and stores each as a repo secret the same hidden way. Slack alerts are switched on in the repo's `.patchhound.yml`.
4. It turns on what GitHub needs (Actions, and Actions opening pull requests), opens a pull request named **Add Patchhound**, and offers to merge it. Say yes.

That is the whole setup. Merging starts the first run, and it runs every 4 hours after that. Watch it in the repo's **Actions** tab, under **patchhound**: each run's **Summary** page says what it found, what it fixed and why anything was left out. When it can fix something, a pull request from the branch `patchhound/fixes` appears. Review it and merge it like any other.

`init` does not touch your checkout: it makes the pull request from a fresh copy of your default branch. Run it again any time: it does only what is still missing.

## What a run does

- **Scan:** reads the lockfile and checks every package against [OSV](https://osv.dev) and CISA's list of exploited vulnerabilities. Claude reads your code to judge whether each advisory is reachable, and only the ones that matter raise an alert.
- **Fix:** applies the safe updates first (lockfile refreshes, patch and minor bumps), then major upgrades, with Claude Code adapting your code to them. Your build, type check and tests must keep passing, and a change that breaks one is left out, with the reason in the PR.
- **Malicious packages** get a pull request of their own straight away.
- **Nothing is merged** without you.

The job that runs your project's code has no write access and no secret but Claude's sign-in. A separate job, which runs nothing from your project, checks the result and opens the pull request.

## Good to know

- npm and pnpm lockfiles at the repo root are what it is tested on most (yarn works too).
- Public repos run on Actions for free. A private repo uses its account's monthly Actions minutes (2,000 on GitHub Free): a run that finds nothing new is the scan alone, about 1 to 2 minutes, and one that fixes something takes 10 to 30. To run less often: `npx patchhound init --schedule "17 3 * * *"` (once a day).
- Claude Code may spend at most $10 on one run (`fix.budget_usd`). On a Claude subscription, that counts against your plan's usage.
- Try it locally first, without changing anything: `npx patchhound scan --dry-run` in a project folder.

[docs/github-action.md](docs/github-action.md) has the workflow `init` writes, every setting, and what Patchhound will not do.

## License

MIT
