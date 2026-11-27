/** What the workflow `patchhound init` writes depends on. */
export interface WorkflowOptions {
  /** The Action to run: `owner/repo@ref`. */
  action: string;
  /** The repo's default branch: the first run starts when this file lands there. */
  base: string;
  /** Use an Anthropic API key (secret ANTHROPIC_API_KEY) instead of a Claude token. */
  apiKey?: boolean;
  /** When scheduled runs start (cron, UTC). */
  schedule?: string;
}

export const WORKFLOW_PATH = '.github/workflows/patchhound.yml';
export const DEFAULT_SCHEDULE = '17 */4 * * *';

/**
 * The workflow: three jobs, each holding only what it needs (see docs/github-action.md, which shows
 * this same file). The fix job runs the project's installs, scripts, tests and a coding agent, so it
 * holds no write access and no secret but Claude's sign-in; it hands each PR off as a git bundle to
 * the publish job, which runs nothing from the project.
 */
export function workflowFile(options: WorkflowOptions): string {
  const schedule = options.schedule ?? DEFAULT_SCHEDULE;
  const claude = options.apiKey
    ? 'anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}'
    : 'claude-code-oauth-token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}';
  return `name: patchhound
on:
  schedule:
    - cron: "${schedule}"${schedule === DEFAULT_SCHEDULE ? '   # every 4 hours' : ''}
  workflow_dispatch:          # "Run workflow" in the Actions tab starts one any time
  push:                       # and the first one starts when this file is merged
    branches: [${options.base}]
    paths: [${WORKFLOW_PATH}]

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
      - uses: ${options.action}
        with:
          mode: scan
          ${claude}
          typesafe-api-key: \${{ secrets.TYPESAFE_API_KEY }}
          slack-webhook-url: \${{ secrets.SLACK_WEBHOOK_URL }}

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
      - uses: ${options.action}
        with:
          mode: fix
          ${claude}
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
      - uses: ${options.action}
        with:
          mode: publish
`;
}
