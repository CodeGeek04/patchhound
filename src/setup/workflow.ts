/** What the workflow `patchhound init` writes depends on. */
export interface WorkflowOptions {
  /** The Action to run: `owner/repo@ref`. */
  action: string;
  /** The branch fixes go to; the first run starts when this file lands there. */
  base: string;
  /**
   * The repo's default branch, where GitHub runs schedules from. When fixes go elsewhere (staging),
   * every job checks out `base` (PATCHHOUND_BASE), and the schedule starts once this file reaches the
   * default branch.
   */
  defaultBranch?: string;
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
  const elsewhere = options.defaultBranch !== undefined && options.defaultBranch !== options.base;
  const quote = (branch: string) => (/^[\w./-]+$/.test(branch) ? branch : JSON.stringify(branch));
  const env = elsewhere ? `\nenv:\n  PATCHHOUND_BASE: ${quote(options.base)}   # the branch fixes go to, and that every job checks out\n` : '';
  const checkout = elsewhere ? '\n          ref: ${{ env.PATCHHOUND_BASE }}' : '';
  const claude = options.apiKey
    ? 'anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}'
    : 'claude-code-oauth-token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}';
  return `name: patchhound
on:
  schedule:
    - cron: "${schedule}"${schedule === DEFAULT_SCHEDULE ? '   # every 4 hours' : ''}
  workflow_dispatch:          # "Run workflow" in the Actions tab starts one any time
  push:                       # and the first one starts when this file is merged
    branches: [${quote(options.base)}]
    paths: [${WORKFLOW_PATH}]
${env}
concurrency: patchhound

jobs:
  scan:                       # alerts; never runs your project's code
    runs-on: ubuntu-latest
    permissions:
      contents: read
    outputs:
      fix: \${{ steps.patchhound.outputs.fix }}   # false: nothing new to fix, so the next jobs are skipped
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false${checkout}
      - id: patchhound
        uses: ${options.action}
        with:
          mode: scan
          ${claude}
          typesafe-api-key: \${{ secrets.TYPESAFE_API_KEY }}
          slack-webhook-url: \${{ secrets.SLACK_WEBHOOK_URL }}

  fix:                        # installs, checks and Claude Code; read-only
    needs: scan
    if: needs.scan.outputs.fix != 'false' || github.event_name == 'workflow_dispatch'   # "Run workflow" always fixes
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
    outputs:
      handoff: \${{ steps.patchhound.outputs.handoff }}   # false: nothing to publish, so publish is skipped
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false   # keeps the token out of .git/config, where installs and tests could read it${checkout}
      - id: patchhound
        uses: ${options.action}
        with:
          mode: fix
          ${claude}
        # env: variables your build or code generation needs (placeholders are enough for a build that does not connect)

  publish:                    # checks each bundle and pushes it; runs nothing from your project
    needs: fix
    if: always() && (needs.fix.result == 'success' || needs.fix.result == 'failure') && needs.fix.outputs.handoff != 'false'
    runs-on: ubuntu-latest
    permissions:
      contents: write          # push the fix branch
      pull-requests: write     # open and update the fix PR
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false${checkout}
      - uses: ${options.action}
        with:
          mode: publish
`;
}
