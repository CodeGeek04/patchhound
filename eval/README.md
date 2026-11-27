# Triage eval

`npm run eval` scores triage and the policy against findings someone has labeled by hand. It is the milestone 2 gate: fewer than 1 in 5 notifications irrelevant, and no critical worth an alert missed (a critical or KEV-listed advisory labeled reachable or worth an alert).

## Keep labels out of git

A labels file says which advisories affect which app, and whether the vulnerable code is reachable. For a private app that is a map for an attacker, so labels live in `eval/local/`, which git ignores. Never commit them, and never paste them into an issue.

## The labels file

`eval/local/labels.json` (or any path given as the first argument). A label is per advisory and app, the way an alert lists it:

```json
{
  "apps": {
    "App 1": "~/code/storefront"
  },
  "items": [
    {
      "app": "App 1",
      "advisory": "GHSA-35jh-r3h4-6jhm",
      "reachable": "yes",
      "notify": true,
      "weight": 1,
      "stratum": "critical",
      "confirmed": true,
      "note": "app/api/render/route.ts:4 passes request text to _.template"
    }
  ]
}
```

- `apps` maps a short name to the project folder. Only the short name appears in the output.
- `advisory` is the advisory id a scan prints (GHSA, CVE or MAL).
- `reachable`: `yes`, `no` or `unknown`: can an attacker make code the app runs in production reach the vulnerable part the way the advisory describes?
- `notify`: would you want an alert about it now, rather than in the weekly digest?
- `weight`: how many alerts the label stands for. Label a random sample of N out of M alerts and give each M/N, and precision estimates them all. Default 1.
- `stratum`: `critical` marks labels for every critical or KEV-listed advisory in production code, which recall needs in full.
- `confirmed`: false for a draft label nobody has checked yet. The output counts drafts apart.

## Running it

```
npm run eval -- eval/local/labels.json --only-labeled
npm run eval -- eval/local/labels.json --draft eval/local/candidates.json
```

Each finding whose answer counts goes to Jev and to Claude once; answers are cached, so a second run costs nothing until the code or the advisory changes. The output compares three strategies on the same answers: Jev first and Claude when Jev is unsure, Claude for every such finding, and Jev alone, each with the policy as specified and without its critical floor. `--only-labeled` asks Claude about labeled advisories only, which is all the scores need. `--draft` also writes every advisory any variant alerts on, with its evidence and both models' answers, to choose labels from.
