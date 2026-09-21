# VibeGuard launch playbook

Goal: hit #1 on GitHub trending. Trending rewards **velocity** — stars in a
short window — so everything below is sequenced around a single launch day.

## Before launch

- [ ] Replace every `YOUR-USERNAME` in the repo with your GitHub handle
      (README, pyproject.toml, action.yml, .pre-commit-hooks.yaml, config example).
- [ ] Record `docs/demo.gif`: a 20-second terminal capture of VibeGuard
      blocking a commit that contains a fake Stripe key. Tools: `peek`,
      `terminalizer`, or asciinema → gif. This GIF goes at the top of the README
      and inside every launch post. It's the whole pitch in one image.
- [ ] Create the GitHub repo with topics: `security`, `pre-commit`,
      `ai`, `llm`, `devtools`, `secrets`, `github-actions`.
- [ ] Write a 3-line repo description: "Stop AI coding agents from committing
      secrets. Pre-commit hook + GitHub Action. Zero dependencies."
- [ ] Make one real commit that isn't the scaffold — e.g. add a rule you
      actually needed — so the history looks alive.
- [ ] Line up 10+ people to star it in the first 2 hours (DM them the night before).

## Launch day (do all four within the same few hours)

1. **LinkedIn** — personal story post (draft below). Post the GIF natively,
   not as a link. Ask a question at the end to drive comments.
2. **Hacker News** — "Show HN" between 8–10am ET on a Tue/Wed/Thu.
   Title options:
   - `Show HN: VibeGuard – stop AI coding agents from committing secrets`
   - `Show HN: My AI agent committed an AWS key, so I built a pre-commit hook`
   Stay in the comments for the first 3 hours and answer everything.
3. **Reddit** — r/programming, r/devops, r/Python. Lead with the problem,
   not the repo. No spammy cross-posting within the same hour.
4. **Dev.to / your blog** — "I let an AI agent loose on my repo for a week.
   Here's what it tried to commit." Story > tutorial.

## LinkedIn draft

> My AI coding agent is a 10x engineer with the survival instincts of a toddler.
>
> Last week it "fixed" our payments integration by hardcoding the Stripe
> LIVE key. Then it tried to commit it. At 2am. With the message "fix payments".
>
> So I built VibeGuard: a pre-commit hook + GitHub Action that blocks secrets
> and AI-generated security holes before they reach your repo. 60-second setup,
> zero dependencies.
>
> [GIF]
>
> It's open source (MIT) — link in comments. ⭐ if it's ever saved you.
>
> Honest question: what's the worst thing YOUR agent has tried to ship? 👇

## After launch

- [ ] Reply to every issue/PR within 24h for the first week — responsiveness
      converts visitors into stargazers.
- [ ] Ship one visible feature in week 1 (SARIF output is the best candidate)
      to show momentum.
- [ ] Thank sharers publicly; quote-post the best LinkedIn comments.
- [ ] If it trends, pin a tweet/post: "We're #N on GitHub trending 🔥" —
      social proof compounds.
