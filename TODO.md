# TODO — user-side actions

Prune as handled.

- [ ] **Create the GitHub Release for `v0.17.0`** from your own terminal (the gate's deny floor blocks `gh release` for the agent). Publishing to GitHub Packages fires on Release publication, and `publish.yml` re-runs typecheck + tests on the tag.
  - Before releasing: `publish.yml` still publishes `@frapetti-dev/pi-verdict`, but the package is `@jonatsu/pi-verdict` — fix or remove the workflow first (deployment installs via the git spec), or the publish targets the wrong scope.
- [ ] **Research:** https://github.com/odin-labs-ai/odin-rnd/tree/292ccac1bedf0144d2f0b1326ecd2cb35ba36992/experiments/blueprint-floor/rules — third-party experiment, pinned at commit `292ccac`; may hold patterns worth adopting for the gate's rule/floor layer. Evaluate what it does, what transfers to `extensions/pi-verdict.ts`, and what (if anything) contradicts ADR-0007/0008 before proposing anything.