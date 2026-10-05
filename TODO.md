# TODO — user-side actions

Prune as handled.

- [ ] **Create the GitHub Release for `v0.17.0`** from your own terminal (the gate's deny floor blocks `gh release` for the agent). Publishing to GitHub Packages fires on Release publication, and `publish.yml` re-runs typecheck + tests on the tag.
  - `publish.yml` now publishes `@jonatsu/pi-verdict` — the scope mismatch is fixed (item 8). The workflow authenticates with its own `GITHUB_TOKEN` (`packages: write`), so no extra setup is needed.