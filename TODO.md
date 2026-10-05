# TODO — user-side actions

Prune as handled.

- [ ] **Create the GitHub Release for `v0.17.0`** from your own terminal (the gate's deny floor blocks `gh release` for the agent). Publishing to GitHub Packages fires on Release publication, and `publish.yml` re-runs typecheck + tests on the tag.
  - Before releasing: `publish.yml` still publishes `@frapetti-dev/pi-verdict`, but the package is `@jonatsu/pi-verdict` — fix or remove the workflow first (deployment installs via the git spec), or the publish targets the wrong scope.