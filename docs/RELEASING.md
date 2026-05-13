# Releasing Veil

Operator runbook for tagging a release. Assumes the source repo has
been transferred to `getveil/veil` and the Homebrew tap repo
`getveil/homebrew-tap` exists.

## One-time setup

1. **Create `getveil/homebrew-tap`** on GitHub if it doesn't exist.
   Use `docs/homebrew-tap-README.md` as the initial `README.md`.
   `Formula/veil.rb` is created automatically by the first successful
   release run — no need to pre-populate.

2. **Create a fine-grained PAT** to let GoReleaser push the formula:
   - GitHub → Settings → Developer settings → Personal access tokens →
     Fine-grained tokens → Generate new token.
   - Resource owner: `getveil`.
   - Repository access: select **only** `getveil/homebrew-tap`.
   - Permissions: Repository → **Contents: Read and write**.
   - Expiry: 1 year (calendar a renewal).
   - Copy the token.

3. **Add the token as a repo secret on `getveil/veil`:**
   - Repo → Settings → Secrets and variables → Actions →
     New repository secret.
   - Name: `HOMEBREW_TAP_TOKEN`.
   - Value: the token from step 2.

## Releasing

1. Confirm `main` is green in CI.

2. Optional local dry-run (requires `goreleaser` installed):
   ```bash
   brew install goreleaser  # if needed
   make release-snapshot
   ```
   Inspect `dist/` for the four tarballs, `checksums.txt`, and the
   generated `Formula/veil.rb` preview. Snapshot mode does not push.

3. Tag and push:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

   For a release candidate (recommended for the first release):
   ```bash
   git tag v0.1.0-rc1
   git push origin v0.1.0-rc1
   ```
   GoReleaser will mark this as a pre-release on GitHub.

4. Watch the `release` workflow in the GitHub Actions tab. On success:
   - GitHub Release at
     `https://github.com/getveil/veil/releases/tag/v0.1.0` with four
     tarballs, `checksums.txt`, `checksums.txt.sig`,
     `checksums.txt.pem`, and one SBOM per archive.
   - A commit pushed to `getveil/homebrew-tap` updating
     `Formula/veil.rb`.

5. Verify on a clean macOS or Linux host:
   ```bash
   brew update
   brew install getveil/tap/veil
   veil --version    # expect: veil v0.1.0 (...)
   ```

## Recovery

### Workflow failed mid-release

Re-run via the Actions UI's "Run workflow" button (`workflow_dispatch`)
with the same tag. GoReleaser's `--clean` flag wipes `dist/` first, so
a partial prior run is not a problem.

### Tag pushed in error

```bash
git push --delete origin v0.1.0   # remove the remote tag
git tag -d v0.1.0                 # remove the local tag
gh release delete v0.1.0 --yes    # remove the GitHub Release if created

# If the formula was pushed to the tap, revert that commit:
git -C path/to/homebrew-tap revert HEAD
```

### Tap token expired

Symptom: release workflow succeeds for the GitHub Release but fails at
the formula push step with a 401 / 403 from the tap repo.

Fix: regenerate the PAT per the one-time setup, update
`HOMEBREW_TAP_TOKEN`, then re-run the workflow via `workflow_dispatch`.

### Cosign keyless signing failed (OIDC outage)

Re-run the workflow when [GitHub OIDC](https://www.githubstatus.com/)
recovers. No state to clean up.

## Verifying a release as a user

See the [Direct download](../README.md#direct-download) section of the
top-level README for `shasum`, `cosign verify-blob`, and
`gh attestation verify` commands.
