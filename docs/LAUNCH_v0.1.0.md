# Veil v0.1.0 Launch Checklist

One-time, dated runbook for the Veil v0.1.0 public launch. After launch,
archive this file to `docs/launches/2026-launch-v0.1.0.md` (or delete it).
For every-release procedures and recovery steps, see
[docs/RELEASING.md](RELEASING.md).

This checklist consolidates:
- pre-flight verification that the tree is ready,
- one-time GitHub organisation work (repo transfer, tap creation, PAT, secret),
- release-candidate (`v0.1.0-rc1`) verification,
- explicit abort criteria,
- the final `v0.1.0` tag,
- the first 48 hours of post-launch monitoring.

Work through each section in order. Boxes are sequential — do not skip ahead.

---

## 1. Pre-flight (before any GitHub state changes)

- [ ] Release-distribution branch merged to `main`; `main` CI is green.
- [ ] `CHANGELOG.md` exists at the repo root and the `[0.1.0]` heading reads
      `## [0.1.0] — YYYY-MM-DD` with **today's actual date**. Fill in
      `2026-MM-DD` now:
      ```bash
      TODAY=$(date +%F)   # YYYY-MM-DD
      sed -i.bak "s/2026-MM-DD/$TODAY/" CHANGELOG.md && rm CHANGELOG.md.bak
      git add CHANGELOG.md
      git commit -m "docs(changelog): set v0.1.0 release date"
      ```
- [ ] `cmd/veil/main.go` still declares `var version = "dev"`. GoReleaser
      injects the real version via `-ldflags`; do **not** hand-edit this.
- [ ] `Makefile` still has `VER ?= dev`. Same reason.
- [ ] Local dry-run succeeds:
      ```bash
      brew install goreleaser   # if not already installed
      make release-snapshot
      ```
      Inspect `dist/` for four tarballs, `checksums.txt`, SBOMs, and the
      generated `Formula/veil.rb` preview.
- [ ] `.github/social-preview.png` exists and renders correctly at 1280×640.
      Open it locally: `open .github/social-preview.png`.
- [ ] No accidental secrets / `.env` files in tracked content:
      ```bash
      git ls-files | grep -E '\.env$|secret|credential' || echo "clean"
      ```
      Expected: `clean` (or only `scripts/demo-fixture/.env.template`, which
      is a fixture).

## 2. One-time GitHub setup

Order matters: create the tap **before** transferring the source repo, so
GoReleaser's first push has somewhere to land.

- [ ] **Create `getveil/homebrew-tap`** on GitHub as a public repository.
      Seed its initial `README.md` from the content of
      [`docs/homebrew-tap-README.md`](homebrew-tap-README.md). Do **not**
      create `Formula/veil.rb` by hand — GoReleaser writes it on the first
      release.
- [ ] **Transfer `8enji/veil` → `getveil/veil`** via Settings → Transfer
      ownership. Confirm `https://github.com/8enji/veil` auto-redirects to
      the new URL.
- [ ] **Update your local remote** in this clone (and any other clones):
      ```bash
      git remote set-url origin https://github.com/getveil/veil.git
      git fetch origin
      ```
- [ ] **Upload the social preview:** `getveil/veil` → Settings → Social
      preview → Upload `.github/social-preview.png`.
- [ ] **Create a fine-grained PAT** scoped to **only** `getveil/homebrew-tap`,
      permission **Contents: Read and write**, expiry 1 year. Copy the token.
- [ ] **Add the PAT as a repo secret** on `getveil/veil`: Settings →
      Secrets and variables → Actions → New repository secret. Name:
      `HOMEBREW_TAP_TOKEN`. Value: the PAT from the previous step.

## 3. Release candidate (`v0.1.0-rc1`)

- [ ] Push the rc tag:
      ```bash
      git tag v0.1.0-rc1
      git push origin v0.1.0-rc1
      ```
- [ ] Watch the `release` workflow in
      `https://github.com/getveil/veil/actions/workflows/release.yml` →
      green.
- [ ] GitHub Release exists at
      `https://github.com/getveil/veil/releases/tag/v0.1.0-rc1`, marked
      **pre-release**, with the expected artifacts:
      - 4 tarballs: `veil_0.1.0-rc1_{darwin,linux}_{amd64,arm64}.tar.gz`
      - `checksums.txt`
      - `checksums.txt.sig`
      - `checksums.txt.pem`
      - 4 SBOMs (one per archive)
- [ ] `Formula/veil.rb` was committed to `getveil/homebrew-tap` by the
      `goreleaserbot` author.
- [ ] **Brew install on a clean macOS host:**
      ```bash
      brew update
      brew install getveil/tap/veil
      veil --version    # expect: veil v0.1.0-rc1 (darwin/<arch>)
      ```
- [ ] **Brew install on a clean Linux host:**
      ```bash
      brew update
      brew install getveil/tap/veil
      veil --version    # expect: veil v0.1.0-rc1 (linux/<arch>)
      ```
- [ ] **Verify the cosign signature** on `checksums.txt`:
      ```bash
      cosign verify-blob \
        --certificate checksums.txt.pem \
        --signature checksums.txt.sig \
        --certificate-identity-regexp 'https://github.com/getveil/veil/.github/workflows/release.yml@.*' \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        checksums.txt
      ```
      Expected: `Verified OK`.
- [ ] **Verify a build-provenance attestation:**
      ```bash
      gh attestation verify veil_0.1.0-rc1_darwin_arm64.tar.gz \
        --repo getveil/veil
      ```
      Expected: a one-line success and the attestation predicate URL.
- [ ] **Shell completions install:** open a new zsh shell and type
      `veil ` then TAB — subcommand list should appear.
- [ ] **End-to-end smoke test against a sandbox `.env`:**
      ```bash
      mkdir /tmp/veil-smoke && cd /tmp/veil-smoke
      cat > .env <<'EOF'
      GITHUB_TOKEN=ghp_x1y2z3a4b5c6d7e8f9g0h1i2j3k4l5m6n7o8
      OPENAI_API_KEY=sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      EOF
      veil init
      cat .env                              # placeholders, not the originals
      veil list                             # both secrets vaulted
      veil status                           # clean status
      veil uninstall --dry-run              # plan visible
      veil uninstall                        # restores originals
      cat .env                              # originals back
      cd / && rm -rf /tmp/veil-smoke
      ```

## 4. Abort criteria

If any of the following are true, **do not tag v0.1.0**. Fix the underlying
cause, delete the rc tag and its release per
[docs/RELEASING.md → Recovery](RELEASING.md#recovery), and retag `v0.1.0-rc2`:

- [ ] The release workflow failed at any step on the rc.
- [ ] `cosign verify-blob` failed.
- [ ] `gh attestation verify` failed for any tarball.
- [ ] `brew install` produced an unrunnable binary on any tested platform.
- [ ] `veil init` corrupted the sandbox `.env` in the smoke test, or
      `veil uninstall` failed to restore it.
- [ ] Any expected artifact (4 tarballs, `checksums.txt`, `.sig`, `.pem`,
      SBOMs) is missing or mis-named.

If **all** boxes above can be honestly ticked (all false), proceed.

## 5. Final tag (`v0.1.0`)

- [ ] Push the final tag:
      ```bash
      git tag v0.1.0
      git push origin v0.1.0
      ```
- [ ] Workflow succeeds. GitHub Release at
      `https://github.com/getveil/veil/releases/tag/v0.1.0` is **not**
      marked pre-release.
- [ ] `CHANGELOG.md`'s `[0.1.0]` compare-URL footer resolves:
      `https://github.com/getveil/veil/releases/tag/v0.1.0` returns 200.
- [ ] Brew install one more time on clean macOS + Linux:
      ```bash
      brew update
      brew install getveil/tap/veil
      veil --version    # expect: veil v0.1.0 (...)
      ```
- [ ] Spot-check the social preview by opening
      `https://github.com/getveil/veil` in a private browser window.

## 6. Post-launch (first 48 hours)

- [ ] Watch the Issues tab for install or first-run reports.
- [ ] Each morning, sanity-check a fresh user path:
      ```bash
      brew update && brew install getveil/tap/veil
      ```
      Confirm it succeeds and the version is `v0.1.0`.
- [ ] If something breaks, follow
      [docs/RELEASING.md → Recovery](RELEASING.md#recovery). For severe
      issues (credential leak, panic on init), publish a `v0.1.1` per
      [docs/RELEASING.md → Releasing](RELEASING.md#releasing).

## 7. Archive

- [ ] Move this file out of the active docs path:
      ```bash
      mkdir -p docs/launches
      git mv docs/LAUNCH_v0.1.0.md docs/launches/2026-launch-v0.1.0.md
      ```
- [ ] If any post-launch hotfixes shipped, update `CHANGELOG.md`'s
      `[Unreleased]` section accordingly.
- [ ] Commit:
      ```bash
      git add docs/launches docs/LAUNCH_v0.1.0.md
      git commit -m "docs: archive v0.1.0 launch checklist"
      ```
