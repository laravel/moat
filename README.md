<p align="center">
    <img src="./art/logo.svg" alt="Logo Laravel Moat" width="50%">
    <img src="./art/demo.png" alt="Example Laravel Moat" width="800">
    <p align="center">
        <a href="https://github.com/laravel/moat/actions"><img alt="GitHub Workflow Status (main)" src="https://github.com/laravel/moat/actions/workflows/ci.yml/badge.svg"></a>
        <a href="https://github.com/laravel/moat/releases"><img alt="Latest Version" src="https://img.shields.io/github/v/release/laravel/moat"></a>
        <a href="https://github.com/laravel/moat/blob/1.x/LICENSE"><img alt="License" src="https://img.shields.io/github/license/laravel/moat"></a>
    </p>
</p>

## Introduction

**Moat** reviews the security posture of your **GitHub organization** and **repositories**, then surfaces recommendations to consider. It inspects the security controls GitHub already offers — 2FA enforcement, branch protection, signed commits, secret scanning, Dependabot alerts, workflow permissions, pinned actions, repository webhooks, and more — and reports which ones are not enabled or not configured in line with common recommendations.

Moat covers checks across **two-factor authentication**, **branch protection**, **signed commits**, **secret scanning**, **Dependabot alerts**, **workflow permissions**, **pinned actions**, **repository webhooks**, and others.

> **What Moat is — and what it is not.** Moat is a read-only review tool. It does **not** modify any settings, harden your repositories, prevent intrusions, or remediate compromises. It surfaces **suggestions** based on GitHub's own security settings; it is your responsibility to evaluate each one in the context of your project and decide whether to apply it. A clean Moat report does not certify that an account is secure, nor does a failing report mean it has been compromised.

## Installation

> **Works with any GitHub organization, user, or repository.** A `GITHUB_TOKEN`, `GH_TOKEN`, or [GitHub CLI](https://cli.github.com) login is required.

### Homebrew (macOS / Linux)

```bash
brew tap laravel/moat https://github.com/laravel/moat
brew install laravel/moat/moat
```

### Prebuilt binaries

Download the archive for your platform from the [releases page](https://github.com/laravel/moat/releases) and place `moat` on your `PATH`.

### Build from Source / Contribution

To build the project from source you will need to have [rust installed](https://rust-lang.org/tools/install/).

Once rust is installed, fork and clone the project to have a copy on your system

`git clone git@github.com:laravel/moat.git`

From inside the moat directory you can now compile and test `moat`

```sh
cd moat
cargo build # debug build
cargo build --release  # production release
```

The binary will be in `./target/release`
Now move the `moat` exe to a file in your path. 

You can run tests with: `cargo test` and build documention with `cargo doc`

## Usage

```bash
moat <account>
```

`<account>` can be a GitHub organization, a user, or an `<owner>/<repo>` slug.

```bash
moat <your-org>
moat <owner>/<repo>
```

### Options

- `-v`, `--verbose` — display all collaborators and members instead of truncating the list.
- `--theme <auto|dark|light>` — color theme. Defaults to `auto`, which detects the terminal background via `COLORFGBG`.
- `-h`, `--help` — print help.
- `-V`, `--version` — print version.

## Authentication

`moat` resolves a GitHub token in this order:

1. `GITHUB_TOKEN` environment variable
2. `GH_TOKEN` environment variable
3. `gh auth token` (if the [GitHub CLI](https://cli.github.com) is installed and logged in)

For organization audits the token needs:

- `admin:org` — list members, admins, outside collaborators, 2FA enforcement, and read org-level Actions policies
- `repo` — read branch protection, required reviews, secret scanning, Dependabot alerts, repository contents (`SECURITY.md`), and repository webhooks
- `workflow` — read `.github/workflows/*` files to detect unpinned actions, `pull_request_target` misuse, and overly permissive `permissions:` blocks

A classic PAT with these scopes works. For user accounts, only `repo` and `workflow` are required.

**Important: If you create a personal access token to run Moat, revoke it as soon as you're done.** Visit [github.com/settings/tokens](https://github.com/settings/tokens) and delete the token after your review. Tokens that linger on disk or in shell history are themselves a security risk — Moat only needs access for the duration of the run.

## Checks

Each entry below describes a security setting Moat looks at, along with the reasoning behind the suggestion. The text explains the risk that the setting helps mitigate — it does not imply that enabling the setting alone is sufficient to defend against the threat, nor that leaving it disabled means an account is compromised.

### `organization_requires_two_factor`

Stolen passwords are the entry point of most maintainer-account compromises; enforcing 2FA org-wide raises the cost of a takeover from a phishing email to a physical device.

### `organization_members_all_have_two_factor`

The org-wide 2FA policy only covers members enrolled after it was turned on; anyone predating it remains the weakest unlocked door into the org.

### `organization_new_members_default_to_no_permissions`

This setting decides the blast radius of a single compromised account; with write or admin as the default, one stolen session can push to every repo at once instead of just the ones that member legitimately touches.

### `repositories_actions_workflow_token_is_read_only`

Every workflow inherits this token by default; granting write at the org or repo level means a typo'd action reference or a hijacked third-party action can rewrite history, tags, and releases without ever needing a maintainer's credentials.

### `repositories_secret_scanning_is_enabled`

Secrets accidentally committed stay valid until someone notices; scanning gives you minutes-to-hours warning instead of waiting for a leaked-credential abuse alert from a downstream provider.

### `repositories_secret_push_protection_is_enabled`

Scanning finds secrets after they reach GitHub; push protection rejects them at the git layer so the credential never enters history, forks, mirrors, or backups in the first place.

### `repositories_dependabot_alerts_are_enabled`

Most package compromises are disclosed publicly before they are widely exploited; alerts tell you which of your repos consume the bad version so you can pin or patch within the window before mass scanning catches up.

### `repositories_dependabot_security_updates_are_enabled`

Alerts only tell you a vulnerable dependency is in use; security updates are what actually open the PR that bumps it. Without them, an alert sits in the dashboard until someone notices, and the window before mass scanning catches up is exactly the window you wanted to close.

### `repositories_releases_are_immutable`

Without immutability, an existing tag can be moved or its assets replaced after the fact; downstream consumers pinned to a version they audited will silently fetch different bytes the next time they install.

### `repositories_fork_pull_requests_require_approval`

A fork PR can ship malicious workflow changes that run with your runners' filesystem and network access on the first push; approval gating lets a human read the diff before code from a stranger executes.

### `repositories_commits_are_signed`

A stolen developer token can push commits authored as anyone; requiring a verified signature ties each commit to a key the attacker doesn't have, turning a leaked token from a code-push into a noisy failure.

### `repositories_pull_requests_require_reviews`

Without required reviews, a single compromised contributor account can push directly to a release branch — peer review is the cheapest mechanism that catches malicious patches before they ship.

### `repositories_release_branches_are_locked`

Force pushes and branch deletions rewrite history — an attacker (or a tired maintainer) can erase the audit trail of a malicious commit or quietly replace a tagged release with a different tree.

### `repositories_release_branches_have_linear_history`

Merge commits can hide unreviewed parents — a `git merge` of an unprotected side branch can introduce code that no reviewer ever saw, while still appearing as a normal merge in the PR.

### `repositories_webhooks_are_secure`

Plain-HTTP hooks leak payloads (and any secrets inside them) to any network on the path, and a hook without a shared secret has no way to prove the request actually came from GitHub.

### `repositories_have_no_direct_collaborators`

Direct collaborators bypass org-level team membership audits and outlive role changes; access reviews miss them, so a long-departed contributor can keep push rights indefinitely.

### `repositories_private_vulnerability_reporting_is_enabled`

Without a private intake, researchers either drop a public issue (advertising the bug before it's fixed) or give up; the private channel lets you triage and ship a patched release before exploitation.

### `repositories_workflow_actions_are_pinned`

Tags and branches are mutable — when `tj-actions/changed-files` was compromised in 2025, the attacker repointed the existing tags, so every workflow `@v1` instantly ran malicious code; SHA pins make that impossible.

### `repositories_pull_request_target_is_safe`

`pull_request_target` runs with the base repo's secrets and write token; if the workflow then checks out the PR's code, any fork PR executes attacker-controlled code with full repo privileges.

### `repositories_workflow_permissions_are_restricted`

Without a declared `permissions:` block (or with `write-all`), every step in the workflow — including third-party actions — runs with full repo write access, turning any compromised action into a code-push primitive.

### `repositories_have_security_policy`

Without a disclosure channel, well-meaning researchers file public issues with full PoCs — `SECURITY.md` is what funnels them to a private channel before the world sees the bug.

### `repositories_have_dependabot_config`

Pinning actions to SHAs is only safe if something keeps them up to date; without Dependabot the pins rot and either get bumped to a tag (defeating the pin) or stay stuck on a known-vulnerable revision.

## Configuration

`moat` looks for a `moat.toml` file at the root of each audited repository. Use it to disable checks that don't apply to that repo. Disabled checks render as `SKIPPED` in the output and don't count toward the failure total.

```toml
[checks]
repositories_commits_are_signed = "off"
repositories_workflow_actions_are_pinned = "off"
```

Values are `"on"` (default) or `"off"`. Use any check ID from the [Checks](#checks) section above.

You can also declare additional release branches that should be treated as protected alongside the default branch and any branches matching the built-in release patterns:

```toml
release_branches = ["0.x", "1.x"]
```

## Checks skipped on GitHub Free

- **GitHub Free plan on private repos.** Several checks rely on features that aren't available on Free for private repositories, so they skip with `N/A (plan)`:
  - `repositories_commits_are_signed`
  - `repositories_pull_requests_require_reviews`
  - `repositories_release_branches_are_locked`
  - `repositories_release_branches_have_linear_history`
  - `repositories_secret_scanning_is_enabled`
  - `repositories_secret_push_protection_is_enabled`

## Contributing

Thank you for considering contributing to Moat! The contribution guide can be found in the [Laravel documentation](https://laravel.com/docs/contributions).

## Code of Conduct

In order to ensure that the Laravel community is welcoming to all, please review and abide by the [Code of Conduct](https://laravel.com/docs/contributions#code-of-conduct).

## Security Vulnerabilities

Please review [our security policy](https://github.com/laravel/moat/security/policy) on how to report security vulnerabilities.

## License

Moat is open-sourced software licensed under the [MIT license](LICENSE).
