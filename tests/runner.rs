use moat::checks::CHECKS;
use moat::runner::{
    self, AccountKind, CheckResult, format_missing_scopes_error, format_sso_error,
    format_unauthorized_error,
};
use moat::support::github::{AuthSource, FakeGitHubClient};
use moat::support::outcome::Status;
use serde_json::json;

fn result_with(status: Status) -> CheckResult {
    CheckResult {
        check: &CHECKS[0],
        status,
        summary: String::new(),
        description: None,
        how_to_fix: "",
        affected_repos: Vec::new(),
        affected_repo_branches: Vec::new(),
        affected_repo_release_branches: Vec::new(),
        org_default_issue: false,
        org_only_issue: false,
        private_repos_excluded_by_plan: 0,
        private_repos_in_scope: 0,
        private_repos_filtered_out: 0,
        repos_skipped_no_data: 0,
        no_data_label: None,
        skip_reason: None,
    }
}

#[test]
fn exit_code_is_zero_when_no_failures() {
    let results = vec![
        result_with(Status::Pass),
        result_with(Status::Warn),
        result_with(Status::Skipped),
    ];
    assert_eq!(runner::exit_code(&results), 0);
}

#[test]
fn exit_code_is_one_when_any_check_fails() {
    let results = vec![result_with(Status::Pass), result_with(Status::Fail)];
    assert_eq!(runner::exit_code(&results), 1);
}

#[test]
fn exit_code_is_zero_for_empty_results() {
    assert_eq!(runner::exit_code(&[]), 0);
}

#[tokio::test]
async fn detect_account_resolves_organization() {
    let client =
        FakeGitHubClient::new().with_json("/users/acme", json!({ "type": "Organization" }));
    let k = runner::detect_account(&client, "acme").await.unwrap();
    assert!(matches!(k, AccountKind::Organization));
}

#[tokio::test]
async fn detect_account_resolves_user() {
    let client = FakeGitHubClient::new().with_json("/users/nuno", json!({ "type": "User" }));
    let k = runner::detect_account(&client, "nuno").await.unwrap();
    assert!(matches!(k, AccountKind::User));
}

#[tokio::test]
async fn detect_account_404_is_friendly_error() {
    let client = FakeGitHubClient::new().with_not_found("/users/ghost");
    let e = runner::detect_account(&client, "ghost").await.unwrap_err();
    assert!(e.to_string().contains("ghost"));
}

#[tokio::test]
async fn detect_account_403_is_scope_error() {
    let client = FakeGitHubClient::new().with_forbidden("/users/secret");
    let e = runner::detect_account(&client, "secret").await.unwrap_err();
    assert!(e.to_string().contains("scope"));
}

fn stub_org(org: &str) -> FakeGitHubClient {
    FakeGitHubClient::new()
        .with_json(
            format!("/orgs/{org}"),
            json!({
                "two_factor_requirement_enabled": true,
                "default_repository_permission": "read",
                "plan": { "name": "team" }
            }),
        )
        .with_json(
            format!("/orgs/{org}/settings/immutable-releases"),
            json!({ "enforced_repositories": "all" }),
        )
        .with_json(
            format!("/orgs/{org}/actions/permissions/fork-pr-contributor-approval"),
            json!({ "approval_policy": "all_external_contributors" }),
        )
        .with_json(
            format!("/orgs/{org}/actions/permissions/workflow"),
            json!({ "default_workflow_permissions": "read" }),
        )
        .with_json(
            format!("/orgs/{org}/code-security/configurations/defaults"),
            json!([]),
        )
        .with_paginated(format!("/orgs/{org}/members?filter=2fa_disabled"), vec![])
        .with_paginated(format!("/orgs/{org}/members?role=admin"), vec![])
        .with_paginated(format!("/orgs/{org}/outside_collaborators"), vec![])
        .with_paginated(format!("/orgs/{org}/hooks"), vec![])
        .with_paginated(format!("/orgs/{org}/rulesets"), vec![])
        .with_paginated(
            format!("/orgs/{org}/repos?type=all"),
            vec![json!({
                "name": "demo",
                "archived": false,
                "fork": false,
                "default_branch": "main",
                "security_and_analysis": {
                    "secret_scanning": { "status": "enabled" },
                    "secret_scanning_push_protection": { "status": "enabled" }
                }
            })],
        )
        .with_json(
            format!("/repos/{org}/demo/branches/main/protection"),
            json!({
                "required_signatures": { "enabled": true },
                "required_pull_request_reviews": {}
            }),
        )
        .with_json(
            format!("/repos/{org}/demo/actions/permissions/workflow"),
            json!({ "default_workflow_permissions": "read" }),
        )
        .with_status(format!("/repos/{org}/demo/vulnerability-alerts"), 204)
        .with_json(
            format!("/repos/{org}/demo/automated-security-fixes"),
            json!({ "enabled": true, "paused": false }),
        )
        .with_json(
            format!("/repos/{org}/demo/private-vulnerability-reporting"),
            json!({ "enabled": true }),
        )
        .with_json(
            format!("/repos/{org}/demo/immutable-releases"),
            json!({ "enabled": true }),
        )
        .with_json(
            format!("/repos/{org}/demo/actions/permissions/fork-pr-contributor-approval"),
            json!({ "approval_policy": "all_external_contributors" }),
        )
        .with_json(
            format!("/repos/{org}/demo/actions/permissions"),
            json!({ "sha_pinning_required": true }),
        )
        .with_paginated(format!("/repos/{org}/demo/hooks"), vec![])
        .with_paginated(
            format!("/repos/{org}/demo/collaborators?affiliation=direct"),
            vec![],
        )
}

#[tokio::test]
async fn run_org_checks_completes_against_fake_client() {
    let client = stub_org("acme");
    let org = runner::fetch_org_context(&client, "acme").await.unwrap();
    let repos: Vec<moat::checks::RepoContext> = Vec::new();
    let ctx = runner::CheckContext {
        org: Some(&org),
        repos: &repos,
    };
    let results = runner::run_checks(&ctx);
    runner::render_posture_panel(&results);
    runner::render_checks_panel(&results, Some(&org), "test-owner", 0, false);
}

#[tokio::test]
async fn run_repo_checks_completes_against_fake_client() {
    let client = stub_org("acme");
    let contexts = runner::fetch_repo_contexts(&client, "acme", AccountKind::Organization)
        .await
        .unwrap();
    let ctx = runner::CheckContext {
        org: None,
        repos: &contexts,
    };
    let results = runner::run_checks(&ctx);
    runner::render_posture_panel(&results);
    runner::render_checks_panel(&results, None, "test-owner", contexts.len(), false);
}

fn security_policy_status(contexts: &[moat::checks::RepoContext]) -> Status {
    let ctx = runner::CheckContext {
        org: None,
        repos: contexts,
    };
    runner::run_checks(&ctx)
        .into_iter()
        .find(|r| r.check.id == "repositories_have_security_policy")
        .expect("security policy check present")
        .status
}

#[tokio::test]
async fn repo_inherits_security_policy_from_org_dot_github_repo() {
    // `demo` ships no SECURITY.md of its own, but the org's special `.github`
    // repository publishes one (here under its `.github/` directory). GitHub
    // serves that as `demo`'s security policy, so the check must pass via the
    // inherited fallback rather than flagging the repo as missing one.
    let client = stub_org("acme").with_raw(
        "/repos/acme/.github/contents/.github/SECURITY.md",
        "# Security Policy\n",
    );
    let contexts = runner::fetch_repo_contexts(&client, "acme", AccountKind::Organization)
        .await
        .unwrap();
    assert_eq!(security_policy_status(&contexts), Status::Pass);
}

#[tokio::test]
async fn repo_without_own_or_inherited_security_policy_fails() {
    // No SECURITY.md on the repo and no `.github` repo fallback — the check
    // should still fail, confirming the fallback doesn't mask a genuine miss.
    let client = stub_org("acme");
    let contexts = runner::fetch_repo_contexts(&client, "acme", AccountKind::Organization)
        .await
        .unwrap();
    assert_eq!(security_policy_status(&contexts), Status::Fail);
}

#[tokio::test]
async fn list_repos_excludes_security_advisory_forks() {
    let org = "acme";
    let client = FakeGitHubClient::new().with_paginated(
        format!("/orgs/{org}/repos?type=all"),
        vec![
            json!({ "name": "demo", "archived": false, "fork": false }),
            json!({
                "name": "public-php-workflow-ghsa-8xq3-q5v5-wg6h",
                "archived": false,
                "fork": false
            }),
        ],
    );

    let repos = runner::list_repos(
        &client,
        org,
        AccountKind::Organization,
        runner::VisibilityFilter::All,
    )
    .await
    .unwrap();
    let names: Vec<&str> = repos.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, vec!["demo"]);
}

#[tokio::test]
async fn list_repos_filters_by_visibility() {
    let org = "acme";
    let repos_json = vec![
        json!({ "name": "open", "archived": false, "fork": false, "private": false }),
        json!({ "name": "closed", "archived": false, "fork": false, "private": true }),
    ];
    let path = format!("/orgs/{org}/repos?type=all");

    let names = |visibility| {
        let client = FakeGitHubClient::new().with_paginated(path.clone(), repos_json.clone());
        async move {
            let repos = runner::list_repos(&client, org, AccountKind::Organization, visibility)
                .await
                .unwrap();
            repos
                .iter()
                .map(|r| r.name.clone())
                .collect::<Vec<String>>()
        }
    };

    assert_eq!(
        names(runner::VisibilityFilter::All).await,
        vec!["open", "closed"]
    );
    assert_eq!(names(runner::VisibilityFilter::Public).await, vec!["open"]);
    assert_eq!(
        names(runner::VisibilityFilter::Private).await,
        vec!["closed"]
    );
}

#[tokio::test]
async fn invalid_moat_toml_aborts_the_run() {
    let client = stub_org("acme").with_raw(
        "/repos/acme/demo/contents/moat.toml",
        "[checks]\nnot_a_real_check = \"off\"\n",
    );
    let err = match runner::fetch_repo_contexts(&client, "acme", AccountKind::Organization).await {
        Ok(_) => panic!("expected fetch_repo_contexts to fail on invalid moat.toml"),
        Err(e) => e,
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("Invalid moat.toml"), "got: {msg}");
    assert!(msg.contains("acme/demo"), "got: {msg}");
    assert!(msg.contains("Unknown check"), "got: {msg}");
}

#[tokio::test]
async fn missing_moat_toml_continues_with_defaults() {
    // stub_org does not stub the moat.toml endpoint, so get_raw returns NotFound
    // and the run should proceed normally.
    let client = stub_org("acme");
    let contexts = runner::fetch_repo_contexts(&client, "acme", AccountKind::Organization)
        .await
        .unwrap();
    assert_eq!(contexts.len(), 1);
}

#[test]
fn missing_scopes_error_labels_github_token_source() {
    // GITHUB_TOKEN remediation steers the user to regenerate the PAT or unset
    // the env var to fall back to gh — the message must name the env var so the
    // user knows what to regenerate.
    let granted = vec!["repo".to_string(), "read:org".to_string()];
    let required = ["admin:org", "repo", "workflow"];
    let missing = ["admin:org", "workflow"];
    let err =
        format_missing_scopes_error(AuthSource::GithubTokenEnv, &granted, &required, &missing);
    let s = err.to_string();
    assert!(s.contains("GITHUB_TOKEN"));
    assert!(s.contains("admin:org"));
    assert!(s.contains("https://github.com/settings/tokens"));
    assert!(s.contains("unset GITHUB_TOKEN"));
    assert!(!s.contains("gh auth login -s"));
}

#[test]
fn missing_scopes_error_labels_gh_token_source() {
    let granted = vec!["repo".to_string()];
    let required = ["repo", "workflow"];
    let missing = ["workflow"];
    let err = format_missing_scopes_error(AuthSource::GhTokenEnv, &granted, &required, &missing);
    let s = err.to_string();
    assert!(s.contains("GH_TOKEN"));
    assert!(s.contains("unset GH_TOKEN"));
    assert!(s.contains("export GH_TOKEN=<new-token>"));
}

#[test]
fn missing_scopes_error_labels_gh_cli_source() {
    // gh CLI source should recommend `gh auth login -s ...` with the joined
    // required scope list, not the PAT regeneration flow.
    let granted = vec!["repo".to_string()];
    let required = ["admin:org", "repo", "workflow"];
    let missing = ["admin:org", "workflow"];
    let err = format_missing_scopes_error(AuthSource::GhCli, &granted, &required, &missing);
    let s = err.to_string();
    assert!(s.contains("gh auth token"));
    assert!(s.contains("gh auth login -s admin:org,repo,workflow -h github.com -w"));
    assert!(!s.contains("settings/tokens"));
}

#[test]
fn sso_error_names_source_and_account() {
    for src in [
        AuthSource::GithubTokenEnv,
        AuthSource::GhTokenEnv,
        AuthSource::GhCli,
    ] {
        let err = format_sso_error(src, "acme", "https://github.com/orgs/acme/sso?return_to=/x");
        let s = err.to_string();
        assert!(s.contains(&format!("{src}")));
        assert!(s.contains("acme"));
        assert!(s.contains("sso?return_to=/x"));
    }
}

#[test]
fn unauthorized_error_labels_source() {
    let s = format_unauthorized_error(AuthSource::GithubTokenEnv).to_string();
    assert!(s.contains("GITHUB_TOKEN"));
    assert!(s.contains("401 Unauthorized"));
    assert!(s.contains("https://github.com/settings/tokens"));
    assert!(s.contains("classic personal access token"));
    assert!(s.contains("admin:org, repo, workflow"));
    assert!(s.contains("fine-grained PATs are not supported"));
    assert!(s.contains("unset GITHUB_TOKEN"));

    let s = format_unauthorized_error(AuthSource::GhCli).to_string();
    assert!(s.contains("gh auth token"));
    assert!(s.contains("gh auth login -s admin:org,repo,workflow -h github.com -w"));
}

#[tokio::test]
async fn user_account_repo_checks_with_empty_listing() {
    let client = FakeGitHubClient::new()
        .with_json("/users/nuno", json!({ "type": "User" }))
        .with_paginated("/users/nuno/repos", vec![]);
    let contexts = runner::fetch_repo_contexts(&client, "nuno", AccountKind::User)
        .await
        .unwrap();
    assert!(contexts.is_empty());
}
