use moat::checks::StateCtx;
use moat::checks::common::WebhookInfo;
use moat::checks::org_context::ForkPrContributorApprovalState;
use moat::checks::repo_context::{
    BranchProtectionState, BranchProtections, DependabotConfigState, FeatureState, FeatureStatus,
    FilePresence, ReleaseImmutabilityRepoState, RepoContext, RepoListing, SHAPinningState,
    SecurityAndAnalysis, WorkflowTokenState,
};
use moat::checks::{
    repositories_actions_workflow_token_is_read_only as workflow_token,
    repositories_commits_are_signed as signed_commits,
    repositories_dependabot_alerts_are_enabled as dependabot_alerts,
    repositories_dependabot_security_updates_are_enabled as dependabot_security_updates,
    repositories_enforce_workflow_actions_sha_pinning as enforce_pinning,
    repositories_fork_pull_requests_require_approval as fork_pr_approval,
    repositories_have_dependabot_config as dependabot_config,
    repositories_have_no_direct_collaborators as direct_collaborators,
    repositories_have_security_policy as security_policy,
    repositories_private_vulnerability_reporting_is_enabled as pvr,
    repositories_pull_request_target_is_safe as prt_safe,
    repositories_pull_requests_require_reviews as pr_reviews,
    repositories_release_branches_are_locked as immutable_branch,
    repositories_release_branches_have_linear_history as linear_history,
    repositories_releases_are_immutable as releases_immutable,
    repositories_secret_push_protection_is_enabled as push_protection,
    repositories_secret_scanning_is_enabled as secret_scanning,
    repositories_webhooks_are_secure as webhooks_secure,
    repositories_workflow_actions_are_sha_pinned as pinned_actions,
    repositories_workflow_permissions_are_restricted as workflow_perms,
};
use moat::support::github::FakeGitHubClient;
use moat::support::outcome::Status;
use moat::support::workflows::{BranchedWorkflows, Workflow};
use serde_json::json;

fn bw(workflows: Vec<Workflow>) -> BranchedWorkflows {
    BranchedWorkflows {
        per_branch: vec![("main".into(), workflows)],
    }
}

fn workflows_by_branch(states: Vec<(&str, Vec<Workflow>)>) -> BranchedWorkflows {
    BranchedWorkflows {
        per_branch: states
            .into_iter()
            .map(|(branch, ws)| (branch.into(), ws))
            .collect(),
    }
}

fn protected(signed_commits: bool, pr_reviews: bool) -> BranchProtectionState {
    BranchProtectionState::Protected {
        signed_commits,
        pr_reviews,
        pr_dismiss_stale_reviews: pr_reviews,
        pr_require_last_push_approval: pr_reviews,
        pr_require_code_owner_review: pr_reviews,
        enforce_admins: false,
        required_linear_history: false,
        allow_force_pushes: false,
        allow_deletions: false,
    }
}

fn ctx(branch: BranchProtectionState, token: WorkflowTokenState) -> RepoContext {
    RepoContext {
        name: "r".into(),
        archived: false,
        private: false,
        default_branch: Some("main".into()),
        branch_protections: BranchProtections::from_single("main", branch),
        workflow_token: token,
        secret_scanning: FeatureState::Enabled,
        push_protection: FeatureState::Enabled,
        dependabot_alerts: FeatureState::Enabled,
        dependabot_security_updates: FeatureState::Enabled,
        private_vulnerability_reporting: FeatureState::Enabled,
        workflows: bw(Vec::new()),
        security_md: FilePresence::Absent,
        dependabot_config: DependabotConfigState::Missing,
        webhooks: Vec::new(),
        direct_collaborators: Vec::new(),
        release_immutability: ReleaseImmutabilityRepoState::Enabled,
        fork_pr_contributor_approval: ForkPrContributorApprovalState::AllExternalContributors,
        sha_pinning: SHAPinningState::Enforced,
        codeowners: FilePresence::Absent,
        config: moat::config::Config::default(),
    }
}

#[test]
fn signed_commits_flag_routing() {
    let mut pass = ctx(protected(true, false), WorkflowTokenState::Read);
    pass.private = true;
    let mut fail = ctx(protected(false, true), WorkflowTokenState::Read);
    fail.private = true;
    assert_eq!(signed_commits::repo_check(&pass).status, Status::Pass);
    assert_eq!(signed_commits::repo_check(&fail).status, Status::Fail);
}

#[test]
fn pr_reviews_flag_routing() {
    let pass = ctx(protected(false, true), WorkflowTokenState::Read);
    let fail = ctx(protected(true, false), WorkflowTokenState::Read);
    assert_eq!(pr_reviews::repo_check(&pass).status, Status::Pass);
    assert_eq!(pr_reviews::repo_check(&fail).status, Status::Fail);
}

fn protected_pr(
    pr_reviews: bool,
    dismiss: bool,
    last_push: bool,
    code_owner: bool,
) -> BranchProtectionState {
    BranchProtectionState::Protected {
        signed_commits: false,
        pr_reviews,
        pr_dismiss_stale_reviews: dismiss,
        pr_require_last_push_approval: last_push,
        pr_require_code_owner_review: code_owner,
        enforce_admins: false,
        required_linear_history: false,
        allow_force_pushes: false,
        allow_deletions: false,
    }
}

#[test]
fn pr_reviews_repo_check_lists_missing_sub_requirements() {
    let c = ctx(
        protected_pr(true, false, false, false),
        WorkflowTokenState::Read,
    );
    let out = pr_reviews::repo_check(&c);
    assert_eq!(out.status, Status::Fail);
    assert!(out.items.iter().any(|i| {
        i.to_ascii_lowercase()
            .contains("stale reviews not dismissed")
    }));
    assert!(out.items.iter().any(|i| {
        i.to_ascii_lowercase()
            .contains("last-push approval not required")
    }));
    // CODEOWNERS absent → code-owner-review failure must be suppressed.
    assert!(
        !out.items
            .iter()
            .any(|i| i.to_ascii_lowercase().contains("code-owner review"))
    );
}

#[test]
fn pr_reviews_repo_check_requires_code_owner_review_when_codeowners_present() {
    let mut c = ctx(
        protected_pr(true, true, true, false),
        WorkflowTokenState::Read,
    );
    c.codeowners = FilePresence::Present;
    let out = pr_reviews::repo_check(&c);
    assert_eq!(out.status, Status::Fail);
    assert_eq!(out.items.len(), 1);
    assert!(
        out.items[0]
            .to_ascii_lowercase()
            .contains("code-owner review not required")
    );
}

#[test]
fn pr_reviews_repo_check_passes_when_all_sub_requirements_met() {
    let mut c = ctx(
        protected_pr(true, true, true, true),
        WorkflowTokenState::Read,
    );
    c.codeowners = FilePresence::Present;
    let out = pr_reviews::repo_check(&c);
    assert_eq!(out.status, Status::Pass);
}

#[test]
fn pr_reviews_repo_check_reports_reviews_not_required_first() {
    let c = ctx(
        protected_pr(false, false, false, false),
        WorkflowTokenState::Read,
    );
    let out = pr_reviews::repo_check(&c);
    assert_eq!(out.status, Status::Fail);
    assert_eq!(out.items, vec!["reviews not required".to_string()]);
}

#[test]
fn workflow_token_states() {
    let r = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    let w = ctx(
        BranchProtectionState::Unprotected,
        WorkflowTokenState::Write,
    );
    assert_eq!(workflow_token::repo_check(&r).status, Status::Pass);
    assert_eq!(workflow_token::repo_check(&w).status, Status::Fail);
}

#[test]
fn dependabot_config_skipped_when_no_workflows() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(Vec::new());
    c.dependabot_config = DependabotConfigState::Missing;
    assert_eq!(dependabot_config::repo_check(&c).status, Status::Skipped);
}

#[test]
fn dependabot_config_description_counts_only_repos_with_workflows() {
    let mut readable = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    readable.name = "readable".into();
    readable.workflows = bw(vec![wf(
        ".github/workflows/ci.yml",
        "on: push\njobs:\n  a:\n    steps:\n      - run: echo\n",
    )]);
    readable.dependabot_config = DependabotConfigState::Missing;

    let mut no_workflows = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    no_workflows.name = "no_workflows".into();
    no_workflows.workflows = bw(Vec::new());
    no_workflows.dependabot_config = DependabotConfigState::Missing;

    let repos = vec![&readable, &no_workflows];
    let note = dependabot_config::description(StateCtx {
        org: None,
        repos: &repos,
    });

    assert_eq!(note, Some("1/1 repository lack a Dependabot config".into()));
}

#[test]
fn feature_state_outcomes_cover_all_variants() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);

    c.secret_scanning = FeatureState::Enabled;
    c.push_protection = FeatureState::Disabled;
    c.dependabot_alerts = FeatureState::PlanGated;

    assert_eq!(secret_scanning::repo_check(&c).status, Status::Pass);
    assert_eq!(push_protection::repo_check(&c).status, Status::Fail);
    assert_eq!(dependabot_alerts::repo_check(&c).status, Status::Skipped);
}

#[test]
fn dependabot_security_updates_repo_check_maps_feature_states() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);

    c.dependabot_security_updates = FeatureState::Enabled;
    assert_eq!(
        dependabot_security_updates::repo_check(&c).status,
        Status::Pass
    );

    c.dependabot_security_updates = FeatureState::Disabled;
    assert_eq!(
        dependabot_security_updates::repo_check(&c).status,
        Status::Fail
    );

    c.dependabot_security_updates = FeatureState::PlanGated;
    assert_eq!(
        dependabot_security_updates::repo_check(&c).status,
        Status::Skipped
    );
}

fn listing(default_branch: Option<&str>, sa: Option<SecurityAndAnalysis>) -> RepoListing {
    RepoListing {
        name: "demo".into(),
        archived: false,
        fork: false,
        private: true,
        default_branch: default_branch.map(String::from),
        security_and_analysis: sa,
        permissions: None,
    }
}

fn happy_path_client() -> FakeGitHubClient {
    FakeGitHubClient::new()
        .with_json(
            "/repos/acme/demo/branches/main/protection",
            json!({
                "required_signatures": { "enabled": true },
                "required_pull_request_reviews": { "dismiss_stale_reviews": true }
            }),
        )
        .with_json(
            "/repos/acme/demo/actions/permissions/workflow",
            json!({ "default_workflow_permissions": "read" }),
        )
        .with_status("/repos/acme/demo/vulnerability-alerts", 204)
        .with_json(
            "/repos/acme/demo/automated-security-fixes",
            json!({ "enabled": true, "paused": false }),
        )
        .with_json(
            "/repos/acme/demo/immutable-releases",
            json!({ "enabled": true }),
        )
        .with_json(
            "/repos/acme/demo/actions/permissions/fork-pr-contributor-approval",
            json!({ "approval_policy": "all_external_contributors" }),
        )
        .with_json(
            "/repos/acme/demo/actions/permissions",
            json!({ "sha_pinning_required": true }),
        )
        .with_paginated("/repos/acme/demo/hooks", vec![])
        .with_paginated("/repos/acme/demo/collaborators?affiliation=direct", vec![])
}

#[tokio::test]
async fn repo_context_fetch_happy_path() {
    let client = happy_path_client();
    let sa = SecurityAndAnalysis {
        secret_scanning: Some(FeatureStatus {
            status: "enabled".into(),
        }),
        secret_scanning_push_protection: Some(FeatureStatus {
            status: "enabled".into(),
        }),
    };
    let r = RepoContext::fetch(
        &client,
        "acme",
        listing(Some("main"), Some(sa)),
        FilePresence::Absent,
    )
    .await
    .unwrap();

    assert!(matches!(
        &r.branch_protections.branches[..],
        [(
            _,
            BranchProtectionState::Protected {
                signed_commits: true,
                pr_reviews: true,
                ..
            }
        )]
    ));
    assert!(matches!(r.workflow_token, WorkflowTokenState::Read));
    assert!(matches!(r.secret_scanning, FeatureState::Enabled));
    assert!(matches!(r.push_protection, FeatureState::Enabled));
    assert!(matches!(r.dependabot_alerts, FeatureState::Enabled));
}

#[tokio::test]
async fn repo_context_fetch_inherits_org_default_security_md() {
    // The repo has no SECURITY.md of its own (happy_path_client seeds none), so
    // fetch must fall back to the owner's `.github` default passed in here.
    let client = happy_path_client();
    let sa = SecurityAndAnalysis {
        secret_scanning: Some(FeatureStatus {
            status: "enabled".into(),
        }),
        secret_scanning_push_protection: Some(FeatureStatus {
            status: "enabled".into(),
        }),
    };
    let r = RepoContext::fetch(
        &client,
        "acme",
        listing(Some("main"), Some(sa)),
        FilePresence::Present,
    )
    .await
    .unwrap();
    assert_eq!(r.security_md, FilePresence::Present);
}

#[tokio::test]
async fn repo_context_fetch_uses_own_security_md_over_absent_org_default() {
    // The repo ships its own SECURITY.md, so it passes on its own merit even
    // when the owner has no `.github` default to inherit.
    let client = happy_path_client().with_raw("/repos/acme/demo/contents/SECURITY.md", "# Sec\n");
    let sa = SecurityAndAnalysis {
        secret_scanning: Some(FeatureStatus {
            status: "enabled".into(),
        }),
        secret_scanning_push_protection: Some(FeatureStatus {
            status: "enabled".into(),
        }),
    };
    let r = RepoContext::fetch(
        &client,
        "acme",
        listing(Some("main"), Some(sa)),
        FilePresence::Absent,
    )
    .await
    .unwrap();
    assert_eq!(r.security_md, FilePresence::Present);
}

#[tokio::test]
async fn repo_context_fetch_unprotected_when_protection_missing() {
    let client = happy_path_client()
        .with_not_found("/repos/acme/demo/branches/main/protection")
        .with_json(
            "/repos/acme/demo/actions/permissions/workflow",
            json!({ "default_workflow_permissions": "write" }),
        )
        .with_not_found("/repos/acme/demo/vulnerability-alerts")
        .with_json(
            "/repos/acme/demo/automated-security-fixes",
            json!({ "enabled": false, "paused": false }),
        )
        .with_json(
            "/repos/acme/demo/immutable-releases",
            json!({ "enabled": false }),
        )
        .with_json(
            "/repos/acme/demo/actions/permissions",
            json!({ "sha_pinning_required": false }),
        );

    // Pass a plan_gated sa wrapper-less listing so missing s_a doesn't crash
    // — instead we provide a stub.
    let sa = SecurityAndAnalysis {
        secret_scanning: Some(FeatureStatus {
            status: "disabled".into(),
        }),
        secret_scanning_push_protection: Some(FeatureStatus {
            status: "disabled".into(),
        }),
    };
    let r = RepoContext::fetch(
        &client,
        "acme",
        listing(Some("main"), Some(sa)),
        FilePresence::Absent,
    )
    .await
    .unwrap();
    assert!(matches!(
        &r.branch_protections.branches[..],
        [(_, BranchProtectionState::Unprotected)]
    ));
    assert!(matches!(r.workflow_token, WorkflowTokenState::Write));
    assert!(matches!(r.dependabot_alerts, FeatureState::Disabled));
}

#[tokio::test]
async fn repo_context_fetch_plan_gated_private_repo_marks_scan_and_push_plan_gated() {
    let client = happy_path_client()
        .with_plan_gated("/repos/acme/demo/branches/main/protection")
        .with_json(
            "/repos/acme/demo/actions/permissions/workflow",
            json!({ "default_workflow_permissions": "read" }),
        )
        .with_status("/repos/acme/demo/vulnerability-alerts", 204)
        .with_json(
            "/repos/acme/demo/automated-security-fixes",
            json!({ "enabled": true, "paused": false }),
        )
        .with_json(
            "/repos/acme/demo/immutable-releases",
            json!({ "enabled": true }),
        )
        .with_json(
            "/repos/acme/demo/actions/permissions/fork-pr-contributor-approval",
            json!({ "approval_policy": "all_external_contributors" }),
        )
        .with_json(
            "/repos/acme/demo/actions/permissions",
            json!({ "sha_pinning_required": true }),
        );

    let sa = SecurityAndAnalysis {
        secret_scanning: Some(FeatureStatus {
            status: "disabled".into(),
        }),
        secret_scanning_push_protection: Some(FeatureStatus {
            status: "disabled".into(),
        }),
    };
    let r = RepoContext::fetch(
        &client,
        "acme",
        listing(Some("main"), Some(sa)),
        FilePresence::Absent,
    )
    .await
    .unwrap();

    assert!(matches!(
        &r.branch_protections.branches[..],
        [(_, BranchProtectionState::PlanGated)]
    ));
    assert!(matches!(r.secret_scanning, FeatureState::PlanGated));
    assert!(matches!(r.push_protection, FeatureState::PlanGated));
    assert!(matches!(r.dependabot_alerts, FeatureState::Enabled));
}

#[tokio::test]
async fn repo_context_fetch_forks_are_rejected() {
    let client = FakeGitHubClient::new();
    let mut l = listing(Some("main"), None);
    l.fork = true;
    let err = RepoContext::fetch(&client, "acme", l, FilePresence::Absent)
        .await
        .err()
        .expect("expected fork to be rejected");
    assert!(err.to_string().to_ascii_lowercase().contains("fork"));
}

#[test]
fn direct_collaborators_states() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);

    c.direct_collaborators = Vec::new();
    assert_eq!(direct_collaborators::repo_check(&c).status, Status::Pass);

    c.direct_collaborators = vec!["alice".into(), "bob".into()];
    let outcome = direct_collaborators::repo_check(&c);
    assert_eq!(outcome.status, Status::Fail);
    assert_eq!(outcome.summary, "2");
}

#[tokio::test]
async fn repo_context_fetch_direct_collaborators_populated() {
    let client = happy_path_client().with_paginated(
        "/repos/acme/demo/collaborators?affiliation=direct",
        vec![json!({ "login": "alice" })],
    );

    let sa = SecurityAndAnalysis {
        secret_scanning: Some(FeatureStatus {
            status: "enabled".into(),
        }),
        secret_scanning_push_protection: Some(FeatureStatus {
            status: "enabled".into(),
        }),
    };
    let r = RepoContext::fetch(
        &client,
        "acme",
        listing(Some("main"), Some(sa)),
        FilePresence::Absent,
    )
    .await
    .unwrap();

    assert_eq!(r.direct_collaborators, vec!["alice".to_string()]);
}

#[tokio::test]
async fn repo_context_fetch_direct_collaborators_public_repo_filters_read_only() {
    let client = happy_path_client().with_paginated(
        "/repos/acme/demo/collaborators?affiliation=direct",
        vec![
            json!({ "login": "reader", "permissions": { "pull": true } }),
            json!({ "login": "writer", "permissions": { "push": true } }),
        ],
    );

    let sa = SecurityAndAnalysis {
        secret_scanning: Some(FeatureStatus {
            status: "enabled".into(),
        }),
        secret_scanning_push_protection: Some(FeatureStatus {
            status: "enabled".into(),
        }),
    };
    let mut l = listing(Some("main"), Some(sa));
    l.private = false;
    let r = RepoContext::fetch(&client, "acme", l, FilePresence::Absent)
        .await
        .unwrap();

    assert_eq!(r.direct_collaborators, vec!["writer".to_string()]);
}

#[tokio::test]
async fn repo_context_fetch_direct_collaborators_forbidden_bails() {
    let client =
        happy_path_client().with_forbidden("/repos/acme/demo/collaborators?affiliation=direct");

    let sa = SecurityAndAnalysis {
        secret_scanning: Some(FeatureStatus {
            status: "enabled".into(),
        }),
        secret_scanning_push_protection: Some(FeatureStatus {
            status: "enabled".into(),
        }),
    };
    let err = RepoContext::fetch(
        &client,
        "acme",
        listing(Some("main"), Some(sa)),
        FilePresence::Absent,
    )
    .await
    .err()
    .expect("expected bail");
    assert!(err.to_string().contains("direct collaborators"));
}

fn wf(path: &str, yaml: &str) -> Workflow {
    Workflow {
        path: path.into(),
        doc: serde_yaml::from_str(yaml).unwrap(),
    }
}

fn protected_full(
    enforce_admins: bool,
    required_linear_history: bool,
    allow_force_pushes: bool,
    allow_deletions: bool,
) -> BranchProtectionState {
    BranchProtectionState::Protected {
        signed_commits: false,
        pr_reviews: false,
        pr_dismiss_stale_reviews: false,
        pr_require_last_push_approval: false,
        pr_require_code_owner_review: false,
        enforce_admins,
        required_linear_history,
        allow_force_pushes,
        allow_deletions,
    }
}

#[test]
fn pinned_actions_flags_unpinned_refs() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(vec![wf(
        "ci.yml",
        "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n",
    )]);
    let o = pinned_actions::repo_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert_eq!(o.summary, "✗");
    assert!(o.items.iter().any(|i| i.contains("unpinned")));
}

#[test]
fn pinned_actions_passes_when_all_refs_pinned() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(vec![wf(
        "ci.yml",
        "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@1234567890123456789012345678901234567890\n",
    )]);
    let o = pinned_actions::repo_check(&c);
    assert_eq!(o.status, Status::Pass);
}

#[test]
fn pinned_actions_no_workflows_is_skipped() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(Vec::new());
    let o = pinned_actions::repo_check(&c);
    assert_eq!(o.status, Status::Skipped);
}

#[test]
fn enforce_pinning_fails_when_setting_off() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.sha_pinning = SHAPinningState::NotEnforced;
    c.workflows = bw(vec![wf(
        "ci.yml",
        "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@1234567890123456789012345678901234567890\n",
    )]);
    let o = enforce_pinning::repo_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert_eq!(o.summary, "✗");
    assert_eq!(o.items.len(), 1);
}

#[test]
fn enforce_pinning_passes_when_setting_on() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.sha_pinning = SHAPinningState::Enforced;
    c.workflows = bw(vec![wf(
        "ci.yml",
        "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n",
    )]);
    let o = enforce_pinning::repo_check(&c);
    assert_eq!(o.status, Status::Pass);
}

#[test]
fn enforce_pinning_plan_gated_is_skipped() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.sha_pinning = SHAPinningState::PlanGated;
    c.workflows = bw(vec![wf(
        "ci.yml",
        "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n",
    )]);
    assert_eq!(enforce_pinning::repo_check(&c).status, Status::Skipped);
}

#[test]
fn enforce_pinning_no_workflows_is_skipped() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.sha_pinning = SHAPinningState::NotEnforced;
    c.workflows = bw(Vec::new());
    assert_eq!(enforce_pinning::repo_check(&c).status, Status::Skipped);
}

#[tokio::test]
async fn repo_context_fetch_sha_pinning_enforced() {
    let client = happy_path_client();
    let sa = SecurityAndAnalysis {
        secret_scanning: Some(FeatureStatus {
            status: "enabled".into(),
        }),
        secret_scanning_push_protection: Some(FeatureStatus {
            status: "enabled".into(),
        }),
    };
    let r = RepoContext::fetch(
        &client,
        "acme",
        listing(Some("main"), Some(sa)),
        FilePresence::Absent,
    )
    .await
    .unwrap();
    assert!(matches!(r.sha_pinning, SHAPinningState::Enforced));
}

#[tokio::test]
async fn repo_context_fetch_sha_pinning_not_enforced() {
    let client = happy_path_client().with_json(
        "/repos/acme/demo/actions/permissions",
        json!({ "sha_pinning_required": false }),
    );
    let sa = SecurityAndAnalysis {
        secret_scanning: Some(FeatureStatus {
            status: "enabled".into(),
        }),
        secret_scanning_push_protection: Some(FeatureStatus {
            status: "enabled".into(),
        }),
    };
    let r = RepoContext::fetch(
        &client,
        "acme",
        listing(Some("main"), Some(sa)),
        FilePresence::Absent,
    )
    .await
    .unwrap();
    assert!(matches!(r.sha_pinning, SHAPinningState::NotEnforced));
}

#[tokio::test]
async fn repo_context_fetch_sha_pinning_bails_when_endpoint_missing() {
    let client = happy_path_client().with_not_found("/repos/acme/demo/actions/permissions");
    let sa = SecurityAndAnalysis {
        secret_scanning: Some(FeatureStatus {
            status: "enabled".into(),
        }),
        secret_scanning_push_protection: Some(FeatureStatus {
            status: "enabled".into(),
        }),
    };
    let err = RepoContext::fetch(
        &client,
        "acme",
        listing(Some("main"), Some(sa)),
        FilePresence::Absent,
    )
    .await
    .err()
    .expect("expected bail");
    assert!(err.to_string().to_ascii_lowercase().contains("sha pinning"));
}

#[test]
fn immutable_branch_fails_when_force_pushes_allowed() {
    let c = ctx(
        protected_full(false, false, true, false),
        WorkflowTokenState::Read,
    );
    let o = immutable_branch::repo_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(
        o.items
            .iter()
            .any(|i| i.to_ascii_lowercase().contains("force pushes"))
    );
}

#[test]
fn immutable_branch_fails_when_deletions_allowed() {
    let c = ctx(
        protected_full(false, false, false, true),
        WorkflowTokenState::Read,
    );
    let o = immutable_branch::repo_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(
        o.items
            .iter()
            .any(|i| i.to_ascii_lowercase().contains("deletions"))
    );
}

#[test]
fn immutable_branch_lists_both_when_both_allowed() {
    let c = ctx(
        protected_full(false, false, true, true),
        WorkflowTokenState::Read,
    );
    let o = immutable_branch::repo_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert_eq!(o.items.len(), 2);
}

#[test]
fn immutable_branch_passes_when_neither_allowed() {
    let c = ctx(
        protected_full(false, false, false, false),
        WorkflowTokenState::Read,
    );
    assert_eq!(immutable_branch::repo_check(&c).status, Status::Pass);
}

#[test]
fn immutable_branch_unprotected_fails() {
    let c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    assert_eq!(immutable_branch::repo_check(&c).status, Status::Fail);
}

#[test]
fn immutable_branch_plan_gated_skipped() {
    let c = ctx(BranchProtectionState::PlanGated, WorkflowTokenState::Read);
    assert_eq!(immutable_branch::repo_check(&c).status, Status::Skipped);
}

#[test]
fn webhooks_empty_passes() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.webhooks = Vec::new();
    assert_eq!(webhooks_secure::repo_check(&c).status, Status::Pass);
}

#[test]
fn webhooks_http_url_fails_with_not_https() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.webhooks = vec![WebhookInfo {
        url: "http://example.com/hook".into(),
        has_secret: true,
    }];
    let o = webhooks_secure::repo_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(
        o.items
            .iter()
            .any(|i| i.to_ascii_lowercase().contains("not https"))
    );
}

#[test]
fn webhooks_no_secret_fails() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.webhooks = vec![WebhookInfo {
        url: "https://example.com/hook".into(),
        has_secret: false,
    }];
    let o = webhooks_secure::repo_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(
        o.items
            .iter()
            .any(|i| i.to_ascii_lowercase().contains("no secret"))
    );
}

#[test]
fn webhooks_empty_url_renders_as_unknown() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.webhooks = vec![WebhookInfo {
        url: String::new(),
        has_secret: false,
    }];
    let o = webhooks_secure::repo_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(
        o.items
            .iter()
            .any(|i| i.to_ascii_lowercase().contains("<unknown>"))
    );
}

#[test]
fn webhooks_both_failures_reported() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.webhooks = vec![WebhookInfo {
        url: "http://example.com/hook".into(),
        has_secret: false,
    }];
    let o = webhooks_secure::repo_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert_eq!(o.items.len(), 2);
}

#[test]
fn security_policy_present_passes() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.security_md = FilePresence::Present;
    assert_eq!(security_policy::repo_check(&c).status, Status::Pass);
}

#[test]
fn security_policy_absent_fails() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.security_md = FilePresence::Absent;
    assert_eq!(security_policy::repo_check(&c).status, Status::Fail);
}

#[test]
fn releases_immutable_states() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.release_immutability = ReleaseImmutabilityRepoState::Enabled;
    assert_eq!(releases_immutable::repo_check(&c).status, Status::Pass);
    c.release_immutability = ReleaseImmutabilityRepoState::Disabled;
    assert_eq!(releases_immutable::repo_check(&c).status, Status::Fail);
}

#[test]
fn fork_pr_approval_states() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.fork_pr_contributor_approval = ForkPrContributorApprovalState::AllExternalContributors;
    assert_eq!(fork_pr_approval::repo_check(&c).status, Status::Pass);
    c.fork_pr_contributor_approval = ForkPrContributorApprovalState::FirstTimeContributors;
    assert_eq!(fork_pr_approval::repo_check(&c).status, Status::Fail);
    c.fork_pr_contributor_approval =
        ForkPrContributorApprovalState::FirstTimeContributorsNewToGithub;
    assert_eq!(fork_pr_approval::repo_check(&c).status, Status::Fail);
    c.fork_pr_contributor_approval = ForkPrContributorApprovalState::Other;
    assert_eq!(fork_pr_approval::repo_check(&c).status, Status::Fail);
}

#[test]
fn pvr_public_feature_states() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.private = false;
    c.private_vulnerability_reporting = FeatureState::Enabled;
    assert_eq!(pvr::repo_check(&c).status, Status::Pass);
    c.private_vulnerability_reporting = FeatureState::Disabled;
    assert_eq!(pvr::repo_check(&c).status, Status::Fail);
    c.private_vulnerability_reporting = FeatureState::PlanGated;
    assert_eq!(pvr::repo_check(&c).status, Status::Skipped);
}

#[test]
fn prt_safe_empty_workflows_skipped() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(Vec::new());
    assert_eq!(prt_safe::repo_check(&c).status, Status::Skipped);
}

#[test]
fn prt_safe_pull_request_target_with_untrusted_checkout_fails() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(vec![wf(
        "danger.yml",
        "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
    )]);
    let o = prt_safe::repo_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(
        o.items
            .iter()
            .any(|i| i.to_ascii_lowercase().contains("danger.yml"))
    );
}

#[test]
fn prt_safe_pull_request_target_with_head_ref_fails() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(vec![wf(
        "danger.yml",
        "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.head_ref }}\n",
    )]);
    assert_eq!(prt_safe::repo_check(&c).status, Status::Fail);
}

#[test]
fn prt_safe_pull_request_target_case_insensitive_checkout_fails() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(vec![wf(
        "danger.yml",
        "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: Actions/Checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
    )]);
    assert_eq!(prt_safe::repo_check(&c).status, Status::Fail);
}

#[test]
fn prt_safe_pull_request_target_third_party_checkout_fails() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(vec![wf(
        "danger.yml",
        "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: some-org/checkout/v2@v2\n        with:\n          ref: ${{ github.head_ref }}\n",
    )]);
    assert_eq!(prt_safe::repo_check(&c).status, Status::Fail);
}

#[test]
fn prt_safe_pull_request_target_shell_checkout_fails() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(vec![wf(
        "danger.yml",
        "on: pull_request_target\njobs:\n  a:\n    steps:\n      - run: git fetch origin ${{ github.head_ref }} && git checkout FETCH_HEAD\n",
    )]);
    assert_eq!(prt_safe::repo_check(&c).status, Status::Fail);
}

#[test]
fn prt_safe_pull_request_target_without_checkout_passes() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(vec![wf(
        "safe.yml",
        "on: pull_request_target\njobs:\n  a:\n    steps:\n      - run: echo hi\n",
    )]);
    assert_eq!(prt_safe::repo_check(&c).status, Status::Pass);
}

#[test]
fn linear_history_repo_check_flag_routing() {
    let pass = ctx(
        protected_full(false, true, false, false),
        WorkflowTokenState::Read,
    );
    let fail = ctx(
        protected_full(false, false, false, false),
        WorkflowTokenState::Read,
    );
    assert_eq!(linear_history::repo_check(&pass).status, Status::Pass);
    assert_eq!(linear_history::repo_check(&fail).status, Status::Fail);
}

#[test]
fn workflow_perms_no_workflows_skipped() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(Vec::new());
    assert_eq!(workflow_perms::repo_check(&c).status, Status::Skipped);
}

#[test]
fn workflow_perms_multi_branch_findings_visible() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = workflows_by_branch(vec![
        (
            "main",
            vec![wf(
                "ci.yml",
                "on: push\npermissions: write-all\njobs:\n  a:\n    steps:\n      - run: echo\n",
            )],
        ),
        ("release", Vec::new()),
    ]);
    assert_eq!(workflow_perms::repo_check(&c).status, Status::Fail);
}

#[test]
fn workflow_perms_missing_block_fails() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(vec![wf(
        "ci.yml",
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
    )]);
    let o = workflow_perms::repo_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(
        o.items
            .iter()
            .any(|i| i.to_ascii_lowercase().contains("missing"))
    );
}

#[test]
fn workflow_perms_write_all_fails() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(vec![wf(
        "ci.yml",
        "on: push\npermissions: write-all\njobs:\n  a:\n    steps:\n      - run: echo\n",
    )]);
    let o = workflow_perms::repo_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(
        o.items
            .iter()
            .any(|i| i.to_ascii_lowercase().contains("write-all"))
    );
}

#[test]
fn workflow_perms_scoped_write_fails() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(vec![wf(
        "ci.yml",
        "on: push\npermissions:\n  contents: write\n  issues: read\njobs:\n  a:\n    steps:\n      - run: echo\n",
    )]);
    let o = workflow_perms::repo_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(
        o.items
            .iter()
            .any(|i| i.to_ascii_lowercase().contains("contents"))
    );
}

#[test]
fn workflow_perms_read_only_passes() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(vec![wf(
        "ci.yml",
        "on: push\npermissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - run: echo\n",
    )]);
    assert_eq!(workflow_perms::repo_check(&c).status, Status::Pass);
}

#[test]
fn workflow_perms_job_level_write_all_fails() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(vec![wf(
        "ci.yml",
        "on: push\npermissions:\n  contents: read\njobs:\n  a:\n    permissions: write-all\n    steps:\n      - run: echo\n",
    )]);
    let o = workflow_perms::repo_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(
        o.items
            .iter()
            .any(|i| i.to_ascii_lowercase().contains("job `a`")
                && i.to_ascii_lowercase().contains("write-all"))
    );
}

#[test]
fn workflow_perms_job_level_scoped_write_fails() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(vec![wf(
        "ci.yml",
        "on: push\npermissions:\n  contents: read\njobs:\n  release:\n    permissions:\n      contents: write\n      issues: read\n    steps:\n      - run: echo\n",
    )]);
    let o = workflow_perms::repo_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(
        o.items
            .iter()
            .any(|i| i.to_ascii_lowercase().contains("job `release`")
                && i.to_ascii_lowercase().contains("contents"))
    );
}

#[test]
fn workflow_perms_job_level_read_only_passes() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(vec![wf(
        "ci.yml",
        "on: push\npermissions:\n  contents: read\njobs:\n  a:\n    permissions:\n      contents: read\n    steps:\n      - run: echo\n",
    )]);
    assert_eq!(workflow_perms::repo_check(&c).status, Status::Pass);
}

#[test]
fn workflow_perms_deploy_pages_job_with_required_writes_passes() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(vec![wf(
        "deploy.yml",
        "on: push\npermissions:\n  contents: read\njobs:\n  deploy:\n    permissions:\n      pages: write\n      id-token: write\n    steps:\n      - uses: actions/deploy-pages@0000000000000000000000000000000000000000\n",
    )]);
    assert_eq!(workflow_perms::repo_check(&c).status, Status::Pass);
}

#[test]
fn workflow_perms_deploy_pages_job_with_extra_writes_fails() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(vec![wf(
        "deploy.yml",
        "on: push\npermissions:\n  contents: read\njobs:\n  deploy:\n    permissions:\n      pages: write\n      id-token: write\n      contents: write\n    steps:\n      - uses: actions/deploy-pages@ffffffffffffffffffffffffffffffffffffffff\n",
    )]);
    let o = workflow_perms::repo_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(o.items.iter().any(|i| i.contains("contents")));
}

#[test]
fn workflow_perms_deploy_pages_job_top_level_write_still_fails() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(vec![wf(
        "deploy.yml",
        "on: push\npermissions:\n  contents: write\njobs:\n  deploy:\n    permissions:\n      pages: write\n      id-token: write\n    steps:\n      - uses: actions/deploy-pages@1111111111111111111111111111111111111111\n",
    )]);
    let o = workflow_perms::repo_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(o.items.iter().any(|i| i.contains("contents")));
}

#[test]
fn workflow_perms_deploy_pages_full_user_workflow_passes() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(vec![wf(
        "deploy.yml",
        r#"on:
  push:
    branches: ["main"]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      - run: echo build
  deploy:
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    needs: build
    permissions:
      contents: read
      pages: write
      id-token: write
    steps:
      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
"#,
    )]);
    assert_eq!(workflow_perms::repo_check(&c).status, Status::Pass);
}

#[test]
fn workflow_perms_deploy_pages_job_without_action_still_fails() {
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.workflows = bw(vec![wf(
        "deploy.yml",
        "on: push\npermissions:\n  contents: read\njobs:\n  deploy:\n    permissions:\n      pages: write\n    steps:\n      - run: echo\n",
    )]);
    let o = workflow_perms::repo_check(&c);
    assert_eq!(o.status, Status::Fail);
    assert!(o.items.iter().any(|i| i.contains("pages")));
}

#[test]
fn workflow_perms_custom_known_action_from_config_passes() {
    let config = moat::config::Config::parse(
        r#"
            [workflow_permissions]
            "my-org/custom-deploy" = ["deployments"]
        "#,
        &[],
    )
    .unwrap();
    let mut c = ctx(BranchProtectionState::Unprotected, WorkflowTokenState::Read);
    c.config = config;
    c.workflows = bw(vec![wf(
        "deploy.yml",
        "on: push\npermissions:\n  contents: read\njobs:\n  deploy:\n    permissions:\n      deployments: write\n    steps:\n      - uses: my-org/custom-deploy@v1\n",
    )]);
    assert_eq!(workflow_perms::repo_check(&c).status, Status::Pass);
}

#[tokio::test]
async fn repo_context_fetch_bails_on_forbidden_workflow_token() {
    let client =
        happy_path_client().with_forbidden("/repos/acme/demo/actions/permissions/workflow");
    let sa = SecurityAndAnalysis {
        secret_scanning: Some(FeatureStatus {
            status: "enabled".into(),
        }),
        secret_scanning_push_protection: Some(FeatureStatus {
            status: "enabled".into(),
        }),
    };
    let err = RepoContext::fetch(
        &client,
        "acme",
        listing(Some("main"), Some(sa)),
        FilePresence::Absent,
    )
    .await
    .err()
    .expect("expected bail on 403");
    assert!(
        err.to_string().contains("workflow token"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn dependabot_security_updates_enabled_when_endpoint_reports_true() {
    let client = happy_path_client().with_json(
        "/repos/acme/demo/automated-security-fixes",
        json!({ "enabled": true, "paused": false }),
    );
    let sa = SecurityAndAnalysis {
        secret_scanning: Some(FeatureStatus {
            status: "enabled".into(),
        }),
        secret_scanning_push_protection: Some(FeatureStatus {
            status: "enabled".into(),
        }),
    };
    let r = RepoContext::fetch(
        &client,
        "acme",
        listing(Some("main"), Some(sa)),
        FilePresence::Absent,
    )
    .await
    .unwrap();
    assert!(matches!(
        r.dependabot_security_updates,
        FeatureState::Enabled
    ));
}

#[tokio::test]
async fn dependabot_security_updates_disabled_when_endpoint_reports_false() {
    let client = happy_path_client().with_json(
        "/repos/acme/demo/automated-security-fixes",
        json!({ "enabled": false, "paused": false }),
    );
    let sa = SecurityAndAnalysis {
        secret_scanning: Some(FeatureStatus {
            status: "enabled".into(),
        }),
        secret_scanning_push_protection: Some(FeatureStatus {
            status: "enabled".into(),
        }),
    };
    let r = RepoContext::fetch(
        &client,
        "acme",
        listing(Some("main"), Some(sa)),
        FilePresence::Absent,
    )
    .await
    .unwrap();
    assert!(matches!(
        r.dependabot_security_updates,
        FeatureState::Disabled
    ));
}

#[tokio::test]
async fn dependabot_security_updates_disabled_when_endpoint_404() {
    let client = happy_path_client().with_not_found("/repos/acme/demo/automated-security-fixes");
    let sa = SecurityAndAnalysis {
        secret_scanning: Some(FeatureStatus {
            status: "enabled".into(),
        }),
        secret_scanning_push_protection: Some(FeatureStatus {
            status: "enabled".into(),
        }),
    };
    let r = RepoContext::fetch(
        &client,
        "acme",
        listing(Some("main"), Some(sa)),
        FilePresence::Absent,
    )
    .await
    .unwrap();
    assert!(matches!(
        r.dependabot_security_updates,
        FeatureState::Disabled
    ));
}

#[tokio::test]
async fn dependabot_security_updates_bails_when_endpoint_forbidden() {
    let client = happy_path_client().with_forbidden("/repos/acme/demo/automated-security-fixes");
    let sa = SecurityAndAnalysis {
        secret_scanning: Some(FeatureStatus {
            status: "enabled".into(),
        }),
        secret_scanning_push_protection: Some(FeatureStatus {
            status: "enabled".into(),
        }),
    };
    let err = RepoContext::fetch(
        &client,
        "acme",
        listing(Some("main"), Some(sa)),
        FilePresence::Absent,
    )
    .await
    .err()
    .expect("expected bail");
    assert!(
        err.to_string().contains("dependabot security updates"),
        "unexpected error: {err}"
    );
}
