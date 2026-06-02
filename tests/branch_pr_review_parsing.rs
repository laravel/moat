use moat::checks::repo_context::{
    BranchProtectionState, FeatureStatus, FilePresence, RepoContext, RepoListing,
    SecurityAndAnalysis,
};
use moat::support::github::FakeGitHubClient;
use serde_json::json;

fn listing() -> RepoListing {
    RepoListing {
        name: "demo".into(),
        archived: false,
        fork: false,
        private: false,
        default_branch: Some("main".into()),
        security_and_analysis: Some(SecurityAndAnalysis {
            secret_scanning: Some(FeatureStatus {
                status: "enabled".into(),
            }),
            secret_scanning_push_protection: Some(FeatureStatus {
                status: "enabled".into(),
            }),
        }),
        permissions: None,
    }
}

/// Seeds every endpoint `RepoContext::fetch` calls so the test can focus on
/// branch-protection parsing without spurious bail-outs from elsewhere.
fn base_client() -> FakeGitHubClient {
    FakeGitHubClient::new()
        .with_status("/repos/acme/demo/contents/.moat.yml", 404)
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
            "/repos/acme/demo/private-vulnerability-reporting",
            json!({ "enabled": true }),
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

fn pr_review_sub_flags(state: &BranchProtectionState) -> (bool, bool, bool, bool) {
    match state {
        BranchProtectionState::Protected {
            pr_reviews,
            pr_dismiss_stale_reviews,
            pr_require_last_push_approval,
            pr_require_code_owner_review,
            ..
        } => (
            *pr_reviews,
            *pr_dismiss_stale_reviews,
            *pr_require_last_push_approval,
            *pr_require_code_owner_review,
        ),
        _ => panic!("expected protected state"),
    }
}

#[tokio::test]
async fn classic_branch_protection_parses_pr_review_sub_flags() {
    let client = base_client().with_json(
        "/repos/acme/demo/branches/main/protection",
        json!({
            "required_pull_request_reviews": {
                "required_approving_review_count": 1,
                "dismiss_stale_reviews": true,
                "require_last_push_approval": true,
                "require_code_owner_reviews": true,
            }
        }),
    );

    let ctx = RepoContext::fetch(&client, "acme", listing(), FilePresence::Absent)
        .await
        .unwrap();
    let (_, state) = &ctx.branch_protections.branches[0];
    assert_eq!(pr_review_sub_flags(state), (true, true, true, true));
}

#[tokio::test]
async fn classic_branch_protection_defaults_pr_sub_flags_to_false() {
    let client = base_client().with_json(
        "/repos/acme/demo/branches/main/protection",
        json!({ "required_pull_request_reviews": {} }),
    );

    let ctx = RepoContext::fetch(&client, "acme", listing(), FilePresence::Absent)
        .await
        .unwrap();
    let (_, state) = &ctx.branch_protections.branches[0];
    // No required_approving_review_count → defaults to "any positive" (true here, count optional).
    // Sub-flags default to false.
    assert_eq!(pr_review_sub_flags(state), (true, false, false, false));
}

#[tokio::test]
async fn classic_branch_protection_pr_reviews_false_when_count_is_zero() {
    let client = base_client().with_json(
        "/repos/acme/demo/branches/main/protection",
        json!({
            "required_pull_request_reviews": { "required_approving_review_count": 0 }
        }),
    );

    let ctx = RepoContext::fetch(&client, "acme", listing(), FilePresence::Absent)
        .await
        .unwrap();
    let (_, state) = &ctx.branch_protections.branches[0];
    let (pr_reviews, _, _, _) = pr_review_sub_flags(state);
    assert!(!pr_reviews);
}

#[tokio::test]
async fn repo_ruleset_parses_pr_review_sub_flags() {
    let client = base_client()
        .with_status("/repos/acme/demo/branches/main/protection", 404)
        .with_json(
            "/repos/acme/demo/rules/branches/main",
            json!([{
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews_on_push": true,
                    "require_last_push_approval": true,
                    "require_code_owner_review": true,
                },
            }]),
        );

    let ctx = RepoContext::fetch(&client, "acme", listing(), FilePresence::Absent)
        .await
        .unwrap();
    let (_, state) = &ctx.branch_protections.branches[0];
    assert_eq!(pr_review_sub_flags(state), (true, true, true, true));
}

#[tokio::test]
async fn repo_ruleset_pr_reviews_false_when_count_is_zero() {
    let client = base_client()
        .with_status("/repos/acme/demo/branches/main/protection", 404)
        .with_json(
            "/repos/acme/demo/rules/branches/main",
            json!([{
                "type": "pull_request",
                "parameters": { "required_approving_review_count": 0 },
            }]),
        );

    let ctx = RepoContext::fetch(&client, "acme", listing(), FilePresence::Absent)
        .await
        .unwrap();
    let (_, state) = &ctx.branch_protections.branches[0];
    let (pr_reviews, _, _, _) = pr_review_sub_flags(state);
    assert!(!pr_reviews);
}

#[tokio::test]
async fn repo_ruleset_pr_sub_flags_default_false_when_parameters_missing() {
    let client = base_client()
        .with_status("/repos/acme/demo/branches/main/protection", 404)
        .with_json(
            "/repos/acme/demo/rules/branches/main",
            json!([{ "type": "pull_request" }]),
        );

    let ctx = RepoContext::fetch(&client, "acme", listing(), FilePresence::Absent)
        .await
        .unwrap();
    let (_, state) = &ctx.branch_protections.branches[0];
    assert_eq!(pr_review_sub_flags(state), (false, false, false, false));
}
