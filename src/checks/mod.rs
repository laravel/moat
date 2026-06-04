pub mod common;
pub mod org_context;
pub mod repo_context;

pub mod organization_members_all_have_two_factor;
pub mod organization_new_members_default_to_no_permissions;
pub mod organization_requires_two_factor;
pub mod repositories_actions_workflow_token_is_read_only;
pub mod repositories_commits_are_signed;
pub mod repositories_dependabot_alerts_are_enabled;
pub mod repositories_dependabot_security_updates_are_enabled;
pub mod repositories_enforce_workflow_actions_sha_pinning;
pub mod repositories_fork_pull_requests_require_approval;
pub mod repositories_have_dependabot_config;
pub mod repositories_have_no_direct_collaborators;
pub mod repositories_have_security_policy;
pub mod repositories_private_vulnerability_reporting_is_enabled;
pub mod repositories_pull_request_target_is_safe;
pub mod repositories_pull_requests_require_reviews;
pub mod repositories_release_branches_are_locked;
pub mod repositories_release_branches_have_linear_history;
pub mod repositories_releases_are_immutable;
pub mod repositories_secret_push_protection_is_enabled;
pub mod repositories_secret_scanning_is_enabled;
pub mod repositories_webhooks_are_secure;
pub mod repositories_workflow_actions_are_sha_pinned;
pub mod repositories_workflow_permissions_are_restricted;

pub use org_context::OrgContext;
pub use repo_context::RepoContext;

use crate::support::outcome::CheckOutcome;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    Org,
    Repo,
    OrgAndRepo,
}

pub struct StateCtx<'a> {
    pub org: Option<&'a OrgContext>,
    pub repos: &'a [&'a RepoContext],
}

pub struct Check {
    pub id: &'static str,
    pub label: &'static str,
    pub how_to_fix: fn(StateCtx<'_>) -> &'static str,
    pub why_enable: &'static str,
    pub org_eval: Option<fn(&OrgContext) -> CheckOutcome>,
    pub repo_eval: Option<fn(&RepoContext) -> CheckOutcome>,
    pub description: fn(StateCtx<'_>) -> Option<String>,
    /// When set, the check is only evaluated on repos where this predicate
    /// returns `true`. Private repos are filtered out for checks that only
    /// make sense in a public-disclosure context.
    pub applies_to_repo: Option<fn(&RepoContext) -> bool>,
    /// When `true`, the check is skipped entirely for non-organization
    /// accounts (User accounts). Use for checks whose premise only makes
    /// sense in an organization context (e.g. "use teams instead").
    pub org_only: bool,
    /// When `true`, this check evaluates org-level rulesets. On the GitHub
    /// Free plan, rulesets are saved but not enforced — the renderer adds a
    /// warning note so users know to upgrade or apply rules per-repo.
    pub ruleset_based: bool,
    /// Optional path suffix appended to `https://github.com/{org}/{repo}` for
    /// each entry in the "Affected repositories" listing. Supports a
    /// `{branch}` placeholder (substituted with the repo's default branch, or
    /// `HEAD` if unknown). `None` links to the repo root.
    pub repo_link_path: Option<&'static str>,
}

impl Check {
    pub fn scope(&self) -> Scope {
        match (self.org_eval.is_some(), self.repo_eval.is_some()) {
            (true, true) => Scope::OrgAndRepo,
            (true, false) => Scope::Org,
            (false, true) => Scope::Repo,
            (false, false) => panic!("check `{}` has no evaluators", self.id),
        }
    }

    /// The label to use for the applicable-repo subset in summaries.
    pub fn repo_noun(&self) -> &'static str {
        "repositories"
    }
}

pub fn public_only(r: &RepoContext) -> bool {
    !r.private
}

pub fn known_check_ids() -> Vec<&'static str> {
    CHECKS.iter().map(|c| c.id).collect()
}

pub static CHECKS: &[Check] = &[
    // ----- Org-only -----
    Check {
        id: "organization_requires_two_factor",
        label: organization_requires_two_factor::LABEL,
        how_to_fix: organization_requires_two_factor::how_to_fix,
        why_enable: organization_requires_two_factor::WHY_ENABLE,
        org_eval: Some(organization_requires_two_factor::org_check),
        repo_eval: None,
        description: organization_requires_two_factor::description,
        applies_to_repo: None,
        org_only: false,
        ruleset_based: false,
        repo_link_path: None,
    },
    Check {
        id: "organization_members_all_have_two_factor",
        label: organization_members_all_have_two_factor::LABEL,
        how_to_fix: organization_members_all_have_two_factor::how_to_fix,
        why_enable: organization_members_all_have_two_factor::WHY_ENABLE,
        org_eval: Some(organization_members_all_have_two_factor::org_check),
        repo_eval: None,
        description: organization_members_all_have_two_factor::description,
        applies_to_repo: None,
        org_only: false,
        ruleset_based: false,
        repo_link_path: None,
    },
    Check {
        id: "organization_new_members_default_to_no_permissions",
        label: organization_new_members_default_to_no_permissions::LABEL,
        how_to_fix: organization_new_members_default_to_no_permissions::how_to_fix,
        why_enable: organization_new_members_default_to_no_permissions::WHY_ENABLE,
        org_eval: Some(organization_new_members_default_to_no_permissions::org_check),
        repo_eval: None,
        description: organization_new_members_default_to_no_permissions::description,
        applies_to_repo: None,
        org_only: false,
        ruleset_based: false,
        repo_link_path: None,
    },
    // ----- Org + Repo (merged) -----
    Check {
        id: "repositories_actions_workflow_token_is_read_only",
        label: repositories_actions_workflow_token_is_read_only::LABEL,
        how_to_fix: repositories_actions_workflow_token_is_read_only::how_to_fix,
        why_enable: repositories_actions_workflow_token_is_read_only::WHY_ENABLE,
        org_eval: Some(repositories_actions_workflow_token_is_read_only::org_check),
        repo_eval: Some(repositories_actions_workflow_token_is_read_only::repo_check),
        description: repositories_actions_workflow_token_is_read_only::description,
        applies_to_repo: None,
        org_only: false,
        ruleset_based: false,
        repo_link_path: None,
    },
    Check {
        id: "repositories_secret_scanning_is_enabled",
        label: repositories_secret_scanning_is_enabled::LABEL,
        how_to_fix: repositories_secret_scanning_is_enabled::how_to_fix,
        why_enable: repositories_secret_scanning_is_enabled::WHY_ENABLE,
        org_eval: Some(repositories_secret_scanning_is_enabled::org_check),
        repo_eval: Some(repositories_secret_scanning_is_enabled::repo_check),
        description: repositories_secret_scanning_is_enabled::description,
        applies_to_repo: None,
        org_only: false,
        ruleset_based: false,
        repo_link_path: None,
    },
    Check {
        id: "repositories_secret_push_protection_is_enabled",
        label: repositories_secret_push_protection_is_enabled::LABEL,
        how_to_fix: repositories_secret_push_protection_is_enabled::how_to_fix,
        why_enable: repositories_secret_push_protection_is_enabled::WHY_ENABLE,
        org_eval: Some(repositories_secret_push_protection_is_enabled::org_check),
        repo_eval: Some(repositories_secret_push_protection_is_enabled::repo_check),
        description: repositories_secret_push_protection_is_enabled::description,
        applies_to_repo: None,
        org_only: false,
        ruleset_based: false,
        repo_link_path: None,
    },
    Check {
        id: "repositories_dependabot_alerts_are_enabled",
        label: repositories_dependabot_alerts_are_enabled::LABEL,
        how_to_fix: repositories_dependabot_alerts_are_enabled::how_to_fix,
        why_enable: repositories_dependabot_alerts_are_enabled::WHY_ENABLE,
        org_eval: Some(repositories_dependabot_alerts_are_enabled::org_check),
        repo_eval: Some(repositories_dependabot_alerts_are_enabled::repo_check),
        description: repositories_dependabot_alerts_are_enabled::description,
        applies_to_repo: None,
        org_only: false,
        ruleset_based: false,
        repo_link_path: None,
    },
    Check {
        id: "repositories_dependabot_security_updates_are_enabled",
        label: repositories_dependabot_security_updates_are_enabled::LABEL,
        how_to_fix: repositories_dependabot_security_updates_are_enabled::how_to_fix,
        why_enable: repositories_dependabot_security_updates_are_enabled::WHY_ENABLE,
        org_eval: Some(repositories_dependabot_security_updates_are_enabled::org_check),
        repo_eval: Some(repositories_dependabot_security_updates_are_enabled::repo_check),
        description: repositories_dependabot_security_updates_are_enabled::description,
        applies_to_repo: None,
        org_only: false,
        ruleset_based: false,
        repo_link_path: None,
    },
    Check {
        id: "repositories_releases_are_immutable",
        label: repositories_releases_are_immutable::LABEL,
        how_to_fix: repositories_releases_are_immutable::how_to_fix,
        why_enable: repositories_releases_are_immutable::WHY_ENABLE,
        org_eval: Some(repositories_releases_are_immutable::org_check),
        repo_eval: Some(repositories_releases_are_immutable::repo_check),
        description: repositories_releases_are_immutable::description,
        applies_to_repo: None,
        org_only: false,
        ruleset_based: false,
        repo_link_path: None,
    },
    Check {
        id: "repositories_fork_pull_requests_require_approval",
        label: repositories_fork_pull_requests_require_approval::LABEL,
        how_to_fix: repositories_fork_pull_requests_require_approval::how_to_fix,
        why_enable: repositories_fork_pull_requests_require_approval::WHY_ENABLE,
        org_eval: Some(repositories_fork_pull_requests_require_approval::org_check),
        repo_eval: Some(repositories_fork_pull_requests_require_approval::repo_check),
        description: repositories_fork_pull_requests_require_approval::description,
        applies_to_repo: Some(public_only),
        org_only: false,
        ruleset_based: false,
        repo_link_path: Some("/settings/actions"),
    },
    Check {
        id: "repositories_commits_are_signed",
        label: repositories_commits_are_signed::LABEL,
        how_to_fix: repositories_commits_are_signed::how_to_fix,
        why_enable: repositories_commits_are_signed::WHY_ENABLE,
        org_eval: Some(repositories_commits_are_signed::org_check),
        repo_eval: Some(repositories_commits_are_signed::repo_check),
        description: repositories_commits_are_signed::description,
        applies_to_repo: None,
        org_only: false,
        ruleset_based: true,
        repo_link_path: None,
    },
    Check {
        id: "repositories_pull_requests_require_reviews",
        label: repositories_pull_requests_require_reviews::LABEL,
        how_to_fix: repositories_pull_requests_require_reviews::how_to_fix,
        why_enable: repositories_pull_requests_require_reviews::WHY_ENABLE,
        org_eval: Some(repositories_pull_requests_require_reviews::org_check),
        repo_eval: Some(repositories_pull_requests_require_reviews::repo_check),
        description: repositories_pull_requests_require_reviews::description,
        applies_to_repo: None,
        org_only: false,
        ruleset_based: true,
        repo_link_path: None,
    },
    Check {
        id: "repositories_release_branches_are_locked",
        label: repositories_release_branches_are_locked::LABEL,
        how_to_fix: repositories_release_branches_are_locked::how_to_fix,
        why_enable: repositories_release_branches_are_locked::WHY_ENABLE,
        org_eval: Some(repositories_release_branches_are_locked::org_check),
        repo_eval: Some(repositories_release_branches_are_locked::repo_check),
        description: repositories_release_branches_are_locked::description,
        applies_to_repo: None,
        org_only: false,
        ruleset_based: true,
        repo_link_path: None,
    },
    Check {
        id: "repositories_release_branches_have_linear_history",
        label: repositories_release_branches_have_linear_history::LABEL,
        how_to_fix: repositories_release_branches_have_linear_history::how_to_fix,
        why_enable: repositories_release_branches_have_linear_history::WHY_ENABLE,
        org_eval: Some(repositories_release_branches_have_linear_history::org_check),
        repo_eval: Some(repositories_release_branches_have_linear_history::repo_check),
        description: repositories_release_branches_have_linear_history::description,
        applies_to_repo: None,
        org_only: false,
        ruleset_based: true,
        repo_link_path: None,
    },
    Check {
        id: "repositories_webhooks_are_secure",
        label: repositories_webhooks_are_secure::LABEL,
        how_to_fix: repositories_webhooks_are_secure::how_to_fix,
        why_enable: repositories_webhooks_are_secure::WHY_ENABLE,
        org_eval: Some(repositories_webhooks_are_secure::org_check),
        repo_eval: Some(repositories_webhooks_are_secure::repo_check),
        description: repositories_webhooks_are_secure::description,
        applies_to_repo: None,
        org_only: false,
        ruleset_based: false,
        repo_link_path: None,
    },
    Check {
        id: "repositories_have_no_direct_collaborators",
        label: repositories_have_no_direct_collaborators::LABEL,
        how_to_fix: repositories_have_no_direct_collaborators::how_to_fix,
        why_enable: repositories_have_no_direct_collaborators::WHY_ENABLE,
        org_eval: Some(repositories_have_no_direct_collaborators::org_check),
        repo_eval: Some(repositories_have_no_direct_collaborators::repo_check),
        description: repositories_have_no_direct_collaborators::description,
        applies_to_repo: None,
        org_only: true,
        ruleset_based: false,
        repo_link_path: Some("/settings/access"),
    },
    Check {
        id: "repositories_private_vulnerability_reporting_is_enabled",
        label: repositories_private_vulnerability_reporting_is_enabled::LABEL,
        how_to_fix: repositories_private_vulnerability_reporting_is_enabled::how_to_fix,
        why_enable: repositories_private_vulnerability_reporting_is_enabled::WHY_ENABLE,
        org_eval: Some(repositories_private_vulnerability_reporting_is_enabled::org_check),
        repo_eval: Some(repositories_private_vulnerability_reporting_is_enabled::repo_check),
        description: repositories_private_vulnerability_reporting_is_enabled::description,
        applies_to_repo: Some(public_only),
        org_only: false,
        ruleset_based: false,
        repo_link_path: None,
    },
    // ----- Repo-only -----
    Check {
        id: "repositories_have_security_policy",
        label: repositories_have_security_policy::LABEL,
        how_to_fix: repositories_have_security_policy::how_to_fix,
        why_enable: repositories_have_security_policy::WHY_ENABLE,
        org_eval: None,
        repo_eval: Some(repositories_have_security_policy::repo_check),
        description: repositories_have_security_policy::description,
        applies_to_repo: Some(public_only),
        org_only: false,
        ruleset_based: false,
        repo_link_path: Some("/security/policy"),
    },
    Check {
        id: "repositories_workflow_actions_are_sha_pinned",
        label: repositories_workflow_actions_are_sha_pinned::LABEL,
        how_to_fix: repositories_workflow_actions_are_sha_pinned::how_to_fix,
        why_enable: repositories_workflow_actions_are_sha_pinned::WHY_ENABLE,
        org_eval: None,
        repo_eval: Some(repositories_workflow_actions_are_sha_pinned::repo_check),
        description: repositories_workflow_actions_are_sha_pinned::description,
        applies_to_repo: None,
        org_only: false,
        ruleset_based: false,
        repo_link_path: Some("/tree/{branch}/.github/workflows"),
    },
    Check {
        id: "repositories_enforce_workflow_actions_sha_pinning",
        label: repositories_enforce_workflow_actions_sha_pinning::LABEL,
        how_to_fix: repositories_enforce_workflow_actions_sha_pinning::how_to_fix,
        why_enable: repositories_enforce_workflow_actions_sha_pinning::WHY_ENABLE,
        org_eval: None,
        repo_eval: Some(repositories_enforce_workflow_actions_sha_pinning::repo_check),
        description: repositories_enforce_workflow_actions_sha_pinning::description,
        applies_to_repo: None,
        org_only: false,
        ruleset_based: false,
        repo_link_path: Some("/settings/actions"),
    },
    Check {
        id: "repositories_pull_request_target_is_safe",
        label: repositories_pull_request_target_is_safe::LABEL,
        how_to_fix: repositories_pull_request_target_is_safe::how_to_fix,
        why_enable: repositories_pull_request_target_is_safe::WHY_ENABLE,
        org_eval: None,
        repo_eval: Some(repositories_pull_request_target_is_safe::repo_check),
        description: repositories_pull_request_target_is_safe::description,
        applies_to_repo: Some(public_only),
        org_only: false,
        ruleset_based: false,
        repo_link_path: Some("/tree/{branch}/.github/workflows"),
    },
    Check {
        id: "repositories_workflow_permissions_are_restricted",
        label: repositories_workflow_permissions_are_restricted::LABEL,
        how_to_fix: repositories_workflow_permissions_are_restricted::how_to_fix,
        why_enable: repositories_workflow_permissions_are_restricted::WHY_ENABLE,
        org_eval: None,
        repo_eval: Some(repositories_workflow_permissions_are_restricted::repo_check),
        description: repositories_workflow_permissions_are_restricted::description,
        applies_to_repo: None,
        org_only: false,
        ruleset_based: false,
        repo_link_path: Some("/tree/{branch}/.github/workflows"),
    },
    Check {
        id: "repositories_have_dependabot_config",
        label: repositories_have_dependabot_config::LABEL,
        how_to_fix: repositories_have_dependabot_config::how_to_fix,
        why_enable: repositories_have_dependabot_config::WHY_ENABLE,
        org_eval: None,
        repo_eval: Some(repositories_have_dependabot_config::repo_check),
        description: repositories_have_dependabot_config::description,
        applies_to_repo: None,
        org_only: false,
        ruleset_based: false,
        repo_link_path: Some("/new/{branch}?filename=.github%2Fdependabot.yml"),
    },
];
