use crate::checks::common::{self, CollaboratorEntry, WebhookInfo, permission_error};
use crate::support::github::{Fetch, Fetch403, GitHubClient};
use crate::support::outcome::CheckOutcome;
use anyhow::Result;
use futures::future::try_join_all;
use futures::stream::{self, StreamExt};
use serde::Deserialize;
use std::collections::BTreeMap;

pub use crate::checks::common::{FeatureState, WorkflowTokenState};

const COLLABORATOR_CONCURRENCY: usize = 12;

async fn traced<F, T>(label: &str, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    common::traced(None, label, fut).await
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OrgPlan {
    Free,
    Team,
    Enterprise,
    Other,
}

pub struct OrgContext {
    pub plan: OrgPlan,
    pub two_factor_required: TwoFactorState,
    pub members_without_2fa: Vec<String>,
    pub outside_collaborators: Vec<String>,
    pub admins: Vec<String>,
    pub default_repository_permission: DefaultRepoPermissionState,
    pub release_immutability: ReleaseImmutabilityState,
    pub fork_pr_contributor_approval: ForkPrContributorApprovalState,
    pub workflow_token: WorkflowTokenState,
    pub secret_scanning_default: FeatureDefaultState,
    pub push_protection_default: FeatureDefaultState,
    pub dependabot_alerts_default: FeatureDefaultState,
    pub dependabot_security_updates_default: FeatureDefaultState,
    pub webhooks: Vec<WebhookInfo>,
    pub private_vulnerability_reporting: FeatureDefaultState,
    pub rulesets: OrgRulesets,
}

pub struct OrgRulesets {
    pub any_active: bool,
    pub required_signatures: bool,
    pub pull_request: bool,
    pub pr_dismiss_stale_reviews: bool,
    pub pr_require_last_push_approval: bool,
    pub pr_require_code_owner_review: bool,
    pub required_linear_history: bool,
    pub non_fast_forward: bool,
    pub deletion: bool,
    pub has_bypass_actors: bool,
}

impl OrgRulesets {
    pub fn empty() -> Self {
        Self {
            any_active: false,
            required_signatures: false,
            pull_request: false,
            pr_dismiss_stale_reviews: false,
            pr_require_last_push_approval: false,
            pr_require_code_owner_review: false,
            required_linear_history: false,
            non_fast_forward: false,
            deletion: false,
            has_bypass_actors: false,
        }
    }
}

#[derive(Clone, Copy)]
pub enum FeatureDefaultState {
    Enabled,
    Disabled,
    NotSet,
}

impl FeatureDefaultState {
    pub fn to_outcome(&self) -> CheckOutcome {
        match self {
            Self::Enabled => CheckOutcome::pass("Enabled by default for new repositories"),
            Self::Disabled => CheckOutcome::fail("Disabled by default for new repositories"),
            Self::NotSet => {
                CheckOutcome::warn("No default security configuration set for new repositories")
            }
        }
    }
}

#[derive(Clone, Copy)]
pub enum ForkPrContributorApprovalState {
    AllExternalContributors,
    FirstTimeContributors,
    FirstTimeContributorsNewToGithub,
    Other,
    PlanGated,
}

#[derive(Clone, Copy)]
pub enum TwoFactorState {
    Required,
    NotRequired,
}

#[derive(Clone, Copy)]
pub enum ReleaseImmutabilityState {
    All,
    Selected,
    None,
}

pub enum DefaultRepoPermissionState {
    None,
    Read,
    Write,
    Admin,
    Other(String),
}

#[derive(Deserialize)]
struct OrgResponse {
    two_factor_requirement_enabled: Option<bool>,
    default_repository_permission: Option<String>,
    plan: Option<OrgPlanResponse>,
}

#[derive(Deserialize)]
struct OrgPlanResponse {
    name: Option<String>,
}

#[derive(Deserialize)]
struct ImmutableReleasesResponse {
    enforced_repositories: Option<String>,
}

#[derive(Deserialize)]
struct ForkPrContributorApprovalResponse {
    approval_policy: Option<String>,
}

#[derive(Deserialize)]
struct WorkflowPermsResponse {
    default_workflow_permissions: Option<String>,
}

#[derive(Deserialize)]
struct SecurityConfigDefault {
    default_for_new_repos: Option<String>,
    configuration: Option<SecurityConfigInner>,
}

#[derive(Deserialize)]
struct SecurityConfigInner {
    secret_scanning: Option<String>,
    secret_scanning_push_protection: Option<String>,
    dependabot_alerts: Option<String>,
    dependabot_security_updates: Option<String>,
    private_vulnerability_reporting: Option<String>,
}

#[derive(Deserialize)]
struct User {
    login: String,
}

impl OrgContext {
    pub async fn fetch(client: &impl GitHubClient, org: &str) -> Result<Self> {
        let org_path = format!("/orgs/{org}");
        let immut_path = format!("/orgs/{org}/settings/immutable-releases");
        let fork_pr_path = format!("/orgs/{org}/actions/permissions/fork-pr-contributor-approval");
        let wf_perms_path = format!("/orgs/{org}/actions/permissions/workflow");
        let sec_defaults_path = format!("/orgs/{org}/code-security/configurations/defaults");
        let members_2fa_path = format!("/orgs/{org}/members?filter=2fa_disabled");
        let admins_path = format!("/orgs/{org}/members?role=admin");
        let hooks_path = format!("/orgs/{org}/hooks");

        let (
            org_resp,
            immut_resp,
            fork_pr_resp,
            wf_perms_resp,
            sec_defaults_resp,
            members_without_2fa,
            outside_collaborators,
            admins,
            webhooks,
            rulesets,
        ) = tokio::try_join!(
            traced(
                "organization settings",
                client.get_json::<OrgResponse>(&org_path),
            ),
            traced(
                "release immutability policy",
                client.get_json::<ImmutableReleasesResponse>(&immut_path),
            ),
            traced(
                "fork PR contributor approval policy",
                client.get_json::<ForkPrContributorApprovalResponse>(&fork_pr_path),
            ),
            traced(
                "default workflow token permissions",
                client.get_json::<WorkflowPermsResponse>(&wf_perms_path),
            ),
            traced(
                "default code security configuration",
                client.get_json::<Vec<SecurityConfigDefault>>(&sec_defaults_path),
            ),
            traced(
                "members without 2FA",
                fetch_logins(client, &members_2fa_path, org, "members without 2FA"),
            ),
            traced(
                "outside collaborators",
                fetch_outside_collaborators(client, org),
            ),
            traced(
                "organization admins",
                fetch_logins(client, &admins_path, org, "organization admins"),
            ),
            traced(
                "organization webhooks",
                common::fetch_webhooks(client, &hooks_path, org, None),
            ),
            traced("organization rulesets", fetch_org_rulesets(client, org)),
        )?;

        let (two_factor_required, default_repository_permission, plan) = match org_resp {
            Fetch::Ok(o) => {
                let tfa = match o.two_factor_requirement_enabled {
                    Some(true) => TwoFactorState::Required,
                    Some(false) => TwoFactorState::NotRequired,
                    None => return Err(permission_error("organization 2FA policy", org, None)),
                };
                let perm = match o.default_repository_permission.as_deref() {
                    Some("none") => DefaultRepoPermissionState::None,
                    Some("read") => DefaultRepoPermissionState::Read,
                    Some("write") => DefaultRepoPermissionState::Write,
                    Some("admin") => DefaultRepoPermissionState::Admin,
                    Some(other) => DefaultRepoPermissionState::Other(other.to_string()),
                    None => {
                        return Err(permission_error(
                            "organization default repository permission",
                            org,
                            None,
                        ));
                    }
                };
                let plan = match o.plan.as_ref().and_then(|p| p.name.as_deref()) {
                    Some("free") => OrgPlan::Free,
                    Some("team") => OrgPlan::Team,
                    Some("enterprise") | Some("business") | Some("business_plus") => {
                        OrgPlan::Enterprise
                    }
                    Some(_) => OrgPlan::Other,
                    None => return Err(permission_error("organization plan", org, None)),
                };
                (tfa, perm, plan)
            }
            Fetch::NotFound | Fetch::Forbidden => {
                return Err(permission_error("organization settings", org, None));
            }
        };

        let release_immutability = match immut_resp {
            Fetch::Ok(r) => match r.enforced_repositories.as_deref() {
                Some("all") => ReleaseImmutabilityState::All,
                Some("selected") => ReleaseImmutabilityState::Selected,
                Some("none") => ReleaseImmutabilityState::None,
                _ => return Err(permission_error("release immutability policy", org, None)),
            },
            Fetch::NotFound | Fetch::Forbidden => {
                return Err(permission_error("release immutability policy", org, None));
            }
        };

        let fork_pr_contributor_approval = match fork_pr_resp {
            Fetch::Ok(r) => match r.approval_policy.as_deref() {
                Some("all_external_contributors") => {
                    ForkPrContributorApprovalState::AllExternalContributors
                }
                Some("first_time_contributors") => {
                    ForkPrContributorApprovalState::FirstTimeContributors
                }
                Some("first_time_contributors_new_to_github") => {
                    ForkPrContributorApprovalState::FirstTimeContributorsNewToGithub
                }
                Some(_) => ForkPrContributorApprovalState::Other,
                None => {
                    return Err(permission_error(
                        "fork PR contributor approval policy",
                        org,
                        None,
                    ));
                }
            },
            Fetch::NotFound | Fetch::Forbidden => {
                return Err(permission_error(
                    "fork PR contributor approval policy",
                    org,
                    None,
                ));
            }
        };

        let workflow_token = match wf_perms_resp {
            Fetch::Ok(w) => match w.default_workflow_permissions.as_deref() {
                Some("read") => WorkflowTokenState::Read,
                Some(_) => WorkflowTokenState::Write,
                None => {
                    return Err(permission_error(
                        "default workflow token permissions",
                        org,
                        None,
                    ));
                }
            },
            Fetch::NotFound | Fetch::Forbidden => {
                return Err(permission_error(
                    "default workflow token permissions",
                    org,
                    None,
                ));
            }
        };

        let (
            secret_scanning_default,
            push_protection_default,
            dependabot_alerts_default,
            dependabot_security_updates_default,
            private_vulnerability_reporting,
        ) = match sec_defaults_resp {
            Fetch::Ok(defaults) => {
                let chosen = defaults
                    .into_iter()
                    .find(|d| {
                        d.default_for_new_repos
                            .as_deref()
                            .is_some_and(|v| v != "none")
                    })
                    .and_then(|d| d.configuration);
                match chosen {
                    Some(c) => (
                        feature_default(
                            c.secret_scanning.as_deref(),
                            org,
                            "default secret scanning policy",
                        )?,
                        feature_default(
                            c.secret_scanning_push_protection.as_deref(),
                            org,
                            "default secret push protection policy",
                        )?,
                        feature_default(
                            c.dependabot_alerts.as_deref(),
                            org,
                            "default dependabot alerts policy",
                        )?,
                        feature_default(
                            c.dependabot_security_updates.as_deref(),
                            org,
                            "default dependabot security updates policy",
                        )?,
                        feature_default(
                            c.private_vulnerability_reporting.as_deref(),
                            org,
                            "default private vulnerability reporting policy",
                        )?,
                    ),
                    None => (
                        FeatureDefaultState::NotSet,
                        FeatureDefaultState::NotSet,
                        FeatureDefaultState::NotSet,
                        FeatureDefaultState::NotSet,
                        FeatureDefaultState::NotSet,
                    ),
                }
            }
            Fetch::NotFound | Fetch::Forbidden => {
                return Err(permission_error(
                    "default code security configuration",
                    org,
                    None,
                ));
            }
        };

        Ok(Self {
            plan,
            two_factor_required,
            members_without_2fa,
            outside_collaborators,
            admins,
            default_repository_permission,
            release_immutability,
            fork_pr_contributor_approval,
            workflow_token,
            secret_scanning_default,
            push_protection_default,
            dependabot_alerts_default,
            dependabot_security_updates_default,
            webhooks,
            private_vulnerability_reporting,
            rulesets,
        })
    }
}

#[derive(Deserialize)]
struct RulesetSummary {
    id: u64,
    #[serde(default)]
    enforcement: Option<String>,
}

#[derive(Deserialize)]
struct RulesetDetail {
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    conditions: Option<RulesetConditions>,
    #[serde(default)]
    rules: Vec<RulesetRule>,
    #[serde(default)]
    bypass_actors: Vec<BypassActor>,
}

#[derive(Deserialize, Default)]
struct RulesetConditions {
    #[serde(default)]
    ref_name: Option<RefPattern>,
    #[serde(default)]
    repository_name: Option<RefPattern>,
    #[serde(default)]
    repository_id: Option<RepositoryIdCondition>,
}

#[derive(Deserialize, Default)]
struct RefPattern {
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
}

#[derive(Deserialize, Default)]
struct RepositoryIdCondition {
    #[serde(default)]
    repository_ids: Vec<u64>,
}

#[derive(Deserialize)]
struct RulesetRule {
    #[serde(rename = "type")]
    rule_type: String,
    #[serde(default)]
    parameters: Option<RuleParameters>,
}

#[derive(Deserialize, Default)]
struct RuleParameters {
    #[serde(default)]
    required_approving_review_count: Option<u32>,
    #[serde(default)]
    dismiss_stale_reviews_on_push: Option<bool>,
    #[serde(default)]
    require_last_push_approval: Option<bool>,
    #[serde(default)]
    require_code_owner_review: Option<bool>,
}

#[derive(Deserialize)]
struct BypassActor {
    #[serde(default)]
    bypass_mode: Option<String>,
}

fn targets_all_repos(conditions: Option<&RulesetConditions>) -> bool {
    let Some(c) = conditions else {
        return false;
    };
    if c.repository_id
        .as_ref()
        .is_some_and(|r| !r.repository_ids.is_empty())
    {
        return false;
    }
    let Some(name) = c.repository_name.as_ref() else {
        return false;
    };
    name.exclude.is_empty() && name.include.iter().any(|p| p == "~ALL")
}

fn targets_default_or_all_branches(conditions: Option<&RulesetConditions>) -> bool {
    let Some(c) = conditions else {
        return false;
    };
    let Some(r) = c.ref_name.as_ref() else {
        return false;
    };
    r.exclude.is_empty()
        && r.include
            .iter()
            .any(|p| p == "~ALL" || p == "~DEFAULT_BRANCH")
}

pub async fn fetch_org_rulesets(client: &impl GitHubClient, org: &str) -> Result<OrgRulesets> {
    let summaries: Vec<RulesetSummary> = match client
        .get_paginated_plan_aware::<RulesetSummary>(&format!("/orgs/{org}/rulesets"))
        .await?
    {
        Fetch403::Ok(v) => v,
        // GitHub returns 403 with "Upgrade to GitHub Team" on Free plans — that's a plan gate,
        // not a permission issue, so degrade gracefully. A real Forbidden still bails.
        Fetch403::PlanGated => return Ok(OrgRulesets::empty()),
        Fetch403::Forbidden => return Err(permission_error("organization rulesets", org, None)),
        Fetch403::NotFound => return Ok(OrgRulesets::empty()),
    };

    let active: Vec<u64> = summaries
        .into_iter()
        .filter(|s| s.enforcement.as_deref() == Some("active"))
        .map(|s| s.id)
        .collect();

    if active.is_empty() {
        return Ok(OrgRulesets::empty());
    }

    let details: Vec<RulesetDetail> = try_join_all(active.into_iter().map(|id| async move {
        match client
            .get_json::<RulesetDetail>(&format!("/orgs/{org}/rulesets/{id}"))
            .await?
        {
            Fetch::Ok(d) => Ok::<_, anyhow::Error>(d),
            Fetch::NotFound | Fetch::Forbidden => {
                Err(permission_error(&format!("ruleset {id}"), org, None))
            }
        }
    }))
    .await?;

    let mut out = OrgRulesets::empty();
    for detail in details {
        // Only branch rulesets contribute to branch-protection booleans.
        if detail.target.as_deref().unwrap_or("branch") != "branch" {
            continue;
        }
        let all_repos = targets_all_repos(detail.conditions.as_ref());
        let default_or_all_branches = targets_default_or_all_branches(detail.conditions.as_ref());
        // The ruleset must reach every repo's default/release branches before
        // its rules can be claimed as org-wide protection.
        if !(all_repos && default_or_all_branches) {
            continue;
        }

        out.any_active = true;
        if detail.bypass_actors.iter().any(|a| a.bypass_mode.is_some()) {
            out.has_bypass_actors = true;
        }
        for rule in detail.rules {
            match rule.rule_type.as_str() {
                "required_signatures" => out.required_signatures = true,
                "pull_request" => {
                    let params = rule.parameters.as_ref();
                    let count = params
                        .and_then(|p| p.required_approving_review_count)
                        .unwrap_or(0);
                    if count >= 1 {
                        out.pull_request = true;
                    }
                    if params
                        .and_then(|p| p.dismiss_stale_reviews_on_push)
                        .unwrap_or(false)
                    {
                        out.pr_dismiss_stale_reviews = true;
                    }
                    if params
                        .and_then(|p| p.require_last_push_approval)
                        .unwrap_or(false)
                    {
                        out.pr_require_last_push_approval = true;
                    }
                    if params
                        .and_then(|p| p.require_code_owner_review)
                        .unwrap_or(false)
                    {
                        out.pr_require_code_owner_review = true;
                    }
                }
                "required_linear_history" => out.required_linear_history = true,
                "non_fast_forward" => out.non_fast_forward = true,
                "deletion" => out.deletion = true,
                _ => {}
            }
        }
    }
    Ok(out)
}

fn feature_default(value: Option<&str>, org: &str, resource: &str) -> Result<FeatureDefaultState> {
    match value {
        Some("enabled") => Ok(FeatureDefaultState::Enabled),
        Some("disabled") => Ok(FeatureDefaultState::Disabled),
        Some("not_set") | None => Ok(FeatureDefaultState::NotSet),
        Some(_) => Err(permission_error(resource, org, None)),
    }
}

async fn fetch_logins(
    client: &impl GitHubClient,
    path: &str,
    org: &str,
    resource: &str,
) -> Result<Vec<String>> {
    match client.get_paginated::<User>(path).await? {
        Fetch::Ok(users) => Ok(users.into_iter().map(|u| u.login).collect()),
        Fetch::Forbidden => Err(permission_error(resource, org, None)),
        Fetch::NotFound => Ok(Vec::new()),
    }
}

#[derive(Deserialize)]
struct RepoBrief {
    name: String,
    #[serde(default)]
    private: bool,
    #[serde(default)]
    fork: bool,
    #[serde(default)]
    archived: bool,
}

async fn fetch_outside_collaborators(client: &impl GitHubClient, org: &str) -> Result<Vec<String>> {
    let outside_path = format!("/orgs/{org}/outside_collaborators");
    let repos_path = format!("/orgs/{org}/repos?type=all");
    let (all, repos_resp) = tokio::try_join!(
        fetch_logins(client, &outside_path, org, "outside collaborators"),
        client.get_paginated::<RepoBrief>(&repos_path),
    )?;

    if all.is_empty() {
        return Ok(all);
    }
    let logins = all;

    let repos: Vec<RepoBrief> = match repos_resp {
        Fetch::Ok(v) => v
            .into_iter()
            .filter(|r| !r.fork && !r.archived && !common::is_security_advisory_fork(&r.name))
            .collect(),
        Fetch::Forbidden | Fetch::NotFound => {
            return Err(permission_error(
                "repository list for outside collaborator scan",
                org,
                None,
            ));
        }
    };

    let pairs: Vec<(String, String)> = stream::iter(repos)
        .map(|repo| async move {
            let path = format!(
                "/repos/{org}/{}/collaborators?affiliation=outside",
                repo.name
            );
            let collaborators = match client.get_paginated::<CollaboratorEntry>(&path).await {
                Ok(Fetch::Ok(v)) => v,
                Ok(Fetch::Forbidden) | Ok(Fetch::NotFound) => {
                    return Err(permission_error(
                        "outside collaborators",
                        org,
                        Some(&repo.name),
                    ));
                }
                Err(e) => return Err(e),
            };
            Ok(collaborators
                .into_iter()
                .filter(|c| repo.private || c.permissions.is_more_than_read())
                .map(|c| (c.login, repo.name.clone()))
                .collect::<Vec<_>>())
        })
        .buffer_unordered(COLLABORATOR_CONCURRENCY)
        .collect::<Vec<Result<Vec<(String, String)>>>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();

    let mut by_login: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (login, repo) in pairs {
        by_login.entry(login).or_default().push(repo);
    }
    for repos in by_login.values_mut() {
        repos.sort();
        repos.dedup();
    }

    Ok(logins
        .into_iter()
        .filter_map(|l| {
            by_login
                .get(&l)
                .map(|repos| format!("{l} ({})", repos.join(", ")))
        })
        .collect())
}
