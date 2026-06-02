use crate::checks::common::{self, CollaboratorEntry, permission_error};
use crate::config::{Config, InvalidConfigError};
use crate::support::github::{Fetch, Fetch403, GitHubClient};
use crate::support::outcome::CheckOutcome;
use crate::support::workflows::{self, BranchedWorkflows};
use anyhow::Result;
use futures::future::try_join_all;
use serde::Deserialize;

pub use crate::checks::common::{FeatureState, FilePresence, WebhookInfo, WorkflowTokenState};
pub use crate::checks::org_context::ForkPrContributorApprovalState;

#[derive(Clone, Copy)]
pub enum ReleaseImmutabilityRepoState {
    Enabled,
    Disabled,
    PlanGated,
}

#[derive(Clone, Copy)]
pub enum SHAPinningState {
    Enforced,
    NotEnforced,
    PlanGated,
}

async fn traced<F, T>(repo: &str, label: &str, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    common::traced(Some(repo), label, fut).await
}

pub struct RepoContext {
    pub name: String,
    pub archived: bool,
    pub private: bool,
    pub default_branch: Option<String>,
    pub branch_protections: BranchProtections,
    pub workflow_token: WorkflowTokenState,
    pub secret_scanning: FeatureState,
    pub push_protection: FeatureState,
    pub dependabot_alerts: FeatureState,
    pub dependabot_security_updates: FeatureState,
    pub private_vulnerability_reporting: FeatureState,
    pub workflows: BranchedWorkflows,
    pub security_md: FilePresence,
    pub dependabot_config: DependabotConfigState,
    pub webhooks: Vec<WebhookInfo>,
    pub direct_collaborators: Vec<String>,
    pub release_immutability: ReleaseImmutabilityRepoState,
    pub fork_pr_contributor_approval: ForkPrContributorApprovalState,
    pub sha_pinning: SHAPinningState,
    pub codeowners: FilePresence,
    pub config: Config,
}

pub enum BranchProtectionState {
    Protected {
        signed_commits: bool,
        pr_reviews: bool,
        pr_dismiss_stale_reviews: bool,
        pr_require_last_push_approval: bool,
        pr_require_code_owner_review: bool,
        enforce_admins: bool,
        required_linear_history: bool,
        allow_force_pushes: bool,
        allow_deletions: bool,
    },
    Unprotected,
    PlanGated,
}

#[derive(Default)]
pub struct BranchProtections {
    pub branches: Vec<(String, BranchProtectionState)>,
}

impl BranchProtections {
    pub fn from_single(name: impl Into<String>, state: BranchProtectionState) -> Self {
        Self {
            branches: vec![(name.into(), state)],
        }
    }

    pub fn none() -> Self {
        Self {
            branches: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.branches.is_empty()
    }

    pub fn any_plan_gated(&self) -> bool {
        self.branches
            .iter()
            .any(|(_, s)| matches!(s, BranchProtectionState::PlanGated))
    }

    /// Aggregate a per-branch evaluation across all release branches.
    /// `eval` returns Ok(()) for pass, Err(reasons) for fail (reasons are appended
    /// prefixed with the branch name when more than one branch is tracked).
    pub fn aggregate<F>(&self, eval: F) -> CheckOutcome
    where
        F: Fn(&BranchProtectionState) -> BranchEval,
    {
        if self.is_empty() {
            return CheckOutcome::skipped_no_data("—", "repos, no release branches");
        }
        let multi = self.branches.len() > 1;
        let mut failures: Vec<String> = Vec::new();
        let mut failing_branches: Vec<String> = Vec::new();
        let mut any_plan_gated = false;
        let mut any_pass = false;
        for (name, state) in &self.branches {
            match eval(state) {
                BranchEval::Pass => any_pass = true,
                BranchEval::Fail(reasons) => {
                    if !failing_branches.contains(name) {
                        failing_branches.push(name.clone());
                    }
                    if reasons.is_empty() {
                        failures.push(if multi {
                            format!("{name}: ✗")
                        } else {
                            "✗".into()
                        });
                    } else {
                        for r in reasons {
                            failures.push(if multi { format!("{name}: {r}") } else { r });
                        }
                    }
                }
                BranchEval::PlanGated => any_plan_gated = true,
            }
        }
        if !failures.is_empty() {
            let summary = if multi {
                format!("✗ {}", failing_branches.join(", "))
            } else {
                "✗".to_string()
            };
            CheckOutcome::fail(summary).with_items(failures)
        } else if any_pass {
            CheckOutcome::pass("✓")
        } else if any_plan_gated {
            CheckOutcome::skipped_plan_gated("N/A (plan)")
        } else {
            CheckOutcome::pass("✓")
        }
    }

    /// Aggregate a single boolean flag across release branches. `pick` returns
    /// `Some(true)` to pass, `Some(false)` to fail with no detail, and `None`
    /// when the state isn't `Protected` (the helper supplies the standard
    /// mapping for Unprotected/PlanGated).
    pub fn aggregate_flag<F>(&self, pick: F) -> CheckOutcome
    where
        F: Fn(&BranchProtectionState) -> Option<bool>,
    {
        self.aggregate(|state| match pick(state) {
            Some(true) => BranchEval::Pass,
            Some(false) => BranchEval::Fail(Vec::new()),
            None => match state {
                BranchProtectionState::Unprotected => BranchEval::Fail(Vec::new()),
                BranchProtectionState::PlanGated => BranchEval::PlanGated,
                BranchProtectionState::Protected { .. } => unreachable!(),
            },
        })
    }
}

pub enum BranchEval {
    Pass,
    Fail(Vec<String>),
    PlanGated,
}

pub enum DependabotConfigState {
    Ok { github_actions: bool },
    Missing,
}

#[derive(Deserialize, Clone)]
pub struct RepoListing {
    pub name: String,
    pub archived: bool,
    pub fork: bool,
    #[serde(default)]
    pub private: bool,
    pub default_branch: Option<String>,
    pub security_and_analysis: Option<SecurityAndAnalysis>,
    pub permissions: Option<RepoPermissions>,
}

#[derive(Deserialize, Clone)]
pub struct RepoPermissions {
    #[serde(default)]
    pub admin: bool,
    #[serde(default)]
    pub maintain: bool,
}

#[derive(Deserialize, Clone)]
pub struct SecurityAndAnalysis {
    pub secret_scanning: Option<FeatureStatus>,
    pub secret_scanning_push_protection: Option<FeatureStatus>,
}

#[derive(Deserialize, Clone)]
pub struct FeatureStatus {
    pub status: String,
}

#[derive(Deserialize)]
struct BranchProtection {
    required_signatures: Option<EnabledFlag>,
    required_pull_request_reviews: Option<RequiredPullRequestReviews>,
    enforce_admins: Option<EnabledFlag>,
    required_linear_history: Option<EnabledFlag>,
    allow_force_pushes: Option<EnabledFlag>,
    allow_deletions: Option<EnabledFlag>,
}

#[derive(Deserialize, Default)]
struct RequiredPullRequestReviews {
    #[serde(default)]
    required_approving_review_count: Option<u32>,
    #[serde(default)]
    dismiss_stale_reviews: Option<bool>,
    #[serde(default)]
    require_code_owner_reviews: Option<bool>,
    #[serde(default)]
    require_last_push_approval: Option<bool>,
}

#[derive(Deserialize)]
struct EnabledFlag {
    enabled: bool,
}

#[derive(Deserialize)]
struct WorkflowPerms {
    default_workflow_permissions: String,
}

impl RepoContext {
    pub async fn fetch(
        client: &impl GitHubClient,
        org: &str,
        mut repo: RepoListing,
        org_default_security_md: FilePresence,
    ) -> Result<Self> {
        // Forks are filtered out before fetch (see runner::list_repos and
        // org_context::fetch_repo_briefs); if one slips through, refuse to
        // audit it — fork settings are derived from upstream and we can't
        // evaluate them in isolation.
        if repo.fork {
            return Err(anyhow::anyhow!(
                "`{org}/{}` is a fork — Moat does not audit forks (their settings inherit from upstream)",
                repo.name
            ));
        }

        let config = traced(&repo.name, "config", fetch_config(client, org, &repo.name)).await?;

        let mut release_branch_names = compute_release_branches(&repo.default_branch, &config);
        release_branch_names.sort();

        let webhooks_path = format!("/repos/{org}/{}/hooks", repo.name);

        let (
            branches,
            workflow_token,
            dependabot_alerts,
            dependabot_security_updates,
            private_vulnerability_reporting,
            workflows,
            own_security_md,
            dependabot_config,
            webhooks,
            direct_collaborators,
            release_immutability,
            fork_pr_contributor_approval,
            sha_pinning,
            codeowners,
        ) = tokio::try_join!(
            traced(
                &repo.name,
                "branch protections",
                fetch_all_branch_protections(client, org, &repo.name, &release_branch_names),
            ),
            traced(
                &repo.name,
                "workflow token permissions",
                fetch_workflow_token(client, org, &repo.name),
            ),
            traced(
                &repo.name,
                "dependabot alerts",
                fetch_dependabot_alerts(client, org, &repo.name),
            ),
            traced(
                &repo.name,
                "dependabot security updates",
                fetch_dependabot_security_updates(client, org, &repo.name),
            ),
            traced(
                &repo.name,
                "private vulnerability reporting",
                fetch_private_vulnerability_reporting(client, org, &repo.name, repo.private),
            ),
            traced(
                &repo.name,
                "workflows",
                workflows::fetch_workflows_for_branches(
                    client,
                    org,
                    &repo.name,
                    &release_branch_names,
                ),
            ),
            traced(
                &repo.name,
                "SECURITY.md",
                common::locate_security_md(client, org, &repo.name),
            ),
            traced(
                &repo.name,
                "dependabot config",
                fetch_dependabot_config(client, org, &repo.name),
            ),
            traced(
                &repo.name,
                "webhooks",
                common::fetch_webhooks(client, &webhooks_path, org, Some(&repo.name)),
            ),
            traced(
                &repo.name,
                "direct collaborators",
                fetch_direct_collaborators(client, org, &repo.name, repo.private),
            ),
            traced(
                &repo.name,
                "release immutability",
                fetch_release_immutability(client, org, &repo.name),
            ),
            traced(
                &repo.name,
                "fork PR contributor approval",
                fetch_fork_pr_contributor_approval(client, org, &repo.name, repo.private),
            ),
            traced(
                &repo.name,
                "SHA pinning enforcement",
                fetch_sha_pinning(client, org, &repo.name),
            ),
            traced(
                &repo.name,
                "CODEOWNERS",
                common::locate_codeowners(client, org, &repo.name),
            ),
        )?;

        let branch_protections = BranchProtections { branches };

        // A repo with no SECURITY.md of its own inherits the owner's `.github`
        // repository default, which GitHub serves as that repo's security
        // policy. Honour that fallback so an org-wide policy counts as present.
        let security_md = match own_security_md {
            FilePresence::Present => FilePresence::Present,
            FilePresence::Absent => org_default_security_md,
        };

        // List endpoints (`/users/{user}/repos`, `/orgs/{org}/repos`) sometimes
        // omit `security_and_analysis` — it only reliably appears on the repo
        // detail endpoint. Hydrate from the detail endpoint when missing so
        // pick_feature doesn't misreport "missing permission".
        if repo.security_and_analysis.is_none() {
            repo.security_and_analysis =
                hydrate_security_and_analysis(client, org, &repo.name).await?;
        }

        let plan_gated = repo.private && branch_protections.any_plan_gated();
        let secret_scanning = pick_feature(
            &repo,
            |s| &s.secret_scanning,
            plan_gated,
            "secret scanning",
            org,
        )?;
        let push_protection = pick_feature(
            &repo,
            |s| &s.secret_scanning_push_protection,
            plan_gated,
            "secret push protection",
            org,
        )?;

        Ok(Self {
            name: repo.name,
            archived: repo.archived,
            private: repo.private,
            default_branch: repo.default_branch,
            branch_protections,
            workflow_token,
            secret_scanning,
            push_protection,
            dependabot_alerts,
            dependabot_security_updates,
            private_vulnerability_reporting,
            workflows,
            security_md,
            dependabot_config,
            webhooks,
            direct_collaborators,
            release_immutability,
            fork_pr_contributor_approval,
            sha_pinning,
            codeowners,
            config,
        })
    }
}

#[derive(Deserialize)]
struct ImmutableReleasesRepo {
    enabled: bool,
}

async fn fetch_release_immutability(
    client: &impl GitHubClient,
    org: &str,
    repo: &str,
) -> Result<ReleaseImmutabilityRepoState> {
    match client
        .get_json_plan_aware::<ImmutableReleasesRepo>(&format!(
            "/repos/{org}/{repo}/immutable-releases"
        ))
        .await?
    {
        Fetch403::Ok(r) if r.enabled => Ok(ReleaseImmutabilityRepoState::Enabled),
        Fetch403::Ok(_) => Ok(ReleaseImmutabilityRepoState::Disabled),
        Fetch403::PlanGated => Ok(ReleaseImmutabilityRepoState::PlanGated),
        Fetch403::NotFound | Fetch403::Forbidden => Err(permission_error(
            "release immutability setting",
            org,
            Some(repo),
        )),
    }
}

#[derive(Deserialize)]
struct ForkPrApprovalRepo {
    approval_policy: Option<String>,
}

async fn fetch_fork_pr_contributor_approval(
    client: &impl GitHubClient,
    org: &str,
    repo: &str,
    private: bool,
) -> Result<ForkPrContributorApprovalState> {
    // Fork PR approval doesn't apply to private repos — the API returns a 422
    // "Fork PR approval is not allowed for private repositories." Skip the call.
    if private {
        return Ok(ForkPrContributorApprovalState::PlanGated);
    }
    match client
        .get_json_plan_aware::<ForkPrApprovalRepo>(&format!(
            "/repos/{org}/{repo}/actions/permissions/fork-pr-contributor-approval"
        ))
        .await?
    {
        Fetch403::Ok(r) => match r.approval_policy.as_deref() {
            Some("all_external_contributors") => {
                Ok(ForkPrContributorApprovalState::AllExternalContributors)
            }
            Some("first_time_contributors") => {
                Ok(ForkPrContributorApprovalState::FirstTimeContributors)
            }
            Some("first_time_contributors_new_to_github") => {
                Ok(ForkPrContributorApprovalState::FirstTimeContributorsNewToGithub)
            }
            Some(_) => Ok(ForkPrContributorApprovalState::Other),
            None => Err(permission_error(
                "fork PR contributor approval policy",
                org,
                Some(repo),
            )),
        },
        Fetch403::PlanGated => Ok(ForkPrContributorApprovalState::PlanGated),
        Fetch403::NotFound | Fetch403::Forbidden => Err(permission_error(
            "fork PR contributor approval policy",
            org,
            Some(repo),
        )),
    }
}

#[derive(Deserialize)]
struct ActionsPermissions {
    #[serde(default)]
    sha_pinning_required: Option<bool>,
}

async fn fetch_sha_pinning(
    client: &impl GitHubClient,
    org: &str,
    repo: &str,
) -> Result<SHAPinningState> {
    match client
        .get_json_plan_aware::<ActionsPermissions>(&format!(
            "/repos/{org}/{repo}/actions/permissions"
        ))
        .await?
    {
        Fetch403::Ok(p) => match p.sha_pinning_required {
            Some(true) => Ok(SHAPinningState::Enforced),
            Some(false) => Ok(SHAPinningState::NotEnforced),
            None => Err(permission_error(
                "actions SHA pinning setting",
                org,
                Some(repo),
            )),
        },
        Fetch403::PlanGated => Ok(SHAPinningState::PlanGated),
        Fetch403::NotFound | Fetch403::Forbidden => Err(permission_error(
            "actions SHA pinning setting",
            org,
            Some(repo),
        )),
    }
}

async fn fetch_branch_protection(
    client: &impl GitHubClient,
    org: &str,
    repo: &str,
    branch: &str,
) -> Result<BranchProtectionState> {
    let classic_path = format!("/repos/{org}/{repo}/branches/{branch}/protection");
    let (classic, rules) = tokio::try_join!(
        client.get_json_plan_aware::<BranchProtection>(&classic_path),
        fetch_branch_rules(client, org, repo, branch),
    )?;

    Ok(match classic {
        Fetch403::Ok(bp) => {
            let classic_pr = bp.required_pull_request_reviews.as_ref();
            let classic_pr_reviews = classic_pr.is_some_and(|r| {
                r.required_approving_review_count
                    .map(|n| n >= 1)
                    .unwrap_or(true)
            });
            BranchProtectionState::Protected {
                signed_commits: bp.required_signatures.map(|s| s.enabled).unwrap_or(false)
                    || rules.signed_commits,
                pr_reviews: classic_pr_reviews || rules.pr_reviews,
                pr_dismiss_stale_reviews: classic_pr
                    .and_then(|r| r.dismiss_stale_reviews)
                    .unwrap_or(false)
                    || rules.pr_dismiss_stale_reviews,
                pr_require_last_push_approval: classic_pr
                    .and_then(|r| r.require_last_push_approval)
                    .unwrap_or(false)
                    || rules.pr_require_last_push_approval,
                pr_require_code_owner_review: classic_pr
                    .and_then(|r| r.require_code_owner_reviews)
                    .unwrap_or(false)
                    || rules.pr_require_code_owner_review,
                enforce_admins: bp.enforce_admins.map(|e| e.enabled).unwrap_or(false) || rules.any,
                required_linear_history: bp
                    .required_linear_history
                    .map(|e| e.enabled)
                    .unwrap_or(false)
                    || rules.required_linear_history,
                allow_force_pushes: bp.allow_force_pushes.map(|e| e.enabled).unwrap_or(false)
                    && !rules.non_fast_forward,
                allow_deletions: bp.allow_deletions.map(|e| e.enabled).unwrap_or(false)
                    && !rules.deletion,
            }
        }
        Fetch403::NotFound if rules.any => BranchProtectionState::Protected {
            signed_commits: rules.signed_commits,
            pr_reviews: rules.pr_reviews,
            pr_dismiss_stale_reviews: rules.pr_dismiss_stale_reviews,
            pr_require_last_push_approval: rules.pr_require_last_push_approval,
            pr_require_code_owner_review: rules.pr_require_code_owner_review,
            enforce_admins: true,
            required_linear_history: rules.required_linear_history,
            allow_force_pushes: !rules.non_fast_forward,
            allow_deletions: !rules.deletion,
        },
        Fetch403::NotFound => BranchProtectionState::Unprotected,
        Fetch403::Forbidden => {
            return Err(permission_error(
                &format!("branch protection for `{branch}`"),
                org,
                Some(repo),
            ));
        }
        Fetch403::PlanGated => BranchProtectionState::PlanGated,
    })
}

#[derive(Deserialize)]
struct RuleEntry {
    #[serde(rename = "type")]
    rule_type: String,
    #[serde(default)]
    parameters: Option<RulePullRequestParams>,
}

#[derive(Deserialize, Default)]
struct RulePullRequestParams {
    #[serde(default)]
    required_approving_review_count: Option<u32>,
    #[serde(default)]
    dismiss_stale_reviews_on_push: Option<bool>,
    #[serde(default)]
    require_last_push_approval: Option<bool>,
    #[serde(default)]
    require_code_owner_review: Option<bool>,
}

#[derive(Default)]
struct RulesetFlags {
    any: bool,
    signed_commits: bool,
    pr_reviews: bool,
    pr_dismiss_stale_reviews: bool,
    pr_require_last_push_approval: bool,
    pr_require_code_owner_review: bool,
    required_linear_history: bool,
    non_fast_forward: bool,
    deletion: bool,
}

async fn fetch_branch_rules(
    client: &impl GitHubClient,
    org: &str,
    repo: &str,
    branch: &str,
) -> Result<RulesetFlags> {
    let path = format!("/repos/{org}/{repo}/rules/branches/{branch}");
    let entries = match client.get_json_plan_aware::<Vec<RuleEntry>>(&path).await? {
        Fetch403::Ok(v) => v,
        // Private repos on Free plan return 403 "Upgrade to GitHub Pro" — plan gate, not perms.
        Fetch403::PlanGated => return Ok(RulesetFlags::default()),
        Fetch403::NotFound => return Ok(RulesetFlags::default()),
        Fetch403::Forbidden => {
            return Err(permission_error(
                &format!("branch rules for `{branch}`"),
                org,
                Some(repo),
            ));
        }
    };
    let mut flags = RulesetFlags::default();
    for entry in entries {
        flags.any = true;
        match entry.rule_type.as_str() {
            "required_signatures" => flags.signed_commits = true,
            "pull_request" => {
                let params = entry.parameters.unwrap_or_default();
                let count = params.required_approving_review_count.unwrap_or(0);
                if count >= 1 {
                    flags.pr_reviews = true;
                }
                if params.dismiss_stale_reviews_on_push.unwrap_or(false) {
                    flags.pr_dismiss_stale_reviews = true;
                }
                if params.require_last_push_approval.unwrap_or(false) {
                    flags.pr_require_last_push_approval = true;
                }
                if params.require_code_owner_review.unwrap_or(false) {
                    flags.pr_require_code_owner_review = true;
                }
            }
            "required_linear_history" => flags.required_linear_history = true,
            "non_fast_forward" => flags.non_fast_forward = true,
            "deletion" => flags.deletion = true,
            _ => {}
        }
    }
    Ok(flags)
}

fn compute_release_branches(default_branch: &Option<String>, config: &Config) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    if let Some(b) = default_branch
        && seen.insert(b.clone())
    {
        out.push(b.clone());
    }

    for b in config.release_branches() {
        if seen.insert(b.clone()) {
            out.push(b.clone());
        }
    }

    out
}

async fn fetch_all_branch_protections(
    client: &impl GitHubClient,
    org: &str,
    repo: &str,
    branches: &[String],
) -> Result<Vec<(String, BranchProtectionState)>> {
    try_join_all(branches.iter().map(|branch| async move {
        let state = fetch_branch_protection(client, org, repo, branch).await?;
        Ok::<_, anyhow::Error>((branch.clone(), state))
    }))
    .await
}

async fn fetch_workflow_token(
    client: &impl GitHubClient,
    org: &str,
    repo: &str,
) -> Result<WorkflowTokenState> {
    match client
        .get_json::<WorkflowPerms>(&format!("/repos/{org}/{repo}/actions/permissions/workflow"))
        .await?
    {
        Fetch::Ok(w) if w.default_workflow_permissions == "read" => Ok(WorkflowTokenState::Read),
        Fetch::Ok(_) => Ok(WorkflowTokenState::Write),
        Fetch::NotFound | Fetch::Forbidden => Err(permission_error(
            "workflow token permissions",
            org,
            Some(repo),
        )),
    }
}

async fn fetch_dependabot_alerts(
    client: &impl GitHubClient,
    org: &str,
    repo: &str,
) -> Result<FeatureState> {
    match client
        .get_presence_plan_aware(&format!("/repos/{org}/{repo}/vulnerability-alerts"))
        .await?
    {
        Fetch403::Ok(_) => Ok(FeatureState::Enabled),
        Fetch403::NotFound => Ok(FeatureState::Disabled),
        Fetch403::PlanGated => Ok(FeatureState::PlanGated),
        Fetch403::Forbidden => Err(permission_error("dependabot alerts", org, Some(repo))),
    }
}

#[derive(Deserialize)]
struct AutomatedSecurityFixes {
    enabled: bool,
}

async fn fetch_dependabot_security_updates(
    client: &impl GitHubClient,
    org: &str,
    repo: &str,
) -> Result<FeatureState> {
    match client
        .get_json_plan_aware::<AutomatedSecurityFixes>(&format!(
            "/repos/{org}/{repo}/automated-security-fixes"
        ))
        .await?
    {
        Fetch403::Ok(r) if r.enabled => Ok(FeatureState::Enabled),
        Fetch403::Ok(_) => Ok(FeatureState::Disabled),
        Fetch403::NotFound => Ok(FeatureState::Disabled),
        Fetch403::PlanGated => Ok(FeatureState::PlanGated),
        Fetch403::Forbidden => Err(permission_error(
            "dependabot security updates",
            org,
            Some(repo),
        )),
    }
}

#[derive(Deserialize)]
struct PrivateVulnReporting {
    enabled: bool,
}

async fn fetch_private_vulnerability_reporting(
    client: &impl GitHubClient,
    org: &str,
    repo: &str,
    private: bool,
) -> Result<FeatureState> {
    // Private repos can't accept private vuln reports — leave this as a benign
    // PlanGated which `applies_to_repo: public_only` already filters out.
    if private {
        return Ok(FeatureState::PlanGated);
    }
    match client
        .get_json_plan_aware::<PrivateVulnReporting>(&format!(
            "/repos/{org}/{repo}/private-vulnerability-reporting"
        ))
        .await?
    {
        Fetch403::Ok(p) if p.enabled => Ok(FeatureState::Enabled),
        Fetch403::Ok(_) => Ok(FeatureState::Disabled),
        Fetch403::NotFound => Ok(FeatureState::Disabled),
        Fetch403::PlanGated => Ok(FeatureState::PlanGated),
        Fetch403::Forbidden => Err(permission_error(
            "private vulnerability reporting",
            org,
            Some(repo),
        )),
    }
}

async fn fetch_config(client: &impl GitHubClient, org: &str, repo: &str) -> Result<Config> {
    match client
        .get_raw(&format!(
            "/repos/{org}/{repo}/contents/{}",
            crate::config::FILE_NAME
        ))
        .await?
    {
        Fetch::Ok(text) => {
            let known = crate::checks::known_check_ids();
            Config::parse(&text, &known).map_err(|source| {
                anyhow::Error::new(InvalidConfigError {
                    org_repo: format!("{org}/{repo}"),
                    source,
                })
            })
        }
        Fetch::NotFound | Fetch::Forbidden => Ok(Config::default()),
    }
}

fn pick_feature(
    repo: &RepoListing,
    pick: impl Fn(&SecurityAndAnalysis) -> &Option<FeatureStatus>,
    plan_gated: bool,
    resource: &str,
    org: &str,
) -> Result<FeatureState> {
    let Some(sa) = &repo.security_and_analysis else {
        return if plan_gated {
            Ok(FeatureState::PlanGated)
        } else {
            Err(permission_error(resource, org, Some(&repo.name)))
        };
    };
    Ok(match pick(sa) {
        Some(f) if f.status == "enabled" => FeatureState::Enabled,
        Some(_) if plan_gated => FeatureState::PlanGated,
        Some(_) => FeatureState::Disabled,
        None if plan_gated => FeatureState::PlanGated,
        None => return Err(permission_error(resource, org, Some(&repo.name))),
    })
}

#[derive(Deserialize)]
struct RepoDetail {
    security_and_analysis: Option<SecurityAndAnalysis>,
}

async fn hydrate_security_and_analysis(
    client: &impl GitHubClient,
    org: &str,
    repo: &str,
) -> Result<Option<SecurityAndAnalysis>> {
    match client
        .get_json::<RepoDetail>(&format!("/repos/{org}/{repo}"))
        .await?
    {
        Fetch::Ok(d) => Ok(d.security_and_analysis),
        Fetch::Forbidden | Fetch::NotFound => Ok(None),
    }
}

async fn fetch_dependabot_config(
    client: &impl GitHubClient,
    org: &str,
    repo: &str,
) -> Result<DependabotConfigState> {
    for path in [".github/dependabot.yml", ".github/dependabot.yaml"] {
        match client
            .get_raw(&format!("/repos/{org}/{repo}/contents/{path}"))
            .await?
        {
            Fetch::Ok(text) => {
                let github_actions = parse_has_github_actions(&text);
                return Ok(DependabotConfigState::Ok { github_actions });
            }
            Fetch::Forbidden => return Err(permission_error("dependabot config", org, Some(repo))),
            Fetch::NotFound => {}
        }
    }
    Ok(DependabotConfigState::Missing)
}

fn parse_has_github_actions(text: &str) -> bool {
    #[derive(Deserialize)]
    struct DependabotFile {
        #[serde(default)]
        updates: Vec<UpdateEntry>,
    }
    #[derive(Deserialize)]
    struct UpdateEntry {
        #[serde(rename = "package-ecosystem", default)]
        package_ecosystem: String,
    }
    serde_yaml::from_str::<DependabotFile>(text)
        .map(|f| {
            f.updates
                .iter()
                .any(|u| u.package_ecosystem == "github-actions")
        })
        .unwrap_or(false)
}

async fn fetch_direct_collaborators(
    client: &impl GitHubClient,
    org: &str,
    repo: &str,
    private: bool,
) -> Result<Vec<String>> {
    match client
        .get_paginated::<CollaboratorEntry>(&format!(
            "/repos/{org}/{repo}/collaborators?affiliation=direct"
        ))
        .await?
    {
        Fetch::Ok(v) => Ok(v
            .into_iter()
            .filter(|c| private || c.permissions.is_more_than_read())
            .map(|c| c.login)
            .collect()),
        Fetch::Forbidden | Fetch::NotFound => {
            Err(permission_error("direct collaborators", org, Some(repo)))
        }
    }
}
