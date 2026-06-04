use crate::checks::StateCtx;
use crate::checks::common::repos_word;
use crate::checks::repo_context::{RepoContext, SHAPinningState};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories enforce workflow actions SHA pinning";
pub const HOW_TO_FIX: &str = "https://github.com/organizations/{org}/settings/actions > General actions permissions > *Check* -> Require actions to be pinned to a full-length commit SHA > *Click* -> Save";
pub const WHY_ENABLE: &str = "Pinning `uses:` refs by hand isn't enough — anyone can later reintroduce a mutable `@v1` tag. The repo-level \"Require actions to be pinned\" setting prevents that: enforcement happens at workflow run time, so a workflow with an unpinned `uses:` ref fails to start until the ref is pinned. Pair it with `repositories_workflow_actions_are_sha_pinned`, which flags the refs that are unpinned today.";

pub fn how_to_fix(_ctx: StateCtx<'_>) -> &'static str {
    HOW_TO_FIX
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    if !ctx.workflows.has_any_workflows() {
        return CheckOutcome::skipped_no_data("N/A (no workflows)", "repos, no workflows");
    }

    match ctx.sha_pinning {
        SHAPinningState::Enforced => CheckOutcome::pass("✓"),
        SHAPinningState::NotEnforced => CheckOutcome::fail("✗").with_items(vec![
            "repo setting \"Require actions to be pinned to a full-length commit SHA\" is OFF — settings → actions → general → Actions permissions"
                .into(),
        ]),
        SHAPinningState::PlanGated => CheckOutcome::skipped_plan_gated("N/A (plan)"),
    }
}

pub fn description(ctx: StateCtx<'_>) -> Option<String> {
    let mut applicable = 0usize;
    let mut not_enforced_repos = 0usize;
    for r in ctx.repos {
        if !r.workflows.has_any_workflows() {
            continue;
        }
        match r.sha_pinning {
            SHAPinningState::Enforced => applicable += 1,
            SHAPinningState::NotEnforced => {
                applicable += 1;
                not_enforced_repos += 1;
            }
            SHAPinningState::PlanGated => {}
        }
    }

    if applicable == 0 {
        return None;
    }

    Some(if not_enforced_repos == 0 {
        "every repository with workflows enforces SHA pinning at the repo level".to_string()
    } else {
        format!(
            "{not_enforced_repos}/{applicable} {} with workflows don't enforce SHA pinning at the repo level",
            repos_word(applicable)
        )
    })
}
