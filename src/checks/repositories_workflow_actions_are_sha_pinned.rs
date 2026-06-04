use crate::checks::StateCtx;
use crate::checks::common::{noun, repos_word};
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;
use crate::support::workflows;

pub const LABEL: &str = "Repositories workflow actions are SHA-pinned";
pub const HOW_TO_FIX: &str = "In each affected workflow file below, replace every tag or branch ref with the full-length commit SHA (keep the tag as a trailing comment for readability). For example:\n```diff\n    - name: Cache dependencies\n-      uses: actions/cache@v5\n+      uses: actions/cache@27d5ce7f107fe9357f9df03efb73ab90386fccae # v5\n```\nTip: hand the file list to your coding agent and ask it to pin every `uses:` ref — it can resolve each tag to its commit SHA for you.";
pub const WHY_ENABLE: &str = "Tags and branches are mutable — when tj-actions/changed-files was compromised in 2025, the attacker repointed the existing tags, so every workflow `@v1` instantly ran malicious code; pinning each `uses:` ref to a full-length commit SHA makes that impossible. Note: pinning the refs is necessary but not sufficient — pair it with the repo-level enforcement setting (see `repositories_enforce_workflow_actions_sha_pinning`) so unpinned refs can't be reintroduced.";

pub fn how_to_fix(_ctx: StateCtx<'_>) -> &'static str {
    HOW_TO_FIX
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    if !ctx.workflows.has_any_workflows() {
        return CheckOutcome::skipped_no_data("N/A (no workflows)", "repos, no workflows");
    }

    let multi = ctx.workflows.len() > 1;
    let mut unpinned: Vec<String> = Vec::new();
    let mut failing_branches: Vec<String> = Vec::new();

    for (branch, wfs) in ctx.workflows.iter() {
        let mut branch_unpinned: Vec<String> = Vec::new();
        for wf in wfs {
            for uses in workflows::collect_uses(&wf.doc) {
                if !workflows::is_pinned(&uses) {
                    branch_unpinned.push(format!("unpinned ref — {}: {}", wf.path, uses));
                }
            }
        }
        if !branch_unpinned.is_empty() && !failing_branches.contains(branch) {
            failing_branches.push(branch.clone());
        }
        for f in branch_unpinned {
            unpinned.push(if multi { format!("{branch}: {f}") } else { f });
        }
    }

    if unpinned.is_empty() {
        return CheckOutcome::pass("✓");
    }

    let mut outcome = CheckOutcome::fail("✗").with_items(unpinned);
    if !failing_branches.is_empty() {
        outcome = outcome.with_failing_branches(failing_branches);
    }
    outcome
}

pub fn description(ctx: StateCtx<'_>) -> Option<String> {
    let mut total_unpinned = 0usize;
    let mut bad_repos = 0usize;
    let mut applicable = 0usize;
    for r in ctx.repos {
        if !r.workflows.has_any_workflows() {
            continue;
        }

        applicable += 1;
        let mut repo_unpinned = 0usize;
        for (_, wfs) in r.workflows.iter() {
            for wf in wfs {
                for uses in workflows::collect_uses(&wf.doc) {
                    if !workflows::is_pinned(&uses) {
                        repo_unpinned += 1;
                    }
                }
            }
        }
        if repo_unpinned > 0 {
            bad_repos += 1;
            total_unpinned += repo_unpinned;
        }
    }

    if applicable == 0 {
        return None;
    }

    Some(if total_unpinned == 0 {
        format!(
            "every workflow action is SHA-pinned across all {applicable} {} with workflows",
            repos_word(applicable)
        )
    } else {
        format!(
            "{total_unpinned} unpinned {} across {bad_repos}/{applicable} {} with workflows",
            noun(total_unpinned, "action reference", "action references"),
            repos_word(applicable)
        )
    })
}
