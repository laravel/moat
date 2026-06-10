use crate::checks::StateCtx;
use crate::checks::common::{noun, repos_word};
use crate::checks::repo_context::RepoContext;
use crate::config::Config;
use crate::support::outcome::CheckOutcome;
use crate::support::workflows::{self, PermissionsBlock, Workflow};
use serde_yaml::Value;

pub const LABEL: &str = "Repositories workflow permissions are restricted";
pub const HOW_TO_FIX: &str = "In each `.github/workflows/*.yml` below > *Add* -> A top-level `permissions:` block > *Set* -> The minimum scopes needed — for read-only workflows:\n```yaml\npermissions:\n  contents: read\n```";
pub const WHY_ENABLE: &str = "Without a declared `permissions:` block (or with `write-all`), every step in the workflow — including third-party actions — runs with full repo write access, turning any compromised action into a code-push primitive.";

fn findings_for_workflows(wfs: &[Workflow], config: &Config) -> (Vec<String>, bool) {
    let mut findings: Vec<String> = Vec::new();
    let mut had_filtered_writes = false;
    for wf in wfs {
        match workflows::top_level_permissions(&wf.doc) {
            PermissionsBlock::Missing => {
                findings.push(format!("{}: missing permissions block", wf.path))
            }
            PermissionsBlock::WriteAll => findings.push(format!("{}: write-all", wf.path)),
            PermissionsBlock::Scoped(writes) if !writes.is_empty() => {
                findings.push(format!("{}: write scopes [{}]", wf.path, writes.join(", ")));
            }
            _ => {}
        }
        for (job, block) in workflows::job_level_permissions(&wf.doc) {
            match block {
                PermissionsBlock::WriteAll => {
                    findings.push(format!("{}: job `{}` write-all", wf.path, job));
                }
                PermissionsBlock::Scoped(writes) if !writes.is_empty() => {
                    let writes_to_report = filter_job_writes(&wf.doc, &job, &writes, config);
                    if !writes_to_report.is_empty() {
                        findings.push(format!(
                            "{}: job `{}` write scopes [{}]",
                            wf.path,
                            job,
                            writes_to_report.join(", ")
                        ));
                    } else {
                        had_filtered_writes = true;
                    }
                }
                _ => {}
            }
        }
    }
    (findings, had_filtered_writes)
}

fn known_action_matches<'a>(uses: &'a str, config: &'a Config) -> Option<Vec<&'a str>> {
    let action = uses.split('@').next().unwrap_or(uses);
    if action.starts_with("./") || action.starts_with("docker://") {
        return None;
    }
    config.known_action_writes(action)
}

fn filter_job_writes<'a>(doc: &Value, job: &str, writes: &[&'a str], config: &Config) -> Vec<&'a str> {
    for uses in workflows::job_action_uses(doc, job) {
        if let Some(allowed) = known_action_matches(&uses, config) {
            return writes
                .iter()
                .filter(|w| !allowed.contains(w))
                .copied()
                .collect();
        }
    }
    writes.to_vec()
}

pub fn how_to_fix(_ctx: StateCtx<'_>) -> &'static str {
    HOW_TO_FIX
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    if ctx.workflows.is_empty() {
        return CheckOutcome::skipped_no_data("—", "repos, no workflows");
    }
    if !ctx.workflows.has_any_workflows() {
        return CheckOutcome::skipped_no_data("N/A", "repos, no workflows");
    }

    let multi = ctx.workflows.len() > 1;
    let mut all_findings: Vec<String> = Vec::new();
    let mut failing_branches: Vec<String> = Vec::new();
    for (branch, wfs) in ctx.workflows.iter() {
        let (findings, _) = findings_for_workflows(wfs, &ctx.config);
        if findings.is_empty() {
            continue;
        }
        if !failing_branches.contains(branch) {
            failing_branches.push(branch.clone());
        }
        for f in findings {
            all_findings.push(if multi { format!("{branch}: {f}") } else { f });
        }
    }

    if !all_findings.is_empty() {
        return CheckOutcome::fail("✗")
            .with_items(all_findings)
            .with_failing_branches(failing_branches);
    }
    CheckOutcome::pass("✓")
}

pub fn description(ctx: StateCtx<'_>) -> Option<String> {
    let mut total_bad = 0usize;
    let mut bad_repos = 0usize;
    let mut total_exempted_workflows = 0usize;
    let mut applicable = 0usize;
    for r in ctx.repos {
        if !r.workflows.has_any_workflows() {
            continue;
        }
        applicable += 1;
        let mut repo_bad = 0usize;
        let mut repo_exempted = 0usize;
        for (_, wfs) in r.workflows.iter() {
            for wf in wfs {
                let top_bad = match workflows::top_level_permissions(&wf.doc) {
                    PermissionsBlock::Missing | PermissionsBlock::WriteAll => true,
                    PermissionsBlock::Scoped(w) if !w.is_empty() => true,
                    _ => false,
                };
                let (job_bad, job_exempted) =
                    workflows::job_level_permissions(&wf.doc)
                        .into_iter()
                        .fold((false, false), |(bad, exempted), (job, b)| {
                            let has_writes = match &b {
                                PermissionsBlock::WriteAll => true,
                                PermissionsBlock::Scoped(w) if !w.is_empty() => true,
                                _ => false,
                            };
                            if !has_writes {
                                return (bad, exempted);
                            }
                            let remaining = match &b {
                                PermissionsBlock::Scoped(w) if !w.is_empty() => {
                                    filter_job_writes(&wf.doc, &job, w, &r.config)
                                }
                                _ => vec![],
                            };
                            if remaining.is_empty() && !matches!(b, PermissionsBlock::WriteAll) {
                                (bad, true)
                            } else {
                                (true, exempted)
                            }
                        });
                if top_bad || job_bad {
                    repo_bad += 1;
                }
                if job_exempted {
                    repo_exempted += 1;
                }
            }
        }
        if repo_bad > 0 {
            bad_repos += 1;
            total_bad += repo_bad;
        }
        if repo_exempted > 0 && repo_bad == 0 {
            total_exempted_workflows += repo_exempted;
        }
    }

    if applicable == 0 {
        return None;
    }
    Some(if total_bad == 0 {
        let base = format!(
            "every workflow declares a read-only permissions block across all {applicable} {} with workflows",
            repos_word(applicable)
        );
        if total_exempted_workflows > 0 {
            format!(
                "{base} ({total_exempted_workflows} {} with known-action exemptions)",
                noun(total_exempted_workflows, "workflow", "workflows"),
            )
        } else {
            base
        }
    } else {
        let base = format!(
            "{total_bad} {} grant write or omit the permissions block across {bad_repos}/{applicable} {} with workflows",
            noun(total_bad, "workflow", "workflows"),
            repos_word(applicable)
        );
        if total_exempted_workflows > 0 {
            format!(
                "{base}; {total_exempted_workflows} {} exempted for known actions",
                noun(total_exempted_workflows, "workflow", "workflows"),
            )
        } else {
            base
        }
    })
}
