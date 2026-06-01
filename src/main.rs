use std::sync::OnceLock;

use anyhow::Result;
use clap::Parser;
use moat::runner::{self, AccountKind, AuditTarget, CheckContext};
use moat::support::panel;
use moat::support::report::Report;
use moat::{cli, support};

static OUTPUT_FORMAT: OnceLock<cli::Format> = OnceLock::new();

fn current_format() -> cli::Format {
    OUTPUT_FORMAT.get().copied().unwrap_or(cli::Format::Pretty)
}

#[tokio::main]
async fn main() {
    match run().await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            emit_error(current_format(), &e);
            std::process::exit(1);
        }
    }
}

fn emit_error(format: cli::Format, e: &anyhow::Error) {
    let (title, body) = if let Some(auth) = e.downcast_ref::<moat::runner::AuthError>() {
        (auth.title.clone(), auth.to_plain_body())
    } else {
        ("Error".to_string(), format!("{e:#}"))
    };

    match format {
        cli::Format::Pretty => {
            if let Some(auth) = e.downcast_ref::<moat::runner::AuthError>() {
                auth.render();
            } else {
                runner::render_generic_error(&body);
            }
        }
        cli::Format::Json => {
            let value = serde_json::json!({
                "kind": "error",
                "title": title,
                "message": body.trim_end(),
            });
            if let Ok(rendered) = serde_json::to_string_pretty(&value) {
                println!("{rendered}");
            }
        }
        cli::Format::Markdown => {
            println!("# {title}\n");
            println!("{}", body.trim_end());
        }
    }
}

async fn run() -> Result<i32> {
    let cli = match cli::Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            panel::init_theme(cli::Theme::Auto.into());
            let format = sniff_format_from_argv().unwrap_or(cli::Format::Pretty);
            let _ = OUTPUT_FORMAT.set(format);
            render_clap_error(format, &e);
            return Ok(e.exit_code());
        }
    };
    let _ = OUTPUT_FORMAT.set(cli.format);
    panel::init_theme(cli.theme.into());

    if cli.help || (cli.account.is_none() && !cli.self_update && !cli.version) {
        use clap::CommandFactory;
        let inner_width = panel::width().saturating_sub(8);
        let mut cmd = cli::Cli::command().term_width(inner_width);
        let help = cmd.render_help().to_string();
        emit_info(cli.format, "Moat", "help", &help)?;
        return Ok(0);
    }

    if cli.version {
        let body = format!("Moat v{}", env!("CARGO_PKG_VERSION"));
        emit_info(cli.format, "Version", "version", &body)?;
        return Ok(0);
    }

    if cli.self_update {
        use support::update::SelfUpdateOutcome;
        let outcome = tokio::task::spawn_blocking(support::update::run_self_update)
            .await
            .unwrap_or_else(|e| SelfUpdateOutcome::Failed(e.to_string()));
        let body = match outcome {
            SelfUpdateOutcome::Updated(v) => {
                format!("Moat updated to v{}.", v.trim_start_matches('v'))
            }
            SelfUpdateOutcome::UpToDate => "Moat is already up to date.".to_string(),
            SelfUpdateOutcome::ManagedExternally { manager, latest } => format!(
                "Moat v{} is available. This binary is managed by {}; run `brew update && brew upgrade moat` to update.",
                latest.trim_start_matches('v'),
                manager,
            ),
            SelfUpdateOutcome::Failed(e) => format!("Self-update failed: {e}"),
        };
        emit_info(cli.format, "Self-update", "self_update", &body)?;
        return Ok(0);
    }

    let (token, auth_source) = support::github::resolve_token()
        .map_err(|e| anyhow::Error::new(runner::format_no_token_error(&format!("{e:#}"))))?;
    let client = support::github::Client::new(token)?;
    let preflight = runner::verify_token_credentials(&client, auth_source).await?;

    let cli::Cli {
        account,
        verbose,
        public,
        private,
        self_update: _,
        help: _,
        version: _,
        theme: _,
        format,
    } = cli;
    let account = account.expect("clap guarantees account is present unless --self-update");

    let visibility = match (public, private) {
        (true, _) => runner::VisibilityFilter::Public,
        (_, true) => runner::VisibilityFilter::Private,
        _ => runner::VisibilityFilter::All,
    };

    let pretty = matches!(format, cli::Format::Pretty);

    let outdated_note: Option<String> = if pretty {
        let latest = tokio::task::spawn_blocking(support::update::latest_version)
            .await
            .ok()
            .flatten();
        latest
            .as_deref()
            .filter(|l| support::update::is_newer_than_current(l))
            .map(|_| "(outdated, run --self-update)".to_string())
    } else {
        None
    };
    let outdated_note = outdated_note.as_deref();

    if let Some((owner, repo)) = account.split_once('/') {
        if owner.is_empty() || repo.is_empty() || repo.contains('/') {
            anyhow::bail!("Invalid target `{account}` — expected `owner/repo` or `account`.");
        }
        if public || private {
            anyhow::bail!(
                "`--public` and `--private` filter the repositories of an account or organization; they can't be used when auditing a single `owner/repo`."
            );
        }
        let listing = runner::ensure_viewer_can_audit_repo(&client, owner, repo).await?;
        runner::verify_token_for_target(
            AuditTarget::UserOrRepo,
            &account,
            auth_source,
            preflight.clone(),
        )
        .await?;
        if pretty {
            runner::print_repo_header(owner, repo, outdated_note);
            support::panel::bump_progress_total(1 + runner::REPO_TICKS);
        }
        let contexts = runner::fetch_single_repo_context(&client, owner, listing).await?;
        if pretty {
            support::panel::finish_progress("Repository");
        }

        let ctx = CheckContext {
            org: None,
            repos: &contexts,
        };
        let results = runner::run_checks(&ctx);
        let active_total = contexts.iter().filter(|c| !c.archived).count();
        if pretty {
            runner::render_checks_panel(&results, None, owner, active_total, verbose);
            runner::render_posture_panel(&results);
        } else {
            emit_report(format, &account, "repository", &results)?;
        }
        Ok(runner::exit_code(&results))
    } else {
        let kind = runner::ensure_viewer_can_audit_account(&client, &account).await?;
        let target = match kind {
            AccountKind::Organization => AuditTarget::Organization,
            AccountKind::User => AuditTarget::UserOrRepo,
        };
        runner::verify_token_for_target(target, &account, auth_source, preflight).await?;
        if pretty {
            runner::print_header(&account, kind, outdated_note);
        }

        let do_org = matches!(kind, AccountKind::Organization);

        let listings = runner::list_repos(&client, &account, kind, visibility).await?;

        if pretty {
            let mut total_ticks = 1 + runner::REPO_TICKS * listings.len();
            if do_org {
                total_ticks += runner::ORG_TICKS;
            }
            support::panel::bump_progress_total(total_ticks);
        }

        let org_ctx = if do_org {
            Some(runner::fetch_org_context(&client, &account).await?)
        } else {
            None
        };

        let repo_contexts = runner::fetch_repo_contexts_from(&client, &account, listings).await?;

        if pretty {
            support::panel::finish_progress(match kind {
                AccountKind::Organization => "Organization",
                AccountKind::User => "User",
            });
        }

        let ctx = CheckContext {
            org: org_ctx.as_ref(),
            repos: &repo_contexts,
        };
        let results = runner::run_checks(&ctx);
        let active_total = repo_contexts.iter().filter(|c| !c.archived).count();
        if pretty {
            runner::render_checks_panel(
                &results,
                org_ctx.as_ref(),
                &account,
                active_total,
                verbose,
            );
            runner::render_posture_panel(&results);
        } else {
            let kind_str = match kind {
                AccountKind::Organization => "organization",
                AccountKind::User => "user",
            };
            emit_report(format, &account, kind_str, &results)?;
        }
        Ok(runner::exit_code(&results))
    }
}

fn render_clap_error(format: cli::Format, e: &clap::Error) {
    use moat::runner::{AuthError, AuthErrorLine};
    let raw = e.to_string();
    let mut lines: Vec<AuthErrorLine> = Vec::new();
    let mut first = true;
    for line in raw.lines() {
        let stripped = if first {
            first = false;
            line.trim_start_matches("error: ")
        } else {
            line
        };
        if stripped.trim().is_empty() {
            lines.push(AuthErrorLine::Blank);
        } else {
            lines.push(AuthErrorLine::Text(stripped.to_string()));
        }
    }
    while matches!(lines.last(), Some(AuthErrorLine::Blank)) {
        lines.pop();
    }
    let err = AuthError {
        title: "Error".to_string(),
        lines,
    };
    match format {
        cli::Format::Pretty => err.render(),
        cli::Format::Json => {
            let value = serde_json::json!({
                "kind": "error",
                "title": err.title,
                "message": err.to_plain_body().trim_end(),
            });
            if let Ok(rendered) = serde_json::to_string_pretty(&value) {
                println!("{rendered}");
            }
        }
        cli::Format::Markdown => {
            println!("# {}\n", err.title);
            println!("{}", err.to_plain_body().trim_end());
        }
    }
}

fn sniff_format_from_argv() -> Option<cli::Format> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--format=") {
            return parse_format(value);
        }
        if arg == "--format"
            && let Some(value) = args.next()
        {
            return parse_format(&value);
        }
    }
    None
}

fn parse_format(value: &str) -> Option<cli::Format> {
    match value {
        "json" => Some(cli::Format::Json),
        "markdown" => Some(cli::Format::Markdown),
        "pretty" => Some(cli::Format::Pretty),
        _ => None,
    }
}

fn emit_info(format: cli::Format, title: &str, kind: &str, body: &str) -> Result<()> {
    match format {
        cli::Format::Pretty => {
            if kind == "help" {
                runner::render_raw_panel(title, body);
            } else {
                runner::render_info_panel(title, &[body.to_string()]);
            }
        }
        cli::Format::Json => {
            let value = serde_json::json!({ "kind": kind, "message": body });
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            use std::io::Write;
            writeln!(handle, "{}", serde_json::to_string_pretty(&value)?)?;
        }
        cli::Format::Markdown => {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            use std::io::Write;
            writeln!(handle, "# {title}\n")?;
            if kind == "help" {
                writeln!(handle, "```\n{}\n```", body.trim_end())?;
            } else {
                writeln!(handle, "{body}")?;
            }
        }
    }
    Ok(())
}

fn emit_report(
    format: cli::Format,
    account: &str,
    account_kind: &str,
    results: &[moat::runner::CheckResult],
) -> Result<()> {
    let report = Report::from_results(account, account_kind, results);
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    match format {
        cli::Format::Json => report.write_json(&mut handle)?,
        cli::Format::Markdown => report.write_markdown(&mut handle)?,
        cli::Format::Pretty => unreachable!("pretty handled on the caller side"),
    }
    Ok(())
}
