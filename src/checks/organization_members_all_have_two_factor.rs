use crate::checks::StateCtx;
use crate::checks::common::noun;
use crate::checks::org_context::OrgContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Organization members all have two factor";
pub const HOW_TO_FIX: &str = "https://github.com/orgs/{org}/people?query=two-factor%3Adisabled > Ask each listed member to enable 2FA on their GitHub account";
pub const WHY_ENABLE: &str = "The org-wide 2FA policy only covers members enrolled after it was turned on; anyone here predates it and remains the weakest unlocked door into the org.";

pub fn how_to_fix(_ctx: StateCtx<'_>) -> &'static str {
    HOW_TO_FIX
}

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    if ctx.members_without_2fa.is_empty() {
        CheckOutcome::pass("Every member has 2FA enabled")
    } else {
        CheckOutcome::fail(format!(
            "{} member(s) without 2FA enabled",
            ctx.members_without_2fa.len()
        ))
        .with_items(ctx.members_without_2fa.clone())
    }
}

pub fn description(ctx: StateCtx<'_>) -> Option<String> {
    let org = ctx.org?;
    if org.members_without_2fa.is_empty() {
        Some("every member has two-factor authentication enabled".into())
    } else {
        let n = org.members_without_2fa.len();
        Some(format!(
            "{n} {} can sign in without two-factor authentication",
            noun(n, "member", "members")
        ))
    }
}
