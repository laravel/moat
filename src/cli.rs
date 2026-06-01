use clap::{Parser, ValueEnum};

#[derive(Parser)]
#[command(
    name = "moat",
    version,
    about = "Reviews the security posture of your GitHub organization & repositories and suggests improvements",
    disable_help_flag = true,
    disable_version_flag = true
)]
pub struct Cli {
    pub account: Option<String>,

    /// Print help.
    #[arg(short = 'h', long, action = clap::ArgAction::SetTrue)]
    pub help: bool,

    /// Print version.
    #[arg(short = 'V', long, action = clap::ArgAction::SetTrue)]
    pub version: bool,

    /// Display all collaborators and members instead of truncating the list.
    #[arg(short, long)]
    pub verbose: bool,

    /// Audit only public repositories.
    #[arg(long, conflicts_with = "private")]
    pub public: bool,

    /// Audit only private repositories.
    #[arg(long, conflicts_with = "public")]
    pub private: bool,

    /// Download and install the latest released version of moat, then exit.
    #[arg(long)]
    pub self_update: bool,

    /// Color theme. `auto` detects the terminal background via COLORFGBG.
    #[arg(long, value_enum, default_value_t = Theme::Auto)]
    pub theme: Theme,

    /// Output format. `pretty` prints the styled terminal report; `json` and
    /// `markdown` suppress all panels and emit a machine-readable report on
    /// stdout instead.
    #[arg(long, value_enum, default_value_t = Format::Pretty)]
    pub format: Format,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum Theme {
    #[default]
    Auto,
    Dark,
    Light,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum Format {
    #[default]
    Pretty,
    Json,
    Markdown,
}

impl From<Theme> for crate::support::panel::ThemeChoice {
    fn from(t: Theme) -> Self {
        match t {
            Theme::Auto => Self::Auto,
            Theme::Dark => Self::Dark,
            Theme::Light => Self::Light,
        }
    }
}
