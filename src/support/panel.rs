use owo_colors::OwoColorize;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

const MIN_WIDTH: usize = 60;
const MAX_WIDTH: usize = 120;
const DEFAULT_WIDTH: usize = 80;

static CACHED_WIDTH: OnceLock<usize> = OnceLock::new();

pub fn width() -> usize {
    *CACHED_WIDTH.get_or_init(|| {
        let cols = terminal_size::terminal_size()
            .map(|(terminal_size::Width(w), _)| w as usize)
            .unwrap_or(DEFAULT_WIDTH);
        cols.clamp(MIN_WIDTH, MAX_WIDTH)
    })
}

struct ProgressState {
    badge: String,
    brand: String,
    brand_note: Option<String>,
    left: String,
    tty: bool,
    done: AtomicUsize,
    total: AtomicUsize,
}

static PROGRESS: Mutex<Option<ProgressState>> = Mutex::new(None);

pub fn progress(_msg: &str) {
    let state = PROGRESS.lock().unwrap();
    let Some(s) = state.as_ref() else {
        return;
    };
    let done = s.done.fetch_add(1, Ordering::Relaxed) + 1;
    if !s.tty {
        return;
    }
    let total = s.total.load(Ordering::Relaxed);
    let right = if total > 0 {
        let word = if total == 1 { "check" } else { "checks" };
        format!("{}/{} {word}", done.min(total), total)
    } else {
        let word = if done == 1 { "check" } else { "checks" };
        format!("{done} {word}")
    };
    rewrite_header_right(s, &right);
}

pub fn bump_progress_total(extra: usize) {
    let state = PROGRESS.lock().unwrap();
    if let Some(s) = state.as_ref() {
        let total = s.total.fetch_add(extra, Ordering::Relaxed) + extra;
        if s.tty {
            let done = s.done.load(Ordering::Relaxed);
            let word = if total == 1 { "check" } else { "checks" };
            let right = format!("{}/{} {word}", done.min(total), total);
            rewrite_header_right(s, &right);
        }
    }
}

pub fn finish_progress(final_right: &str) {
    let mut state = PROGRESS.lock().unwrap();
    if let Some(s) = state.as_ref()
        && s.tty
    {
        rewrite_header_right(s, final_right);
    }
    *state = None;
}

fn rewrite_header_right(s: &ProgressState, right: &str) {
    let inner = width() - 2;
    let note_visible = s
        .brand_note
        .as_ref()
        .map(|n| 1 + n.chars().count())
        .unwrap_or(0);
    let used = 2
        + s.badge.chars().count()
        + 1
        + s.brand.chars().count()
        + note_visible
        + 3
        + s.left.chars().count()
        + right.chars().count()
        + 2;
    let pad = inner.saturating_sub(used);
    let brand_rendered = match &s.brand_note {
        Some(note) => format!("{} {}", text_bold(&s.brand), warning(note)),
        None => text_bold(&s.brand),
    };
    let row = format!(
        "  {} {} {} {}{}{}  ",
        accent_bold(&s.badge),
        brand_rendered,
        muted("·"),
        text_bold(&s.left),
        " ".repeat(pad),
        muted(right),
    );
    print!(
        "\x1b[3A\r\x1b[2K{}{}{}\x1b[3B\r",
        border("│"),
        row,
        border("│"),
    );
    std::io::stdout().flush().ok();
}

#[derive(Clone, Copy)]
pub struct Palette {
    pub border: (u8, u8, u8),
    pub text: (u8, u8, u8),
    pub muted: (u8, u8, u8),
    pub success: (u8, u8, u8),
    pub warning: (u8, u8, u8),
    pub danger: (u8, u8, u8),
    pub info: (u8, u8, u8),
    pub accent: (u8, u8, u8),
    pub gradient: [(u8, u8, u8); 20],
}

const DARK_PALETTE: Palette = Palette {
    border: (38, 50, 68),
    text: (229, 231, 235),
    muted: (124, 132, 151),
    success: (126, 231, 135),
    warning: (242, 204, 96),
    danger: (239, 83, 80),
    info: (138, 180, 255),
    accent: (192, 132, 252),
    gradient: [
        (239, 83, 80),
        (239, 96, 82),
        (240, 110, 84),
        (240, 123, 85),
        (240, 137, 87),
        (241, 150, 89),
        (241, 164, 91),
        (241, 177, 92),
        (242, 191, 94),
        (242, 204, 96),
        (229, 207, 100),
        (216, 210, 105),
        (203, 213, 109),
        (190, 216, 113),
        (177, 219, 118),
        (164, 222, 122),
        (152, 225, 126),
        (139, 228, 130),
        (132, 230, 133),
        (126, 231, 135),
    ],
};

const LIGHT_PALETTE: Palette = Palette {
    border: (148, 163, 184),
    text: (15, 23, 42),
    muted: (71, 85, 105),
    success: (21, 128, 61),
    warning: (180, 83, 9),
    danger: (185, 28, 28),
    info: (29, 78, 216),
    accent: (126, 34, 206),
    gradient: [
        (185, 28, 28),
        (188, 41, 24),
        (190, 55, 21),
        (193, 68, 17),
        (195, 82, 14),
        (198, 95, 10),
        (200, 109, 7),
        (203, 122, 3),
        (205, 136, 0),
        (180, 130, 5),
        (155, 132, 12),
        (130, 134, 19),
        (105, 137, 27),
        (80, 139, 34),
        (60, 138, 40),
        (45, 134, 47),
        (33, 130, 54),
        (24, 127, 58),
        (21, 128, 61),
        (20, 110, 53),
    ],
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ThemeChoice {
    #[default]
    Auto,
    Dark,
    Light,
}

static PALETTE: OnceLock<Palette> = OnceLock::new();

pub fn init_theme(choice: ThemeChoice) {
    let palette = match choice {
        ThemeChoice::Dark => DARK_PALETTE,
        ThemeChoice::Light => LIGHT_PALETTE,
        ThemeChoice::Auto => {
            if detect_light_background() {
                LIGHT_PALETTE
            } else {
                DARK_PALETTE
            }
        }
    };
    let _ = PALETTE.set(palette);
}

fn palette() -> &'static Palette {
    PALETTE.get_or_init(|| {
        if detect_light_background() {
            LIGHT_PALETTE
        } else {
            DARK_PALETTE
        }
    })
}

/// Detect a light terminal background. Uses `terminal-light`, which first
/// checks the COLORFGBG env var (rxvt, konsole, terminator, gnome-terminal)
/// and then falls back to an OSC 11 query (Apple Terminal, iTerm2, Alacritty,
/// kitty, xterm). Returns false on non-terminals or when detection fails.
///
/// The OSC 11 fallback writes an escape sequence to stdout and reads the
/// reply back from stdin, which requires switching the terminal into raw
/// mode. When either stream is redirected (piped output, `cargo test`, CI)
/// the handshake never completes and the terminal can be left in raw mode —
/// printing a runaway staircase of un-returned newlines. So only probe when
/// both stdin and stdout are interactive terminals; otherwise assume dark.
fn detect_light_background() -> bool {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return false;
    }
    terminal_light::luma().map(|l| l > 0.5).unwrap_or(false)
}

pub fn border(s: &str) -> String {
    let c = palette().border;
    s.truecolor(c.0, c.1, c.2).to_string()
}
pub fn text(s: &str) -> String {
    let c = palette().text;
    s.truecolor(c.0, c.1, c.2).to_string()
}
pub fn text_bold(s: &str) -> String {
    let c = palette().text;
    s.truecolor(c.0, c.1, c.2).bold().to_string()
}
pub fn muted(s: &str) -> String {
    let c = palette().muted;
    s.truecolor(c.0, c.1, c.2).to_string()
}
pub fn success(s: &str) -> String {
    let c = palette().success;
    s.truecolor(c.0, c.1, c.2).to_string()
}
pub fn success_bold(s: &str) -> String {
    let c = palette().success;
    s.truecolor(c.0, c.1, c.2).bold().to_string()
}
pub fn warning(s: &str) -> String {
    let c = palette().warning;
    s.truecolor(c.0, c.1, c.2).to_string()
}
pub fn warning_bold(s: &str) -> String {
    let c = palette().warning;
    s.truecolor(c.0, c.1, c.2).bold().to_string()
}
pub fn danger(s: &str) -> String {
    let c = palette().danger;
    s.truecolor(c.0, c.1, c.2).to_string()
}
pub fn danger_bold(s: &str) -> String {
    let c = palette().danger;
    s.truecolor(c.0, c.1, c.2).bold().to_string()
}
pub fn info(s: &str) -> String {
    let c = palette().info;
    s.truecolor(c.0, c.1, c.2).to_string()
}
pub fn info_underline(s: &str) -> String {
    let c = palette().info;
    s.truecolor(c.0, c.1, c.2).underline().to_string()
}
pub fn accent(s: &str) -> String {
    let c = palette().accent;
    s.truecolor(c.0, c.1, c.2).to_string()
}
pub fn accent_bold(s: &str) -> String {
    let c = palette().accent;
    s.truecolor(c.0, c.1, c.2).bold().to_string()
}

/// 20-stop red → yellow → green gradient. Returns the RGB for bucket `idx`
/// out of `total` positions, using the active theme's gradient stops.
fn gradient_rgb(idx: usize, total: usize) -> (u8, u8, u8) {
    let stops = &palette().gradient;
    let n = total.max(1);
    let bucket = (idx * stops.len()) / n;
    stops[bucket.min(stops.len() - 1)]
}

pub fn gradient(s: &str, idx: usize, total: usize) -> String {
    let (r, g, b) = gradient_rgb(idx, total);
    s.truecolor(r, g, b).to_string()
}

#[derive(Default)]
pub struct Line {
    pub visible: usize,
    pub rendered: String,
}

impl Line {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn raw(mut self, vis: &str, rendered: &str) -> Self {
        self.visible += vis.chars().count();
        self.rendered.push_str(rendered);
        self
    }
    pub fn space(self, n: usize) -> Self {
        let s = " ".repeat(n);
        self.raw(&s.clone(), &s)
    }
    pub fn plain(self, s: &str) -> Self {
        let r = s.to_string();
        self.raw(s, &r)
    }
    pub fn styled(self, s: &str, f: impl FnOnce(&str) -> String) -> Self {
        let r = f(s);
        self.raw(s, &r)
    }
}

pub fn top_titled(title: &str, badge: &str) {
    let prefix_visible = format!("╭─ {} ", badge);
    let title_visible = title.to_string();
    let used = prefix_visible.chars().count() + title_visible.chars().count() + 1;
    let dashes = width().saturating_sub(used + 1);
    let title_part = format!(" {} ", text_bold(title));
    let right = border(&format!("{}─╮", "─".repeat(dashes)));
    println!(
        "{}{}{}{}",
        border("╭─ "),
        accent_bold(badge),
        title_part,
        right,
    );
}

pub fn top_section(label: &str) {
    top_section_styled(label, text_bold);
}

/// Same as [`top_section`] but lets the caller style the title (e.g. with
/// [`danger_bold`] for an authentication error panel).
pub fn top_section_styled(label: &str, style: impl FnOnce(&str) -> String) {
    let prefix_visible = format!("╭─ {} ", label);
    let used = prefix_visible.chars().count();
    let dashes = width().saturating_sub(used + 1);
    println!(
        "{}{}{}",
        border("╭─ "),
        style(label),
        border(&format!(" {}╮", "─".repeat(dashes))),
    );
}

pub fn bottom() {
    println!("{}", border(&format!("╰{}╯", "─".repeat(width() - 2))));
}

pub fn blank() {
    let inner = width() - 2;
    println!("{}{}{}", border("│"), " ".repeat(inner), border("│"));
}

pub fn row(line: Line) {
    let inner = width() - 2;
    let pad = inner.saturating_sub(line.visible);
    println!(
        "{}{}{}{}",
        border("│"),
        line.rendered,
        " ".repeat(pad),
        border("│")
    );
}

pub fn raw_line(line: Line) {
    println!("{}", line.rendered);
}

pub fn divider() {
    let inner = width() - 2;
    let dashes = inner - 2;
    println!(
        "{}{}{}",
        border("│"),
        border(&format!(" {} ", "─".repeat(dashes))),
        border("│"),
    );
}

pub fn header_panel(badge: &str, brand: &str, brand_note: Option<&str>, left: &str, right: &str) {
    println!();
    println!("{}", border(&format!("╭{}╮", "─".repeat(width() - 2))));
    let inner = width() - 2;
    let note_visible = brand_note.map(|n| 1 + n.chars().count()).unwrap_or(0);
    let used = 2
        + badge.chars().count()
        + 1
        + brand.chars().count()
        + note_visible
        + 3
        + left.chars().count()
        + right.chars().count()
        + 2;
    let pad = inner.saturating_sub(used);
    let brand_rendered = match brand_note {
        Some(note) => format!("{} {}", text_bold(brand), warning(note)),
        None => text_bold(brand),
    };
    let rendered = format!(
        "  {} {} {} {}{}{}  ",
        accent_bold(badge),
        brand_rendered,
        muted("·"),
        text_bold(left),
        " ".repeat(pad),
        muted(right),
    );
    println!("{}{}{}", border("│"), rendered, border("│"));
    bottom();
    println!();

    let mut state = PROGRESS.lock().unwrap();
    *state = Some(ProgressState {
        badge: badge.into(),
        brand: brand.into(),
        brand_note: brand_note.map(|s| s.to_string()),
        left: left.into(),
        tty: std::io::stdout().is_terminal(),
        done: AtomicUsize::new(0),
        total: AtomicUsize::new(0),
    });
    drop(state);
    let _ = right;
}

pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_breaks_on_word_boundaries() {
        let lines = wrap("the quick brown fox jumps", 10);
        assert!(lines.iter().all(|l| l.chars().count() <= 10));
        assert_eq!(lines.join(" "), "the quick brown fox jumps");
    }

    #[test]
    fn line_tracks_visible_separately_from_rendered() {
        let l = Line::new()
            .plain("hi")
            .styled("X", |s| format!("\x1b[31m{s}\x1b[0m"));
        assert_eq!(l.visible, 3);
        assert!(l.rendered.contains("hi"));
        assert!(l.rendered.contains("\x1b[31m"));
    }
}
