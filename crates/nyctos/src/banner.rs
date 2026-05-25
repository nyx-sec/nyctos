//! Startup banner printed by `nyctos serve` when stdout is a TTY.

use std::io::IsTerminal;

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_NYCTOS_GREEN: &str = "\x1b[38;2;46;160;103m";
const ANSI_NYCTOS_GOLD: &str = "\x1b[38;2;199;154;43m";
const ANSI_NYCTOS_MUTED: &str = "\x1b[38;2;159;163;173m";
const ANSI_NYCTOS_RED: &str = "\x1b[38;2;157;47;37m";
const NYCTOS_TAGLINE: &str = "            automated pentesting, refined";
const COMMUNITY_EDITION_NOTICE_LINES: [&str; 3] = [
    "Community Edition",
    "License required: organizations over 100 employees or $1M annual revenue.",
    "Commercial licensing: nyctos.dev/pricing",
];

const NYCTOS_BANNER: [(&str, &str); 6] = [
    ("███╗   ██╗██╗   ██╗ ██████╗", "████████╗ ██████╗ ███████╗"),
    ("████╗  ██║╚██╗ ██╔╝██╔════╝", "╚══██╔══╝██╔═══██╗██╔════╝"),
    ("██╔██╗ ██║ ╚████╔╝ ██║     ", "   ██║   ██║   ██║███████╗"),
    ("██║╚██╗██║  ╚██╔╝  ██║     ", "   ██║   ██║   ██║╚════██║"),
    ("██║ ╚████║   ██║   ╚██████╗", "   ██║   ╚██████╔╝███████║"),
    ("╚═╝  ╚═══╝   ╚═╝    ╚═════╝", "   ╚═╝    ╚═════╝ ╚══════╝"),
];

pub(crate) fn print_startup_banner() {
    if !std::io::stdout().is_terminal() {
        return;
    }
    print!("{}", startup_banner(should_colorize_stdout()));
}

fn should_colorize_stdout() -> bool {
    if !std::io::stdout().is_terminal() {
        return false;
    }
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if std::env::var("CLICOLOR").is_ok_and(|value| value == "0") {
        return false;
    }
    !std::env::var("TERM").is_ok_and(|value| value == "dumb")
}

fn startup_banner(color: bool) -> String {
    let mut out = String::new();
    out.push('\n');
    for (nyc, tos) in NYCTOS_BANNER {
        if color {
            out.push_str(ANSI_NYCTOS_GREEN);
            out.push_str(nyc);
            out.push_str(ANSI_NYCTOS_GOLD);
            out.push_str(tos);
            out.push_str(ANSI_RESET);
        } else {
            out.push_str(nyc);
            out.push_str(tos);
        }
        out.push('\n');
    }
    if color {
        out.push_str(ANSI_NYCTOS_MUTED);
        out.push_str(NYCTOS_TAGLINE);
        out.push_str(ANSI_RESET);
        push_colored_community_notice(&mut out);
    } else {
        out.push_str(NYCTOS_TAGLINE);
        out.push_str("\n\n");
        out.push_str(&COMMUNITY_EDITION_NOTICE_LINES.join("\n"));
    }
    out.push_str("\n\n");
    out
}

fn push_colored_community_notice(out: &mut String) {
    out.push_str("\n\n");
    out.push_str(ANSI_BOLD);
    out.push_str(ANSI_NYCTOS_GOLD);
    out.push_str("Community Edition");
    out.push_str(ANSI_RESET);
    out.push('\n');
    out.push_str(ANSI_BOLD);
    out.push_str(ANSI_NYCTOS_RED);
    out.push_str("License required:");
    out.push_str(ANSI_RESET);
    out.push(' ');
    out.push_str(ANSI_NYCTOS_MUTED);
    out.push_str("organizations over 100 employees or $1M annual revenue.");
    out.push_str(ANSI_RESET);
    out.push('\n');
    out.push_str(ANSI_NYCTOS_MUTED);
    out.push_str("Commercial licensing: ");
    out.push_str(ANSI_RESET);
    out.push_str(ANSI_NYCTOS_GREEN);
    out.push_str("nyctos.dev/pricing");
    out.push_str(ANSI_RESET);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_banner_renders_plain_solid_tagline() {
        let banner = startup_banner(false);

        assert!(banner.contains("███╗   ██╗██╗   ██╗ ██████╗"));
        assert!(!banner.contains(" █████╗  ██████╗"));
        assert!(banner.contains("\n            automated pentesting, refined"));
        assert!(banner.contains("\n\nCommunity Edition\n"));
        assert!(banner.contains("License required: organizations over 100 employees"));
        assert!(!banner.contains("\x1b["));
    }

    #[test]
    fn startup_banner_can_render_with_brand_colors() {
        let banner = startup_banner(true);

        assert!(banner.contains(ANSI_NYCTOS_GREEN));
        assert!(banner.contains(ANSI_NYCTOS_GOLD));
        assert!(banner.contains(ANSI_NYCTOS_MUTED));
        assert!(banner.contains(ANSI_NYCTOS_RED));
        assert!(banner.contains(ANSI_BOLD));
        assert!(banner.contains("automated pentesting, refined"));
        assert!(banner.contains("License required:"));
        assert!(banner.contains("nyctos.dev/pricing"));
    }
}
