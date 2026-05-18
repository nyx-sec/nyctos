//! Startup banner printed by `nyx-agent serve` when stdout is a TTY.

use std::io::IsTerminal;

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_NYX_GREEN: &str = "\x1b[38;2;46;160;103m";
const ANSI_NYX_GOLD: &str = "\x1b[38;2;199;154;43m";
const ANSI_NYX_MUTED: &str = "\x1b[38;2;159;163;173m";
const NYX_AGENT_TAGLINE: &str = "                       automated pentesting, refined";

const NYX_AGENT_BANNER: [(&str, &str); 6] = [
    ("███╗   ██╗██╗   ██╗██╗  ██╗", "     █████╗  ██████╗ ███████╗███╗   ██╗████████╗"),
    ("████╗  ██║╚██╗ ██╔╝╚██╗██╔╝", "    ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝"),
    ("██╔██╗ ██║ ╚████╔╝  ╚███╔╝", "     ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║"),
    ("██║╚██╗██║  ╚██╔╝   ██╔██╗", "     ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║"),
    ("██║ ╚████║   ██║   ██╔╝ ██╗", "    ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║"),
    ("╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝", "    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝"),
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
    for (nyx, agent) in NYX_AGENT_BANNER {
        if color {
            out.push_str(ANSI_NYX_GREEN);
            out.push_str(nyx);
            out.push_str(ANSI_NYX_GOLD);
            out.push_str(agent);
            out.push_str(ANSI_RESET);
        } else {
            out.push_str(nyx);
            out.push_str(agent);
        }
        out.push('\n');
    }
    if color {
        out.push_str(ANSI_NYX_MUTED);
        out.push_str(NYX_AGENT_TAGLINE);
        out.push_str(ANSI_RESET);
    } else {
        out.push_str(NYX_AGENT_TAGLINE);
    }
    out.push_str("\n\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_banner_renders_plain_solid_tagline() {
        let banner = startup_banner(false);

        assert!(banner.contains("███╗   ██╗"));
        assert!(banner.contains("automated pentesting, refined"));
        assert!(!banner.contains("\x1b["));
    }

    #[test]
    fn startup_banner_can_render_with_brand_colors() {
        let banner = startup_banner(true);

        assert!(banner.contains(ANSI_NYX_GREEN));
        assert!(banner.contains(ANSI_NYX_GOLD));
        assert!(banner.contains(ANSI_NYX_MUTED));
        assert!(banner.contains("automated pentesting, refined"));
    }
}
