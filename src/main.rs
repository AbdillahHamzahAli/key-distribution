use std::io::IsTerminal;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use key_distribution::apps::{kdc_server, peer};
use key_distribution::tui;

#[derive(Parser)]
#[command(
    name = "key-distribution",
    version,
    about = "Interactive KDC key distribution and encrypted chat with manual AES-128"
)]
struct Cli {
    /// Use the line-based interface instead of the full-screen TUI.
    #[arg(long, global = true, conflicts_with = "tui")]
    plain: bool,
    /// Force the full-screen TUI even when stdout is not a terminal.
    #[arg(long, global = true)]
    tui: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the Key Distribution Center.
    Kdc,
    /// Run a peer (prompts for Alice/Bob unless --role is given).
    Peer {
        #[arg(long, value_enum)]
        role: Option<Role>,
    },
    /// Run Alice (initiator).
    Alice,
    /// Run Bob (responder).
    Bob,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Role {
    Alice,
    Bob,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let tui_enabled = if cli.plain {
        false
    } else if cli.tui {
        true
    } else {
        std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
    };

    if !tui_enabled {
        install_ctrl_c();
    }

    let result = match cli.command {
        Command::Kdc => {
            if tui_enabled {
                tui::run_kdc()
            } else {
                kdc_server::run()
            }
        }
        Command::Peer { role } => {
            let role = role.map(|role| match role {
                Role::Alice => peer::PeerRole::Alice,
                Role::Bob => peer::PeerRole::Bob,
            });
            if tui_enabled {
                tui::run_peer(role)
            } else {
                peer::run_peer(role)
            }
        }
        Command::Alice => {
            if tui_enabled {
                tui::run_peer(Some(peer::PeerRole::Alice))
            } else {
                peer::run_peer(Some(peer::PeerRole::Alice))
            }
        }
        Command::Bob => {
            if tui_enabled {
                tui::run_peer(Some(peer::PeerRole::Bob))
            } else {
                peer::run_peer(Some(peer::PeerRole::Bob))
            }
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn install_ctrl_c() {
    let _ = ctrlc::set_handler(|| {
        eprintln!("\n[!] interrupted, shutting down");
        std::process::exit(130);
    });
}
