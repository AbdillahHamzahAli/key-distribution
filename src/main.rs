use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use key_distribution::apps::{kdc_server, peer};

#[derive(Parser)]
#[command(
    name = "key-distribution",
    version,
    about = "Interactive KDC key distribution and encrypted chat with manual AES-128"
)]
struct Cli {
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
    install_ctrl_c();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Kdc => kdc_server::run(),
        Command::Peer { role } => peer::run_peer(role.map(|role| match role {
            Role::Alice => peer::PeerRole::Alice,
            Role::Bob => peer::PeerRole::Bob,
        })),
        Command::Alice => peer::run_peer(Some(peer::PeerRole::Alice)),
        Command::Bob => peer::run_peer(Some(peer::PeerRole::Bob)),
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
