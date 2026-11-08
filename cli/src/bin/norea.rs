//! norea: developer and test tool (inspect, protect with test key files).
//! WP-00 skeleton: `--help` only. Subcommands come in WP-05 (CORE-API.md §3).

use clap::Parser;

#[derive(Parser)]
#[command(name = "norea", version, about = "NoREA developer tool. Not implemented yet.")]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
    eprintln!("norea: not implemented yet (WP-05)");
    std::process::exit(2);
}
