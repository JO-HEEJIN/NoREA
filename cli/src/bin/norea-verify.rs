//! norea-verify: verify evidence or a disclosure package without any secret.
//! WP-00 skeleton: `--help` only. Subcommands come in WP-05 (CORE-API.md §3).

use clap::Parser;

#[derive(Parser)]
#[command(name = "norea-verify", version, about = "Verify NoREA evidence or disclosure packages (no secrets needed). Not implemented yet.")]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
    eprintln!("norea-verify: not implemented yet (WP-05)");
    std::process::exit(2);
}
