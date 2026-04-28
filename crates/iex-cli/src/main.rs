use std::ffi::OsString;

use anyhow::Result;
use clap::{Parser, Subcommand};

mod compat;
mod explain;
mod inspect;
mod search;

use compat::Invocation;
use explain::{run_explain_command, ExplainArgs};
use inspect::{run_inspect_command, InspectArgs};
use search::{run_matches_command, run_search_command, SearchArgs};

#[derive(Parser, Debug)]
#[command(
    name = "ix",
    about = "IX v2 intelligent expression toolkit",
    after_help = "SCHEMA\n  expr: lit:text | re:pattern | prefix:x | suffix:x | A && B | A || B\nSNIPS\n  ix error src\n  ix search 'lit:fn' crates --json\n  ix matches 're:TODO|FIXME' .\n  ix inspect src/main.rs --range 40:80\n  ix inspect --expr 'lit:SearchConfig' crates --context 2 --json"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    Search(SearchArgs),
    Matches(SearchArgs),
    Inspect(InspectArgs),
    Explain(ExplainArgs),
}

fn main() -> Result<()> {
    let raw_args: Vec<OsString> = std::env::args_os().collect();
    match compat::route_invocation(raw_args)? {
        Invocation::Canonical(command) => dispatch_command(command),
        Invocation::Compat(args) => run_search_command(args),
    }
}

fn dispatch_command(command: Command) -> Result<()> {
    match command {
        Command::Search(args) => run_search_command(args),
        Command::Matches(args) => run_matches_command(args),
        Command::Inspect(args) => run_inspect_command(args),
        Command::Explain(args) => run_explain_command(args),
    }
}
