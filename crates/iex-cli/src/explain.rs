use std::io::Write;

use anyhow::Result;
use clap::Args;
use iex_core::ExpressionPlan;

#[derive(Args, Debug)]
pub struct ExplainArgs {
    #[arg(help = "Expression to parse into an IX plan")]
    pub expr: String,
}

pub fn run_explain_command(args: ExplainArgs) -> Result<()> {
    let plan = ExpressionPlan::parse(&args.expr)?;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer(&mut handle, &plan)?;
    handle.write_all(b"\n")?;
    Ok(())
}
