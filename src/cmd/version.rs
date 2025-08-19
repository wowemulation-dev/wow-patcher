use clap::Parser;

#[derive(Parser, Debug)]
pub struct VersionArgs {
    /// Show detailed version information
    #[arg(short = 'd', long = "detailed")]
    pub detailed: bool,
}

pub fn execute(args: VersionArgs) {
    if args.detailed {
        println!("{}", crate::version::detailed_info());
    } else {
        println!("{}", crate::version::info());
    }
}