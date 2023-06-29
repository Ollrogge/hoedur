use std::path::PathBuf;

use anyhow::{Context, Result};
use archive::{tar::write_file_raw, Archive, ArchiveBuilder};
use clap::Parser;
use common::{
    fs::{bufwriter, decoder},
    hashbrown::hash_map::Entry,
    log::{init_log, LOG_INFO},
    FxHashMap,
};
use fuzzer::{CorpusEntry, CorpusEntryKind};
use hoedur::coverage::CoverageReport;
use modeling::hardware::WriteTo;
use modeling::input::InputId;

#[derive(Parser, Debug)]
#[command(name = "hoedur-crash-archive")]
pub struct Arguments {
    #[arg(long, default_value = LOG_INFO)]
    pub log_config: PathBuf,

    /// Output dir for config archive + reproducer inputs
    pub output: PathBuf,

    /// Corpus archive file
    #[arg(long)]
    pub corpus_archive: PathBuf,

    /// Coverage report file
    #[arg(long)]
    pub report: PathBuf,

    // Input id of a specific crash
    #[arg(long)]
    pub input_id: Option<InputId>,
}

fn main() -> Result<()> {
    let opt = Arguments::parse();

    init_log(&opt.log_config)?;
    log::trace!("Args: {:#?}", opt);

    Ok(())
}
