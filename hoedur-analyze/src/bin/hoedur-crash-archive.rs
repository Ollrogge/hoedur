use std::fs::read;
use std::{borrow::Borrow, path::PathBuf};

use anyhow::{anyhow, Context, Result};
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
use modeling::input::{InputFile, InputId};

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

    // Input id of a specific crash
    #[arg(long)]
    pub input_id: Option<InputId>,

    #[arg(long)]
    pub input: Option<PathBuf>,
}

fn main() -> Result<()> {
    let opt = Arguments::parse();

    init_log(&opt.log_config)?;
    log::trace!("Args: {:#?}", opt);

    log::info!(
        "Loading corpus archive {} ...",
        opt.corpus_archive.display()
    );
    let mut corpus_archive = Archive::from_reader(
        decoder(&opt.corpus_archive).context("Failed to load corpus archive")?,
    );

    if opt.input.is_none() && opt.input_id.is_none() {
        return Err(anyhow!("Neither input file nor input id was provided"));
    }

    let exploration_archive = match opt.input_id {
        Some(id) => archive::create_archive(&opt.output, &format!("crash-{}", id), true, true)
            .map(ArchiveBuilder::from)
            .context("Failed to create config archive")?,
        None => {
            let id = 0;
            let archive =
                archive::create_archive(&opt.output, &format!("crash-#{}", id), true, true)
                    .map(ArchiveBuilder::from)
                    .context("Failed to create config archive")?;

            let input = InputFile::read_from_path(opt.input.unwrap().as_path())?;

            write_file_raw(
                &mut archive.borrow_mut(),
                &format!("input/input-{}.bin", id),
                input.write_size()?,
                0,
                |writer| input.write_to(writer),
            )
            .context("Failed to write crash input to corpus")?;

            archive
        }
    };

    for entry in corpus_archive.iter::<CorpusEntryKind>()? {
        let mut entry = entry?;

        match entry.kind() {
            Some(CorpusEntryKind::Common(_))
            | Some(CorpusEntryKind::Emulator(_))
            | Some(CorpusEntryKind::Modeling(_)) => {
                let header = entry.header().clone();
                exploration_archive
                    .borrow_mut()
                    .append(&header, entry.raw_entry())
                    .with_context(|| {
                        format!(
                            "Failed to append {:?} to config archive",
                            header.path().unwrap_or_default(),
                        )
                    })?;
            }
            Some(CorpusEntryKind::InputFile(_)) => {
                if let CorpusEntry::InputFile { input, .. } =
                    entry.parse_entry().unwrap().with_context(|| {
                        format!("Failed to parse input file {:?}", entry.header().path())
                    })?
                {
                    if opt.input_id.is_some() {
                        if input.id() == opt.input_id.unwrap() {
                            write_file_raw(
                                &mut exploration_archive.borrow_mut(),
                                &format!("input/input-{}.bin", input.id()),
                                input.write_size()?,
                                0,
                                |writer| input.write_to(writer),
                            )
                            .context("Failed to write crash input to corpus")?;
                        }
                    }
                } else {
                    unreachable!()
                }
            }
            Some(CorpusEntryKind::Fuzzer(_)) => {
                // remove fuzzer statistics
                log::debug!("skipping corpus entry {:#?}", entry.header().path());
            }
            None => {
                log::warn!(
                    "unknown corpus entry at {:?}",
                    entry.header().path().unwrap_or_default()
                );
            }
        }
    }

    Ok(())
}
