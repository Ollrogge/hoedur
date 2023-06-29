use crate::cli::ExplorationArguments;
use crate::coverage::{CoverageReport, CrashReason};
use crate::Emulator;
use anyhow::{Context, Result};
use archive::{
    create_archive,
    tar::{write_file, write_serialized},
    Archive, ArchiveBuilder,
};
use common::fs::{bufwriter, decoder};
use core::arch;
use fuzzer::Fuzzer;
use fuzzer::{CorpusEntry, CorpusEntryKind, CorpusInputFile, IntoInputFileIter, Mode};
use modeling::hardware::{Input, WriteTo};
use modeling::input::{InputFile, InputId};
use nix::libc::creat;
use qemu_rs::Address;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct ExplorationConfig {
    pub archive: ArchiveBuilder,
    pub import_corpus: Vec<PathBuf>,
    pub prefix_input: Vec<PathBuf>,
}

impl ExplorationConfig {
    pub fn new(
        archive: ArchiveBuilder,
        import_corpus: Vec<PathBuf>,
        prefix_input: Vec<PathBuf>,
    ) -> Self {
        Self {
            archive,
            import_corpus,
            prefix_input,
        }
    }

    pub fn from_cli(name: &str, args: ExplorationArguments) -> Result<Self> {
        println!("Name?: {:?}", name);
        let archive = create_archive(&args.archive_dir.archive_dir, "exploration", true, false)
            .map(ArchiveBuilder::from)?;

        Ok(Self::new(
            archive,
            args.import_corpus,
            args.prefix.prefix_input,
        ))
    }
}

pub fn run_fuzzer(emulator: Emulator, config: ExplorationConfig) -> Result<()> {
    Fuzzer::new(
        "root_cause".to_string(),
        None,
        config.import_corpus,
        false,
        true,
        config.archive.clone(),
        emulator,
    )?
    .run_exploration(config.archive)?;

    Ok(())
}
