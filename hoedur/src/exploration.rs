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
    pub inputs: Vec<PathBuf>,
    pub archive: ArchiveBuilder,
    pub archive_dir: PathBuf,
    pub prefix_input: Vec<PathBuf>,
}

impl ExplorationConfig {
    pub fn new(
        inputs: Vec<PathBuf>,
        archive: ArchiveBuilder,
        archive_dir: PathBuf,
        prefix_input: Vec<PathBuf>,
    ) -> Self {
        Self {
            inputs,
            archive,
            archive_dir,
            prefix_input,
        }
    }

    pub fn from_cli(name: &str, args: ExplorationArguments) -> Result<Self> {
        println!("Name?: {:?}", name);
        let archive = create_archive(&args.archive_dir.archive_dir, "root_cause", true, false)
            .map(ArchiveBuilder::from)?;

        Ok(Self::new(
            args.inputs,
            archive,
            args.archive_dir.archive_dir,
            args.prefix.prefix_input,
        ))
    }
}

pub fn run_fuzzer(
    emulator: Emulator,
    config: ExplorationConfig,
    import_files: Vec<InputFile>,
) -> Result<()> {
    Fuzzer::new(
        "root_cause".to_string(),
        None,
        vec![],
        import_files,
        false,
        true,
        config.archive,
        emulator,
    )?
    .run_exploration(config.archive_dir)?;

    Ok(())
}
