use crate::cli::ExplorationArguments;
use crate::Emulator;
use anyhow::{Context, Result};
use archive::{create_archive, ArchiveBuilder};
use fuzzer::Fuzzer;
use regex::Regex;
use std::path::PathBuf;

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
        let re = Regex::new(r"#(\d+)").context("regex")?;
        let crash_id = re
            .captures(args.import_corpus[0].to_str().unwrap())
            .and_then(|caps| caps.get(1))
            .context("get crash id from pathbuf")?;
        let archive = create_archive(
            &args.archive_dir.archive_dir,
            &format!("crash-#{}.exploration", crash_id.as_str()),
            true,
            false,
        )
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
