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
    pub output_dir: PathBuf,
    pub import_corpus: Vec<PathBuf>,
    pub prefix_input: Vec<PathBuf>,
    pub duration: u64,
}

impl ExplorationConfig {
    pub fn new(
        archive: ArchiveBuilder,
        output_dir: PathBuf,
        import_corpus: Vec<PathBuf>,
        prefix_input: Vec<PathBuf>,
        duration: u64,
    ) -> Self {
        Self {
            archive,
            output_dir,
            import_corpus,
            prefix_input,
            duration,
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

        let duration = args
            .duration
            .parse::<u64>()
            .context("unable to parse exploration duration to u64")?;

        Ok(Self::new(
            archive,
            args.archive_dir.archive_dir,
            args.import_corpus,
            args.prefix.prefix_input,
            duration,
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
    .run_exploration3(config.output_dir, config.duration)?;

    Ok(())
}
