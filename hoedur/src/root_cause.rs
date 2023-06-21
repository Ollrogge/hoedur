use crate::cli::RootCauseArguments;
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
use fuzzer::{CorpusEntry, CorpusEntryKind, CorpusInputFile, IntoInputFileIter};
use modeling::hardware::{Input, WriteTo};
use modeling::input::{InputFile, InputId};
use nix::libc::creat;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct RootCauseConfig {
    pub inputs: Vec<PathBuf>,
    pub archive: ArchiveBuilder,
    pub archive_dir: PathBuf,
    pub prefix_input: Vec<PathBuf>,
}

impl RootCauseConfig {
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

    pub fn from_cli(name: &str, args: RootCauseArguments) -> Result<Self> {
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
    config: RootCauseConfig,
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
    .run_exploration()?;

    Ok(())
}

#[derive(Debug, Clone)]
pub struct CrashSource {
    input: InputId,
    report: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CrashInfo {
    time: u64,
    source: CrashSource,
    input: CorpusInputFile,
}

impl CrashInfo {
    pub fn new(time: u64, source: CrashSource, input: CorpusInputFile) -> CrashInfo {
        CrashInfo {
            time,
            source,
            input,
        }
    }

    pub fn from_input_id(
        id: InputId,
        corpus_path: PathBuf,
        report_path: PathBuf,
    ) -> Result<CrashInfo> {
        let report = CoverageReport::load_from(&report_path)
            .context(format!("Failed to load coverage report: {:?}", report_path))?;

        let mut corpus_archive = Archive::from_reader(decoder(corpus_path.as_path())?);

        let input_file = corpus_archive
            .iter()?
            .input_files()
            .find(|f| f.is_ok() && f.as_ref().unwrap().input.id() == id)
            .ok_or_else(|| anyhow::anyhow!("Unable to find InputFile matching id"))
            .context("Unable to find InputFile matching input id")??;

        let input_coverage = report
            .inputs()
            .iter()
            .find(|&f| f.crash_reason().is_some() && f.timestamp().is_some() && f.id() == id)
            .context("Unable to find InputCoverage matching input id")?;

        let source = || CrashSource {
            input: input_coverage.id(),
            report: report_path
                .file_name()
                .map(|filename| filename.to_string_lossy().to_string()),
        };

        Ok(CrashInfo {
            time: input_coverage.timestamp().unwrap(),
            source: source(),
            input: input_file,
        })
    }

    pub fn write_crash_archive(&mut self, dir: PathBuf) {}
}

pub struct RootCauseAnalysis {
    working_dir: PathBuf,
}

impl RootCauseAnalysis {
    pub fn new(
        input_id: InputId,
        corpus_path: PathBuf,
        report_path: PathBuf,
    ) -> Result<RootCauseAnalysis> {
        let mut crashing_input: Option<InputFile> = None;

        let mut base_dir = corpus_path.clone().parent().unwrap().to_owned();

        let mut corpus_archive = Archive::from_reader(decoder(corpus_path.as_path())?);

        let mut config_archive = archive::create_archive(&base_dir, "config", true, true)
            .context("Failed to create config archive")?;

        for entry in corpus_archive.iter::<CorpusEntryKind>()? {
            let mut entry = entry?;

            match entry.kind() {
                Some(CorpusEntryKind::Common(_))
                | Some(CorpusEntryKind::Emulator(_))
                | Some(CorpusEntryKind::Modeling(_)) => {
                    let header = entry.header().clone();
                    config_archive
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
                        match crashing_input.as_ref() {
                            Some(v) => {
                                if input.len() < v.len() {
                                    crashing_input = Some(input)
                                }
                            }
                            None => crashing_input = Some(input),
                        }
                    } else {
                        // InputId should uniquely identify existing input I think ?
                        unreachable!();
                    }
                }
                Some(CorpusEntryKind::Fuzzer(_)) => {}
                None => {
                    log::warn!(
                        "unknown corpus entry at {:?}",
                        entry.header().path().unwrap_or_default()
                    );
                }
            }
        }

        let crashing_input = crashing_input.unwrap();

        let input_path = base_dir.join(format!("input-{}-reproducer.bin", crashing_input.id()));

        crashing_input
            .write_to(bufwriter(&input_path)?)
            .with_context(|| format!("Failed to write reproducer input file {:?}", input_path))?;

        Ok(RootCauseAnalysis {
            working_dir: base_dir,
        })
    }

    pub fn config_path(&self) -> PathBuf {
        let mut path = self.working_dir.clone();
        path.push("config.corpus.tar.zst");

        path
    }
}
