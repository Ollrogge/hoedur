use std::{fmt, io, path::PathBuf};

use anyhow::{Context, Result};
use archive::{tar::write_file_raw, Archive, ArchiveBuilder};
use clap::Parser;
use common::{
    fs::decoder,
    hashbrown::hash_map::Entry,
    log::{init_log, LOG_INFO},
    FxHashMap,
};
use fuzzer::{CorpusEntry, CorpusEntryKind};
use hoedur::coverage::{CoverageReport, CrashReason};
use modeling::input::InputId;
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(name = "hoedur-eval-crash")]
struct Arguments {
    #[arg(long, default_value = LOG_INFO)]
    log_config: PathBuf,

    #[arg(long)]
    yaml: bool,

    report: PathBuf,

    #[arg(long)]
    sort_by_shortest_input: bool,

    #[arg(long)]
    corpus_archive: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
struct CrashTime {
    time: u64,
    source: CrashSource,
}

#[derive(Debug, Clone, Serialize)]
struct CrashSource {
    input: InputId,
    report: Option<String>,
}

impl fmt::Display for CrashTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:>7} s", self.time)
    }
}

impl fmt::Display for CrashSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Input id {}", self.input)?;

        if let Some(report) = &self.report {
            write!(f, " ({report})")
        } else {
            Ok(())
        }
    }
}

fn first_occurence(opt: Arguments) -> Result<()> {
    let mut crashes = FxHashMap::default();

    log::info!("Loading coverage report {:?} ...", opt.report);

    let report =
        CoverageReport::load_from(&opt.report).context("Failed to load coverage report")?;

    // find first occurrence for each crash
    for input in report.inputs() {
        // collect crash reason
        let reason = match input.crash_reason() {
            Some(reason) => reason,
            None => {
                continue;
            }
        };

        // get meta info
        let time = match input.timestamp() {
            Some(time) => time,
            None => {
                log::debug!("skipping input {} without timestamp", input.id());
                continue;
            }
        };
        let source = || CrashSource {
            input: input.id(),
            report: opt
                .report
                .file_name()
                .map(|filename| filename.to_string_lossy().to_string()),
        };

        match crashes.entry(reason.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(CrashTime {
                    time,
                    source: source(),
                });
            }
            Entry::Occupied(entry) => {
                let crash_time = entry.into_mut();
                if time < crash_time.time {
                    crash_time.time = time;
                    crash_time.source = source();
                }
            }
        }
    }

    // sort by crash time
    let mut crashes: Vec<_> = crashes.into_iter().collect();
    crashes.sort_by(|a, b| a.1.time.cmp(&b.1.time));

    // print crashes with time
    if opt.yaml {
        serde_yaml::to_writer(io::stdout(), &crashes).context("Failed to serialize crashes")
    } else {
        for (crash, crash_time) in crashes {
            println!("{} : {:x?} :\t {}", crash_time, crash, crash_time.source);
        }

        Ok(())
    }
}

fn shortest_input(opt: Arguments) -> Result<()> {
    log::info!("Loading coverage report {:?} ...", opt.report);
    let report = CoverageReport::load_from(&opt.report)
        .with_context(|| format!("Failed to load coverage report {:?}", opt.report))?;

    // collect input->crash reason mapping
    let mut inputs = FxHashMap::default();
    for input in report.inputs() {
        if let Some(crash_reason) = input.crash_reason() {
            inputs.insert(input.id(), crash_reason);
        }
    }

    let corpus_archive = opt.corpus_archive.unwrap();

    log::info!("Loading corpus archive {} ...", corpus_archive.display());
    let mut corpus_archive =
        Archive::from_reader(decoder(&corpus_archive).context("Failed to load corpus archive")?);

    // copy config files + collect inputs
    let mut reproducers = FxHashMap::default();
    for entry in corpus_archive.iter::<CorpusEntryKind>()? {
        let mut entry = entry?;

        match entry.kind() {
            Some(CorpusEntryKind::Common(_))
            | Some(CorpusEntryKind::Emulator(_))
            | Some(CorpusEntryKind::Modeling(_))
            | Some(CorpusEntryKind::Fuzzer(_)) => {
                continue;
            }
            Some(CorpusEntryKind::InputFile(_)) => {
                if let CorpusEntry::InputFile { input, .. } =
                    entry.parse_entry().unwrap().with_context(|| {
                        format!("Failed to parse input file {:?}", entry.header().path())
                    })?
                {
                    // collect shortest input per crash reason
                    if let Some(crash_reason) = inputs.get(&input.id()) {
                        match reproducers.entry(crash_reason) {
                            Entry::Vacant(entry) => {
                                entry.insert(input);
                            }
                            Entry::Occupied(mut entry) => {
                                let reproducer = entry.get_mut();

                                if input.len() < reproducer.len() {
                                    *reproducer = input;
                                }
                            }
                        }
                    }
                } else {
                    unreachable!()
                }
            }
            None => {
                log::warn!(
                    "unknown corpus entry at {:?}",
                    entry.header().path().unwrap_or_default()
                );
            }
        }
    }

    let mut crashes = Vec::new();
    for (reason, input) in reproducers {
        crashes.push((
            reason,
            CrashSource {
                input: input.id(),
                report: opt
                    .report
                    .file_name()
                    .map(|filename| filename.to_string_lossy().to_string()),
            },
        ));
    }

    // sort by crash time
    let reproducers: Vec<_> = crashes;
    // print crashes with time
    if opt.yaml {
        serde_yaml::to_writer(io::stdout(), &reproducers).context("Failed to serialize crashes")
    } else {
        for (crash, crash_source) in reproducers {
            println!(
                "Shortest input for crash : {:x?} :\t {}",
                crash, crash_source
            );
        }
        Ok(())
    }
}

fn main() -> Result<()> {
    let opt = Arguments::parse();

    init_log(&opt.log_config)?;
    log::trace!("Args: {:#?}", opt);

    if opt.sort_by_shortest_input {
        shortest_input(opt)
    } else {
        first_occurence(opt)
    }
}
