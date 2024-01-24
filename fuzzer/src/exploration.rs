use anyhow::{Context, Result};
use archive::{tar::write_file_raw, ArchiveBuilder};
use common::fs::bufwriter;
use modeling::hardware::WriteTo;
use modeling::input::InputFile;
use qemu_rs::Address;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use common::FxHashSet;

#[derive(Debug, Clone, Hash)]
pub struct ExplorationCoverage {}

impl ExplorationCoverage {
    pub fn new() -> ExplorationCoverage {
        ExplorationCoverage {}
    }

    pub fn get_hash(&self) -> u64 {
        let mut s = DefaultHasher::new();
        self.hash(&mut s);
        s.finish()
    }
}

pub struct ExplorationMode {
    output_dir: PathBuf,
    unique_crashes: usize,
    // not crashing
    unique_inputs: usize,
}

fn create_dirs(output_dir: &PathBuf) -> Result<()> {
    let crashes = output_dir.join("exploration/crashes");
    let non_crashes = output_dir.join("exploration/non_crashes");

    if crashes.is_dir() {
        fs::remove_dir_all(crashes.clone()).context("remove crashes dir")?;
    }

    if non_crashes.is_dir() {
        fs::remove_dir_all(non_crashes.clone()).context("remove non_crashes dir")?;
    }

    fs::create_dir_all(crashes)?;
    fs::create_dir_all(non_crashes)?;

    Ok(())
}

impl ExplorationMode {
    pub fn new(output_dir: PathBuf) -> Result<Self> {
        create_dirs(&output_dir)?;

        Ok(ExplorationMode {
            output_dir,
            unique_crashes: 0,
            unique_inputs: 0,
        })
    }

    pub fn crashes_len(&self) -> usize {
        self.unique_crashes
    }

    pub fn non_crashes_len(&self) -> usize {
        self.unique_inputs
    }

    pub fn inputs_len(&self) -> usize {
        self.unique_inputs
    }

    pub fn save_crash(&mut self, f: &InputFile) -> Result<()> {
        let crash_path = self
            .output_dir
            .join(format!("exploration/crashes/input-{}.bin", f.id()));

        self.unique_crashes += 1;

        let writer = bufwriter(&crash_path).context("unable to create writer for crash path")?;

        return f.write_to(writer).context("failed to write crashing input");
    }

    pub fn save_input(&mut self, f: &InputFile) -> Result<()> {
        let non_crash_path = self
            .output_dir
            .join(format!("exploration/non_crashes/input-{}.bin", f.id()));

        let writer =
            bufwriter(&non_crash_path).context("unable to create writer for crash path")?;

        self.unique_inputs += 1;

        return f.write_to(writer).context("failed to write crashing input");
    }
}
