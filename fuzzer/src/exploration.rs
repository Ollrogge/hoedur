use anyhow::{anyhow, Context, Result};
use archive::tar::write_file;
use archive::{create_archive, tar::write_file_raw, Archive, ArchiveBuilder};
use modeling::hardware::WriteTo;
use modeling::input::InputFile;
use qemu_rs::Address;
use std::collections::hash_map::DefaultHasher;
use std::{
    hash::{Hash, Hasher},
    path::PathBuf,
};

use common::FxHashSet;

#[derive(Debug, Clone, Hash)]
pub struct ExplorationCoverage {
    pc: Address,
    ra: Address,
    basic_blocks: usize,
    mmio_read: usize,
    mmio_write: usize,
    input_stream_len: usize,
}

impl ExplorationCoverage {
    pub fn new(
        pc: Address,
        ra: Address,
        basic_blocks: usize,
        mmio_read: usize,
        mmio_write: usize,
        input_stream_len: usize,
    ) -> ExplorationCoverage {
        ExplorationCoverage {
            pc,
            ra,
            basic_blocks,
            mmio_read,
            mmio_write,
            input_stream_len,
        }
    }

    pub fn get_hash(&self) -> u64 {
        let mut s = DefaultHasher::new();
        self.hash(&mut s);
        s.finish()
    }
}

pub struct ExplorationMode {
    crash_archive: ArchiveBuilder,
    none_crash_archive: ArchiveBuilder,
    unique_crashes: FxHashSet<u64>,
    unique_none_crashes: FxHashSet<u64>,
}

impl ExplorationMode {
    pub fn new(archive_dir: PathBuf) -> Result<Self> {
        let crash_archive = create_archive(&archive_dir, "exploration_crash", true, true)
            .map(ArchiveBuilder::from)?;

        let not_crash_archive = create_archive(&archive_dir, "exploration_not_crash", true, false)
            .map(ArchiveBuilder::from)?;

        Ok(ExplorationMode {
            crash_archive,
            none_crash_archive: not_crash_archive,
            unique_crashes: FxHashSet::default(),
            unique_none_crashes: FxHashSet::default(),
        })
    }

    pub fn save_crash(&mut self, cov: ExplorationCoverage, f: &InputFile) -> Result<()> {
        if self.unique_crashes.insert(cov.get_hash()) {
            println!(
                "Found another crash: pc:{} ra:{}, basic blocks: {}, input stream length: {}",
                cov.pc, cov.ra, cov.basic_blocks, cov.input_stream_len,
            );

            return write_file_raw(
                &mut self.crash_archive.borrow_mut(),
                &format!("crashes/input-{}.bin", f.id()),
                f.write_size()?,
                0,
                |writer| f.write_to(writer),
            )
            .context("Failed to save crashing input");
        }
        log::info!("Crashing archive len: {}", self.unique_crashes.len());
        Ok(())
    }

    pub fn save_none_crash(&mut self, cov: ExplorationCoverage, f: &InputFile) -> Result<()> {
        // todo find a better way to reduce crashing input amount
        // check how AFL does it
        if self.unique_crashes.len() * 2 < self.unique_none_crashes.len() {
            return Ok(());
        }
        if self.unique_none_crashes.insert(cov.get_hash()) {
            return write_file_raw(
                &mut self.none_crash_archive.borrow_mut(),
                &format!("not_crashes/input-{}.bin", f.id()),
                f.write_size()?,
                0,
                |writer| f.write_to(writer),
            )
            .context("Failed to save non crashing input");
        }
        log::info!(
            "None crashing archive len: {}",
            self.unique_none_crashes.len()
        );
        Ok(())
    }
}
