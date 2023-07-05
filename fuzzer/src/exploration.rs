use anyhow::{anyhow, Context, Result};
use archive::{create_archive, tar::write_file_raw, write_config, Archive, ArchiveBuilder};
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
    archive: ArchiveBuilder,
    unique_crashes: FxHashSet<u64>,
    // not crashing
    unique_inputs: FxHashSet<u64>,
}

impl ExplorationMode {
    pub fn new(archive: ArchiveBuilder) -> Result<Self> {
        Ok(ExplorationMode {
            archive,
            unique_crashes: FxHashSet::default(),
            unique_inputs: FxHashSet::default(),
        })
    }

    pub fn crashes_len(&self) -> usize {
        self.unique_crashes.len()
    }

    pub fn inputs_len(&self) -> usize {
        self.unique_inputs.len()
    }

    pub fn save_crash(&mut self, cov: ExplorationCoverage, f: &InputFile) -> Result<()> {
        if self.unique_crashes.insert(cov.get_hash()) {
            /*
            println!(
                "Found another crash: pc:{} ra:{}, basic blocks: {}, input stream length: {}",
                cov.pc, cov.ra, cov.basic_blocks, cov.input_stream_len,
            );
            */

            return write_file_raw(
                &mut self.archive.borrow_mut(),
                &format!("crash/input-{}.bin", f.id()),
                f.write_size()?,
                0,
                |writer| f.write_to(writer),
            )
            .context("Failed to save crashing input");
        }
        log::info!("Crashing archive len: {}", self.unique_crashes.len());
        Ok(())
    }

    pub fn save_input(&mut self, cov: ExplorationCoverage, f: &InputFile) -> Result<()> {
        // todo find a better way to reduce crashing input amount
        // check how AFL does it
        if self.unique_crashes.len() * 2 < self.unique_inputs.len() {
            return Ok(());
        }
        if self.unique_inputs.insert(cov.get_hash()) {
            return write_file_raw(
                &mut self.archive.borrow_mut(),
                &format!("input/input-{}.bin", f.id()),
                f.write_size()?,
                0,
                |writer| f.write_to(writer),
            )
            .context("Failed to save non crashing input");
        }
        log::info!("None crashing archive len: {}", self.unique_inputs.len());
        Ok(())
    }
}
