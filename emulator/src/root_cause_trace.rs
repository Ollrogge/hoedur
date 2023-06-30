use anyhow::{Context, Result};
use common::{fs::encoder, FxHashMap, FxHashSet};
use std::{
    fmt::{self, Debug},
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    sync::{atomic::Ordering, Arc},
};
use zstd::stream::AutoFinishEncoder;

pub struct RootCauseTrace {}

impl RootCauseTrace {
    pub fn new() -> Self {
        RootCauseTrace {}
    }

    pub fn on_instruction(&self, pc: u32) -> Result<()> {
        Ok(())
    }
}
