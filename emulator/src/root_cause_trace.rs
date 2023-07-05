use anyhow::{Context, Result};
use common::{fs::encoder, hashbrown::hash_map::Entry, FxHashMap, FxHashSet};
use rune::ast::In;
use serde::Serialize;
use std::cmp::min;
use std::collections::HashMap;
use std::convert::TryInto;
use std::{
    fmt::{self, Debug},
    fs::File,
    io::{BufWriter, Write},
    path::Path,
    path::PathBuf,
    sync::{atomic::Ordering, Arc},
};
use zstd::stream::AutoFinishEncoder;

use qemu_rs::{qcontrol, register, Address, Register};

use trace_analysis::trace::{self, SerializedEdge, SerializedInstruction, SerializedTrace};

use crate::StopReason;

#[derive(Serialize)]
enum EdgeType {
    Direct,
    Indirect,
    Conditional,
    Syscall,
    Return,
    Regular,
    Unknown,
}

#[derive(PartialEq, Eq, Hash, Serialize)]
struct Edge {
    from: Address,
    to: Address,
}

impl Edge {
    pub fn to_serialized_edge(&self, count: u64) -> SerializedEdge {
        SerializedEdge::new(self.from as usize, self.to as usize, count as usize)
    }
}

#[derive(Serialize)]
struct EdgeInfo {
    typ: EdgeType,
    count: u64,
}

#[derive(Copy, Clone, Serialize)]
struct Value {
    is_set: bool,
    value: u32,
}

#[derive(Serialize)]
struct MemoryData {
    tmp: u32,
}

impl MemoryData {
    pub fn new() -> MemoryData {
        MemoryData { tmp: 0 }
    }
}

type Registers = [Value; Register::AMOUNT];

#[derive(Serialize)]
struct InstructionData {
    /// how often instruction was called
    count: usize,
    mnemonic: String,
    /// min values for each register
    min_vals: Registers,
    /// max values for each register
    max_vals: Registers,
    last_vals: Registers,
    last_successor: Address,
    // todo: leverage memory models to derive the memory access data ?
    mem: MemoryData,
}

impl InstructionData {
    pub fn new(disas: String) -> InstructionData {
        InstructionData {
            count: 0,
            mnemonic: disas,
            min_vals: [Value {
                is_set: false,
                value: u32::MAX,
            }; Register::AMOUNT],
            max_vals: [Value {
                is_set: false,
                value: 0,
            }; Register::AMOUNT],
            last_vals: [Value {
                is_set: false,
                value: 0,
            }; Register::AMOUNT],
            last_successor: 0,
            mem: MemoryData::new(),
        }
    }

    pub fn to_serialized_instruction(&self, pc: Address) -> trace::SerializedInstruction {
        let mut min_vals: HashMap<usize, trace::Register> = Default::default();
        let mut max_vals: HashMap<usize, trace::Register> = Default::default();
        let mut last_vals: HashMap<usize, trace::Register> = Default::default();

        let insert_if_set = |registers: &mut HashMap<usize, trace::Register>,
                             values: &Registers| {
            for (i, v) in values.into_iter().enumerate() {
                if v.is_set {
                    registers.insert(i, trace::Register::from(v.value as u64));
                }
            }
        };

        insert_if_set(&mut min_vals, &self.min_vals);
        insert_if_set(&mut max_vals, &self.max_vals);
        insert_if_set(&mut last_vals, &self.last_vals);

        SerializedInstruction {
            address: pc as usize,
            mnemonic: self.mnemonic.clone(),
            registers_min: trace::Registers::from(min_vals),
            registers_max: trace::Registers::from(max_vals),
            registers_last: trace::Registers::from(last_vals),
            last_successor: self.last_successor as usize,
            count: self.count,
            memory: None,
        }
    }
}

#[derive(Serialize)]
struct Trace<'a> {
    instructions: &'a FxHashMap<Address, InstructionData>,
    edges: &'a FxHashMap<Edge, EdgeInfo>,
}

impl<'a> Trace<'a> {
    pub fn new(
        instructions: &'a FxHashMap<Address, InstructionData>,
        edges: &'a FxHashMap<Edge, EdgeInfo>,
    ) -> Trace<'a> {
        Trace {
            instructions,
            edges,
        }
    }

    pub fn write_to<W: Write>(&self, stream: &mut W) -> Result<()> {
        Ok(bincode::serialize_into(stream, self)?)
    }
}

// decided for HashMap and not BtreeMap which would be closer to std::map they use
// since I expect a lot of instructions to be executed multiple times ? in this
// case O(1) lookup seems nice.
// todo: need to sort stuff in the end though if needed
pub struct RootCauseTrace {
    instructions: FxHashMap<Address, InstructionData>,
    edges: FxHashMap<Edge, EdgeInfo>,
    reg_state: [u32; Register::AMOUNT],
    prev_edge_type: EdgeType,
    prev_ins_addr: Address,
    first_address: Address,
    image_base: Address,
    trace_dir: Option<PathBuf>,
    trace_cnt: u64,
}

impl RootCauseTrace {
    pub fn new(trace_file_path: Option<PathBuf>) -> Self {
        let trace_dir = if let Some(path) = trace_file_path {
            let parent = path.parent().unwrap_or_else(|| &Path::new("."));
            Some(parent.to_path_buf())
        } else {
            None
        };

        RootCauseTrace {
            instructions: FxHashMap::default(),
            edges: FxHashMap::default(),
            reg_state: [0; Register::AMOUNT],
            prev_edge_type: EdgeType::Unknown,
            prev_ins_addr: 0,
            first_address: 0,
            image_base: 0,
            trace_dir,
            trace_cnt: 0,
        }
    }

    pub fn on_instruction(&mut self, pc: u32) -> Result<()> {
        if self.instructions.len() == 0x0 {
            self.first_address = pc;
        }
        self.update_instructions(pc)?;
        self.update_edges(pc)
    }

    pub fn post_run(&mut self, stop_reason: &Option<StopReason>) -> Result<()> {
        let (trace_dir, stop_reason) = match (self.trace_dir.as_mut(), stop_reason) {
            (Some(a), Some(b)) => (a, b),
            (_, _) => return Ok(()),
        };

        log::info!("Writing serialized trace to file");

        let instructions = self
            .instructions
            .iter()
            .map(|(pc, inst)| inst.to_serialized_instruction(*pc))
            .collect();

        let edges = self
            .edges
            .iter()
            .map(|(edge, edgeinfo)| edge.to_serialized_edge(edgeinfo.count))
            .collect();

        let trace = SerializedTrace {
            instructions,
            edges,
            first_address: self.first_address as usize,
            last_address: self.prev_ins_addr as usize,
            image_base: self.image_base as usize,
        };

        self.trace_cnt += 1;

        let stream = match stop_reason {
            StopReason::Crash { .. } => {
                trace_dir.push(format!("crashes/{}.bin", self.trace_cnt));
                encoder(&trace_dir)
            }
            _ => {
                trace_dir.push(format!("non_crashes/{}.bin", self.trace_cnt));
                encoder(&trace_dir)
            }
        }
        .context("Unable to open trace file")?;
        trace_dir.pop();
        trace_dir.pop();
        self.reset();

        Ok(bincode::serialize_into(stream, &trace)?)
    }

    fn reset(&mut self) {
        self.instructions.clear();
        self.edges.clear();
        self.prev_ins_addr = 0;
        self.prev_edge_type = EdgeType::Unknown;
        self.reg_state = [0; Register::AMOUNT];
    }

    fn update_instructions(&mut self, pc: u32) -> Result<()> {
        // In this code, map is used to transform the Result<Register, _> into a Result<QControlRegister, _> (assuming qcontrol().register(reg) returns QControlRegister). If try_from fails and returns an Err, then the map function will not be applied, and the Err will be passed through to collect, which will immediately return the Err.
        let registers: Result<Vec<_>> = Register::printable()
            .iter()
            .map(ToString::to_string)
            .map(|x| Register::try_from(x.as_str()))
            .map(|res_reg| res_reg.map(|reg| qcontrol().register(reg)))
            .collect();

        let registers = registers.context("Unable to get register values")?;

        if !self.instructions.contains_key(&pc) {
            self.instructions
                .insert(pc, InstructionData::new("".to_string()));
        }

        // todo check if reg operand that is written to
        // check if reg value changed OR reg is register operand that is written to
        if let Some(inst_data) = self.instructions.get_mut(&pc) {
            inst_data.count += 1;
            for i in 0..registers.len() {
                // has register changed ?
                if self.reg_state[i] != registers[i] {
                    if registers[i] <= inst_data.min_vals[i].value {
                        inst_data.min_vals[i].value = registers[i];
                    }
                    if registers[i] >= inst_data.max_vals[i].value {
                        inst_data.max_vals[i].value = registers[i];
                    }

                    inst_data.last_vals[i].value = registers[i];
                    inst_data.min_vals[i].is_set = true;
                    inst_data.max_vals[i].is_set = true;
                    inst_data.last_vals[i].is_set = true;
                }
            }
        }

        self.reg_state = registers.try_into().unwrap();

        Ok(())
    }

    fn update_edges(&mut self, pc: u32) -> Result<()> {
        if self.prev_ins_addr != 0 {
            let edge = Edge {
                from: self.prev_ins_addr,
                to: pc,
            };

            match self.edges.entry(edge) {
                Entry::Vacant(entry) => {
                    // todo: get type
                    entry.insert(EdgeInfo {
                        typ: EdgeType::Unknown,
                        count: 0,
                    });
                }
                Entry::Occupied(mut entry_wrapper) => {
                    let entry = entry_wrapper.get_mut();
                    entry.count += 1;
                }
            }
        }

        if let Some(inst_data) = self.instructions.get_mut(&self.prev_ins_addr) {
            inst_data.last_successor = pc;
        }
        Ok(())
    }
}
