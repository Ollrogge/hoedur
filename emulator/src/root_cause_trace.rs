use anyhow::{Context, Result};
use common::{fs::encoder, hashbrown::hash_map::Entry, FxHashMap, FxHashSet};
use rune::ast::In;
use serde::Serialize;
use std::convert::TryInto;
use std::{
    fmt::{self, Debug},
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    sync::{atomic::Ordering, Arc},
};
use zstd::stream::AutoFinishEncoder;

use qemu_rs::{qcontrol, register, Address, Register};

use trace_analysis::trace::{SerializedInstruction, SerializedTrace};

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

#[derive(Serialize)]
struct InstructionData {
    /// how often instruction was called
    count: u64,
    mnemonic: String,
    /// min values for each register
    min_vals: [Value; Register::AMOUNT],
    /// max values for each register
    max_vals: [Value; Register::AMOUNT],
    last_vals: [Value; Register::AMOUNT],
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
}

impl RootCauseTrace {
    pub fn new() -> Self {
        RootCauseTrace {
            instructions: FxHashMap::default(),
            edges: FxHashMap::default(),
            reg_state: [0; Register::AMOUNT],
            prev_edge_type: EdgeType::Unknown,
            prev_ins_addr: 0,
        }
    }

    pub fn on_instruction(&mut self, pc: u32) -> Result<()> {
        self.update_instructions(pc)?;

        self.update_edges(pc)
    }

    pub fn post_run<W: Write>(&self, stream: &mut W) -> Result<()> {
        Trace::new(&self.instructions, &self.edges).write_to(stream)
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
