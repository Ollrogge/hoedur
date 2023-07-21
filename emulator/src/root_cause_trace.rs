use anyhow::{anyhow, Context, Result};
use capstone::arch::arm::{self, ArmInsn, ArmOperandType};
use capstone::prelude::*;
use common::fs::bufwriter;
use common::{hashbrown::hash_map::Entry, FxHashMap};
use frametracer::AccessType;
use qemu_rs::{memory::MemoryType, qcontrol, Address, Register, USize};
use serde::Serialize;
use std::collections::HashMap;
use std::convert::TryInto;
use std::{fmt::Debug, io::Write, path::Path, path::PathBuf};

use serde_json;
use trace_analysis::trace::{
    self, Memory as SerializedMemory, SerializedEdge, SerializedInstruction, SerializedTrace,
};
use trace_analysis::trace_analyzer::MemoryAddresses;

use crate::StopReason;

#[derive(Serialize, Debug, PartialEq, Clone)]
enum EdgeType {
    Direct,
    Indirect,
    Conditional,
    Syscall,
    Return,
    Regular,
    Unknown,
}

#[derive(PartialEq, Eq, Hash, Serialize, Copy, Clone)]
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
    edge_type: EdgeType,
    count: u64,
}

#[derive(Copy, Clone, Serialize)]
struct Value {
    is_set: bool,
    value: u32,
}

#[derive(Default, Debug, Clone, Copy)]
struct MemoryField {
    address: Address,
    size: u8,
    value: USize,
}

#[derive(Default, Debug)]
struct MemoryData {
    last_addr: MemoryField,
    min_addr: MemoryField,
    max_addr: MemoryField,
    last_value: MemoryField,
    min_value: MemoryField,
    max_value: MemoryField,
}

type Registers = [Value; Register::AMOUNT];

struct InstructionData {
    /// how often instruction was called
    count: usize,
    /// disassembled name of inst
    mnemonic: String,
    /// min values for each register
    min_vals: Registers,
    /// max values for each register
    max_vals: Registers,
    /// last-seen value of regs
    last_vals: Registers,
    // last successor of recorded for this inst
    last_successor: Address,
    // todo: leverage memory models to derive the memory access data ?
    mem_data: MemoryData,
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
            mem_data: MemoryData::default(),
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

        let memory = if self.mem_data.last_addr.size != 0 {
            Some(SerializedMemory {
                min_address: self.mem_data.min_addr.address as u64,
                max_address: self.mem_data.max_addr.address as u64,
                last_address: self.mem_data.last_addr.address as u64,
                min_value: self.mem_data.min_value.value as u64,
                max_value: self.mem_data.max_value.value as u64,
                last_value: self.mem_data.last_value.value as u64,
            })
        } else {
            None
        };

        SerializedInstruction {
            address: pc as usize,
            mnemonic: self.mnemonic.clone(),
            registers_min: trace::Registers::from(min_vals),
            registers_max: trace::Registers::from(max_vals),
            registers_last: trace::Registers::from(last_vals),
            last_successor: self.last_successor as usize,
            count: self.count,
            memory: memory,
        }
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
    cs: Capstone,
    detailed_trace_info: Vec<(usize, [u32; Register::AMOUNT])>,
}

impl RootCauseTrace {
    pub fn new(trace_file_path: Option<PathBuf>) -> Self {
        let trace_dir = if let Some(path) = trace_file_path {
            let parent = path.parent().unwrap_or_else(|| &Path::new("."));
            Some(parent.to_path_buf())
        } else {
            None
        };

        let cs = Capstone::new()
            .arm()
            .mode(arm::ArchMode::Thumb)
            .detail(true)
            .endian(capstone::Endian::Little)
            .build()
            .expect("failed to init capstone");

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
            cs: cs,
            detailed_trace_info: vec![],
        }
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

        // write memory ranges
        if self.trace_cnt == 0x0 {
            trace_dir.push("addresses.json");
            for block in qcontrol().memory_blocks() {
                if block.name.contains("ram") {
                    // define everything to be stack for now
                    let addresses = MemoryAddresses {
                        heap_start: 0x0,
                        heap_end: 0x0,
                        stack_start: block.start as usize,
                        stack_end: block.start as usize + block.data.len(),
                    };

                    let json = serde_json::to_string(&addresses).context("json to string")?;

                    bufwriter(&trace_dir)
                        .and_then(|mut f| f.write_all(json.as_bytes()).context("write all"))?;
                }
            }

            trace_dir.pop();
        }

        // write crash / non_crash trace
        let mut stream = match stop_reason {
            StopReason::Crash { .. } => {
                trace_dir.push(format!("crashes/{}-summary.bin", self.trace_cnt));
                bufwriter(&trace_dir)
            }
            _ => {
                trace_dir.push(format!("non_crashes/{}-summary.bin", self.trace_cnt));
                bufwriter(&trace_dir)
            }
        }
        .context("Unable to open trace file")?;

        bincode::serialize_into(&mut stream, &trace).context("serialize trace")?;

        trace_dir.pop();
        // write detailed inst / register state information
        let mut stream = match stop_reason {
            StopReason::Crash { .. } => {
                trace_dir.push(format!("{}-full.bin", self.trace_cnt));
                bufwriter(&trace_dir)
            }
            _ => {
                trace_dir.push(format!("{}-full.bin", self.trace_cnt));
                bufwriter(&trace_dir)
            }
        }
        .context("Unable to open detailed trace info file")?;

        bincode::serialize_into(&mut stream, &self.detailed_trace_info)
            .context("serialized detailed trace info")?;

        trace_dir.pop();
        trace_dir.pop();

        self.reset();
        self.trace_cnt += 1;

        Ok(())
    }

    fn reset(&mut self) {
        self.instructions.clear();
        self.edges.clear();
        self.prev_ins_addr = 0;
        self.prev_edge_type = EdgeType::Unknown;
        self.reg_state = [0; Register::AMOUNT];
        self.detailed_trace_info.clear();
    }

    pub fn on_memory_access(
        &mut self,
        memory_type: MemoryType,
        access_type: AccessType,
        pc: Address,
        address: Address,
        value: USize,
        size: u8,
    ) -> Result<()> {
        // disregard everything with more than 8 bytes similar to aurora
        if access_type != AccessType::Write || size > 0x8 {
            return Ok(());
        }

        // TODO: think about how to handle mmio accesses -> need to add it
        // to memory ranges first
        if memory_type == MemoryType::Mmio {
            return Ok(());
        }

        if size == 0x0 {
            log::info!("Memory access size 0? {:x}", pc);
        }

        if let Some(inst) = self.instructions.get_mut(&pc) {
            let mem_data = &mut inst.mem_data;
            let access = MemoryField {
                address,
                size,
                value,
            };

            if mem_data.last_addr.size != 0x0 && mem_data.last_addr.size != access.size {
                log::info!("Memory operand has different access sizes: {:x}", pc);
            }

            if mem_data.max_addr.address <= access.address {
                mem_data.max_addr = access;
            }
            if mem_data.min_addr.address >= access.address {
                mem_data.min_addr = access;
            }
            mem_data.last_addr = access;

            if mem_data.max_value.value <= access.value {
                mem_data.max_value = access;
            }
            if mem_data.min_value.value >= access.value {
                mem_data.min_value = access;
            }
            mem_data.last_value = access;
        }
        Ok(())
    }

    pub fn on_instruction(&mut self, pc: u32) -> Result<()> {
        if self.instructions.len() == 0x0 {
            self.first_address = pc;
        }

        // update Regular add type instruction after it has been executed
        if self.prev_edge_type == EdgeType::Regular {
            self.update_instructions(self.prev_ins_addr)?;
        }

        // only consider 4 byte because max inst length of ARMv7-M is 32 bit
        let edge_type = qcontrol()
            .memory_blocks()
            .find(|x| x.contains(pc))
            .and_then(|mem_block| {
                self.cs
                    .disasm_all(&mem_block.data[(pc as usize)..(pc as usize) + 4], 0)
                    .ok()
            })
            .and_then(|insts| match insts.iter().next() {
                Some(inst) => Some(self.get_edge_type(inst)),
                _ => None,
            })
            .unwrap_or(EdgeType::Unknown);

        match edge_type {
            // regular edges are being handled after they have been executed
            EdgeType::Regular => (),
            _ => self.update_instructions(pc)?,
        }

        if self.prev_ins_addr != 0x0 {
            self.update_edges(pc, edge_type.clone())?;
        }

        self.prev_ins_addr = pc;
        self.prev_edge_type = edge_type;
        Ok(())
    }

    fn update_instructions(&mut self, pc: u32) -> Result<()> {
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
                    // update reg value in global state
                    self.reg_state[i] = registers[i];

                    // min / max val
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

        self.detailed_trace_info.push((
            pc as usize,
            registers
                .try_into()
                .map_err(|_| anyhow!("register vec to array"))?,
        ));

        Ok(())
    }

    fn update_edges(&mut self, pc: u32, edge_type: EdgeType) -> Result<()> {
        if self.prev_ins_addr != 0 {
            let edge = Edge {
                from: self.prev_ins_addr,
                to: pc,
            };

            match self.edges.entry(edge) {
                Entry::Vacant(entry) => {
                    // todo: get type
                    entry.insert(EdgeInfo {
                        edge_type: edge_type,
                        count: 0,
                    });
                }
                Entry::Occupied(mut entry_wrapper) => {
                    let entry = entry_wrapper.get_mut();
                    entry.count += 1;
                    if edge_type != entry.edge_type {
                        log::info!("Edge {:x} -> {:x} differs from the stored one. Type1: {:?}, Type2: {:?}", edge.from, edge.to, entry.edge_type, edge_type)
                    }
                }
            }
        }

        // add last successor information to previous instruction
        if let Some(inst_data) = self.instructions.get_mut(&self.prev_ins_addr) {
            inst_data.last_successor = pc;
        }
        Ok(())
    }

    fn get_edge_type(&self, inst: &capstone::Insn) -> EdgeType {
        match inst.id().0 {
            id if id == ArmInsn::ARM_INS_BX as u32
                || id == ArmInsn::ARM_INS_BLX as u32
                || id == ArmInsn::ARM_INS_POP as u32 =>
            {
                EdgeType::Return
            }

            id if id == ArmInsn::ARM_INS_BL as u32
                || id == ArmInsn::ARM_INS_B as u32
                || id == ArmInsn::ARM_INS_BIC as u32
                || id == ArmInsn::ARM_INS_CBZ as u32
                || id == ArmInsn::ARM_INS_CBNZ as u32
                || id == ArmInsn::ARM_INS_TBH as u32
                || id == ArmInsn::ARM_INS_TBB as u32 =>
            {
                if let Ok(details) = self.cs.insn_detail(&inst) {
                    if let capstone::arch::ArchDetail::ArmDetail(inst_detail) =
                        details.arch_detail()
                    {
                        // check if condition codes of inst are != unconditional
                        if inst_detail.cc() != capstone::arch::arm::ArmCC::ARM_CC_AL {
                            return EdgeType::Conditional;
                        }
                        for op in inst_detail.operands() {
                            match op.op_type {
                                ArmOperandType::Imm(_) => return EdgeType::Direct,
                                ArmOperandType::Reg(_) => return EdgeType::Indirect,
                                _ => (),
                            }
                        }
                    }
                }
                EdgeType::Unknown
            }

            id if id == ArmInsn::ARM_INS_SVC as u32 => EdgeType::Syscall,

            _ => EdgeType::Regular,
        }
    }
}
