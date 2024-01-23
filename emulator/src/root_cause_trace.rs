use anyhow::{anyhow, Context, Result};
use capstone::arch::arm::{self, ArmInsn, ArmOperandType};
use capstone::prelude::*;
use common::fs::bufwriter;
use common::{hashbrown::hash_map::Entry, FxHashMap};
use frametracer::AccessType;
use qemu_rs::{memory::MemoryType, qcontrol, Address, ConditionCode, FlagBits, Register, USize};
use serde::Serialize;
use std::collections::HashMap;
use std::{fmt::Debug, io::Write, ops::Range, path::Path, path::PathBuf};

use rand::Rng;
use serde_json;
use trace_analysis::trace::{
    self, EdgeType, Memory as SerializedMemory, SerializedEdge, SerializedInstruction,
    SerializedTrace,
};
use trace_analysis::trace_analyzer::MemoryAddresses;

use crate::StopReason;

#[derive(PartialEq, Eq, Hash, Serialize, Copy, Clone)]
struct Edge {
    from: Address,
    to: Address,
}

impl Edge {
    pub fn to_serialized_edge(&self, count: u64, typ: EdgeType) -> SerializedEdge {
        SerializedEdge::new(self.from as usize, self.to as usize, count as usize, typ)
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

struct ItState {
    condition: ConditionCode,
    state: Vec<bool>,
}

impl ItState {
    pub fn new(condition: ConditionCode, state: Vec<bool>) -> ItState {
        ItState { condition, state }
    }
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

pub struct RootCauseTrace {
    instructions: FxHashMap<Address, InstructionData>,
    edges: FxHashMap<Edge, EdgeInfo>,
    reg_state: [u32; Register::AMOUNT],
    prev_edge_type: EdgeType,
    prev_ins_addr: Address,
    prev_mnemonic: Option<String>,
    prev_regs_written: Vec<Register>,
    itstate: Option<ItState>,
    first_address: Address,
    image_base: Address,
    trace_dir: Option<PathBuf>,
    trace_cnt: u64,
    cs: Capstone,
    detailed_trace_info: Vec<Vec<u32>>,
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
            .extra_mode([arch::arm::ArchExtraMode::MClass].iter().copied())
            .detail(true)
            //.endian(capstone::Endian::Little)
            .build()
            .expect("failed to init capstone");

        RootCauseTrace {
            instructions: FxHashMap::default(),
            edges: FxHashMap::default(),
            reg_state: [0; Register::AMOUNT],
            prev_edge_type: EdgeType::Unknown,
            prev_ins_addr: 0,
            prev_mnemonic: None,
            prev_regs_written: vec![],
            itstate: None,
            first_address: 0,
            image_base: 0,
            trace_dir,
            trace_cnt: 0,
            cs: cs,
            detailed_trace_info: vec![],
        }
    }

    pub fn post_run(
        &mut self,
        stop_reason: &Option<StopReason>,
        bugs: &Option<Vec<String>>,
    ) -> Result<()> {
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
            .map(|(edge, edgeinfo)| edge.to_serialized_edge(edgeinfo.count, edgeinfo.edge_type))
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
            let mut mem_ranges: MemoryAddresses = MemoryAddresses(HashMap::new());
            for block in qcontrol().memory_blocks() {
                // todo: should also allow readonly block and then check in aurora
                // for the type of instruction. e.g. a read of readonly is fine
                // but a write is not
                if !block.readonly {
                    mem_ranges.0.insert(
                        block.name,
                        Range {
                            start: block.start as usize,
                            end: block.start as usize + block.data.len(),
                        },
                    );
                }
            }
            let json = serde_json::to_string(&mem_ranges).context("json to string")?;

            bufwriter(&trace_dir)
                .and_then(|mut f| f.write_all(json.as_bytes()).context("write all"))?;

            trace_dir.pop();
        }

        // bugs we identified based on hook scripts
        // solution for finding false negatives that don't crash even though the
        // bug was triggered
        let is_bug = match bugs {
            Some(bugs) => true,
            None => false,
        };
        // write crash / non_crash trace
        let mut rng = rand::thread_rng();
        let random_number: u64 = rng.gen();

        let is_crash = match stop_reason {
            StopReason::RomWrite { .. }
            | StopReason::NonExecutable { .. }
            | StopReason::Crash { .. } => true,
            _ => false,
        };

        let mut stream = if is_crash || is_bug {
            trace_dir.push(format!("crashes/{}-summary.bin", random_number));
            bufwriter(&trace_dir)
        } else {
            trace_dir.push(format!("non_crashes/{}-summary.bin", random_number));
            bufwriter(&trace_dir)
        }
        .context("Unable to open trace file")?;

        bincode::serialize_into(&mut stream, &trace).context("serialize trace")?;

        trace_dir.pop();
        // write detailed inst / register state information
        let mut stream = if is_crash || is_bug {
            trace_dir.push(format!("{}-full.bin", random_number));
            bufwriter(&trace_dir)
        } else {
            trace_dir.push(format!("{}-full.bin", random_number));
            bufwriter(&trace_dir)
        }
        .context("Unable to open detailed trace_info file")?;

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
        self.prev_regs_written = vec![];
        self.prev_mnemonic = None;
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
        // disregard everything with more than 4 bytes similar to aurora
        if access_type != AccessType::Write || size > 0x4 {
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

        let registers: Result<Vec<_>> = Register::printable()
            .iter()
            .map(ToString::to_string)
            .map(|x| Register::try_from(x.as_str()))
            .map(|res_reg| res_reg.map(|reg| qcontrol().register(reg)))
            .collect();

        let registers = registers.context("failed to obtain registers")?;

        let (mnemonic, edge_type, mut regs_written, is_it) = qcontrol()
            .memory_blocks()
            .find(|x| x.contains(pc))
            .and_then(|mem_block| {
                let off = (pc - mem_block.start) as usize;

                // ARMv7-M thumb2 is a mix of 2 and 4 byte instructions, therefore
                // we try to disassemble every instruction contained within 4 bytes
                // and take the first valid inst found
                let inst = self
                    .cs
                    .disasm_all(&mem_block.data[off..(off + 4)], 0)
                    .ok()?;
                let inst = inst.iter().next()?;

                let regs_written = self
                    .cs
                    .insn_detail(&inst)
                    .and_then(|detail| {
                        Ok(detail
                            .regs_write()
                            .iter()
                            .filter_map(|&reg_id| self.cs.reg_name(reg_id))
                            .collect::<Vec<_>>())
                    })
                    .unwrap_or(vec![]);

                Some((
                    Some(format!(
                        "{} {}",
                        inst.mnemonic().unwrap_or(""),
                        inst.op_str().unwrap_or(""),
                    )),
                    self.get_edge_type(&inst),
                    regs_written,
                    inst.id().0 == ArmInsn::ARM_INS_IT as u32,
                ))
            })
            .unwrap_or((None, EdgeType::Unknown, vec![], false));

        // capstone doesnt differentiate between xpsr and cpsr. Since we know that
        // we are only considering Cortex-M, we adjust the name
        for reg in regs_written.iter_mut() {
            if reg.to_uppercase() == "CPSR" {
                *reg = "XPSR".to_string();
            }
        }

        let regs_written = regs_written
            .iter()
            .map(|x| Register::try_from(x.as_str()))
            .collect::<Result<Vec<_>>>()
            .unwrap_or(vec![]);

        // update register state to prevent false positives due to special arm
        // instructions that restore register values and returns
        // e.g.: pop        {r3,r4,r5,r6,r7,pc}
        if self.prev_edge_type == EdgeType::Return {
            for i in 0..registers.len() {
                self.reg_state[i] = registers[i];
            }
        }
        // do the same after a push
        // e.g.: push {r3, lr}
        if let Some(mnemonic) = &self.prev_mnemonic {
            if mnemonic.contains("push") {
                for i in 0..registers.len() {
                    self.reg_state[i] = registers[i];
                }
            }
        }

        // update Regular type instruction after it has been executed
        if self.prev_edge_type == EdgeType::Regular {
            self.update_instructions(
                self.prev_ins_addr,
                &registers,
                self.prev_mnemonic.clone(),
                self.prev_regs_written.clone(),
            )?;
        }

        // Conditional execution in ARM = conditional jumps in x86 so handle it as edges
        // skip instructions as long as update_itstate returns true
        // we don't have to update anything else except prev_edge_type as we are already
        // in a conditional block so previous instruction should be counted as edge source
        if self.itstate.is_some() {
            let skip_inst = self.update_itstate(registers[Register::xPSR as usize]);
            if skip_inst {
                self.prev_edge_type = EdgeType::Conditional;
                return Ok(());
            }
        }

        // handle conditional execution
        if is_it {
            if self.itstate.is_some() {
                anyhow::bail!("it instruction even though we still have itstate");
            }
            // TODO: handling itstate based on xPSR register doesn't work. QEMU
            // doesnt seem to correctly set it? therefore we interpret the instruction
            // string instead of the register
            self.init_itstate_str(mnemonic.clone().unwrap_or("".to_string()))?;
        }

        match edge_type {
            // regular edges are being handled after they have been executed
            EdgeType::Regular => self.prev_mnemonic = mnemonic,
            _ => self.update_instructions(pc, &registers, mnemonic, regs_written.clone())?,
        }

        // update edge after it has been taken, so prev_edge_type
        if self.prev_ins_addr != 0x0 {
            self.update_edges(self.prev_ins_addr, pc, self.prev_edge_type.clone())?;
        }

        self.detailed_trace_info.push(registers);
        self.prev_ins_addr = pc;
        self.prev_edge_type = edge_type;
        self.prev_regs_written = regs_written;
        Ok(())
    }

    // could use this func if QEMU would update xPSR correctly
    fn init_itstate(&mut self, xPSR: u32, mnemonic: String) {
        // [26:25] = IT[7:6], [15:10] = IT[5:0]
        let itstate = ((xPSR >> 25) & 3) << 5 | ((xPSR >> 10) & 0x3f);

        let base_condition = (itstate >> 5) & 7;
        let sz = (itstate & 0x1f).count_ones();
        println!(
            "Handle it state:  {} {:32b} {} {} {}",
            mnemonic, xPSR, base_condition, itstate, sz
        );
    }

    // todo: Implement sth like register index to make this hardcoding go away
    // example: ite eq => Condition is eq, condition should be true for first instruction
    // following it instruction (t) and false for the second (e)
    fn update_itstate(&mut self, xPSR: u32) -> bool {
        let mut should_skip_inst = false;
        let bit_set = |val: u32, pos: u32| -> bool { (val & (1 << pos)) != 0 };
        let bits_equal =
            |val: u32, pos1: u32, pos2: u32| -> bool { bit_set(val, pos1) == bit_set(val, pos2) };
        if let Some(ref mut itstate) = self.itstate {
            let condition_set = match itstate.condition {
                // equal, Z = 1
                ConditionCode::EQ => bit_set(xPSR, FlagBits::Z.to_bit_index() as u32),
                // Not equal, Z = 0
                ConditionCode::NE => !bit_set(xPSR, FlagBits::Z.to_bit_index() as u32),
                // Higher or same, unsigned C = 1
                ConditionCode::CS => bit_set(xPSR, FlagBits::C.to_bit_index() as u32),
                // Lower, unsigned C = 0
                ConditionCode::CC => !bit_set(xPSR, FlagBits::C.to_bit_index() as u32),
                // Negative, N = 1
                ConditionCode::MI => bit_set(xPSR, FlagBits::N.to_bit_index() as u32),
                // Positive or zero , N = 0
                ConditionCode::PL => !bit_set(xPSR, FlagBits::N.to_bit_index() as u32),
                // Overflow, V = 1
                ConditionCode::VS => bit_set(xPSR, FlagBits::V.to_bit_index() as u32),
                // No overflow, V = 0
                ConditionCode::VC => !bit_set(xPSR, FlagBits::V.to_bit_index() as u32),
                // Higher, unsigned, C = 1 && Z = 0
                ConditionCode::HI => {
                    bit_set(xPSR, FlagBits::C.to_bit_index() as u32)
                        && !bit_set(xPSR, FlagBits::Z.to_bit_index() as u32)
                }
                // Lower or same, unsigned, C = 0 || Z = 1
                ConditionCode::LS => {
                    !bit_set(xPSR, FlagBits::C.to_bit_index() as u32)
                        || bit_set(xPSR, FlagBits::Z.to_bit_index() as u32)
                }
                // Greater equal, signed, N = V
                ConditionCode::GE => bits_equal(
                    xPSR,
                    FlagBits::N.to_bit_index() as u32,
                    FlagBits::V.to_bit_index() as u32,
                ),
                // Less than, signed, N != V
                ConditionCode::LT => !bits_equal(
                    xPSR,
                    FlagBits::N.to_bit_index() as u32,
                    FlagBits::V.to_bit_index() as u32,
                ),
                // Greater than, signed, Z = 0 && N = V
                ConditionCode::GT => {
                    !bit_set(xPSR, FlagBits::Z.to_bit_index() as u32)
                        && bits_equal(
                            xPSR,
                            FlagBits::N.to_bit_index() as u32,
                            FlagBits::V.to_bit_index() as u32,
                        )
                }
                // Less than or equal, signed, Z = 1 && N != V
                ConditionCode::LE => {
                    bit_set(xPSR, FlagBits::Z.to_bit_index() as u32)
                        && !bits_equal(
                            xPSR,
                            FlagBits::N.to_bit_index() as u32,
                            FlagBits::V.to_bit_index() as u32,
                        )
                }
                _ => unimplemented!(),
            };

            if let Some(exec_if_condition_set) = itstate.state.pop() {
                if exec_if_condition_set {
                    // execute if condition is set, so skip if not set
                    should_skip_inst = !condition_set;
                } else {
                    // execute if condition not set, so skip if set
                    should_skip_inst = condition_set;
                }

                if itstate.state.len() == 0 {
                    self.itstate = None;
                }
            }
        }

        should_skip_inst
    }

    fn init_itstate_str(&mut self, mnemonic: String) -> Result<()> {
        let parts: Vec<&str> = mnemonic.split(' ').collect();

        if parts.len() > 2 {
            println!("It instruction has 2 condition codes ?: {:}", mnemonic);
            unimplemented!();
        }

        let condition_code = ConditionCode::try_from(parts[1])?;

        let mut conditions = vec![];
        for c in parts[0].chars().skip(1) {
            if c == 't' {
                conditions.push(true);
            } else {
                conditions.push(false);
            }
        }
        // reverse vector as conditions are evaluated from msb to lsb
        conditions.reverse();

        /*
        println!(
            "Itstate: {}, {:?}, {:?}",
            mnemonic, condition_code, conditions
        );
        */

        self.itstate = Some(ItState::new(condition_code, conditions));

        Ok(())
    }

    fn update_instructions(
        &mut self,
        pc: u32,
        registers: &Vec<u32>,
        mnemonic: Option<String>,
        regs_written: Vec<Register>,
    ) -> Result<()> {
        //println!("Regs written: {:?} 0x{:x} {:?}", regs_written, pc, mnemonic);

        if !self.instructions.contains_key(&pc) {
            self.instructions
                .insert(pc, InstructionData::new(mnemonic.unwrap_or("".to_string())));
        }

        let regs_written = regs_written.iter().map(|&r| r as usize).collect::<Vec<_>>();

        if let Some(inst_data) = self.instructions.get_mut(&pc) {
            inst_data.count += 1;
            for i in 0..registers.len() {
                // check if reg value changed OR reg is register operand that is written to
                // regs_written is for flags registers which e.g. can be 0 but be written
                if self.reg_state[i] != registers[i] || regs_written.contains(&i) {
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

        Ok(())
    }

    fn update_edges(&mut self, prev_pc: u32, pc: u32, edge_type: EdgeType) -> Result<()> {
        let edge = Edge {
            from: prev_pc,
            to: pc,
        };

        match self.edges.entry(edge) {
            // new edge found
            Entry::Vacant(entry) => {
                entry.insert(EdgeInfo {
                    edge_type: edge_type,
                    count: 0,
                });
            }
            // updated existing edge
            Entry::Occupied(mut entry_wrapper) => {
                let entry = entry_wrapper.get_mut();
                entry.count += 1;
                if edge_type != entry.edge_type {
                    log::info!(
                        "Edge {:x} -> {:x} differs from the stored one. Type1: {:?}, Type2: {:?}",
                        edge.from,
                        edge.to,
                        entry.edge_type,
                        edge_type
                    );

                    assert!(edge_type == entry.edge_type);
                }
            }
        }

        // add last successor information to previous instruction
        if let Some(inst_data) = self.instructions.get_mut(&prev_pc) {
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
                //|| id == ArmInsn::ARM_INS_BIC as u32
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
                        // handle stuff like BNE (ARM_CC_NE)
                        if inst_detail.cc() != capstone::arch::arm::ArmCC::ARM_CC_AL {
                            return EdgeType::Conditional;
                        }

                        for op in inst_detail.operands() {
                            match op.op_type {
                                // immediate edge operand
                                ArmOperandType::Imm(_) => return EdgeType::Direct,
                                // reg as edge operand
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
