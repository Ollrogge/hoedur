

fn on_instruction(pc) {
    //log::info!("MY HOOL CALLED {}", pc);
    let regs = register::list();
    log::info!("Regs: {:?}", regs);
}

pub fn main(api) {
    api.on_instruction(None, on_instruction);
}