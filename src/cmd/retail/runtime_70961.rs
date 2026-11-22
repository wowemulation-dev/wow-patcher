use std::{collections::HashMap, thread, time::Duration};

use windows_sys::Win32::System::Memory::{
    MEM_MAPPED, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE,
};

use super::{
    DataPatch, Options, Plan, Result, absolute_jump,
    process::Process,
    recipe::{LoaderRecipe, Recipe},
    registry, runtime,
};

fn require(process: &Process, address: usize, expected: &[u8], name: &str) -> Result<()> {
    if process.read(address, expected.len())? != expected {
        return Err(format!("{name}: unexpected runtime bytes at 0x{address:X}").into());
    }
    Ok(())
}

fn read_u64(process: &Process, address: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        process.read(address, 8)?.try_into().unwrap(),
    ))
}

fn read_u32(process: &Process, address: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        process.read(address, 4)?.try_into().unwrap(),
    ))
}

fn verify_all(process: &Process, verified: &[(usize, Vec<u8>)]) -> Result<()> {
    process.ensure_running()?;
    for (address, bytes) in verified {
        require(process, *address, bytes, "Registered patch verification")?;
    }
    Ok(())
}

fn apply_data(
    process: &Process,
    patch: &DataPatch,
    verified: &mut Vec<(usize, Vec<u8>)>,
) -> Result<()> {
    let address = process.base + patch.rva;
    require(process, address, &patch.original, patch.name)?;
    process.write(address, &patch.replacement)?;
    verified.push((address, patch.replacement.clone()));
    Ok(())
}

fn apply_code(
    process: &Process,
    rva: usize,
    expected: &[u8],
    replacement: &[u8],
    name: &str,
    verified: &mut Vec<(usize, Vec<u8>)>,
) -> Result<()> {
    let address = process.base + rva;
    require(process, address, expected, name)?;
    process.write(address, replacement)?;
    verified.push((address, replacement.to_vec()));
    Ok(())
}

fn wait_for_entry(process: &Process, entry: usize, timeout: Duration) -> Result<()> {
    runtime::wait_until(process, timeout, "the 70961 entry hold", || {
        if process.region(process.base)?.Type == MEM_MAPPED
            && process.initial_thread_rip()? == entry
        {
            require(process, entry, &[0xeb, 0xfe], "Entry hold")?;
            return Ok(Some(()));
        }
        Ok(None)
    })
}

fn install_loader(
    process: &Process,
    recipe: &LoaderRecipe,
    verified: &mut Vec<(usize, Vec<u8>)>,
) -> Result<()> {
    let (loader_base, _) = process
        .loader_module()?
        .ok_or("Wow_loader.dll is not loaded at the 70961 initialization stage")?;
    let state =
        read_u64(process, loader_base + recipe.state_pointer_rva)? ^ recipe.state_pointer_xor;
    let state = usize::try_from(state)?;
    let lock = read_u64(process, state + recipe.lock_offset)?;
    let status = read_u32(process, state + recipe.status_offset)?;
    if state & 0xf != 0 || lock != 0 || status != recipe.status_xor {
        return Err(format!(
            "Unexpected 70961 loader state: state=0x{state:X}, lock=0x{lock:X}, status=0x{status:08X}"
        )
        .into());
    }
    let publisher = loader_base + recipe.publisher_rva;
    require(
        process,
        publisher,
        recipe.publisher_prologue,
        "Loader publisher prologue",
    )?;
    let displacement =
        i32::try_from(recipe.publisher_rva as i64 - recipe.clone_notice_return_rva as i64)?;
    let mut call = vec![0xe8];
    call.extend_from_slice(&displacement.to_le_bytes());
    require(
        process,
        loader_base + recipe.clone_notice_return_rva - 5,
        &call,
        "Selected loader 0x100 call site",
    )?;

    let counters = process.allocate(64, PAGE_READWRITE)?;
    let shim = loader_status_shim(
        counters,
        publisher + recipe.publisher_prologue.len(),
        loader_base + recipe.clone_notice_return_rva,
        recipe.publisher_prologue,
    );
    let shim_address = process.allocate(shim.len(), PAGE_READWRITE)?;
    process.write(shim_address, &shim)?;
    process.protect(shim_address, shim.len(), PAGE_EXECUTE_READ)?;

    let mut publisher_jump = vec![0x90; recipe.publisher_prologue.len()];
    publisher_jump[..6].copy_from_slice(&[0xff, 0x25, 0, 0, 0, 0]);
    publisher_jump[6..14].copy_from_slice(&(shim_address as u64).to_le_bytes());

    let mapping = loader_base + recipe.mapping_rva;
    let region = process.region(mapping)?;
    if region.Type != MEM_MAPPED
        || region.Protect != PAGE_EXECUTE_READ
        || region.BaseAddress as usize != mapping
        || region.AllocationBase as usize != mapping
        || region.RegionSize != recipe.mapping_size
        || process
            .region(mapping + recipe.mapping_size)?
            .AllocationBase as usize
            == mapping
    {
        return Err("Unexpected 70961 loader code mapping layout; refusing to unmap it".into());
    }
    let mut copy = process.read(mapping, recipe.mapping_size)?;
    let publisher_offset = publisher - mapping;
    copy[publisher_offset..publisher_offset + publisher_jump.len()]
        .copy_from_slice(&publisher_jump);
    process.replace_mapping(mapping, &copy)?;
    let updated = process.region(mapping)?;
    if updated.Type != MEM_MAPPED
        || updated.Protect != PAGE_EXECUTE_READ
        || updated.RegionSize != recipe.mapping_size
    {
        return Err("Replacement loader mapping has unexpected type, protection, or size".into());
    }
    require(process, mapping, &copy, "Full replacement loader mapping")?;
    process.flush(mapping, copy.len())?;
    verified.push((shim_address, shim));
    verified.push((publisher, publisher_jump));
    println!("Installed and verified the 70961 loader status shim");
    Ok(())
}

fn warm_code(process: &Process, recipe: &Recipe, timeout: Duration) -> Result<()> {
    let start = process.base + super::TEXT_START;
    let end = start + recipe.text_size;
    let stub = warm_stub(start, end);
    let scratch = process.base + recipe.scratch_rva;
    let original = process.read(scratch, stub.len())?;
    process.write(scratch, &stub)?;
    let old_protection = process.protect(scratch, stub.len(), PAGE_EXECUTE_READWRITE)?;
    process.run_zero_reader(scratch, timeout)?;
    process.write(scratch, &original)?;
    process.protect(scratch, stub.len(), old_protection)?;
    require(process, scratch, &original, "Restored warm scratch")?;
    if process.protection(scratch)? != old_protection {
        return Err("Warm scratch protection was not restored".into());
    }
    println!("Prepared 70961 code pages and restored temporary bytes and protection");
    Ok(())
}

fn install_certificate(
    process: &Process,
    plan: &Plan,
    verified: &mut Vec<(usize, Vec<u8>)>,
) -> Result<()> {
    let recipe = plan.recipe;
    let path = plan
        .certificate
        .to_str()
        .ok_or("Invalid certificate path")?;
    let mut path_bytes = path.as_bytes().to_vec();
    path_bytes.push(0);
    let path_address = process.allocate(path_bytes.len(), PAGE_READWRITE)?;
    let table_address = process.allocate(12, PAGE_READWRITE)?;
    let stub_address = process.allocate(82, PAGE_READWRITE)?;
    let table = file_table(7725530, path_address);
    let stub = file_hook_stub(
        table_address,
        process.base + recipe.resolver + super::PROLOGUE.len(),
    );
    process.write(path_address, &path_bytes)?;
    process.write(table_address, &table)?;
    process.write(stub_address, &stub)?;
    process.protect(path_address, path_bytes.len(), PAGE_READONLY)?;
    process.protect(table_address, table.len(), PAGE_READONLY)?;
    process.protect(stub_address, 82, PAGE_EXECUTE_READ)?;
    verified.push((path_address, path_bytes));
    verified.push((table_address, table));
    verified.push((stub_address, stub));

    apply_code(
        process,
        recipe.result_bl,
        &[0x32, 0xdb],
        &[0xb3, 0x01],
        "Local file override 1",
        verified,
    )?;
    apply_code(
        process,
        recipe.result_edi,
        &[0xe8, 0x4a, 0x3c, 0, 0, 0x44, 0x0f],
        &[0xbf, 0x01, 0, 0, 0, 0x90, 0x90],
        "Local file override 2",
        verified,
    )?;
    apply_code(
        process,
        recipe.helper,
        &[0x48, 0x89, 0x5c],
        &[0x33, 0xc0, 0xc3],
        "Local file override 3",
        verified,
    )?;
    apply_code(
        process,
        recipe.gate + 4,
        &[0x74, 0x5c],
        &[0x90, 0x90],
        "Local file override 4",
        verified,
    )?;
    let mut jump = absolute_jump(stub_address);
    jump.push(0x90);
    apply_code(
        process,
        recipe.resolver,
        super::PROLOGUE,
        &jump,
        "Local-file hook entry",
        verified,
    )?;
    Ok(())
}

pub(super) fn launch(opts: &Options, plan: &Plan) -> Result<()> {
    let loader_recipe = plan
        .recipe
        .loader
        .as_ref()
        .ok_or("The 70961 launcher requires its loader recipe")?;
    Process::ensure_not_running(&plan.executable)?;
    if let Err(error) = registry::prepare() {
        eprintln!("Warning: custom launch-options registry preparation failed: {error}");
    }
    let process = Process::create(&plan.executable, &opts.config)?;
    println!("Created client PID {}", process.pid);
    let mut verified = Vec::new();
    let entry = process.base + plan.entry_rva;
    require(
        &process,
        entry,
        &plan.entry_original,
        "Suspended 70961 entry point",
    )?;
    process.write(entry, &[0xeb, 0xfe])?;
    process.resume_initial()?;
    wait_for_entry(&process, entry, opts.timeout)?;
    for _ in 0..15 {
        process.ensure_running()?;
        thread::sleep(Duration::from_millis(100));
    }
    process.suspend()?;
    install_loader(&process, loader_recipe, &mut verified)?;
    for patch in &plan.data {
        apply_data(&process, patch, &mut verified)?;
    }
    process.write(entry, &plan.entry_original)?;
    warm_code(&process, plan.recipe, opts.timeout)?;
    verify_all(&process, &verified)?;
    process.resume()?;

    thread::sleep(Duration::from_millis(250));
    process.ensure_running()?;
    process.suspend()?;
    runtime::validate_code(&process, plan.recipe)?;
    install_certificate(&process, plan, &mut verified)?;
    verify_all(&process, &verified)?;
    process.resume()?;
    println!(
        "70961 patches installed and verified; client PID {} resumed",
        process.pid
    );
    process.release()
}

fn warm_stub(start: usize, end: usize) -> Vec<u8> {
    let mut code = hex::decode("5348BB").unwrap();
    code.extend_from_slice(&(start as u64).to_le_bytes());
    code.extend_from_slice(&hex::decode("48B9").unwrap());
    code.extend_from_slice(&(end as u64).to_le_bytes());
    code.extend_from_slice(
        &hex::decode("48BA00100000000000004839CB0F8D0B000000488B034801D3E9ECFFFFFF5B33C0C3")
            .unwrap(),
    );
    code
}

fn file_hook_stub(table: usize, continuation: usize) -> Vec<u8> {
    let mut code = hex::decode("85D20F882A00000033C049B9").unwrap();
    code.extend_from_slice(&(table as u64).to_le_bytes());
    code.extend_from_slice(
        &hex::decode("8D0C40C1E10242391409740CFFC03D0100000072EB33C0C34A8B440904C3").unwrap(),
    );
    code.extend_from_slice(&hex::decode("48895C2408574883EC20488BF948B8").unwrap());
    code.extend_from_slice(&(continuation as u64).to_le_bytes());
    code.extend_from_slice(&[0xff, 0xe0, 0x90]);
    code
}

fn file_table(id: i32, path: usize) -> Vec<u8> {
    let mut table = id.to_le_bytes().to_vec();
    table.extend_from_slice(&(path as u64).to_le_bytes());
    table
}

fn loader_status_shim(
    counters: usize,
    continuation: usize,
    clone_notice_return: usize,
    prologue: &[u8],
) -> Vec<u8> {
    let mut code = Vec::new();
    let mut labels = HashMap::new();
    let mut branches = Vec::new();
    macro_rules! emit {
        ($hex:literal) => {
            code.extend_from_slice(&hex::decode($hex).unwrap());
        };
    }
    macro_rules! jump {
        ($opcode:literal, $label:expr) => {
            emit!($opcode);
            branches.push((code.len(), $label));
            code.extend_from_slice(&0i32.to_le_bytes());
        };
    }
    macro_rules! label {
        ($label:literal) => {
            labels.insert($label, code.len());
        };
    }
    emit!("9C5052");
    for status in [0x103u32, 0x302, 0x303, 0x307] {
        emit!("4181F9");
        code.extend_from_slice(&status.to_le_bytes());
        let label: &'static str = match status {
            0x103 => "code103",
            0x302 => "code302",
            0x303 => "code303",
            _ => "code307",
        };
        jump!("0F84", label);
    }
    emit!("4181F900010000");
    jump!("0F85", "forward");
    emit!("48B8");
    code.extend_from_slice(&(clone_notice_return as u64).to_le_bytes());
    emit!("4839442418");
    jump!("0F84", "code100");
    label!("forward");
    emit!("48B8");
    code.extend_from_slice(&((counters + 32) as u64).to_le_bytes());
    emit!("4C8908488B542418488950085A589D");
    code.extend_from_slice(prologue);
    emit!("FF2500000000");
    code.extend_from_slice(&(continuation as u64).to_le_bytes());
    for (label, offset) in [
        ("code103", 0usize),
        ("code302", 16),
        ("code303", 8),
        ("code307", 24),
        ("code100", 48),
    ] {
        labels.insert(label, code.len());
        emit!("48B8");
        code.extend_from_slice(&((counters + offset) as u64).to_le_bytes());
        emit!("F048FF005A589DC3");
    }
    for (offset, label) in branches {
        let displacement = i32::try_from(labels[label] as i64 - offset as i64 - 4).unwrap();
        code[offset..offset + 4].copy_from_slice(&displacement.to_le_bytes());
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warm_stub_has_reference_layout_and_bounds() {
        let start = 0x00007ff612341000;
        let end = 0x00007ff65e002e7c;
        let code = warm_stub(start, end);
        assert_eq!(code.len(), 55);
        assert_eq!(
            u64::from_le_bytes(code[3..11].try_into().unwrap()),
            start as u64
        );
        assert_eq!(
            u64::from_le_bytes(code[13..21].try_into().unwrap()),
            end as u64
        );
        assert_eq!(hex::encode(&code[46..]), "e9ecffffff5b33c0c3");
    }

    #[test]
    fn file_hook_and_table_match_reference_layout() {
        let table = 0x000001ab23456780;
        let continuation = 0x00007ff665432109;
        let code = file_hook_stub(table, continuation);
        assert_eq!(code.len(), 76);
        assert_eq!(
            u64::from_le_bytes(code[12..20].try_into().unwrap()),
            table as u64
        );
        assert_eq!(
            u64::from_le_bytes(code[65..73].try_into().unwrap()),
            continuation as u64
        );
        let packed = file_table(7725530, table);
        assert_eq!(packed.len(), 12);
        assert_eq!(i32::from_le_bytes(packed[..4].try_into().unwrap()), 7725530);
        assert_eq!(
            u64::from_le_bytes(packed[4..].try_into().unwrap()),
            table as u64
        );
    }

    #[test]
    fn loader_shim_has_reference_size_pointers_and_counter_offsets() {
        let counters = 0x0000011122334400;
        let continuation = 0x00007ff665432109;
        let selected_return = 0x00007ff700100100;
        let prologue = hex::decode("4157415641554154565755534881ECB8010000").unwrap();
        let code = loader_status_shim(counters, continuation, selected_return, &prologue);
        assert_eq!(code.len(), 237);
        assert_eq!(
            u64::from_le_bytes(code[91..99].try_into().unwrap()),
            (counters + 32) as u64
        );
        assert_eq!(
            u64::from_le_bytes(code[70..78].try_into().unwrap()),
            selected_return as u64
        );
        assert_eq!(
            u64::from_le_bytes(code[139..147].try_into().unwrap()),
            continuation as u64
        );
        for (offset, counter) in [(149, 0), (167, 16), (185, 8), (203, 24), (221, 48)] {
            assert_eq!(
                u64::from_le_bytes(code[offset..offset + 8].try_into().unwrap()),
                (counters + counter) as u64
            );
        }
    }
}
