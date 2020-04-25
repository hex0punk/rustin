use goblin;
use goblin::elf::Elf;
use goblin::mach::load_command::CommandVariant;
use goblin::mach::MachO;
use goblin::elf::dynamic::{
    DF_1_PIE, DF_BIND_NOW, DT_FLAGS, DT_FLAGS_1, DT_RPATH, DT_RUNPATH,
};
use goblin::elf::header::ET_DYN;
use goblin::elf::program_header::{PF_X, PT_GNU_RELRO, PT_GNU_STACK};

use serde::{Deserialize, Serialize};
use crate::binary::BinType::Mach;

const MH_ALLOW_STACK_EXECUTION: u32 = 0x0002_0000;
const MH_PIE: u32 = 0x0020_0000;
const MH_NO_HEAP_EXECUTION: u32 = 0x0100_0000;

#[derive(Serialize, Deserialize, Debug)]
pub enum Relro {
    Partial,
    Full,
    None,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ElfProtections {
    pub canary: bool,
    pub nx: bool,
    pub pie: bool,
    pub relro: Relro,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MachOProtections {
    pub canary: bool,
    pub nx: bool,
    pub pie: bool,
    pub nx_heap: bool,
    pub arc: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum BinaryProtections {
    ElfProtections(ElfProtections),
    MachOProtections(MachOProtections)
}

pub trait BinProtectionsChecks {
    fn has_canary(&self) -> bool;
    fn has_nx(&self) -> bool;
    fn has_pie(&self) -> bool;
}

pub trait ElfProtectionsChecks {
    fn has_relro(&self) -> Relro;
}

pub trait MachOProtectionsChecks {
    fn has_arc(&self) -> bool;
    fn has_nx_heap(&self) -> bool;
}

pub struct ProtectionsCheck;
impl ProtectionsCheck {
    pub fn parse_elf(elf: &Elf) -> BinaryProtections{
        BinaryProtections::ElfProtections(ElfProtections{
            canary: elf.has_canary(),
            nx: elf.has_nx(),
            pie: elf.has_pie(),
            relro: elf.has_relro(),
        })
    }
    pub fn parse_machO(macho: &MachO) -> BinaryProtections{
        BinaryProtections::MachOProtections(MachOProtections{
            canary: macho.has_canary(),
            nx: macho.has_nx(),
            pie: macho.has_pie(),
            nx_heap: macho.has_nx_heap(),
            arc: macho.has_arc(),
        })
    }
}

impl BinProtectionsChecks for MachO<'_> {
    fn has_canary(&self) -> bool {
        if let Ok(imports) = self.imports() {
            for import in imports.iter() {
                match import.name {
                    "___stack_chk_fail" => return true,
                    "___stack_chk_guard" => return true,
                    _ => continue,
                }
            }
        }
        false
    }
    fn has_nx(&self) -> bool {
        !matches!(self.header.flags & MH_ALLOW_STACK_EXECUTION, x if x != 0)
    }
    fn has_pie(&self) -> bool {
        matches!(self.header.flags & MH_PIE, x if x != 0)
    }

}

impl MachOProtectionsChecks for MachO<'_> {
    fn has_arc(&self) -> bool {
        if let Ok(imports) = self.imports() {
            for import in imports.iter() {
                if import.name == "_objc_release" {
                    return true;
                }
            }
        }
        false
    }
    fn has_nx_heap(&self) -> bool {
        matches!(self.header.flags & MH_NO_HEAP_EXECUTION, x if x != 0)
    }
}

impl BinProtectionsChecks for Elf<'_> {
    fn has_canary(&self) -> bool {
        for sym in &self.dynsyms {
            if let Some(name) = self.dynstrtab.get(sym.st_name) {
                if let Ok(name) = name {
                    match name {
                        "__stack_chk_fail" => return true,
                        "__intel_security_cookie" => return true,
                        _ => continue,
                    }
                }
            }
        }
        false
    }

    fn has_nx(&self) -> bool {
        for header in &self.program_headers {
            if header.p_type == PT_GNU_STACK {
                if PF_X != header.p_flags & PF_X {
                    return true;
                }
                break;
            }
        }
        return false;
    }

    fn has_pie(&self) -> bool {
        if self.header.e_type == ET_DYN {
            return true;
        }
        return false;
    }
}

impl ElfProtectionsChecks for Elf<'_> {
    fn has_relro(&self) -> Relro {
        for header in &self.program_headers {
            if header.p_type == PT_GNU_RELRO {
                if let Some(dynamic) = &self.dynamic {
                    for dyns in &dynamic.dyns {
                        if dyns.d_tag == DT_FLAGS
                            || dyns.d_tag == DT_FLAGS_1
                            && DF_BIND_NOW & dyns.d_val == 0
                        {
                            return Relro::Full;
                        }
                    }
                }
                return Relro::Partial;
            }
        }
        Relro::None
    }
}

