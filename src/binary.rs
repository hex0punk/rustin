use goblin::elf::Elf;
use goblin::mach::{Mach, MachO};
use goblin::Object;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum BinType {
    Elf,
    PE,
    Mach,
    Archive,
    Unknown,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum BinArch {
    X86,
    X64,
    None,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SecType {
    Code,
    Data,
    None,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SymType {
    Func,
    Unk,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum PIE {
    DSO,
    PIE,
    None,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Relro {
    Partial,
    Full,
    None,
}

// SymbolType  type;
// std::string name;
// uint64_t    addr;

#[derive(Serialize, Deserialize, Debug)]
pub struct Symbol {
    pub symboltype: SymType,
    pub name: String,
    pub addr: usize,
}

// Binary       *binary;
// std::string   name;
// SectionType   type;
// uint64_t      vma;
// uint64_t      size;
// uint8_t       *bytes;

#[derive(Serialize, Deserialize, Debug)]
pub struct Section {
    pub name: String,
    pub sectype: u32, //TODO: Parse hex value and match to a SecType
    pub vma: u64,
    pub size: u64,
}

// std::string             filename;
// BinaryType              type;
// std::string             type_str;
// BinaryArch              arch;
// std::string             arch_str;
// unsigned                bits;
// uint64_t                entry;
// std::vector<Section>    sections;
// std::vector<Symbol>     symbols;

// pub struct Protections {
//     /// Stack Canary (*CFLAGS=*`-fstack-protector*`)
//     pub canary: bool,
//     /// Clang Control Flow Integrity (*CFLAGS=*`-fsanitize=cfi-*`)
//     pub clang_cfi: bool,
//     /// Clang SafeStack (*CFLAGS=*`-fsanitize=safe-stack`)
//     pub clang_safestack: bool,
//     /// Fortify (*CFLAGS=*`-D_FORTIFY_SOURCE`)
//     pub fortify: bool,
//     /// Fortified functions
//     pub fortified: u32,
//     //fortifiable:  Option<Vec<OsString>>,
//     /// No Execute
//     pub nx: bool,
//     /// Position Inpendent Executable (*CFLAGS=*`-pie -fPIE`)
//     pub pie: PIE,
//     /// Relocation Read-Only
//     pub relro: Relro,
// }

// pub struct ElfBin(Elf);
// pub struct ElfMachO(MachO);

#[derive(Serialize, Deserialize, Debug)]
pub struct Binary {
    pub filename: String,
    pub binarytype: BinType,
    pub binaryarch: BinArch,
    pub entry: u64,
    pub symbols: Vec<Symbol>,
    pub sections: Vec<Section>,
}

pub trait BinSymbols {
    fn get_symbols(self) -> Vec<Symbol>;
}

pub trait BinSections {
    fn get_sections(self) -> Vec<Section>;
}

impl BinSections for &Elf<'_> {
    fn get_sections(self) -> Vec<Section> {
        let sections = &self.section_headers;
        let mut result: Vec<Section> = Vec::new();
        for sec in sections {
            result.push(Section {
                name: "".to_string(), // TODO: get from sec.sh_name,
                sectype: sec.sh_type, // TODO: Parse as SecType
                vma: sec.sh_addr,
                size: sec.sh_size,
            });
        }
        result
    }
}

impl BinSections for &MachO<'_> {
    fn get_sections(self) -> Vec<Section> {
        let segments = &self.segments;
        let mut result: Vec<Section> = Vec::new();
        for seg in segments {
            let sections = segments.sections();
            //sections is a dynamic iterator, so this needs to be mutable
            let mut unboxed_iter = sections;
            for sec_iter in unboxed_iter {
                for sec in sec_iter {
                    let sec = sec.unwrap();
                    result.push(Section {
                        name: sec.0.name().unwrap().to_string(),
                        sectype: 0, //TODO: Need to find a way to get type of MachO section
                        vma: sec.0.addr,
                        size: sec.0.size,
                    });
                }
            }
        }
        result
    }
}

impl BinSymbols for &Elf<'_> {
    fn get_symbols(self) -> Vec<Symbol> {
        let strtab = &self.strtab;
        let dynstrtab = &self.dynstrtab;
        let syms = &self.syms;
        let dynsyms = &self.dynsyms;

        let mut result: Vec<Symbol> = Vec::new();

        // Get strippable symbols
        for sym in syms.iter() {
            result.push(Symbol {
                symboltype: if sym.is_function() {
                    SymType::Func
                } else {
                    SymType::Unk
                }, // TODO: not accurate
                name: strtab.get(sym.st_name).unwrap().unwrap().to_string(),
                addr: sym.st_name,
            });

            if sym.is_function() {
                let strsym = strtab.get(sym.st_name);
            }
        }
        // Get dynamic symbols
        for sym in dynsyms.iter() {
            result.push(Symbol {
                symboltype: if sym.is_function() {
                    SymType::Func
                } else {
                    SymType::Unk
                }, // TODO: not accurate
                name: dynstrtab.get(sym.st_name).unwrap().unwrap().to_string(),
                addr: sym.st_name,
            });
        }
        result
    }
}

impl BinSymbols for &MachO<'_> {
    fn get_symbols(self) -> Vec<Symbol> {
        let syms = self.symbols.iter().nth(0);
        let mut result: Vec<Symbol> = Vec::new();
        for sym in syms.unwrap().iter() {
            let s = &sym.unwrap();
            result.push(Symbol {
                symboltype: SymType::Func, // TODO: not accurate
                name: s.0.to_string(),
                addr: s.1.n_strx,
            });
        }
        result
    }
}
