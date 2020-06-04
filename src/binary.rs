use goblin::elf::section_header::sht_to_str;
use goblin::elf::Elf;
use goblin::mach::constants as mach_constants;
use goblin::mach::MachO;

use std::fmt;
use std::str;

use serde::export::Formatter;
use serde::{Deserialize, Serialize};

pub mod protections;

#[derive(Serialize, Deserialize, Debug)]
pub enum BinType {
    Elf,
    PE,
    Mach,
    Archive,
    Unknown,
}

//Created custom impl for debug below
#[derive(Serialize, Deserialize)]
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
    pub sectype: String, //TODO: Parse hex value and match to a SecType
    pub vma: u64,
    pub size: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Binary {
    pub filename: String,
    pub binarytype: BinType,
    pub binaryarch: BinArch,
    pub entry: u64,
    pub language: String,
    pub symbols: Vec<Symbol>,
    pub sections: Vec<Section>,
    pub protections: protections::BinaryProtections,
    pub libraries: Vec<String>,
    pub machine: String,
}

impl Binary {
    pub fn print_properties(&self) {
        println!("{:<14} {}", "filename:", &self.filename);
        println!("{:<14} {}", "arch:", format!("{:?}", &self.binaryarch));
        println!("{:<14} {}", "type:", format!("{:?}", &self.binarytype));
        println!("{:<14} {}", "machine:", &self.machine);
        println!("{:<14} {}", "language:", &self.language);
        println!("{:<14} {:#x}", "entry:", &self.entry);
    }

    pub fn print_symbols(&self) {
        println!("{0:<10} {1:<} {2:>50}", "VAddress", "Type", "Name");
        println!("{:-<1$}", "", 70);
        for sym in &self.symbols {
            println!(
                "{:#010x?} {:>20?} {:>50}",
                sym.addr, sym.symboltype, sym.name,
            );
        }
        println!("Number of Symbols: {}", &self.symbols.len());
    }

    pub fn print_sections(&self) {
        println!("{} {:>11} {:<20} {:10}", "VAddress", "Size", "Name", "Type");
        println!("{:-<1$}", "", 60);
        for sec in &self.sections {
            println!(
                "{:#010x?} {:#10x?} {:#20} {:10}",
                sec.vma, sec.size, sec.name, sec.sectype
            );
        }
    }

    pub fn print_libraries(&self) {
        for lib in &self.libraries {
            println!("{:?}", lib);
        }
    }

    //static
    pub fn get_language(symbols: &Vec<Symbol>) -> String {
        let mut result = "unknown or c";
        for sym in symbols {
            if sym.name.contains("_$LT$") {
                result = "rust";
                break;
            } else if sym.name.len() >= 3 && &sym.name[..3] == "go." {
                result = "go";
                break;
            } else if sym.name.contains("swift_once") {
                result = "swift";
                break;
            } else if sym.name.len() >= 6 && &sym.name[..6] == "_OBJC_" {
                // Have to make sure it isn't swift, so can't return
                result = "objc";
            } else if sym.name.len() >= 6 && &sym.name[..6] == "_objc_" {
                // Have to make sure it isn't swift, so can't return
                result = "objc";
            } else if sym.name.len() >= 2 && &sym.name[..2] == "_Z" {
                result = "c";
            } else if sym.name.len() >= 3 && &sym.name[..3] == "__Z" {
                result = "c";
            }
        }
        result.to_string()
    }
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
                name: self
                    .shdr_strtab
                    .get(sec.sh_name)
                    .expect("Error getting section")
                    .expect("Error obtaining section name")
                    .to_string(), // TODO: get from sec.sh_name,
                sectype: sht_to_str(sec.sh_type).to_string(), // TODO: Parse as SecType
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
        let sections = segments.sections();
        //sections is a dynamic iterator, so this needs to be mutable
        let unboxed_iter = sections;
        for sec_iter in unboxed_iter {
            for sec in sec_iter {
                let sec = match sec {
                    Ok(sec) => sec,
                    Err(_err) => continue,
                };
                let name = match sec.0.name() {
                    Ok(name) => name.to_string(),
                    Err(_err) => "Invalid Name".to_string(),
                };
                let sec_type = sec.0.flags & mach_constants::SECTION_TYPE;
                result.push(Section {
                    name,
                    sectype: s_type_to_str(sec_type).to_string(), //TODO: Need to find a way to get type of MachO section
                    vma: sec.0.addr,
                    size: sec.0.size,
                });
            }
        }
        result
    }
}

impl BinSymbols for &Elf<'_> {
    fn get_symbols(self) -> Vec<Symbol> {
        let strtab = &self.strtab;
        let syms = &self.syms;
        let dynsyms = &self.dynsyms;

        let mut result: Vec<Symbol> = Vec::new();

        // Get strippable symbols
        for sym in syms.iter() {
            let name = strtab
                .get(sym.st_name)
                .expect("")
                .expect("Error getting section name");
            result.push(Symbol {
                symboltype: if sym.is_function() {
                    SymType::Func
                } else {
                    SymType::Unk
                },
                name: name.to_string(),
                addr: sym.st_name,
            });
        }
        // Get dynamic symbols
        for sym in dynsyms.iter() {
            let name = strtab
                .get(sym.st_name)
                .expect("")
                .expect("Error getting section name");
            result.push(Symbol {
                symboltype: if sym.is_function() {
                    SymType::Func
                } else {
                    SymType::Unk
                },
                name: name.to_string(),
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
        let iter = syms.expect("Error obtaining symbol iterator");
        for sym in iter {
            let s = &sym.expect("Error obtaining symbol list");
            result.push(Symbol {
                symboltype: SymType::Func, // TODO: not accurate
                name: s.0.to_string(),
                addr: s.1.n_strx,
            });
        }
        result
    }
}

impl fmt::Debug for BinArch {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            BinArch::X64 => write!(f, "x64"),
            BinArch::X86 => write!(f, "x86"),
            BinArch::None => write!(f, "unknown"),
        }
    }
}

fn s_type_to_str(sec: u32) -> &'static str {
    match sec {
        mach_constants::S_REGULAR => "S_REGULAR",
        mach_constants::S_ZEROFILL => "S_ZEROFILL",
        mach_constants::S_NON_LAZY_SYMBOL_POINTERS => "S_NON_LAZY_SYMBOL_POINTERS",
        mach_constants::S_SYMBOL_STUBS => "S_SYMBOL_STUBS",
        _ => "UNKNOWN",
    }
}
