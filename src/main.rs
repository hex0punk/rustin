use goblin::{error, Object};
use goblin::error::Error;
use goblin::elf::Elf;
use goblin::mach::{Mach, MachO};

use std::env;
use std::path::Path;
use std::fs;

#[derive(Debug)]
pub enum BinType {
    Elf,
    PE,
    Mach,
    Archive,
    Unknown,
}

#[derive(Debug)]
pub enum BinArch {
    X86,
    X64,
    None,
}

#[derive(Debug)]
pub enum SecType {
    Code,
    Data,
    None,
}

#[derive(Debug)]
pub enum SymType {
    Func,
    Unk,
}

#[derive(Debug)]
pub enum PIE {
    DSO,
    PIE,
    None,
}

#[derive(Debug)]
pub enum Relro {
    Partial,
    Full,
    None,
}

// SymbolType  type;
// std::string name;
// uint64_t    addr;

#[derive(Debug)]
pub struct Symbol {
    pub symboltype: SymType,
    pub name: String,
    pub addr: u64,
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

pub struct Protections {
        /// Stack Canary (*CFLAGS=*`-fstack-protector*`)
        pub canary: bool,
        /// Clang Control Flow Integrity (*CFLAGS=*`-fsanitize=cfi-*`)
        pub clang_cfi: bool,
        /// Clang SafeStack (*CFLAGS=*`-fsanitize=safe-stack`)
        pub clang_safestack: bool,
        /// Fortify (*CFLAGS=*`-D_FORTIFY_SOURCE`)
        pub fortify: bool,
        /// Fortified functions
        pub fortified: u32,
        //fortifiable:  Option<Vec<OsString>>,
        /// No Execute
        pub nx: bool,
        /// Position Inpendent Executable (*CFLAGS=*`-pie -fPIE`)
        pub pie: PIE,
        /// Relocation Read-Only
        pub relro: Relro,
}

// pub struct ElfBin(Elf);
// pub struct ElfMachO(MachO);

#[derive(Debug)]
pub struct Binary{
    pub filename: String,
    pub binarytype: BinType,
    pub binaryarch: BinArch,
    pub entry: u64,
    pub symbols: Option<Vec<Symbol>>,
}

impl Binary {

}

pub trait BinSymbols {
    fn get_symbols(self);
}

impl BinSymbols for &Elf<'_> {
    fn get_symbols(self) {
        let syms = &self.syms;
        println!("{:?}", syms);
    }
}

impl BinSymbols for &MachO<'_> {
    fn get_symbols(self) {
        let syms = self.symbols.iter().nth(0);
        for sym in syms.unwrap().iter()  {
            println!("{:?}", sym.unwrap().0);
        }
    }
}

fn load_binary(file: &Path) -> Result<Binary, Error> {
    let buffer = fs::read(file)?;
    match Object::parse(&buffer)? {
        Object::Elf(elf) => {
            println!("{:?}", elf.section_headers);
            &elf.get_symbols();
            Ok(Binary {
                filename: file.display().to_string(),
                binarytype: BinType::Elf,
                binaryarch: if elf.is_64 { BinArch::X64 } else { BinArch::X86 },
                entry: elf.entry,
                symbols: None,
            })
        },
        Object::PE(pe) => {
            Ok(Binary {
                filename: file.display().to_string(),
                binarytype: BinType::PE,
                binaryarch: if pe.is_64 { BinArch::X64 } else { BinArch::X86 },
                entry: pe.entry as u64,
                symbols: None,
            })
        },
        Object::Mach(mach) => match mach{
            Mach::Binary(macho) => {
                &macho.get_symbols();
                //println!("{:?}", macho.symbols);
                Ok(Binary {
                    filename: file.display().to_string(),
                    binarytype: BinType::Mach,
                    binaryarch: if macho.is_64 { BinArch::X64 } else { BinArch::X86 },
                    entry: macho.entry,
                    symbols: None,
                })
            }
            _ => {
                let err = std::io::Error::new(std::io::ErrorKind::Other, "Binary type not supported");
                Err(Error::IO(err))
            }
        },
        _ => {
            let err = std::io::Error::new(std::io::ErrorKind::Other, "Binary type not supported");
            Err(Error::IO(err))
        },
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    let file_path = Path::new(args[1].as_str());
    let bin = load_binary(file_path);
    println!("{:?}", bin);
}
