use goblin::{error, Object};
use goblin::error::Error;
use goblin::elf::Elf;
use goblin::mach::{Mach, MachO};

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
    pub addr: usize,
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
    fn get_symbols(self) -> Vec<Symbol> ;
}

pub trait BinSections {
    fn get_sections(self);
}

impl BinSections for &Elf<'_> {
    fn get_sections(self) {
        let sections = &self.section_headers;
        //println!("{:?}", sections);
    }
}

impl BinSections for &MachO<'_> {
    fn get_sections(self) {
        let segments = &self.segments;
        for seg in segments {
            let sections = segments.sections();
            //sections is a dynamic iterator, so this needs to be mutable
            let mut unboxed_iter = sections;
            for sec_iter in unboxed_iter {
                println!("one");
                for sec in sec_iter{
                    println!("{:?}", sec.unwrap().0);
                }
            }
        }
    }
}

impl BinSymbols for &Elf<'_> {
    fn get_symbols(self) -> Vec<Symbol>  {
        let strtab = &self.strtab;
        let syms = &self.syms;
        let mut result: Vec<Symbol> = Vec::new();
        for sym in syms.iter() {
            //println!("test");
            // println!("{:?}", sym);
            result.push(
                Symbol{
                    symboltype: if sym.is_function() {SymType::Func} else {SymType::Unk},// TODO: not accurate
                    name: strtab.get(sym.st_name).unwrap().unwrap().to_string(),
                    addr: sym.st_name,
                }
            );

            if sym.is_function(){
                let strsym = strtab.get(sym.st_name);
                println!("{:?}", strsym);
                println!("{:?}\n", sym);
            }
        }
        result
    }
}

impl BinSymbols for &MachO<'_> {
    fn get_symbols(self) -> Vec<Symbol> {
        let syms = self.symbols.iter().nth(0);
        let mut result: Vec<Symbol> = Vec::new();
        for sym in syms.unwrap().iter()  {
            let s = &sym.unwrap();
            result.push(
                Symbol{
                    symboltype: SymType::Func, // TODO: not accurate
                    name: s.0.to_string(),
                    addr: s.1.n_strx,
                }
            );
        }
        result
    }
}