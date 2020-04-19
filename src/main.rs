use goblin::{error, Object};
use goblin::error::Error;
use goblin::elf::Elf;
use goblin::mach::{Mach, MachO};

use std::env;
use std::path::Path;
use std::fs;
use goblin::pe::PE;
use std::ops::Deref;

mod binary;
use binary::*;


fn load_binary(file: &Path) -> Result<Binary, Error> {
    let buffer = fs::read(file)?;
    match Object::parse(&buffer)? {
        Object::Elf(elf) => {
            //println!("{:?}", elf.section_headers);
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
        Object::Mach(mach) => match mach {
            Mach::Binary(macho) => {
                &macho.get_symbols();
                &macho.get_sections();
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
