use goblin::elf::Elf;
use goblin::error::Error;
use goblin::mach::{Mach, MachO};
use goblin::{error, Object};

use clap::{App, Arg};

use goblin::pe::PE;
use std::env;
use std::fs;
use std::ops::Deref;
use std::path::Path;

mod binary;
use binary::*;

fn load_binary(file: &Path) -> Result<Binary, Error> {
    let buffer = fs::read(file)?;
    match Object::parse(&buffer)? {
        Object::Elf(elf) => Ok(Binary {
            filename: file.display().to_string(),
            binarytype: BinType::Elf,
            binaryarch: if elf.is_64 {
                BinArch::X64
            } else {
                BinArch::X86
            },
            entry: elf.entry,
            symbols: elf.get_symbols(),
            sections: elf.get_sections(),
        }),
        // Object::PE(pe) => {
        //     Ok(Binary {
        //         filename: file.display().to_string(),
        //         binarytype: BinType::PE,
        //         binaryarch: if pe.is_64 { BinArch::X64 } else { BinArch::X86 },
        //         entry: pe.entry as u64,
        //         symbols: None,
        //         sections:
        //     })
        // },
        Object::Mach(mach) => match mach {
            Mach::Binary(macho) => Ok(Binary {
                filename: file.display().to_string(),
                binarytype: BinType::Mach,
                binaryarch: if macho.is_64 {
                    BinArch::X64
                } else {
                    BinArch::X86
                },
                entry: macho.entry,
                symbols: macho.get_symbols(),
                sections: macho.get_sections(),
            }),
            _ => {
                let err =
                    std::io::Error::new(std::io::ErrorKind::Other, "Binary type not supported");
                Err(Error::IO(err))
            }
        },
        _ => {
            let err = std::io::Error::new(std::io::ErrorKind::Other, "Binary type not supported");
            Err(Error::IO(err))
        }
    }
}

fn main() {
    let matches = App::new("rustin")
        .version("0.1.0")
        .author("hex0punk <codedharma@7c0>")
        .about("Basic binary analysis tool")
        .arg(
            Arg::with_name("path")
                .short("p")
                .required(true)
                .long("path")
                .takes_value(true)
                .help("path to binary"),
        )
        .arg(
            Arg::with_name("sections")
                .short("h")
                .long("sections")
                .help("Display sections"),
        )
        .arg(
            Arg::with_name("symbols")
                .short("s")
                .long("symbols")
                .takes_value(false)
                .help("Display symbols"),
        )
        .get_matches();

    let path = matches.value_of("path").unwrap();
    let display_headers = matches.is_present("sections");
    let display_symbols = matches.is_present("symbols");

    let file_path = Path::new(path);
    let bin = load_binary(file_path);
    let bin = bin.unwrap();
    println!("Filename: {:?}", &bin.filename);
    println!("Arch: {:?}", &bin.binaryarch);
    println!("Type: {:?}", &bin.binarytype);
    println!("Entry: {:#x?} \n\n", &bin.entry);

    if display_headers {
        bin.print_sections();
    }

    if display_symbols {
        bin.print_symbols();
    }
}
