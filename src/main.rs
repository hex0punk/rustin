use goblin::elf::header::machine_to_str;
use goblin::error::Error;
use goblin::mach::constants::cputype::get_arch_name_from_types;
use goblin::mach::Mach;
use goblin::Object;

use clap::{App, Arg};

use std::fs;
use std::path::Path;

mod binary;
use binary::*;

fn load_binary(file: &Path) -> Result<Binary, Error> {
    let buffer = fs::read(file)?;
    match Object::parse(&buffer)? {
        Object::Elf(elf) => {
            let symbols = elf.get_symbols();
            Ok(Binary {
                filename: file.display().to_string(),
                binarytype: BinType::Elf,
                binaryarch: if elf.is_64 {
                    BinArch::X64
                } else {
                    BinArch::X86
                },
                entry: elf.entry,
                language: Binary::get_language(&symbols), //borrowed
                symbols,                                  //moved (so this must come after
                sections: elf.get_sections(),
                protections: protections::ProtectionsCheck::parse_elf(&elf),
                libraries: elf.libraries.iter().map(|s| s.to_string()).collect(),
                machine: machine_to_str(elf.header.e_machine).to_string(),
            })
        }
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
            Mach::Binary(macho) => {
                let symbols = macho.get_symbols();
                Ok(Binary {
                    filename: file.display().to_string(),
                    binarytype: BinType::Mach,
                    binaryarch: if macho.is_64 {
                        BinArch::X64
                    } else {
                        BinArch::X86
                    },
                    entry: macho.entry,
                    language: Binary::get_language(&symbols), //borrowed
                    symbols,                                  //moved
                    sections: macho.get_sections(),
                    protections: protections::ProtectionsCheck::parse_macho(&macho),
                    libraries: macho.libs.iter().map(|s| s.to_string()).collect(),
                    machine: match get_arch_name_from_types(
                        macho.header.cputype,
                        macho.header.cpusubtype,
                    ) {
                        Some(m_type) => m_type.to_string(),
                        None => "unknown".to_string(),
                    },
                })
            }
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
                .short("s")
                .long("sections")
                .help("Display sections"),
        )
        .arg(
            Arg::with_name("libraries")
                .short("l")
                .long("libs")
                .help("Display libraries"),
        )
        .arg(
            Arg::with_name("symbols")
                .short("S")
                .long("symbols")
                .takes_value(false)
                .help("Display symbols"),
        )
        .get_matches();

    let path = matches.value_of("path").expect("Error parsing path");
    let display_headers = matches.is_present("sections");
    let display_symbols = matches.is_present("symbols");
    let display_libs = matches.is_present("libraries");

    let file_path = Path::new(path);
    let bin = load_binary(file_path);
    let bin = match bin {
        Ok(bin) => bin,
        Err(err) => panic!("Problem opening the file: {:?}", err),
    };

    bin.print_properties();

    bin.protections.print_protections();

    println!("\n\n");

    if display_headers {
        bin.print_sections();
    }

    if display_symbols {
        bin.print_symbols();
    }

    if display_libs {
        bin.print_libraries();
    }
}
