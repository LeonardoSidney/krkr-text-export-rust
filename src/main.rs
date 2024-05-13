use crate::tools::psb_analyzer::PSBAnalyzer;

pub mod tools;

use std::fs::File;
use std::io::{self, BufReader, Read};
fn main() {
    println!("KaraKara translate tool!");

    let file_location: &str =
        "/home/sumire/repos/mine/karakara/karakaraInjector/karakara-01.txt.scn";
    let file: File = File::open(file_location).expect("file not found");
    let reader = BufReader::new(file);

    let buffer: Vec<u8> = reader
        .bytes()
        .collect::<Result<_, _>>()
        .expect("Falha ao ler os bytes do arquivo");

    let mut psb_analyzer: PSBAnalyzer = PSBAnalyzer::new(buffer);

    for string in psb_analyzer.import() {
        println!("{}", string);
    }
}
