use crate::tools::psb_str_man::{PSBStrMan, PackageStatus};

pub struct PSBAnalyzer {
    script: Vec<u8>,
    psb_str_man: PSBStrMan,
    extend_string_limit: bool,
    embeded_referenced: bool,
    warning: bool,
    byte_code_start: u32,
    byte_code_len: u32,
    strings: Vec<String>,
}

impl PSBAnalyzer {
    pub fn new(mut script: Vec<u8>) -> PSBAnalyzer {
        let extend_string_limit: bool = false;
        let mut status: PackageStatus = PSBStrMan::get_package_status(script.clone());
        if status == PackageStatus::MDF {
            script = PSBStrMan::extract_mdf(script.clone());
        }
        status = PSBStrMan::get_package_status(script.clone());
        if status != PackageStatus::PSB {
            panic!("Invalid package");
        }

        let mut psb_str_man: PSBStrMan = PSBStrMan::new(script.clone());
        psb_str_man.set_compress_package(true);
        psb_str_man.set_force_max_offset_length(extend_string_limit);

        let byte_code_start: u32 = PSBAnalyzer::read_offset(script.clone(), 0x24, 4);
        let byte_code_len: u32 =
            PSBAnalyzer::read_offset(script.clone(), 0x10, 4) - byte_code_start;

        if byte_code_len + byte_code_start > script.len() as u32 {
            panic!("Corrupted PSB file");
        }

        PSBAnalyzer {
            script,
            psb_str_man,
            extend_string_limit,
            embeded_referenced: false,
            warning: false,
            byte_code_start,
            byte_code_len,
            strings: Vec::new(),
        }
    }

    pub fn import(&mut self) -> Vec<String> {
        self.embeded_referenced = false;
        self.warning = false;

        let mut calls: Vec<u32> = Vec::new();
        let strings: Vec<String> = self.psb_str_man.import();

        let mut i:u32 = self.byte_code_start;
        loop {
            if i >= self.byte_code_start + self.byte_code_len {
                break;
            }

            let result: Vec<u32> = self.analyze(self.script.clone(), &mut i);
            for id in result {
                if id < strings.len() as u32 && !calls.contains(&id) {
                    calls.push(id);
                }
            }
        }

        for i in 0..strings.len() {
            if !calls.contains(&(i as u32)) {
                println!("Unused string: {}", strings[i]);
                calls.push(i as u32);
            }
        }

        self.strings = PSBAnalyzer::desort(strings.clone(), calls);

        return self.strings.clone();
    }

    fn desort (strings: Vec<String>, calls: Vec<u32>) -> Vec<String> {
        if calls.len() != strings.len() {
            panic!("Calls and strings length mismatch");
        }

        let mut sorted: Vec<String> = Vec::new();
        for i in 0..calls.len() {
            sorted.push(strings[calls[i] as usize].clone());
        }

        return sorted;
    }

    fn analyze(&mut self, script: Vec<u8>, index: &mut u32) -> Vec<u32>{
        let cmd: u8 = script[*index as usize];

        let id: u32 = 0;
        let mut ids: Vec<u32> = Vec::new();

        // strings
        if cmd == 0x15 {
            ids.push(PSBAnalyzer::read_offset(script.clone(), *index + 1, 1));
            *index += 2;
            return ids;
        }
        if cmd == 0x16 {
            ids.push(PSBAnalyzer::read_offset(script.clone(), *index + 1, 2));
            *index += 3;
            return ids;
        }
        if cmd == 0x17 {
            ids.push(PSBAnalyzer::read_offset(script.clone(), *index + 1, 3));
            *index += 4;
            return ids;
        }
        if cmd == 0x18 {
            ids.push(PSBAnalyzer::read_offset(script.clone(), *index + 1, 4));
            *index += 5;
            return ids;
        }
        //numbers
        let numbers: Vec<i32> = vec![0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC];
        if numbers.contains(&(cmd as i32)) {
            *index += 1;
            *index += cmd as u32 - 0x4;
            return ids;
        }
        if cmd == 0x1d {
            *index += 1;
            return ids;
        }
        if cmd == 0x1e {
            *index += 1;
            *index += 4;
            return ids;
        }
        if cmd == 0x1f {
            *index += 1;
            *index += 8;
            return ids;
        }

        let constants: Vec<i32> = vec![0x0, 0x1, 0x2, 0x3];
        if constants.contains(&(cmd as i32)) {
            *index += 1;
            return ids;
        }
        let arrays: Vec<i32> = vec![0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14];
        if arrays.contains(&(cmd as i32)) {
            *index += 1;
            let c_len: u32 = cmd as u32 - 0x0c;
            let count: u32 = PSBAnalyzer::read_offset(script.clone(), *index, c_len);
            *index += c_len;

            let script_byte_read: u8 = script[*index as usize];
            *index += 1;
            let e_len: u32 = script_byte_read as u32 - 0xc;
            *index += e_len * count;

            return ids;
        }
        if cmd == 0x20 {
            *index += 1;
            ids.extend(self.analyze(script.clone(), index));
            return ids;
        }
        if cmd == 0x21 {
            *index += 1;
            ids.extend(self.analyze(script.clone(), index));
            ids.extend(self.analyze(script.clone(), index));
            return ids;
        }
        let references_to_embeded: Vec<i32> = vec![0x19, 0x1a, 0x1b, 0x1c];
        if references_to_embeded.contains(&(cmd as i32)) {
            self.embeded_referenced = true;
            *index += 1;
            *index += cmd as u32 - 0x18;
            return ids;
        }

        self.warning = true;
        *index += 1;
        return ids;
    }

    fn read_offset(script: Vec<u8>, offset: u32, length: u32) -> u32 {
        let mut value: [u8; 8] = [0; 8];

        let end:u32 = std::cmp::min(script.len() as u32, offset + length);
        let start = std::cmp::min(offset, end);

        if start < end {
            value[..end as usize - start as usize].copy_from_slice(&script[start as usize..end as usize]);
        }

        let value64: u64 = u64::from_le_bytes(value);
        return value64 as u32;
    }
}
