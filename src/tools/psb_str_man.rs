use std::io::{BufRead, BufReader, Cursor, Read};
use std::io::{self, Seek, SeekFrom};
use flate2::read::ZlibDecoder;

#[derive(PartialEq)]
pub enum PackageStatus {
    MDF,
    PSB,
    Invalid,
}

struct PSBHeader {
    signature: i32,
    version: i32,
    unk: i32,
    unk2: i32,
    str_off_pos: i32,
    str_data_pos: i32,
    res_off_pos: i32,
    res_len_pos: i32,
    res_data_pos: i32,
    res_index_tree: i32,
}

impl PSBHeader {
    fn new(script: Vec<u8>) -> PSBHeader {
        let mut header: [u8; 40] = [0; 40];
        header.copy_from_slice(&script[0..40]);

        PSBHeader {
            signature: i32::from_le_bytes(header[0..4].try_into().unwrap()),
            version: i32::from_le_bytes(header[4..8].try_into().unwrap()),
            unk: i32::from_le_bytes(header[8..12].try_into().unwrap()),
            unk2: i32::from_le_bytes(header[12..16].try_into().unwrap()),
            str_off_pos: i32::from_le_bytes(header[16..20].try_into().unwrap()),
            str_data_pos: i32::from_le_bytes(header[20..24].try_into().unwrap()),
            res_off_pos: i32::from_le_bytes(header[24..28].try_into().unwrap()),
            res_len_pos: i32::from_le_bytes(header[28..32].try_into().unwrap()),
            res_data_pos: i32::from_le_bytes(header[32..36].try_into().unwrap()),
            res_index_tree: i32::from_le_bytes(header[36..40].try_into().unwrap()),
        }
    }
}

pub struct PSBStrMan {
    script: Vec<u8>,
    compress_package: bool,
    force_max_offset_length: bool,
    off_length: i32,
    str_count: i32,
    old_off_tb_len: i32,
    old_str_dat_len: i32,
}

impl PSBStrMan {
    pub fn new(script: Vec<u8>) -> PSBStrMan {
        PSBStrMan {
            script,
            compress_package: true,
            force_max_offset_length: false,
            off_length: 0,
            str_count: 0,
            old_off_tb_len: 0,
            old_str_dat_len: 0,
        }
    }

    pub fn extract_mdf(mdf: Vec<u8>) -> Vec<u8> {
        let mut zlib: Vec<u8> = Vec::new();
        for i in 8..mdf.len() {
            zlib.push(mdf[i]);
        }

        let mut psb: Vec<u8> = Vec::new();
        let mut decoder: ZlibDecoder<&[u8]> = ZlibDecoder::new(&zlib[..]);
        decoder.read_to_end(&mut psb).unwrap();

        return psb;
    }

    pub fn import(&mut self) -> Vec<String> {
        let status: PackageStatus = PSBStrMan::get_package_status(self.script.clone());
        if status == PackageStatus::Invalid {
            panic!("Invalid package");
        }
        if status == PackageStatus::MDF {
            self.script = PSBStrMan::extract_mdf(self.script.clone());
            self.compress_package = true;
        }

        let header: PSBHeader = PSBHeader::new(self.script.clone());
        let mut reader: &mut Cursor<Vec<u8>> = &mut Cursor::new(self.script.clone());
        reader.seek(SeekFrom::Start(header.str_off_pos as u64)).unwrap();
        self.off_length = self.convert_size(reader.bytes().next().unwrap().unwrap());
        self.str_count = PSBStrMan::read_offset(PSBStrMan::read_bytes_from_cursor(&mut reader, self.off_length), 0, self.off_length as usize);
        self.off_length = self.convert_size(reader.bytes().next().unwrap().unwrap());

        let mut offsets: Vec<i32> = Vec::new();
        for _ in 0..self.str_count {
            offsets.push(PSBStrMan::read_offset(PSBStrMan::read_bytes_from_cursor(&mut reader, self.off_length), 0, self.off_length as usize));
        }
        self.old_off_tb_len = reader.position() as i32  - header.str_off_pos;

        let mut strings: Vec<String> = Vec::new();
        for i in 0..(self.str_count as usize) {
            reader.seek(SeekFrom::Start(header.str_data_pos as u64 + offsets[i] as u64)).unwrap();
            let mut string: Vec<u8> = Vec::new();
            loop {
                let byte: u8 = reader.bytes().next().unwrap().unwrap();
                if byte == 0 {
                    break;
                }
                string.push(byte);
            }
            let string_utf8 = String::from_utf8(string).unwrap();
            strings.push(string_utf8);
        }

        self.old_str_dat_len = reader.position() as i32 - header.str_data_pos;

        return strings;

    }

    fn read_bytes_from_cursor (cursor: &mut Cursor<Vec<u8>>, length:i32) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        for _ in 0..length {
            bytes.push(cursor.bytes().next().unwrap().unwrap());
        }
        return bytes;
    }

    fn convert_size(&self, b: u8) -> i32 {
        if b == 0xD {
            return 1;
        }
        if b == 0xE {
            return 2;
        }
        if b == 0xF {
            return 3;
        }
        if b == 0x10 {
            return 4;
        }
        panic!("Invalid size")
    }

    pub fn get_package_status(script: Vec<u8>) -> PackageStatus {
        let offset = PSBStrMan::read_offset(script, 0, 3);
        print!("Offset: {:x}\n", offset);
        if offset == 0x66646D {
            return PackageStatus::MDF;
        } else if offset == 0x425350 {
            return PackageStatus::PSB;
        }
        return PackageStatus::Invalid;
    }

    fn read_offset(script: Vec<u8>, offset: usize, length: usize) -> i32 {
        let mut value: [u8; 4] = [0; 4];
        let end = std::cmp::min(script.len(), offset + length);
        let start = std::cmp::min(offset, end);

        if start < end {
            value[..end - start].copy_from_slice(&script[start..end]);
        }

        return i32::from_le_bytes(value);
    }

    pub fn set_compress_package(&mut self, compress_package: bool) {
        self.compress_package = compress_package;
    }

    pub fn set_force_max_offset_length(&mut self, force_max_offset_length: bool) {
        self.force_max_offset_length = force_max_offset_length;
    }
}
