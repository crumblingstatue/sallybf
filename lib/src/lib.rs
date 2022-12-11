use byteorder::{ByteOrder, LE};
use std::path::Path;

use encoding::{all::ISO_8859_1, Encoding};
use thiserror::Error;

/// Handle to a BG&E BigFile
#[derive(Debug)]
pub struct Bf {
    map: memmap2::Mmap,
    meta: Meta,
}

#[derive(Debug)]
pub struct OffsetKeyPair {
    offset: u32,
    key: u32,
}

#[derive(Debug, Clone)]
pub struct Dir {
    first_file_idx: u32,
    first_subdir_idx: u32,
    next_idx: u32,
    prev_idx: u32,
    parent_idx: u32,
    name: String,
}

impl Dir {
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone)]
pub struct File {
    size: u32,
    next_idx: u32,
    prev_idx: u32,
    dir_idx: u32,
    unix_stamp: u32,
    name: String,
}

impl File {
    pub fn size(&self) -> u32 {
        self.size
    }
}

#[derive(Debug)]
struct Meta {
    offset_key_pairs: Vec<OffsetKeyPair>,
    dirs: Vec<Dir>,
    files: Vec<File>,
}

#[derive(Error, Debug)]
pub enum HeaderParseError {
    #[error("Magic mismatch. Expected 'BIG\\0', found {found_bytes:?}")]
    MagicMismatch { found_bytes: [u8; 4] },
    #[error("Unsupported version. Expected 0x22, got {ver:x}")]
    UnsupportedVer { ver: u32 },
}

#[derive(Error, Debug)]
pub enum OpenError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("header parse error: {0}")]
    HeaderParse(#[from] HeaderParseError),
}

fn file_meta_offset(offset_table_offset: u32, offset_table_max_size: u32) -> usize {
    (offset_table_offset + offset_table_max_size * 8) as usize
}

fn dir_meta_offset(file_meta_offset: usize, offset_table_max_size: u32) -> usize {
    file_meta_offset + offset_table_max_size as usize * 84
}

impl Bf {
    /// Open a BigFile located at `path`.
    ///
    /// # Safety
    ///
    /// The file must not be changed while the `Bf` value exists.
    /// This is because the underlying implementation is a memory map, which can cause
    /// memory safety issues if the underlying file is changed while it's active.
    pub unsafe fn open<P: AsRef<Path>>(path: P) -> Result<Bf, OpenError> {
        let f = std::fs::File::open(path)?;
        let map = memmap2::Mmap::map(&f)?;
        let magic = &map[0..4];
        if magic != b"BIG\0" {
            return Err(HeaderParseError::MagicMismatch {
                found_bytes: magic.try_into().unwrap(),
            }
            .into());
        }
        let ver = LE::read_u32(&map[4..]);
        if ver != 0x22 {
            return Err(HeaderParseError::UnsupportedVer { ver }.into());
        }
        let file_count = LE::read_u32(&map[8..]);
        let dir_count = LE::read_u32(&map[12..]);
        let offset_table_max_size = LE::read_u32(&map[32..]);
        let _initial_key = LE::read_u32(&map[40..]);
        let offset_table_offset = LE::read_u32(&map[52..]);
        let mut off = offset_table_offset as usize;
        macro_rules! r_u32 {
            () => {{
                let val = LE::read_u32(&map[off..]);
                off += 4;
                val
            }};
        }
        let mut offset_table_entries = Vec::with_capacity(file_count as usize);
        for _ in 0..file_count {
            let offset = r_u32!();
            let key = r_u32!();
            offset_table_entries.push(OffsetKeyPair { offset, key });
        }

        let file_meta_offset = file_meta_offset(offset_table_offset, offset_table_max_size);
        off = file_meta_offset;
        let mut file_meta_entries = Vec::with_capacity(file_count as usize);
        for _ in 0..file_count {
            let file_size = r_u32!();
            // Swapped prev/next
            let prev = r_u32!();
            let next = r_u32!();
            let dir_idx = r_u32!();
            let unix_stamp = r_u32!();
            let filename = decode_iso_null_term(&map[off..]);
            off += 64;
            file_meta_entries.push(File {
                size: file_size,
                next_idx: next,
                prev_idx: prev,
                dir_idx,
                unix_stamp,
                name: filename,
            });
        }
        off = dir_meta_offset(file_meta_offset, offset_table_max_size);
        let mut dir_meta_entries = Vec::with_capacity(dir_count as usize);
        for _ in 0..dir_count {
            let first_file_idx = r_u32!();
            let first_subdir_idx = r_u32!();
            // Swapped prev/next
            let prev_idx = r_u32!();
            let next_idx = r_u32!();
            let parent_idx = r_u32!();
            let dir_name = decode_iso_null_term(&map[off..]);
            dir_meta_entries.push(Dir {
                first_file_idx,
                first_subdir_idx,
                next_idx,
                prev_idx,
                parent_idx,
                name: dir_name,
            });
            off += 64;
        }
        Ok(Self {
            map,
            meta: Meta {
                offset_key_pairs: offset_table_entries,
                dirs: dir_meta_entries,
                files: file_meta_entries,
            },
        })
    }
    pub fn read_dir(&self, node: NodeIdx) -> impl Iterator<Item = (NodeIdx, Node)> {
        let mut dir_entries = vec![];
        log::debug!("read_dir for node idx {node}");
        let dir = &self.meta.dirs[node as usize];
        log::debug!("== read_dir dir Node debug ==");
        log::debug!("{dir:#?}");
        log::debug!("== END read_dir dir Node debug ==");
        // Subdirs
        let mut idx = dir.first_subdir_idx;
        loop {
            if idx == INVALID {
                break;
            }
            let subdir = &self.meta.dirs[idx as usize];
            dir_entries.push((idx, Node::Dir(subdir.clone())));
            idx = subdir.next_idx;
        }
        // Files
        idx = dir.first_file_idx;
        loop {
            if idx == INVALID {
                break;
            }
            let file = &self.meta.files[idx as usize];
            dir_entries.push((idx, Node::File(file.clone())));
            idx = file.next_idx;
        }
        log::debug!("{dir_entries:#?}");
        dir_entries.into_iter()
    }
    pub fn lookup_dir_entry(&self, dir_idx: NodeIdx, name: &str) -> Option<(NodeIdx, Node)> {
        let dir = self.meta.dirs.get(dir_idx as usize)?;
        log::debug!("Looking up '{name}' inside '{}' ({dir_idx})", dir.name());
        // Search subdirs
        let mut idx = dir.first_subdir_idx;
        loop {
            if idx == INVALID {
                break;
            }
            let dir = &self.meta.dirs[idx as usize];
            log::debug!("Comparing '{name}' against {}", dir.name);
            if dir.name == name {
                log::debug!("Found dir '{name}', idx {idx}");
                return Some((idx, Node::Dir(dir.clone())));
            }
            idx = dir.next_idx;
        }
        // Search files
        idx = dir.first_file_idx;
        loop {
            if idx == INVALID {
                break;
            }
            let file = &self.meta.files[idx as usize];
            if file.name == name {
                log::debug!("Found file '{name}', idx {idx}");
                return Some((idx, Node::File(file.clone())));
            }
            idx = file.next_idx;
        }
        log::debug!("No such entry: '{name}' inside {dir_idx}");
        None
    }
    pub fn get_file_meta(&self, idx: NodeIdx) -> Option<&File> {
        self.meta.files.get(idx as usize)
    }
    pub fn get_dir_meta(&self, idx: NodeIdx) -> Option<&Dir> {
        self.meta.dirs.get(idx as usize)
    }
    pub fn get_file_data(&self, idx: NodeIdx) -> Option<&[u8]> {
        let offset = self.meta.offset_key_pairs.get(idx as usize)?.offset as usize;
        let size = LE::read_u32(&self.map[offset..]);
        Some(&self.map[offset + 4..offset + 4 + size as usize])
    }
}

type NodeIdx = u32;
const INVALID: NodeIdx = NodeIdx::MAX;

#[derive(Debug)]
pub enum Node {
    File(File),
    Dir(Dir),
}

impl Node {
    pub fn name(&self) -> &str {
        match self {
            Node::File(f) => &f.name,
            Node::Dir(d) => &d.name,
        }
    }
}

fn decode_iso_null_term(data: &[u8]) -> String {
    let len = data.iter().position(|b| *b == 0).unwrap_or(64);
    let data = &data[..len];
    ISO_8859_1
        .decode(data, encoding::DecoderTrap::Strict)
        .unwrap()
}
