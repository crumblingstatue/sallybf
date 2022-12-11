#![feature(iter_array_chunks)]

use std::{
    env,
    time::{Duration, SystemTime},
};

use fuser::{FileAttr, FileType};
use sallybf::Bf;

struct Fs {
    bf: Bf,
}

impl fuser::Filesystem for Fs {
    fn lookup(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        let InodeResolvedIdx::Dir(parent_idx) = self.bf.resolve_inode(parent) else {
            panic!("Trying to look up child of a file");
        };
        match self
            .bf
            .lookup_dir_entry(parent_idx, &name.to_string_lossy())
        {
            Some((idx, node)) => reply.entry(
                &Duration::ZERO,
                &FileAttr {
                    ino: node.resolve_inode(idx),
                    size: node.size(),
                    blocks: 0,
                    atime: SystemTime::UNIX_EPOCH,
                    mtime: SystemTime::UNIX_EPOCH,
                    ctime: SystemTime::UNIX_EPOCH,
                    crtime: SystemTime::UNIX_EPOCH,
                    kind: node.file_type(),
                    perm: node.perm(),
                    nlink: 0,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    blksize: 0,
                    flags: 0,
                },
                0,
            ),
            None => reply.error(1),
        }
    }
    fn getattr(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyAttr) {
        let Some(node) = self.bf.lookup_inode(ino) else {
            log::debug!("getattr inode {ino} Not found");
            reply.error(1);
            return;
        };
        log::debug!("getattr node {ino} resolved to {}", node.name());
        log::debug!("{node:#?}");
        reply.attr(
            &Duration::ZERO,
            &FileAttr {
                ino,
                size: node.size(),
                blocks: 0,
                atime: SystemTime::UNIX_EPOCH,
                mtime: SystemTime::UNIX_EPOCH,
                ctime: SystemTime::UNIX_EPOCH,
                crtime: SystemTime::UNIX_EPOCH,
                kind: node.file_type(),
                perm: node.perm(),
                nlink: 0,
                uid: 0,
                gid: 0,
                rdev: 0,
                blksize: 0,
                flags: 0,
            },
        )
    }
    fn readdir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: fuser::ReplyDirectory,
    ) {
        if offset == 0 {
            for (i, (node_idx, entry)) in self.bf.read_dir(ino as u32 - 1).enumerate() {
                let full = reply.add(
                    entry.resolve_inode(node_idx),
                    dbg!(i as i64 + 1),
                    entry.file_type(),
                    entry.name(),
                );
                if full {
                    log::warn!("Full buffer");
                    reply.ok();
                    return;
                }
            }
        }
        reply.ok();
    }
    fn read(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyData,
    ) {
        let Some(filedata) = self.bf.get_file_by_inode(ino) else {
            reply.error(1);
            return;
        };
        let end = (offset as usize + size as usize).min(filedata.len());
        reply.data(&filedata[offset as usize..end]);
    }
}

pub trait BfNodeExt {
    fn file_type(&self) -> FileType;
    fn perm(&self) -> u16;
    fn resolve_inode(&self, idx: u32) -> u64;
    fn size(&self) -> u64;
}

impl BfNodeExt for sallybf::Node {
    fn file_type(&self) -> FileType {
        match self {
            sallybf::Node::File(_) => FileType::RegularFile,
            sallybf::Node::Dir(_) => FileType::Directory,
        }
    }
    fn perm(&self) -> u16 {
        match self {
            sallybf::Node::File(_) => 0o644,
            sallybf::Node::Dir(_) => 0o755,
        }
    }
    fn resolve_inode(&self, idx: u32) -> u64 {
        let inode = match self {
            sallybf::Node::File(_) => idx as u64 + FILE_INODE_BEGIN,
            // FUSE root is at 1, sallybf root is at idx 0.
            // To map root to 1, we map inodes to (index + 1)
            sallybf::Node::Dir(_) => idx as u64 + 1,
        };
        log::debug!("Made inode {inode} for idx {idx}");
        inode
    }

    fn size(&self) -> u64 {
        match self {
            sallybf::Node::File(f) => f.size() as u64,
            sallybf::Node::Dir(_) => 0,
        }
    }
}

pub trait BfExt {
    fn resolve_inode(&self, inode: u64) -> InodeResolvedIdx;
    fn lookup_inode(&self, inode: u64) -> Option<sallybf::Node>;
    fn get_file_by_inode(&self, inode: u64) -> Option<&[u8]>;
}

pub enum InodeResolvedIdx {
    Dir(u32),
    File(u32),
}

impl BfExt for Bf {
    fn resolve_inode(&self, inode: u64) -> InodeResolvedIdx {
        if inode >= FILE_INODE_BEGIN {
            let idx = (inode - FILE_INODE_BEGIN) as u32;
            log::debug!("It's a file, index {idx}");
            InodeResolvedIdx::File(idx)
        } else {
            let idx = inode as u32 - 1;
            log::debug!("It's a directory, index {idx}");
            InodeResolvedIdx::Dir(idx)
        }
    }
    fn lookup_inode(&self, inode: u64) -> Option<sallybf::Node> {
        log::debug!("lookup_inode for inode {inode}");
        let result = match self.resolve_inode(inode) {
            InodeResolvedIdx::Dir(idx) => self
                .get_dir_meta(idx)
                .map(|d| sallybf::Node::Dir(d.clone())),
            InodeResolvedIdx::File(idx) => self
                .get_file_meta(idx)
                .map(|f| sallybf::Node::File(f.clone())),
        };
        log::debug!("Lookup result: {result:#?}");
        result
    }
    fn get_file_by_inode(&self, inode: u64) -> Option<&[u8]> {
        let idx = inode.checked_sub(FILE_INODE_BEGIN)? as u32;
        self.get_file_data(idx)
    }
}

const FILE_INODE_BEGIN: u64 = i32::MAX as u64 + 1;

fn main() {
    env_logger::init();
    let Some([bf_path, mount_path]) = env::args_os().skip(1).array_chunks().next() else {
        eprintln!("Usage: sallybf-fuse <bf_path> <mount_path>");
        return;
    };
    let bf = unsafe { Bf::open(bf_path).unwrap() };
    fuser::mount2(Fs { bf }, mount_path, &[]).unwrap();
}
