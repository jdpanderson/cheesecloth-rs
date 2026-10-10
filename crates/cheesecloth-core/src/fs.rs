//! Private files and directories, and directory sync. The OS code is in
//! `fs/unix.rs` and `fs/windows.rs`.

use std::{io, path::Path};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as os;
#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
use windows as os;

/// Creates `dir` and its parents. Only this user, root or SYSTEM, and on
/// Windows Administrators, may use `dir` (0700 on Unix). An existing `dir`
/// gets the same permissions.
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    os::create_private_dir(dir)
}

/// Writes a file that only this user, root or SYSTEM, and on Windows
/// Administrators, may read (0600 on Unix). The file is written beside
/// `path` and then renamed, so `path` always holds a whole file.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut f = os::create_private_file(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// Makes the creation, renaming and removal of files in `dir` durable. On
/// Windows it does nothing: see `fs/windows.rs`.
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    os::sync_dir(dir)
}

#[cfg(test)]
mod tests;
