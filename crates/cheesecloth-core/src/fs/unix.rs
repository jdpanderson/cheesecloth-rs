//! Unix: private files and directories through permission bits.

use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub(super) fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

/// Creates a new file with mode 0600. Fails if the file exists.
pub(super) fn create_private_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

pub(super) fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}
