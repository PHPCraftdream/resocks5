use std::fs::{self, File};
use std::io;
use std::path::Path;

use anyhow::{Context, Result};

/// Non-unix/windows targets have no supported advisory lock here;
/// this fallback keeps exotic targets compiling (CI is
/// ubuntu+windows only) but provides no real exclusion.
pub(super) fn try_exclusive_lock(_file: &File) -> io::Result<()> {
    Ok(())
}

pub(super) fn unlock(_file: &File) -> io::Result<()> {
    Ok(())
}

pub(super) fn is_lock_busy(_e: &io::Error) -> bool {
    false
}

/// Old plain-rename behavior.
pub(super) fn commit(tmp: &Path, path: &Path) -> Result<()> {
    if let Err(e) = fs::rename(tmp, path) {
        let _ = fs::remove_file(tmp);
        return Err(e)
            .with_context(|| format!("replace {} with {}", path.display(), tmp.display()));
    }
    Ok(())
}
