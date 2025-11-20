use walkdir::DirEntry;


// Linux: sort by inode to keep files with nearby disk locations together
// (optimises access patterns for many files on ext-filesystems).
#[cfg(target_os = "linux")]
pub fn optimize_file_order(dirs: &mut [DirEntry]) {
	use walkdir::DirEntryExt;
	dirs.sort_by(|a, b| {
		let a_inode = a.ino();
		let b_inode = b.ino();
		a_inode.cmp(&b_inode)
	});
}

// macOS: use the device and inode from `Metadata` for a similar effect to
// Linux. `std::os::unix::fs::MetadataExt` is available on Unix-like
// platforms including macOS and exposes `dev()` and `ino()`.
#[cfg(target_os = "macos")]
pub fn optimize_file_order(dirs: &mut [DirEntry]) {
	use std::os::unix::fs::MetadataExt;
	dirs.sort_by(|a, b| {
		let a_meta = a.metadata();
		let b_meta = b.metadata();
		match (a_meta, b_meta) {
			(Ok(am), Ok(bm)) => (am.dev(), am.ino()).cmp(&(bm.dev(), bm.ino())),
			_ => a.path().cmp(&b.path()),
		}
	});
}

// Windows: metadata does not expose POSIX-style inode semantics portably
// in the standard library in the same way. Fall back to sorting by
// path to provide deterministic ordering on Windows.
#[cfg(target_family = "windows")]
pub fn optimize_file_order(dirs: &mut [DirEntry]) {
	dirs.sort_by(|a, b| a.path().cmp(&b.path()));
}

// Other platforms: no-op (preserve original order).
#[cfg(not(any(target_os = "linux", target_os = "macos", target_family = "windows")))]
pub fn optimize_file_order(_dirs: &mut [DirEntry]) {}
