/* Copyright [2025] [Cerda]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Main functions doing actual work.
//!
//!
//! Use `create_hashes()` to prepare the hashes for a path.
//!
//! Then use `write_hashes()` to save it to disk, or `read_hashes()` to get the
//! saved hashes, them with `compare_hashes()` and print them with
//! `write_hash_comparison_results()`.

mod compare;
mod write;
mod optimize_file_order;

use std::{
	collections::BTreeMap,
	fs::File,
	io::{BufRead, BufReader, Write},
	path::{Path, PathBuf},
	sync::LazyLock,
	time::Duration,
};

use indicatif::{ProgressBar, ProgressIterator, ProgressStyle};
use regex::Regex;
use tabwriter::TabWriter;
use walkdir::{DirEntry, WalkDir};

pub use self::{compare::*, write::*};
use crate::{
	Algorithm, Error, hash_file,
	utilities::relative_name,
};

static SPINNER_STRINGS: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Create subpath->hash mappings for a given path using a given algorithm up to
/// a given depth.
pub fn create_hashes(
	path: &Path,
	ignored_files: Vec<PathBuf>,
	algo: Algorithm,
	depth: Option<usize>,
	follow_symlinks: bool,
) -> BTreeMap<PathBuf, String> {
	let mut walkdir = WalkDir::new(path).follow_links(follow_symlinks);
	if let Some(depth) = depth {
		walkdir = walkdir.max_depth(depth + 1);
	}

	let pb_style = ProgressStyle::default_bar()
		.template("{prefix:.bold.dim} {spinner} {wide_bar} {pos:>7}/{len:7} ETA: {eta} - {msg}")
		.unwrap()
		.tick_strings(&SPINNER_STRINGS);

	let pb = ProgressBar::new_spinner();
	pb.set_style(pb_style);

	pb.enable_steady_tick(Duration::from_millis(80));
	pb.set_message("Finding files to hash...");
	let mut files: Vec<DirEntry> = walkdir
		.into_iter()
		.filter_entry(|e: &walkdir::DirEntry| {
			let filename = relative_name(path, e.path());
			match (ignored_files.iter().any(|f| f.as_path().eq(filename)), e.file_type().is_file()) {
				(true, true) => {
					// hashes.insert(mul_str("-", algo.hexlen()), filename);
					false
				}
				(true, false) => false,
				_ => true,
			}
		})
		.flatten()
		.filter(|e| e.file_type().is_file())
		.collect();

	optimize_file_order::optimize_file_order(&mut files);

	pb.reset();
	pb.set_length(files.len() as u64);
	pb.set_message("Hashing files...");

	let hashes: BTreeMap<PathBuf, String> = files
		.into_iter()
		.progress_with(pb)
		.map(|e| {
			let value = hash_file(algo, e.path());
			let filename = relative_name(path, e.path());
			(filename.to_owned(), value)
		})
		.collect();
	hashes
}


/// Create hash mappings for given files using a given algorithm
pub fn create_hashes_for_files(
	path: &Path,
	files: Vec<PathBuf>,
	algo: Algorithm,
) -> BTreeMap<PathBuf, String> {

	let pb_style = ProgressStyle::default_bar()
		.template("{prefix:.bold.dim} {spinner} {wide_bar} {pos:>7}/{len:7} ETA: {eta} - {msg}")
		.unwrap()
		.tick_strings(&SPINNER_STRINGS);
	let pb = ProgressBar::new_spinner();
	pb.set_style(pb_style);
	pb.enable_steady_tick(Duration::from_millis(80));
	pb.set_message("Finding files to hash...");

	let files: Vec<PathBuf> = files
		.into_iter()
		.filter_map(|f| {
			let p = if f.is_relative() { path.join(f) } else { f };
			if p.is_file() {Some(p)} else {None}
		})
		.collect();

	pb.reset();
	pb.set_length(files.len() as u64);
	pb.set_message("Hashing files...");

	files
		.into_iter()
		.progress_with(pb)
		.map(|e| {
			let value = hash_file(algo, e.as_path());
			let filename = relative_name(path, e.as_path());
			(filename.to_owned(), value)
		})
		.collect::<BTreeMap<PathBuf, String>>()
}


/// Serialise the specified hashes to the specified output file.
pub fn write_hashes(out_file: &Path, hashes: BTreeMap<PathBuf, String>) -> i32 {
	let file = File::create(&out_file).unwrap();
	let mut out = TabWriter::new(file);

	// hashes.insert(
	// 	out_file.to_string_lossy().to_string(),
	// 	mul_str("-", algo.hexlen()),
	// );
	for (fname, hash) in hashes {
		writeln!(&mut out, "{}  {}", hash, fname.to_string_lossy()).unwrap();
	}

	out.flush().expect("Failed to flush output file");
	0
}

/// Read uppercased hashes with `write_hashes()` from the specified path or fail
/// with line numbers not matching pattern.
pub fn read_hashes(file: &Path) -> Result<BTreeMap<PathBuf, String>, Error> {
	let mut hashes = BTreeMap::new();

	let reader = BufReader::new(File::open(&file).unwrap());
	for line in reader.lines() {
		match line {
			Ok(line) => {
				if line.is_empty() {
					continue;
				}
				// Skip comment lines
				if line.trim_start().starts_with(";"){
					continue;
				}
				try_contains(&line, &mut hashes)?;
			}
			Err(err) => return Err(Error::HashesFileParsingFailure(err.to_string())),
		}
	}

	Ok(hashes)
}


/// Regex matching lines where the hash appears first, followed by the
/// filename. This targets the canonical output produced by
/// `write_hashes()` which writes `HASH FILENAME` (one or more spaces
/// separating fields).
///
/// - Case-insensitive (`(?i)`).
/// - Capture group 1: the hash (one or more hex digits or hyphens).
/// - Capture group 2: the filename/path (non-greedy to the line end).
/// - Example matches: `A1B2C3 path/to/file.txt` or `-----  /ignored`.
static LINE_RGX1: LazyLock<Regex> = LazyLock::new(|| 
	Regex::new(r"(?i)^([[:xdigit:]-]+)\s+(.+?)$").unwrap());

/// Regex matching lines where the filename appears first and the hash
/// is at the end of the line. This accepts optional tabs before the
/// separating whitespace and requires at least one whitespace before the
/// hash (i.e. `FILENAME<TAB*> <SPACE+>HASH`).
///
/// - Case-insensitive (`(?i)`).
/// - Capture group 1: the filename/path.
/// - Capture group 2: the hash (one or more hex digits or hyphens).
/// - Example matches: `path/to/file\tA1B2C3` or `some name   -----`.
static LINE_RGX2: LazyLock<Regex> = LazyLock::new(|| 
	Regex::new(r"(?i)^(.+?)\t{0,}\s{1,}([[:xdigit:]-]+)$").unwrap());


fn try_contains(line: &str, hashes: &mut BTreeMap<PathBuf, String>) -> Result<(), Error> {
	if let Some(captures) = LINE_RGX1.captures(line) {
		let file = filepath_parser(&captures[2]);
		let hash = captures[1].to_uppercase();
		hashes.insert(file, hash);
		return Ok(());
	}
	if let Some(captures) = LINE_RGX2.captures(line) {
		let file = filepath_parser(&captures[1]);
		let hash = captures[2].to_uppercase();
		hashes.insert(file, hash);
		return Ok(());
	}
	Err(Error::HashesFileParsingFailure(line.to_owned()))
}

fn filepath_parser(raw: &str) -> PathBuf {
	// Basic cleanup
	let mut s = raw.trim().replace('*', "");

	// On non-Windows platforms convert a lone backslash separator
	// (e.g. coming from a Windows-style list) to forward slashes so
	// `Path::new` parses components predictably. This avoids turning
	// a Windows-style path into a single filename with backslashes.
	if !cfg!(windows) && s.contains('\\') && !s.contains('/') {
		s = s.replace('\\', "/");
	}

	// Build a PathBuf from the (possibly normalized) string. 
	Path::new(&s).to_owned()
}