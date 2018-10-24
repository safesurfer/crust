#!/usr/bin/env run-cargo-script
//! ```cargo
//! [dependencies]
//! clap = "=2.27.1"
//! colored = "1.6.0"
//! heck = "0.3.0"
//! toml = "0.4.5"
//! walkdir = "2.0.1"
//! zip = "=0.2.6"
//! ```
extern crate clap;
extern crate colored;
extern crate heck;
extern crate toml;
extern crate walkdir;
extern crate zip;

use clap::{App, Arg};
use colored::*;
use heck::ShoutySnakeCase;
use std::env;
use std::fs::{read_dir, File};
use std::io::{self, Read};
use std::iter;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str;
use walkdir::WalkDir;
use zip::write::FileOptions;
use zip::ZipWriter;

const TARGET_LINUX_X64: &str = "x86_64-unknown-linux-gnu";
const TARGET_OSX_X64: &str = "x86_64-apple-darwin";
const TARGET_WINDOWS_X64: &str = "x86_64-pc-windows-gnu";

const EXAMPLES: &[&str] = &["client", "proxy"];

const ARCHS: &[Arch] = &[
    Arch {
        name: "linux-x64",
        target: TARGET_LINUX_X64,
        toolchain: "",
    },
    Arch {
        name: "osx-x64",
        target: TARGET_OSX_X64,
        toolchain: "",
    },
    Arch {
        name: "win-x64",
        target: TARGET_WINDOWS_X64,
        toolchain: "",
    },
];

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const HOST_ARCH_NAME: &str = "linux-x64";
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const HOST_ARCH_NAME: &str = "osx-x64";
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const HOST_ARCH_NAME: &str = "win-x64";

const COMMIT_HASH_LEN: usize = 7;

fn main() {
    let arch_names: Vec<_> = ARCHS.into_iter().map(|args| args.name).collect();

    // Parse command line arguments.
    let matches = App::new("crust packaging tool")
        .arg(
            Arg::with_name("NAME")
                .short("n")
                .long("name")
                .takes_value(true)
                .possible_values(EXAMPLES)
                .required(true)
                .help("Name of the example to package"),
        ).arg(
            Arg::with_name("COMMIT")
                .short("c")
                .long("commit")
                .help("Uses commit hash instead of version string in the package name"),
        ).arg(
            Arg::with_name("ARCH")
                .short("a")
                .long("arch")
                .takes_value(true)
                .possible_values(&arch_names)
                .help("Target platform and architecture"),
        ).arg(
            Arg::with_name("TOOLCHAIN")
                .short("t")
                .long("toolchain")
                .takes_value(true)
                .help("Path to the toolchain (for cross-compilation)"),
        ).arg(
            Arg::with_name("DEST")
                .short("d")
                .long("dest")
                .takes_value(true)
                .help("Destination directory (uses current dir by default)"),
        ).get_matches();

    let example = matches.value_of("NAME").unwrap();
    let version_string = get_version_string(example, matches.is_present("COMMIT"));

    let arch_name = matches.value_of("ARCH").unwrap_or(HOST_ARCH_NAME);
    let arch = find_arch(arch_name);

    let dest_dir = matches.value_of("DEST").unwrap_or(".");

    let toolchain_path = matches.value_of("TOOLCHAIN");
    let target_dir = env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());

    let file_options = FileOptions::default();

    setup_env(toolchain_path, arch);

    // Run the build.
    let mut executables = Vec::new();

    // Normal library
    let target = arch.map(|arch| arch.target);
    if !build(example, target) {
        return;
    }

    let arch_executables = find_executables(example, target, &target_dir);
    executables.extend_from_slice(&arch_executables);

    // Create executable archive.
    if !executables.is_empty() {
        let archive_name = format!("{}-{}-{}.zip", example, version_string, arch_name);
        let path: PathBuf = [dest_dir, &archive_name].iter().collect();

        let file = File::create(path).unwrap();
        let mut archive = ZipWriter::new(file);

        for path in executables {
            archive
                .start_file(path.file_name().unwrap().to_string_lossy(), file_options)
                .unwrap();

            let mut file = File::open(path).unwrap();
            io::copy(&mut file, &mut archive).unwrap();
        }

        for path in read_dir(Path::new("resources")).unwrap() {
            let path = path.unwrap();
            archive
                .start_file(path.file_name().to_string_lossy(), file_options)
                .unwrap();

            let mut file = File::open(path.path()).unwrap();
            io::copy(&mut file, &mut archive).unwrap();
        }
    }
}

struct Arch {
    name: &'static str,
    target: &'static str,
    toolchain: &'static str,
}

fn get_version_string(example: &str, commit: bool) -> String {
    if commit {
        // Get the current commit hash.
        let output = Command::new("git")
            .arg("rev-parse")
            .arg("HEAD")
            .output()
            .expect("failed to run git");

        str::from_utf8(&output.stdout).unwrap().trim()[0..COMMIT_HASH_LEN].to_string()
    } else {
        // Extract the version string from Cargo.toml
        use toml::Value;

        let mut file = File::open(Path::new("Cargo.toml")).expect("failed to open Cargo.toml");
        let mut content = String::new();
        file.read_to_string(&mut content)
            .expect("failed to read Cargo.toml");

        let toml = content
            .parse::<Value>()
            .expect("failed to parse Cargo.toml");
        toml["package"]["version"]
            .as_str()
            .expect("failed to read package version from Cargo.toml")
            .to_string()
    }
}

fn get_toolchain_bin(toolchain_path: Option<&str>, arch: Option<&Arch>, bin: &str) -> String {
    let mut result = PathBuf::new();

    if let Some(path) = toolchain_path {
        result.push(path);
        result.push("bin");
    }

    let prefix = arch.map(|arch| arch.toolchain).unwrap_or("");

    result.push(format!("{}{}", prefix, bin));
    result.into_os_string().into_string().unwrap()
}

fn find_arch(name: &str) -> Option<&Arch> {
    ARCHS.into_iter().find(|arch| arch.name == name)
}

fn setup_env(toolchain_path: Option<&str>, arch: Option<&Arch>) {
    let arch = if let Some(arch) = arch { arch } else { return };

    let name = format!("CARGO_TARGET_{}_LINKER", arch.target.to_shouty_snake_case());

    let value = if let Some(toolchain_path) = toolchain_path {
        let value = get_toolchain_bin(Some(toolchain_path), Some(arch), "gcc");

        println!(
            "{}: setting environment variable {} to {}",
            "notice".green().bold(),
            name.bold(),
            value.bold()
        );

        env::set_var(&name, &value);
        Some(value)
    } else {
        env::var(&name).ok()
    };

    if let Some(value) = value {
        if !Path::new(&value).exists() {
            println!(
                "{}: the environment variable {} is set, but points to \
                 non-existing file {}. This might cause linker failures.",
                "warning".yellow().bold(),
                name.bold(),
                value.bold(),
            );
        }
    } else {
        println!(
            "{}: the environment variable {} is not set. \
             This might cause linker failure.",
            "warning".yellow().bold(),
            name.bold()
        );
    }
}

fn build(example: &str, target: Option<&str>) -> bool {
    let mut command = Command::new("cargo");
    command
        .arg("build")
        .arg("--verbose")
        .arg("--release")
        .arg("--example")
        .arg(format!("{}", example));

    if let Some(target) = target {
        command.arg("--target").arg(target);
    }

    command.status().unwrap().success()
}

fn find_executables(example: &str, target: Option<&str>, target_dir: &str) -> Vec<PathBuf> {
    let mut prefix = PathBuf::from(target_dir);
    if let Some(target) = target {
        prefix = prefix.join(target);
    }
    prefix = prefix.join("release").join("examples");

    let mut result = Vec::with_capacity(1);

    // linux,osx
    let path = prefix.join(format!("{}", example));
    if path.exists() {
        result.push(path);
    }

    // windows
    let path = prefix.join(format!("{}.exe", example));
    if path.exists() {
        result.push(path);
    }

    if result.is_empty() {
        panic!("No executables found in {}/release", target_dir)
    }

    result
}

fn path_into_string(path: PathBuf) -> String {
    path.into_os_string()
        .into_string()
        .unwrap()
        .replace('\\', "/")
}
