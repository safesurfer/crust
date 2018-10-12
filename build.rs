use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;

fn get_git_hash() -> String {
    let commit_output = Command::new("git")
        .arg("rev-parse")
        .arg("--verify")
        .arg("HEAD")
        .output()
        .expect("Cannot get git commit");
    let commit_string = String::from_utf8_lossy(&commit_output.stdout);
    return format!("{}", commit_string.lines().next().unwrap_or(""));
}

// Bake in the git revision hash
fn main() {
    let commit = get_git_hash();

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("git_commit_hash");
    let mut f = File::create(&dest_path).unwrap();
    f.write_all(&commit.as_bytes()).unwrap();
}
