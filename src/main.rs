use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use axioscan::{scan, Status};

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::from(3)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut args = env::args().skip(1);
    let mut json = false;
    let mut path = PathBuf::from(".");

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(ExitCode::SUCCESS);
            }
            "--json" => json = true,
            _ if arg.starts_with('-') => {
                return Err(format!("unknown flag: {arg}"));
            }
            _ => {
                path = PathBuf::from(arg);
                if let Some(extra) = args.next() {
                    return Err(format!(
                        "unexpected extra argument: {extra}. Only one path is supported."
                    ));
                }
            }
        }
    }

    let report = scan(&path).map_err(|e| e.to_string())?;

    if json {
        println!("{}", report.render_json());
    } else {
        println!("{}", report.render_human());
    }

    let code = match report.status {
        Status::NoEvidenceFound => ExitCode::SUCCESS,
        Status::AtRisk => ExitCode::from(1),
        Status::Compromised => ExitCode::from(2),
    };

    Ok(code)
}

fn print_help() {
    println!(
        "\
axioscan — Local IOC scanner for the axios / plain-crypto-js supply-chain incident

Usage:
  axioscan [--json] [PATH]

Arguments:
  PATH      Repository root to scan (default: current directory)

Options:
  --json    Emit machine-readable JSON output
  -h        Show this help message

Exit codes:
  0         No evidence found
  1         At-risk or unverifiable exposure detected
  2         Compromise evidence detected
  3         Scanner error"
    );
}
