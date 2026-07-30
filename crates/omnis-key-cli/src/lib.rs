use clap::{CommandFactory, Parser, Subcommand};
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};

mod agent;
mod checkpoint;
mod demo;
mod output;
mod receipts;

pub const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const COMPATIBILITY_BASE_NAME: &str = "jcode";
pub const COMPATIBILITY_BASE_VERSION: &str = jcode_build_meta::PKG_VERSION;

#[derive(Debug, Parser)]
#[command(
    name = "omnis-key",
    disable_version_flag = true,
    about = "OMNIS KEY Local Integrity V1",
    long_about = "OMNIS KEY Local Integrity V1 records and verifies bounded local evidence receipts.\n\nReceipt subjects and event IDs are plaintext. Do not place secrets in them, and do not treat the local ledger as a secret vault."
)]
struct Cli {
    #[command(subcommand)]
    command: TopLevel,
}

#[derive(Debug, Subcommand)]
enum TopLevel {
    /// Show the product and inherited compatibility-base versions.
    Version {
        /// Emit the frozen machine-readable response.
        #[arg(long)]
        json: bool,
    },
    /// Record, inspect, and reconcile bounded local receipts.
    Receipts {
        #[command(subcommand)]
        action: ReceiptCommand,
    },
    /// Experimental checkpoint source preview; unavailable unless separately activated.
    Checkpoint {
        #[command(subcommand)]
        action: CheckpointCommand,
    },
    /// Run credential-free synthetic fixtures.
    Demo {
        #[command(subcommand)]
        action: DemoCommand,
    },
    /// Compatibility alias for the inherited `jcode omnis` spelling.
    #[command(hide = true)]
    Omnis {
        #[command(subcommand)]
        action: CompatibilityCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ReceiptCommand {
    /// Inspect the canonical local receipt chain.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Verify the canonical local receipt chain.
    Verify {
        #[arg(long)]
        json: bool,
    },
    /// Append or exactly replay one bounded local receipt.
    Record {
        #[arg(long, value_name = "ID")]
        event_id: String,
        #[arg(value_name = "KIND")]
        kind: String,
        #[arg(value_name = "SUBJECT")]
        subject: String,
        #[arg(long, value_name = "HEX")]
        evidence_sha256: String,
        #[arg(long)]
        json: bool,
    },
    /// Reconcile terminal safety-decision receipt obligations.
    ReconcileSafety {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum CheckpointCommand {
    /// Ask a separately activated experimental checkpoint authority to anchor the local head.
    Anchor {
        #[arg(long, value_name = "ID")]
        request_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Verify the local chain against the separately retained checkpoint.
    VerifyAnchored {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum DemoCommand {
    /// Exercise append, exact replay, verification, and concrete tamper refusal offline.
    Integrity {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum CompatibilityCommand {
    Status {
        #[arg(long)]
        json: bool,
    },
    Verify {
        #[arg(long)]
        json: bool,
    },
    Record {
        #[arg(long, value_name = "ID")]
        event_id: String,
        #[arg(value_name = "KIND")]
        kind: String,
        #[arg(value_name = "SUBJECT")]
        subject: String,
        #[arg(long, value_name = "HEX")]
        evidence_sha256: String,
        #[arg(long)]
        json: bool,
    },
    ReconcileSafety {
        #[arg(long)]
        json: bool,
    },
    Anchor {
        #[arg(long, value_name = "ID")]
        request_id: String,
        #[arg(long)]
        json: bool,
    },
    VerifyAnchored {
        #[arg(long)]
        json: bool,
    },
}

pub fn run_from<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    if args.len() == 1 {
        return agent::launch_exact_sibling(&args[0]);
    }
    let stdout = io::stdout();
    let stderr = io::stderr();
    run_with_io(args, &mut stdout.lock(), &mut stderr.lock())
}

pub fn run_jcode_omnis_from<I, T>(args: I) -> Option<i32>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let translated = match translate_jcode_omnis_args(&args) {
        CompatibilityTranslation::NotOmnis => return None,
        CompatibilityTranslation::UsageRefusal => {
            eprintln!("error: unsupported global option before `jcode omnis`");
            return Some(2);
        }
        CompatibilityTranslation::Run(translated) => translated,
    };
    let stdout = io::stdout();
    let stderr = io::stderr();
    Some(run_with_io(
        translated,
        &mut stdout.lock(),
        &mut stderr.lock(),
    ))
}

pub fn run_with_io<I, T>(args: I, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    if is_exact_version_flag(&args) {
        return write_human_version(stdout);
    }
    if args.len() == 1 {
        let mut command = Cli::command();
        let mut help = Vec::new();
        return match command
            .write_long_help(&mut help)
            .and_then(|()| help.write_all(b"\n"))
            .and_then(|()| stdout.write_all(&help))
        {
            Ok(()) => 0,
            Err(_) => 3,
        };
    }
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let exit = error.exit_code();
            let rendered = error.to_string();
            let write = if error.use_stderr() {
                stderr.write_all(rendered.as_bytes())
            } else {
                stdout.write_all(rendered.as_bytes())
            };
            return match write {
                Ok(()) => exit,
                Err(_) => 3,
            };
        }
    };
    dispatch(cli.command, stdout, stderr)
}

fn is_exact_version_flag(args: &[OsString]) -> bool {
    args.len() == 2 && matches!(args[1].to_str(), Some("--version") | Some("-V"))
}

fn write_human_version(stdout: &mut dyn Write) -> i32 {
    match writeln!(stdout, "omnis-key {PRODUCT_VERSION}").and_then(|()| {
        writeln!(
            stdout,
            "{COMPATIBILITY_BASE_NAME} compatibility base {COMPATIBILITY_BASE_VERSION}"
        )
    }) {
        Ok(()) => 0,
        Err(_) => 3,
    }
}

fn dispatch(command: TopLevel, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    match command {
        TopLevel::Version { json: false } => write_human_version(stdout),
        TopLevel::Version { json: true } => output::emit_version(stdout),
        TopLevel::Receipts { action } => run_receipt(action, stdout, stderr),
        TopLevel::Checkpoint { action } => run_checkpoint(action, stdout, stderr),
        TopLevel::Demo { action } => match action {
            DemoCommand::Integrity { json } => demo::run(json, stdout, stderr),
        },
        TopLevel::Omnis { action } => run_compatibility(action, stdout, stderr),
    }
}

fn run_receipt(action: ReceiptCommand, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    match action {
        ReceiptCommand::Status { json } => {
            let context = match canonical_receipt_context(json, "receipts.status", stdout, stderr) {
                Ok(context) => context,
                Err(exit) => return exit,
            };
            receipts::status(&context, json, "receipts.status", stdout, stderr)
        }
        ReceiptCommand::Verify { json } => {
            let context = match canonical_receipt_context(json, "receipts.verify", stdout, stderr) {
                Ok(context) => context,
                Err(exit) => return exit,
            };
            receipts::status(&context, json, "receipts.verify", stdout, stderr)
        }
        ReceiptCommand::Record {
            event_id,
            kind,
            subject,
            evidence_sha256,
            json,
        } => {
            let context = match canonical_receipt_context(json, "receipts.record", stdout, stderr) {
                Ok(context) => context,
                Err(exit) => return exit,
            };
            receipts::record(
                &context,
                receipts::RecordInput {
                    event_id,
                    kind,
                    subject,
                    evidence_sha256,
                },
                json,
                stdout,
                stderr,
            )
        }
        ReceiptCommand::ReconcileSafety { json } => {
            receipts::reconcile_safety(json, stdout, stderr)
        }
    }
}

fn canonical_receipt_context(
    json: bool,
    command: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<receipts::ReceiptContext, i32> {
    receipts::ReceiptContext::canonical().map_err(|_| {
        output::emit::<()>(
            json,
            command,
            false,
            "RECEIPT_STATE_UNSAFE",
            None,
            3,
            (stdout, stderr),
        )
    })
}

fn run_checkpoint(
    action: CheckpointCommand,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    match action {
        CheckpointCommand::Anchor { request_id, json } => {
            checkpoint::anchor(&request_id, json, stdout, stderr)
        }
        CheckpointCommand::VerifyAnchored { json } => {
            checkpoint::verify_anchored(json, stdout, stderr)
        }
    }
}

fn run_compatibility(
    action: CompatibilityCommand,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    match action {
        CompatibilityCommand::Status { json } => {
            run_receipt(ReceiptCommand::Status { json }, stdout, stderr)
        }
        CompatibilityCommand::Verify { json } => {
            run_receipt(ReceiptCommand::Verify { json }, stdout, stderr)
        }
        CompatibilityCommand::Record {
            event_id,
            kind,
            subject,
            evidence_sha256,
            json,
        } => run_receipt(
            ReceiptCommand::Record {
                event_id,
                kind,
                subject,
                evidence_sha256,
                json,
            },
            stdout,
            stderr,
        ),
        CompatibilityCommand::ReconcileSafety { json } => {
            run_receipt(ReceiptCommand::ReconcileSafety { json }, stdout, stderr)
        }
        CompatibilityCommand::Anchor { request_id, json } => run_checkpoint(
            CheckpointCommand::Anchor { request_id, json },
            stdout,
            stderr,
        ),
        CompatibilityCommand::VerifyAnchored { json } => {
            run_checkpoint(CheckpointCommand::VerifyAnchored { json }, stdout, stderr)
        }
    }
}

pub fn is_jcode_omnis_invocation(args: &[impl AsRef<OsStr>]) -> bool {
    let owned: Vec<OsString> = args
        .iter()
        .map(|argument| argument.as_ref().to_os_string())
        .collect();
    matches!(
        translate_jcode_omnis_args(&owned),
        CompatibilityTranslation::Run(_) | CompatibilityTranslation::UsageRefusal
    )
}

enum CompatibilityTranslation {
    NotOmnis,
    UsageRefusal,
    Run(Vec<OsString>),
}

fn translate_jcode_omnis_args(args: &[OsString]) -> CompatibilityTranslation {
    let mut index = 1;
    while index < args.len() {
        let Some(argument) = args[index].to_str() else {
            return CompatibilityTranslation::NotOmnis;
        };
        if argument == "omnis" {
            let Some(rest) = strip_jcode_globals(&args[index + 1..]) else {
                return CompatibilityTranslation::UsageRefusal;
            };
            let mut translated = Vec::with_capacity(rest.len() + 2);
            translated.push(OsString::from("omnis-key"));
            if matches!(
                rest.first().and_then(|value| value.to_str()),
                Some("receipts") | Some("checkpoint") | Some("demo") | Some("version")
            ) {
                translated.extend(rest);
            } else {
                translated.push(OsString::from("omnis"));
                translated.extend(rest);
            }
            return CompatibilityTranslation::Run(translated);
        }
        if is_root_display_flag(argument) {
            return CompatibilityTranslation::NotOmnis;
        }
        if is_ignored_pre_command_flag(argument)
            || is_ignored_option_with_inline_value(argument)
            || is_ignored_short_option_with_attached_value(argument)
        {
            index += 1;
            continue;
        }
        if is_ignored_valued_option(argument) {
            if index + 1 >= args.len() {
                return CompatibilityTranslation::NotOmnis;
            }
            if args[index + 1].to_str().is_none() {
                return CompatibilityTranslation::NotOmnis;
            }
            index += 2;
            continue;
        }
        if argument == "--resume" {
            index += 1;
            if index < args.len() {
                let Some(next) = args[index].to_str() else {
                    return CompatibilityTranslation::NotOmnis;
                };
                if next != "omnis" && !next.starts_with('-') {
                    index += 1;
                }
            }
            continue;
        }
        return CompatibilityTranslation::NotOmnis;
    }
    CompatibilityTranslation::NotOmnis
}

fn strip_jcode_globals(args: &[OsString]) -> Option<Vec<OsString>> {
    let mut stripped = Vec::with_capacity(args.len());
    let mut index = 0;
    while index < args.len() {
        let Some(argument) = args[index].to_str() else {
            stripped.push(args[index].clone());
            index += 1;
            continue;
        };
        if argument == "--" {
            stripped.extend(args[index..].iter().cloned());
            break;
        }
        if is_ignored_global_flag(argument)
            || is_ignored_option_with_inline_value(argument)
            || is_ignored_short_option_with_attached_value(argument)
        {
            index += 1;
            continue;
        }
        if is_ignored_valued_option(argument) {
            let value = args.get(index + 1)?;
            value.to_str()?;
            index += 2;
            continue;
        }
        if argument == "--resume" {
            index += 1;
            if let Some(value) = args.get(index) {
                let value = value.to_str()?;
                if !value.starts_with('-') && !is_compatibility_command_word(value) {
                    index += 1;
                }
            }
            continue;
        }
        stripped.push(args[index].clone());
        index += 1;
    }
    Some(stripped)
}

fn is_root_display_flag(argument: &str) -> bool {
    matches!(argument, "--help" | "-h" | "--version" | "-V")
}

fn is_ignored_pre_command_flag(argument: &str) -> bool {
    is_ignored_global_flag(argument) || argument == "--onboarding-sim"
}

fn is_ignored_global_flag(argument: &str) -> bool {
    matches!(
        argument,
        "--no-update"
            | "--auto-update"
            | "--trace"
            | "--quiet"
            | "--no-selfdev"
            | "--debug-socket"
            | "--disable-base-tools"
            | "--fresh-spawn"
    )
}

fn is_ignored_valued_option(argument: &str) -> bool {
    matches!(
        argument,
        "--provider"
            | "-p"
            | "--cwd"
            | "-C"
            | "--remote-working-dir"
            | "--socket"
            | "--model"
            | "-m"
            | "--provider-profile"
            | "--tool-profile"
            | "--tools"
            | "--disabled-tools"
            | "--spawn-hotkey"
    )
}

fn is_ignored_option_with_inline_value(argument: &str) -> bool {
    [
        "--provider=",
        "--cwd=",
        "--remote-working-dir=",
        "--socket=",
        "--model=",
        "--provider-profile=",
        "--tool-profile=",
        "--tools=",
        "--disabled-tools=",
        "--spawn-hotkey=",
        "--resume=",
    ]
    .iter()
    .any(|prefix| argument.starts_with(prefix))
}

fn is_ignored_short_option_with_attached_value(argument: &str) -> bool {
    argument.len() > 2
        && ["-p", "-C", "-m"]
            .iter()
            .any(|prefix| argument.starts_with(prefix))
}

fn is_compatibility_command_word(argument: &str) -> bool {
    matches!(
        argument,
        "status"
            | "verify"
            | "record"
            | "reconcile-safety"
            | "anchor"
            | "verify-anchored"
            | "receipts"
            | "checkpoint"
            | "demo"
            | "integrity"
            | "version"
    )
}

#[cfg(test)]
mod tests;
