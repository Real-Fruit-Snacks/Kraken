fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_file = "../../proto/kraken.proto";
    let generated = "src/generated/kraken.rs";

    // Recompile if proto file changes
    println!("cargo:rerun-if-changed={}", proto_file);

    // Skip code generation if protoc is not available and generated code already exists.
    // This allows building on machines without protoc installed, as long as the
    // pre-generated code in src/generated/ is up to date.
    if std::path::Path::new(generated).exists() && which_protoc().is_err() {
        eprintln!("build.rs: protoc not found, using pre-generated code");
        return Ok(());
    }

    // Only build gRPC server/client code when grpc feature is enabled
    let build_grpc = std::env::var("CARGO_FEATURE_GRPC").is_ok();

    eprintln!("build.rs: CARGO_FEATURE_GRPC = {}", build_grpc);

    tonic_build::configure()
        .build_server(build_grpc)
        .build_client(build_grpc)
        .out_dir("src/generated")
        .compile(&[proto_file], &["../../proto"])?;

    Ok(())
}

/// Check if protoc is available on PATH
fn which_protoc() -> Result<(), Box<dyn std::error::Error>> {
    std::process::Command::new("protoc")
        .arg("--version")
        .output()?;
    Ok(())
}
