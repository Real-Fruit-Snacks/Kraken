fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_file = "../../proto/kraken.proto";

    // Recompile if proto file changes
    println!("cargo:rerun-if-changed={}", proto_file);

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
