/// To generate updated proto objects:
/// run `RUSTFLAGS="--cfg genproto" cargo build`
fn main() -> std::io::Result<()> {
    #[cfg(genproto)]
    generate_protos()?;
    Ok(())
}

#[cfg(genproto)]
fn generate_protos() -> std::io::Result<()> {
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .out_dir("src/generated")
        .build_transport(true)
        .compile_protos(
            &[
                "proto/v1/admin.proto",
                "proto/v1/service.proto",
                "proto/v1/wallet.proto",
            ],
            &["proto"],
        )?;

    Ok(())
}
