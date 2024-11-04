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
        .out_dir("src/generated") // you can change the generated code's location
        .compile_protos(
            &["proto/v1/admin.proto"],
            &["proto"], // specify the root location to search proto dependencies
        )?;
    Ok(())
}
