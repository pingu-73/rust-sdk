/// To generate updated proto objects:
/// run `RUSTFLAGS="--cfg genproto" cargo build`
fn main() -> std::io::Result<()> {
    #[cfg(genproto)]
    generate_protos()?;
    Ok(())
}

#[cfg(genproto)]
fn generate_protos() -> std::io::Result<()> {
    prost_build::compile_protos(
        &[
            "src/protos/v1/admin.proto",
            "src/protos/v1/service.proto",
            "src/protos/v1/wallet.proto",
        ],
        &["src/protos"],
    )?;

    let from_path = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("ark.v1.rs");
    std::fs::copy(from_path, "src/generated/types.rs").unwrap();
    Ok(())
}
