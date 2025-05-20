
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // original when we had a single proto file
    // tonic_build::compile_protos("proto/custody.proto")?;
    // updated now that there are multiple proto files
    tonic_build::configure()
    .compile(
        &[
            "proto/custody.proto",
            "proto/registry.proto",
            "proto/relay.proto",
            "proto/dkg.proto",
            "proto/vault.proto",
            "proto/mpc.proto",
            "proto/issuer.proto"
        ],
        &["proto"],
    )
    .unwrap();
    Ok(())
}