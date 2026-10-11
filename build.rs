#![allow(unsafe_code)]

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // SAFETY: the build script is single-threaded and sets PROTOC before code generation.
    unsafe { std::env::set_var("PROTOC", protoc) };
    tonic_prost_build::compile_protos("proto/probe.proto")?;
    Ok(())
}
