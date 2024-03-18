use std::io::Result;

fn main() -> Result<()> {
    let mut prost_config = prost_build::Config::new();
    prost_config.protoc_arg("--experimental_allow_proto3_optional");

    prost_config.compile_protos(&["src/microscurid.proto"], &["src/"])?;
    Ok(())
}