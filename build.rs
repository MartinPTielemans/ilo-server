//! Generates the sync protocol's Rust types from Chromium's `.proto` files.

use prost_types::field_descriptor_proto::Type;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto");
    let mut files = protox::compile(["components/sync/protocol/sync.proto"], ["proto"])?;
    // The server never reads specifics, and decoding them would drop the
    // fields of data types newer than these files; both are length-delimited
    // on the wire, so bytes keep them exactly as the client sent them.
    let specifics = files
        .file
        .iter_mut()
        .filter(|file| file.package() == "sync_pb")
        .flat_map(|file| file.message_type.iter_mut())
        .filter(|message| message.name() == "SyncEntity")
        .flat_map(|message| message.field.iter_mut())
        .find(|field| field.name() == "specifics")
        .ok_or("SyncEntity.specifics is missing")?;
    specifics.set_type(Type::Bytes);
    specifics.type_name = None;
    prost_build::Config::new().compile_fds(files)?;
    Ok(())
}
