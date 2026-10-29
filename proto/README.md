# Chromium's sync protocol

`components/sync/protocol/` holds the `.proto` files of Chromium's sync protocol, unmodified, from Chromium 156.0.8078.47 (commit [`1d17a2e2ee147bb7d6ae2ab6abdb3a2510c17775`](https://chromium.googlesource.com/chromium/src/+/1d17a2e2ee147bb7d6ae2ab6abdb3a2510c17775/components/sync/protocol/)), the engine ilo pins. They are `sync.proto` and every file it imports, under Chromium's BSD licence in [`LICENSE`](LICENSE).

`build.rs` compiles them with `protox` and makes `SyncEntity.specifics` plain bytes before generating Rust, so the server stores and serves a client's specifics byte for byte, encrypted or not, including fields newer than these files.

To update: replace the folder's contents with the same files at the new engine's commit, add any newly imported file, and change the commit above.
