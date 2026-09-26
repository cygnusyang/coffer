//! uniffi-bindgen CLI 入口（与 uniffi runtime 同版本，防绑定物漂移）。
//!
//! 由 `tools/build_swift_bindings.sh` 通过
//! `cargo run -p cf-ffi --features bindgen-cli --bin uniffi-bindgen` 调用。

fn main() {
    uniffi::uniffi_bindgen_main();
}
