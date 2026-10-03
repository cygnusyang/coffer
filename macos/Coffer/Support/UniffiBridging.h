// UniffiBridging.h —— UniFFI 双 namespace 组合桥接头（官方模式专用，Task 2/3）。
//
// uniffi-bindgen --library 为每个 namespace 各生成一个 FFI 头（cf_ffiFFI.h /
// cf_assembleFFI.h），而 swiftc 的 `-import-objc-header` 只认最后一个参数——
// 两个头直接并列传会被后一个整体覆盖（实测：cf_ffi 的符号全部不可见）。
// 用组合桥接头 `#include` 两个 FFI 头，作为唯一的 `-import-objc-header` 传入。
//
// 两个头共享 UNIFFI_SHARED_HEADER_V4 防重入宏，重复类型（RustBuffer /
// ForeignBytes 等）只展开一次，重复 include 安全（见各自头文件的 shared 段）。
//
// 引用方：
//   - tools/build_macos_app.sh（OFFICIAL_LICENSE=1 时）
//   - tools/run_official_license_adapter_tests.sh
//
// 注意：本头文件路径固定于 CoreBindings 之外，不随绑定重生成而清空。

#ifndef UniffiBridging_h
#define UniffiBridging_h

#include "cf_ffiFFI.h"
#include "cf_assembleFFI.h"

#endif /* UniffiBridging_h */
