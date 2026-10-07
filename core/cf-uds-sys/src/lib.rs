//! macOS UDS peer 凭据 syscall 封装（cf-mcp `--uds` 传输，docs/20 §3.1 / §3.6 ②）。
//!
//! 背景：cf-mcp 是 `#![forbid(unsafe_code)]` 的 crate，而 UDS 传输的 peer 凭据
//! 提取必须经 libc FFI——故把**唯一的 unsafe 面**隔离在本 sys crate，对外只暴露
//! 安全封装（`io::Result` / 普通值），调用方无需 unsafe。
//!
//! 平台：`target_os = "macos"`（docs/20 §3.1 明确 macOS）。非 macOS 下 peer PID
//! 判定不可用，函数返回 [`io::ErrorKind::Unsupported`]，调用方据此跳过该检查
//! （会话 challenge 仍是全平台防护，docs/20 §3.6 ③）。
//!
//! 零网络：本 crate 只做 AF_UNIX **本机回环**的 peer 凭据提取，无任何网络能力
//! （docs/27 D-4 零网络新口径：本机内 IPC 允许、不违背「不去云端」）。

#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::io;
use std::os::unix::net::UnixStream;

/// 连接方 peer PID（Darwin `getsockopt(SOL_LOCAL, LOCAL_PEERPID)`）。
///
/// macOS `getpeereid(2)` 只返回 euid/egid（**不含 PID**）；要拿连接方进程的
/// PID 须 `LOCAL_PEERPID`（sys/un.h，值 0x002）。docs/20 §3.6 ②「连接方 PID
/// 须为 spawn 方」的判据用本函数忠实落地。
#[cfg(target_os = "macos")]
pub fn peer_pid(stream: &UnixStream) -> io::Result<libc::pid_t> {
    use std::os::unix::io::AsRawFd;
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY：getsockopt 对已连接的 AF_UNIX fd 取 LOCAL_PEERPID；pid/len 是栈上
    // 有效写缓冲（长度正确）。返回 0 表示成功、此时 pid 已写入；否则 errno 就绪。
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            &mut pid as *mut libc::pid_t as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        Ok(pid)
    } else {
        Err(io::Error::last_os_error())
    }
}

/// 非 macOS：peer PID 判定不可用（调用方跳过该检查，challenge 仍生效）。
#[cfg(not(target_os = "macos"))]
pub fn peer_pid(stream: &UnixStream) -> io::Result<libc::pid_t> {
    let _ = stream;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "LOCAL_PEERPID is only supported on macOS",
    ))
}

/// 本进程有效 UID（`geteuid`）——peer 同用户校验的参照。
#[cfg(target_os = "macos")]
pub fn self_euid() -> libc::uid_t {
    // SAFETY：geteuid 无参数、无前置条件，返回当前进程有效 UID。
    unsafe { libc::geteuid() }
}

/// 非 macOS：无同用户校验，参照值恒 0（peer_euid 恒 Unsupported，检查跳过）。
#[cfg(not(target_os = "macos"))]
pub fn self_euid() -> libc::uid_t {
    0
}

/// 连接方 peer euid（macOS `getpeereid(2)`，docs/20 §3.1 同用户校验）。
///
/// 与 0600 socket 文件权限形成纵深：即使文件权限被放宽，仍要求连接方与
/// 本进程同用户（euid 相等）。
#[cfg(target_os = "macos")]
pub fn peer_euid(stream: &UnixStream) -> io::Result<libc::uid_t> {
    use std::os::unix::io::AsRawFd;
    let mut euid: libc::uid_t = 0;
    let mut egid: libc::gid_t = 0;
    // SAFETY：getpeereid 对已连接的 AF_UNIX fd 返回对方 euid/egid；写缓冲为
    // 栈上有效指针。返回 0 表示成功。
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut euid, &mut egid) };
    if rc == 0 {
        Ok(euid)
    } else {
        Err(io::Error::last_os_error())
    }
}

/// 非 macOS：peer euid 判定不可用（调用方跳过该检查，challenge 仍生效）。
#[cfg(not(target_os = "macos"))]
pub fn peer_euid(stream: &UnixStream) -> io::Result<libc::uid_t> {
    let _ = stream;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "getpeereid is only supported on macOS",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// 自连接对（本进程既 bind 又 connect）：LOCAL_PEERPID 应回本进程 PID，
    /// getpeereid 应回本进程 euid——直接验证 syscall 封装正确性。
    #[test]
    #[cfg(target_os = "macos")]
    fn self_connection_reports_self_credentials() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("cf-uds-sys-peer-{}-{nanos}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind uds path");
        let _client = UnixStream::connect(&path).expect("connect to uds path");
        let (server, _addr) = listener.accept().expect("accept connection");

        assert_eq!(
            peer_pid(&server).expect("peer_pid must succeed on macOS"),
            std::process::id() as libc::pid_t,
            "LOCAL_PEERPID 对本进程自连接应回本进程 PID"
        );
        assert_eq!(
            peer_euid(&server).expect("peer_euid must succeed on macOS"),
            self_euid(),
            "getpeereid 对本进程自连接应回本进程 euid"
        );

        drop(server);
        let _ = std::fs::remove_file(&path);
    }

    /// 非 macOS：peer 判定明确 Unsupported（调用方据此跳过，不静默假成功）。
    #[test]
    #[cfg(not(target_os = "macos"))]
    fn peer_checks_unsupported_off_macos() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("cf-uds-sys-peer-{}-{nanos}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind uds path");
        let _client = UnixStream::connect(&path).expect("connect to uds path");
        let (server, _addr) = listener.accept().expect("accept connection");
        assert!(
            peer_pid(&server).is_err(),
            "off-macOS peer_pid 须 Unsupported"
        );
        assert!(
            peer_euid(&server).is_err(),
            "off-macOS peer_euid 须 Unsupported"
        );
        drop(server);
        let _ = std::fs::remove_file(&path);
    }
}
