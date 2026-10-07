//! native messaging 帧编解码（docs/31 §3.1：4 字节 LE 长度前缀）。
//!
//! 覆盖：编解码往返、半包（长度前缀齐全但 payload 未到齐）、截断（前缀不足）、
//! 粘包（一缓冲多帧）、空 payload。

use cf_browser::error::CfBrowserError;
use cf_browser::host::{frame_header_len, HostRelay};
use cf_browser::protocol::{decode_frame, encode_frame};

#[test]
fn encode_decode_roundtrip() {
    let payload = b"hello native messaging";
    let framed = encode_frame(payload).expect("encode");
    assert_eq!(framed.len(), 4 + payload.len());
    // 前缀为小端 4 字节
    assert_eq!(&framed[..4], &(payload.len() as u32).to_le_bytes());

    let (out, rest) = decode_frame(&framed).expect("decode");
    assert_eq!(out, payload);
    assert!(rest.is_empty());
}

#[test]
fn frame_header_len_constant() {
    assert_eq!(frame_header_len(), 4);
}

#[test]
fn empty_payload_roundtrip() {
    let framed = encode_frame(b"").expect("encode");
    assert_eq!(framed.len(), 4);
    let (out, rest) = decode_frame(&framed).expect("decode");
    assert!(out.is_empty());
    assert!(rest.is_empty());
}

#[test]
fn truncated_header_is_invalid() {
    // 前缀不足 4 字节 → 半包（等待更多字节）
    for len in 0..4 {
        let buf = vec![0u8; len];
        assert!(matches!(
            decode_frame(&buf),
            Err(CfBrowserError::InvalidLength(_))
        ));
    }
}

#[test]
fn half_packet_is_invalid_length() {
    // 声明 10 字节，只来了 4 字节 → payload 未到齐（InvalidLength，调用方继续读）
    let mut buf = (10u32).to_le_bytes().to_vec();
    buf.extend_from_slice(b"ab"); // 仅 2/10
    assert!(matches!(
        decode_frame(&buf),
        Err(CfBrowserError::InvalidLength(_))
    ));
}

#[test]
fn sticky_pack_decodes_first_frame_and_returns_rest() {
    // 一缓冲粘两帧：解码出第一帧 + 剩余
    let a = encode_frame(b"frame-a").expect("encode");
    let b = encode_frame(b"frame-b").expect("encode");
    let mut joined = a.clone();
    joined.extend_from_slice(&b);

    let (first, rest) = decode_frame(&joined).expect("第一帧");
    assert_eq!(first, b"frame-a");
    assert_eq!(rest, b);
    let (second, rest2) = decode_frame(rest).expect("第二帧");
    assert_eq!(second, b"frame-b");
    assert!(rest2.is_empty());
}

#[test]
fn zero_length_declared_but_body_present() {
    // 声明 0 字节但缓冲有多余 → 第一帧为空，其余返回
    let framed = encode_frame(b"").expect("encode");
    let mut buf = framed.clone();
    buf.extend_from_slice(b"extra");
    let (out, rest) = decode_frame(&buf).expect("decode");
    assert!(out.is_empty());
    assert_eq!(rest, b"extra");
}

// ---------------------------------------------------------------- HostRelay 盲传骨架

#[test]
fn relay_forwards_frame_verbatim() {
    let relay = HostRelay;
    let payload = b"\x00\x01\x02 opaque bytes, not parsed by host";
    let framed = encode_frame(payload).expect("encode");

    let (forwarded, rest) = relay.relay_frame(&framed).expect("relay");
    assert_eq!(forwarded, framed, "盲传零改写");
    assert!(rest.is_empty());

    let (out, _) = decode_frame(&forwarded).expect("decode");
    assert_eq!(out, payload, "内容原样");
}

#[test]
fn relay_rejects_half_packet() {
    let relay = HostRelay;
    let mut buf = (5u32).to_le_bytes().to_vec();
    buf.extend_from_slice(b"ab");
    assert!(matches!(
        relay.relay_frame(&buf),
        Err(CfBrowserError::InvalidLength(_))
    ));
}

#[test]
fn relay_wrap_preserves_payload() {
    let relay = HostRelay;
    let payload = b"\xde\xad\xbe\xef";
    let framed = relay.wrap(payload).expect("wrap");
    let (out, _) = decode_frame(&framed).expect("decode");
    assert_eq!(out, payload);
}
