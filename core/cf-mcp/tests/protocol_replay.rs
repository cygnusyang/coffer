//! Replay 防护测试（docs/20 §3.6）。
//!
//! stdio 传输本身无持久 token（replay 面 = 0）；本组守卫的是协议层的
//! **消息 id 单调性**（§3.6 --uds 四对策之一，MVP stdio 亦作防御性执行）：
//! 数值 id 乱序 / 重号 → `-32600` 拒绝；通知（无 id）与字符串 id 不受影响。

use serde_json::{json, Value};

use cf_mcp::provider::{ProviderError, RunSpec, SecretMeta, SecretProvider};
use cf_mcp::McpServer;

/// 本组测试只用 `ping`，provider 不会被真正调用。
#[derive(Debug, Clone, Default)]
struct DummyProvider;

impl SecretProvider for DummyProvider {
    fn list_secret_names(&self, _vault: Option<&str>) -> Result<Vec<String>, ProviderError> {
        Ok(vec![])
    }
    fn list_secrets(&self, _vault: Option<&str>) -> Result<Vec<SecretMeta>, ProviderError> {
        Ok(vec![])
    }
    fn get_secret_metadata(&self, _secret_ref: &str) -> Result<SecretMeta, ProviderError> {
        Err(ProviderError::NotFound("dummy".into()))
    }
    fn run_with_secret(&self, _spec: &RunSpec) -> Result<i32, ProviderError> {
        Err(ProviderError::NotFound("dummy".into()))
    }
}

fn server() -> McpServer {
    McpServer::new(Box::new(DummyProvider))
}

fn ping(id: i64) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#)
}

fn response(resp: String, msg: &str) -> Value {
    serde_json::from_str(&resp).expect(msg)
}

#[test]
fn accepts_monotonic_numeric_ids() {
    let s = server();
    for id in 1..=3 {
        let resp = s.handle_line(&ping(id)).expect("must respond");
        let v = response(resp, "ping response");
        assert_eq!(v["id"], json!(id), "ping id {id} should succeed");
        assert!(v["result"].is_object(), "ping id {id} should return result");
    }
}

#[test]
fn rejects_repeated_id() {
    let s = server();
    assert!(s.handle_line(&ping(1)).is_some(), "first id 1 must succeed");
    let resp = s.handle_line(&ping(1)).expect("must respond");
    let v = response(resp, "repeated id response");
    assert_eq!(v["error"]["code"], -32600, "repeated id must be rejected");
}

#[test]
fn rejects_out_of_order_id() {
    let s = server();
    assert!(s.handle_line(&ping(5)).is_some(), "id 5 must succeed");
    let resp = s.handle_line(&ping(3)).expect("must respond");
    let v = response(resp, "out-of-order response");
    assert_eq!(
        v["error"]["code"], -32600,
        "out-of-order id must be rejected"
    );
}

#[test]
fn notifications_do_not_affect_id_tracking() {
    let s = server();
    // 通知（无 id）不应扰动 id 序列
    assert!(
        s.handle_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
            .is_none(),
        "notification must not produce a response"
    );
    assert!(
        s.handle_line(&ping(1)).is_some(),
        "id 1 after notification must succeed"
    );
    assert!(s.handle_line(&ping(2)).is_some(), "id 2 must succeed");
}

#[test]
fn string_ids_are_not_monotonic_checked() {
    // §3.6：字符串 id 无法排序，不做单调校验（不拒绝）。
    let s = server();
    assert!(
        s.handle_line(r#"{"jsonrpc":"2.0","id":"a","method":"ping"}"#)
            .is_some(),
        "string id a must succeed"
    );
    assert!(
        s.handle_line(r#"{"jsonrpc":"2.0","id":"b","method":"ping"}"#)
            .is_some(),
        "string id b must succeed"
    );
}

#[test]
fn numeric_id_mixed_with_string_id_is_checked_against_numeric_only() {
    let s = server();
    assert!(
        s.handle_line(&ping(7)).is_some(),
        "numeric id 7 must succeed"
    );
    assert!(
        s.handle_line(r#"{"jsonrpc":"2.0","id":"x","method":"ping"}"#)
            .is_some(),
        "string id must not break tracking"
    );
    // 数字 8 > 7 仍合法；数字 6 <= 7 拒绝
    assert!(
        s.handle_line(&ping(8)).is_some(),
        "numeric id 8 must succeed"
    );
    let resp = s.handle_line(&ping(6)).expect("must respond");
    let v = response(resp, "out-of-order response");
    assert_eq!(
        v["error"]["code"], -32600,
        "numeric id 6 after 8 must be rejected"
    );
}
