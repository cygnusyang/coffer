//! MCP / JSON-RPC 2.0 协议帧测试（docs/20 §3.1–§3.4）。
//!
//! 覆盖：帧解析（合法 / 非 JSON / 版本错 / 缺 method）、生命周期
//! （initialize / notifications/initialized / tools/list / tools/call / ping）、
//! 错误码映射（-32700/-32600/-32601/-32602 与 7xxx 应用层）、
//! 输出 Redactor 管道（§3.5-2：所有 content[0].text 经 SecretRedactor）。

use serde_json::{json, Value};

use cf_mcp::error::McpError;
use cf_mcp::protocol::{parse_frame, RequestId, JSONRPC_VERSION, MCP_PROTOCOL_VERSION};
use cf_mcp::provider::{ProviderError, RunSpec, SecretMeta, SecretProvider};
use cf_mcp::redact::REDACTION_TOKEN;
use cf_mcp::McpServer;

/// 固定数据假 provider（协议 / 分发层测试，避免依赖进程环境变量）。
#[derive(Debug, Clone)]
struct FakeProvider {
    names: Vec<String>,
    fail: Option<ProviderError>,
}

impl FakeProvider {
    fn ok() -> Self {
        Self {
            names: vec!["OPENAI_API_KEY".into(), "sk-abc123xxxxxxxx".into()],
            fail: None,
        }
    }
    fn failing(err: ProviderError) -> Self {
        Self { names: vec![], fail: Some(err) }
    }
}

impl SecretProvider for FakeProvider {
    fn list_secret_names(&self, _vault: Option<&str>) -> Result<Vec<String>, ProviderError> {
        if let Some(e) = &self.fail {
            return Err(e.clone());
        }
        Ok(self.names.clone())
    }
    fn list_secrets(&self, _vault: Option<&str>) -> Result<Vec<SecretMeta>, ProviderError> {
        if let Some(e) = &self.fail {
            return Err(e.clone());
        }
        Ok(self
            .names
            .iter()
            .map(|n| SecretMeta {
                name: n.clone(),
                id: format!("fake:{n}"),
                vault: "v".into(),
                category: "test".into(),
                updated_at: None,
            })
            .collect())
    }
    fn get_secret_metadata(&self, secret_ref: &str) -> Result<SecretMeta, ProviderError> {
        if let Some(e) = &self.fail {
            return Err(e.clone());
        }
        Ok(SecretMeta {
            name: secret_ref.into(),
            id: format!("fake:{secret_ref}"),
            vault: "v".into(),
            category: "test".into(),
            updated_at: None,
        })
    }
    fn run_with_secret(&self, spec: &RunSpec) -> Result<i32, ProviderError> {
        if let Some(e) = &self.fail {
            return Err(e.clone());
        }
        if spec.cmd == "exit-42" {
            return Ok(42);
        }
        Ok(0)
    }
}

fn server() -> McpServer {
    McpServer::new(Box::new(FakeProvider::ok()))
}

fn parse_resp(raw: &str) -> Value {
    serde_json::from_str(raw).expect("server response must be valid JSON")
}

// ===========================================================================
// 帧解析
// ===========================================================================

#[test]
fn parse_valid_request_frame() {
    let line = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#;
    let frame = parse_frame(line).expect("valid frame must parse");
    assert_eq!(frame.jsonrpc, JSONRPC_VERSION);
    assert_eq!(frame.id, Some(RequestId::Number(1)));
    assert_eq!(frame.method, "initialize");
}

#[test]
fn parse_notification_has_no_id() {
    let line = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    let frame = parse_frame(line).expect("notification must parse");
    assert!(frame.id.is_none());
}

#[test]
fn parse_rejects_non_json() {
    let err = parse_frame("not json at all").expect_err("must reject non-JSON");
    assert_eq!(err.code(), -32700);
}

#[test]
fn parse_rejects_wrong_jsonrpc_version() {
    let err = parse_frame(r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#).expect_err("...");
    assert_eq!(err.code(), -32600);
}

#[test]
fn parse_rejects_missing_method() {
    let err = parse_frame(r#"{"jsonrpc":"2.0","id":1}"#).expect_err("...");
    assert_eq!(err.code(), -32600);
}

// ===========================================================================
// 生命周期（§3.2）
// ===========================================================================

#[test]
fn initialize_returns_protocol_version_and_capabilities() {
    let s = server();
    let line = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#;
    let resp = s.handle_line(line).expect("initialize must produce a response");
    let v = parse_resp(&resp);
    assert_eq!(v["id"], json!(1), "response must echo request id");
    assert_eq!(v["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
    assert_eq!(v["result"]["capabilities"]["tools"], json!({}));
    assert!(v["result"]["serverInfo"]["name"].is_string());
    assert!(v["result"]["serverInfo"]["version"].is_string());
}

#[test]
fn initialized_notification_gets_no_response() {
    let s = server();
    let line = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    assert!(s.handle_line(line).is_none(), "notification must not be answered");
}

#[test]
fn tools_list_returns_exactly_four_mvp_tools() {
    let s = server();
    let resp = s.handle_line(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#).expect("response");
    let v = parse_resp(&resp);
    let tools = v["result"]["tools"].as_array().expect("tools must be an array");
    assert_eq!(tools.len(), 4, "MVP 只注册 4 工具（docs/20 §3.3）");
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        vec!["list_secret_names", "list_secrets", "run_with_secret", "get_secret_metadata"]
    );
    for t in tools {
        assert!(t["inputSchema"].is_object(), "each tool must declare inputSchema");
        assert!(t["description"].is_string(), "each tool must carry a description");
    }
}

#[test]
fn ping_returns_empty_result() {
    let s = server();
    let resp = s.handle_line(r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#).expect("response");
    let v = parse_resp(&resp);
    assert_eq!(v["result"], json!({}));
}

#[test]
fn unknown_method_returns_method_not_found() {
    let s = server();
    let resp = s.handle_line(r#"{"jsonrpc":"2.0","id":4,"method":"bogus/method"}"#).expect("response");
    let v = parse_resp(&resp);
    assert_eq!(v["error"]["code"], -32601);
}

#[test]
fn parse_error_response_has_null_id() {
    let s = server();
    let resp = s.handle_line("### not json ###").expect("must respond with parse error");
    let v = parse_resp(&resp);
    assert_eq!(v["error"]["code"], -32700);
    assert!(v["id"].is_null(), "parse error response id must be null");
}

// ===========================================================================
// tools/call（§3.3）
// ===========================================================================

#[test]
fn tools_call_list_secret_names_returns_names() {
    let s = server();
    let line = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"list_secret_names","arguments":{}}}"#;
    let resp = s.handle_line(line).expect("response");
    let v = parse_resp(&resp);
    assert_eq!(v["result"]["isError"], json!(false));
    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("OPENAI_API_KEY"));
}

#[test]
fn tools_call_redacts_secret_like_tokens_in_output() {
    // §3.5-2 输出 Redactor 管道：所有 content[0].text 经 SecretRedactor。
    let s = server();
    let line = r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"list_secret_names","arguments":{}}}"#;
    let resp = s.handle_line(line).expect("response");
    let v = parse_resp(&resp);
    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("OPENAI_API_KEY"), "非 sk- 前缀的名称须保留");
    assert!(text.contains(REDACTION_TOKEN), "sk- 指纹名称须被脱敏");
    assert!(!text.contains("sk-abc123xxxxxxxx"), "sk- 指纹名称不得原样出现在输出");
}

#[test]
fn tools_call_run_with_secret_returns_exit_code() {
    let s = server();
    let line = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"run_with_secret","arguments":{"secret":"OPENAI_API_KEY","cmd":"exit-42"}}}"#;
    let resp = s.handle_line(line).expect("response");
    let v = parse_resp(&resp);
    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("\"exit_code\":42"), "run_with_secret 须返回子进程退出码");
}

#[test]
fn tools_call_unknown_tool_returns_method_not_found() {
    let s = server();
    // AS-4 硬拒四件套之一：reveal_secret 不在注册表 → -32601
    let line = r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"reveal_secret","arguments":{}}}"#;
    let resp = s.handle_line(line).expect("response");
    let v = parse_resp(&resp);
    assert_eq!(v["error"]["code"], -32601);
}

#[test]
fn tools_call_missing_name_returns_invalid_params() {
    let s = server();
    let line = r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{}}"#;
    let resp = s.handle_line(line).expect("response");
    let v = parse_resp(&resp);
    assert_eq!(v["error"]["code"], -32602);
}

#[test]
fn tools_call_missing_required_param_returns_invalid_params() {
    let s = server();
    // run_with_secret 要求 secret / cmd（§3.3 inputSchema required）
    let line = r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"run_with_secret","arguments":{"cmd":"sh"}}}"#;
    let resp = s.handle_line(line).expect("response");
    let v = parse_resp(&resp);
    assert_eq!(v["error"]["code"], -32602);
}

#[test]
fn tools_call_provider_error_maps_to_7xxx() {
    let s = McpServer::new(Box::new(FakeProvider::failing(ProviderError::NotFound(
        "nope".into(),
    ))));
    let line = r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"get_secret_metadata","arguments":{"secret":"nope"}}}"#;
    let resp = s.handle_line(line).expect("response");
    let v = parse_resp(&resp);
    assert_eq!(v["error"]["code"], 7003, "SecretNotFound 须映射到 7003（§3.4）");
}

#[test]
fn tools_call_get_secret_metadata_returns_lifecycle_envelope() {
    let s = server();
    let line = r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"get_secret_metadata","arguments":{"secret":"OPENAI_API_KEY"}}}"#;
    let resp = s.handle_line(line).expect("response");
    let v = parse_resp(&resp);
    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    for field in [
        "id",
        "name",
        "type",
        "vault",
        "project",
        "environment",
        "created_at",
        "updated_at",
        "expires_at",
        "rotation_interval",
        "allowed_agents",
        "allowed_actions",
        "last_used_at",
        "last_rotated_at",
    ] {
        assert!(text.contains(field), "metadata 必须携带 AS-9 生命周期字段 {field:?}");
    }
}

#[test]
fn error_code_constants_match_section_34() {
    // 冻结 docs/20 §3.4 错误码表（7xxx 段；docs/03 §12 登记落 G-F）。
    assert_eq!(McpError::ParseError(String::new()).code(), -32700);
    assert_eq!(McpError::InvalidRequest(String::new()).code(), -32600);
    assert_eq!(McpError::MethodNotFound(String::new()).code(), -32601);
    assert_eq!(McpError::InvalidParams(String::new()).code(), -32602);
    assert_eq!(McpError::Internal(String::new()).code(), -32603);
    assert_eq!(McpError::ProviderUnavailable(String::new()).code(), 7001);
    assert_eq!(McpError::AuthRequired(String::new()).code(), 7002);
    assert_eq!(McpError::SecretNotFound(String::new()).code(), 7003);
    let sub = McpError::SubprocessFailed { exit_code: None, detail: String::new() };
    assert_eq!(sub.code(), 7004);
    assert_eq!(McpError::InvalidParameter(String::new()).code(), 7005);
    assert_eq!(McpError::InternalError(String::new()).code(), 7006);
}
