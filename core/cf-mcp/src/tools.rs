//! 工具分发（docs/20 §3.3 MVP 四项）。
//!
//! 工具注册表**只含 4 项**：`list_secret_names` / `list_secrets` /
//! `run_with_secret` / `get_secret_metadata`——「收缩为 4 工具面」（§3.3）。
//! grant/revoke/rotate/environment 系列属 v2.x 完整面（§1.3），**不在**本注册表；
//! AS-4 硬拒四项（reveal_secret / get_password / dump_vault / export_all_secrets）
//! 也一律不注册（未注册即 `-32601`）。
//!
//! 输出管道（§3.5-2）：所有 `content[0].text` 经 [`SecretRedactor`] 处理。

use std::path::PathBuf;

use serde::Serialize;
use serde_json::{json, Value};

use crate::audit::{AuditEvent, UsageAudit};
use crate::error::McpError;
use crate::provider::{RunSpec, SecretMeta, SecretProvider};
use crate::redact::SecretRedactor;

/// MCP 工具定义（`tools/list` 返回项）。
#[derive(Debug, Clone, Serialize)]
pub struct ToolDefinition {
    /// 工具名。
    pub name: &'static str,
    /// 人类可读描述。
    pub description: &'static str,
    /// 参数 JSON Schema（§3.3；序列化为 MCP 规范的 `inputSchema` 驼峰键）。
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// 工具结果 `content[]` 项（MVP 仅 `text` 类型，§3.3）。
#[derive(Debug, Clone, Serialize)]
pub struct ContentItem {
    /// 内容类型（恒 `"text"`）。
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// 文本内容（已经 SecretRedactor 处理）。
    pub text: String,
}

/// 工具调用完整结果。
#[derive(Debug, Clone)]
pub struct ToolResult {
    /// `content[]` 内容项。
    pub content: Vec<ContentItem>,
    /// 是否工具级错误（MCP `isError`；MVP 恒 `false`，错误走 JSON-RPC error）。
    pub is_error: bool,
}

/// 工具注册表 + 分发。
#[derive(Debug)]
pub struct ToolRegistry {
    definitions: Vec<ToolDefinition>,
}

impl ToolRegistry {
    /// 含 MVP 四项的注册表（docs/20 §3.3）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            definitions: vec![
                ToolDefinition {
                    name: "list_secret_names",
                    description: "List the names of all available secrets (values never returned).",
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "vault": { "type": "string", "description": "Optional vault filter." }
                        },
                        "additionalProperties": false
                    }),
                },
                ToolDefinition {
                    name: "list_secrets",
                    description: "List secret metadata (name, id, category, updated_at; values never returned).",
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "vault": { "type": "string", "description": "Optional vault filter." }
                        },
                        "additionalProperties": false
                    }),
                },
                ToolDefinition {
                    name: "run_with_secret",
                    description: "Run a command with a secret injected into its environment. The value is never returned.",
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "secret": { "type": "string", "description": "Secret reference (not the value)." },
                            "env_name": { "type": "string", "description": "Environment variable name to inject (default: the secret name)." },
                            "cmd": { "type": "string", "description": "Command to run." },
                            "args": { "type": "array", "items": { "type": "string" }, "description": "Command arguments." },
                            "cwd": { "type": "string", "description": "Working directory (optional)." }
                        },
                        "required": ["secret", "cmd"],
                        "additionalProperties": false
                    }),
                },
                ToolDefinition {
                    name: "get_secret_metadata",
                    description: "Get read-only metadata for a secret (the value is never returned).",
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "secret": { "type": "string", "description": "Secret reference." }
                        },
                        "required": ["secret"],
                        "additionalProperties": false
                    }),
                },
            ],
        }
    }

    /// `tools/list` 用：全部工具定义。
    #[must_use]
    pub fn definitions(&self) -> &[ToolDefinition] {
        &self.definitions
    }

    /// 工具名清单。
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.definitions.iter().map(|d| d.name).collect()
    }

    /// 分发一次工具调用。
    ///
    /// 返回 `Ok(ToolResult)`（`content` 已经 Redactor 处理）或 `McpError`
    /// （工具级错误 → JSON-RPC error，码值见 §3.4）。未注册工具 →
    /// [`McpError::MethodNotFound`]（`-32601`）。
    pub fn call(
        &self,
        provider: &dyn SecretProvider,
        redactor: &SecretRedactor,
        audit: &dyn UsageAudit,
        name: &str,
        args: &Value,
    ) -> Result<ToolResult, McpError> {
        let text = match name {
            "list_secret_names" => call_list_secret_names(provider, args)?,
            "list_secrets" => call_list_secrets(provider, args)?,
            "run_with_secret" => call_run_with_secret(provider, audit, args)?,
            "get_secret_metadata" => call_get_secret_metadata(provider, args)?,
            other => return Err(McpError::MethodNotFound(format!("tool not found: {other}"))),
        };
        Ok(ToolResult {
            content: vec![ContentItem {
                kind: "text",
                text: redactor.redact(&text),
            }],
            is_error: false,
        })
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// SecretMeta → AS-9 生命周期信封（docs/20 §3.3 字段 + AS-9 扩展键）。
///
/// §3.3 冻结返回 `{name,id,category,updated_at,allowed_actions}`；本信封是
/// **超集**：额外补 AS-9 生命周期键（project/environment/created_at/expires_at/
/// rotation_interval/allowed_agents/last_used_at/last_rotated_at），缺省为空值。
/// **形状即契约**（mcp_acceptance.rs AS-9 判据），值由 provider 填充；本信封
/// **永不包含 Secret 明文**（AS-14 可用不可见）。
#[must_use]
pub fn secret_meta_json(meta: &SecretMeta) -> Value {
    json!({
        "id": meta.id.as_str(),
        "name": meta.name.as_str(),
        "type": "secret",
        "vault": meta.vault.as_str(),
        "category": meta.category.as_str(),
        "project": "",
        "environment": "",
        "created_at": "",
        "updated_at": meta.updated_at,
        "expires_at": "",
        "rotation_interval": "",
        "allowed_agents": [],
        "allowed_actions": [],
        "last_used_at": "",
        "last_rotated_at": "",
    })
}

fn call_list_secret_names(provider: &dyn SecretProvider, args: &Value) -> Result<String, McpError> {
    let vault = optional_string(args, "vault");
    let names = provider
        .list_secret_names(vault.as_deref())
        .map_err(McpError::from)?;
    Ok(json!({ "names": names }).to_string())
}

fn call_list_secrets(provider: &dyn SecretProvider, args: &Value) -> Result<String, McpError> {
    let vault = optional_string(args, "vault");
    let metas = provider
        .list_secrets(vault.as_deref())
        .map_err(McpError::from)?;
    let secrets: Vec<Value> = metas.iter().map(secret_meta_json).collect();
    Ok(json!({ "secrets": secrets }).to_string())
}

fn call_run_with_secret(
    provider: &dyn SecretProvider,
    audit: &dyn UsageAudit,
    args: &Value,
) -> Result<String, McpError> {
    let secret = required_string(args, "secret")?;
    // M-4（KNOWN-ISSUES）：缺省 env_name 取 `op://` 引用末段（field/item 名，
    // `default_env_name` 规则在 op.rs 锁定）——不再取整个 secret 串（对 `op://`
    // 引用必 7005）。末段非法环境变量名时由 provider 校验层照常 7005。
    let env_name = optional_string(args, "env_name")
        .unwrap_or_else(|| crate::provider::op::default_env_name(&secret));
    let cmd = required_string(args, "cmd")?;
    let cmd_args: Vec<String> = args
        .get("args")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let cwd = args
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);

    let spec = RunSpec {
        secret_ref: secret.clone(),
        env_name,
        cmd: cmd.clone(),
        args: cmd_args,
        cwd,
    };
    let code = provider.run_with_secret(&spec).map_err(McpError::from)?;

    // 审计：USE 事件（失败不阻断工具调用——审计尽力而为，D-3 未定）。
    if let Err(e) = audit.record(&AuditEvent::use_event(&secret, code == 0)) {
        tracing::warn!(error = ?e, secret = %secret, "audit record failed");
    }
    Ok(json!({ "exit_code": code }).to_string())
}

fn call_get_secret_metadata(
    provider: &dyn SecretProvider,
    args: &Value,
) -> Result<String, McpError> {
    let secret = required_string(args, "secret")?;
    let meta = provider
        .get_secret_metadata(&secret)
        .map_err(McpError::from)?;
    let value = secret_meta_json(&meta);
    Ok(serde_json::to_string(&value)?)
}

/// 取必填字符串参数（缺失 / 空串 → [`McpError::InvalidParams`]）。
fn required_string(args: &Value, key: &str) -> Result<String, McpError> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| McpError::InvalidParams(format!("missing or empty parameter `{key}`")))
}

/// 取可选字符串参数（缺失 / 空串 → `None`）。
fn optional_string(args: &Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}
