//! MiniMax Code 的转发请求构造：**Anthropic Messages 协议** + Bearer 鉴权。
//!
//! ── 为什么不是 OpenAI 兼容 ──────────────────────────────────
//! 客户端的 provider 声明是 `npm: '@ai-sdk/anthropic'`，端点
//! `POST /mavis/api/v1/llm/v1/messages` 就是标准 Anthropic Messages。
//! 因此本家的请求体要**从 chat 形态转成 Anthropic 形态**，响应帧要**折回 chat
//! SSE** —— 两侧都走既有的翻译层，不自己写一套：
//!   * 请求：`anthropic_request_from_chat`（system 提到顶层、tool 消息变
//!     `tool_result` 块、`tool_calls` 变 `tool_use` 块）；
//!   * 响应：`UpstreamKind::Anthropic`（**网关**据此选它那台
//!     `AnthropicToChatStream` 翻译机 —— 插件只负责在 `StreamHead` 里如实
//!     声明协议，不做响应翻译）。
//! 走翻译层的理由与 ZCode 活动套餐通道逐字相同：账号轮换、限额冷却、退避重试、
//! usage 记账与取消处理全部留在网关编排层，只有字节形态在翻译器里变。
//!
//! ── 两个网关门禁（实测 2026-10-21）──────────────────────────
//! ```text
//!   无 Authorization            → 401（空体）
//!   Bearer <任意假令牌>          → 401 {"error":"invalid access token"}
//!   带查询串（设备参数）         → 同上（**签名头与查询串都不影响判定**）
//! ```
//! ⇒ 推理链只需要 `Authorization: Bearer`，不需要 `endpoints::sign`。
//!
//! ── 强制推理（会咬人的一处）────────────────────────────────
//! 本家的模型**都要求思考**：发 `thinking:{"type":"disabled"}` 会被上游
//! `400 … requires adaptive thinking` 拒掉（实测）。
//!
//! 好消息是**转换层天然不会发出这个键**：[`anthropic_request_from_chat`] 的
//! `thinking` 只由 chat 体的 `reasoning_effort` 折算而来（见
//! `anthropic_outbound::thinking_budget`），客户端若在 body 里塞一个
//! `thinking` 对象，它**根本不参与组装** —— 所以「客户端明确关闭思考」这一档
//! 在这里被自然吞掉（那是「上游做不到」，不是「我们没实现」）。
//!
//! 下面 `drop_disabled_thinking` 是**防御性**的一道：万一将来有人给转换层
//! 加了「chat 体的 `thinking` 直通」逻辑，这一道能保证本家仍不会把它发出去。
//! 对应地，测试断言的是「转换产物里绝不出现 `type: disabled`」，
//! 而不是「客户端传什么就原样留着」——后者与真实链路不符。
//!
//! 「客户端想要更多思考」正常透传：`reasoning_effort` → `thinking.budget_tokens`
//! 由转换层负责，本文件一字不改。
//!
//! ── 搬进插件时改了什么 ──────────────────────────────────────
//! ```text
//!   不变：URL、三个头（Content-Type / Authorization / anthropic-version）、
//!         转换层调用、thinking.disabled 的删除逻辑、缺模型名本地 400
//!   改：  产物类型从网关的 plan 结构换成插件的 `ChatPlan`（多一个
//!         `upstream: UpstreamKind::Anthropic` 字段 —— 网关靠它选翻译机）
//! ```
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 本 crate 编译期禁止 unwrap/expect/panic（见 `main.rs` 的 deny）。

use agent2api_provider_sdk::ChatPlan;
use serde_json::Value;

use crate::anthropic::anthropic_outbound;
use crate::errors::GatewayError;

use super::credentials::MinimaxCredential;
use super::endpoints;
use super::region::Region;

/// Anthropic 协议版本头（与 ZCode 通道同值）。
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// 组装一次转发请求。
///
/// `body` 是客户端发来的 chat 请求体；本函数负责把它翻成 Anthropic Messages。
/// 模型名缺省时不猜（上游没有「默认模型」概念，猜一个会让客户端的意图被悄悄改写）
/// —— 交给网关的模型解析去兜。
///
/// `region` 决定打哪个网关（国内 `agent.minimax.cn` / 国际 `agent.minimax.io`）：
/// 两个地区的**请求形状与鉴权完全相同**，差的只有域名 —— 所以这里只是把基址
/// 换成 `region.gateway_url()`，别处（body 转换、头、常量）一律不分叉。
pub fn build_chat_plan(
    region: Region,
    credential: &MinimaxCredential,
    body: &Value,
) -> Result<ChatPlan, GatewayError> {
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if model.is_empty() {
        return Err(GatewayError::with_status(400, "MiniMax Code 请求缺少模型名"));
    }

    let mut payload = anthropic_outbound::anthropic_request_from_chat(body, model).map_err(
        |message| GatewayError::with_status(400, format!("请求体转换失败：{message}")),
    )?;
    drop_disabled_thinking(&mut payload);

    let headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        (
            "Authorization".to_string(),
            format!("Bearer {}", credential.access_token),
        ),
        ("anthropic-version".to_string(), ANTHROPIC_VERSION.to_string()),
    ];

    Ok(ChatPlan {
        url: endpoints::gateway_url(region, endpoints::MESSAGES_PATH),
        headers,
        body: payload,
        upstream: agent2api_provider_protocol::UpstreamKind::Anthropic,
    })
}

/// 把 `thinking.type == "disabled"` 删掉（上游对它会回
/// `400 requires adaptive thinking`，见模块头）。
///
/// **只删 `disabled`**：`enabled` / `adaptive` 与 `budget_tokens` 一律留着 ——
/// 吞掉它们等于把用户的设置静默丢弃。
///
/// ── 为什么它今天是防御性的 ──────────────────────────────────
/// 转换层的 `thinking` 只由 `reasoning_effort` 折算，客户端 body 里自带的
/// `thinking` 不会进产物（见模块头）。所以这条在当前链路上**不会命中**；
/// 它守的是「将来有人给转换层加了直通逻辑」那一天。
fn drop_disabled_thinking(payload: &mut Value) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };
    let disabled = object
        .get("thinking")
        .and_then(|thinking| thinking.get("type"))
        .and_then(Value::as_str)
        .map(|kind| kind.eq_ignore_ascii_case("disabled"))
        .unwrap_or(false);
    if disabled {
        object.remove("thinking");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn credential() -> MinimaxCredential {
        MinimaxCredential {
            id: "minimax-1".into(),
            access_token: "mmoat_test1234567890".into(),
            ..Default::default()
        }
    }

    #[test]
    fn builds_an_anthropic_request_with_bearer() {
        let body = json!({
            "model": "MiniMax-M3.1-Flash",
            "max_tokens": 64,
            "messages": [
                {"role": "system", "content": "你是助手"},
                {"role": "user", "content": "hi"}
            ]
        });
        let plan = build_chat_plan(Region::Cn, &credential(), &body).expect("应能构造");
        assert_eq!(
            plan.url,
            "https://agent.minimax.cn/mavis/api/v1/llm/v1/messages"
        );
        // 鉴权：只认 Bearer（x-api-key 会被 401 拒，见模块头）
        let auth = plan
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.as_str())
            .unwrap_or("");
        assert_eq!(auth, "Bearer mmoat_test1234567890");
        assert!(
            !plan
                .headers
                .iter()
                .any(|(key, _)| key.eq_ignore_ascii_case("x-api-key")),
            "不能带 x-api-key"
        );
        // 系统消息提到顶层（Anthropic 协议要求）
        assert_eq!(plan.body["system"], json!("你是助手"));
        assert_eq!(plan.body["model"], json!("MiniMax-M3.1-Flash"));
        assert_eq!(plan.body["messages"][0]["role"], json!("user"));
    }

    /// **最重要的一处**：响应协议必须如实申报成 Anthropic —— 网关靠它选翻译机。
    /// 申报错了会把 Anthropic SSE 当 chat SSE 透传给客户端，
    /// 症状是「状态码 200 但客户端收到一堆乱码」。
    #[test]
    fn the_upstream_protocol_is_anthropic_not_chat() {
        let body = json!({
            "model": "MiniMax-M3",
            "max_tokens": 8,
            "messages": [{"role": "user", "content": "hi"}]
        });
        let plan = build_chat_plan(Region::Cn, &credential(), &body).expect("应能构造");
        assert_eq!(
            plan.upstream,
            agent2api_provider_protocol::UpstreamKind::Anthropic,
            "网关据此选 Anthropic 翻译机；报成 Chat 会让客户端收到乱码"
        );
    }

    /// **转换产物里绝不能出现 `type: disabled`** —— 上游对它会回
    /// `400 requires adaptive thinking`（见模块头）。
    ///
    /// 这条同时钉住两件事：① 转换层不从 chat 体直通 `thinking`；
    /// ② 即便将来直通了，`drop_disabled_thinking` 也会把它删掉。
    #[test]
    fn a_disabled_thinking_never_reaches_the_upstream() {
        let body = json!({
            "model": "MiniMax-M3",
            "max_tokens": 32,
            "thinking": {"type": "disabled"},
            "messages": [{"role": "user", "content": "hi"}]
        });
        let plan = build_chat_plan(Region::Cn, &credential(), &body).expect("应能构造");
        let printed = plan.body.to_string();
        assert!(
            !printed.contains("\"disabled\""),
            "disabled 必须被吞掉，否则上游 400：{printed}"
        );
    }

    /// 「客户端想要更多思考」这一档**必须能落到产物上**：chat 的
    /// `reasoning_effort` 由转换层折成 `thinking.budget_tokens`。
    ///
    /// ⚠️ 注意渠道：客户端表达思考的字段是 **`reasoning_effort`**，不是
    /// `thinking` 对象（后者根本不参与组装，见模块头）—— 拿 `thinking` 写这条
    /// 用例会误判成「被吞掉了」。
    #[test]
    fn an_explicit_reasoning_request_reaches_the_body() {
        let body = json!({
            "model": "MiniMax-M3",
            "max_tokens": 4096,
            "reasoning_effort": "high",
            "messages": [{"role": "user", "content": "hi"}]
        });
        let plan = build_chat_plan(Region::Cn, &credential(), &body).expect("应能构造");
        assert_eq!(
            plan.body.pointer("/thinking/type"),
            Some(&json!("enabled")),
            "reasoning_effort 必须折成 thinking：{}",
            plan.body
        );
        assert!(
            plan.body
                .pointer("/thinking/budget_tokens")
                .and_then(Value::as_i64)
                .is_some_and(|budget| budget > 0),
            "预算必须是正数：{}",
            plan.body
        );
    }

    /// 没有思考诉求时**不能凭空注入** `thinking`（那会改变上游对模型的默认
    /// 行为，且让 temperature / top_p 被转换层丢掉）。
    #[test]
    fn no_reasoning_request_means_no_thinking_key() {
        let body = json!({
            "model": "MiniMax-M3",
            "max_tokens": 64,
            "temperature": 0.7,
            "messages": [{"role": "user", "content": "hi"}]
        });
        let plan = build_chat_plan(Region::Cn, &credential(), &body).expect("应能构造");
        assert!(
            plan.body.get("thinking").is_none(),
            "没要求思考就不该注入：{}",
            plan.body
        );
        // 没有 thinking 时 temperature 照常透传（转换层只在 thinking 开启时丢它）
        assert_eq!(plan.body["temperature"], json!(0.7));
    }

    /// **地区必须落在 URL 上**：这是拆家后唯一真正分叉的地方 —— 请求体、头、
    /// 转换层两地逐字相同。国际版打到 `agent.minimax.io`（**不是**
    /// `.minimaxi.com` —— 后者只认国内令牌，见 `region.rs` 的 `gateway_url`）。
    #[test]
    fn the_region_decides_the_gateway() {
        let body = json!({
            "model": "MiniMax-M3.1-Flash",
            "max_tokens": 8,
            "messages": [{"role": "user", "content": "hi"}]
        });
        let intl = build_chat_plan(Region::Intl, &credential(), &body).expect("应能构造");
        assert_eq!(
            intl.url,
            "https://agent.minimax.io/mavis/api/v1/llm/v1/messages"
        );
        assert!(
            !intl.url.contains("minimax.cn"),
            "国际版绝不能打到国内网关：{}",
            intl.url
        );
        // 除 URL 之外两地必须一字不差 —— 有别的差异就说明分叉错了
        let cn = build_chat_plan(Region::Cn, &credential(), &body).expect("应能构造");
        assert_eq!(cn.headers, intl.headers, "鉴权头两地一致（同一个 client_id）");
        assert_eq!(cn.body, intl.body, "转换后的请求体两地一致");
    }

    #[test]
    fn missing_model_is_rejected_locally() {
        let body = json!({"messages": [{"role": "user", "content": "hi"}]});
        let error = build_chat_plan(Region::Cn, &credential(), &body).expect_err("应被拒");
        assert!(error.to_string().contains("模型名"), "实际：{error}");
    }

    /// 空 messages 也要在本地给出可读错误，而不是让转换层 panic。
    #[test]
    fn missing_messages_is_rejected_locally() {
        let body = json!({"model": "MiniMax-M3", "max_tokens": 8});
        let error = build_chat_plan(Region::Cn, &credential(), &body).expect_err("应被拒");
        assert!(
            error.to_string().contains("请求体转换失败"),
            "实际：{error}"
        );
    }
}
