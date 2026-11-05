//! MiniMax Code 上游错误分类。
//!
//! ── 实测到的响应形状（2026-10-21，curl 直连）───────────────
//! ```text
//!   401（无 Authorization）  → 空体
//!   401（假令牌）            → {"code":401,"message":"auth failed"}          ← 网关
//!   401（假令牌）            → {"error":"invalid access token"}               ← 账户类
//!   400（缺签名）            → {"error":"invalid signature"}
//!   400（思考关闭）          → ... requires adaptive thinking
//!   503（路径拼错）          → {"error":"direct_route_not_configured"}
//! ```
//! ⚠️ 上游**没有** `base_resp` 信封在推理路径上（那是账户/签到接口的形状）。
//! 推理失败一律「HTTP 状态码 + `code`/`error` 二选一字段」。
//!
//! ── 四档怎么归 ──────────────────────────────────────────────
//!   * `invalid access token` / `auth failed` / 401 → **`TokenExpired`**：
//!     编排层会先刷新凭证、再**同一账号**重试一次。本家有真续期端点
//!     （`grant_type=refresh_token`），所以这一档能自愈；刷不动时用户会收到
//!     「凭证过期」的可读提示，而不是原始 401。
//!   * 429 / 限流文案 → **`QuotaLimited`**：冷却该账号并换下一个。
//!     本家的额度分两个窗口（5 小时 / 周），耗尽与限速都走 429，
//!     只在文案上不同；两种处置一样（都是「这个号先别用」），所以不细分。
//!   * 内容审核（`content_filter` / 敏感词）→ **`ContentBlocked`**：
//!     不罚账号、换中性提示词重试一次。
//!   * 其余 → **`Fatal`**。`requires adaptive thinking` 与
//!     `direct_route_not_configured` 明确落在这一档：前者是我们的请求形状问题，
//!     后者是端点拼错 —— 罚账号或换账号都只会让同一面墙撞更多次。
//!
//! ── 搬进插件时改了什么 ──────────────────────────────────────
//! ```text
//!   不变：四档判定顺序、全部标记词、message_of 的拼法、401 不看正文这条护栏
//!   改：  返回类型从网关的 `UpstreamErrorClass` 换成插件的
//!         `agent2api_provider_protocol::ErrorClass`（同一个封闭四档枚举，
//!         只是搬到了协议 crate 里 —— 网关侧那台翻译机按它分流）
//! ```
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 本 crate 编译期禁止 unwrap/expect/panic（见 `main.rs` 的 deny）。

use agent2api_provider_protocol::ErrorClass;
use serde_json::Value;

/// 令牌失效的正文标记（网关与账户类两条链各一种写法）。
const TOKEN_MARKERS: [&str; 3] = ["invalid access token", "auth failed", "token is required"];

/// 限流 / 额度耗尽的文案标记。
const RATE_MARKERS: [&str; 4] = ["rate limit", "too many requests", "quota", "usage limit"];

/// 内容审核类标记（保守集合：宁可漏判成 Fatal，也不误罚账号）。
const CONTENT_MARKERS: [&str; 4] = ["content_filter", "content filter", "内容审核", "违规"];

/// 从正文里取业务码（`{"code":401}` 的整数或字符串形态）。
fn upstream_code(body: &Value) -> Option<i64> {
    body.get("code")
        .or_else(|| body.get("status_code"))
        .and_then(|value| {
            value
                .as_i64()
                .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
        })
}

/// 正文的文本形态（未解析出 JSON 时也拿得到 —— 上游偶尔回纯文本）。
fn text_of(body: &Value) -> String {
    match body {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// 客户端可见的完整文案：`上游返回 {status}: {上游原文}`（与别家同格式）。
fn message_of(status: u16, body: &Value) -> String {
    format!("上游返回 {status}: {body}")
}

/// 按上游响应归类（见模块头的四档）。
pub fn classify(status: u16, body: &Value) -> ErrorClass {
    let lower = text_of(body).to_ascii_lowercase();
    let code = upstream_code(body);
    let is_token_expired = TOKEN_MARKERS
        .iter()
        .any(|marker| lower.contains(&marker.to_ascii_lowercase()));

    // ① 凭证失效优先于「401 一律当过期」：本家的 401 有两种正文写法，但语义
    //    相同（令牌不可用），都该走刷新 + 同账号重试。
    //
    //    ⚠️ **401 不看正文**：实测「不带 Authorization」时上游回的就是
    //    `401` + **空体**。若要求正文里有 `invalid access token` 才算过期，
    //    这一档会落进 Fatal 原样透传 —— 症状是「续期明明可用，用户却看到
    //    原始 401」。这条曾被自己的测试抓住，别改回只认文案。
    if is_token_expired || status == 401 {
        return ErrorClass::TokenExpired {
            message: message_of(status, body),
        };
    }

    // ② 内容审核：不罚账号
    if CONTENT_MARKERS
        .iter()
        .any(|marker| lower.contains(&marker.to_ascii_lowercase()))
    {
        return ErrorClass::ContentBlocked {
            status,
            message: message_of(status, body),
            upstream_code: code,
        };
    }

    // ③ 限流 / 额度：冷却账号（上游不给恢复时间，走网关兜底冷却时长）
    if status == 429
        || RATE_MARKERS
            .iter()
            .any(|marker| lower.contains(&marker.to_ascii_lowercase()))
    {
        return ErrorClass::QuotaLimited {
            reset_at: None,
            message: message_of(status, body),
            upstream_code: code,
            status,
        };
    }

    // ④ 其余原样透传
    ErrorClass::Fatal {
        status,
        message: message_of(status, body),
        upstream_code: code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn gateway_auth_failure_is_token_expired() {
        let body = json!({"code": 401, "message": "auth failed"});
        assert!(matches!(
            classify(401, &body),
            ErrorClass::TokenExpired { .. }
        ));
    }

    #[test]
    fn account_style_auth_failure_is_token_expired() {
        // 账户类接口的写法与网关不同（error 而非 code），语义一样
        let body = json!({"error": "invalid access token"});
        assert!(matches!(
            classify(401, &body),
            ErrorClass::TokenExpired { .. }
        ));
    }

    #[test]
    fn plain_401_without_body_is_token_expired() {
        // 无 Authorization 时上游回 401 空体 —— 也该走刷新路径而不是原样透传
        assert!(matches!(
            classify(401, &Value::Null),
            ErrorClass::TokenExpired { .. }
        ));
        // 非 401 的正文里若出现令牌失效标记，同样算过期
        let body = json!({"error": "invalid access token"});
        assert!(matches!(
            classify(400, &body),
            ErrorClass::TokenExpired { .. }
        ));
    }

    #[test]
    fn rate_limit_is_quota_limited() {
        let body = json!({"type": "error", "error": {"type": "rate_limit_error"}});
        let class = classify(429, &body);
        assert!(matches!(class, ErrorClass::QuotaLimited { .. }));
        // 本档必须换账号（这是网关编排唯一的判据）
        assert!(class.rotates_account());
    }

    #[test]
    fn usage_limit_wording_is_quota_limited() {
        // 两个额度窗口（5h / 周）耗尽都走 429，文案里带 usage limit
        let body = json!({"error": "weekly usage limit reached"});
        assert!(matches!(
            classify(429, &body),
            ErrorClass::QuotaLimited { .. }
        ));
    }

    #[test]
    fn content_filter_does_not_punish_account() {
        let body = json!({"error": {"code": "content_filter"}});
        let class = classify(400, &body);
        assert!(matches!(class, ErrorClass::ContentBlocked { .. }));
        // 内容拦截**不**换账号（换家只会撞同一面墙），这是与 QuotaLimited 的分界
        assert!(!class.rotates_account());
    }

    /// 这两条是「我们的请求形状问题」，罚账号或换账号都无解 —— 必须留在 Fatal。
    #[test]
    fn request_shape_errors_stay_fatal() {
        let adaptive = json!({"error": "model requires adaptive thinking"});
        assert!(matches!(
            classify(400, &adaptive),
            ErrorClass::Fatal { .. }
        ));
        let route = json!({"error": "direct_route_not_configured"});
        assert!(matches!(
            classify(503, &route),
            ErrorClass::Fatal { .. }
        ));
        // 缺签名同属「我们发错了」，不能罚账号
        let signature = json!({"error": "invalid signature"});
        assert!(matches!(
            classify(400, &signature),
            ErrorClass::Fatal { .. }
        ));
    }

    #[test]
    fn plain_text_body_is_tolerated() {
        let body = Value::String("upstream is down".to_string());
        match classify(500, &body) {
            ErrorClass::Fatal { message, .. } => {
                assert!(message.contains("upstream is down"));
            }
            other => panic!("纯文本 500 应归 Fatal，实际 {other:?}"),
        }
    }

    /// HTTP 状态码要原样带到分类里（客户端看到的状态与上游一致）。
    #[test]
    fn the_status_is_preserved_for_passthrough_classes() {
        let class = classify(503, &json!({"error": "x"}));
        assert_eq!(class.status(), 503);
        // TokenExpired 没有自己的状态码，恒按 401 呈现
        assert_eq!(classify(401, &Value::Null).status(), 401);
    }
}
