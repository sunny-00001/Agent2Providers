//! MiniMax Code 专属出网：**不跟随 3xx** + 账号代理优先的三段出口。
//!
//! ── 为什么不能用仓库共用的 `http::send_raw` ──────────────────────
//! 两处差异，都是本家的硬需求：
//!
//! 1. **必须不跟随重定向**（`redirect: 'error'`）。
//!    大陆出口访问 `agent.minimax.io` 会回 **307 → `agent.minimaxi.com`**，
//!    那是**地域重定向**（「你的出口 IP 不在国际站服务范围」），而
//!    `.minimaxi.com` 只认国内令牌 ⇒ 跟过去必然得到 `401 invalid access token`，
//!    把「换个出口」伪装成「令牌失效」，用户会去反复重新登录而毫无效果。
//!    客户端自己也是 `redirect: 'error'`，理由相同。仓库共用的 `send_raw`
//!    没有关掉重定向，所以本家自带一份。
//!
//! 2. **网关默认出口要生效**。
//!    `http::send_raw` 在 `proxy` 为 `None` 时走的是**显式直连**
//!    （`control_client(None, "direct")`），不看网关的默认出口。对国内版
//!    （直连即可达）这条无所谓；但国际版账号若只有网关级出口、账号自己没配
//!    代理，直连就是必败 —— 而那正是「网关设了代理但还是超时」的典型症状。
//!    所以本家的出口优先级是：
//!    ```text
//!      账号级代理  →  网关默认出口  →  显式直连
//!    ```
//!
//! ── 客户端仍然按出口缓存 ────────────────────────────────────
//! 与 `http::control_client` 同一取舍：`reqwest::Client` 的连接池是按代理分的，
//! 每次请求都新建会丢掉复用（每条请求多一次 TLS 握手）。出口就那么几条，
//! 缓存不会膨胀。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 本 crate 编译期禁止 unwrap/expect/panic（见 `main.rs` 的 deny）。

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use agent2api_provider_protocol::WireProxy;
use serde_json::Value;

/// 控制面请求的超时（都是小请求：目录 / 余额 / 签到 / 设备码）。
pub const REQUEST_TIMEOUT_MS: u64 = 20_000;

/// 出站 User-Agent：客户端是 Electron，默认 UA 即可（上游不校验）。
const USER_AGENT: &str = "undici";

/// 一次请求的原始结果（与 `http::ApiResponse` 同形）。
pub struct ApiResponse {
    pub status: u16,
    /// 是否 2xx。
    pub ok: bool,
    /// 解析出的 JSON（空体 / 非 JSON 一律 `None`）。
    pub payload: Option<Value>,
    /// 原始文本（错误文案里要带上游原文）。
    pub text: String,
}

fn cache() -> &'static Mutex<HashMap<String, reqwest::Client>> {
    static CACHE: OnceLock<Mutex<HashMap<String, reqwest::Client>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 解析出口：账号级 → 网关默认 → 直连（`""` / `"direct"`）。
fn proxy_url(proxy: Option<&WireProxy>, gateway_proxy: &str) -> String {
    match proxy {
        Some(proxy) => proxy.to_url(),
        None => gateway_proxy.trim().to_string(),
    }
}

/// 建 / 取一个客户端（按出口缓存）。
///
/// ── `redirect(none)` 是本模块存在的首要理由 ──────────────────
/// 见模块头第 1 条：跟随 307 会把「出口 IP 不对」变成「令牌失效」。
fn client_for(url: &str) -> reqwest::Client {
    if let Ok(guard) = cache().lock() {
        if let Some(client) = guard.get(url) {
            return client.clone();
        }
    }
    let mut builder = reqwest::Client::builder()
        // 与仓库其余各家同一条栈：rustls，不依赖系统 openssl
        .use_rustls_tls()
        .timeout(Duration::from_millis(REQUEST_TIMEOUT_MS))
        // 唯一一处与共用客户端不同的策略：不跟重定向
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(USER_AGENT);
    let trimmed = url.trim();
    if trimmed.is_empty() || trimmed == "direct" {
        // 显式直连：**必须调 `no_proxy()`**。仓库开了 reqwest 的
        // `system-proxy` 特性（Antigravity 要跟随系统代理），默认会读系统设置；
        // 不关掉的话「直连就是直连」这条语义就被机器环境悄悄改写了。
        builder = builder.no_proxy();
    } else {
        match reqwest::Proxy::all(trimmed) {
            Ok(proxy) => builder = builder.proxy(proxy),
            // 代理 URL 非法时降级直连而不是让整条链路失败（与共用客户端同口径）
            Err(_) => builder = builder.no_proxy(),
        }
    }
    let built = builder.build().unwrap_or_else(|_| reqwest::Client::new());
    if let Ok(mut guard) = cache().lock() {
        if guard.len() >= 64 {
            guard.clear();
        }
        guard.insert(url.to_string(), built.clone());
    }
    built
}

/// 发一次请求。
///
/// 非 2xx **也返回 `Ok`**：本家对「哪些状态码算失败」的判据在调用方
/// （401 走续期、3xx 要点名「出口不在服务范围」、其余按四档分类）。
pub async fn request(
    method: &str,
    url: &str,
    body: Option<&Value>,
    form: Option<&str>,
    headers: &[(String, String)],
    proxy: Option<&WireProxy>,
    gateway_proxy: &str,
) -> Result<ApiResponse, String> {
    let client = client_for(&proxy_url(proxy, gateway_proxy));
    let mut builder = match method {
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        _ => client.get(url),
    };
    builder = builder.header("Accept", "application/json");
    for (key, value) in headers {
        builder = builder.header(key.as_str(), value.as_str());
    }
    if let Some(payload) = body {
        builder = builder
            .header("Content-Type", "application/json")
            .body(payload.to_string());
    } else if let Some(form) = form {
        builder = builder
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form.to_string());
    }
    let response = builder.send().await.map_err(|error| describe(&error))?;
    let status = response.status().as_u16();
    let text = response.text().await.map_err(|error| describe(&error))?;
    let payload = if text.trim().is_empty() {
        None
    } else {
        serde_json::from_str::<Value>(&text).ok()
    };
    Ok(ApiResponse {
        status,
        ok: (200..300).contains(&status),
        payload,
        text,
    })
}

/// 传输错误 → 人话（带完整原因链，便于排障）。
///
/// ── 为什么要原因链而不是顶层一句话 ──────────────────────────
/// `reqwest::Error` 的 `Display` 只给最外层（`error sending request`），
/// 代理握手失败 / DNS / TLS 在它下面几层 —— 只打顶层会让「代理配错了」
/// 看起来与「上游挂了」一模一样。
pub fn describe(error: &reqwest::Error) -> String {
    let mut parts: Vec<String> = vec![error.to_string()];
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(error);
    let mut depth = 0;
    while let Some(error) = source {
        if depth >= 4 {
            break;
        }
        parts.push(error.to_string());
        source = error.source();
        depth += 1;
    }
    if error.is_timeout() {
        parts.insert(0, "请求超时".to_string());
    }
    parts.join(" ← ")
}

/// 一次失败的状态码是不是**重定向**（用于给出「换个出口」的提示）。
pub fn is_redirect(status: u16) -> bool {
    (300..400).contains(&status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirects_are_recognized_as_their_own_class() {
        // 3xx 必须单独成档：跟过去会变成 401，而真相是「出口 IP 不对」
        assert!(is_redirect(301));
        assert!(is_redirect(307));
        assert!(is_redirect(302));
        assert!(!is_redirect(200));
        assert!(!is_redirect(401));
        assert!(!is_redirect(500));
    }

    #[test]
    fn the_proxy_priority_is_account_then_gateway_then_direct() {
        let account = WireProxy {
            protocol: "http".into(),
            host: "127.0.0.1".into(),
            port: Some(7897),
            username: String::new(),
            password: String::new(),
        };
        // ① 有账号代理 → 用它（忽略网关默认）
        assert_eq!(proxy_url(Some(&account), "http://gw:8080"), "http://127.0.0.1:7897");
        // ② 没账号代理 → 用网关默认
        assert_eq!(proxy_url(None, "http://gw:8080"), "http://gw:8080");
        // ③ 都没有 → 空串 = 直连
        assert_eq!(proxy_url(None, ""), "");
        // 显式直连也是一个有效取值（网关给的就是它）
        assert_eq!(proxy_url(None, "direct"), "direct");
    }

    /// 代理 URL 非法时必须降级直连而不是 panic（本 crate 禁 unwrap）。
    #[test]
    fn a_broken_proxy_url_does_not_panic() {
        let _client = client_for("这不是一个合法 URL");
        // 同一出口第二次取到的是缓存里那个（不会重复 build）
        let _again = client_for("这不是一个合法 URL");
    }
}
