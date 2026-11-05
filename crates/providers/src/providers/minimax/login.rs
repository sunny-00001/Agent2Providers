//! MiniMax Code 的登录：**OAuth 2.0 设备授权（RFC 8628）+ PKCE S256**。
//!
//! ── 实测（2026-10-21）────────────────────────────────────────
//! ```text
//! POST https://account.minimax.cn/oauth2/device/code
//!   client_id=mcode-public&scope=agent.default&audience=agent-backend
//!   &code_challenge=<S256>&code_challenge_method=S256
//! → {"device_code":"…","expires_in":300,"interval":3,"user_code":"K3CG-SPQZ",
//!    "verification_uri":"https://account.minimax.cn/oauth-authorize",
//!    "verification_uri_complete":"…?user_code=K3CG-SPQZ"}
//!
//! POST https://account.minimax.cn/oauth2/token
//!   client_id=mcode-public&grant_type=urn:ietf:params:oauth:grant-type:device_code
//!   &device_code=…&code_verifier=…
//! → 200 {access_token:"mmoat_…", refresh_token:"mmort_…", expires_in, scope}
//! → 400 {"error":"authorization_pending"}   还没授权（正常，继续等）
//! → 400 {"error":"slow_down"} / expired_token / access_denied
//! ```
//!
//! ── 为什么走设备码而不是「打开网页抓回调」─────────────────────
//! 客户端的登录就是这条 grant。它有两个好处，**容器部署下尤其要紧**：
//!   1. **不需要本地回调端口**：授权在用户的浏览器里完成，我们只轮询 ——
//!      于是不必让用户的本机能被上游回调到（容器里那根本做不到），
//!      也不需要桌面壳放行任何 `127.0.0.1` 导航；
//!   2. **PKCE**：设备码即使泄漏，没有本进程里的 verifier 也换不成令牌。
//!      verifier 只活在进程内的登录表里，不进前端、不进日志、不落盘。
//!
//! ── 为什么用轮询型申报（`poll_interval_ms > 0`）────────────────
//! 网关的登录框架按这个字段分流：`> 0` 会起后台任务按它调 `login_poll`。
//! 报成 0（回调型）会让界面一直等一个永远不来的回调 —— 而使用设备码时
//! **授权页在用户自己的浏览器里**，没有任何东西会回调到网关。
//!
//! ── 一轮登录的状态放在进程内（为什么不落盘 / 不放账号表）────────
//! 设备码 5 分钟就作废，`code_verifier` 是**一次性秘密**（PKCE 的意义就在于
//! 它不落盘）。所以按 `flow` 存进进程内表即可；插件进程重启 = 用户重新点一次
//! 登录，代价可以忽略。这与 `astudio/login.rs` 的处置一致。
//!
//! ── `slow_down` 的处理 ──────────────────────────────────────
//! 上游要求客户端按 `interval`（实测 3 秒）轮询，快了回 `slow_down`。
//! 本实现固定 3 秒一拍（由网关按我们申报的间隔调），遇到 `slow_down` 当作
//! 「还没好」而不是失败 —— 一次抢跑不该让用户重来。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 本 crate 编译期禁止 unwrap/expect/panic（见 `main.rs` 的 deny）。

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use agent2api_provider_protocol::WireProxy;
use serde_json::{json, Value};

use crate::errors::GatewayError;
use crate::logging;

use super::credentials::{self, MinimaxCredential};
use super::endpoints;
use super::net;
use super::region::Region;

/// 网关按这个间隔调 `login.poll`（实测上游要求 3 秒一拍）。
pub const POLL_INTERVAL_MS: u64 = 3_000;

/// 设备码有效期兜底（上游通常给 `expires_in: 300`）。
const DEFAULT_EXPIRES_IN: i64 = 300;

/// 一轮登录的进程内状态。
struct Entry {
    /// 哪个地区（换令牌 / 落账号都按它走）。同一时刻两地的登录流程可以并存。
    region: Region,
    /// 设备码（换令牌的凭据，**不外传**）。
    device_code: String,
    /// PKCE verifier（一次性秘密，**不落盘、不进日志**）。
    code_verifier: String,
    /// 设备码到期时刻（毫秒）
    expires_at_ms: i64,
    /// 被取消 / 被上游判死 → 后续 `poll` 立刻返回终态，不再碰上游
    spent: Option<String>,
}

/// 一次设备授权的**对外**信息（不含设备码与 verifier）。
#[derive(Clone, Debug)]
pub struct DeviceFlow {
    /// 登录流程 id（网关后续用 `poll` / `cancel` 都带它）
    pub flow: String,
    /// 给用户打开的授权页（含 user_code，**不含 verifier**）
    pub auth_url: String,
    /// 用户在页面上要输入的设备码（界面上照抄给用户看）
    pub user_code: String,
    /// 这个会话属于哪个地区
    pub region: Region,
}

/// 换到的令牌。
///
/// ⚠️ **`Debug` 是手写的、脱敏的**（不 derive）：access / refresh 令牌绝不该
/// 出现在任何日志、panic 消息或 `{:?}` 输出里 —— 而 `#[derive(Debug)]` 恰好会
/// 把它们打出来。这不是危言：`PollOutcome` 需要 `Debug`（测试用
/// `expect_err`），而它包着本结构，derive 会让整条链可打印。
#[derive(Clone)]
pub struct Credentials {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
    pub user_id: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Credentials")
            .field("access_token", &credentials::masked(&self.access_token))
            .field(
                "refresh_token",
                &if self.refresh_token.is_empty() {
                    "(无)".to_string()
                } else {
                    credentials::masked(&self.refresh_token)
                },
            )
            .field("expires_at", &self.expires_at)
            .field("user_id", &self.user_id)
            .finish()
    }
}

/// 轮询结果。
///
/// `Debug` 是给测试用的（`expect_err` 要求 `Ok` 侧可打印）——
/// 它**不含**设备码与 verifier（那两个是凭据级数据，绝不该进日志）。
#[derive(Debug)]
pub enum PollOutcome {
    /// 用户还没授权
    Pending,
    /// 上游要求放慢（同样继续等）
    SlowDown,
    /// 拿到令牌
    Ready(Box<Credentials>),
}

fn flows() -> &'static Mutex<HashMap<String, Entry>> {
    static FLOWS: OnceLock<Mutex<HashMap<String, Entry>>> = OnceLock::new();
    FLOWS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn with_flows<T>(action: impl FnOnce(&mut HashMap<String, Entry>) -> T) -> T {
    match flows().lock() {
        Ok(mut table) => action(&mut table),
        Err(poisoned) => action(&mut poisoned.into_inner()),
    }
}

/// 申请一个设备码并登记这一轮登录。
///
/// `region` 决定问哪台授权服务器（国内 `account.minimax.cn` /
/// 国际 `account.minimax.io`）—— 两地的设备码**互不通用**。
pub async fn start(
    region: Region,
    proxy: Option<&WireProxy>,
    gateway_proxy: &str,
) -> Result<DeviceFlow, GatewayError> {
    let verifier = random_token();
    let challenge = pkce_challenge(&verifier);
    let body = format!(
        "client_id={client}&scope={scope}&audience={audience}\
         &code_challenge={challenge}&code_challenge_method=S256",
        client = endpoints::OAUTH_CLIENT_ID,
        scope = encode_space(endpoints::OAUTH_SCOPE),
        audience = endpoints::OAUTH_AUDIENCE,
        challenge = challenge,
    );
    let url = endpoints::auth_url(region, endpoints::DEVICE_CODE_PATH);
    let payload = post_form(region, &url, &body, "申请设备码", proxy, gateway_proxy).await?;
    let device_code = payload
        .get("device_code")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| GatewayError::with_status(502, "设备码响应里没有 device_code"))?
        .to_string();
    let user_code = payload
        .get("user_code")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    // 优先用 `verification_uri_complete`（带 code，用户点开就填好）；
    // 上游没给时用基础地址 + 手动拼 code
    let auth_url = payload
        .get("verification_uri_complete")
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            let base = payload.get("verification_uri").and_then(Value::as_str)?;
            if user_code.is_empty() {
                Some(base.to_string())
            } else {
                Some(format!("{base}?user_code={user_code}"))
            }
        })
        .ok_or_else(|| GatewayError::with_status(502, "设备码响应里没有授权页地址"))?;
    let expires_in = payload
        .get("expires_in")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_EXPIRES_IN);
    let flow = random_flow_id();
    let expires_at_ms = logging::now_ms() + expires_in * 1000;
    with_flows(|table| {
        table.insert(
            flow.clone(),
            Entry {
                region,
                device_code,
                code_verifier: verifier,
                expires_at_ms,
                spent: None,
            },
        );
    });
    Ok(DeviceFlow {
        flow,
        auth_url,
        user_code,
        region,
    })
}

/// 问一次「用户授权了吗」。
///
/// 未登记的 flow / 已作废 / 已过期都返回终态错误（`Failed`），由调用方决定
/// 「重新发起登录」的文案。
pub async fn poll(
    flow: &str,
    proxy: Option<&WireProxy>,
    gateway_proxy: &str,
) -> Result<PollOutcome, GatewayError> {
    // 每次 poll 都把这一轮的状态取出来（不改动；改动在下面的收尾分支里）
    let (region, device_code, code_verifier, expires_at_ms, spent) = with_flows(|table| {
        table.get(flow).map(|entry| {
            (
                entry.region,
                entry.device_code.clone(),
                entry.code_verifier.clone(),
                entry.expires_at_ms,
                entry.spent.clone(),
            )
        })
    })
    .ok_or_else(|| GatewayError::with_status(400, "这次登录已失效，请重新发起"))?;

    if let Some(reason) = spent {
        return Err(GatewayError::with_status(400, reason));
    }
    if expires_at_ms > 0 && logging::now_ms() >= expires_at_ms {
        mark_spent(flow, "设备码已过期，请重新发起登录");
        return Err(GatewayError::with_status(400, "设备码已过期，请重新发起登录"));
    }

    let body = format!(
        "client_id={client}&grant_type={grant}&device_code={device}&code_verifier={verifier}",
        client = endpoints::OAUTH_CLIENT_ID,
        grant = encode_space(endpoints::DEVICE_CODE_GRANT),
        device = device_code,
        verifier = code_verifier,
    );
    let url = endpoints::auth_url(region, endpoints::TOKEN_PATH);
    let response = match net::request(
        "POST",
        &url,
        None,
        Some(&body),
        &[("Accept".to_string(), "application/json".to_string())],
        proxy,
        gateway_proxy,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            // 网络抖动：**不**把这一轮判死，让后台循环继续等
            // （`code=minimax_transport` 是给调用方判断「继续等」的标记）
            return Err(GatewayError::with_status(502, format!("设备授权轮询不可达：{error}"))
                .with_code("minimax_transport"));
        }
    };
    let payload = response.payload.unwrap_or(Value::Null);

    if response.ok {
        let access_token = payload
            .get("access_token")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| GatewayError::with_status(502, "登录响应里没有 access_token"))?
            .to_string();
        return Ok(PollOutcome::Ready(Box::new(credentials_from(&payload, access_token))));
    }

    let error_name = payload.get("error").and_then(Value::as_str).unwrap_or("");
    match error_name {
        "authorization_pending" => return Ok(PollOutcome::Pending),
        // `slow_down` 是「你问太快了」，不是失败 —— 继续等即可
        "slow_down" => return Ok(PollOutcome::SlowDown),
        _ => {}
    }
    let description = payload
        .get("error_description")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    let message = match error_name {
        "expired_token" => "设备码已过期，请重新发起登录".to_string(),
        "access_denied" => "你在授权页取消了这次登录".to_string(),
        "" => format!("设备授权返回 HTTP {}", response.status),
        other => format!(
            "设备授权失败：{other}{}",
            if description.is_empty() {
                String::new()
            } else {
                format!("（{description}）")
            }
        ),
    };
    let error = GatewayError::with_status(if response.status == 401 { 401 } else { 400 }, message);
    let error = if error_name.is_empty() {
        error
    } else {
        error.with_code(error_name)
    };
    // 上游明确说这枚码不能再用 ⇒ 本地也立刻作废：否则后台循环还会拿它继续打
    // （一拍 3 秒打满 5 分钟），而结果注定是同一个错误。
    if is_terminal_device_error(Some(error_name)) {
        mark_spent(flow, "这次登录已结束，请重新发起");
    }
    Err(error)
}

/// 取消一轮登录：把设备码划掉，后续 `poll` 立刻返回终态、不再碰上游。
///
/// 不撤销上游的 `device_code`（协议里没有 revoke 端点），但必须让本进程
/// **不再用它** —— 否则后台循环会每 3 秒白打一次注定失败的上游请求。
pub fn cancel(flow: &str) {
    mark_spent(flow, "这次登录已取消，请重新发起");
}

/// 把一轮登录标成终态（取消 / 过期 / 被上游判死共用一条路）。
fn mark_spent(flow: &str, reason: &str) {
    with_flows(|table| {
        if let Some(entry) = table.get_mut(flow) {
            entry.spent = Some(reason.to_string());
        }
    });
}

/// 一轮登录彻底结束（拿到账号或失败后由调用方清理）。
pub fn forget(flow: &str) {
    with_flows(|table| {
        table.remove(flow);
    });
}

/// 上游说「这枚设备码不能再用了吗」。
///
/// 只有明确判死的两种才算：`expired_token`（5 分钟到了）、`access_denied`
/// （用户在授权页点了拒绝）。其余（`authorization_pending` / `slow_down` 已在上层
/// 分开处理，`invalid_grant` 之类是协议噪音）一律**不**划掉 —— 误划的后果是
/// 用户明明马上要授权成功，却被我们判成取消。
fn is_terminal_device_error(code: Option<&str>) -> bool {
    matches!(code, Some("expired_token") | Some("access_denied"))
}

/// 用刷新令牌换一对新令牌（**refresh_token 单次有效、每次轮换**）。
///
/// 调用方必须在拿到新令牌后立刻落盘：旧的刷新令牌在应答到达的瞬间就死了，
/// 丢一次就等于账号要用户重新登录。
///
/// `region` 必须是**账号所属地区**：国内账号的刷新令牌拿到 `account.minimax.io`
/// 去换，得到的是一个含义模糊的 `invalid_grant`（令牌不认识，而不是"过期"），
/// 用户会被引向「重新登录」而其实什么都没坏。
pub async fn refresh(
    region: Region,
    refresh_token: &str,
    proxy: Option<&WireProxy>,
    gateway_proxy: &str,
) -> Result<Credentials, GatewayError> {
    if refresh_token.trim().is_empty() {
        return Err(GatewayError::with_status(
            400,
            "没有可用于续期的 refresh token，请重新登录 MiniMax Code",
        ));
    }
    let body = format!(
        "grant_type={grant}&refresh_token={token}&client_id={client}\
         &scope={scope}&audience={audience}",
        grant = endpoints::REFRESH_GRANT,
        token = refresh_token.trim(),
        client = endpoints::OAUTH_CLIENT_ID,
        scope = encode_space(endpoints::OAUTH_SCOPE),
        audience = endpoints::OAUTH_AUDIENCE,
    );
    let url = endpoints::auth_url(region, endpoints::TOKEN_PATH);
    let response = net::request(
        "POST",
        &url,
        None,
        Some(&body),
        &[("Accept".to_string(), "application/json".to_string())],
        proxy,
        gateway_proxy,
    )
    .await
    .map_err(|error| GatewayError::with_status(502, format!("续期请求不可达：{error}")))?;
    let payload = response.payload.unwrap_or(Value::Null);
    if !response.ok {
        let error = payload.get("error").and_then(Value::as_str).unwrap_or("");
        // `invalid_grant` = 刷新令牌本身没了（已被轮换掉 / 被撤销）—— 这是
        // 永久失败，只有重新登录能救；其余（5xx / 网络）按临时失败处理。
        //
        // 文案要说清机制：本家的 refresh token **单次有效、每次轮换**，所以它
        // 最常见的失效原因不是过期，而是**同一个账号在别处续过一次**（另一台
        // 机器、或官方客户端自己）。只写「已失效」会让用户以为是我们的 bug。
        // ⚠️ 纯文本（前端按文本渲染，不解析 Markdown）：别写 `**强调**`。
        if error == "invalid_grant" {
            return Err(GatewayError::with_status(
                401,
                format!(
                    "续期失败：刷新令牌已失效（invalid_grant），请重新登录 MiniMax Code {}。\
                     这通常不是账号问题 —— 本家的刷新令牌单次有效、每次轮换，\
                     同一个账号在别处（官方客户端 / 另一台机器的面板）续过一次，\
                     这里存的那一枚就会被作废，谁先续谁赢",
                    region.label()
                ),
            ));
        }
        return Err(GatewayError::with_status(
            if response.status == 401 { 401 } else { 502 },
            format!(
                "续期失败：上游返回 HTTP {}{}",
                response.status,
                if error.is_empty() {
                    String::new()
                } else {
                    format!("（{error}）")
                }
            ),
        ));
    }
    let access_token = payload
        .get("access_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| GatewayError::with_status(502, "续期响应里没有 access_token"))?
        .to_string();
    Ok(credentials_from(&payload, access_token))
}

/// 从令牌响应造凭证（含 JWT 解析出的 `exp` / `user.id`）。
fn credentials_from(payload: &Value, access_token: String) -> Credentials {
    let refresh_token = payload
        .get("refresh_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let (jwt_expires, jwt_user) = credentials::decode_jwt_claims(&access_token);
    let (jwt_user, stable) = if jwt_user.is_empty() {
        (String::new(), credentials::stable_identity(&access_token))
    } else {
        (jwt_user, String::new())
    };
    let expires_at = payload
        .get("expires_in")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .map(|seconds| logging::now_ms() + seconds * 1000)
        // `expires_in` 缺失时用 JWT 的 `exp`（更权威，实测两者一致）
        .unwrap_or(jwt_expires);
    let user_id = if jwt_user.is_empty() { stable } else { jwt_user };
    Credentials {
        access_token,
        refresh_token,
        expires_at,
        user_id,
    }
}

/// 表单 POST → 解析后的响应体（非 2xx 在这里就报错）。
async fn post_form(
    _region: Region,
    url: &str,
    body: &str,
    what: &str,
    proxy: Option<&WireProxy>,
    gateway_proxy: &str,
) -> Result<Value, GatewayError> {
    let response = net::request(
        "POST",
        url,
        None,
        Some(body),
        &[("Accept".to_string(), "application/json".to_string())],
        proxy,
        gateway_proxy,
    )
    .await
    .map_err(|error| GatewayError::with_status(502, format!("{what}不可达：{error}")))?;
    if !response.ok {
        return Err(GatewayError::with_status(
            if response.status == 401 { 401 } else { 502 },
            format!(
                "{what}失败：HTTP {}{}",
                response.status,
                if response.text.trim().is_empty() {
                    String::new()
                } else {
                    format!("：{}", response.text)
                }
            ),
        ));
    }
    response.payload.ok_or_else(|| {
        GatewayError::with_status(502, format!("{what}的响应不是合法 JSON"))
    })
}

/// 表单值里的空格编码成 `%20`（`scope` 可能多值；`+` 也合法但 `%20` 更稳）。
fn encode_space(value: &str) -> String {
    value.replace(' ', "%20")
}

/// PKCE 的 S256 challenge：`base64url(sha256(verifier))`，无填充。
fn pkce_challenge(verifier: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// 43 字符的 base64url 随机串（RFC 7636 要求 43–128 字符）。
fn random_token() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// 登录流程 id（与 verifier 同一熵源，够长到不可猜）。
fn random_flow_id() -> String {
    format!("minimax-{}", random_token())
}

/// 用系统熵源填随机字节；取不到时退回「时间 + 计数器」的组合。
///
/// 不用 `unwrap` —— 本 crate 编译期禁止；而这里的随机性只用于 PKCE verifier
/// 与本地流程标识，退化路径仍远好于「固定值」。
fn fill_random(buf: &mut [u8]) {
    if getrandom::getrandom(buf).is_ok() {
        return;
    }
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    let tick = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let seed = now ^ tick.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    for (index, slot) in buf.iter_mut().enumerate() {
        *slot = (seed >> ((index % 8) * 8)) as u8 ^ (index as u8).wrapping_mul(31);
    }
}

/// 一次成功登录的令牌 → 凭证快照（供探活 / 立即使用）。
///
/// 只做「字段搬运」：地点（地区）由调用方持有 —— 账号 id 前缀与请求域都从
/// 它取，放不进凭证里（放进去反而多一处可能与账号记录不一致的状态）。
pub fn credential_of(credentials: &Credentials) -> MinimaxCredential {
    MinimaxCredential {
        id: String::new(),
        access_token: credentials.access_token.clone(),
        refresh_token: credentials.refresh_token.clone(),
        expires_at: credentials.expires_at,
        // 身份挖不到时留空（账户请求的 `user_id` 会写 0，签名仍合法）
        user_id: credentials.user_id.clone(),
    }
}

/// 一次成功登录 → 落库账号的 `secret`（键名与 `credentials.rs` 的读取链一致）。
pub fn secret_of(credentials: &Credentials, name: &str) -> Value {
    let mut secret = json!({
        "accessToken": credentials.access_token,
        "name": name,
    });
    if let Some(object) = secret.as_object_mut() {
        if !credentials.refresh_token.trim().is_empty() {
            object.insert(
                "refreshToken".to_string(),
                Value::String(credentials.refresh_token.clone()),
            );
        }
        if credentials.expires_at > 0 {
            object.insert("expiresAt".to_string(), Value::from(credentials.expires_at));
        }
        if !credentials.user_id.trim().is_empty() {
            object.insert(
                "userId".to_string(),
                Value::String(credentials.user_id.clone()),
            );
        }
    }
    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_base64url_sha256() {
        // RFC 7636 附录 B 的示例 verifier
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            pkce_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn random_token_is_long_enough_and_url_safe() {
        let token = random_token();
        // 32 字节 base64url 无填充 = 43 字符（RFC 7636 的下限）
        assert_eq!(token.chars().count(), 43);
        assert!(
            token
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'),
            "必须只用 base64url 字符集：{token}"
        );
        assert_ne!(token, random_token(), "两次生成必须不同");
    }

    #[test]
    fn credentials_prefer_expires_in_and_fall_back_to_jwt() {
        // 只给 expires_in
        let payload = json!({"access_token": "mmoat_opaque1234567890", "refresh_token": "mmort_x", "expires_in": 3600});
        let credentials = credentials_from(&payload, "mmoat_opaque1234567890".into());
        assert!(credentials.expires_at > logging::now_ms());
        assert_eq!(credentials.refresh_token, "mmort_x");
        assert!(credentials.user_id.is_empty(), "不透明令牌解析不出 user.id");
    }

    #[test]
    fn credentials_read_jwt_claims_when_expires_in_is_absent() {
        let payload_jwt = "eyJleHAiOjE3MDAwMDAwMDAsInVzZXIiOnsiaWQiOiJ1NDIifX0";
        let token = format!("header.{payload_jwt}.sig");
        let credentials = credentials_from(&json!({"refresh_token": "mmort_y"}), token.clone());
        assert_eq!(credentials.access_token, token);
        assert_eq!(credentials.expires_at, 1_700_000_000_000);
        assert_eq!(credentials.user_id, "u42");
    }

    /// 网络类失败要带 `minimax_transport` 标记（调用方据此「继续等」而不是
    /// 「登录失败」），且**不**把这一轮判死。
    #[test]
    fn transport_failures_are_marked_as_retryable() {
        let error = GatewayError::with_status(502, "轮询不可达").with_code("minimax_transport");
        assert_eq!(error.code.as_deref(), Some("minimax_transport"));
    }

    /// 判据本身：只有上游明确判死的那两种错误才允许划掉码。
    ///
    /// 误划的代价是「用户马上要授权成功，却被我们判成取消」—— 所以白名单式判断，
    /// 协议噪音（`invalid_grant` / 空串）一律不划。
    #[test]
    fn only_terminal_device_errors_are_treated_as_dead() {
        assert!(is_terminal_device_error(Some("expired_token")));
        assert!(is_terminal_device_error(Some("access_denied")));
        assert!(!is_terminal_device_error(Some("authorization_pending")));
        assert!(!is_terminal_device_error(Some("slow_down")));
        assert!(!is_terminal_device_error(Some("invalid_grant")));
        assert!(!is_terminal_device_error(None));
    }

    /// 空刷新令牌不该白打一次上游（那条早退分支根本不 await 网络）。
    #[test]
    fn refresh_without_token_fails_locally() {
        let error = futures_block(refresh(Region::Cn, "  ", None, "direct"))
            .expect_err("空刷新令牌应被拒");
        assert!(error.to_string().contains("refresh token"), "实际：{error}");
    }

    /// 两个地区的授权服务器必须**不同主机**，且国际版不是 `.cn` 的兄弟域。
    #[test]
    fn each_region_asks_its_own_auth_host() {
        let cn = endpoints::auth_url(Region::Cn, endpoints::DEVICE_CODE_PATH);
        let intl = endpoints::auth_url(Region::Intl, endpoints::DEVICE_CODE_PATH);
        assert_eq!(cn, "https://account.minimax.cn/oauth2/device/code");
        assert_eq!(intl, "https://account.minimax.io/oauth2/device/code");
        assert!(!intl.contains("minimax.cn"), "国际版不能打到国内授权服务器");
        // 换令牌 / 续期同域：地区参数是唯一的开关
        assert!(endpoints::auth_url(Region::Intl, endpoints::TOKEN_PATH)
            .starts_with("https://account.minimax.io/"));
    }

    /// 登录流程表：未登记的 flow 必须给可读错误（而不是 panic 或静默 Pending）。
    #[test]
    fn an_unknown_flow_fails_locally() {
        let error = futures_block(poll("no-such-flow", None, "direct")).expect_err("应被拒");
        assert!(error.to_string().contains("已失效"), "实际：{error}");
    }

    /// 取消后不再打上游：`poll` 必须在**发起请求之前**就返回终态。
    ///
    /// 这条用例不联网：手工登记一轮（到期时刻设成「还很久」），
    /// 唯一能让 `poll` 提前返回的就是「已作废」那一支。
    #[test]
    fn a_canceled_flow_fails_before_any_network_call() {
        let flow = "minimax-test-canceled";
        with_flows(|table| {
            table.insert(
                flow.to_string(),
                Entry {
                    region: Region::Cn,
                    device_code: "device-code-for-cancel-test".to_string(),
                    code_verifier: random_token(),
                    // 远未到期：排除「过期」那一支，确保命中的是「已作废」
                    expires_at_ms: logging::now_ms() + 600_000,
                    spent: None,
                },
            );
        });
        cancel(flow);
        let error = futures_block(poll(flow, None, "direct")).expect_err("已作废的流程不该打上游");
        assert!(
            error.to_string().contains("已取消"),
            "文案要点明是取消（不是过期 / 上游报错），实际：{error}"
        );
        forget(flow);
    }

    /// 登录落库的 secret 键名必须与 `credentials.rs` 的读取链对上 ——
    /// 对不上的症状是「登录成功了，但账号立刻报凭证不完整」。
    #[test]
    fn the_login_secret_round_trips_through_the_credential_reader() {
        let credentials = Credentials {
            access_token: "mmoat_login1234567890".into(),
            refresh_token: "mmort_login".into(),
            expires_at: 1_700_000_000_000,
            user_id: "u77".into(),
        };
        let secret = secret_of(&credentials, "我的账号");
        let parsed = credentials::from_record(Some(&secret)).expect("必须能被凭证读取链解析");
        assert_eq!(parsed.access_token, "mmoat_login1234567890");
        assert_eq!(parsed.refresh_token, "mmort_login");
        assert_eq!(parsed.expires_at, 1_700_000_000_000);
        assert_eq!(parsed.user_id, "u77");
        // 备注名也在（账号页显示它）
        assert_eq!(secret["name"], json!("我的账号"));
    }

    /// 没有刷新令牌时不该往 secret 里塞空键（空键会让「能否续期」判成 true）。
    #[test]
    fn a_token_without_refresh_does_not_write_an_empty_key() {
        let credentials = Credentials {
            access_token: "mmoat_only1234567890".into(),
            refresh_token: String::new(),
            expires_at: 0,
            user_id: String::new(),
        };
        let secret = secret_of(&credentials, "仅访问令牌");
        assert!(secret.get("refreshToken").is_none());
        assert!(secret.get("expiresAt").is_none());
        assert!(secret.get("userId").is_none());
        // 读取链仍能解析出这条记录（只是不能续期）
        let parsed = credentials::from_record(Some(&secret)).expect("应能解析");
        assert!(!parsed.can_refresh());
    }

    /// 极小的「跑一个立即 ready 的 future」助手 —— 只为让上面那几条同步断言
    /// 不必引 `#[tokio::test]`（那些路径根本不 await 网络）。
    fn futures_block<F: std::future::Future>(future: F) -> F::Output {
        use std::task::{Context, Poll, Wake, Waker};
        struct Noop;
        impl Wake for Noop {
            fn wake(self: std::sync::Arc<Self>) {}
        }
        let waker = Waker::from(std::sync::Arc::new(Noop));
        let mut context = Context::from_waker(&waker);
        let mut pinned = std::pin::pin!(future);
        match pinned.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("该分支不应等待网络"),
        }
    }
}
