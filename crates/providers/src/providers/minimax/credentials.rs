//! MiniMax Code 的凭证形态：**OAuth `mmoat_` 令牌 + 刷新令牌**。
//!
//! ── 一份令牌打通三件事（实测 2026-10-21）────────────────────────
//! `mmoat_` 令牌既能打模型网关（`/mavis/api/v1/llm/v1/messages`），也能打账户
//! 接口（积分 / 签到）。所以「登录一次」就覆盖支持矩阵的前五列，不需要像
//! Marvis 那样再补设备指纹。
//!
//! ── 为什么不读客户端凭据文件（重要，别「顺手」加上）──────────────
//! 客户端把令牌存在 `~/.minimax/auth/prod/cn/mcode-public/auth.json`，
//! 看起来像白送的导入源。但同一目录下还有一个 `auth-state.json`，**两个文件各带
//! 一个 `generation` 计数器，客户端要求两者相等**，否则判定「这个账号在别处登录
//! 过」并要求用户重登（`MCodeOAuthCore.readUsableCredential`）。
//! 我们只要写一次令牌就会打乱它的代际，代价是让用户的桌面客户端被迫重新扫码 ——
//! 所以本家**只自己登录、只写自己的账号库**。
//!
//! ⚠️ **容器部署**：容器里根本读不到 Windows 宿主上的 `~/.minimax/`，所以「导入
//! 本机登录态」这类入口对本包**不提供**（`normalize_account` 对 `Desktop` 明确
//! 回绝并指路「用浏览器登录」）。这条限制同时也绕开了上面那个代际破坏问题。
//!
//! ── 凭证字段 ────────────────────────────────────────────────
//! ```text
//!   accessToken   mmoat_ 访问令牌（转发 / 余额 / 签到都用它）
//!   refreshToken  mmort_ 刷新令牌（单次有效，每次续期都轮换）
//!   expiresAt     访问令牌到期时刻（毫秒，0 = 未知）
//!   userId        JWT 里的 user.id（登录身份；账号 id 由它派生）
//! ```
//!
//! ── 搬进插件时改了什么 ──────────────────────────────────────
//! ```text
//!   不变：字段名与兼容读取链、validate_shape 的三条判据、masked 的脱敏形态、
//!         decode_jwt_claims、stable_identity 的判定顺序（JWT → 前缀尾段）
//!   改：  错误类型从网关 GatewayError 换成插件的同形类型；base64 走
//!         `base64::engine::general_purpose::URL_SAFE_NO_PAD`（仓库已依赖）
//! ```
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 本 crate 编译期禁止 unwrap/expect/panic（见 `main.rs` 的 deny）。

use serde_json::Value;

use crate::errors::GatewayError;

/// 访问令牌前缀（OAuth access token）。
pub const TOKEN_PREFIX: &str = "mmoat_";

/// 刷新令牌前缀（OAuth refresh token）。
pub const REFRESH_PREFIX: &str = "mmort_";

/// 续期窗口：距到期不足这么久就报「临期」（秒）。
///
/// 60 秒足够覆盖一次请求的往返；比它更长的窗口会让「刚续过的账号」在维护
/// 任务里被反复判定为临期（上游有效期 3600 秒，取 60 不影响判据）。
pub const EXPIRY_WINDOW_MS: i64 = 60_000;

/// 日志 / 界面用的脱敏形态（前 8 后 4 —— 前缀本身有信息量，多留两位）。
pub fn masked(token: &str) -> String {
    let count = token.chars().count();
    if count <= 14 {
        return "*".repeat(count);
    }
    let head: String = token.chars().take(8).collect();
    let tail: String = token.chars().skip(count - 4).collect();
    format!("{head}…{tail}")
}

/// 从账号记录取值：优先 `keys` 里的名字，取第一个非空字符串。
fn pick(record: &Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(value) = record.get(*key).and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    String::new()
}

/// 一次转发 / 余额 / 签到用的凭证快照。
///
/// ⚠️ **`Debug` 是手写的、脱敏的**（不 derive）：两个令牌绝不该出现在日志、
/// panic 消息或 `{:?}` 输出里。这个结构会被单飞表（`flight::Table<T>`）与
/// 若干 `Result` 包着，derive 会让它们全变可打印 —— 脱敏一次就够。
#[derive(Clone, Default)]
pub struct MinimaxCredential {
    /// 账号记录 id（错误归因与冷却键用）
    pub id: String,
    /// `mmoat_` 访问令牌
    pub access_token: String,
    /// `mmort_` 刷新令牌（可能为空 —— 老记录 / 手工粘贴可能只给了访问令牌）
    pub refresh_token: String,
    /// 访问令牌到期时刻（毫秒，0 = 未知）
    pub expires_at: i64,
    /// 登录身份（JWT 的 `user.id`）；空时账户请求的 `user_id` 参数写 0
    pub user_id: String,
}

impl std::fmt::Debug for MinimaxCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MinimaxCredential")
            .field("id", &self.id)
            .field("access_token", &masked(&self.access_token))
            .field(
                "refresh_token",
                &if self.refresh_token.is_empty() {
                    "(无)".to_string()
                } else {
                    masked(&self.refresh_token)
                },
            )
            .field("expires_at", &self.expires_at)
            .field("user_id", &self.user_id)
            .finish()
    }
}

impl MinimaxCredential {
    /// 是否有可用于续期的刷新令牌。
    pub fn can_refresh(&self) -> bool {
        !self.refresh_token.is_empty()
    }

    /// 是否具备转发所需的最小凭证集合（只有访问令牌是硬要求）。
    pub fn is_complete(&self) -> bool {
        !self.access_token.is_empty()
    }

    /// 令牌是否已过期或临期（`now_ms` 由调用方给，便于单测注入）。
    ///
    /// 到期时刻未知（0）时返回 `false` —— **宁可漏刷，也不要凭猜测打上游**
    /// （与 `Provider::token_expiring` 的默认口径一致）。
    pub fn expiring_at(&self, now_ms: i64) -> bool {
        self.expires_at > 0 && now_ms + EXPIRY_WINDOW_MS >= self.expires_at
    }

    /// 已经过期（不是临期）。续期链用它区分「还能再撑一会儿」与「必须刷新」。
    pub fn expired_at(&self, now_ms: i64) -> bool {
        self.expires_at > 0 && now_ms >= self.expires_at
    }
}

/// 从账号记录（插件 `store::record` 拼出的形态）还原凭证快照。
///
/// 兼容两种形态：
///   1. 平铺在记录上（`accessToken` / `refreshToken` / `expiresAt` / `userId`）；
///   2. 包在 `auth` 里（`{"auth": {"accessToken": …}}`）—— 旧记录 / 导入形态。
pub fn from_record(record: Option<&Value>) -> Result<MinimaxCredential, GatewayError> {
    let Some(record) = record else {
        return Err(GatewayError::with_status(400, "缺少 MiniMax Code 账号凭证"));
    };
    let auth = record.get("auth");
    let read = |keys: &[&str]| -> String {
        let flat = pick(record, keys);
        if !flat.is_empty() {
            return flat;
        }
        match auth {
            Some(auth) => pick(auth, keys),
            None => String::new(),
        }
    };

    let expires_at = record
        .get("expiresAt")
        .or_else(|| record.get("expires_at"))
        .and_then(Value::as_i64)
        .or_else(|| auth.and_then(|auth| auth.get("expiresAt").and_then(Value::as_i64)))
        .filter(|value| *value > 0)
        .unwrap_or(0);

    let credential = MinimaxCredential {
        id: read(&["id", "accountId"]),
        access_token: read(&["accessToken", "access_token", "token"]),
        refresh_token: read(&["refreshToken", "refresh_token"]),
        expires_at,
        user_id: read(&["userId", "user_id", "uid"]),
    };
    if !credential.is_complete() {
        return Err(GatewayError::with_status(
            400,
            "MiniMax Code 凭证不完整：需要在账号里配置 accessToken（mmoat_ 开头的访问令牌）",
        ));
    }
    Ok(credential)
}

/// 添加账号时的形状校验（不联网）。
///
/// **不强制 `mmoat_` 前缀**：客户端老版本 / 手工粘贴的令牌可能不带前缀，
/// 而前缀只是「这是 OAuth 令牌」的提示，不是上游的校验项（实测带前缀的假令牌
/// 与不带的假令牌都回 `invalid access token`，说明上游看的是内容不是前缀）。
/// 因此这里只拦「明显粘错」的形态：长度过短、或像是把整段 JSON 粘进来了。
pub fn validate_shape(record: &Value) -> Result<(), GatewayError> {
    let credential = from_record(Some(record))?;
    let token = credential.access_token.as_str();
    if token.chars().count() < 16 {
        return Err(GatewayError::with_status(
            400,
            "MiniMax Code 访问令牌看起来不完整（长度异常短），请重新登录后再试",
        ));
    }
    if token.contains('{') || token.contains('"') {
        return Err(GatewayError::with_status(
            400,
            "这像是整段 JSON 而不是访问令牌 —— MiniMax Code 只需要其中的 accessToken 值",
        ));
    }
    Ok(())
}

/// 从 JWT 里解出 `exp`（秒 → 毫秒）与 `user.id`。
///
/// 客户端的访问令牌是 JWT（HS256）。**只读不验签**：签名的作用是防篡改，
/// 而这份令牌我们只会原样还给签发方；读它的 `exp` 只是为了让账号页能显示
/// 「还有多久过期」，读 `user.id` 只是为了派生稳定的账号 id。
///
/// 返回 `(exp_ms, user_id)`；不是 JWT 或解析失败返回 `(0, "")`。
pub fn decode_jwt_claims(token: &str) -> (i64, String) {
    let Some(payload) = jwt_payload(token) else {
        return (0, String::new());
    };
    let expires = payload
        .get("exp")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .map(|seconds| seconds.saturating_mul(1000))
        .unwrap_or(0);
    let user_id = payload
        .pointer("/user/id")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    (expires, user_id)
}

/// 从 JWT 里尽量挖出一个**稳定**的身份标识（账号 id 的派生键）。
///
/// ── 为什么 `decode_jwt_claims` 不够（2026-10-22 实测）────────────
/// 线上令牌是 `mmoat_` 前缀的**不透明串**（实测长度 60，`mmoat_` 之后没有
/// `.`），完整 JWT 只在开发/旧版本里出现。于是 `decode_jwt_claims` 恒返回
/// `(0, "")` ⇒ 账号 id 退回 `sha256(accessToken)` ⇒ 令牌每小时轮换、或重新登录
/// 换一枚，就**算出另一个 id**，同一个人被存成两条账号（用户看到两个自己，
/// 旧的那条再也刷不动）。这正是「重新添加同一个账号会被识别成不同账号」。
///
/// 所以先按 JWT 找 `user.id` / `uid` / `user_id`，再按 `token-` / `user-`
/// 前缀（部分上游签发形态）剥出尾段。
///
/// 返回**不带地区**的裸身份（调用方拼地区前缀）；挖不到时返回空串，
/// 由调用方决定兜底。
///
/// ⚠️ 裸令牌本体**绝不能**当返回值：那是凭据，会进账号 id 与日志。
pub fn stable_identity(token: &str) -> String {
    let token = token.trim();
    if token.is_empty() {
        return String::new();
    }
    if let Some(identity) = jwt_identity(token) {
        return identity;
    }
    for prefix in ["token-", "user-"] {
        if let Some(tail) = token.strip_prefix(prefix) {
            let tail = tail.trim();
            // 太短的尾段没有区分度，宁可不用（不能拿它去唯一化账号）
            // 「有区分度」的下限取 4：真实形态是 `token-880281` 这种纯数字尾段，
            // 一旦要求 8 位就会把整档跳过。
            if tail.chars().count() >= 4 && !tail.contains('.') {
                return format!("{prefix}{tail}");
            }
        }
    }
    String::new()
}

/// JWT 里的身份：依次看 `user.id` / `uid` / `user_id`，最后才看 `sub`。
///
/// 「依次」是刻意的：本家真实令牌的 `user.id` 才是登录身份，`sub` 在
/// 客户端授权里是 client 标识（拿它当 id 会把同一个人所有会话并成一条，
/// 或者把不同的人并成一条 —— 两种都错）。所以只有前面全空时才用 `sub`。
fn jwt_identity(token: &str) -> Option<String> {
    let payload = jwt_payload(token)?;
    for pointer in ["/user/id", "/uid", "/user_id"] {
        if let Some(identity) = payload
            .pointer(pointer)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Some(identity.to_string());
        }
    }
    // 数量型身份（`uid: 12345`）也照收：上游两种都发过
    for pointer in ["/user/id", "/uid", "/user_id"] {
        if let Some(number) = payload.pointer(pointer).and_then(Value::as_i64) {
            return Some(number.to_string());
        }
    }
    payload
        .get("sub")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// JWT 的 payload 段解成 JSON（三段式且中段是合法 base64url + JSON 才给）。
fn jwt_payload(token: &str) -> Option<Value> {
    let mut parts = token.split('.');
    let (Some(_header), Some(payload), Some(_signature)) = (parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let bytes = base64_url_decode(payload).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    serde_json::from_str::<Value>(&text).ok()
}

/// base64url（无填充）解码 —— JWT 段的标准编码。
fn base64_url_decode(text: &str) -> Result<Vec<u8>, ()> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    // 有些签发方带填充，先去干净
    let trimmed = text.trim_end_matches('=');
    URL_SAFE_NO_PAD.decode(trimmed).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_flat_record() {
        let record = json!({
            "accessToken": "mmoat_abc1234567890",
            "refreshToken": "mmort_def",
            "expiresAt": 1_700_000_000_000i64,
            "userId": "u1"
        });
        let credential = from_record(Some(&record)).expect("应能解析");
        assert_eq!(credential.access_token, "mmoat_abc1234567890");
        assert_eq!(credential.refresh_token, "mmort_def");
        assert_eq!(credential.expires_at, 1_700_000_000_000);
        assert!(credential.can_refresh());
    }

    #[test]
    fn reads_nested_auth() {
        let record = json!({
            "id": "minimax-1",
            "auth": {"accessToken": "mmoat_xyz1234567890", "expiresAt": 5}
        });
        let credential = from_record(Some(&record)).expect("应能解析");
        assert_eq!(credential.id, "minimax-1");
        assert_eq!(credential.access_token, "mmoat_xyz1234567890");
        assert_eq!(credential.expires_at, 5);
        assert!(!credential.can_refresh(), "没给刷新令牌就是不能续期");
    }

    /// **回归护栏**：只有刷新令牌、没有访问令牌时必须在本地就报错，
    /// 而不是拼一个空 `Authorization: Bearer ` 去打上游（那会得到一句
    /// 含义不明的 401，用户看不出该做什么）。
    #[test]
    fn missing_access_token_is_rejected_locally() {
        let record = json!({"refreshToken": "mmort_def"});
        let error = from_record(Some(&record)).expect_err("应被拒");
        assert!(
            error.to_string().contains("accessToken"),
            "错误文案要点名缺 accessToken，实际：{error}"
        );
    }

    /// 没有任何记录时也要给可读错误，而不是 panic。
    #[test]
    fn absent_record_is_rejected_locally() {
        let error = from_record(None).expect_err("应被拒");
        assert!(error.to_string().contains("凭证"), "实际：{error}");
    }

    #[test]
    fn shape_validation_rejects_pasted_json() {
        let record = json!({"accessToken": "{\"accessToken\":\"mmoat_xxxxxxxxxxxx\"}"});
        assert!(validate_shape(&record).is_err());
    }

    #[test]
    fn shape_validation_rejects_short_tokens() {
        let record = json!({"accessToken": "short"});
        assert!(validate_shape(&record).is_err());
    }

    #[test]
    fn shape_validation_accepts_a_plain_long_token() {
        // 不强制 `mmoat_` 前缀（见函数文档）
        let record = json!({"accessToken": "abcdefghijklmnopqrstuvwxyz012345"});
        assert!(validate_shape(&record).is_ok());
    }

    #[test]
    fn masked_keeps_prefix_and_tail() {
        let shown = masked("mmoat_abcdefghijklmnop");
        assert!(shown.starts_with("mmoat_ab"));
        assert!(shown.ends_with("mnop"));
        assert!(shown.contains('…'));
        // 过短的令牌整串打码（不能泄漏长度以外的信息）
        assert_eq!(masked("short"), "*****");
    }

    /// **凭据不该被 `{:?}` 打出来**：`Debug` 必须是脱敏的。
    ///
    /// 这条钉的是「有人把 `#[derive(Debug)]` 加回来」——那会让 access /
    /// refresh 令牌进日志、进 panic 消息，而这类泄漏是事后无法收回的。
    #[test]
    fn the_debug_form_does_not_leak_tokens() {
        let credential = MinimaxCredential {
            id: "minimax-1".into(),
            access_token: "mmoat_secret1234567890".into(),
            refresh_token: "mmort_secret1234567890".into(),
            expires_at: 1_700_000_000_000,
            user_id: "u1".into(),
        };
        let printed = format!("{credential:?}");
        assert!(!printed.contains("mmoat_secret"), "Debug 泄漏了访问令牌：{printed}");
        assert!(!printed.contains("mmort_secret"), "Debug 泄漏了刷新令牌：{printed}");
        // 脱敏后的形态仍要能帮排障（前缀 + 尾段）
        assert!(printed.contains('…'), "应当保留脱敏形态：{printed}");
        // 非凭据字段照常显示
        assert!(printed.contains("minimax-1"));
        assert!(printed.contains("u1"));
    }

    #[test]
    fn jwt_claims_are_read_without_verification() {
        // {"exp":1700000000,"user":{"id":"u42"}} 的 base64url
        let payload = "eyJleHAiOjE3MDAwMDAwMDAsInVzZXIiOnsiaWQiOiJ1NDIifX0";
        let token = format!("header.{payload}.sig");
        let (expires, user_id) = decode_jwt_claims(&token);
        assert_eq!(expires, 1_700_000_000_000);
        assert_eq!(user_id, "u42");
    }

    #[test]
    fn non_jwt_token_yields_no_claims() {
        assert_eq!(decode_jwt_claims("mmoat_opaque"), (0, String::new()));
        assert_eq!(decode_jwt_claims("a.b"), (0, String::new()));
        assert_eq!(decode_jwt_claims("a.!!!.c"), (0, String::new()));
    }

    /// **回归护栏**：不透明 `mmoat_` 令牌（线上真实形态）挖不到稳定
    /// 身份时，`stable_identity` 必须返回空串 —— 由上层退回令牌哈希。
    ///
    /// 这条钉的是「别自作聪明把令牌本体当身份」：那会让账号 id 里带上凭据。
    #[test]
    fn opaque_token_has_no_stable_identity() {
        let opaque = "mmoat_pmqO3U8yZk1sVb7Qx2Ld4Rt6Nc8Wh0Ej3Fu5Gi7Hk9Lm";
        assert_eq!(stable_identity(opaque), "");
        // 裸令牌本体绝不能出现在返回值里（防「顺手」把 token 当身份）
        assert!(!stable_identity(opaque).contains("mmoat_"));
    }

    /// JWT 的三种身份写法都要认，且 `user.id` 优先于 `sub`。
    #[test]
    fn stable_identity_reads_jwt_claims() {
        // {"user":{"id":"u42"}}：只有 user.id
        let payload = "eyJ1c2VyIjp7ImlkIjoidTQyIn19";
        assert_eq!(stable_identity(&format!("h.{payload}.s")), "u42");
        // 同时有 sub 时 user.id 优先（sub 是 client 标识，拿它会把不同人并成一条）
        let payload = "eyJzdWIiOiJtY29kZS1wdWJsaWMiLCJ1c2VyIjp7ImlkIjoidTQyIn19";
        assert_eq!(stable_identity(&format!("h.{payload}.s")), "u42");
        // 数量型 uid
        let payload = "eyJ1aWQiOjEyMzQ1fQ";
        assert_eq!(stable_identity(&format!("h.{payload}.s")), "12345");
    }

    /// `token-` / `user-` 前缀形态要剥出尾段（这才是「同一身份换令牌仍稳定」）
    #[test]
    fn stable_identity_uses_prefixed_tail() {
        assert_eq!(stable_identity("token-880281"), "token-880281");
        assert_eq!(stable_identity("user-545178"), "user-545178");
        // 尾段太短没有区分度：宁可不用（交给上层退回令牌哈希）
        assert_eq!(stable_identity("token-12"), "");
        assert_eq!(stable_identity("token-abc"), "");
    }

    /// 临期 / 过期判据：未知到期时刻一律「不临期」（宁可漏刷，不凭猜测打上游）。
    #[test]
    fn expiry_needs_a_known_deadline() {
        let unknown = MinimaxCredential {
            access_token: "mmoat_x1234567890".into(),
            expires_at: 0,
            ..Default::default()
        };
        assert!(!unknown.expiring_at(1_700_000_000_000));
        assert!(!unknown.expired_at(1_700_000_000_000));

        let soon = MinimaxCredential {
            access_token: "mmoat_x1234567890".into(),
            expires_at: 1_700_000_030_000,
            ..Default::default()
        };
        // 到期前 30 秒 → 临期（窗口 60 秒）
        assert!(soon.expiring_at(1_700_000_000_000));
        // 但还没真过期
        assert!(!soon.expired_at(1_700_000_000_000));
        // 过了到期时刻 → 已过期
        assert!(soon.expired_at(1_700_000_100_000));
    }
}
