//! MiniMax Code 的账号面：公开视图、稳定身份、规范化（手填 / 文件接入）。
//!
//! ── 公开视图的键名是**契约**（改错了界面就是一片空白）────────────
//! 网关把 `normalize_account` 产出的 `public` 原样透给前端，前端按固定键名读：
//! ```text
//!   name          账号主名（未设备注时用）
//!   uid           账号标识列（AccountFeatures.identifier）
//!   tokenTail     令牌尾号（脱敏展示）
//!   expiresAt     有效期列（AccountFeatures.expiry）
//!   hasSession    「有可用登录态」徽章
//!   canRefresh    「能自动续期」徽章
//!   edition       地区徽章（AccountFeatures.edition）
//! ```
//! ⚠️ `edition` 同时是网关**反查账号记录**的字段之一
//! （`plugin_identity::MIRRORED_IDENTITY_KEYS` 把它镜像到记录顶层；缺了它
//! 国际版账号会被当成国内版反查，即使补了 uid 也匹配不上）。
//! 所以它必须写成稳定的 `cn` / `intl`，而不是用户随手填的 `international`。
//!
//! ── 稳定身份（去重键）──────────────────────────────────────
//! 访问令牌**每小时轮换**，拿它当身份会让同一个人每小时多出一条账号。
//! 身份按强度递减取：
//!   1. `userId`（已在记录里，或 JWT 里挖出来的）；
//!   2. `credentials::stable_identity` 挖出的稳定身份；
//!   3. 都挖不到 → **空串**（网关退回按凭证去重，可能产生重复记录）。
//!
//! ⚠️ 返回的**不带地区前缀**：网关的 `plugin_identity` 会按 provider 作用域
//! 隔离主键（`{provider}-account-{hash(provider, …, identity)}`），两个地区
//! 天然是两个命名空间。这里再加地区前缀反而会让「同一个人在两地」的身份
//! 看起来不同（那对网关没有意义 —— 它本来就按 provider 分开存）。
//!
//! ── 为什么 `Desktop` 来源回绝（**容器部署的硬限制**）─────────────
//! 客户端的登录态在 `~/.minimax/auth/prod/<region>/mcode-public/auth.json`，
//! 而：
//!   1. **容器里读不到**（那是 Windows 宿主上的路径，没有挂载约定）；
//!   2. 就算读得到，同目录的 `auth-state.json` 带一个 `generation` 计数器，
//!      **两个文件必须相等**，否则客户端判定「这个账号在别处登录过」并要求
//!      用户重新扫码。我们写一次就破坏它的代际 —— 代价是用户的桌面客户端
//!      被迫重登。
//! 所以本包**不提供**「导入本机登录态」，明确回绝并指路「用浏览器登录」。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 本 crate 编译期禁止 unwrap/expect/panic（见 `main.rs` 的 deny）。

use agent2api_provider_protocol as proto;
use serde_json::{json, Value};

use crate::errors::GatewayError;

use super::credentials;
use super::region::Region;

/// 备注名长度上限（与别家同一口径）。
const MAX_NAME_LENGTH: usize = 100;

/// 输入长度上限（超过这个长度的输入一定是粘错了东西）。
const MAX_INPUT_LENGTH: usize = 16_384;

/// 从载荷里取一个非空字符串（多候选键）。
fn pick(payload: &Value, keys: &[&str]) -> String {
    for key in keys {
        let value = payload
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");
        if !value.is_empty() {
            return value.to_string();
        }
    }
    String::new()
}

/// 按字符数截断（不按字节 —— 中文备注名按字节截会切出半个字）。
fn truncate_chars(text: &str, max: usize) -> String {
    let count = text.chars().count();
    if count <= max {
        return text.to_string();
    }
    text.chars().take(max).collect()
}

/// 令牌尾 4 字符。
fn token_tail(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    let start = chars.len().saturating_sub(4);
    chars[start..].iter().collect()
}

/// 账号的公开视图（键名见模块头）。
pub fn public(region: Region, secret: &Value) -> Value {
    let credential = credentials::from_record(Some(secret)).ok();
    let access_token = credential
        .as_ref()
        .map(|credential| credential.access_token.clone())
        .unwrap_or_default();
    let user_id = credential
        .as_ref()
        .map(|credential| credential.user_id.clone())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| credentials::stable_identity(&access_token));
    let refresh = credential
        .as_ref()
        .map(|credential| credential.refresh_token.clone())
        .unwrap_or_default();

    let name = {
        let explicit = pick(secret, &["name"]);
        if !explicit.is_empty() {
            explicit
        } else if !user_id.is_empty() {
            format!("MiniMax Code {} {user_id}", region.label())
        } else {
            format!("MiniMax Code {}", region.label())
        }
    };

    let mut view = json!({
        "name": name,
        "uid": user_id.clone(),
        // 地区徽章：**必须是稳定 id**（cn / intl），网关会把它镜像到记录顶层
        // 并据此反查账号记录（缺了它国际版会被当国内版找）
        "edition": region.edition_id(),
        "tokenTail": token_tail(&access_token),
        "hasSession": credential.is_some(),
        "canRefresh": !refresh.trim().is_empty(),
    });
    if let Some(object) = view.as_object_mut() {
        let expires_at = credential
            .as_ref()
            .map(|credential| credential.expires_at)
            .unwrap_or(0);
        if expires_at > 0 {
            object.insert("expiresAt".to_string(), Value::from(expires_at));
        }
        // 昵称 / 邮箱 / 头像：有就带上（界面在这些列上显示它们）
        for key in ["nickname", "email", "avatarUrl", "avatar"] {
            let value = pick(secret, &[key]);
            if !value.is_empty() {
                object.insert(key.to_string(), Value::String(value));
            }
        }
    }
    view
}

/// 账号的**稳定身份**（去重键，见模块头）。
pub fn identity(secret: &Value) -> String {
    // ① 记录里已经存的身份（登录时探活顺带取到的，最权威）
    let explicit = pick(secret, &["userId", "user_id", "uid"]);
    if !explicit.is_empty() {
        return format!("user-{explicit}");
    }
    // ② 从令牌里挖（JWT 的 user.id / uid / 前缀尾段）
    let token = pick(secret, &["accessToken", "access_token", "token"]);
    let stable = credentials::stable_identity(&token);
    if !stable.is_empty() {
        return stable;
    }
    // ③ 挖不到 → 空串（网关退回按凭证去重）。
    //
    // 为什么不退回 `sha256(令牌)`：令牌每小时轮换 ⇒ 同一个人每小时多一条账号，
    // 而用户看到的是「两个自己、旧的那个刷不动」。空串让网关按凭证内容去重，
    // 至少重复添加**同一个令牌**时不会新增；而线上 `mmoat_` 是不透明串，
    // 本地没有任何办法从它推出稳定身份 —— 那种情况下如实说明「可能产生重复」，
    // 好过制造一条注定漂移的 id。补法在探活那条路上（把 userId 带回记录）。
    String::new()
}

/// 把一次登录 / 粘贴的载荷变成一条可落库的账号。
///
/// `name_hint` 是用户在界面上指定的备注名（`None` = 我们取名）。
pub fn normalize_account(
    region: Region,
    input: proto::NormalizeInput,
) -> Result<proto::NormalizedAccount, GatewayError> {
    match input.source {
        proto::NormalizeSource::Manual { payload } => from_payload(region, &payload, input.name),
        proto::NormalizeSource::FileText { content, .. } => {
            if content.chars().count() > MAX_INPUT_LENGTH {
                return Err(GatewayError::with_status(400, "凭证内容过长，请确认选对了文件"));
            }
            // 文本文件可能是「一整份 JSON」或「裸令牌一行」
            let trimmed = content.trim();
            let parsed: Value = serde_json::from_str(trimmed).unwrap_or_else(|_| json!(trimmed));
            from_payload(region, &parsed, input.name)
        }
        proto::NormalizeSource::FileBase64 { .. } => Err(GatewayError::with_status(
            400,
            "MiniMax Code 的凭证是文本令牌，不支持二进制文件；请粘贴 accessToken 或改用浏览器登录",
        )),
        proto::NormalizeSource::Desktop => Err(GatewayError::with_status(
            400,
            format!(
                "MiniMax Code 不支持导入本机客户端登录态（客户端登录态在 ~/.minimax/auth/prod/{}，\
                 写它会破坏客户端的登录代际并迫使你重新扫码）。请改用「浏览器登录」（设备码），\
                 或手工粘贴 accessToken",
                region.desktop_region_dir()
            ),
        )),
    }
}

/// 从一份 JSON（或裸令牌字符串）载荷解析账号。
fn from_payload(
    region: Region,
    payload: &Value,
    name_hint: Option<String>,
) -> Result<proto::NormalizedAccount, GatewayError> {
    if let Some(text) = payload.as_str() {
        if text.chars().count() > MAX_INPUT_LENGTH {
            return Err(GatewayError::with_status(400, "凭证内容过长，请确认粘贴对了内容"));
        }
    }

    // 裸令牌：直接粘了一串 accessToken（能转发，但没有刷新令牌 ⇒ 不能续期）
    let raw = payload.as_str().map(str::trim).unwrap_or("");
    if !raw.is_empty() {
        let secret = json!({ "accessToken": raw });
        let name = default_name(region, &secret);
        return finish(region, with_name(secret, name_hint, name));
    }

    let access_token = pick(payload, &["accessToken", "access_token", "token"]);
    if access_token.is_empty() {
        return Err(GatewayError::with_status(
            400,
            "缺少 accessToken（请粘贴浏览器登录输出，或 MiniMax Code 的访问令牌）",
        ));
    }
    // 整段 JSON 被粘进单字段的常见误用（`accessToken` 的值本身是一段 JSON）
    if access_token.starts_with('{') {
        return Err(GatewayError::with_status(
            400,
            "accessToken 的值看起来是一整段 JSON —— 只需要其中的令牌字符串",
        ));
    }

    let mut secret = payload.clone();
    if let Some(object) = secret.as_object_mut() {
        object.insert("accessToken".to_string(), Value::String(access_token.clone()));
        // token_type 恒 Bearer，不落（没有消费方）
        object.remove("token_type");
        object.remove("tokenType");
    }
    // 形状校验（长度 / 明显粘错）在本地拦掉，不白打一次上游
    credentials::validate_shape(&secret)?;
    // 备注名的兜底链要用**整个 secret**（身份可能只存在于 `userId` 字段里，
    // 而那条链与 `identity()` 同源 —— 见 `default_name`）
    let name = default_name(region, &secret);
    // 载荷自带的 `name` 不算备注名（那可能是从别处抄来的字段）；只有用户
    // 在界面上填的 `name_hint` 才算。`with_name` 会覆写掉旧值。
    let explicit_hint = name_hint.filter(|value| !value.trim().is_empty());
    finish(region, with_name(secret, explicit_hint, name))
}

/// 账号的默认名（用户没指定备注名时用）。
///
/// 身份按**与 `identity()` 同一优先级**取：记录里的 `userId` 优先于令牌里挖的。
/// 两处口径必须一致 —— 不一致会出现「账号 id 是按 userId 算的、名字里却是令牌的
/// 尾段」这种自相矛盾的记录，排障时很难对上。
fn default_name(region: Region, secret: &Value) -> String {
    let explicit = pick(secret, &["userId", "user_id", "uid"]);
    let identity = if explicit.is_empty() {
        let token = pick(secret, &["accessToken", "access_token", "token"]);
        credentials::stable_identity(&token)
    } else {
        explicit
    };
    if identity.is_empty() {
        format!("MiniMax Code {}", region.label())
    } else {
        format!("MiniMax Code {} {identity}", region.label())
    }
}

/// 写备注名（截断到上限，空串不写）。
fn with_name(mut secret: Value, hint: Option<String>, fallback: String) -> Value {
    let name = match hint {
        Some(hint) if !hint.trim().is_empty() => truncate_chars(hint.trim(), MAX_NAME_LENGTH),
        _ => fallback,
    };
    if let Some(object) = secret.as_object_mut() {
        object.insert("name".to_string(), Value::String(name));
    }
    secret
}

/// 收尾：产出 `NormalizedAccount`（公开视图 + 稳定身份 + 非桌面端）。
fn finish(region: Region, secret: Value) -> Result<proto::NormalizedAccount, GatewayError> {
    let public = public(region, &secret);
    Ok(proto::NormalizedAccount {
        identity: identity(&secret),
        public,
        secret,
        // 本包不提供「实时读本机客户端」型账号（见模块头）
        desktop: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn manual(payload: Value, name: Option<&str>) -> proto::NormalizeInput {
        proto::NormalizeInput {
            provider: "minimax".to_string(),
            source: proto::NormalizeSource::Manual { payload },
            name: name.map(str::to_string),
            proxy: None,
        }
    }

    #[test]
    fn a_full_payload_becomes_a_complete_account() {
        let payload = json!({
            "accessToken": "mmoat_full1234567890",
            "refreshToken": "mmort_full",
            "expiresAt": 1_700_000_000_000i64,
            "userId": "u42"
        });
        let account = normalize_account(Region::Cn, manual(payload, Some("工作号"))).expect("应能解析");
        assert_eq!(account.identity, "user-u42");
        assert!(!account.desktop);
        assert_eq!(account.public["name"], json!("工作号"));
        assert_eq!(account.public["uid"], json!("u42"));
        assert_eq!(account.public["edition"], json!("cn"));
        assert_eq!(account.public["expiresAt"], json!(1_700_000_000_000i64));
        assert_eq!(account.public["canRefresh"], json!(true));
        assert_eq!(account.public["hasSession"], json!(true));
        assert_eq!(account.public["tokenTail"], json!("7890"));
    }

    /// 国际版的公开视图必须写 `intl`（网关把它镜像到记录顶层并据此反查；
    /// 写成 `cn` 会让国际版账号被当国内版找）。
    #[test]
    fn the_public_view_carries_the_region_id() {
        let payload = json!({"accessToken": "mmoat_intl1234567890", "userId": "u7"});
        let intl = normalize_account(Region::Intl, manual(payload, None)).expect("应能解析");
        assert_eq!(intl.public["edition"], json!("intl"));
        assert!(
            intl.public["name"].as_str().is_some_and(|name| name.contains("国际版")),
            "默认名要能区分地区：{:?}",
            intl.public["name"]
        );
    }

    /// 裸令牌只给一个字符串：能转发，但没有刷新令牌 ⇒ `canRefresh` 必须为 false
    /// （界面据此显示「不能自动续期」，而不是假装能续）。
    #[test]
    fn a_bare_token_is_accepted_without_refresh() {
        let account = normalize_account(Region::Cn, manual(json!("mmoat_bare1234567890"), None))
            .expect("应能解析");
        assert_eq!(account.public["canRefresh"], json!(false));
        assert_eq!(account.public["hasSession"], json!(true));
        // 身份挖不出来（不透明令牌）→ 空串，交给网关按凭证去重
        assert_eq!(account.identity, "");
    }

    /// 粘了一整段 JSON 进 `accessToken` 字段是常见误操作 —— 本地拦住，
    /// 别拿它去打上游（那只会得到一句含义不明的 401）。
    #[test]
    fn pasted_json_inside_the_token_field_is_rejected() {
        let payload = json!({"accessToken": "{\"accessToken\":\"mmoat_x1234567890\"}"});
        let error = normalize_account(Region::Cn, manual(payload, None)).expect_err("应被拒");
        assert!(error.to_string().contains("JSON"), "实际：{error}");
    }

    /// 缺 accessToken 要给可行动的提示（而不是空记录）。
    #[test]
    fn a_payload_without_a_token_is_rejected() {
        let error =
            normalize_account(Region::Cn, manual(json!({"refreshToken": "mmort_x"}), None))
                .expect_err("应被拒");
        assert!(error.to_string().contains("accessToken"), "实际：{error}");
    }

    /// 文本文件导入：整份 JSON 与「裸令牌一行」两种都要认。
    #[test]
    fn a_text_file_is_accepted_in_both_shapes() {
        let json_file = proto::NormalizeInput {
            provider: "minimax".to_string(),
            source: proto::NormalizeSource::FileText {
                content: "{\"accessToken\":\"mmoat_file1234567890\",\"userId\":\"u9\"}".to_string(),
                file_name: Some("auth.json".to_string()),
            },
            name: None,
            proxy: None,
        };
        let account = normalize_account(Region::Cn, json_file).expect("应能解析");
        assert_eq!(account.identity, "user-u9");

        // 裸令牌一行（前后可能有空白）
        let raw_file = proto::NormalizeInput {
            provider: "minimax".to_string(),
            source: proto::NormalizeSource::FileText {
                content: "\n  mmoat_raw1234567890  \n".to_string(),
                file_name: None,
            },
            name: None,
            proxy: None,
        };
        let account = normalize_account(Region::Cn, raw_file).expect("应能解析");
        assert_eq!(account.public["hasSession"], json!(true));
    }

    /// **容器部署的硬限制**：两条不该支持的来源必须明确回绝并指路，
    /// 而不是静默失败或硬凑一个账号。文案里要带上客户端那条路径（便于排障）。
    #[test]
    fn desktop_and_binary_sources_are_refused_with_guidance() {
        let desktop = proto::NormalizeInput {
            provider: "minimax".to_string(),
            source: proto::NormalizeSource::Desktop,
            name: None,
            proxy: None,
        };
        let error = normalize_account(Region::Intl, desktop).expect_err("应被拒");
        let message = error.to_string();
        assert!(message.contains("浏览器登录"), "要指出可行路径：{message}");
        assert!(message.contains("/en"), "要带上国际版的客户端地区目录：{message}");

        let binary = proto::NormalizeInput {
            provider: "minimax".to_string(),
            source: proto::NormalizeSource::FileBase64 {
                content: "UEsDBA==".to_string(),
                file_name: Some("x.bin".to_string()),
            },
            name: None,
            proxy: None,
        };
        let error = normalize_account(Region::Cn, binary).expect_err("应被拒");
        assert!(error.to_string().contains("二进制"), "实际：{error}");
    }

    /// 身份优先级：记录里的 `userId` 优先于令牌里挖的。
    #[test]
    fn the_recorded_identity_wins_over_the_token() {
        let payload_jwt = "eyJ1c2VyIjp7ImlkIjoidG9rZW4taWQifX0";
        let token = format!("h.{payload_jwt}.s");
        let secret = json!({"accessToken": token, "userId": "from-record"});
        assert_eq!(identity(&secret), "user-from-record");

        // 记录里没有 → 用令牌里挖出来的
        let secret = json!({"accessToken": token});
        assert_eq!(identity(&secret), "token-id");
    }

    /// 备注名按**字符**截断（不按字节 —— 中文备注按字节切会切出半个字）。
    #[test]
    fn the_name_is_truncated_by_characters() {
        let long: String = "中".repeat(MAX_NAME_LENGTH + 50);
        let account = normalize_account(
            Region::Cn,
            manual(json!({"accessToken": "mmoat_x1234567890"}), Some(&long)),
        )
        .expect("应能解析");
        let name = account.public["name"].as_str().unwrap_or("");
        assert_eq!(name.chars().count(), MAX_NAME_LENGTH);
        assert!(name.chars().all(|ch| ch == '中'), "不能切出半个字");
    }

    /// 过长的输入要在本地拦住（那一定是粘错了东西）。
    #[test]
    fn an_oversized_text_file_is_rejected() {
        let huge = "a".repeat(MAX_INPUT_LENGTH + 1);
        let input = proto::NormalizeInput {
            provider: "minimax".to_string(),
            source: proto::NormalizeSource::FileText {
                content: huge,
                file_name: None,
            },
            name: None,
            proxy: None,
        };
        let error = normalize_account(Region::Cn, input).expect_err("应被拒");
        assert!(error.to_string().contains("过长"), "实际：{error}");
    }

    /// 账号名的兜底链：显式备注 > 身份 > 「MiniMax Code <地区>」。
    #[test]
    fn the_default_name_falls_back_to_the_region() {
        // 用户给了备注名 → 用它
        let named = normalize_account(
            Region::Cn,
            manual(json!({"accessToken": "mmoat_x1234567890", "userId": "u1"}), Some("备注")),
        )
        .expect("应能解析");
        assert_eq!(named.public["name"], json!("备注"));
        // 没给 → 用身份
        let identified = normalize_account(
            Region::Cn,
            manual(json!({"accessToken": "mmoat_x1234567890", "userId": "u1"}), None),
        )
        .expect("应能解析");
        assert!(identified.public["name"].as_str().unwrap_or("").contains("u1"));
        // 连身份都没有 → 只有地区名
        let bare = normalize_account(Region::Cn, manual(json!("mmoat_x1234567890"), None))
            .expect("应能解析");
        assert_eq!(bare.public["name"], json!("MiniMax Code 国内版"));
        // 空白备注名不算（不能被写成一个空名字）
        let blank = normalize_account(
            Region::Cn,
            manual(json!({"accessToken": "mmoat_x1234567890"}), Some("   ")),
        )
        .expect("应能解析");
        assert_ne!(blank.public["name"], json!(""));
    }

    /// 公开视图里不该出现**完整令牌**（那是凭据，只能出现在 secret 里）。
    #[test]
    fn the_public_view_never_exposes_the_raw_token() {
        let token = "mmoat_secret1234567890";
        let account =
            normalize_account(Region::Cn, manual(json!({"accessToken": token}), None)).expect("应能解析");
        let text = account.public.to_string();
        assert!(!text.contains(token), "公开视图泄漏了完整令牌：{text}");
        // secret 里必须有（转发要用）
        assert_eq!(account.secret["accessToken"], json!(token));
    }
}
