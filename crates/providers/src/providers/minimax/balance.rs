//! MiniMax Code 账户读数与签到：积分余额 + 逐份批次到期 + 七天一签 + 探活。
//!
//! ── 本项目「积分制」家的标准口径 ────────────────────────────
//! 账号页的四列分别读这些键（网关前端 `accounts-panels.tsx` / `accounts-domain.ts`）：
//! ```text
//!   余额          顶层 availableView（优于 balanceView）→ 主读数
//!   明细弹层      wallets[].balanceView（一句人话）
//!   最近到期      credits[].expireAt 里**还有剩余**的最早一笔（creditExpiryOf）
//!   最近到期积分  同一笔的 remain（creditRowsOf）
//! ```
//! 所以 `credits[]` 必须写 `expireAt` + `remain`，且**过期的与已用尽的不要写进去**
//! （`creditExpiryOf` 会跳过 `expire <= now`，但 `creditRowsOf` 会把它们折叠成
//! 「已用完」摞在弹层末尾 —— 本家每天发一批、30 天错峰的阶梯有三十行，
//! 全塞进去会淹掉真正要紧的那几笔）。取舍写在 [`credit_rows`]。
//!
//! ── 四个接口各回答什么 ──────────────────────────────────────
//! ```text
//!   POST /matrix/api/v1/commerce/get_membership_info   → 余额（唯一权威总额）
//!   GET  /minimax-cloud/api/v1/credit/details          → 每批的剩余与到期时刻
//!   GET  /minimax-cloud/api/v1/signin/status           → 七天一签的进度
//!   POST /minimax-cloud/api/v1/signin/claim            → 领今天那份
//! ```
//! 前两个都要「签名 + Bearer」（缺签名回 `400 invalid signature`，见
//! `endpoints.rs` 的模块头）；**余额以 membership 为准、台账只负责时间** ——
//! 过期批次不清零（实测留下 `-0.31` 这类负残留），把台账的 `remaining_amount`
//! 直接相加会与余额对不上。
//!
//! ── 签到的链路依据（不是猜的）───────────────────────────────
//! ① 客户端 `archon` 页的 `signin` store 直接调这两个端点；
//! ② 校验器在 `@mavis/shared/dist/daily-signin.js`（七天、`status` 1–4、
//!    `claim_result` 1/2），本文件的 `parse_panel` 按它逐条复刻；
//! ③ 积分确实是它发的：台账里 `credit_type == 2` 的批次就是签到产出，
//!    `expire_at_ms` 正好是领取日 + 30 天的账户时区零点。
//!
//! ── 幂等 ────────────────────────────────────────────────────
//! 当天重复领回 `claim_result == 2`（今日已领），**不算失败** —— 如实报成功并
//! 说明是重复调用（`CheckinOutcome::Done`）。客户端自己不自动领（卡片要用户点
//! 按钮），所以对「只用网关」的用户来说，这个签到链是白拿的 4000 积分/轮。
//!
//! ── `timezone_id` 为什么写死北京 ─────────────────────────────
//! 上游只认 IANA 名（传偏移量回 `invalid timezone_id`），而它决定「今天是哪天」。
//! 与 `endpoints::timezone_offset()`（跟随系统时区）**是两件事**：那是签名的
//! 一部分，这是上游的日期判据。国内版账号的签到日历按北京日算；国际版也走
//! 同一口径 —— 此刻没有任何实测证据表明上游会按账号地区拒绝 / 改写这个值，
//! 而「按地区换个时区名」是一个没有依据的分叉。真要改，凭据是「国际账号用
//! `Asia/Shanghai` 领到的批次 `expire_at_ms` 与本地日历对不上」—— 先测再改。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 本 crate 编译期禁止 unwrap/expect/panic（见 `main.rs` 的 deny）。

use agent2api_provider_protocol::WireProxy;
use serde_json::{json, Map, Value};

use crate::errors::GatewayError;
use crate::logging;

use super::credentials::{self, MinimaxCredential};
use super::endpoints;
use super::net;
use super::region::Region;

/// 台账翻页上限（每页 100 条，30 天阶梯 + 购买批次远低于这个数；
/// 上限只是防御上游 `total_count` 给错值时的死循环）。
const MAX_LEDGER_PAGES: u32 = 10;

/// 签到接口要求的时区名。上游只认 IANA 名，传偏移量回 `invalid timezone_id`。
pub const SIGNIN_TIMEZONE: &str = "Asia/Shanghai";

/// 一轮签到的天数（上游 `days[]` 恒 7 条）。
pub const SIGNIN_CYCLE_DAYS: usize = 7;

/// 签到领取结果码：1 = 本次领到，2 = 今日已领（**幂等，不是错误**）。
const CLAIM_CREDITED: i64 = 1;
const CLAIM_ALREADY: i64 = 2;

/// 签到面板的 `status` 取值域（`claimed` / `claimable` / 未开始 / 已错过）。
const SIGNIN_STATUS_MIN: i64 = 1;
const SIGNIN_STATUS_MAX: i64 = 4;

/// 一次签名请求的结果。
struct SignedResponse {
    status: u16,
    payload: Option<Value>,
    text: String,
}

/// 发一次带签名的账户类请求（拼查询串 → 算三头 → 打网关）。
///
/// `region` 决定打哪个网关（国内 / 国际）。**签名本身不分地区**：它是
/// `pathname + search` 的 MD5，域名不在里面（见 `endpoints.rs` 的模块头）。
async fn signed_request(
    region: Region,
    credential: &MinimaxCredential,
    path: &str,
    extra_query: &str,
    body: Option<&Value>,
    proxy: Option<&WireProxy>,
    gateway_proxy: &str,
) -> Result<SignedResponse, GatewayError> {
    let now = logging::now_ms();
    let body_text = match body {
        Some(value) => value.to_string(),
        None => String::new(),
    };
    let signed = endpoints::sign(
        path,
        extra_query,
        &body_text,
        now,
        endpoints::timezone_offset(),
        &credential.user_id,
    );
    let url = format!("{}{}", region.gateway_url(), signed.path_with_query);
    let mut headers: Vec<(String, String)> = vec![(
        "Authorization".to_string(),
        format!("Bearer {}", credential.access_token),
    )];
    headers.extend(signed.headers);

    let response = net::request(
        if body.is_some() { "POST" } else { "GET" },
        &url,
        body,
        None,
        &headers,
        proxy,
        gateway_proxy,
    )
    .await
    .map_err(|error| GatewayError::with_status(502, format!("MiniMax Code 账户接口不可达：{error}")))?;
    Ok(SignedResponse {
        status: response.status,
        payload: response.payload,
        text: response.text,
    })
}

/// 把一次失败翻译成给人看的话（401 点名「重新登录」，重定向给出「换出口」建议，
/// 缺签名单列一句）。
fn describe_failure(status: u16, payload: Option<&Value>, text: &str, what: &str) -> GatewayError {
    let body = payload
        .map(|value| value.to_string())
        .unwrap_or_else(|| text.to_string());
    let lower = body.to_ascii_lowercase();
    let message = if lower.contains("invalid signature") {
        format!("{what}被上游拒绝：请求签名不合法（本插件签名实现与客户端不一致，请反馈）")
    } else if net::is_redirect(status) {
        // **3xx 必须单独一支**：国际站对大陆出口 IP 回 307 跳国内域，
        // 跟过去只会得到 401（见 `region.rs` 模块头）。不单独说的话，
        // 用户会看到「登录态已过期」并被引向无意义的重新登录。
        //
        // 文案要**点名这个账号自己**：账户请求走账号级出口（没配就是直连），
        // 只说「去网络设置配代理」会让人以为是全局开关，配完还不生效。
        // ⚠️ 纯文本（前端按文本渲染，不解析 Markdown）：别写 `**强调**`。
        format!(
            "{what}失败：上游返回 {status} 重定向 —— 本机出口 IP 不在国际站的服务范围。\
             请在「这个账号」的代理设置里指定一个境外出口，配好后重试；\
             这不是登录态问题，重新登录不会改变结果"
        )
    } else if status == 401 {
        format!("{what}失败：登录态已失效（HTTP 401），请在账号页重新登录 MiniMax Code")
    } else {
        format!("{what}失败：上游返回 HTTP {status}{}", if body.trim().is_empty() { String::new() } else { format!("：{body}") })
    };
    GatewayError::with_status(if status == 401 { 401 } else { 502 }, message)
}

/// 取一个数值（数字或数字字符串）。
fn to_number(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse::<f64>().ok(),
        _ => None,
    }
    .filter(|value| value.is_finite())
}

/// 金额 / 积分的紧凑显示（`4000` 而不是 `4000.0`）。
fn compact(value: f64) -> String {
    if (value.fract()).abs() < f64::EPSILON {
        return format!("{:.0}", value);
    }
    if value.abs() >= 10.0 {
        return format!("{:.1}", value);
    }
    format!("{:.2}", value)
}

/// 余额摘要（`op_credit_summary`）。
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CreditSummary {
    pub total: f64,
    pub purchased: f64,
    pub free: f64,
}

/// 从 `get_membership_info` 的响应里取余额摘要。
///
/// ── 字段链照抄客户端（同一条兜底链，少一级就会在某种账号上读成 0）──
/// ```js
/// op_credit_summary.total_remaining_amount
///   ?? opcredit_balance ?? total_remains_credit ?? 0
/// ```
/// ⚠️ `total_remains_credit` / `opcredit_balance` 是**旧账**：在已迁到积分池的
/// 账号上恒为 0。所以它们只在 `op_credit_summary` **整块缺失**时兜底，
/// 而不是并列候选。
pub fn parse_credit_summary(payload: &Value) -> Option<CreditSummary> {
    // 账户类接口的信封：`{base_resp:{status_code,…}, data:{…}}`；也兼容直接平铺
    let body = payload.get("data").unwrap_or(payload);
    if let Some(summary) = body
        .get("op_credit_summary")
        .filter(|value| value.is_object())
    {
        let total = to_number(summary.get("total_remaining_amount"));
        if let Some(total) = total {
            let purchased = to_number(summary.get("purchased_remaining_amount")).unwrap_or(0.0);
            let free = to_number(summary.get("free_remaining_amount")).unwrap_or(total - purchased);
            return Some(CreditSummary {
                total,
                purchased,
                free,
            });
        }
    }
    let flat = to_number(body.get("opcredit_balance"))
        .or_else(|| to_number(body.get("total_remains_credit")))?;
    Some(CreditSummary {
        total: flat,
        purchased: 0.0,
        free: flat,
    })
}

/// 一份积分批次。
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CreditLot {
    /// 发放面额
    pub granted: f64,
    /// 剩余
    pub remaining: f64,
    /// 发放时刻（毫秒；0 = 上游没给）
    pub granted_at_ms: i64,
    /// 到期时刻（毫秒；缺这个字段的批次**直接丢弃** —— 见 [`parse_lots`]）
    pub expire_at_ms: i64,
    /// 上游的批次类型（1 = 购买，2 = 签到）
    pub credit_type: Option<i64>,
}

/// 读一批台账条目（`details[]`）。
///
/// **没有 `expire_at_ms` 的条目一律丢弃**：没有到期时刻的批次如果当成
/// 「永不过期」写进 `credits[]`，前端 `creditExpiryOf` 会跳过它（`expire<=0`），
/// 于是它既不进到期列也不进明细 —— 不如不写。
pub fn parse_lots(payload: &Value) -> Vec<CreditLot> {
    let body = payload.get("data").unwrap_or(payload);
    let Some(details) = body.get("details").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut lots: Vec<CreditLot> = Vec::with_capacity(details.len());
    for entry in details {
        let expire_at_ms = to_number(entry.get("expire_at_ms")).unwrap_or(0.0);
        if expire_at_ms <= 0.0 {
            continue;
        }
        lots.push(CreditLot {
            granted: to_number(entry.get("granted_amount")).unwrap_or(0.0),
            remaining: to_number(entry.get("remaining_amount")).unwrap_or(0.0),
            granted_at_ms: to_number(entry.get("granted_at_ms")).unwrap_or(0.0) as i64,
            expire_at_ms: expire_at_ms as i64,
            credit_type: entry.get("credit_type").and_then(Value::as_i64),
        });
    }
    lots.sort_by_key(|lot| lot.expire_at_ms);
    lots
}

/// 台账响应里的总条数（翻页用；缺失返回 None）。
pub fn total_count(payload: &Value) -> Option<i64> {
    let body = payload.get("data").unwrap_or(payload);
    body.get("total_count").and_then(Value::as_i64)
}

/// 一批台账条目是否为空（翻页终止判据）。
pub fn raw_lot_count(payload: &Value) -> usize {
    payload
        .get("data")
        .unwrap_or(payload)
        .get("details")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

/// 「还有剩余且未过期」的批次，按到期升序。
fn alive_lots(lots: &[CreditLot], now_ms: i64) -> Vec<&CreditLot> {
    let mut alive: Vec<&CreditLot> = lots
        .iter()
        .filter(|lot| lot.remaining > 0.0 && lot.expire_at_ms > now_ms)
        .collect();
    alive.sort_by_key(|lot| lot.expire_at_ms);
    alive
}

/// 批次 → `credits[]` 行（前端读 `expireAt` / `remain` / `name`）。
///
/// ── 三个取舍（都在前端有对应的读数方）──────────────────────────
///   1. **只写还有剩余的批次**：用光的那批到期时没有东西可损失，
///      写进去会让「最近到期积分」显示成 0；
///   2. **不写 `daily` / `record` / `unlimited` 三个标记**：三个都是
///      `creditExpiryOf` 的跳过键，本家的批次是**真到期**（发放日 + 30 天），
///      不是每日重置；
///   3. `name` 按 `credit_type` 给中文（1 = 购买积分，2 = 签到积分），
///      缺失时给中性名 —— 明细弹层里「这是哪来的」比金额次要，但有比没有好。
fn credit_rows(lots: &[CreditLot], now_ms: i64) -> Vec<Value> {
    alive_lots(lots, now_ms)
        .into_iter()
        .map(|lot| {
            let mut row = Map::new();
            row.insert(
                "name".to_string(),
                json!(match lot.credit_type {
                    Some(1) => "购买积分",
                    Some(2) => "签到积分",
                    _ => "积分",
                }),
            );
            row.insert("unit".to_string(), json!("积分"));
            row.insert("granted".to_string(), json!(lot.granted));
            row.insert("remain".to_string(), json!(lot.remaining));
            row.insert("expireAt".to_string(), json!(lot.expire_at_ms));
            if lot.granted_at_ms > 0 {
                row.insert("grantAt".to_string(), json!(lot.granted_at_ms));
            }
            Value::Object(row)
        })
        .collect()
}

/// 一次签到的面板（`days[]` 里的一天）。
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SigninDay {
    pub day_no: i64,
    pub points: f64,
    pub status: i64,
    pub is_today: bool,
}

/// 签到面板。
#[derive(Clone, Debug, PartialEq)]
pub struct SigninPanel {
    pub scene: i64,
    pub days: Vec<SigninDay>,
}

impl SigninPanel {
    /// 今天这一天（可能没有）。
    pub fn today(&self) -> Option<&SigninDay> {
        self.days.iter().find(|day| day.is_today)
    }

    /// 今天能不能领（上游只把可领那一天标 `status == 2`）。
    pub fn claimable(&self) -> bool {
        self.today().map(|day| day.status == 2).unwrap_or(false)
    }

    /// 今天是否已领。
    pub fn claimed(&self) -> bool {
        self.today().map(|day| day.status == 3).unwrap_or(false)
    }

    /// 一轮的总积分（界面上「一轮共 N 积分」）。
    pub fn cycle_points(&self) -> f64 {
        self.days.iter().map(|day| day.points).sum()
    }
}

/// 读签到面板；形状不合规返回 None（`validateSigninPanel` 的同款校验）。
///
/// 校验三条（照客户端 `@mavis/shared/dist/daily-signin.js`）：
/// 恰好 7 天、`day_no` 唯一且落在 1..=7、可领天与今天各至多一个。
/// **半信半疑的响应不如不认** —— 读错一天会让按钮状态与事实相反。
pub fn parse_panel(payload: &Value) -> Option<SigninPanel> {
    // 业务失败被包在 HTTP 200 里：`base_resp.status_code != 0` 就是失败
    if let Some(code) = payload
        .pointer("/base_resp/status_code")
        .and_then(Value::as_i64)
    {
        if code != 0 {
            return None;
        }
    }
    let data = payload.get("data")?;
    let scene = data.get("scene").and_then(Value::as_i64).unwrap_or(0);
    let raw_days = data.get("days")?.as_array()?;
    let mut days: Vec<SigninDay> = Vec::with_capacity(raw_days.len());
    let mut seen: Vec<i64> = Vec::with_capacity(SIGNIN_CYCLE_DAYS);
    let (mut claimable, mut todays) = (0u32, 0u32);
    for entry in raw_days {
        let day_no = entry.get("day_no").and_then(Value::as_i64)?;
        // `day_no` 必须落在 1..=7 且不重复 —— 半信半疑的响应不如不认
        if !(1..=7).contains(&day_no) || seen.contains(&day_no) {
            return None;
        }
        let points = to_number(entry.get("points"))?;
        let status = entry.get("status").and_then(Value::as_i64)?;
        if !(SIGNIN_STATUS_MIN..=SIGNIN_STATUS_MAX).contains(&status) {
            return None;
        }
        let is_today = entry
            .get("is_today")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if status == 2 {
            claimable += 1;
        }
        if is_today {
            todays += 1;
        }
        seen.push(day_no);
        days.push(SigninDay {
            day_no,
            points,
            status,
            is_today,
        });
    }
    if days.len() != SIGNIN_CYCLE_DAYS || claimable > 1 || todays > 1 {
        return None;
    }
    days.sort_by_key(|day| day.day_no);
    Some(SigninPanel { scene, days })
}

/// 一次签到的结果。
#[derive(Clone, Debug, PartialEq)]
pub struct SigninClaim {
    pub claim_id: String,
    /// 1 = 本次领到，2 = 今日已领
    pub result: i64,
    pub day_no: i64,
    pub points: f64,
    pub expire_at_ms: i64,
}

/// 读签到结果；形状不合规返回 None。
pub fn parse_claim(payload: &Value) -> Option<SigninClaim> {
    if let Some(code) = payload
        .pointer("/base_resp/status_code")
        .and_then(Value::as_i64)
    {
        if code != 0 {
            return None;
        }
    }
    let data = payload.get("data")?;
    let claim_id = data.get("claim_id")?.as_str()?.trim().to_string();
    if claim_id.is_empty() {
        return None;
    }
    let result = data.get("claim_result").and_then(Value::as_i64)?;
    if result != CLAIM_CREDITED && result != CLAIM_ALREADY {
        return None;
    }
    let day_no = data.get("day_no").and_then(Value::as_i64)?;
    if !(1..=7).contains(&day_no) {
        return None;
    }
    Some(SigninClaim {
        claim_id,
        result,
        day_no,
        points: to_number(data.get("points")).unwrap_or(0.0),
        expire_at_ms: to_number(data.get("expire_at_ms")).unwrap_or(0.0) as i64,
    })
}

/// 上游信封里的失败文案（`base_resp.status_msg` / `error` / `message`）。
fn envelope_message(payload: &Value) -> String {
    payload
        .pointer("/base_resp/status_msg")
        .and_then(Value::as_str)
        .or_else(|| payload.get("error").and_then(Value::as_str))
        .or_else(|| payload.get("message").and_then(Value::as_str))
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

/// 接口成功判定：`base_resp.status_code == 0`，或没有信封时看 `code`。
fn envelope_ok(payload: &Value) -> bool {
    if let Some(code) = payload
        .pointer("/base_resp/status_code")
        .and_then(Value::as_i64)
    {
        return code == 0;
    }
    match payload.get("code").and_then(Value::as_i64) {
        Some(code) => code == 0 || code == 200,
        None => true,
    }
}

// ────────────────────────────────────────────────────────────────
// 网络部分
// ────────────────────────────────────────────────────────────────

/// 查一次余额（归一化形状见模块头）。
pub async fn fetch_usage(
    region: Region,
    credential: &MinimaxCredential,
    proxy: Option<&WireProxy>,
    gateway_proxy: &str,
) -> Result<Value, GatewayError> {
    // ① 余额（唯一权威总额）
    let membership = signed_request(
        region,
        credential,
        endpoints::MEMBERSHIP_PATH,
        "",
        Some(&json!({})),
        proxy,
        gateway_proxy,
    )
    .await?;
    if !(200..300).contains(&membership.status) {
        return Err(describe_failure(
            membership.status,
            membership.payload.as_ref(),
            &membership.text,
            "查询积分余额",
        ));
    }
    let membership_payload = membership.payload.unwrap_or(Value::Null);
    if !envelope_ok(&membership_payload) {
        let message = envelope_message(&membership_payload);
        return Err(GatewayError::with_status(
            502,
            format!(
                "查询积分余额失败：{}",
                if message.is_empty() {
                    "上游返回业务失败".to_string()
                } else {
                    message
                }
            ),
        ));
    }
    let Some(summary) = parse_credit_summary(&membership_payload) else {
        return Err(GatewayError::with_status(
            502,
            "积分余额读取失败：上游响应里没有 op_credit_summary（账号可能尚未开通积分池）",
        ));
    };

    // ② 台账（到期两列）。**失败不拖垮余额** —— 两个不同接口，只有余额是必需的
    let (lots, ledger_note) = match fetch_ledger(region, credential, proxy, gateway_proxy).await {
        Ok(lots) => (lots, None),
        Err(error) => (Vec::new(), Some(error.to_string())),
    };
    let now = logging::now_ms();
    Ok(normalize(region, summary, &lots, now, ledger_note))
}

/// 拉全量台账（翻页；`page_number` 才是生效参数，`page` 会被上游忽略）。
async fn fetch_ledger(
    region: Region,
    credential: &MinimaxCredential,
    proxy: Option<&WireProxy>,
    gateway_proxy: &str,
) -> Result<Vec<CreditLot>, GatewayError> {
    let mut all: Vec<CreditLot> = Vec::new();
    let mut page = 1u32;
    let mut total = i64::MAX;
    while page <= MAX_LEDGER_PAGES && (all.len() as i64) < total {
        let query = format!("page_number={page}&page_size=100");
        let response = signed_request(
            region,
            credential,
            endpoints::CREDIT_DETAILS_PATH,
            &query,
            None,
            proxy,
            gateway_proxy,
        )
        .await?;
        if !(200..300).contains(&response.status) {
            return Err(describe_failure(
                response.status,
                response.payload.as_ref(),
                &response.text,
                "查询积分明细",
            ));
        }
        let payload = response.payload.unwrap_or(Value::Null);
        if !envelope_ok(&payload) {
            return Err(GatewayError::with_status(502, "查询积分明细失败：上游返回业务失败"));
        }
        let raw_count = raw_lot_count(&payload);
        all.extend(parse_lots(&payload));
        if let Some(count) = total_count(&payload) {
            total = count;
        }
        // 一整页都没条目 = 到底了（`total_count` 缺失或给错时也能收敛）
        if raw_count < 100 {
            break;
        }
        page += 1;
    }
    Ok(all)
}

/// 把余额与台账归一成 `usage` 的契约形状。
///
/// `region` 只用来在钱包 / 套餐名上标出地区（`MiniMax Code 国际版积分`）——
/// 同一页里两家的账号分组相邻，光看「MiniMax Code 积分」分不出是哪一个。
fn normalize(
    region: Region,
    summary: CreditSummary,
    lots: &[CreditLot],
    now_ms: i64,
    ledger_note: Option<String>,
) -> Value {
    let alive = alive_lots(lots, now_ms);
    let next_expire = alive.first().map(|lot| lot.expire_at_ms);
    let expiring_soon: f64 = alive
        .iter()
        .filter(|lot| lot.expire_at_ms - now_ms <= 7 * 86_400_000)
        .map(|lot| lot.remaining)
        .sum();
    // 三十天窗口内到期的积分（含前七天）—— 给界面的细节描述用
    let expiring_month: f64 = alive
        .iter()
        .filter(|lot| lot.expire_at_ms - now_ms <= 30 * 86_400_000)
        .map(|lot| lot.remaining)
        .sum();

    let view = format!("剩 {} 积分", compact(summary.total));
    let plan_name = format!("MiniMax Code {}积分", region.label());

    let mut wallet = Map::new();
    wallet.insert("type".to_string(), json!("credits"));
    wallet.insert("displayName".to_string(), json!(plan_name.clone()));
    wallet.insert("unit".to_string(), json!("积分"));
    wallet.insert("balance".to_string(), json!(summary.total));
    wallet.insert("free".to_string(), json!(summary.free));
    wallet.insert("purchased".to_string(), json!(summary.purchased));
    wallet.insert("balanceView".to_string(), json!(view.clone()));

    let mut document = json!({
        "available": summary.total,
        "availableView": view,
        "unit": "积分",
        "wallets": [Value::Object(wallet)],
        "subscription": {
            "planName": plan_name,
            "status": "credits",
            // 积分是逐批到期的，没有「订阅到期日」这一个时刻 —— 写 0 而不是编
            "expireAt": 0,
            "remainQuota": summary.total,
        },
        "minimax": {
            "region": region.edition_id(),
            "nextExpireAt": next_expire.unwrap_or(0),
            "expiringIn7Days": expiring_soon,
            "expiringIn30Days": expiring_month,
            "lotCount": alive.len(),
            "expireNote": "积分按批次发放：每批在发放日 + 30 个自然日到期（账户时区当日 00:00 失效）",
            "ledgerNote": ledger_note,
        },
        "raw": {
            "membership": {
                "total": summary.total,
                "free": summary.free,
                "purchased": summary.purchased,
            },
            "lotCount": lots.len(),
        },
    });
    // `credits[]` 只在非空时挂：给一个空数组会让明细入口点出一个空框
    let rows = credit_rows(lots, now_ms);
    if !rows.is_empty() {
        if let Some(object) = document.as_object_mut() {
            object.insert("credits".to_string(), Value::Array(rows));
        }
    }
    document
}

/// 查某账号的签到面板（网关的签到中心用它做「今日能不能领」）。
pub async fn query_signin(
    region: Region,
    credential: &MinimaxCredential,
    proxy: Option<&WireProxy>,
    gateway_proxy: &str,
) -> Result<SigninPanel, GatewayError> {
    let query = format!(
        "timezone_id={}",
        endpoints::encode_uri_component(SIGNIN_TIMEZONE)
    );
    let response = signed_request(
        region,
        credential,
        endpoints::SIGNIN_STATUS_PATH,
        &query,
        None,
        proxy,
        gateway_proxy,
    )
    .await?;
    if !(200..300).contains(&response.status) {
        return Err(describe_failure(
            response.status,
            response.payload.as_ref(),
            &response.text,
            "查询签到状态",
        ));
    }
    let payload = response.payload.unwrap_or(Value::Null);
    parse_panel(&payload).ok_or_else(|| {
        GatewayError::with_status(
            502,
            "签到状态读取失败：上游响应不是合法的七天面板（可能接口已变更）",
        )
    })
}

/// 领今天那份积分。
///
/// 返回 `(outcome, credit, message)` —— 与插件协议的 `CheckinReport` 一致：
/// **今天已领不算失败**（`claim_result == 2` 报 `Done` 并说明是重复调用，
/// 幂等是上游保证的）。
pub async fn claim_signin(
    region: Region,
    credential: &MinimaxCredential,
    proxy: Option<&WireProxy>,
    gateway_proxy: &str,
) -> Result<(CheckinOutcomeLite, Option<String>, Option<String>), GatewayError> {
    let query = format!(
        "timezone_id={}",
        endpoints::encode_uri_component(SIGNIN_TIMEZONE)
    );
    let response = signed_request(
        region,
        credential,
        endpoints::SIGNIN_CLAIM_PATH,
        &query,
        Some(&json!({})),
        proxy,
        gateway_proxy,
    )
    .await?;
    if !(200..300).contains(&response.status) {
        return Err(describe_failure(
            response.status,
            response.payload.as_ref(),
            &response.text,
            "签到",
        ));
    }
    let payload = response.payload.unwrap_or(Value::Null);
    let Some(claim) = parse_claim(&payload) else {
        let message = envelope_message(&payload);
        return Ok((
            CheckinOutcomeLite::Failed,
            None,
            Some(if message.is_empty() {
                "签到失败：上游响应不是合法的领取结果".to_string()
            } else {
                format!("签到失败：{message}")
            }),
        ));
    };
    if claim.result == CLAIM_ALREADY {
        return Ok((
            CheckinOutcomeLite::Done,
            None,
            Some(format!("今日已签到（第 {} 天，本轮无需重复领取）", claim.day_no)),
        ));
    }
    Ok((
        CheckinOutcomeLite::Claimed,
        Some(format!("第 {} 天 +{} 积分", claim.day_no, compact(claim.points))),
        Some(format!(
            "签到成功：第 {} 天 +{} 积分{}",
            claim.day_no,
            compact(claim.points),
            if claim.expire_at_ms > 0 {
                "（30 天后到期）"
            } else {
                "（按上游规则到期）"
            }
        )),
    ))
}

/// 本家签到结果的三种落点（映射到协议枚举时只做一次转换）。
///
/// 单独一个小枚举而不是直接用 `proto::CheckinOutcome`：那两个「已领」与
/// 「真领到」的区别是本家自己的语义（都算成功），而协议枚举还带着
/// `Ineligible` / `Inactive` / `Captcha` 三种本家不会走到的情况。在这里
/// 收窄一步，转换点就只有一处。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CheckinOutcomeLite {
    /// 本次真领到
    Claimed,
    /// 今日已领（幂等，同样算成功）
    Done,
    /// 上游明确说领不了（响应不合法 / 业务拒绝）
    Failed,
}

// ────────────────────────────────────────────────────────────────
// 添加账号时的探活
// ────────────────────────────────────────────────────────────────

/// 探活结果（添加账号弹窗用来决定「保存并提示什么」）。
#[derive(Clone, Debug)]
pub struct ProbeOutcome {
    /// 是否可用
    pub ok: bool,
    /// 给用户看的一句话
    pub message: String,
    /// 顺手发现到的**稳定身份**（JWT 的 `user.id`）。
    ///
    /// 空串 = 这一次没发现。这不是「探活失败」，只是没有额外信息。
    ///
    /// ── 为什么探活要顺带报告身份 ────────────────────────────────
    /// 线上 `mmoat_` 令牌是不透明串，**令牌里读不出身份**；而账户类接口
    /// （余额 / 签到）的签名查询串要带 `user_id=<身份>`，缺它时 Sign 出来的
    /// 三个头全部不合法（`invalid signature`）⇒ 余额恒空、签到恒失败。
    ///
    /// 续期端点只回一对令牌、**不回身份**，所以这个缺口一旦形成（账号落库时
    /// 没带上 `userId`）就再也没机会补回来了。而探活是**唯一一次**手上有
    /// 「一个刚签发、还活着」的令牌的时机。
    pub identity: String,
}

/// 发一次最小对话验证凭证（`region` 决定打哪个网关 —— 拿国内版令牌去打国际
/// 网关只会得到一句 `invalid access token`，而令牌其实好好的）。
///
/// ── 为什么探活要真的发一次对话 ───────────────────────────────
/// 本家虽然有个 `/mavis/api/v1/models` 目录接口，但它**免鉴权**（实测无 token
/// 也 200），拿它当探活会永远通过。推理端点的门禁最严（纯看 token），
/// 用 `max_tokens: 1` 打的成本可以忽略，而得出的结论正好覆盖支持矩阵第一列。
///
/// 网络错误不抛（返回 `ok: false` + 可读 message），让界面能「仍然保存 ——
/// 离线录入是合理场景」。
pub async fn probe(
    region: Region,
    credential: &MinimaxCredential,
    proxy: Option<&WireProxy>,
    gateway_proxy: &str,
) -> ProbeOutcome {
    let body = json!({
        "model": probe_model(),
        "max_tokens": 1,
        "messages": [{ "role": "user", "content": "hi" }],
    });
    let plan = match super::chat::build_chat_plan(region, credential, &body) {
        Ok(plan) => plan,
        Err(error) => {
            return ProbeOutcome {
                ok: false,
                message: error.message,
                identity: String::new(),
            }
        }
    };
    match net::request(
        "POST",
        &plan.url,
        Some(&plan.body),
        None,
        &plan.headers,
        proxy,
        gateway_proxy,
    )
    .await
    {
        Ok(response) if response.ok => ProbeOutcome {
            ok: true,
            message: format!(
                "{} 令牌可用（已用一次最小对话验证）",
                region.display_name()
            ),
            identity: credentials::stable_identity(&credential.access_token),
        },
        Ok(response) => {
            // 归因（决定提示文案，别混）：401 → 令牌失效；其余 → 如实转发上游状态
            let message = if response.status == 401 {
                format!(
                    "{} 令牌不可用（HTTP 401）：请重新登录或确认这枚令牌属于{}",
                    region.display_name(),
                    region.label()
                )
            } else {
                format!(
                    "{} 探活失败：上游返回 HTTP {}（令牌本身可能有效，稍后可再试）",
                    region.display_name(),
                    response.status
                )
            };
            ProbeOutcome {
                ok: false,
                message,
                identity: credentials::stable_identity(&credential.access_token),
            }
        }
        Err(error) => ProbeOutcome {
            ok: false,
            // 网络问题不阻断保存：离线录入是合理场景
            message: format!("未能完成探活（{error}），账号已保存但请在网络恢复后测一次"),
            identity: credentials::stable_identity(&credential.access_token),
        },
    }
}

/// 探活用的模型名：兜底清单里那个（上游都认），并优先取远程清单的第一条。
fn probe_model() -> String {
    let manifest = super::models::manifest(Region::Cn);
    manifest
        .first()
        .and_then(|entry| entry.get("id"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| "MiniMax-M3".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn panel_value() -> Value {
        json!({
            "base_resp": {"status_code": 0},
            "data": {
                "scene": 2,
                "days": [
                    {"day_no": 1, "points": 400, "status": 3, "is_today": false},
                    {"day_no": 2, "points": 400, "status": 3, "is_today": false},
                    {"day_no": 3, "points": 400, "status": 2, "is_today": true},
                    {"day_no": 4, "points": 1000, "status": 1, "is_today": false},
                    {"day_no": 5, "points": 400, "status": 1, "is_today": false},
                    {"day_no": 6, "points": 400, "status": 1, "is_today": false},
                    {"day_no": 7, "points": 1000, "status": 1, "is_today": false}
                ]
            }
        })
    }

    #[test]
    fn reads_the_seven_day_panel() {
        let panel = parse_panel(&panel_value()).expect("应能解析");
        assert_eq!(panel.days.len(), SIGNIN_CYCLE_DAYS);
        assert_eq!(panel.scene, 2);
        assert!(panel.claimable(), "今天 status=2 就是可领");
        assert!(!panel.claimed());
        assert_eq!(panel.cycle_points(), 4000.0);
        // 400+400+400+1000+400+400+1000 = 4000（实测一轮的总额）
        assert_eq!(panel.today().map(|day| day.day_no), Some(3));
    }

    /// **半信半疑的响应不如不认** —— 校验器抓到的每一种坏形状都必须返回 None。
    /// 读错一天会让按钮状态与事实相反（点一下必然报错）。
    #[test]
    fn a_malformed_panel_is_rejected() {
        // 天数不是 7
        let short = json!({"data": {"days": [
            {"day_no": 1, "points": 1, "status": 1, "is_today": true}
        ]}});
        assert!(parse_panel(&short).is_none());
        // day_no 重复
        let mut duplicated = panel_value();
        duplicated["data"]["days"][1]["day_no"] = json!(1);
        assert!(parse_panel(&duplicated).is_none());
        // status 越界
        let mut bad_status = panel_value();
        bad_status["data"]["days"][0]["status"] = json!(9);
        assert!(parse_panel(&bad_status).is_none());
        // 两个「今天」
        let mut two_today = panel_value();
        two_today["data"]["days"][0]["is_today"] = json!(true);
        assert!(parse_panel(&two_today).is_none());
        // 业务失败信封（HTTP 200 但 status_code != 0）
        let failed = json!({"base_resp": {"status_code": 7}, "data": {}});
        assert!(parse_panel(&failed).is_none());
    }

    #[test]
    fn reads_the_claim_result_and_keeps_idempotence_distinct() {
        let credited = json!({"base_resp": {"status_code": 0}, "data": {
            "claim_id": "c1", "claim_result": 1, "day_no": 3,
            "points": 400, "expire_at_ms": 1_792_000_000_000i64
        }});
        let claim = parse_claim(&credited).expect("应能解析");
        assert_eq!(claim.result, CLAIM_CREDITED);
        assert_eq!(claim.day_no, 3);

        let already = json!({"base_resp": {"status_code": 0}, "data": {
            "claim_id": "c2", "claim_result": 2, "day_no": 3, "points": 400
        }});
        let claim = parse_claim(&already).expect("应能解析");
        assert_eq!(claim.result, CLAIM_ALREADY, "2 = 今日已领（幂等，不是失败）");

        // 未定义的结果码要如实判成「形状不合规」而不是硬塞成功
        let unknown = json!({"data": {"claim_id": "c3", "claim_result": 9, "day_no": 3}});
        assert!(parse_claim(&unknown).is_none());
        // 缺 claim_id 同属不合规
        let missing_id = json!({"data": {"claim_result": 1, "day_no": 3}});
        assert!(parse_claim(&missing_id).is_none());
    }

    #[test]
    fn credit_summary_prefers_the_new_pool_field() {
        // 新账：op_credit_summary 全给你
        let fresh = json!({"data": {"op_credit_summary": {
            "total_remaining_amount": 4100.5,
            "purchased_remaining_amount": 100.5,
            "free_remaining_amount": 4000.0
        }}});
        let summary = parse_credit_summary(&fresh).expect("应能解析");
        assert_eq!(summary.total, 4100.5);
        assert_eq!(summary.purchased, 100.5);
        assert_eq!(summary.free, 4000.0);

        // 旧账：两块都没有，只有旧字段 —— 它们是兜底而不是并列候选
        let legacy = json!({"data": {"total_remains_credit": 12.0}});
        let summary = parse_credit_summary(&legacy).expect("应能解析");
        assert_eq!(summary.total, 12.0);
        assert_eq!(summary.purchased, 0.0);
        assert_eq!(summary.free, 12.0);

        // 新块存在但缺主字段 → 走旧字段兜底（而不是把 total 当 0）
        let partial = json!({"data": {
            "op_credit_summary": {"purchased_remaining_amount": 5.0},
            "opcredit_balance": 77.0
        }});
        assert_eq!(parse_credit_summary(&partial).map(|s| s.total), Some(77.0));
    }

    /// 没有到期时刻的批次必须丢弃：前端 `creditExpiryOf` 会跳过 `expire<=0`，
    /// 于是它既不进到期列也不进明细（写进去等于白写）。
    #[test]
    fn lots_without_an_expiry_are_dropped() {
        let payload = json!({"data": {"details": [
            {"granted_amount": 400, "remaining_amount": 400, "expire_at_ms": 1_792_000_000_000i64, "credit_type": 2},
            {"granted_amount": 100, "remaining_amount": 100},
            {"granted_amount": 50, "remaining_amount": 50, "expire_at_ms": 0}
        ]}});
        let lots = parse_lots(&payload);
        assert_eq!(lots.len(), 1, "只有带到期时刻的那一条");
        assert_eq!(lots[0].remaining, 400.0);
        assert_eq!(lots[0].credit_type, Some(2));
    }

    /// `credits[]` 只写「还有剩余且未过期」的批次，且不能带 `daily` / `record`
    /// / `unlimited` 三个跳过键（本家的批次是真到期，不是每日重置）。
    #[test]
    fn credit_rows_skip_dead_lots_and_reset_markers() {
        let now = 1_700_000_000_000i64;
        let lots = vec![
            // 已用尽
            CreditLot { granted: 400.0, remaining: 0.0, granted_at_ms: now, expire_at_ms: now + 86_400_000, credit_type: Some(2) },
            // 已过期
            CreditLot { granted: 400.0, remaining: 400.0, granted_at_ms: now - 86_400_000, expire_at_ms: now - 1, credit_type: Some(2) },
            // 还活着
            CreditLot { granted: 400.0, remaining: 400.0, granted_at_ms: now, expire_at_ms: now + 86_400_000, credit_type: Some(2) },
        ];
        let rows = credit_rows(&lots, now);
        assert_eq!(rows.len(), 1, "只有还有剩余且未过期的那一条");
        assert_eq!(rows[0]["remain"], json!(400.0));
        assert_eq!(rows[0]["expireAt"], json!(now + 86_400_000));
        assert_eq!(rows[0]["name"], json!("签到积分"));
        assert!(rows[0].get("daily").is_none());
        assert!(rows[0].get("record").is_none());
        assert!(rows[0].get("unlimited").is_none());
    }

    /// 归一化后的文档必须把地区说清（账号页两家相邻，光看「MiniMax Code」分不出）。
    #[test]
    fn the_usage_document_names_the_region() {
        let now = 1_700_000_000_000i64;
        let lots = vec![CreditLot {
            granted: 400.0,
            remaining: 400.0,
            granted_at_ms: now,
            expire_at_ms: now + 86_400_000,
            credit_type: Some(2),
        }];
        let cn = normalize(
            Region::Cn,
            CreditSummary { total: 400.0, purchased: 0.0, free: 400.0 },
            &lots,
            now,
            None,
        );
        let intl = normalize(
            Region::Intl,
            CreditSummary { total: 400.0, purchased: 0.0, free: 400.0 },
            &lots,
            now,
            None,
        );
        assert_eq!(cn["minimax"]["region"], json!("cn"));
        assert_eq!(intl["minimax"]["region"], json!("intl"));
        assert_ne!(
            cn["subscription"]["planName"],
            intl["subscription"]["planName"]
        );
        // 主读数与钱包一句话都要在
        assert!(cn["availableView"].as_str().is_some_and(|text| text.contains("积分")));
        assert!(cn["wallets"][0]["balanceView"].as_str().is_some());
        // 台账失败时只留一条备注，不把余额整块变成错误
        let with_note = normalize(
            Region::Cn,
            CreditSummary { total: 400.0, purchased: 0.0, free: 400.0 },
            &[],
            now,
            Some("明细接口超时".to_string()),
        );
        assert_eq!(with_note["minimax"]["ledgerNote"], json!("明细接口超时"));
        assert_eq!(with_note["available"], json!(400.0));
    }

    /// 台账接口失败不该拖垮余额（两个不同接口，只有余额是必需的）——
    /// 这条钉的是 `fetch_usage` 里那处「失败不传播」的取舍。
    #[test]
    fn a_ledger_failure_does_not_break_the_balance() {
        let now = 1_700_000_000_000i64;
        let document = normalize(
            Region::Cn,
            CreditSummary { total: 4000.0, purchased: 0.0, free: 4000.0 },
            &[],
            now,
            Some("查询积分明细失败：上游返回 HTTP 500".to_string()),
        );
        assert_eq!(document["available"], json!(4000.0));
        assert!(
            document.get("credits").is_none(),
            "空明细不该挂一个空数组（点开会是个空框）"
        );
    }

    /// 探活用的模型名必须是清单里真实存在的那一个（猜一个名字会得到 400，
    /// 而那会被读成「令牌坏了」）。
    #[test]
    fn the_probe_model_exists_in_the_manifest() {
        let model = probe_model();
        let known = super::super::models::fallback_manifest()
            .iter()
            .any(|entry| entry.get("id").and_then(Value::as_str) == Some(model.as_str()));
        assert!(known, "探活模型必须是兜底清单里有的：{model}");
    }

    /// 金额显示：整数不带小数点，小数按量级裁位数（界面上「剩 4000 积分」）。
    #[test]
    fn amounts_are_shown_compactly() {
        assert_eq!(compact(4000.0), "4000");
        assert_eq!(compact(4100.5), "4100.5");
        assert_eq!(compact(0.31), "0.31");
    }

    /// `envelope_ok` / `envelope_message`：三种信封写法都要认。
    #[test]
    fn the_business_envelope_is_read_leniently() {
        assert!(envelope_ok(&json!({"base_resp": {"status_code": 0}})));
        assert!(!envelope_ok(&json!({"base_resp": {"status_code": 7}})));
        assert!(envelope_ok(&json!({"code": 200})));
        assert!(envelope_ok(&json!({"code": 0})));
        assert!(!envelope_ok(&json!({"code": 401})));
        // 没有信封 = 成功（不是所有接口都包信封）
        assert!(envelope_ok(&json!({"data": {}})));

        assert_eq!(
            envelope_message(&json!({"base_resp": {"status_msg": "签名错误"}})),
            "签名错误"
        );
        assert_eq!(envelope_message(&json!({"error": "invalid signature"})), "invalid signature");
        assert_eq!(envelope_message(&json!({"message": "nope"})), "nope");
        assert_eq!(envelope_message(&json!({})), "");
    }
}
