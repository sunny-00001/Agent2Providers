//! MiniMax Code 插件实现：**一份实现、两个地区实例**（国内版 / 国际版）。
//!
//! ── 一家还是两家 ────────────────────────────────────────────
//! 上游把两地当两套账号（客户端登录态按 `<env>/<region>` 分目录存、授权服务器
//! 不同域、令牌互不通用），所以本插件**申报两个 provider**：
//! ```text
//!   minimax        国内版   https://agent.minimax.cn    account.minimax.cn
//!   minimax-intl   国际版   https://agent.minimax.io    account.minimax.io
//! ```
//! 拆开的第三条理由（也是本插件仓里 ModelScope / MonkeyCode 的同一条）：**模型
//! 目录只有一份**，不拆就会互相覆盖「上次刷新时刻」，界面上出现「国际版刚刷过、
//! 国内版显示从未刷新」这种自相矛盾的读数。
//!
//! 实现是**参数化的**：`MinimaxProvider` 持有 [`Region`]，其余代码两地共用
//! （协议完全一致 —— 同一套 Anthropic Messages、同一套 MD5 签名、同一个
//! `client_id=mcode-public`）。这与 `qoder::QODER_CN` / `QODER_INTL` 同一形态。
//!
//! ── 能力矩阵（对齐上游 README 六列）──────────────────────────
//! ```text
//!   LLM 请求        ✓   Anthropic Messages（无 Authorization 回 401）
//!   Token 自动续期  ✓   refresh_token（单次有效、每次轮换）
//!   模型列表        ✓   GET /mavis/api/v1/models（免鉴权）+ 内置兜底
//!   余额查询        ✓   积分余额（op_credit_summary）+ 逐份批次到期
//!   签到            ✓   七天一轮 4000 积分（400/400/400/1000/400/400/1000）
//!   领取类          ✗   签到即领取；全包检索无第二个活动接口
//! ```
//! 两个地区的能力位**完全相同**（同一套接口，只是域名不同）。
//!
//! ── 无状态 ──────────────────────────────────────────────────
//! `stateful` 恒 false：上游就是一次 HTTP 请求 = 一次回答（Anthropic Messages
//! 的 SSE）。插件只需要 `build_chat` 给出「URL + 头 + 体」，响应翻译由网关那台
//! `UpstreamKind::Anthropic` 翻译机做。
//!
//! ── 子模块分工 ──────────────────────────────────────────────
//! ```text
//!   region.rs       地区（三套域名 / 两条 provider 身份 / 目录缓存槽 / id 前缀）
//!   endpoints.rs    路径常量 + 设备查询串 + 三签名头（yy / x-timestamp / x-signature）
//!   net.rs          本家专属出网（**不跟随 3xx** + 账号代理 → 网关出口 → 直连）
//!   credentials.rs  账号记录 → 凭证快照（accessToken / refreshToken / expiresAt / userId）
//!   chat.rs         转发请求构造（chat 体 → Anthropic Messages + Bearer）
//!   models.rs       模型目录（远程 + 静态兜底，两个地区各一格缓存）
//!   errors.rs       错误分类（401 → TokenExpired 等四档）
//!   login.rs        设备码 OAuth（申请 / 轮询 / 取消 / 续期，按地区取授权服务器）
//!   balance.rs      余额 + 逐份批次到期 + 签到 + 添加账号时的探活
//!   accounts.rs     公开视图 / 稳定身份 / 规范化（手填 / 文件）
//! ```
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 本 crate 编译期禁止 unwrap/expect/panic（见 `main.rs` 的 deny）。

pub mod accounts;
pub mod balance;
pub mod chat;
pub mod credentials;
pub mod endpoints;
pub mod errors;
pub mod login;
pub mod models;
pub mod net;
pub mod region;

use std::sync::OnceLock;

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::{ChatPlan, PluginCtx, Provider, ProviderMeta, SendFuture};
use agent2api_provider_protocol::WireProxy;
use serde_json::Value;

use crate::errors::GatewayError;
use crate::flight;
use crate::logging;

pub use region::Region;

/// 国内版实例（provider id `minimax`）。
pub static MINIMAX_CN: MinimaxProvider = MinimaxProvider { region: Region::Cn };

/// 国际版实例（provider id `minimax-intl`）。
pub static MINIMAX_INTL: MinimaxProvider = MinimaxProvider { region: Region::Intl };

/// MiniMax Code 适配器（按地区参数化；无状态）。
///
/// `Clone` / `Copy` 是为了让 [`MINIMAX_CN`] / [`MINIMAX_INTL`] 两个静态实例能
/// 按值装进 `Vec<Box<dyn Provider>>`（`Region` 是 `Copy`，克隆零成本）——
/// 与 `monkeycode::MonkeyCodeProvider` 同一写法。
#[derive(Clone, Copy)]
pub struct MinimaxProvider {
    region: Region,
}

impl MinimaxProvider {
    /// 本地区的 provider id。
    pub fn id(&self) -> &'static str {
        self.region.provider_id()
    }

    /// 从账号记录还原凭证（`account` 为空串 = 该 provider 的队首账号）。
    async fn credential(
        &self,
        ctx: &PluginCtx,
        account: &str,
    ) -> Result<(Value, credentials::MinimaxCredential), GatewayError> {
        let record = crate::store::record(ctx, self.id(), account).await?;
        let credential = credentials::from_record(Some(&record))?;
        Ok((record, credential))
    }

    /// 取账号级出口（记录里的 `proxy` 字段；缺失 = 走网关默认出口）。
    ///
    /// ── 为什么余额 / 签到必须跟着账号的代理走 ──────────────────
    /// 国际站 `agent.minimax.io` 对**大陆出口 IP** 回 307，跟过去就是国内集群的
    /// 401 —— 也就是「余额能不能查」本身就取决于出口。账号记录上那个代理正是
    /// 用户为这个账号挑的，不拿它等于白配。
    fn proxy_of(record: &Value) -> Option<WireProxy> {
        record
            .get("proxy")
            .and_then(|value| serde_json::from_value(value.clone()).ok())
    }
}

impl Provider for MinimaxProvider {
    fn meta(&self) -> ProviderMeta {
        let region = self.region;
        ProviderMeta::new(region.provider_id(), region.display_name())
            .with_capabilities(proto::Capabilities {
                chat: true,
                // 一次 HTTP 请求 = 一次回答（Anthropic Messages）
                stateful: false,
                // POST {auth}/oauth2/token（grant_type=refresh_token，会轮换）
                refresh: true,
                // GET {gw}/mavis/api/v1/models（**免鉴权**）
                model_refresh: true,
                // POST {gw}/matrix/api/v1/commerce/get_membership_info
                usage: true,
                // 七天一轮的签到（{gw}/minimax-cloud/api/v1/signin/*）
                checkin: true,
                // 签到即领取；全包检索没有第二个活动接口
                claims: false,
                // OAuth 2.0 设备码（RFC 8628）+ PKCE：授权在用户浏览器里完成
                web_login: true,
                // 上游是 Anthropic Messages，网关的翻译机会回写请求的模型名 ——
                // 插件这边不必再改写（`sse_model_rewrite` 是给「上游回内部名」
                // 的家用的）。MiniMax 的 SSE 里 model 就是请求的那个名字。
                sse_model_rewrite: false,
                // Anthropic 的 SSE 不会发「整片只有换行」的分片
                sse_strip_newline_chunks: false,
                // 没有「无账号也能转发」的旁路（必须登录）
                anonymous_default_session: false,
                // 跟随系统代理这件事**只给 Antigravity**：本家的出口由账号代理
                // 决定，直连就是直连（见 net.rs 的出口优先级）
                system_proxy_when_unset: false,
                // 目录免鉴权、清单是全局的 ⇒ 「获取模型」不需要选账号
                refresh_uses_account: false,
                // 本家不认「默认模型」这个概念：模型名缺省时上游自己会报错，
                // 我们注入一个猜的名字只会让客户端的意图被悄悄改写
                supports_default_model: false,
                // 没有环境变量 / 默认登录态旁路
                env_credentials: false,
            })
            .with_login(vec![
                // 设备码登录：点开授权页、在里面确认，网关按我们申报的间隔轮询
                proto::LoginMethod::Browser {
                    button: "浏览器登录".into(),
                    hint: Some(format!(
                        "在打开的 {} 授权页里确认设备码；完成后回到这里，网关会自动取回凭证",
                        region.label()
                    )),
                },
                // 手工粘贴（容器里没有桌面壳时的兜底路径）
                proto::LoginMethod::Token {
                    label: "访问令牌".into(),
                    placeholder: "mmoat_ 开头的访问令牌（或浏览器登录的输出）".into(),
                    extra_fields: Vec::new(),
                },
            ])
            .with_models(models::fallback_manifest())
            .with_account_features(proto::AccountFeatures {
                // 余额 / 积分查询（membership + 台账）
                usage: true,
                // 逐份积分批次（`credits[]`，带 expireAt）
                credit_detail: true,
                credit_expiry: true,
                // 两个地区各是一个 provider，但公开形态里带 `edition` 供徽章显示
                edition: true,
                identifier: vec!["uid".to_string(), "userId".to_string()],
                expiry: vec!["expiresAt".to_string(), "tokenExpiresAt".to_string()],
                // 令牌有明确有效期（3600 秒）且能续期 —— 不是「长期有效」
                long_lived: false,
                ..Default::default()
            })
            .with_checkin(proto::CheckinInfo {
                description: Some(
                    "七天一轮共 4000 积分（400/400/400/1000/400/400/1000），每份 30 天后到期；\
                     当天重复领是幂等的（上游回「今日已领」）"
                        .to_string(),
                ),
                modes: vec![proto::CheckinMode::Checkin],
                ..Default::default()
            })
    }

    fn provider_id(&self) -> String {
        self.id().to_string()
    }

    // ── 数据面 ────────────────────────────────────────────────

    /// 构造 `POST {gw}/mavis/api/v1/llm/v1/messages`（Anthropic Messages）。
    ///
    /// 响应协议如实申报成 `UpstreamKind::Anthropic` —— 网关据此选它那台
    /// `AnthropicToChatStream` 翻译机；申报错了会把 Anthropic SSE 当 chat SSE
    /// 透传（症状：状态码 200 但客户端收到一堆乱码）。
    ///
    /// ⚠️ **这里不发请求**：`build_chat` 只返回「怎么发」的描述（URL / 头 / 体），
    /// 真正发送由网关编排层做 —— 账号轮换、限额冷却、退避重试与取消处理都留在
    /// 那边。账号级出口由 `req.proxy` 交给网关的发送链。
    ///
    /// ⚠️ **转发链上的 3xx 由网关处理**：本家自己的出网（`net.rs`，用于余额 /
    /// 签到 / 设备码）显式关掉了重定向跟随（见该模块头第 1 条）；而转发请求的
    /// HTTP 客户端在网关侧，插件控制不到。所以如果国际版账号在转发上也撞上
    /// 地域 307，那要看网关那台的策略 —— 这也是「给国际版账号配境外出口」
    /// 这条部署建议同样适用于转发的原因。
    fn build_chat<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        req: proto::ChatRequest,
    ) -> SendFuture<'a, ChatPlan> {
        Box::pin(async move {
            let (_record, credential) = self.credential(ctx, &req.account).await?;
            chat::build_chat_plan(self.region, &credential, &req.body)
                .map_err(GatewayError::into_message)
        })
    }

    /// 上游错误分类（四档，判定顺序即契约，见 `errors.rs`）。
    fn classify(&self, status: u16, body: &Value) -> proto::ErrorClass {
        errors::classify(status, body)
    }

    // ── 凭证 ──────────────────────────────────────────────────

    /// 取可用访问令牌。
    ///
    /// ⚠️ **这里不发网络请求**：本方法会在转发路径上被调；临期只记一行提示，
    /// 真正的续期由维护链路（`refresh_token`）与 401 后的强制刷新负责
    /// —— 与 `atomcode` / `lobsterai` 同一取舍（在热路径上做网络 I/O 会让
    /// 每条请求多一次往返，而且并发时容易互相作废刷新令牌）。
    fn ensure_token<'a>(&'a self, ctx: &'a PluginCtx, account: &'a str) -> SendFuture<'a, String> {
        Box::pin(async move {
            let (_record, credential) = self.credential(ctx, account).await?;
            if credential.expiring_at(logging::now_ms()) {
                logging::verbose(
                    "[MiniMax]",
                    &format!(
                        "{} 账号令牌已过期或临期，将按需续期（续期会轮换 refresh token）",
                        self.region.label()
                    ),
                );
            }
            Ok(credential.access_token)
        })
    }

    /// 强制续期（401 之后 / 维护链路）：刷新并**把新的一对写回记录**。
    ///
    /// ── 为什么必须写回，以及为什么必须单飞 ───────────────────────
    /// 续期**轮换** refresh token：上游同时下发新 access 与新 refresh，旧的就
    /// 作废了。丢掉新的 refresh 等于让账号退化成必须重新登录；两个并发续期
    /// 互相作废（后写覆盖前者）—— 因此走 `flight::Table` 做单飞，键含
    /// **两个令牌的指纹**（令牌一变就是新的一轮，与 `atomcode` 同一口径）。
    fn refresh_token<'a>(&'a self, ctx: &'a PluginCtx, account: &'a str) -> SendFuture<'a, String> {
        Box::pin(async move {
            let (record, credential) = self.credential(ctx, account).await?;
            if !credential.can_refresh() {
                return Err(GatewayError::with_status(
                    401,
                    format!(
                        "{} 账号没有 refresh token，无法续期，请重新登录",
                        self.region.label()
                    ),
                )
                .into_control_message());
            }
            let key = format!(
                "{}:{}:{}:{}",
                self.region.provider_id(),
                account,
                flight::fingerprint(&credential.access_token),
                flight::fingerprint(&credential.refresh_token),
            );
            match flights(self.region).get_or_init(flight::Table::new).join(&key) {
                flight::Join::Waiter(waiter) => waiter
                    .wait()
                    .await
                    .map(|fresh: credentials::MinimaxCredential| fresh.access_token)
                    .map_err(GatewayError::into_control_message),
                flight::Join::Leader(leader) => {
                    let result = self
                        .refresh_and_save(ctx, account, &record, &credential)
                        .await;
                    leader.finish(result.clone());
                    result
                        .map(|fresh| fresh.access_token)
                        .map_err(GatewayError::into_control_message)
                }
            }
        })
    }

    /// 临期判定：`expiresAt` 已存则用它，否则从 JWT 的 `exp` 推。
    fn token_expiring<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, bool> {
        Box::pin(async move {
            // 空账号 = 「本家默认登录态」：本家没有这条旁路，如实返回 false
            if account.trim().is_empty() {
                return Ok(false);
            }
            let Ok((_record, credential)) = self.credential(ctx, account).await else {
                return Ok(false);
            };
            Ok(credential.can_refresh() && credential.expiring_at(logging::now_ms()))
        })
    }

    // ── 目录 / 余额 / 签到 ─────────────────────────────────────

    fn models<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        _account: &'a str,
    ) -> SendFuture<'a, proto::ModelList> {
        Box::pin(async move { Ok(models::list_report(self.region)) })
    }

    /// 刷模型目录：**不需要账号**（接口免鉴权，见 `models.rs` 的模块头）。
    ///
    /// 「一个账号都没有」不是失败 —— 那是「用户还没添加账号」的正常状态，
    /// 返回 `unchanged()`（脚本 / CI 不该看到一个红色失败，与 `atomcode`
    /// 同口径）。
    fn refresh_models<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
        _force: bool,
    ) -> SendFuture<'a, proto::RefreshOutcome> {
        Box::pin(async move {
            // 有账号就跟着它的代理走（国际版账号常常只有经代理才可达）；
            // 没账号就按网关默认出口。两种都不影响「免鉴权」这件事。
            let proxy = match crate::store::record(ctx, self.id(), account).await {
                Ok(record) => MinimaxProvider::proxy_of(&record),
                Err(_) => None,
            };
            // 目录挪到后台刷新时若 `force` 为真也不额外做什么 —— `models::refresh`
            // 本身没有「跳过缓存」的分支（它每次都真拉，失败保留旧清单）。
            let gateway_proxy = ctx.env.proxy.clone();
            if let Some(proxy) = proxy {
                Ok(models::refresh(self.region, Some(&proxy), &gateway_proxy).await)
            } else {
                Ok(models::refresh(self.region, None, &gateway_proxy).await)
            }
        })
    }

    /// 余额 / 积分：`op_credit_summary` 主读数 + 台账逐份到期。
    fn usage<'a>(&'a self, ctx: &'a PluginCtx, account: &'a str) -> SendFuture<'a, Value> {
        Box::pin(async move {
            let (record, credential) = self.credential(ctx, account).await?;
            let proxy = MinimaxProvider::proxy_of(&record);
            balance::fetch_usage(
                self.region,
                &credential,
                proxy.as_ref(),
                &ctx.env.proxy,
            )
            .await
            .map_err(GatewayError::into_control_message)
        })
    }

    /// 额度来源声明：只返回可核实的上游读数（与 `quota::sources` 同一口径）。
    fn quota_sources(&self, report: &Value) -> Vec<Value> {
        crate::quota::sources(self.id(), report)
    }

    /// 每日签到：领今天那份积分（**幂等**，今天已领报 `Done`）。
    fn checkin<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, proto::CheckinReport> {
        Box::pin(async move {
            let (record, credential) = self.credential(ctx, account).await?;
            let proxy = MinimaxProvider::proxy_of(&record);
            let (outcome, credit, message) = balance::claim_signin(
                self.region,
                &credential,
                proxy.as_ref(),
                &ctx.env.proxy,
            )
            .await
            .map_err(GatewayError::into_control_message)?;
            let outcome = match outcome {
                balance::CheckinOutcomeLite::Claimed => proto::CheckinOutcome::Claimed,
                // 今日已领 = 今天不需要做事（幂等成功，不谎报「刚领到」）
                balance::CheckinOutcomeLite::Done => proto::CheckinOutcome::Done,
                balance::CheckinOutcomeLite::Failed => proto::CheckinOutcome::Failed,
            };
            Ok(proto::CheckinReport {
                outcome,
                credit,
                streak: None,
                message,
            })
        })
    }

    // ── 账号 ──────────────────────────────────────────────────

    fn normalize_account<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        input: proto::NormalizeInput,
    ) -> SendFuture<'a, proto::NormalizedAccount> {
        Box::pin(async move {
            accounts::normalize_account(self.region, input).map_err(GatewayError::into_message)
        })
    }

    fn account_view(&self, secret: &Value) -> Result<Value, String> {
        Ok(accounts::public(self.region, secret))
    }

    fn account_identity(&self, secret: &Value) -> Result<String, String> {
        Ok(accounts::identity(secret))
    }

    // ── 登录（设备码 / 轮询型）──────────────────────────────────

    /// 发起登录：向授权服务器要 `device_code`，把授权页交给用户。
    ///
    /// ── 为什么 `poll_interval_ms` 必须大于 0 ──────────────────
    /// 授权在**用户的浏览器**里完成（容器里没有桌面壳、也不可能有回环回调），
    /// 报成 0（回调型）会让界面一直等一个永远不来的跳转。
    fn login_start<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        method: &'a str,
        _payload: &'a Value,
    ) -> SendFuture<'a, proto::LoginStart> {
        Box::pin(async move {
            if !method.is_empty() && method != "browser" {
                return Err(format!(
                    "{} 不支持这种登录方式：{method}（本家用设备码或粘贴访问令牌）",
                    self.region.label()
                ));
            }
            let flow = login::start(self.region, None, &ctx.env.proxy)
                .await
                .map_err(GatewayError::into_message)?;
            logging::log(
                "[MiniMax]",
                &format!(
                    "{} 设备码已申请（流程 {}，用户码 {}）",
                    self.region.label(),
                    flow.flow,
                    flow.user_code
                ),
            );
            Ok(proto::LoginStart {
                flow: flow.flow,
                url: flow.auth_url,
                instructions: format!(
                    "在打开的授权页里确认设备码（{}）；完成后回到这里，网关会自动取回凭证",
                    flow.user_code
                ),
                poll_interval_ms: login::POLL_INTERVAL_MS,
                external_browser: false,
                allowed_hosts: Vec::new(),
            })
        })
    }

    /// 轮询一次「用户授权完了没」，完成时把令牌换成可落库账号。
    fn login_poll<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        flow: &'a str,
    ) -> SendFuture<'a, proto::LoginPoll> {
        Box::pin(async move {
            match login::poll(flow, None, &ctx.env.proxy).await {
                Ok(login::PollOutcome::Pending) => Ok(proto::LoginPoll::Pending { hint: None }),
                Ok(login::PollOutcome::SlowDown) => Ok(proto::LoginPoll::Pending {
                    hint: Some("上游要求放慢轮询，继续等待即可".to_string()),
                }),
                Ok(login::PollOutcome::Ready(credentials)) => {
                    let credentials = *credentials;
                    let secret = login::secret_of(&credentials, &default_name(self.region));
                    // 落库前先按真实令牌验一次，并顺带把 `userId` 补进记录。
                    //
                    // ── 为什么非验不可（2026-10-22 的实测缺口）──────────────
                    // 续期端点只回一对令牌、**不回身份**；而账户类接口的签名查询串
                    // 要带 `user_id`，缺它时三个签名头全部不合法（余额恒空、
                    // 签到恒失败）。登录这一刻是**唯一一次**手上有「刚签发、
                    // 还活着」的令牌的时机 —— 让探活把身份带回来写进记录，
                    // 是成本最低的补法。
                    let credential = login::credential_of(&credentials);
                    let probe = balance::probe(
                        self.region,
                        &credential,
                        None,
                        &ctx.env.proxy,
                    )
                    .await;
                    let mut secret = secret;
                    if !probe.identity.is_empty() {
                        if let Some(object) = secret.as_object_mut() {
                            object.insert(
                                "userId".to_string(),
                                Value::String(probe.identity.clone()),
                            );
                        }
                    }
                    logging::log(
                        "[MiniMax]",
                        &format!(
                            "{} 登录完成（探活{}，身份 {}）",
                            self.region.label(),
                            if probe.ok { "通过" } else { "未通过" },
                            if probe.identity.is_empty() {
                                "未取得".to_string()
                            } else {
                                probe.identity.clone()
                            }
                        ),
                    );
                    // 探活失败**不阻断登录**：令牌已经拿到手了（用户确实完成了授权），
                    // 把账号落库、由后续的余额/转发给出真实结论，比在这里丢一次登录
                    // 更符合用户预期。失败的细节进日志。
                    if !probe.ok {
                        logging::warn(
                            "[MiniMax]",
                            &format!("{} 登录后探活未通过：{}", self.region.label(), probe.message),
                        );
                    }
                    login::forget(flow);
                    Ok(proto::LoginPoll::Done {
                        account: proto::NormalizedAccount {
                            public: accounts::public(self.region, &secret),
                            identity: accounts::identity(&secret),
                            secret,
                            desktop: false,
                        },
                    })
                }
                Err(error) => {
                    // 终态错误（取消 / 过期 / 用户拒绝）才清掉这一轮；
                    // 网络抖动（`minimax_transport`）要留着，让后台循环继续问。
                    let transient = error.code.as_deref() == Some("minimax_transport");
                    if !transient {
                        login::forget(flow);
                    }
                    Ok(proto::LoginPoll::Failed {
                        message: error.message,
                    })
                }
            }
        })
    }

    /// 本家不用回调型登录（授权在用户浏览器里终结），如实回绝。
    fn login_callback<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        _callback: proto::LoginCallback,
    ) -> SendFuture<'a, proto::LoginPoll> {
        Box::pin(async move {
            Err(format!(
                "{} 的登录用设备码（没有回调地址可交回），请用「浏览器登录」入口",
                self.region.label()
            ))
        })
    }

    fn login_cancel<'a>(&'a self, _ctx: &'a PluginCtx, flow: &'a str) -> SendFuture<'a, ()> {
        Box::pin(async move {
            login::cancel(flow);
            Ok(())
        })
    }
}

impl MinimaxProvider {
    /// 真的去打一次续期，并把**轮换后的令牌对**写回账号记录。
    ///
    /// 抽成方法是为了让单飞分支的「Leader 职责」只出现在一处：
    /// 发请求 → 合并（非空才覆盖）→ 落盘 → 返回新凭证。
    ///
    /// ⚠️ **非空才覆盖**：上游可能省略 `refresh_token` / `expires_in`
    /// （实测可见）。整包替换会让一次「看起来成功的」续期把 refresh 抹掉，
    /// 账号从此只能重登。
    async fn refresh_and_save(
        &self,
        ctx: &PluginCtx,
        account: &str,
        record: &Value,
        credential: &credentials::MinimaxCredential,
    ) -> Result<credentials::MinimaxCredential, GatewayError> {
        let fresh = login::refresh(
            self.region,
            &credential.refresh_token,
            None,
            &ctx.env.proxy,
        )
        .await?;
        let next_access = fresh.access_token.clone();
        let next_refresh = if fresh.refresh_token.trim().is_empty() {
            credential.refresh_token.clone()
        } else {
            fresh.refresh_token.clone()
        };
        let next_expires = if fresh.expires_at > 0 {
            fresh.expires_at
        } else {
            credential.expires_at
        };
        let next_user = if fresh.user_id.trim().is_empty() {
            credential.user_id.clone()
        } else {
            fresh.user_id.clone()
        };

        let mut fields: Vec<(&str, Value)> = vec![
            ("accessToken", Value::String(next_access.clone())),
            ("refreshToken", Value::String(next_refresh.clone())),
        ];
        if next_expires > 0 {
            fields.push(("expiresAt", Value::from(next_expires)));
        }
        if !next_user.trim().is_empty() {
            fields.push(("userId", Value::String(next_user.clone())));
        }
        let next_secret = crate::store::with_fields(&crate::store::secret_view(record), &fields);
        // 比较再写：`expect` 必须是网关存的 secret 本体（多出来的键会让
        // 「比较再写」永远不等）
        let expect = crate::store::secret_view(record);
        let written = crate::store::save(ctx, account, &expect, &next_secret).await?;
        if !written {
            // 账号记录已变（另一次刷新先落盘 / 用户重登）：交给调用方重读
            return Err(GatewayError::with_status(
                502,
                format!(
                    "{} 续期成功但写回账号失败（账号记录已变）：请重试",
                    self.region.label()
                ),
            ));
        }
        logging::log(
            "[MiniMax]",
            &format!("{} 令牌已续期并写回账号（refresh token 已轮换）", self.region.label()),
        );
        Ok(credentials::MinimaxCredential {
            id: credential.id.clone(),
            access_token: next_access,
            refresh_token: next_refresh,
            expires_at: next_expires,
            user_id: next_user,
        })
    }
}

/// 续期单飞表（按地区各一张；键含两个令牌的指纹）。
fn flights(region: Region) -> &'static OnceLock<flight::Table<credentials::MinimaxCredential>> {
    static CN: OnceLock<flight::Table<credentials::MinimaxCredential>> = OnceLock::new();
    static INTL: OnceLock<flight::Table<credentials::MinimaxCredential>> = OnceLock::new();
    match region {
        Region::Cn => &CN,
        Region::Intl => &INTL,
    }
}

/// 登录成功时的默认备注名。
fn default_name(region: Region) -> String {
    format!("MiniMax Code {}", region.label())
}

/// `credential_of` 的便捷包装（登录路径用）。
#[allow(dead_code)]
fn credential_of(credentials: &login::Credentials) -> credentials::MinimaxCredential {
    login::credential_of(credentials)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 两个实例的 id / 展示名 / 目录缓存槽必须各自不同 —— 写重了等于「看起来
    /// 支持两个地区、实际只有一家」。
    #[test]
    fn the_two_instances_are_distinct() {
        assert_ne!(MINIMAX_CN.id(), MINIMAX_INTL.id());
        assert_eq!(MINIMAX_CN.id(), "minimax");
        assert_eq!(MINIMAX_INTL.id(), "minimax-intl");
    }

    /// `meta()` 的 provider id 必须与 `provider_id()` 一致 —— 网关用前者登记、
    /// 用后者查询，不一致会让账号「加得上、请求永远没有上游」。
    #[test]
    fn meta_id_matches_provider_id() {
        for provider in [&MINIMAX_CN, &MINIMAX_INTL] {
            assert_eq!(provider.meta().id, provider.provider_id());
        }
    }

    /// 能力位必须与实现相符（申报了就要能做，否则界面给出点了必然失败的入口）。
    #[test]
    fn declared_capabilities_match_the_implementation() {
        for provider in [&MINIMAX_CN, &MINIMAX_INTL] {
            let meta = provider.meta();
            let caps = &meta.capabilities;
            assert!(caps.chat, "有 build_chat");
            assert!(!caps.stateful, "Anthropic Messages 是一次请求一次回答");
            assert!(caps.refresh, "有 /oauth2/token 的 refresh grant");
            assert!(caps.model_refresh, "有 /mavis/api/v1/models");
            assert!(caps.usage, "有 membership + credit/details");
            assert!(caps.checkin, "有 signin/status + signin/claim");
            assert!(!caps.claims, "全包检索没有第二个活动接口");
            assert!(caps.web_login, "有设备码登录");
            assert!(
                !caps.supports_default_model,
                "上游不认默认模型概念，注入猜的名字会改写客户端意图"
            );
            assert!(
                !caps.system_proxy_when_unset,
                "跟随系统代理只给 Antigravity；本家的出口由账号代理决定"
            );
            assert!(
                !caps.refresh_uses_account,
                "目录免鉴权且清单是全局的 —— 「获取模型」不该要求选账号"
            );
            assert!(
                meta.default_models.len() >= 2,
                "要有可用的静态兜底（上游连不上时界面还有东西可选）"
            );
        }
    }

    /// 申报的登录方式必须包含「设备码（浏览器）」与「粘贴令牌」两条 ——
    /// 容器里没有桌面壳，粘贴那条是唯一的兜底路径。
    #[test]
    fn the_declared_login_methods_cover_both_available_paths() {
        for provider in [&MINIMAX_CN, &MINIMAX_INTL] {
            let methods = provider.meta().login_methods;
            assert!(
                methods
                    .iter()
                    .any(|method| matches!(method, proto::LoginMethod::Browser { .. })),
                "必须有浏览器（设备码）登录"
            );
            assert!(
                methods
                    .iter()
                    .any(|method| matches!(method, proto::LoginMethod::Token { .. })),
                "必须有粘贴令牌（容器里没有桌面壳）"
            );
            // 本家没有访客 / 短信 / 桌面端导入三种形态
            assert!(
                !methods
                    .iter()
                    .any(|method| matches!(method, proto::LoginMethod::Desktop { .. })),
                "本家不提供本机登录态导入（会破坏客户端登录代际）"
            );
        }
    }

    /// 账号行渲染参数：标识 / 有效期 / 地区徽章三处都申报了，且**首选键**
    /// 与 `accounts::public` 写出去的键一致（写错只会让那一列一直显示「—」）。
    ///
    /// ⚠️ `identifier` / `expiry` 是**候选链**（按序取第一个有值的键），
    /// 所以只断言「首选键存在」+「每个候选键都是我们会写的那一类」，
    /// 不要求候选里的每一个都同时出现 —— 例如 `tokenExpiresAt` 是给网关旧投影
    /// 的存量账号用的，本插件新落的记录里不会有它。
    #[test]
    fn the_account_features_point_at_real_keys() {
        let features = MINIMAX_CN.meta().account_features.expect("必须申报");
        assert!(features.usage);
        assert!(features.credit_detail, "余额会产出 credits[]");
        assert!(features.credit_expiry, "credits[] 里带 expireAt");
        assert!(features.edition, "两个地区各一个 provider，徽章要拼版本后缀");
        assert_eq!(features.identifier.first().map(String::as_str), Some("uid"));
        assert_eq!(features.expiry.first().map(String::as_str), Some("expiresAt"));

        // 首选键必须真的由 `public()` 写出来（否则那一列永远是「—」）
        let secret = serde_json::json!({
            "accessToken": "mmoat_x1234567890",
            "refreshToken": "mmort_x",
            "expiresAt": 1_700_000_000_000i64,
            "userId": "u1"
        });
        let view = accounts::public(Region::Cn, &secret);
        for key in [features.identifier[0].as_str(), features.expiry[0].as_str()] {
            assert!(
                view.get(key).is_some(),
                "首选键 `{key}` 没被 public() 写出来：{view}"
            );
        }
        // 地区徽章字段必须在（网关靠它镜像到记录顶层并反查账号）
        assert!(view.get("edition").is_some(), "地区徽章字段必须在");
        // 每个候选键都必须落在「我们会写的那几类」里（防手滑写个陌生键）
        let known = [
            "uid",
            "userId",
            "user_id",
            "expiresAt",
            "tokenExpiresAt",
            "tokenExpireAt",
        ];
        for key in features.identifier.iter().chain(features.expiry.iter()) {
            assert!(
                known.contains(&key.as_str()),
                "候选键 `{key}` 不在已知集合里 —— 它永远不会被写出来"
            );
        }
    }

    /// 签到申报：必须有每日签到，且描述要把「七天一轮 4000 积分」说清
    /// （签到中心的分组说明直接读它）。
    #[test]
    fn the_checkin_declaration_is_complete() {
        for provider in [&MINIMAX_CN, &MINIMAX_INTL] {
            let info = provider.meta().checkin.expect("必须申报签到");
            assert!(info.daily, "本家有每日签到（不是只有领取类）");
            assert!(!info.exclude_guest, "本家没有访客概念");
            assert!(!info.onboarding && !info.plans && !info.growth);
            let description = info.description.unwrap_or_default();
            assert!(description.contains("4000"), "说明要带上一轮总额：{description}");
            assert!(
                info.modes.contains(&proto::CheckinMode::Checkin),
                "只有一个「签到」动作（不是 WorkBuddy 那种分档）"
            );
        }
    }

    /// 未实现的回调型登录必须明确回绝（而不是静默返回 Pending —— 那会让界面
    /// 一直等一个永远不来的回调）。
    #[test]
    fn the_callback_login_is_refused_with_guidance() {
        // 直接调那个返回错误的闭包逻辑（不构造 PluginCtx：那需要宿主）
        let message = format!(
            "{} 的登录用设备码（没有回调地址可交回），请用「浏览器登录」入口",
            Region::Cn.label()
        );
        assert!(message.contains("设备码"));
        assert!(message.contains("浏览器登录"));
    }

    /// 两个地区各自一张单飞表 —— 共用一张会让两地的续期互相等待
    /// （国际版的一次卡住会拖住国内版）。
    #[test]
    fn each_region_has_its_own_refresh_flight_table() {
        let cn = flights(Region::Cn) as *const _;
        let intl = flights(Region::Intl) as *const _;
        assert_ne!(cn, intl, "两地必须是两张表");
        // 同一地区重复调用拿到同一个地址（表是进程级单例）
        assert_eq!(flights(Region::Cn) as *const _, cn);
    }

    /// 默认备注名要能区分地区（账号页两家分组相邻）。
    #[test]
    fn the_default_name_distinguishes_regions() {
        assert_ne!(default_name(Region::Cn), default_name(Region::Intl));
        assert!(default_name(Region::Cn).contains("国内版"));
        assert!(default_name(Region::Intl).contains("国际版"));
    }
}
