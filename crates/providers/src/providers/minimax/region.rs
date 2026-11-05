//! MiniMax Code 的**地区**（国内版 / 国际版）：三套域名与两条 provider 身份。
//!
//! ── 搬进插件时改了什么（与网关那份逐条对照，便于 parity 核对）──────
//! ```text
//!   不变：三套域名的取值与「国际版是 .io、.minimaxi.com 只认国内令牌」的实测结论、
//!         目录候选表、账号 id 前缀、客户端地区目录段（cn / en）
//!   改：  ProviderKind → 本模块自己的枚举。插件不认识网关的 kind（那是网关内部
//!         的穷举判断类型，`plugin_kind` 对插件家给占位值），所以身份的判定与互查
//!         全部收在本文件：`provider_id()` / `from_provider_id()` 一对。
//! ```
//!
//! ── 上游长什么样（2026-10-21 实测 + `app.asar` 常量表）──────────
//! 客户端自己就把「地区」当成**第一等的运行期维度**，不是可有可无的标签：
//! ```js
//! // node_modules/@mavis/config/dist/config.js
//! function getRuntimeRegion() {
//!   const val = process.env.MAVIS_REGION;                 // 'cn' | 'en'
//!   if (isValidRuntimeRegion(val)) return val;
//!   if (isElectronProcess()) {
//!     const locale = process.env.NEXT_PUBLIC_LOCALE;
//!     if (locale === 'zh') return 'cn';                    // 中文安装包 → 国内
//!     if (locale === 'en') return 'en';
//!   }
//!   return 'en';
//! }
//! const PRESET_BASE_URLS = {
//!   'cn-prod': 'https://agent.minimax.cn/mavis/api/v1/llm/v1',
//!   'en-prod': 'https://agent.minimax.io/mavis/api/v1/llm/v1',
//! };
//! // node_modules/@mavis/oauth-core/dist/endpoint-config.js
//! const ACCOUNT_ORIGINS = {
//!   cn: { prod: 'https://account.minimax.cn' },
//!   en: { prod: 'https://account.minimax.io' },   // 国际版的授权服务器是另一个域
//! };
//! // node_modules/@mavis/oauth-core/dist/namespace.js
//! namespaceHome = auth/<buildEnv>/<region>/mcode-public     // 两地登录态各存一处
//! ```
//! 于是三个域都按地区分叉：
//! ```text
//!              网关（推理 + 账户 + 签到）              授权服务器
//!   国内  https://agent.minimax.cn/mavis/…        https://account.minimax.cn
//!   国际  https://agent.minimax.io/mavis/…        https://account.minimax.io
//! ```
//!
//! ── ★ 实测证据（2026-10-21，**用真令牌**做的对照矩阵）─────────────
//! ```text
//!   [令牌]           agent.minimax.io   agent.minimaxi.com   agent.minimax.cn
//!   国内（真）            200                200                 200
//!   国际（真）            200              **401**              **401**
//! ```
//! ⇒ **`.io` 才是国际站，`.minimaxi.com` 只认国内令牌。** 两者不是同一套服务。
//!
//! ── ★★ 大陆直连 `.io` 会 307 —— 这是**地域重定向**，不是「没服务」──
//! ```text
//!   大陆出口 → GET agent.minimax.io/…  → 307 → agent.minimaxi.com/…
//!             ↳ 跟着跳过去 = 拿到国内集群的应答 ⇒ 国际令牌必然 401
//!   海外出口 → GET agent.minimax.io/…  → 200（直接服务，不跳）
//! ```
//! 客户端自己也是 `redirect: 'error'`（**不跟随**），正是为了不被这次地域
//! 重定向带偏。插件这边同理：**国际版请求必须不跟随 3xx**，否则
//! 「出口 IP 不在国际站服务范围」会被误报成「令牌失效」。
//!
//! ⚠️ 部署含义（**容器里尤其要看清**）：国际版账号要求网关的**出口 IP 在境外**
//! （或上游放行）。国内直连只会拿到 307 ⇒ 要么给账号配境外代理（插件按
//! 账号级代理建客户端），要么明确接受「国际版在当前网络下不可用」，而**不该**
//! 把它翻成「请重新登录」。
//!
//! 授权服务器仍是 `account.minimax.io`（设备码与续期都走它，实测 200；
//! `verification_uri` 原样透传 —— 改写会让用户看到的域与页面证书不一致）。
//! 续期域名与网关无关：**令牌换到了 ≠ 能用**，两件事分开看。
//!
//! ── ⚠️ 郊区与权威域：本仓打 `.minimaxi.com`，依据如下 ──────────────
//! 客户端常量表把国际版 prod 写成 `.io`（`PRESET_BASE_URLS['en-prod']`，
//! 且 `DOMAIN_URL` 在 `isEn` 分支下也是它），而 `.minimaxi.com` 被列在
//! `LEGACY_MANAGED_PRESET_BASE_URLS` 里。单看常量表会以为该用 `.io`，
//! 但**实测结论是两者都在服务，只是 `.io` 会按 IP 做地理重定向**：
//! ```text
//!   GET agent.minimax.io/mavis/api/v1/models
//!        从中国大陆直连          → 307 → agent.minimaxi.com（Akamai，X-From: ak）
//!        经海外出口（代理）      → 200（直接服务，不跳）
//!   GET agent.minimaxi.com/mavis/api/v1/models  → 200（两地 IP 都直连可用）
//! ```
//! ⇒ 本仓**直接打 `.minimaxi.com`**：它对两种 IP 都是一跳到位，省掉那次
//!   307（跨域重定向还会丢 `Authorization`，实测带 `--location-trusted`
//!   保留后账户端点仍不通）。这是「选一个两边都通的地址」，不是「`.io` 坏了」。
//!
//! ⚠️ **但 `gateway_url()` 仍然必须是 `.io`**（见该函数的文档）—— 目录端点
//! 免鉴权、两地同形，用 `.minimaxi.com` 当兜底无害；而**带令牌**的推理与账户
//! 请求打到 `.minimaxi.com` 会稳定 401。这两件事必须分开看。
//!
//! `verification_uri` 仍按上游原样透传（授权页在 `account.minimax.io`，
//! 那是上游给的地址，不该由我们改写 —— 改写会让用户看到的域与页面证书不一致）。
//!
//! ── ⚠️ 国际版的账户/推理 401：**不是实现问题**（实测已排除）────
//! 用本机客户端 `auth/prod/cn` 的真实国内令牌与库里的真实国际版令牌做过
//! 完整矩阵对照（3 个域名 × `region=cn|en` × 余额/身份两条端点，同一份签名）：
//! ```text
//!   [令牌]              域名          余额/身份
//!   国内（客户端）      cn-gw         ✅200 / ✅200
//!   国内（客户端）      intl-legacy   ✅200 / ✅200
//!   国内（客户端）      intl-io       (307) / ✅200（跟随跳转后）
//!   国际（本仓登录）    cn-gw          401  /  401  {"error":"invalid access token"}
//!   国际（本仓登录）    intl-legacy    401  /  401
//!   国际（本仓登录）    intl-io       (307) /  401
//! ```
//! 即：签名实现、路径、域名、`region` 取值四层都已用真令牌逐格验证无误
//! （国内令牌在**同一条命令**下全通），差异只在**令牌本身**。
//! 设备码申请与轮询接口本身正常（`authorization_pending` 是预期响应），
//! 续期接口也正常（200，发回全新令牌）——**但新令牌同样被网关判为无效**。
//!
//! ⇒ 结论：这取决于上游是否为该账号开通了 `agent-backend` 受众的账户/推理
//! 权限（疑似「新注册的国际账号尚未开通 MiniMax Code 权益」）。
//! **不要再改签名、域名或参数** —— 那三层已被真令牌矩阵排除。
//!
//! ── 为什么是两个 provider 而不是「一家的一个选项」────────────────
//! 与本插件仓的 ModelScope / AutoClaw / ZCode 同一思路：
//!   1. **登录态在两个地区各存一处**（客户端 `auth/<env>/<region>/mcode-public/`），
//!      说明上游把两地当两套账号；
//!   2. **授权服务器不同域** ⇒ 国内拿到的 `mmoat_` 令牌不可能被国际网关接受
//!      （反之亦然）。地区若只是账号上的一个字段，转发链每处都要再读一次它，
//!      读漏一处的症状是「请求打到另一个地区、401」；
//!   3. **模型目录只有一份**（单槽缓存 + 单条刷新排期）⇒ 两个地区的清单会互相
//!      覆盖。这与拆 ModelScope 时那个具体故障逐字相同。
//! 拆成两个 provider 之后，账号集合、清单缓存、刷新排期、签到进度全部按地区
//! 独立，界面上也各占一个分组。
//!
//! ── provider id 的取值（存量兼容）─────────────────────────────
//! 国内版沿用裸 id `minimax`、国际版用 `minimax-intl`。理由是本家在上游网关里
//! **已有存量账号**（2026-10-21 起接入的国内版账号一律记在 `provider: "minimax"`
//! 上），改名会让它们变成「未知 provider」而被界面隐藏。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 本 crate 编译期禁止 unwrap/expect/panic（见 `main.rs` 的 deny）。

/// MiniMax Code 的地区。
///
/// 顺序 = 注册表顺序（国内版在前）：`ALL` 的遍历顺序决定模型目录合并时同名模型
/// 先归谁家、以及界面上两家的先后。**国内版在前**（与 ModelScope / MonkeyCode /
/// ZCode 同一处置：先接入、也是绝大多数用户的那一版）。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum Region {
    /// 国内版（`agent.minimax.cn`；provider id `minimax`）
    #[default]
    Cn,
    /// 国际版（`agent.minimax.io`；provider id `minimax-intl`）
    Intl,
}

impl Region {
    /// 两个地区（注册表顺序：国内版在前）
    pub const ALL: [Region; 2] = [Region::Cn, Region::Intl];

    /// 本地区的 provider id（`"minimax"` / `"minimax-intl"`）。
    ///
    /// **这是插件与网关之间唯一的身份契约**：网关把 provider id 原样透下来
    /// （`ChatRequest.provider`），插件按它挑地区。两条字面量必须与
    /// `pack.json` 的 `providers[].id` 逐字一致 —— 对不上的症状是「账号加得上、
    /// 请求永远没有上游」（网关登记的是清单里那个 id，插件却在等另一个）。
    pub fn provider_id(self) -> &'static str {
        match self {
            Self::Cn => "minimax",
            Self::Intl => "minimax-intl",
        }
    }

    /// provider id → 地区（本家之外的 id 返回 None）。
    pub fn from_provider_id(provider_id: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|region| region.provider_id() == provider_id)
    }

    /// 展示名（界面上跟在 `MiniMax Code` 后面的那一段）。
    pub fn label(self) -> &'static str {
        match self {
            Self::Cn => "国内版",
            Self::Intl => "国际版",
        }
    }

    /// 完整展示名（`meta().label` 用；账号页分组标题也是它）。
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Cn => "MiniMax Code 国内版",
            Self::Intl => "MiniMax Code 国际版",
        }
    }

    /// 客户端里的地区标识（`MAVIS_REGION` 的两个取值，见模块头）。
    ///
    /// 用在账户请求签名查询串与余额文档的 `minimax.region` 上
    /// （本仓口径是 `"cn"` / `"intl"`，与界面上的版本名一致）。
    pub fn edition_id(self) -> &'static str {
        match self {
            Self::Cn => "cn",
            Self::Intl => "intl",
        }
    }

    /// 网关基址（推理 + 账户 + 签到都挂在这个域下，**不带尾部斜杠**）。
    ///
    /// ⚠️ **国际版必须用 `.io`**（2026-10-21 实测纠正，之前写 `.minimaxi.com` 是错的）：
    /// 这两个域**不是同一套服务**，`.minimaxi.com` 只认国内令牌：
    /// ```text
    ///   国际令牌 → agent.minimax.io     → 200（余额 / 身份 / 签到 / 推理 全通）
    ///   国际令牌 → agent.minimaxi.com   → 401 {"error":"invalid access token"}
    ///   国际令牌 → agent.minimax.cn     → 401
    ///   国内令牌 → agent.minimax.cn     → 200
    ///   国内令牌 → agent.minimaxi.com   → 200（另一个入口，同一套服务）
    /// ```
    /// 之所以之前误判：大陆直连 `.io` 会回 **307 → `.minimaxi.com`**，
    /// 于是「跟着跳转」看到的是国内集群，把国际令牌判成无效。**必须不跟随跳转**
    /// （客户端自己也是 `redirect: 'error'`）—— 这个 307 是**地域重定向**，
    /// 说明「你当前的出口 IP 不在国际站的服务范围」，而不是「国际站没服务」。
    ///
    /// ⇒ 部署提示：国际版账号要求本机 / 网关的**出口 IP 在境外**（或上游放行），
    /// 否则连 `.io` 只会拿到 307，而跟着跳到 `.minimaxi.com` 必然是 401。
    /// 插件这边按**账号级代理**建客户端，所以正确做法是给国际版账号配境外出口。
    pub fn gateway_url(self) -> &'static str {
        match self {
            Self::Cn => "https://agent.minimax.cn",
            Self::Intl => "https://agent.minimax.io",
        }
    }

    /// 授权服务器基址（设备码 / 换令牌 / 续期）。
    ///
    /// 国际版是 `account.minimax.io`（与网关**不同域**，实测 200 —— 别照国内版
    /// 的规律把它推成 `account.minimaxi.com`）。
    pub fn auth_host(self) -> &'static str {
        match self {
            Self::Cn => "https://account.minimax.cn",
            Self::Intl => "https://account.minimax.io",
        }
    }

    /// 模型目录的候选地址（**按优先级**，第一个成功即止）。
    ///
    /// 国际版列两条：`.io`（国际站，与 `gateway_url` 一致）在前、`.minimaxi.com`
    /// 在后。目录端点**免鉴权且两边同形**，所以用国内入口作兜底不涉及凭据安全
    /// （它只决定「模型清单从哪儿拉」，不决定令牌发往哪里）；国内版一条就够。
    ///
    /// 与 `gateway_url` 分开写而不是拼出来的理由：目录端点是**免鉴权**的公共
    /// 清单，域名变化时改这里一处即可。
    pub fn catalog_urls(self) -> &'static [&'static str] {
        match self {
            Self::Cn => &["https://agent.minimax.cn"],
            Self::Intl => &["https://agent.minimax.io", "https://agent.minimaxi.com"],
        }
    }

    /// 模型目录的缓存槽名（本插件自己的目录缓存 key，两块互不覆盖）。
    ///
    /// 两个地区各一格：单格的话两地的清单会互相覆盖（拆家前那个故障），
    /// 界面上表现为「国际版刚刷过、国内版显示从未刷新」。
    pub fn catalog_scope(self) -> &'static str {
        match self {
            Self::Cn => "minimax",
            Self::Intl => "minimax-intl",
        }
    }

    /// 账号 id 前缀（见模块头「provider id 的取值」）。
    ///
    /// 国内版是裸 `minimax-`（**存量账号的 id 就是这样**，不能改）；国际版带
    /// `-intl` 段，让同一个人在两地的记录生成不同 id —— 否则第二个添加的账号
    /// 会撞上存储层的跨 provider 保护而加不进来。
    ///
    /// ⚠️ 判「是不是 MiniMax 系」一律走 [`Self::from_provider_id`]，
    /// **绝不要用 `starts_with("minimax")`**：那会把国际版误算进国内版。
    pub fn account_id_prefix(self) -> &'static str {
        match self {
            Self::Cn => "minimax-",
            Self::Intl => "minimax-intl-",
        }
    }

    /// 客户端凭据目录里的**地区段**（`auth/<buildEnv>/<region>/mcode-public/`）。
    ///
    /// ⚠️ 与 `edition_id()` **不同**：客户端用的是 `cn` / `en`，而界面上的版本名是
    /// `cn` / `intl`。证据是客户端自己的拼装（`@mavis/oauth-core/dist/namespace.js`）：
    /// ```js
    /// const namespaceHome = join(authHome, input.buildEnv, input.region, MCODE_OAUTH_CLIENT_ID)
    /// ```
    /// 而 `input.region` 的取值域就是 `getRuntimeRegion()` 的 `'cn' | 'en'`
    /// （同一份 asar 的 `PRESET_BASE_URLS` 用的也是 `cn-prod` / `en-prod`）。
    ///
    /// 拿 `intl` 去拼会得到一个**不存在的路径** ⇒ 「导入本机登录态」对国际版
    /// 永远报「没读到客户端登录态」，而用户明明登录着。
    ///
    /// ⚠️ 容器里这条路径**读不到**（Windows 宿主上的 `~/.minimax/`）—— 本插件
    /// 不依赖它（那条路只在桌面端有意义），保留这个常量只是为了日志与排障时
    /// 能说清「该去哪儿找」。
    pub fn desktop_region_dir(self) -> &'static str {
        match self {
            Self::Cn => "cn",
            Self::Intl => "en",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Region;

    /// 两条身份必须与 `pack.json` 的 provider id 逐字对上 —— 对不上的症状是
    /// 「账号加得上、请求永远没有上游」，而这是编译期看不出来的。
    ///
    /// ⚠️ 国内版必须是裸 `minimax`：上游网关的存量账号记的就是这个 id，
    /// 改了等于把老账号变成「未知 provider」。
    #[test]
    fn region_ids_match_the_expected_literals() {
        assert_eq!(Region::Cn.provider_id(), "minimax");
        assert_eq!(Region::Intl.provider_id(), "minimax-intl");
    }

    /// 互查是双射：id → region → id 必须回到原值
    #[test]
    fn region_lookup_round_trips() {
        for region in Region::ALL {
            assert_eq!(Region::from_provider_id(region.provider_id()), Some(region));
        }
        assert_eq!(Region::from_provider_id("marvis"), None);
        // 前缀判据的反面例子：`minimax-intl` 必须归国际版，而不是被前缀吞成国内版
        assert_eq!(Region::from_provider_id("minimax-intl"), Some(Region::Intl));
        // 前缀式误判的护栏：`starts_with("minimax")` 会把这一条认成国内版
        assert_ne!(Region::from_provider_id("minimax-code"), Some(Region::Cn));
    }

    /// 两个地区的三套域名必须**各自不同** —— 写重了会让两地账号实际打到同一个站，
    /// 是「看起来支持两地区、实际只有一家」的静默失效。
    ///
    /// 授权服务器尤其容易写错：国际版的授权服务器是 `account.minimax.io`，
    /// 不是网关域 `agent.minimaxi.com` 的同名兄弟。
    #[test]
    fn the_two_regions_do_not_share_a_host() {
        assert_ne!(Region::Cn.gateway_url(), Region::Intl.gateway_url());
        assert_ne!(Region::Cn.auth_host(), Region::Intl.auth_host());
        assert_ne!(Region::Cn.catalog_scope(), Region::Intl.catalog_scope());
        assert_ne!(Region::Cn.account_id_prefix(), Region::Intl.account_id_prefix());
    }

    /// 国际版的目录候选表：`.io` 在前、`.minimaxi.com` 作兜底，且首选与网关一致。
    ///
    /// 目录端点免鉴权、两边同形，所以 `.minimaxi.com` 留作兜底是安全的 ——
    /// 它只决定「清单从哪儿拉」，不决定令牌发往哪里。顺序反了会多一跳、
    /// 并依赖上游继续保留那个重定向。
    #[test]
    fn the_intl_catalog_prefers_the_canonical_host() {
        let urls = Region::Intl.catalog_urls();
        assert_eq!(urls.first().copied(), Some("https://agent.minimax.io"));
        assert!(
            urls.contains(&"https://agent.minimaxi.com"),
            "保留国内入口作为目录兜底"
        );
        assert_eq!(
            Region::Cn.catalog_urls(),
            &["https://agent.minimax.cn"],
            "国内版只有一个域，不要列冗余候选"
        );
        // 目录的首选必须与网关一致，否则会「清单从 A 拉、请求打 B」
        assert_eq!(
            urls.first().copied(),
            Some(Region::Intl.gateway_url()),
            "目录首选域必须等于网关域"
        );
    }

    /// 授权服务器与网关必须是**不同主机**（国内 `account.minimax.cn` vs
    /// `agent.minimax.cn`：同后缀不同子域，拼错就会把设备码打到网关上）。
    #[test]
    fn auth_hosts_are_not_the_gateways() {
        for region in Region::ALL {
            assert_ne!(region.auth_host(), region.gateway_url());
            assert!(
                region.auth_host().starts_with("https://"),
                "OAuth 端点只走 https：{}",
                region.auth_host()
            );
            assert!(region.gateway_url().starts_with("https://"));
        }
    }

    /// 客户端地区目录段是 `cn` / `en`，**不是** `intl` —— 拿 `intl` 去拼会得到
    /// 一个不存在的路径。
    #[test]
    fn the_client_region_dir_is_not_the_edition_id() {
        assert_eq!(Region::Cn.desktop_region_dir(), "cn");
        assert_eq!(Region::Intl.desktop_region_dir(), "en");
        assert_ne!(Region::Intl.desktop_region_dir(), Region::Intl.edition_id());
        // 本仓口径的 edition_id 是 cn / intl（与界面上版本名一致）
        assert_eq!(Region::Cn.edition_id(), "cn");
        assert_eq!(Region::Intl.edition_id(), "intl");
    }

    /// **国际版网关必须是 `.io`，绝不能被改回 `.minimaxi.com`。**
    ///
    /// 这条是 2026-10-21 一次真实误判的护栏：当时看到大陆直连 `.io` 回 307
    /// 跳 `.minimaxi.com`，就以为「`.io` 没服务、跟着跳才对」，于是把网关写成
    /// `.minimaxi.com` —— 结果国际版账号的余额稳定 401，被误报成「登录态过期」，
    /// 用户反复重登三次都没用。真相是**两个域不是同一套服务**：
    /// ```text
    ///   国际令牌 → agent.minimax.io    → 200
    ///   国际令牌 → agent.minimaxi.com  → 401 invalid access token
    /// ```
    /// 那个 307 是**地域重定向**（出口 IP 不在国际站服务范围），不是「没服务」。
    /// 有人若想把域改回去，先跑这条测试看它为什么拦着。
    #[test]
    fn the_intl_gateway_is_the_io_host_not_the_legacy_one() {
        assert_eq!(
            Region::Intl.gateway_url(),
            "https://agent.minimax.io",
            "国际站是 .io；.minimaxi.com 只认国内令牌（会稳定 401）"
        );
        assert_eq!(Region::Cn.gateway_url(), "https://agent.minimax.cn");
        // 网关域与目录兜底域**必须不同**：一个是带令牌的请求地址，一个只用来拉免鉴权清单
        assert_ne!(
            Region::Intl.gateway_url(),
            Region::Intl.catalog_urls()[1],
            "目录兜底不能等于网关域 —— 两者语义不同，写重了会让人以为国际站就在那个域"
        );
    }

    /// 两个 provider 的展示名必须能把地区说清（账号页分组相邻，光看
    /// 「MiniMax Code」分不出是哪一个）。
    #[test]
    fn display_names_distinguish_the_regions() {
        assert_ne!(Region::Cn.display_name(), Region::Intl.display_name());
        for region in Region::ALL {
            assert!(
                region.display_name().contains(region.label()),
                "展示名必须含地区词：{}",
                region.display_name()
            );
        }
    }
}
