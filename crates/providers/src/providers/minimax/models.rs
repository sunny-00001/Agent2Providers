//! MiniMax Code 模型目录：`GET /mavis/api/v1/models`（**实测免鉴权**）。
//!
//! ── 上游返回什么（2026-10-21 实测 200）──────────────────────────
//! ```json
//! { "version": "1.0", "ttlSeconds": 300,
//!   "providers": [ { "providerId": "minimax",
//!     "config": { "name": "MiniMax", "npm": "@ai-sdk/anthropic",
//!       "models": {
//!         "MiniMax-M3":          {"name":"M3","attachment":true,"reasoning":true,
//!                                 "tool_call":true,"temperature":true,
//!                                 "limit":{"context":512000,"output":128000},
//!                                 "modalities":{"input":["text","image","video"]},
//!                                 "thinking_config":{"mode":"switchable"}},
//!         "MiniMax-M3.1-Flash":  {… "thinking_config":{"mode":"forced_on"}}
//! } } } ] }
//! ```
//!
//! ── 三个要点（改这份文件前必读）─────────────────────────────
//!   1. **清单在 `config.models` 里，是一条 map 而不是数组** —— `Object.entries`
//!      语义（键就是模型 id）。`providers[]` 里可能还有别的 providerId（客户端
//!      也接 BYOK），只认 `"minimax"`；
//!   2. **这个接口不校验令牌**（实测无 token 也 200）。所以远端拉取不需要账号，
//!      后台刷新在「一个号都没加」时也能跑通 —— 这与别家（必须先有令牌）不同，
//!      也是本家 `/v1/models` 在未登录时就有内容的原因；
//!   3. **必须翻成聚合层键名**（`maxInputTokens` / `supportsImages` /
//!      `supportsReasoning` / `supportsToolCall` / `maxOutputTokens`）——
//!      网关的 `models::shape::list_item` 只认这五个（教训：写 `contextWindow`
//!      会让 512K 上下文与两个能力位整份丢掉）。
//!
//! ── 视频输入为什么只留 text/image ────────────────────────────
//! 上游声明 `["text","image","video"]`，但网关的 `supportsImages` 只有一个布尔位，
//! 下游客户端据此决定「发不发图片」；把 video 当成 image 的等价物会让不支持视频的
//! 客户端也去发视频。
//!
//! ── 两个地区各一格缓存 ──────────────────────────────────────
//! 两地共用同一个目录接口形状、**同一份内容**（实测两地都是 M3 / M3.1-Flash），
//! 但缓存**必须分格**：单格的话谁最后刷新谁的内容留在缓存里，而界面上两个
//! provider 各读各的「上次刷新时刻」 —— 出现「国际版刚刷过、国内版显示从未刷新」
//! 这种自相矛盾的读数。
//!
//! ── 缓存只活在进程内（**为什么不用账号台账**）────────────────────
//! 仓库里给「拉目录要令牌、重启后必须恢复」的家（CodeArts / Accio / Qoder）
//! 提供了 `catalog_ledger`（按账号落进网关的账号库）。本家**不用它**，理由是
//! 接口免鉴权：重启后拉不到真清单时，后台刷新一次就能补上，而静态兜底两条
//! 模型本身可用（不像 CodeArts 那样连兜底都没有 → 重启后全部模型被拒发）。
//! 少一条挂钩就少一处可能不一致的状态。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 本 crate 编译期禁止 unwrap/expect/panic（见 `main.rs` 的 deny）。

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{OnceLock, RwLock};

use agent2api_provider_protocol as proto;
use serde_json::{json, Value};

use crate::logging;

use super::endpoints;
use super::net;
use super::region::Region;

/// 上游 `providers[].providerId`：只收这一家（见模块头第 1 条）。
pub const UPSTREAM_PROVIDER_ID: &str = "minimax";

/// 进程内缓存的清单（远程拉成功后写入，供同步的 `list_models` 读）。两块。
static MANIFEST: OnceLock<RwLock<Vec<Value>>> = OnceLock::new();
static MANIFEST_INTL: OnceLock<RwLock<Vec<Value>>> = OnceLock::new();

/// 最近一次**远程拉取成功**的时刻（毫秒，0 = 从未拉过）。两块。
static LAST_REFRESHED: OnceLock<AtomicI64> = OnceLock::new();
static LAST_REFRESHED_INTL: OnceLock<AtomicI64> = OnceLock::new();

/// 清单来源：远程 / 静态兜底（日志与排障用）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Origin {
    Remote,
    Fallback,
}

fn last_refreshed_store(region: Region) -> &'static AtomicI64 {
    match region {
        Region::Cn => LAST_REFRESHED.get_or_init(|| AtomicI64::new(0)),
        Region::Intl => LAST_REFRESHED_INTL.get_or_init(|| AtomicI64::new(0)),
    }
}

fn manifest_store(region: Region) -> &'static RwLock<Vec<Value>> {
    match region {
        Region::Cn => MANIFEST.get_or_init(|| RwLock::new(Vec::new())),
        Region::Intl => MANIFEST_INTL.get_or_init(|| RwLock::new(Vec::new())),
    }
}

/// 本地区清单是否来自远程。
pub fn remote_refreshed(region: Region) -> bool {
    last_refreshed_store(region).load(Ordering::Relaxed) > 0
}

/// 本地区最近一次远程拉取时刻（毫秒；0 = 从未拉过）。
pub fn last_refreshed_at(region: Region) -> i64 {
    last_refreshed_store(region).load(Ordering::Relaxed)
}

/// 本地区当前清单的来源。
pub fn origin_of(region: Region) -> Origin {
    if remote_refreshed(region) {
        Origin::Remote
    } else {
        Origin::Fallback
    }
}

/// 静态兜底清单（拉不到远端时用，**必须是真能用的**）。
///
/// 两个条目取自 2026-10-21 的线上目录（实测可用），能力位照抄上游声明。
/// 上游 2026-10-19 下架了 M2.7 / M2.7-highspeed，把灰度模型正式发成
/// `MiniMax-M3.1-Flash` —— 兜底只留当前这两条，不列已下架的（列一个点不动的
/// 名字比不列更糟）。
pub fn fallback_manifest() -> Vec<Value> {
    vec![
        model_entry("MiniMax-M3", "M3", 512_000, 128_000, true, true, true, false),
        model_entry(
            "MiniMax-M3.1-Flash",
            "M3.1-Flash",
            512_000,
            128_000,
            true,
            true,
            true,
            true,
        ),
    ]
}

/// 构造一条统一形状的模型记录（键名见模块头第 3 条）。
fn model_entry(
    id: &str,
    label: &str,
    context_window: i64,
    max_output: i64,
    tool_call: bool,
    reasoning: bool,
    images: bool,
    is_default: bool,
) -> Value {
    json!({
        "id": id,
        "object": "model",
        "owned_by": "minimax",
        "name": label,
        "displayName": label,
        "maxInputTokens": context_window,
        "maxOutputTokens": max_output,
        "supportsImages": images,
        "supportsToolCall": tool_call,
        "supportsReasoning": reasoning,
        "isDefault": is_default,
    })
}

/// 同步入口：缓存优先，空则兜底（**按地区读各自的格子**）。
pub fn manifest(region: Region) -> Vec<Value> {
    match manifest_store(region).read() {
        Ok(guard) if !guard.is_empty() => guard.clone(),
        _ => fallback_manifest(),
    }
}

/// `models()` 的返回（含来源与刷新时刻，供网关的目录页展示）。
///
/// `remote` 是「这份清单是不是从上游拉回来的」——界面靠它区分
/// 「上游真清单」与「我们内置的兜底」，两列（来源 / 更新日期）都读它。
pub fn list_report(region: Region) -> proto::ModelList {
    proto::ModelList {
        models: manifest(region),
        meta: proto::CatalogMeta {
            remote: remote_refreshed(region),
            refreshed_at: last_refreshed_at(region),
        },
    }
}

/// 把上游目录响应转成统一形状。
///
/// 只收 `providerId == "minimax"` 的 provider 块；模型 id 必须是
/// `MiniMax-` 前缀（上游可能在同一 map 里塞客户端内部条目，那些发出去会 400）。
fn parse_catalog(body: &Value) -> Vec<Value> {
    let Some(providers) = body.get("providers").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out: Vec<Value> = Vec::new();
    for provider in providers {
        if provider.get("providerId").and_then(Value::as_str) != Some(UPSTREAM_PROVIDER_ID) {
            continue;
        }
        let Some(models) = provider.pointer("/config/models").and_then(Value::as_object) else {
            continue;
        };
        for (id, raw) in models {
            if !id.starts_with("MiniMax-") {
                continue;
            }
            let label = raw
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(id);
            let context_window = raw
                .pointer("/limit/context")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let max_output = raw
                .pointer("/limit/output")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let modalities: Vec<String> = raw
                .pointer("/modalities/input")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let images = modalities.iter().any(|item| item == "image");
            out.push(model_entry(
                id,
                label,
                context_window,
                max_output,
                raw.get("tool_call").and_then(Value::as_bool).unwrap_or(false),
                raw.get("reasoning").and_then(Value::as_bool).unwrap_or(false),
                images,
                false,
            ));
        }
    }
    // ── 顺序：上游 `config.models` 是一张 map，`serde_json` 默认把它解成
    // BTreeMap ⇒ 这里拿到的是**字典序**（`MiniMax-M3` 在 `MiniMax-M3.1-Flash`
    // 前），顺序稳定，可以直接交给界面。
    //
    // `isDefault` 恒 false：本家没有「唯一的默认模型」概念（客户端
    // `defaultModel` 写的是 M3.1-Flash，但那是客户端的选择，用户在我们的
    // 模型管理页里可以各选各的）。这里不猜哪个是默认 —— 猜错会让客户端的
    // 首屏模型与它自己配置文件里的不一致。
    out
}

/// 拉一次目录并落地。返回刷新结果。
///
/// ── 为什么不需要令牌 ────────────────────────────────────────
/// 这个端点实测免鉴权（模块头第 2 条）。所以这里**不取凭证** ——
/// 后台刷新在「一个账号都没加」时也能跑到真清单，而不是永远停在兜底。
///
/// ── 为什么按候选地址逐个试（国际版两条）────────────────────────
/// 国际版首选 `agent.minimax.io`（与 `Region::gateway_url` 一致），
/// `.minimaxi.com` 作为兜底。两者**不是同一套服务**（`.minimaxi.com` 只认国内
/// 令牌），但目录端点免鉴权、两边内容同形，所以这里当兜底是安全的 ——
/// 拿目录只为了模型清单，不涉及凭据。每个候选**各自打一次完整的请求**，
/// 只有拿到合法 JSON 才停 —— 一个 5xx 不该把另一个候选的机会也吃掉。
///
/// 出网走 [`net::request`]（**不跟随 3xx** + 账号代理 → 网关出口 → 直连）：
/// 国际版的目录请求同样可能撞上地域 307，跟过去只会拿到另一个集群的清单。
///
/// ── 失败时不动缓存 ──────────────────────────────────────────
/// 网络抖动不该把一份好用的清单换成空数组（那会让用户「刷新了一下，模型全没了」）。
pub async fn refresh(
    region: Region,
    proxy: Option<&proto::WireProxy>,
    gateway_proxy: &str,
) -> proto::RefreshOutcome {
    let headers = vec![("Accept".to_string(), "application/json".to_string())];
    let mut last_error: Option<String> = None;
    for base in region.catalog_urls() {
        let url = format!("{base}{}", endpoints::CATALOG_PATH);
        let response = match net::request(
            "GET",
            &url,
            None,
            None,
            &headers,
            proxy,
            gateway_proxy,
        )
        .await
        {
            Ok(response) => response,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        if !response.ok {
            logging::warn(
                "[MiniMax]",
                &format!(
                    "模型目录拉取失败（{} {base}）：HTTP {}{}",
                    region.display_name(),
                    response.status,
                    if net::is_redirect(response.status) {
                        "（地域重定向：本机出口 IP 不在该站服务范围）"
                    } else {
                        ""
                    }
                ),
            );
            last_error = Some(format!("HTTP {}", response.status));
            continue;
        }
        let Some(body) = response.payload else {
            last_error = Some("响应不是合法 JSON".to_string());
            continue;
        };
        let entries = parse_catalog(&body);
        if entries.is_empty() {
            last_error =
                Some("清单为空（上游可能调整了 providers[].config.models 结构）".to_string());
            continue;
        }
        let count = entries.len();
        if let Ok(mut guard) = manifest_store(region).write() {
            *guard = entries;
        }
        last_refreshed_store(region).store(logging::now_ms(), Ordering::Relaxed);
        logging::log(
            "[Models]",
            &format!(
                "{} 模型目录已刷新（{count} 个模型，来源 {base}）",
                region.display_name()
            ),
        );
        return proto::RefreshOutcome::refreshed(count);
    }
    let reason = last_error.unwrap_or_else(|| "没有可用的候选地址".to_string());
    logging::warn(
        "[Models]",
        &format!("{} 模型目录刷新失败：{reason}", region.display_name()),
    );
    proto::RefreshOutcome::failed(reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_real_catalog_shape() {
        // 逐字取自 2026-10-21 的线上响应（截短）
        let body = json!({
            "version": "1.0",
            "ttlSeconds": 300,
            "providers": [{
                "providerId": "minimax",
                "config": {
                    "name": "MiniMax",
                    "npm": "@ai-sdk/anthropic",
                    "models": {
                        "MiniMax-M3": {
                            "name": "M3", "attachment": true, "reasoning": true,
                            "tool_call": true,
                            "limit": {"context": 512000, "output": 128000},
                            "modalities": {"input": ["text", "image", "video"], "output": ["text"]},
                            "thinking_config": {"mode": "switchable"}
                        },
                        "MiniMax-M3.1-Flash": {
                            "name": "M3.1-Flash", "attachment": true, "reasoning": true,
                            "tool_call": true,
                            "limit": {"context": 512000, "output": 128000},
                            "modalities": {"input": ["text", "image"], "output": ["text"]}
                        }
                    }
                }
            }]
        });
        let entries = parse_catalog(&body);
        assert_eq!(entries.len(), 2);
        let ids: Vec<&str> = entries.iter().filter_map(|item| item["id"].as_str()).collect();
        assert!(ids.contains(&"MiniMax-M3"));
        assert!(ids.contains(&"MiniMax-M3.1-Flash"));
        // 键名必须是聚合层认的那五个
        let m3 = entries
            .iter()
            .find(|item| item["id"] == json!("MiniMax-M3"))
            .expect("应有 M3");
        assert_eq!(m3["maxInputTokens"], json!(512000));
        assert_eq!(m3["maxOutputTokens"], json!(128000));
        assert_eq!(m3["supportsToolCall"], json!(true));
        assert_eq!(m3["supportsReasoning"], json!(true));
        assert_eq!(m3["supportsImages"], json!(true));
        // 上游键名不能漏进输出（漏了说明只搬了 map 没做映射）
        assert!(m3.get("limit").is_none());
        assert!(m3.get("modalities").is_none());
    }

    /// 视频模态**不能**映射成「支持图片」：网关只有一个布尔位，下游据此决定
    /// 发不发图；把 video 算进去会让不支持视频的客户端也去发视频。
    #[test]
    fn video_modality_does_not_turn_into_image_support() {
        let body = json!({
            "providers": [{"providerId": "minimax", "config": {"models": {
                "MiniMax-video-only": {
                    "name": "v", "limit": {"context": 1, "output": 1},
                    "modalities": {"input": ["text", "video"]}
                }
            }}}]
        });
        let entries = parse_catalog(&body);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["supportsImages"], json!(false));
    }

    #[test]
    fn ignores_other_providers_and_foreign_model_ids() {
        let body = json!({
            "providers": [
                {"providerId": "openai", "config": {"models": {"gpt-4o": {}}}},
                {"providerId": "minimax", "config": {"models": {
                    "MiniMax-M3": {"limit": {"context": 1}},
                    "internal-router": {"limit": {"context": 1}}
                }}}
            ]
        });
        let entries = parse_catalog(&body);
        assert_eq!(entries.len(), 1, "只收 minimax 的 MiniMax-* 条目");
        assert_eq!(entries[0]["id"], json!("MiniMax-M3"));
    }

    #[test]
    fn missing_shape_yields_empty_not_panic() {
        assert!(parse_catalog(&json!({})).is_empty());
        assert!(parse_catalog(&json!({"providers": "nope"})).is_empty());
        assert!(parse_catalog(&json!({"providers": [{"providerId": "minimax"}]})).is_empty());
        assert!(parse_catalog(&Value::Null).is_empty());
    }

    #[test]
    fn fallback_lists_only_the_currently_served_models() {
        // M2.7 系列已下架（2026-10-19），兜底不得再列
        let ids: Vec<String> = fallback_manifest()
            .iter()
            .filter_map(|item| item["id"].as_str().map(str::to_string))
            .collect();
        assert_eq!(ids, vec!["MiniMax-M3", "MiniMax-M3.1-Flash"]);
        // 兜底条目的能力位必须是「真能用」的那一组（点一下就能发请求）
        let flash = fallback_manifest()
            .into_iter()
            .find(|item| item["id"] == json!("MiniMax-M3.1-Flash"))
            .expect("应有 Flash 兜底");
        assert_eq!(flash["supportsToolCall"], json!(true));
        assert_eq!(flash["supportsReasoning"], json!(true));
        assert_eq!(flash["supportsImages"], json!(true));
    }

    /// 两个地区读**各自的**缓存格与「上次刷新时刻」—— 单格的话会互相污染，
    /// 表现为「国际版刷过、国内版显示从未刷新」（见模块头）。
    ///
    /// 只读不写：单测不该往真实状态里落盘，所以这里断言的是
    /// 「两格互相独立且初始状态合法」。
    #[test]
    fn the_two_regions_have_independent_catalog_slots() {
        assert_ne!(Region::Cn.catalog_scope(), Region::Intl.catalog_scope());
        // 兜底清单两地相同（同一份接口形状，实测内容一致）
        assert_eq!(manifest(Region::Cn).len(), manifest(Region::Intl).len());
        assert_eq!(manifest(Region::Cn).len(), fallback_manifest().len());
    }

    /// 清单报告的来源字段必须能把「远程」与「兜底」说清 —— 界面靠它区分
    /// 「这是上游真清单」还是「我们内置的兜底」。
    #[test]
    fn the_report_declares_where_the_list_came_from() {
        let report = list_report(Region::Cn);
        assert_eq!(report.models.len(), fallback_manifest().len());
        // 从未刷新过时 `remote` 必须是 false（进程刚起来的正常状态）
        assert!(
            !report.meta.remote,
            "进程刚起来、没拉过远程，不能报成远程清单"
        );
        // 刷新时刻在没拉过时是 0（界面据此显示「从未刷新」）
        assert_eq!(report.meta.refreshed_at, 0);
    }

    /// `remote_refreshed` / `origin_of` 两个查询必须与报告里的 `remote` 同源
    /// —— 它们都是「这份清单从哪儿来」的读法，答不一致会让界面与日志打架。
    #[test]
    fn the_origin_queries_agree_with_the_report() {
        for region in Region::ALL {
            let report = list_report(region);
            assert_eq!(report.meta.remote, remote_refreshed(region));
            let expected = if report.meta.remote {
                Origin::Remote
            } else {
                Origin::Fallback
            };
            assert_eq!(origin_of(region), expected);
        }
    }
}
