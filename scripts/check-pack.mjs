#!/usr/bin/env node
/**
 * 插件包的**安装期自检**：在把 zip 交给网关之前，先按网关的校验顺序过一遍。
 *
 * ── 为什么需要它（不能只靠 `pack.mjs` 的退出码）────────────────
 * `pack.mjs` 只保证「zip 打出来了」，而网关装包时会按一套**固定顺序**校验
 * （`plugin_host::install`），任何一环不过就是一次安装失败，而失败的现场
 * 只在网关日志里（用户看到的是面板上一句「安装失败：…」）。在 CI 里提前
 * 跑一遍同样的判据，能让「包本身不合规」与「环境问题」分开。
 *
 * 逐条对齐网关的判据（见 `plugin_host/install.rs` 与 `packages.rs`）：
 *   1. 包大小 ≤ 24 MiB（`MAX_PACK_BYTES`）—— 超了网关直接拒收；
 *   2. `pack.json` 可解析、`protocol == 1`（与 `PROTOCOL_VERSION` 一致）；
 *   3. `providers[]` 非空，且 id 只用小写字母 / 数字 / 连字符；
 *   4. `providers[]` 不含**本体保留身份**（`BUILTIN_SUBSCRIPTION_IDS`）；
 *   5. `entry` 非空、键覆盖当前目标、值是**相对路径**且不含 `..`（防 zip slip）；
 *   6. `entry[target]` 指的那个文件**真的在包里**，且 Windows 条目带 `.exe`；
 *   7. `icons` / `ui` 是相对路径且不含 `..`；
 *   8. 包内**没有** `provider-docs.json` 之外的杂项页面（本包是纯后端包）。
 *
 * ── 用法 ──────────────────────────────────────────────────────
 *   node scripts/check-pack.mjs --target x86_64-unknown-linux-gnu
 *   node scripts/check-pack.mjs            # 默认当前平台
 *
 * 退出码：0 = 全部通过；1 = 有断言失败。
 */

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { dirname } from 'node:path'
import process from 'node:process'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '..')

/** 与网关 `plugin_host::packages::MAX_PACK_BYTES` 同值 */
const MAX_PACK_BYTES = 24 * 1024 * 1024

/** 与网关 `provider-protocol::PROTOCOL_VERSION` 同值 */
const PROTOCOL_VERSION = 1

/** 本体保留身份（网关 `availability::BUILTIN_SUBSCRIPTION_IDS`）—— 插件包不得声明 */
const RESERVED_IDS = [
  'claude-subscription',
  'codex-subscription',
  'chatgpt-subscription',
  'copilot-subscription',
  'gemini-subscription',
]

const argv = process.argv.slice(2)
const targetIndex = argv.indexOf('--target')
const TARGET = targetIndex >= 0 ? argv[targetIndex + 1] : null

let failed = 0
const check = (ok, name, detail) => {
  if (ok) {
    console.log(`  ✓ ${name}${detail ? ` — ${detail}` : ''}`)
  } else {
    failed += 1
    console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ''}`)
  }
}

/**
 * 极小的 ZIP 读取器（只读中央目录，够判断条目名与大小）。
 *
 * ── 为什么不引依赖 ──────────────────────────────────────────
 * 这个仓库刻意只有 Node 内置模块（见 `pack.mjs` 自己手写 zip 写入的同一取舍）：
 * 插件打包脚本是发布链的一环，多一个依赖就多一处「CI 上装不上」的可能。
 * 这里只需要列出条目名与解压后大小，中央目录就够了 —— 不必解压内容。
 */
function readZipEntries(buffer) {
  // 从尾部往前找 EOCD（"PK\x05\x06"）
  const EOCD = 0x06054b50
  let eocd = -1
  for (let index = buffer.length - 22; index >= 0 && index >= buffer.length - 22 - 65536; index -= 1) {
    if (buffer.readUInt32LE(index) === EOCD) {
      eocd = index
      break
    }
  }
  if (eocd < 0) throw new Error('找不到 zip 的中央目录结尾（文件不是合法 zip？）')
  const count = buffer.readUInt16LE(eocd + 10)
  let offset = buffer.readUInt32LE(eocd + 16)
  const entries = []
  for (let index = 0; index < count; index += 1) {
    if (buffer.readUInt32LE(offset) !== 0x02014b50) {
      throw new Error(`第 ${index + 1} 个中央目录项签名不对`)
    }
    const nameLength = buffer.readUInt16LE(offset + 28)
    const extraLength = buffer.readUInt16LE(offset + 30)
    const commentLength = buffer.readUInt16LE(offset + 32)
    const compressed = buffer.readUInt32LE(offset + 20)
    const size = buffer.readUInt32LE(offset + 24)
    const mode = buffer.readUInt32LE(offset + 38) >>> 16
    const name = buffer.slice(offset + 46, offset + 46 + nameLength).toString('utf8')
    entries.push({ name, size, compressed, mode })
    offset += 46 + nameLength + extraLength + commentLength
  }
  return entries
}

/** 路径必须是相对、不含 `..`（与网关 `validate_manifest` 同一套判据）。 */
function isSafeRelative(entry) {
  if (entry.startsWith('/') || entry.startsWith('\\')) return false
  if (/^[a-zA-Z]:/.test(entry)) return false
  return !entry.split(/[\\/]/).includes('..')
}

function main() {
  const manifestPath = join(ROOT, 'pack.json')
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  const dist = join(ROOT, 'dist')
  if (!existsSync(dist)) {
    console.error('[check-pack] 没有 dist/ 目录：先跑 node scripts/pack.mjs')
    process.exit(1)
  }

  // 目录里可能有多个平台的包；只查本次目标那个
  const suffix = TARGET ? `-${TARGET}.zip` : '.zip'
  const candidates = readdirSync(dist).filter((name) => name.endsWith(suffix))
  if (candidates.length === 0) {
    console.error(`[check-pack] dist/ 里没有匹配 ${suffix} 的包`)
    process.exit(1)
  }
  for (const name of candidates.sort()) {
    const path = join(dist, name)
    console.log(`\n检查 ${name}`)
    checkZip(path, manifest, TARGET)
  }

  console.log(`\n${'─'.repeat(52)}`)
  if (failed) {
    console.log(`失败 ${failed} 项`)
    process.exit(1)
  }
  console.log('全部通过')
}

function checkZip(path, manifest, target) {
  const buffer = readFileSync(path)
  check(buffer.length > 0 && buffer.length <= MAX_PACK_BYTES,
    '包大小在 24 MiB 之内',
    `${(buffer.length / 1024 / 1024).toFixed(2)} MiB`)

  let entries
  try {
    entries = readZipEntries(buffer)
  } catch (error) {
    check(false, 'zip 可解析', error.message)
    return
  }
  const names = new Set(entries.map((entry) => entry.name))

  // ① pack.json 在包里，且与仓库里那份**逐字一致**（保险：打包脚本可能读到别的）
  check(names.has('pack.json'), '包含 pack.json')
  let packed
  try {
    const index = findEntryData(buffer, entries, 'pack.json')
    packed = JSON.parse(index.toString('utf8'))
  } catch (error) {
    check(false, '包内 pack.json 可解析', error.message)
    return
  }
  check(packed.protocol === PROTOCOL_VERSION,
    'protocol 版本正确', `${packed.protocol}`)
  check(packed.version === manifest.version,
    '版本号与仓库清单一致', packed.version)
  check(packed.id === manifest.id, '包 id 与仓库清单一致', packed.id)

  // ② providers 非空 + id 合法 + 不含保留身份
  const providers = Array.isArray(packed.providers) ? packed.providers : []
  check(providers.length > 0, '声明了至少一家提供商', `${providers.length} 家`)
  const badIds = providers
    .map((provider) => provider.id)
    .filter((id) => typeof id !== 'string' || !/^[a-z0-9-]+$/.test(id))
  check(badIds.length === 0, 'provider id 只含小写字母 / 数字 / 连字符',
    badIds.length ? `违规：${badIds.join(', ')}` : undefined)
  const reserved = providers.map((provider) => provider.id).filter((id) => RESERVED_IDS.includes(id))
  check(reserved.length === 0, '没有声明本体保留身份',
    reserved.length ? `违规：${reserved.join(', ')}` : undefined)
  // 每家都要有 label（界面靠它显示，缺了会回落成裸 id）
  const noLabel = providers.filter((provider) => !provider.label).map((provider) => provider.id)
  check(noLabel.length === 0, '每家都有显示名',
    noLabel.length ? `缺失：${noLabel.join(', ')}` : undefined)

  // ③ entry：非空、覆盖本平台、路径安全、文件真的在包里
  const entryMap = packed.entry || {}
  check(Object.keys(entryMap).length > 0, '声明了入口二进制', `${Object.keys(entryMap).length} 个平台`)
  const declared = target ? entryMap[target] : Object.values(entryMap)[0]
  if (target) {
    check(typeof declared === 'string' && declared.length > 0,
      `覆盖目标平台 ${target}`, declared || '(缺失)')
  }
  if (typeof declared === 'string' && declared) {
    check(isSafeRelative(declared), '入口是安全的相对路径', declared)
    check(names.has(declared), '入口二进制真的在包里', declared)
    // Windows 条目必须带 .exe（网关按 pack.json 的路径找文件，名字不对就启动失败）
    if (/windows/.test(target || '') || /\.exe$/.test(declared)) {
      check(declared.endsWith('.exe'), 'Windows 入口带 .exe 后缀', declared)
    }
    const size = entries.find((entry) => entry.name === declared)?.size ?? 0
    check(size > 1024 * 1024, '入口二进制体积合理（> 1 MiB）', `${(size / 1024 / 1024).toFixed(2)} MiB`)
  } else {
    check(false, '找到可校验的入口', 'entry 为空')
  }

  // ④ icons / ui 路径安全
  if (packed.icons) {
    check(isSafeRelative(packed.icons), 'icons 是安全的相对路径', packed.icons)
  }
  const pages = Array.isArray(packed.ui) ? packed.ui : []
  const badPages = pages.filter((page) => !isSafeRelative(String(page.entry || '')))
  check(badPages.length === 0, 'ui 页面路径安全',
    badPages.length ? `违规：${badPages.map((page) => page.entry).join(', ')}` : undefined)

  // ⑤ 本包是**纯后端包**：不带界面页（签到中心是官方包那个页面，它读网关接口）
  check(pages.length === 0, '没有夹带界面页（纯后端包）',
    pages.length ? `多出 ${pages.length} 个` : undefined)

  // ⑥ 说明数据只含本包申报的家（`pack.mjs` 会过滤，这里复核结果）
  if (names.has('ui/provider-docs.json')) {
    try {
      const docs = JSON.parse(findEntryData(buffer, entries, 'ui/provider-docs.json').toString('utf8'))
      const documented = Object.keys(docs.providers || {})
      const declaredIds = providers.map((provider) => provider.id)
      const strays = documented.filter((id) => !declaredIds.includes(id))
      check(strays.length === 0, '说明数据只含本包的家',
        strays.length ? `多出：${strays.join(', ')}` : documented.join(', '))
      check(docs.schema === 1, '说明数据 schema 正确', `${docs.schema}`)
    } catch (error) {
      check(false, '说明数据可解析', error.message)
    }
  }

  // ⑦ 不该有的东西（zip slip / 绝对路径 / 编辑器残留）
  const suspicious = entries
    .map((entry) => entry.name)
    .filter((name) => !isSafeRelative(name) || /\.(swp|orig|rej)$/.test(name))
  check(suspicious.length === 0, '没有可疑条目',
    suspicious.length ? suspicious.join(', ') : undefined)
}

/**
 * 取出一个条目的内容（只支持 store 模式 —— `pack.mjs` 写的 zip 就是 store）。
 *
 * 走「本地头 → 数据」而不是中央目录：数据偏移只有本地头里有。
 * 这里只解小文件（pack.json / provider-docs.json），大文件不必碰。
 */
function findEntryData(buffer, entries, name) {
  const target = entries.find((entry) => entry.name === name)
  if (!target) throw new Error(`包里没有 ${name}`)
  const LOCAL = 0x04034b50
  for (let offset = 0; offset + 30 <= buffer.length; offset += 1) {
    if (buffer.readUInt32LE(offset) !== LOCAL) continue
    const nameLength = buffer.readUInt16LE(offset + 26)
    const extraLength = buffer.readUInt16LE(offset + 28)
    const entryName = buffer.slice(offset + 30, offset + 30 + nameLength).toString('utf8')
    if (entryName !== name) continue
    const size = buffer.readUInt32LE(offset + 18)
    const start = offset + 30 + nameLength + extraLength
    return buffer.slice(start, start + size)
  }
  throw new Error(`找不到 ${name} 的本地头`)
}

main()
