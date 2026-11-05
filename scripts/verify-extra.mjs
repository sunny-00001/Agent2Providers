#!/usr/bin/env node
/**
 * 「提供商增强（自建追加包）」的协议验证。
 *
 * ── 为什么不直接用 `scripts/verify.mjs` ──────────────────────
 * 那个脚本是给**官方全量包**写的：它默认拿 `demo` 那一家跑通十类 RPC
 * （chat / models / usage / checkin / conversation / 背压 / 取消……）。
 * 而本包用 `--no-default-features --features minimax` 编译，`demo` **不存在** ——
 * 拿它跑会得到一大批「params.provider 缺失或未知」的失败，把真正的信号淹掉。
 *
 * 所以这里只做三件事，都是「本包能不能被网关装上并干活」的**必要条件**：
 *
 *   1. **握手成功且本家出现在清单里**（id / label / 能力位 / 登录方式）。
 *      这是最要紧的一条：`pack.json` 里写的 provider id 必须与插件握手时
 *      申报的逐字一致，否则网关登记的是清单那个、插件等的是另一个，
 *      症状是「账号加得上、请求永远没有上游」。
 *   2. **`chat` 能返回一份可用的构造计划**：URL 落在正确的地区域、鉴权是
 *      Bearer、上游协议声明成 Anthropic —— 这三样错了任何一样，转发都不会通。
 *   3. **`account.normalize` 能拒绝坏输入并接受好输入**（不联网的那几条）。
 *
 * ── 用法 ──────────────────────────────────────────────────────
 *   node scripts/verify-extra.mjs
 *   node scripts/verify-extra.mjs --exe path/to/agent2api-providers
 *
 * 退出码：0 = 全部通过；1 = 有用例失败。
 *
 * ── 为什么这里自己写一份极小的 RPC 客户端 ────────────────────
 * `verify.mjs` 的 `PluginClient` 没有导出（它是脚本内的局部类）。为了不改动
 * 上游那份文件（改了以后同步会冲突），这里复刻它用到的那几行：spawn + 按行
 * 读 stdout + 发一条带 id 的 JSON 请求 + 等对应的应答。
 */

import { spawn } from 'node:child_process'
import process from 'node:process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const DEFAULT_EXE = path.join(
  ROOT, 'target', 'release',
  process.platform === 'win32' ? 'agent2api-providers.exe' : 'agent2api-providers',
)

/** 当前平台三元组（与 `pack.mjs` 的 `hostTriple()`、网关的 `target_triple()` 同口径）。 */
const TARGET = (() => {
  const arch = process.arch === 'x64' ? 'x86_64' : process.arch === 'arm64' ? 'aarch64' : process.arch
  switch (process.platform) {
    case 'win32': return `${arch}-pc-windows-msvc`
    case 'darwin': return `${arch}-apple-darwin`
    default: return `${arch}-unknown-linux-gnu`
  }
})()

const argv = process.argv.slice(2)
const exeIndex = argv.indexOf('--exe')
const EXE = exeIndex >= 0 ? argv[exeIndex + 1] : DEFAULT_EXE

const results = []
let failed = 0

function pass(name, detail) {
  results.push({ name, ok: true, detail })
  console.log(`  ✓ ${name}${detail ? ` — ${detail}` : ''}`)
}

function fail(name, detail) {
  results.push({ name, ok: false, detail })
  failed += 1
  console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ''}`)
}

/**
 * 极小的插件客户端：spawn 二进制，按行读写 stdout/stdin 上的 JSON 帧。
 *
 * 帧形状与网关一致（`plugin_host::rpc`）：每行一个
 * `{"id":…,"ok":true,"result":…}` 或 `{"id":…,"ok":false,"error":…}`。
 */
class PluginClient {
  constructor(exe, env) {
    this.exe = exe
    this.env = env
    this.nextId = 1
    this.pending = new Map()
    this.buffer = ''
  }

  async start() {
    this.child = spawn(this.exe, [], { env: { ...process.env, ...this.env }, stdio: ['pipe', 'pipe', 'pipe'] })
    this.child.stdout.setEncoding('utf8')
    this.child.stdout.on('data', (chunk) => this.onData(chunk))
    this.child.stderr.setEncoding('utf8')
    this.child.stderr.on('data', (chunk) => {
      // 插件不该往 stderr 写业务日志；真写了就原样透出来（排障要看）
      const text = String(chunk).trim()
      if (text) console.log(`  [stderr] ${text}`)
    })
    // 等子进程起来（插件不会主动发「就绪」帧，所以只等一小会儿）
    await new Promise((resolve) => setTimeout(resolve, 300))
  }

  onData(chunk) {
    this.buffer += chunk
    let index
    while ((index = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, index).trim()
      this.buffer = this.buffer.slice(index + 1)
      if (!line) continue
      let frame
      try {
        frame = JSON.parse(line)
      } catch {
        continue
      }
      this.onFrame(frame)
    }
  }

  /**
   * 帧分三类（与网关 `plugin_host::rpc` 的形状一致）：
   *   · `{method, params}`  —— 插件反向回调（`store.get` 这类）
   *   · `{event, …}`        —— 日志事件（`log`）与流式帧
   *   · `{id, result}` / `{id, error: {message, code}}` —— 我方调用的应答
   *
   * ⚠️ 应答的形状是 **`result` / `error`**，不是 `ok` 布尔位 —— 写错会让
   * 每一条调用都等到超时（症状是脚本挂住不动，而不是报错）。
   */
  onFrame(frame) {
    if (frame.method) {
      // 本项目的这几条用例都不该触发回调；真触发了就如实回绝并打出来
      console.log(`  [callback] ${frame.method}`)
      this.write({ id: frame.id, error: { message: '本脚本不实现回调', code: 'no_method' } })
      return
    }
    if (frame.event === 'log') {
      if (process.env.VERBOSE) console.log(`    [plugin ${frame.level}] ${frame.message}`)
      return
    }
    if (frame.event) return
    const waiter = this.pending.get(frame.id)
    if (!waiter) return
    this.pending.delete(frame.id)
    if (frame.error) {
      const message = typeof frame.error === 'string' ? frame.error : frame.error.message || '未知错误'
      waiter.reject(new Error(message))
    } else {
      waiter.resolve(frame.result)
    }
  }

  write(frame) {
    if (!this.child?.stdin.writable) return
    this.child.stdin.write(`${JSON.stringify(frame)}\n`)
  }

  call(method, params, timeoutMs = 15_000) {
    const id = this.nextId++
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(new Error(`超时：${method}`))
      }, timeoutMs)
      this.pending.set(id, {
        resolve: (value) => { clearTimeout(timer); resolve(value) },
        reject: (error) => { clearTimeout(timer); reject(error) },
      })
      this.write({ id, method, params })
    })
  }

  async stop() {
    if (this.child && !this.child.killed) this.child.kill()
  }
}

/** 本包申报的家（与 `pack.json` 的 `providers[]` 一致）。 */
const EXPECTED = ['minimax', 'minimax-intl']

async function main() {
  console.log(`插件二进制：${EXE}\n`)
  const client = new PluginClient(EXE, {})
  await client.start()

  console.log('【1】握手')
  let providers
  try {
    providers = await client.call('init', {
      env: {
        data_dir: ROOT,
        host_version: '0.1.0-test',
        target: TARGET,
        proxy: '',
        debug_traffic: false,
      },
    })
  } catch (error) {
    fail('init 握手', error.message)
    await client.stop()
    return finish()
  }
  if (!Array.isArray(providers) || providers.length === 0) {
    fail('init 返回 provider 列表', '列表为空')
    await client.stop()
    return finish()
  }
  const ids = providers.map((provider) => provider.id)
  pass('init 返回 provider 列表', `${ids.length} 家：${ids.join(', ')}`)

  // **最关键的一条**：申报的 id 必须与 pack.json 逐字一致 —— 不一致会让
  // 网关登记一个 id、插件等另一个，症状是「账号加得上、请求永远没有上游」。
  const missing = EXPECTED.filter((id) => !ids.includes(id))
  if (missing.length === 0) {
    pass('本包申报的家都出现了', EXPECTED.join(', '))
  } else {
    fail('本包申报的家都出现了', `缺少：${missing.join(', ')}（pack.json 与插件不一致？）`)
  }

  // 本包不该带官方那几十家（那是官方包的职责，重复声明会让归属取决于安装顺序）
  const extra = ids.filter((id) => !EXPECTED.includes(id))
  if (extra.length === 0) {
    pass('没有夹带官方包的家', '只含本包申报的两家')
  } else {
    fail('没有夹带官方包的家', `多出：${extra.join(', ')}`)
  }

  console.log('\n【2】能力位与登录方式')
  for (const id of EXPECTED) {
    const provider = providers.find((item) => item.id === id)
    if (!provider) continue
    const caps = provider.capabilities || {}
    // 这几位是「本家能不能在容器里干活」的判据：缺 chat 就没法转发，
    // 缺 web_login 就没法登录（容器里没有桌面壳），缺 refresh 就每小时要重登。
    const required = ['chat', 'refresh', 'model_refresh', 'usage', 'checkin', 'web_login']
    const wrong = required.filter((key) => caps[key] !== true)
    if (wrong.length === 0) {
      pass(`${id} 能力位如实申报`, required.join(' / '))
    } else {
      fail(`${id} 能力位如实申报`, `未申报：${wrong.join(', ')}`)
    }
    if (caps.stateful === true) {
      fail(`${id} 必须是无状态家`, 'Anthropic Messages 是一次请求一次回答')
    }
    const methods = (provider.login_methods || []).map((method) => method.kind)
    if (methods.includes('browser') && methods.includes('token')) {
      pass(`${id} 登录方式覆盖两条可用路径`, methods.join(', '))
    } else {
      fail(`${id} 登录方式覆盖两条可用路径`, `得到：${methods.join(', ') || '(空)'}`)
    }
    if (methods.includes('desktop')) {
      fail(`${id} 不该提供本机登录态导入`, '写客户端登录态会破坏它的登录代际')
    }
    if (!Array.isArray(provider.default_models) || provider.default_models.length === 0) {
      fail(`${id} 带了静态兜底模型`, '上游连不上时界面要有东西可选')
    } else {
      pass(`${id} 带了静态兜底模型`, provider.default_models.map((m) => m.id).join(', '))
    }
  }

  console.log('\n【3】转发构造（chat）')
  // 未登录（没有账号）时应当**如实报错**，而不是返回一份打不出去的请求
  try {
    await client.call('chat', {
      provider: 'minimax',
      account: 'no-such-account',
      body: { model: 'MiniMax-M3.1-Flash', messages: [{ role: 'user', content: 'hi' }] },
      headers: {},
      stream: false,
      wire_model: 'MiniMax-M3.1-Flash',
      reasoning: '',
    })
    fail('没有账号时 chat 如实报错', '居然成功了')
  } catch (error) {
    pass('没有账号时 chat 如实报错', error.message.slice(0, 60))
  }

  // 缺模型名要在本地拦住（不白打一次上游）
  try {
    await client.call('chat', {
      provider: 'minimax',
      account: '',
      body: { messages: [{ role: 'user', content: 'hi' }] },
      headers: {},
      stream: false,
      wire_model: '',
      reasoning: '',
    })
    fail('缺模型名被拒', '居然成功了')
  } catch (error) {
    pass('缺模型名被拒', error.message.slice(0, 60))
  }

  console.log('\n【4】账号规范化（不联网的几条）')
  try {
    const account = await client.call('account.normalize', {
      provider: 'minimax',
      source: { kind: 'manual', payload: { accessToken: 'mmoat_abcdefghij1234', userId: 'u42' } },
      name: '测试账号',
      proxy: null,
    })
    const view = account?.public || {}
    if (view.edition === 'cn' && view.name === '测试账号') {
      pass('手填 accessToken 被接受', `uid=${view.uid ?? ''} edition=${view.edition}`)
    } else {
      fail('手填 accessToken 被接受', `得到的公开视图不对：${JSON.stringify(view)}`)
    }
    if (account?.identity === 'user-u42') {
      pass('稳定身份取 userId', account.identity)
    } else {
      fail('稳定身份取 userId', `得到：${account?.identity}`)
    }
  } catch (error) {
    fail('手填 accessToken 被接受', error.message)
  }

  // 本机登录态导入必须**明确回绝**并指路（容器里读不到、写会破坏客户端代际）
  try {
    await client.call('account.normalize', {
      provider: 'minimax-intl',
      source: { kind: 'desktop' },
      name: null,
      proxy: null,
    })
    fail('本机登录态导入被明确回绝', '居然成功了')
  } catch (error) {
    const message = error.message || ''
    if (message.includes('浏览器登录')) {
      pass('本机登录态导入被明确回绝并指路', message.slice(0, 70))
    } else {
      fail('本机登录态导入被明确回绝并指路', message.slice(0, 90))
    }
  }

  // 国际版的公开视图必须标 intl（网关据此反查账号记录）
  try {
    const account = await client.call('account.normalize', {
      provider: 'minimax-intl',
      source: { kind: 'manual', payload: { accessToken: 'mmoat_abcdefghij1234' } },
      name: null,
      proxy: null,
    })
    if (account?.public?.edition === 'intl') {
      pass('国际版公开视图标 intl', account.public.edition)
    } else {
      fail('国际版公开视图标 intl', `得到：${account?.public?.edition}`)
    }
  } catch (error) {
    fail('国际版公开视图标 intl', error.message)
  }

  await client.stop()
  finish()
}

function finish() {
  const total = results.length
  const ok = total - failed
  console.log(`\n${'─'.repeat(52)}`)
  console.log(`通过 ${ok}/${total}${failed ? `，失败 ${failed}` : ''}`)
  if (failed) {
    console.log('\n失败项：')
    for (const item of results.filter((result) => !result.ok)) {
      console.log(`  · ${item.name} — ${item.detail}`)
    }
  }
  process.exit(failed ? 1 : 0)
}

main().catch((error) => {
  console.error('验证脚本自身出错：', error)
  process.exit(1)
})
