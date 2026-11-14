// magpie-scnet —— 把「超算互联网」(SCNet) 接入 magpie 的 provider 插件。
//
// 这个插件存在的理由：SCNet 的模型服务有两个**互相独立**的档位，各用各的
// API Key，混用会扣错账：
//
//   1. Token Plan（套餐）
//      - 专属 Key，前缀 sk-t…
//      - 控制台路径：模型服务 → Token Plan → API Key
//      - 只覆盖套餐内模型（目前 DeepSeek-V4.1-Flash-1017-Event）
//      - 消耗套餐 Credits，50,000 Credits/月，按模型倍率抵扣
//
//   2. 免费额度（Free Quota）
//      - 通用 Key，前缀 sk-N…（API Key 页「按量付费」下的模型服务 Key）
//      - 控制台路径：模型服务 → API Key → 创建/查看
//      - 免费额度是账号下的一条资源（目前 GLM-5.3-Flash，1 亿 tokens，30 天）
//      - 用通用 Key 调 GLM-5.3-Flash 时先扣免费额度；额度用完/调用其他模型
//        就会走按量付费，**不会**扣 Token Plan 的 Credits
//
// 两档共用同一个 API 域名和协议：
//   OpenAI 兼容：https://api.scnet.cn/api/llm/v1
//   Anthropic 兼容：https://api.scnet.cn/api/llm/anthropic
// 但 Key 和可用模型不同，所以本插件把它们做成两个明确的登录档位，
// 登录时按前缀 + /v1/models 双重校验，避免把 sk-t 填进免费档或反过来。
//
// 额度查询：SCNet 的模型 API 没有 /v1/usage 之类的接口（实测 401），
// 额度只存在于控制台的 /acx/charge/... 接口，需要网页登录 Cookie。
// 因此额度是「可选」的：填了 Cookie 就显示，不填只做模型调用。

const ID = "scnet"
const CHAT = "@ai-sdk/openai-compatible"

// 浏览器 Cookie 自动读取：网站会话过期后，额度接口会返回 401「用户未登录」。
// SCNet 没有任何程序化续期接口，唯一可靠的新 Cookie 来源是用户在默认浏览器里
// 重新登录官网。插件在这里直接从默认浏览器的 Cookie 数据库里读 scnet.cn 的
// 登录态（只读、按域名过滤），从而实现「浏览器里登录一次，插件自动续期」。
// 读取需要 magpie 拥有「完全磁盘访问」权限，解密需要用户在钥匙串弹窗里允许。

import { readFile, realpath, access, readdir } from "node:fs/promises"
import { homedir } from "node:os"
import { join, sep } from "node:path"
import { execFile } from "node:child_process"
import { promisify } from "node:util"
import { createDecipheriv, createHash, pbkdf2Sync, timingSafeEqual, publicEncrypt } from "node:crypto"

const run = promisify(execFile)

// 两档的 API 根地址相同；插件内统一用 OpenAI 兼容协议。
const API_BASE = "https://api.scnet.cn/api/llm/v1"
const CONSOLE_BASE = "https://www.scnet.cn"

// 免费额度目前只覆盖这个模型。即使通用 Key 能列出更多模型，
// 免费档也只暴露这一个，避免用户误用其他模型走按量付费。
const FREE_MODEL = "GLM-5.3-Flash"

// Token Plan 专属 Key 的前缀。用于登录时防止两档混填。
const TOKEN_PLAN_PREFIX = "sk-t"

const TIMEOUT = 20_000
const PLACEHOLDER = "scnet-placeholder"

// =============================================================================
// 基础工具
// =============================================================================

/** hostOf 取域名，仅用于账号显示名。 */
function hostOf(base) {
  try {
    return new URL(base).host
  } catch {
    return base
  }
}

/** num 只接受有限数字；"49,999.85" 这类字符串要先去掉逗号再转。 */
function num(v) {
  if (typeof v === "number" && Number.isFinite(v)) return v
  if (typeof v === "string") {
    const n = Number(v.replace(/,/g, ""))
    return Number.isFinite(n) ? n : undefined
  }
  return undefined
}

/** pct 算百分比，总量为 0 时返回 0，避免 NaN。 */
const pct = (used, total) => (total > 0 ? Math.min(100, Math.max(0, (100 * used) / total)) : 0)

/** fmt 给 Credits / tokens 加千分位，去掉无意义的尾零。 */
function fmt(v) {
  const n = num(v)
  if (n === undefined) return "—"
  return n.toLocaleString("zh-CN", { maximumFractionDigits: 2 })
}

// =============================================================================
// 模型 API
// =============================================================================

/**
 * fetchModels 用 API Key 拉 GET /v1/models。
 *
 * 实测返回：
 *   Token Plan Key → 只有套餐内模型
 *   通用 Key       → 账号可访问的全部模型
 *
 * 这个差异正好可以用来校验档位：Token Plan 不该看到免费模型，
 * 通用 Key 必须能看到 GLM-5.3-Flash。
 */
async function fetchModels(key) {
  const res = await fetch(`${API_BASE}/models`, {
    headers: { Authorization: `Bearer ${key}`, Accept: "application/json" },
    signal: AbortSignal.timeout(TIMEOUT),
  })
  const text = await res.text()

  let body
  try {
    body = JSON.parse(text)
  } catch {
    throw new Error(`/v1/models: 返回的不是 JSON（HTTP ${res.status}）`)
  }
  if (!res.ok) {
    const why = body?.error?.message ?? body?.msg ?? text.slice(0, 200)
    const err = new Error(`${res.status} ${why}`)
    if (res.status === 401) err.signIn = "expired"
    throw err
  }

  const list = Array.isArray(body?.data) ? body.data : Array.isArray(body) ? body : null
  if (!list) throw new Error("/v1/models: 返回结构无法识别")

  return list
    .map((m) => (typeof m === "string" ? m : m?.id))
    .filter((id) => typeof id === "string" && id)
}

/**
 * runtimeModel 生成 magpie 的模型对象。
 * SCNet 是纯文本对话网关，保守声明能力，价格留 0（由 magpie 自己统计）。
 *
 * 上下文上限：SCNet 的 DeepSeek-V4.1-Flash-1017-Event 与麦块云同源
 * （同为 DeepSeek V4.1 Flash 部署），站点未公布上限；麦块云同款模型
 * 实测硬上限 640,000 tokens，按 600,000 声明，给 magpie 的自动压缩留出余量。
 * GLM-5.3-Flash 无实测数据，保持 0。
 */
const CONTEXT_LIMITS = [
  { match: /^deepseek/i, context: 600_000 },
]

function contextLimitOf(id) {
  for (const { match, context } of CONTEXT_LIMITS) {
    if (match.test(String(id))) return context
  }
  return 0
}

function runtimeModel(id) {
  return {
    id,
    providerID: ID,
    name: id,
    api: { id, url: API_BASE, npm: CHAT },
    status: "active",
    headers: {},
    options: {},
    cost: { input: 0, output: 0, cache: { read: 0, write: 0 } },
    limit: { context: contextLimitOf(id), output: 0 },
    capabilities: {
      temperature: true,
      reasoning: false,
      attachment: false,
      toolcall: true,
      input: { text: true, image: false, audio: false, video: false, pdf: false },
      output: { text: true, image: false, audio: false, video: false, pdf: false },
      interleaved: false,
    },
    release_date: "",
    variants: {},
  }
}

function placeholderModel() {
  return {
    id: PLACEHOLDER,
    name: PLACEHOLDER,
    api: { npm: CHAT, url: API_BASE },
  }
}

// =============================================================================
// 控制台额度 API（需要网页 Cookie）
// =============================================================================

/**
 * consoleJson 请求控制台接口。
 *
 * 控制台的响应外壳是 {code,msg,data}，成功码是**字符串** "0"；
 * 未登录时 code 可能是 401/1004 等，需要区分「会话失效」和普通错误。
 *
 * @param {string} path 以 /acx/ 开头的路径
 * @param {object} opts { cookie, method, body }
 */
async function consoleJson(path, { cookie, method = "GET", body } = {}) {
  const headers = {
    Accept: "application/json",
    Cookie: cookie,
    // 控制台是 Vue SPA，后端对 UA/版本没有强校验，但带上更贴近真实请求
    "User-Agent": "magpie-scnet",
    version: "2.12.2",
  }
  let payload
  if (body !== undefined) {
    headers["Content-Type"] = "application/json"
    payload = JSON.stringify(body)
  }

  const res = await fetch(CONSOLE_BASE + path, {
    method,
    headers,
    body: payload,
    signal: AbortSignal.timeout(TIMEOUT),
  })
  const text = await res.text()

  let data
  try {
    data = JSON.parse(text)
  } catch {
    throw new Error(`${path}: 返回的不是 JSON（HTTP ${res.status}）`)
  }

  if (!res.ok) {
    const err = new Error(`${path}: HTTP ${res.status} ${text.slice(0, 160)}`)
    // 网站会话失效时 HTTP 状态就是 401/403，必须标记 signIn，
    // 否则额度层不会触发「从浏览器续期 Cookie」的流程
    if (res.status === 401 || res.status === 403) err.signIn = "expired"
    try {
      const j = JSON.parse(text)
      if (String(j?.code) === "401" || /未登录/.test(String(j?.msg ?? ""))) err.signIn = "expired"
    } catch {
      // 响应体不是 JSON 就按状态码判断
    }
    throw err
  }
  // 成功码是字符串 "0"；其余都按错误处理
  if (String(data?.code) !== "0") {
    const err = new Error(`${path}: ${data?.msg ?? "请求失败"}`)
    if (String(data?.code) === "401" || /登录|未登录/.test(String(data?.msg))) {
      err.signIn = "expired"
    }
    throw err
  }
  return data?.data
}

/** 当前用户的账号 id：免费额度统计接口必须带它。 */
async function currentAccountId(cookie) {
  const data = await consoleJson("/acx/user/customer/group/curuser-group-list?start=0&limit=9999", {
    cookie,
  })
  const first = Array.isArray(data) ? data[0] : null
  const accountId = first?.accountId
  if (!accountId) throw new Error("控制台未返回 accountId，Cookie 可能不完整")
  return accountId
}

/**
 * Token Plan 套餐列表。
 *
 * 实测返回：
 *   [{ resourceAccountId, orderId, resourceId, name, status,
 *      totalDays, usedAmount, totalAmount, unit:"CREDITS",
 *      minValidTime, maxExpireTime, currentTime }]
 */
async function tokenPlanPlans(cookie) {
  const data = await consoleJson("/acx/charge/account/currentuser/tokenplan/list", { cookie })
  return Array.isArray(data) ? data : []
}

/**
 * 免费额度资源列表。
 *
 * 实测返回：
 *   { list:[{ resourceId:"GLM-5.3-Flash", purchaseCount:"100000000",
 *             balance:"99999642", unit:"MTOKENS", validTime, expireTime, status }],
 *     totalBalance, totalPurchaseCount, totalUsed }
 */
async function freeQuotaResources(cookie) {
  const accountId = await currentAccountId(cookie)
  return consoleJson("/acx/charge/account/llmapi/resource/list/statistics", {
    cookie,
    method: "POST",
    body: { accountId },
  })
}

// =============================================================================
// 额度展示
// =============================================================================

/**
 * usageFromTokenPlan 把套餐列表转成 magpie usage。
 * 只取 status = enable 的那条；多条时取最早到期的（最该被关注的）。
 */
function usageFromTokenPlan(plans, user) {
  const live = (Array.isArray(plans) ? plans : []).filter((p) => p?.status === "enable")
  const plan = live.sort((a, b) => String(a.maxExpireTime).localeCompare(String(b.maxExpireTime)))[0]
  if (!plan) {
    return { user, plan: "Token Plan", windows: [], error: "没有生效中的 Token Plan 套餐" }
  }

  const total = num(plan.totalAmount) ?? 0
  const used = num(plan.usedAmount) ?? 0
  const out = {
    user,
    plan: plan.name || "Token Plan",
    windows: [
      {
        name: "Token Plan Credits",
        used: pct(used, total),
        display: `已用 ${fmt(used)} / 共 ${fmt(total)} Credits`,
      },
    ],
  }
  if (total > used) out.balance = `${fmt(total - used)} Credits`
  if (plan.maxExpireTime) out.until = plan.maxExpireTime
  if (total > 0 && used >= total) out.error = "Token Plan Credits 已用完"
  return out
}

/**
 * usageFromFree 把免费额度资源转成 magpie usage。
 * 优先找 GLM-5.3-Flash；没有就取第一条 MTOKENS 资源。
 */
function usageFromFree(data, user) {
  const list = Array.isArray(data?.list) ? data.list : []
  const item =
    list.find((r) => r?.resourceId === FREE_MODEL) ??
    list.find((r) => String(r?.unit).toUpperCase() === "MTOKENS")

  if (!item) {
    return { user, plan: "免费额度", windows: [], error: "账号下没有可用的免费额度" }
  }

  const total = num(item.purchaseCount) ?? 0
  const left = num(item.balance) ?? 0
  const used = Math.max(0, total - left)
  const out = {
    user,
    plan: `${item.resourceId} 免费额度`,
    windows: [
      {
        name: `免费额度 ${item.resourceId}`,
        used: pct(used, total),
        display: `已用 ${fmt(used)} / 共 ${fmt(total)} ${item.unit || "tokens"}`,
      },
    ],
    balance: `${fmt(left)} ${item.unit || "tokens"}`,
  }
  if (item.expireTime) out.until = item.expireTime
  if (left <= 0) out.error = "免费额度已用完"
  return out
}

/**
 * saveWebCookie 把从浏览器读到的新 Cookie 写回账号。
 * 必须整体写回（client.auth.set 是替换式），否则下次查询还是旧 Cookie。
 */
async function saveWebCookie(client, id, auth, cookie) {
  const next = {
    ...auth,
    metadata: {
      ...(auth.metadata ?? {}),
      consoleCookie: cookie,
      cookieRefreshedAt: new Date().toISOString(),
    },
  }
  let saved = false
  if (typeof client?.auth?.set === "function") {
    try {
      await client.auth.set({ path: { id }, body: next })
      saved = true
    } catch {
      // 写不进去也能用这一次，下次过期时再续
    }
  }
  return { ok: true, auth: next, saved }
}

/**
 * readUsage 读额度。Cookie 缺失或会话过期（401 用户未登录）时，
 * 自动从默认浏览器里读一枚新 Cookie 续期后重试——这就是「自动续期」：
 * 用户只要在浏览器里正常登录超算官网，插件就能自己拿到新会话。
 */
async function readUsage(client, id, auth, tier) {
  const user = label(auth)
  const cookie = cookieOf(auth)
  if (!cookie) {
    return {
      user,
      windows: [],
      error: "未提供控制台 Cookie，无法读取额度；模型调用不受影响",
    }
  }
  let r
  try {
    if (tier === "tokenplan") {
      r = usageFromTokenPlan(await tokenPlanPlans(cookie), user)
    } else {
      r = usageFromFree(await freeQuotaResources(cookie), user)
    }
  } catch (e) {
    r = {
      user,
      windows: [],
      error: String(e?.message ?? e),
      ...(e?.signIn ? { signIn: e.signIn } : {}),
    }
  }

  // 只有「会话失效」才值得续期；其他错误（网络等）重试也没用
  if (r.signIn !== "expired") return r

  // 首选：账号密码走 SSO 登录换全新会话（凭据存于账号 metadata）
  const phone = auth?.metadata?.phone
  const ssoPassword = auth?.metadata?.password
  if (phone && ssoPassword) {
    try {
      const fresh = await ssoLogin(phone, ssoPassword)
      const saved = await saveWebCookie(client, id, auth, fresh)
      let r2
      try {
        if (tier === "tokenplan") {
          r2 = usageFromTokenPlan(await tokenPlanPlans(fresh), user)
        } else {
          r2 = usageFromFree(await freeQuotaResources(fresh), user)
        }
      } catch (e) {
        return {
          user,
          windows: [],
          error: `SSO 登录成功但额度查询失败：${String(e?.message ?? e)}`,
          ...(e?.signIn ? { signIn: e.signIn } : {}),
        }
      }
      return { ...r2, cookieRenewed: "sso" }
    } catch (e) {
      // 密码登录失败（密码改动/需要验证码等）才走浏览器候选
    }
  }

  // 其次：从默认浏览器的每个资料里读 Cookie 候选，逐个验证
  let candidates
  try {
    candidates = await browserCookieCandidates()
  } catch (e) {
    // 浏览器续期失败：保留原错误，再附上原因和下一步指引
    return {
      ...r,
      error: `${r.error}；自动续期失败：${String(e?.message ?? e)}`,
    }
  }

  let lastErr = ""
  for (const cand of candidates) {
    const saved = await saveWebCookie(client, id, auth, cand.cookie)
    try {
      let r2
      if (tier === "tokenplan") {
        r2 = usageFromTokenPlan(await tokenPlanPlans(cand.cookie), user)
      } else {
        r2 = usageFromFree(await freeQuotaResources(cand.cookie), user)
      }
      return { ...r2, cookieRefreshed: true, profile: cand.profile }
    } catch (e) {
      lastErr = String(e?.message ?? e)
      continue // 这份资料的会话无效，换下一份
    }
  }
  // 所有候选都无效：浏览器里的会话也是过期的，明确告诉用户去官网重新登录
  const hint = candidates.length
    ? `已尝试默认浏览器的 ${candidates.length} 份资料，会话均未登录（读到的 Cookie：${candidates.flatMap((c) => c.names).join(", ")}）`
    : lastErr
  return {
    user,
    windows: [],
    error: `${hint}；请先在默认浏览器的普通窗口里登录 scnet.cn 并打开任意页面，然后点刷新重试`,
    signIn: "expired",
  }
}

// =============================================================================
// 浏览器 Cookie 自动读取（会话过期时自动续期）
// =============================================================================

/** 浏览器 Cookie 读取失败的错误类型，文案要能直接告诉用户下一步做什么。 */
class BrowserCookieError extends Error {}

// 与社区插件 scnet-auth 相同的浏览器清单：macOS 上主流的三个 Chromium 系浏览器。
// 依次是：显示名、Application Support 下的相对目录、钥匙串账户名。
const BROWSERS = {
  "com.google.Chrome": ["Google Chrome", "Google/Chrome", "Chrome"],
  "com.google.Chrome.beta": ["Google Chrome Beta", "Google/Chrome Beta", "Chrome"],
  "com.google.Chrome.dev": ["Google Chrome Dev", "Google/Chrome Dev", "Chrome"],
  "com.google.Chrome.canary": ["Google Chrome Canary", "Google/Chrome Canary", "Chrome"],
  "com.microsoft.edgemac": ["Microsoft Edge", "Microsoft Edge", "Microsoft Edge"],
  "com.brave.Browser": ["Brave", "BraveSoftware/Brave-Browser", "Brave"],
}

// 只读这些域名下的 Cookie；查询阶段就限定，不把整库拷走。
const COOKIE_HOSTS = ["www.scnet.cn", ".scnet.cn", "scnet.cn", ".www.scnet.cn"]

/**
 * defaultBrowser 问 macOS 当前用什么应用打开 https 链接。
 * 不能枚举或猜测浏览器目录，必须以「默认浏览器」为准。
 */
async function defaultBrowser(signal) {
  try {
    const { stdout } = await run("/usr/bin/osascript", ["-l", "JavaScript", "-e",
      'ObjC.import("AppKit"); ObjC.unwrap($.NSBundle.bundleWithURL($.NSWorkspace.sharedWorkspace.URLForApplicationToOpenURL($.NSURL.URLWithString("https://www.scnet.cn/"))).bundleIdentifier)'],
      { encoding: "utf8", timeout: 10000, maxBuffer: 4096, signal })
    return stdout.trim()
  } catch {
    throw new BrowserCookieError("无法识别默认浏览器，请确认已在系统设置里选择默认浏览器后重试")
  }
}

/**
 * readSCNetRows 只读打开浏览器的 Cookies 数据库，
 * 取出 scnet.cn 相关的 Cookie 行。数据库必须以只读方式打开。
 */
async function readSCNetRows(path) {
  let db
  try {
    if (globalThis.Bun) {
      const { Database } = await import("bun:sqlite")
      db = new Database(path, { readonly: true, safeIntegers: true })
    } else {
      const { DatabaseSync } = await import("node:sqlite")
      db = new DatabaseSync(path, { readOnly: true })
    }
    const version = Number(db.prepare("SELECT value FROM meta WHERE key = 'version'").get()?.value)
    if (!Number.isInteger(version) || version < 1) throw new Error("Unsupported schema")
    const query = db.prepare(`SELECT host_key, name, value, encrypted_value, path, expires_utc, has_expires
      FROM cookies WHERE host_key LIKE '%scnet.cn' LIMIT 128`)
    query.setReadBigInts?.(true)
    const rows = query.all()
    if (rows.length > 64) throw new Error("Too many cookies")
    return { version, rows }
  } finally {
    db?.close()
  }
}

/**
 * decodeCookie 解密单个 Chromium Cookie（v10 加密）。
 * 版本 ≥ 24 的库会在密文前附 32 字节的 host 哈希，解密后校验。
 */
function decodeCookie(row, version, key) {
  let plain
  const encrypted = Buffer.from(row.encrypted_value ?? [])
  if (encrypted.length) {
    if (encrypted.subarray(0, 3).toString() !== "v10") {
      throw new BrowserCookieError("浏览器会话使用暂不支持的加密方式；请手动更新控制台 Cookie")
    }
    try {
      const decipher = createDecipheriv("aes-128-cbc", key, Buffer.alloc(16, 32))
      plain = Buffer.concat([decipher.update(encrypted.subarray(3)), decipher.final()])
      if (version >= 24) {
        const expected = createHash("sha256").update(row.host_key).digest()
        if (plain.length < 32 || !timingSafeEqual(plain.subarray(0, 32), expected)) throw new Error("Host mismatch")
        return new TextDecoder("utf-8", { fatal: true }).decode(plain.subarray(32))
      }
      return new TextDecoder("utf-8", { fatal: true }).decode(plain)
    } catch {
      throw new BrowserCookieError("无法解密此浏览器的会话，请在钥匙串弹窗里点「允许」后重试")
    } finally {
      plain?.fill(0)
      encrypted.fill(0)
    }
  }
  return row.value || ""
}

/**
 * profileDirs 枚举默认浏览器下的所有资料目录：
 * Local State 里记录的「最近使用」排最前，其余 Default/Profile N 跟在后面。
 * 枚举全部资料是为了解决「登录的窗口不是最近使用资料」的情况。
 */
async function profileDirs(base) {
  const dirs = []
  try {
    const state = JSON.parse(await readFile(join(base, "Local State"), "utf8"))
    const last = state.profile?.last_used
    if (last && /^(Default|Profile [0-9]+)$/.test(last)) dirs.push(last)
  } catch {
    // Local State 读不到就只靠目录枚举
  }
  try {
    for (const entry of await readdir(base)) {
      if (/^(Default|Profile [0-9]+)$/.test(entry) && !dirs.includes(entry)) dirs.push(entry)
    }
  } catch {
    // 目录读不到就只有上面那一个候选
  }
  return dirs
}

/**
 * browserCookieCandidates 从默认浏览器的每个资料里读出 scnet.cn 的 Cookie。
 *
 * 返回 [{ profile, cookie }]，按「最近使用优先」排序；解密密钥只取一次。
 * 这里不做有效性判断——是否有效由调用方拿去请求额度接口验证。
 */
async function browserCookieCandidates({ signal } = {}) {
  if (process.platform !== "darwin") {
    throw new BrowserCookieError("自动读取浏览器会话目前仅支持 macOS 的 Chrome、Edge 和 Brave")
  }
  const bundleId = await defaultBrowser(signal)
  const browser = BROWSERS[bundleId]
  if (!browser) {
    throw new BrowserCookieError("当前默认浏览器暂不支持自动读取会话；目前支持 Chrome、Edge 和 Brave，可手动粘贴控制台 Cookie")
  }
  const [, relative, keyring] = browser
  let base
  try {
    base = await realpath(join(homedir(), "Library", "Application Support", relative))
  } catch {
    throw new BrowserCookieError(`本机没有安装或未运行过 ${browser[0]}，无法读取它的会话`)
  }

  // 解密密钥：从钥匙串取一次，所有资料共用；用户在 macOS 弹窗里点「允许」即可
  let key
  const keyOf = async () => {
    if (key) return key
    let password
    try {
      const { stdout } = await run("/usr/bin/security",
        ["find-generic-password", "-w", "-a", keyring, "-s", `${keyring} Safe Storage`],
        { encoding: "buffer", timeout: 60000, maxBuffer: 4096, signal })
      password = Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout)
      let end = password.length
      while (end && [10, 13].includes(password[end - 1])) end--
      if (!end) throw new Error("No key")
      key = pbkdf2Sync(password.subarray(0, end), "saltysalt", 1003, 16, "sha1")
      if (Buffer.isBuffer(stdout)) stdout.fill(0)
      return key
    } catch {
      throw new BrowserCookieError("未获准读取浏览器钥匙串；重新触发时在 macOS 弹窗里点「允许」，或手动粘贴控制台 Cookie")
    } finally {
      password?.fill(0)
    }
  }

  const out = []
  for (const profile of await profileDirs(base)) {
    let dir
    try {
      dir = await realpath(join(base, profile))
      if (!dir.startsWith(base + sep)) continue
    } catch {
      continue // 该资料目录不存在（Local State 里残留的旧记录）
    }
    let path
    for (const rel of ["Network/Cookies", "Cookies"]) {
      const candidate = join(dir, rel)
      try {
        await access(candidate)
        path = await realpath(candidate)
        if (!path.startsWith(dir + sep)) continue
        break
      } catch {
        continue
      }
    }
    if (!path) continue
    let snapshot
    try {
      snapshot = await readSCNetRows(path)
    } catch {
      continue // 这个资料的会话库读不了就跳过，不中断其他资料
    }
    try {
      const k = await keyOf()
      const parts = []
      for (const row of snapshot.rows) {
        if (!COOKIE_HOSTS.includes(row.host_key)) continue
        if (row.has_expires && Number(row.expires_utc) / 1000 - 11644473600000 <= Date.now()) continue
        const value = decodeCookie(row, snapshot.version, k)
        if (!/^[!#$%&'*+.^_`|~\w-]+$/.test(row.name) || /[\x00-\x20\x7f;,]/.test(value)) continue
        if (value) parts.push(`${row.name}=${value}`)
      }
      if (parts.length) out.push({ profile, cookie: parts.join("; "), names: parts.map((x) => x.split("=")[0]) })
    } catch {
      continue // 单个资料解密失败只跳过它
    }
    if (signal?.aborted) break
  }
  if (!out.length) {
    throw new BrowserCookieError("默认浏览器的所有资料里都没有读到超算的登录会话；请在默认浏览器的普通窗口里登录 scnet.cn 并打开任意页面，然后重试")
  }
  return out
}

// =============================================================================
// SSO 密码自动登录（Cookie 自动续期）
// =============================================================================

// SCNet 的额度接口认网页 Cookie，而登录 Cookie 是会话级的，浏览器运行期间
// 不写盘——所以「读浏览器 Cookie 库」的续期方式对它不可靠。
// 唯一确定可靠的续期方式：用账号密码走一遍 SSO 登录，换取全新会话 Cookie。
// 登录流程（2026-11-14 抓包分析）：
//   1. GET /sso/login?service=...        → 页面里有 CAS 的 execution 令牌
//      和登录 JS 文件名（RSA 公钥硬编码在 JS 里）；
//   2. 密码用该公钥做 RSA PKCS#1 加密（表单字段 encrypted=true）；
//   3. POST /sso/login（mode=0 表示账号密码登录）→ 302 重定向链建立会话；
//   4. 沿重定向收集 Set-Cookie，拼成 Cookie 请求头。
// 注意：登录 JS 要求附一个 name="submit" 的隐藏域（值=按钮文字），CAS 兼容。

const SSO_LOGIN_URL =
  "https://www.scnet.cn/sso/login?service=" +
  encodeURIComponent(
    "https://www.scnet.cn/ac/api/auth/loginSsoRedirect.action?originalUrl=https://www.scnet.cn/ui/console/index.html#/llm/token-plan"
  )

/** collectSetCookie 把一次响应的 Set-Cookie 收进 jar（Map：name → value）。 */
function collectSetCookie(res, jar) {
  const list =
    typeof res.headers.getSetCookie === "function"
      ? res.headers.getSetCookie()
      : []
  for (const line of list) {
    const pair = line.split(";")[0]
    const eq = pair.indexOf("=")
    if (eq > 0) jar.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim())
  }
  return jar
}

/** jarToHeader 把 jar 转成 Cookie 请求头的值。 */
function jarToHeader(jar) {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ")
}

/** cookieHeaders 把 Cookie 字符串包成请求头对象；空串时不加该头。 */
function cookieHeaders(cookie) {
  return cookie ? { Cookie: cookie } : {}
}
/**
 * ssoLogin 用手机号 + 密码走 SSO 登录，返回可用的 Cookie 请求头。
 * 失败抛 Error，文案直接可读（密码错误 / 需要验证码 等）。
 */
async function ssoLogin(phone, password) {
  const jar = new Map()

  // 1) 登录页：execution 令牌 + 登录 JS 地址
  const r1 = await fetch(SSO_LOGIN_URL, {
    redirect: "manual",
    signal: AbortSignal.timeout(TIMEOUT),
  })
  const html = await r1.text()
  collectSetCookie(r1, jar)
  const execution = /name="execution" value="([^"]+)"/.exec(html)?.[1]
  if (!execution) throw new Error("SSO 登录页没有返回 execution 令牌")
  const jsUrl = /src="([^"]*login-[a-f0-9]+\.js)"/.exec(html)?.[1]

  // 2) 从登录 JS 里挖 RSA 公钥（站点把它硬编码在 JS 里，密文用 base64）
  let keyB64
  if (jsUrl) {
    try {
      const js = await (
        await fetch(new URL(jsUrl, CONSOLE_BASE).href, {
          signal: AbortSignal.timeout(TIMEOUT),
        })
      ).text()
      keyB64 = /var key = '([^']+)'/.exec(js)?.[1]
    } catch {
      // 拿不到 JS 就用不了密码登录
    }
  }
  if (!keyB64) throw new Error("SSO 登录页没有返回 RSA 公钥，无法用密码登录")

  // 3) RSA PKCS#1 加密密码（站点用 JSEncrypt，同样是 PKCS#1 v1.5）
  const pem =
    "-----BEGIN PUBLIC KEY-----\n" + keyB64 + "\n-----END PUBLIC KEY-----"
  const encPassword = cryptoPublicEncrypt(pem, password)

  // 4) 提交登录表单，沿 302 重定向收集会话 Cookie
  const form = new URLSearchParams({
    username: phone,
    password: encPassword,
    encrypted: "true",
    mode: "0",
    execution,
    _eventId: "submit",
    geolocation: "",
    sensorsAnonId: "",
    submit: "登录",
  })
  let res = await fetch(SSO_LOGIN_URL, {
    method: "POST",
    redirect: "manual",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...cookieHeaders(jarToHeader(jar)),
      "User-Agent": "magpie-scnet",
    },
    body: form.toString(),
    signal: AbortSignal.timeout(TIMEOUT),
  })
  collectSetCookie(res, jar)

  // 5) 跟随重定向链（最多 6 跳），把会话 Cookie 收齐
  for (let hop = 0; hop < 6 && res.status >= 300 && res.status < 400; hop++) {
    const loc = res.headers.get("location")
    if (!loc) break
    const hopHeaders = { "User-Agent": "magpie-scnet" }
    if (jar.size) hopHeaders.Cookie = jarToHeader(jar)
    res = await fetch(loc.startsWith("/") ? new URL(loc, CONSOLE_BASE).href : loc, {
      redirect: "manual",
      headers: hopHeaders,
      signal: AbortSignal.timeout(TIMEOUT),
    })
    collectSetCookie(res, jar)
  }

  const header = jarToHeader(jar)
  // 会话 Cookie 至少要有 Token；没有就说明登录没成功
  if (!/(^|[&; ])Token=/.test(header)) {
    throw new Error("SSO 登录未建立会话（可能密码错误、需要验证码或账号被锁定）")
  }
  return header
}

/** cryptoPublicEncrypt 用站点公钥加密密码（PKCS#1 v1.5，与 JSEncrypt 一致）。 */
function cryptoPublicEncrypt(pem, plain) {
  return publicEncrypt(
    { key: pem, padding: 1 /* RSA_PKCS1_PADDING */ },
    Buffer.from(plain, "utf8")
  ).toString("base64")
}

// =============================================================================
// 账号
// =============================================================================
// =============================================================================
// 账号
// =============================================================================

/** tierOf 读账号的档位，默认 tokenplan。 */
function tierOf(auth) {
  return auth?.metadata?.tier === "free" ? "free" : "tokenplan"
}

/** cookieOf 取控制台 Cookie（整段 Cookie 请求头的值）。 */
function cookieOf(auth) {
  const c = auth?.metadata?.consoleCookie
  return typeof c === "string" ? c.trim() : ""
}

/** label 生成账号显示名：档位 + Key 后四位，绝不暴露完整 Key。 */
function label(auth) {
  const tier = tierOf(auth)
  const name = tier === "free" ? "免费额度" : "Token Plan"
  const key = typeof auth?.key === "string" ? auth.key : ""
  return `${name} · ${hostOf(API_BASE)}${key.length >= 8 ? " …" + key.slice(-4) : ""}`
}

// =============================================================================
// 登录校验
// =============================================================================

/**
 * checkTier 双重校验，防止两档 Key 混用：
 *
 *   1. 前缀：
 *      - Token Plan 必须是 sk-t…
 *      - 免费额度必须是 sk-… 但不能是 sk-t…
 *   2. /v1/models：
 *      - Token Plan 不能把免费模型当成套餐模型（至少要有模型）
 *      - 免费额度必须能看到 GLM-5.3-Flash
 *
 * 前缀只作为第一道提示；真正的能力判断以 /v1/models 为准，
 * 这样站点以后换前缀也不会把用户挡在门外。
 */
function checkTier(tier, key, models) {
  const ids = new Set(models)
  const isTokenPlanKey = key.startsWith(TOKEN_PLAN_PREFIX)

  if (tier === "tokenplan") {
    if (!isTokenPlanKey) {
      return `这看起来不是 Token Plan 专属 Key（应以 ${TOKEN_PLAN_PREFIX} 开头）。Token Plan Key 在「Token Plan」页面获取；当前 Key 可能是 API Key 页的通用 Key。`
    }
    if (!models.length) return "Token Plan Key 没有返回任何可用模型"
    return null
  }

  // free
  if (isTokenPlanKey) {
    return "这是 Token Plan 专属 Key，不能用于免费额度。免费额度请使用「API Key」页的通用模型服务 Key（sk-N…）。"
  }
  if (!key.startsWith("sk-")) return "API Key 应以 sk- 开头"
  if (!ids.has(FREE_MODEL)) {
    return `这个 Key 看不到免费模型 ${FREE_MODEL}，无法用于免费额度档；请确认使用的是「API Key」页的通用 Key，且免费额度仍在有效期内。`
  }
  return null
}

// =============================================================================
// 插件主体
// =============================================================================

function hooks(client) {
  return {
    /** config：provider 静态信息 */
    async config(config) {
      config.provider ??= {}
      const was = config.provider[ID] ?? {}
      const kept = Object.fromEntries(
        Object.entries(was.models ?? {}).filter(([k]) => k !== PLACEHOLDER)
      )
      config.provider[ID] = {
        ...was,
        name: "超算互联网",
        npm: was.npm || CHAT,
        models: Object.keys(kept).length ? kept : { [PLACEHOLDER]: placeholderModel() },
      }
    },

    auth: {
      provider: ID,

      /** loader：模型请求用的 baseURL + Key */
      async loader(getAuth) {
        const auth = await getAuth()
        if (auth?.type !== "api" || !auth.key) return {}
        return { baseURL: API_BASE, apiKey: auth.key }
      },

      methods: [
        {
          type: "oauth",
          label: "超算互联网 API Key",
          prompts: [
            {
              type: "select",
              key: "tier",
              message: "档位（两档 Key 不通用）",
              options: [
                { label: "Token Plan（sk-t…，扣套餐 Credits）", value: "tokenplan" },
                { label: "免费额度（sk-N…，GLM-5.3-Flash）", value: "free" },
              ],
            },
            {
              type: "password",
              key: "apiKey",
              message: "API Key",
              placeholder: "Token Plan 填 sk-t…；免费额度填 API Key 页的 sk-N…",
            },
            {
              type: "password",
              key: "consoleCookie",
              message: "控制台 Cookie（可选；留空则自动从默认浏览器读取）",
              placeholder: "整段 Cookie 值；留空则只做模型调用",
            },
            {
              type: "text",
              key: "phone",
              message: "手机号（可选，用于 Cookie 过期后自动续期）",
              placeholder: "11 位手机号；不填则 Cookie 过期后需手动重登",
            },
            {
              type: "password",
              key: "ssoPassword",
              message: "登录密码（用于 Cookie 过期后自动续期）",
              placeholder: "与超算官网登录密码一致",
              condition: (i) => !!String(i?.phone ?? "").trim(),
            },
          ],

          async authorize(inputs) {
            return {
              url: "",
              instructions: "",
              method: "auto",
              async callback() {
                const tier = inputs?.tier === "free" ? "free" : "tokenplan"
                const key = String(inputs?.apiKey ?? "").trim()
                let cookie = String(inputs?.consoleCookie ?? "").trim()
                const phone = String(inputs?.phone ?? "").trim()
                const ssoPassword = String(inputs?.ssoPassword ?? "")
                if (!key) return { type: "failed", error: "没有填写 API Key" }

                // 1) 拉模型列表，既是校验也是档位能力判断
                let models
                try {
                  models = await fetchModels(key)
                } catch (e) {
                  return {
                    type: "failed",
                    error: `API Key 不可用：${String(e?.message ?? e).slice(0, 300)}`,
                  }
                }

                // 2) 档位与 Key 是否匹配
                const bad = checkTier(tier, key, models)
                if (bad) return { type: "failed", error: bad }

                // 3) Cookie：手动填了就验证；留空则尝试从默认浏览器自动读取
                //    （用户在浏览器里登录过超算官网即可），读不到也不阻断登录
                if (cookie) {
                  try {
                    if (tier === "tokenplan") await tokenPlanPlans(cookie)
                    else await freeQuotaResources(cookie)
                  } catch (e) {
                    return {
                      type: "failed",
                      error: `控制台 Cookie 不可用：${String(e?.message ?? e).slice(0, 300)}`,
                    }
                  }
                } else {
                  try {
                    // 浏览器自动读取：最近使用的资料优先；读不到不阻断登录
                    const candidates = await browserCookieCandidates()
                    let picked = null
                    for (const cand of candidates) {
                      if (tier === "tokenplan") await tokenPlanPlans(cand.cookie)
                      else await freeQuotaResources(cand.cookie)
                      picked = cand
                      break // 第一份能查额度的就用它
                    }
                    if (!picked) throw new BrowserCookieError("浏览器资料里没有找到有效的超算登录会话")
                    cookie = picked.cookie
                  } catch (e) {
                    // 自动读取失败不阻断登录：模型仍然可用，额度稍后再补
                    cookie = ""
                  }
                }

                // 手机号密码已填时先验证 SSO 登录可用，失败不阻断登录
                let ssoNote
                if (phone && ssoPassword) {
                  try {
                    await ssoLogin(phone, ssoPassword)
                  } catch (e) {
                    ssoNote = `SSO 自动续期暂不可用：${String(e?.message ?? e).slice(0, 200)}`
                  }
                }

                return {
                  type: "success",
                  key,
                  metadata: {
                    tier,
                    baseURL: API_BASE,
                    consoleCookie: cookie || undefined,
                    phone: phone || undefined,
                    password: ssoPassword || undefined,
                    ...(ssoNote ? { renewNote: ssoNote } : {}),
                  },
                  accountId: label({ key, metadata: { tier } }),
                }
              },
            }
          },
        },
      ],

      /** usage：按档位查各自的额度；会话过期时自动从浏览器续期 Cookie */
      async usage(getAuth) {
        const auth = await getAuth()
        if (auth?.type !== "api") return { error: "未登录" }
        return readUsage(client, ID, auth, tierOf(auth))
      },
    },

    provider: {
      id: ID,
      async models(provider, { auth } = {}) {
        if (auth?.type !== "api" || !auth.key) return provider.models

        try {
          let ids = await fetchModels(auth.key)
          // 免费档只暴露免费模型，避免误用其他模型走按量付费
          if (tierOf(auth) === "free") ids = ids.filter((id) => id === FREE_MODEL)
          if (!ids.length) return provider.models

          const out = {}
          for (const id of ids) out[id] = runtimeModel(id)
          return out
        } catch (e) {
          if (e?.signIn) throw e
          return provider.models
        }
      },
    },
  }
}

export async function ScnetPlugin({ client } = {}) {
  return hooks(client)
}

// _internal 只给测试用。
export const _internal = {
  ID,
  API_BASE,
  FREE_MODEL,
  TOKEN_PLAN_PREFIX,
  fetchModels,
  runtimeModel,
  placeholderModel,
  consoleJson,
  currentAccountId,
  tokenPlanPlans,
  freeQuotaResources,
  usageFromTokenPlan,
  usageFromFree,
  readUsage,
  browserCookieCandidates,
  ssoLogin,
  saveWebCookie,
  contextLimitOf,
  checkTier,
  tierOf,
  cookieOf,
  label,
  fmt,
  pct,
}
