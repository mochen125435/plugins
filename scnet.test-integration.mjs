// 集成测试：本地假站点复刻 SCNet 的模型 API 与控制台额度接口。
import { test, before, after } from "node:test"
import assert from "node:assert/strict"
import { createServer } from "node:http"
import { generateKeyPairSync, privateDecrypt, constants } from "node:crypto"

import { ScnetPlugin, _internal } from "./scnet.mjs"

const { API_BASE } = _internal
const TOKEN_PLAN_KEY = "sk-t-fake-0001"
const FREE_KEY = "sk-N-fake-0002"
const GOOD_COOKIE = "Token=fake-session; other=1"
const BAD_COOKIE = "Token=expired"

let server
let base
const realFetch = globalThis.fetch

// 假站点的 RSA 密钥对：站点把公钥写进登录 JS，插件用它对密码加密
const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 })
const publicKeyB64 = publicKey.export({ type: "spki", format: "der" }).toString("base64")
const decrypt = (b64) => {
  if (!b64) return ""
  try {
    return privateDecrypt(
      { key: privateKey, padding: constants.RSA_PKCS1_PADDING },
      Buffer.from(b64, "base64")
    ).toString("utf8")
  } catch {
    return "(解密失败)"
  }
}
// SSO 登录过程里假站点收到的请求，用来断言 service 形态与表单内容
const ssoLog = []

before(async () => {
  server = createServer((req, res) => {
    const send = (body, status = 200) => {
      res.writeHead(status, { "content-type": "application/json" })
      res.end(JSON.stringify(body))
    }
    const auth = req.headers.authorization ?? ""
    const cookie = req.headers.cookie ?? ""

    // 模型 API
    if (req.url === "/api/llm/v1/models") {
      if (auth === `Bearer ${TOKEN_PLAN_KEY}`) {
        return send({ object: "list", data: [{ id: "DeepSeek-V4.1-Flash-1017-Event" }] })
      }
      if (auth === `Bearer ${FREE_KEY}`) {
        return send({
          object: "list",
          data: [{ id: "GLM-5.3-Flash" }, { id: "Other-Model" }],
        })
      }
      return send({ error: { message: "Invalid API key" } }, 401)
    }

    // 控制台接口：只认 GOOD_COOKIE
    if (req.url.startsWith("/acx/")) {
      if (cookie !== GOOD_COOKIE) {
        return send({ code: "401", msg: "用户未登录!", data: null })
      }
      if (req.url.startsWith("/acx/user/customer/group/curuser-group-list")) {
        return send({ code: "0", msg: "success", data: [{ accountId: "acc-1" }] })
      }
      if (req.url === "/acx/charge/account/currentuser/tokenplan/list") {
        return send({
          code: "0",
          msg: "success",
          data: [
            {
              resourceAccountId: "res-1",
              orderId: "order-1",
              resourceId: "TP-Event-022",
              name: "DeepSeek-V4.1-Flash-1017首单5千万",
              status: "enable",
              usedAmount: "0.152",
              totalAmount: "50000",
              unit: "CREDITS",
              maxExpireTime: "2026-12-13 23:59:59",
            },
          ],
        })
      }
      if (req.url === "/acx/charge/account/llmapi/resource/list/statistics") {
        let raw = ""
        req.on("data", (c) => (raw += c))
        req.on("end", () => {
          const body = JSON.parse(raw || "{}")
          if (body.accountId !== "acc-1") {
            return send({ code: "1004", msg: "accountId can not be blank" })
          }
          send({
            code: "0",
            msg: "success",
            data: {
              list: [
                {
                  resourceId: "GLM-5.3-Flash",
                  purchaseCount: "100000000",
                  balance: "99999642",
                  unit: "MTOKENS",
                  expireTime: "2026-12-13T23:59:59",
                  status: "enable",
                },
              ],
            },
          })
        })
        return
      }
      return send({ code: "404", msg: "not found" })
    }

    // ---- 假 CAS / SSO：复刻 2026-11-15 实测的登录链路 ----
    // 关键点：service 只能是 loginSsoRedirect.action 本体；
    // 带 originalUrl 时真实站点不发 Token，这里同样不发，用来守回归。
    if (req.url.startsWith("/sso/login")) {
      const q = new URL(req.url, base).searchParams
      ssoLog.push({ method: req.method, url: req.url, service: q.get("service") || "" })

      if (req.method === "GET") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" })
        return res.end(
          `<form><input name="execution" value="e1s1">` +
            `<script src="/login-abc123.js"></script></form>`
        )
      }

      // POST：把表单读全，校验密码确实用站点公钥加密过
      let raw = ""
      req.on("data", (c) => (raw += c))
      req.on("end", () => {
        const form = new URLSearchParams(raw)
        const plain = decrypt(form.get("password") || "")
        ssoLog.push({ form: Object.fromEntries(form), plain })
        const broken = form.get("username") === "no-token"
        res.writeHead(302, {
          location: broken
            ? "/ac/api/auth/loginSsoRedirect.action?ticket=ST-NOTOKEN"
            : "/ac/api/auth/loginSsoRedirect.action?ticket=ST-1-acx-sso-abc",
        })
        res.end()
      })
      return
    }

    if (req.url === "/login-abc123.js") {
      res.writeHead(200, { "content-type": "application/javascript" })
      return res.end(`var key = '${publicKeyB64}';`)
    }

    // 第一跳：发 jsessionid + Token，再 302 到自己（不带 acx 后缀）
    if (req.url.startsWith("/ac/api/auth/loginSsoRedirect.action?ticket=ST-1-acx")) {
      res.writeHead(302, {
        "set-cookie": ["jsessionid=js-1; Path=/", "Token=tok-1; Path=/"],
        location: "/ac/api/auth/loginSsoRedirect.action?ticket=ST-1",
      })
      return res.end()
    }
    // 故障分支：只发 jsessionid、200 空响应 —— 没有 Token，控制台仍判未登录
    if (req.url.startsWith("/ac/api/auth/loginSsoRedirect.action?ticket=ST-NOTOKEN")) {
      res.writeHead(200, { "set-cookie": ["jsessionid=js-1; Path=/"], "content-type": "text/html" })
      return res.end("")
    }

    // 第二跳：落到页面
    if (req.url.startsWith("/ac/api/auth/loginSsoRedirect.action?ticket=ST-1")) {
      res.writeHead(302, { location: "/ui/mall/" })
      return res.end()
    }

    send({ code: "404", msg: "not found" }, 404)
  })

  await new Promise((r) => server.listen(0, "127.0.0.1", r))
  base = `http://127.0.0.1:${server.address().port}`

  // 把两个真实域名改写到本地假站点
  globalThis.fetch = (input, init) => {
    const u = String(input)
      .replace("https://api.scnet.cn", base)
      .replace("https://www.scnet.cn", base)
      .replace("https://api.scnet.cn/api", base + "/api")
    return realFetch(u, init)
  }
})

after(async () => {
  globalThis.fetch = realFetch
  await new Promise((r) => server.close(r))
})

async function plugin() {
  return ScnetPlugin({})
}

// ---- 登录：两档 Key 不能混用 ------------------------------------------------

test("Token Plan 档用 sk-t 登录成功", async () => {
  const p = await plugin()
  const flow = await p.auth.methods[0].authorize({
    tier: "tokenplan",
    apiKey: TOKEN_PLAN_KEY,
    consoleCookie: GOOD_COOKIE,
  })
  const r = await flow.callback()
  assert.equal(r.type, "success")
  assert.equal(r.metadata.tier, "tokenplan")
  assert.equal(r.metadata.consoleCookie, GOOD_COOKIE)
  assert.equal(r.key, TOKEN_PLAN_KEY)
})

test("Token Plan 档拒绝通用 Key", async () => {
  const p = await plugin()
  const flow = await p.auth.methods[0].authorize({
    tier: "tokenplan",
    apiKey: FREE_KEY,
    consoleCookie: "",
  })
  const r = await flow.callback()
  assert.equal(r.type, "failed")
  assert.match(r.error, /不是 Token Plan 专属 Key/)
})

test("免费额度档用通用 Key 登录成功", async () => {
  const p = await plugin()
  const flow = await p.auth.methods[0].authorize({
    tier: "free",
    apiKey: FREE_KEY,
    consoleCookie: GOOD_COOKIE,
  })
  const r = await flow.callback()
  assert.equal(r.type, "success")
  assert.equal(r.metadata.tier, "free")
})

test("免费额度档拒绝 Token Plan Key", async () => {
  const p = await plugin()
  const flow = await p.auth.methods[0].authorize({
    tier: "free",
    apiKey: TOKEN_PLAN_KEY,
    consoleCookie: "",
  })
  const r = await flow.callback()
  assert.equal(r.type, "failed")
  assert.match(r.error, /不能用于免费额度/)
})

test("免费额度档拒绝看不到 GLM-5.3-Flash 的 Key", async () => {
  // 用 Token Plan Key 之外的另一个 key，让服务器返回不含 GLM 的列表
  const p = await plugin()
  const flow = await p.auth.methods[0].authorize({
    tier: "free",
    apiKey: "sk-N-no-glm",
    consoleCookie: "",
  })
  const r = await flow.callback()
  assert.equal(r.type, "failed")
  assert.match(r.error, /API Key 不可用|看不到免费模型/)
})

test("Cookie 无效时登录失败，提前暴露过期", async () => {
  const p = await plugin()
  const flow = await p.auth.methods[0].authorize({
    tier: "tokenplan",
    apiKey: TOKEN_PLAN_KEY,
    consoleCookie: BAD_COOKIE,
  })
  const r = await flow.callback()
  assert.equal(r.type, "failed")
  assert.match(r.error, /控制台 Cookie 不可用/)
})

test("不填 Cookie 也能登录，只做模型", async () => {
  const p = await plugin()
  const flow = await p.auth.methods[0].authorize({
    tier: "free",
    apiKey: FREE_KEY,
    consoleCookie: "",
  })
  const r = await flow.callback()
  assert.equal(r.type, "success")
  assert.equal(r.metadata.consoleCookie, undefined)
})

// ---- 模型：免费档只暴露免费模型 ---------------------------------------------

test("Token Plan 账号列出套餐模型", async () => {
  const p = await plugin()
  const auth = { type: "api", key: TOKEN_PLAN_KEY, metadata: { tier: "tokenplan" } }
  const models = await p.provider.models({ models: {} }, { auth })
  assert.deepEqual(Object.keys(models), ["DeepSeek-V4.1-Flash-1017-Event"])
  assert.equal(models["DeepSeek-V4.1-Flash-1017-Event"].api.url, API_BASE)
})

test("免费额度账号只列出 GLM-5.3-Flash，避免误用其他模型", async () => {
  const p = await plugin()
  const auth = { type: "api", key: FREE_KEY, metadata: { tier: "free" } }
  const models = await p.provider.models({ models: {} }, { auth })
  assert.deepEqual(Object.keys(models), ["GLM-5.3-Flash"])
})

// ---- 额度 ------------------------------------------------------------------

test("Token Plan 额度：Credits 用量与剩余", async () => {
  const p = await plugin()
  const auth = {
    type: "api",
    key: TOKEN_PLAN_KEY,
    metadata: { tier: "tokenplan", consoleCookie: GOOD_COOKIE },
  }
  const u = await p.auth.usage(async () => auth)
  assert.equal(u.plan, "DeepSeek-V4.1-Flash-1017首单5千万")
  assert.equal(u.windows.length, 1)
  assert.match(u.windows[0].display, /已用 0\.15 \/ 共 50,000 Credits/)
  assert.equal(u.balance, "49,999.85 Credits")
  assert.equal(u.until, "2026-12-13 23:59:59")
  assert.equal(u.error, undefined)
})

test("免费额度：先取 accountId，再查资源统计", async () => {
  const p = await plugin()
  const auth = {
    type: "api",
    key: FREE_KEY,
    metadata: { tier: "free", consoleCookie: GOOD_COOKIE },
  }
  const u = await p.auth.usage(async () => auth)
  assert.match(u.plan, /GLM-5\.3-Flash/)
  assert.match(u.windows[0].display, /已用 358 \/ 共 100,000,000 MTOKENS/)
  assert.equal(u.balance, "99,999,642 MTOKENS")
})

test("没有 Cookie 时额度给出明确提示，不静默", async () => {
  const p = await plugin()
  const auth = { type: "api", key: TOKEN_PLAN_KEY, metadata: { tier: "tokenplan" } }
  const u = await p.auth.usage(async () => auth)
  assert.equal(u.windows.length, 0)
  assert.match(u.error, /未提供控制台 Cookie/)
})

test("Cookie 过期时额度标记需要重新登录", async () => {
  const p = await plugin()
  const auth = {
    type: "api",
    key: TOKEN_PLAN_KEY,
    metadata: { tier: "tokenplan", consoleCookie: BAD_COOKIE },
  }
  const u = await p.auth.usage(async () => auth)
  assert.equal(u.signIn, "expired")
  assert.match(u.error, /未登录|请求失败/)
})

// ---- SSO 密码自动续期 ---------------------------------------------------------

test("SSO 登录用不带 originalUrl 的 service，能走完整链路拿到 Token", async () => {
  ssoLog.length = 0
  const cookie = await _internal.ssoLogin("{{PHONE_k3x9qm2p}}", "secret-pass")

  // 两枚 Cookie 缺一不可：Token 是控制台认可的凭据，jsessionid 是会话
  assert.match(cookie, /Token=tok-1/)
  assert.match(cookie, /jsessionid=js-1/)

  const page = ssoLog.find((s) => s.method === "GET" && s.url.startsWith("/sso/login"))
  assert.ok(page, "应当先请求登录页")
  // 这一条是本次故障的根因：service 带 originalUrl 时站点不发 Token
  assert.equal(page.service, "https://www.scnet.cn/ac/api/auth/loginSsoRedirect.action")
  assert.ok(!/originalUrl/.test(page.service), "service 不能带 originalUrl，否则拿不到 Token")

  const post = ssoLog.find((s) => s.form)
  assert.ok(post, "应当提交登录表单")
  assert.equal(post.form.username, "{{PHONE_k3x9qm2p}}")
  assert.equal(post.form.encrypted, "true")
  assert.equal(post.form.mode, "0")
  assert.equal(post.plain, "secret-pass", "密码应是站点公钥 RSA 加密后提交的")
})

test("SSO 登录拿不到 Token 时明确报错，不假装成功", async () => {
  // 用「故障账号」复刻当时的站点行为：只发 jsessionid，不发 Token
  await assert.rejects(
    () => _internal.ssoLogin("no-token", "secret-pass"),
    /SSO 登录未建立会话/
  )
})
