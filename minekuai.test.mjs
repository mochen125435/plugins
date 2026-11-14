// 单元测试：只测纯函数，不触网。
// 跑法：node --test（在插件目录下）

import { test } from "node:test"
import assert from "node:assert/strict"

import { _internal } from "./minekuai.mjs"

const {
  root,
  checkURL,
  fmtTokens,
  pct,
  usageFrom,
  webTokenOf,
  label,
  credentialsOf,
  isStale,
  checkinOutcome,
  pointsWindow,
  dailyWindow,
  localDate,
  WEB_TOKEN_TTL,
  CLIENT_ID,
  contextLimitOf,
  GROUP_CONTEXT,
  groupNameOf,
  groupWindow,
  narrowUsage,
  fmtK,
  runtimeModel,
} = _internal

// ---- 地址规整 ----------------------------------------------------------------

test("root 去掉尾部斜杠与误填的 /v1", () => {
  assert.equal(root("https://minekuai.cn"), "https://minekuai.cn")
  assert.equal(root("https://minekuai.cn/"), "https://minekuai.cn")
  assert.equal(root("https://minekuai.cn/v1"), "https://minekuai.cn")
  assert.equal(root("https://minekuai.cn/v1/"), "https://minekuai.cn")
  assert.equal(root("  https://minekuai.cn  "), "https://minekuai.cn")
  // 部署路径前缀要保留，不能被 /v1 规则误伤
  assert.equal(root("https://example.com/relay"), "https://example.com/relay")
})

test("checkURL 接受 http/https，拒绝其它协议与带账号密码的地址", () => {
  assert.equal(checkURL("https://minekuai.cn"), null)
  assert.equal(checkURL("http://127.0.0.1:8080"), null)
  assert.match(checkURL("ftp://minekuai.cn"), /https/)
  assert.match(checkURL("minekuai.cn"), /https/)
  assert.match(checkURL("https://user:pw@minekuai.cn"), /账号密码/)
})

// ---- 展示格式 ----------------------------------------------------------------

test("fmtTokens 按亿 / 万 压缩", () => {
  assert.equal(fmtTokens(1_000_000_000), "10 亿")
  assert.equal(fmtTokens(12_500_000), "1,250 万")
  assert.equal(fmtTokens(1_234), "1,234")
  assert.equal(fmtTokens(0), "0")
  assert.equal(fmtTokens(undefined), "—")
})

test("pct 对 0 总量返回 0，不产生 NaN，也不超过 100", () => {
  assert.equal(pct(50, 100), 50)
  assert.equal(pct(0, 0), 0)
  assert.equal(pct(200, 100), 100)
})

// ---- 额度换算 ----------------------------------------------------------------

// 2026-11-13 在真实账号上读到的结构（数值替换过，形状保持原样）
const REAL_SHAPE = {
  paid: {
    group: "paygo",
    groupName: "按量付费",
    balance: 999_999_865,
    totalIn: 1_000_000_000,
    totalUsed: 135,
  },
  permanent: { balance: 10_000_000, totalIn: 10_000_000, totalUsed: 0 },
  remaining: 10_000_000,
}

test("usageFrom 把付费与免费两个桶都转成窗口", () => {
  const u = usageFrom(REAL_SHAPE, "minekuai.cn …abcd")
  assert.equal(u.user, "minekuai.cn …abcd")
  assert.equal(u.plan, "按量付费")
  assert.equal(u.windows.length, 2)
  assert.equal(u.windows[0].name, "付费按量 token")
  assert.equal(u.windows[1].name, "免费按量额度")
  // 135 / 10 亿：极小但不是 NaN
  assert.ok(u.windows[0].used > 0 && u.windows[0].used < 0.001)
  assert.match(u.windows[0].display, /已用 135/)
  assert.match(u.windows[0].display, /共 10 亿/)
  // 总剩余 = 付费剩余 + 免费剩余 = 999,999,865 + 10,000,000
  assert.equal(u.balance, "10.1 亿 token")
  assert.equal(u.error, undefined)
})

test("usageFrom 在付费额度用完时给出明确错误", () => {
  const u = usageFrom(
    {
      paid: { groupName: "按量付费", balance: 0, totalIn: 1_000_000_000, totalUsed: 1_000_000_000 },
      permanent: { balance: 0, totalIn: 0, totalUsed: 0 },
    },
    "x"
  )
  assert.equal(u.windows.length, 1)
  assert.equal(u.windows[0].used, 100)
  assert.match(u.error, /已用完/)
})

test("usageFrom 在没有任何额度时不假装成功", () => {
  const u = usageFrom({}, "x")
  assert.equal(u.windows.length, 0)
  assert.equal(u.balance, undefined)
  assert.match(u.error, /暂无可用额度/)
})

test("usageFrom 不把预付费包画成周期窗口", () => {
  // 麦块云是预付费 token 包，没有每天/每月重置；
  // 一旦写了 span 或 resetsAt，magpie 会画成「每日重置」，那是错的
  const u = usageFrom(REAL_SHAPE, "x")
  for (const w of u.windows) {
    assert.equal(w.span, undefined)
    assert.equal(w.resetsAt, undefined)
  }
})

// ---- 账号 --------------------------------------------------------------------

test("webTokenOf 容忍空白与缺失", () => {
  assert.equal(webTokenOf({ metadata: { webToken: "  eyJabc  " } }), "eyJabc")
  assert.equal(webTokenOf({ metadata: {} }), "")
  assert.equal(webTokenOf({}), "")
  assert.equal(webTokenOf(undefined), "")
})

test("label 只用密钥后四位，绝不暴露令牌", () => {
  const auth = { key: "sk-ABCDEFGHIJKLMNOP", metadata: { webToken: "eyJhbGciOiJIUzI1NiJ9.secret" } }
  const name = label(auth, "https://minekuai.cn")
  assert.equal(name, "minekuai.cn …MNOP")
  assert.doesNotMatch(name, /eyJ/)
  assert.doesNotMatch(name, /sk-A/)
})

test("clientid 常量与站点前端一致", () => {
  // 取自麦块云前端 bundle 里硬编码的 Lc 常量；
  // 少了它 /app/token 返回 401，站点改版时这里要跟着更新
  assert.equal(CLIENT_ID, "428a8310cd442757ae699df5d894f051")
})

// ---- 令牌续期 ----------------------------------------------------------------

test("credentialsOf 缺手机号或密码都返回 undefined", () => {
  assert.deepEqual(credentialsOf({ metadata: { phone: "13800000000", password: "pw" } }), {
    phone: "13800000000",
    password: "pw",
  })
  assert.equal(credentialsOf({ metadata: { phone: "13800000000" } }), undefined)
  assert.equal(credentialsOf({ metadata: { password: "pw" } }), undefined)
  assert.equal(credentialsOf({ metadata: {} }), undefined)
})

test("isStale 按 1 天提前量判断是否需要续期", () => {
  const now = Date.now()
  // 还剩 12 小时 → 该续了
  assert.equal(isStale({ metadata: { webTokenExpireAt: now + 12 * 3600 * 1000 } }), true)
  // 还剩 6 天 → 不用续
  assert.equal(isStale({ metadata: { webTokenExpireAt: now + 6 * 86400 * 1000 } }), false)
  // 已过期 → 要续
  assert.equal(isStale({ metadata: { webTokenExpireAt: now - 1000 } }), true)
  // 没有记录过期时间的老账号 → 交给 401 触发
  assert.equal(isStale({ metadata: {} }), false)
})

test("WEB_TOKEN_TTL 与站点前端的 7 天一致", () => {
  assert.equal(WEB_TOKEN_TTL, 7 * 24 * 3600 * 1000)
})

// ---- 签到结果映射 ------------------------------------------------------------

test("checkinOutcome 把三种结果映射成 magpie 的 outcome", () => {
  // 刚签成功
  assert.deepEqual(
    checkinOutcome({ state: "done", credit: 10, streak: 3 }),
    { outcome: "claimed", credit: 10, streak: 3, message: "签到成功 +10 鱼币 · 连续 3 天" }
  )
  // 今天已签：不是失败
  const done = checkinOutcome({ state: "already", credit: 10, detail: "今天已签到 +10 鱼币，明天再来" })
  assert.equal(done.outcome, "done")
  assert.equal(done.credit, 10)
  // 真失败
  const failed = checkinOutcome({ state: "failed", detail: "签到服务暂时不可用" })
  assert.equal(failed.outcome, "failed")
  assert.match(failed.message, /不可用/)
})

test("checkinOutcome 在奖励缺失时也不编数字", () => {
  const r = checkinOutcome({ state: "done" })
  assert.equal(r.outcome, "claimed")
  assert.equal(r.credit, undefined)
  assert.equal(r.streak, undefined)
  assert.equal(r.message, "签到成功")
})

test("checkinOutcome 透传登录失效标记", () => {
  const r = checkinOutcome({ state: "failed", detail: "认证失败", signIn: "expired" })
  assert.equal(r.outcome, "failed")
  assert.equal(r.signIn, "expired")
})

test("localDate 用本地时区，不受 UTC 偏移影响", () => {
  assert.equal(localDate(new Date(2026, 10, 13, 0, 5)), "2026-11-13")
  assert.equal(localDate(new Date(2026, 10, 13, 23, 55)), "2026-11-13")
  assert.match(localDate(), /^\d{4}-\d{2}-\d{2}$/)
})

// ---- 鱼币余额 ----------------------------------------------------------------

test("pointsWindow 显示鱼币总数，不把字符串当数字", () => {
  // 站点返回的是字符串 "40.0000"，必须转换后再展示
  const w = pointsWindow({
    giftPoints: "40.0000",
    heldPoints: "0.0000",
    paidPoints: "0.0000",
    totalPoints: "40.0000",
  })
  assert.equal(w.name, "鱼币余额")
  assert.equal(w.display, "40 鱼币")
  assert.equal(w.aside, true, "只展示，不参与路由")
})

test("pointsWindow 在充值与冻结非零时展开细分", () => {
  const w = pointsWindow({
    giftPoints: "40.0000",
    heldPoints: "5.0000",
    paidPoints: "100.0000",
    totalPoints: "145.0000",
  })
  assert.match(w.display, /145 鱼币/)
  assert.match(w.display, /赠送 40/)
  assert.match(w.display, /充值 100/)
  assert.match(w.display, /冻结 5/)
})

test("pointsWindow 在钱包为空时返回 null，不编造 0", () => {
  assert.equal(pointsWindow({}), null)
  assert.equal(pointsWindow(undefined), null)
})

test("pointsWindow 与 token 余额是两套单位，不写进 balance", () => {
  // 鱼币是站内货币，token 是模型用量；混在一起会得到没有意义的数字
  const w = pointsWindow({ totalPoints: "40.0000", giftPoints: "40.0000" })
  assert.equal(w.balance, undefined)
  assert.match(w.display, /鱼币/)
})

// ---- 今日用量 ----------------------------------------------------------------

test("dailyWindow 的 token 口径包含缓存读（与站点一致）", () => {
  // 站点「Token」= 未命中输入 + 缓存读 + 输出
  const w = dailyWindow({
    daily: [
      {
        date: localDate(),
        inputTokens: 1156619,
        cacheReadTokens: 4533632,
        outputTokens: 9462,
        requests: 17,
      },
    ],
  })
  assert.equal(w.name, "今日用量")
  assert.equal(w.display, "569.97 万 token · 17 次调用")
  assert.equal(w.aside, true)
})

test("dailyWindow 在今天没有调用时明确说暂无调用", () => {
  const w = dailyWindow({
    daily: [{ date: localDate(), inputTokens: 0, cacheReadTokens: 0, outputTokens: 0, requests: 0 }],
  })
  assert.equal(w.display, "今日暂无调用")
})

test("dailyWindow 找不到今天那行时退回最后一行", () => {
  const w = dailyWindow({
    daily: [
      { date: "2026-01-01", inputTokens: 1, cacheReadTokens: 0, outputTokens: 1, requests: 1 },
      { date: "2026-01-02", inputTokens: 100, cacheReadTokens: 0, outputTokens: 0, requests: 2 },
    ],
    // 今天不在列表里
  })
  assert.equal(w.display, "100 token · 2 次调用")
})

test("dailyWindow 没有数据时返回 null，不编造 0", () => {
  assert.equal(dailyWindow({}), null)
  assert.equal(dailyWindow({ daily: [] }), null)
  assert.equal(dailyWindow(undefined), null)
})

test("dailyWindow 能吃 /app/llm/requests/summary 的单 key 汇总，并标明范围", () => {
  // summary 的 data：已经按 apiKeyId 过滤过，本身就是一行，没有 daily 数组
  const w = dailyWindow(
    {
      requests: 28,
      success: 28,
      inputTokens: 300000,
      cacheReadTokens: 1000000,
      cacheWriteTokens: 0,
      outputTokens: 5000,
      points: "0.0000",
      beginTime: "2026-11-14 00:00:00",
      endTime: "2026-11-14 23:59:59",
    },
    localDate(),
    "key"
  )
  assert.equal(w.name, "今日用量（本 key）")
  // 30 万 + 100 万 + 0.5 万 = 130.5 万
  assert.equal(w.display, "130.5 万 token · 28 次调用")
})

test("dailyWindow 的 key 口径在没有调用时说暂无调用", () => {
  const w = dailyWindow({ requests: 0, inputTokens: 0, cacheReadTokens: 0, outputTokens: 0 }, localDate(), "key")
  assert.equal(w.display, "今日暂无调用")
})

test("dailyWindow 账号口径的行名不带「本 key」", () => {
  const w = dailyWindow({
    daily: [{ date: localDate(), inputTokens: 10, cacheReadTokens: 0, outputTokens: 0, requests: 1 }],
  })
  assert.equal(w.name, "今日用量")
})

// ---- 密钥分组与上下文 -------------------------------------------------------

test("contextLimitOf 按分组给出不同上下文：paygo 600K / Lite 256K", () => {
  // 付费按量：站点硬上限 640K，按 600K 声明留 40K 给提前压缩
  assert.equal(contextLimitOf("deepseek-v4.1-flash-1017", "paygo"), 600_000)
  // Lite 免费：站点标 256K，原样声明
  assert.equal(contextLimitOf("deepseek-v4.1-flash-1017", "default"), 256_000)
  // 分组读不到时按 Lite 保守处理，绝不按 600K 放开
  assert.equal(contextLimitOf("deepseek-v4.1-flash-1017", undefined), 256_000)
  assert.equal(contextLimitOf("deepseek-v4.1-flash-1017", "unknown-group"), 256_000)
  // 非 DeepSeek 模型没有实测数据，保持 0
  assert.equal(contextLimitOf("glm-4.6", "paygo"), 0)
})

test("GROUP_CONTEXT 记录站点标称值与实际的压缩值", () => {
  assert.equal(GROUP_CONTEXT.paygo.site, 640_000)
  assert.equal(GROUP_CONTEXT.paygo.context, 600_000)
  assert.equal(GROUP_CONTEXT.default.site, 256_000)
  assert.equal(GROUP_CONTEXT.default.context, 256_000)
  assert.equal(groupNameOf("paygo"), "按量付费")
  assert.equal(groupNameOf("default"), "Lite 免费")
  // 未知分组不吞掉信息，原样返回 code
  assert.equal(groupNameOf("vip"), "vip")
})

test("fmtK 把上下文写成 K，非法值给「未知」", () => {
  assert.equal(fmtK(600_000), "600K")
  assert.equal(fmtK(256_000), "256K")
  assert.equal(fmtK(0), "未知")
  assert.equal(fmtK(undefined), "未知")
})

test("groupWindow 显示分组与两组上下文，付费组不报警", () => {
  const w = groupWindow({ group: "paygo" }, { paid: { balance: "943829213" } })
  assert.equal(w.aside, true)
  assert.match(w.display, /按量付费/)
  assert.match(w.display, /640K/)
  assert.match(w.display, /600K/)
  assert.doesNotMatch(w.display, /不会扣付费 token/)
})

test("groupWindow 在 Lite 组但账号有付费余额时给出混用提醒", () => {
  const w = groupWindow({ group: "default" }, { paid: { balance: "943829213" } })
  assert.match(w.display, /Lite 免费/)
  assert.match(w.display, /256K/)
  assert.match(w.display, /不会扣付费 token/)
})

test("groupWindow 读不到分组时说明按 256K 保守声明", () => {
  const w = groupWindow(null, {})
  assert.match(w.display, /未能读取密钥分组/)
  assert.match(w.display, /256K/)
})

test("runtimeModel 把分组上下文写进 limit.context", () => {
  const paygo = runtimeModel({ id: "deepseek-v4.1-flash-1017", name: "DeepSeek" }, "https://minekuai.cn/v1", "minekuai", "paygo")
  assert.equal(paygo.limit.context, 600_000)
  // 付费组用真实模型名当 id
  assert.equal(paygo.id, "deepseek-v4.1-flash-1017")

  const free = runtimeModel({ id: "deepseek-v4.1-flash-1017", name: "DeepSeek" }, "https://minekuai.cn/v1", "minekuai", "default")
  assert.equal(free.limit.context, 256_000)
  // 免费组用 -lite 后缀区分，避免和付费组同名互相覆盖；
  // 发给上游的 api.id 仍是真实模型名
  assert.equal(free.id, "deepseek-v4.1-flash-1017-lite")
  assert.equal(free.api.id, "deepseek-v4.1-flash-1017")
  assert.match(free.name, /Lite 256K/)
})

// ---- 按分组裁剪额度显示 -----------------------------------------------------

const BOTH_BUCKETS = {
  paid: { group: "paygo", groupName: "按量付费", balance: 900, totalIn: 1000, totalUsed: 100 },
  permanent: { balance: 50, totalIn: 60, totalUsed: 10 },
  remaining: 110,
}

test("narrowUsage 付费组只留付费桶，余额只算付费", () => {
  const out = usageFrom(BOTH_BUCKETS, "u")
  narrowUsage(out, BOTH_BUCKETS, "paygo")
  assert.deepEqual(out.windows.map((w) => w.name), ["付费按量 token"])
  assert.equal(out.plan, "按量付费")
  assert.equal(out.balance, "900 token")
})

test("narrowUsage 免费组补出今日免费额度那一行", () => {
  const data = {
    ...BOTH_BUCKETS,
    today: { used: 5_000_000, remaining: 45_000_000 },
  }
  const out = usageFrom(data, "u")
  narrowUsage(out, data, "default")
  const names = out.windows.map((w) => w.name)
  assert.deepEqual(names, ["今日免费额度", "免费按量额度"])
  assert.match(out.windows[0].display, /共 5,000 万/)
  assert.match(out.windows[0].display, /剩余 4,500 万/)
})

test("narrowUsage 免费组只留免费桶，余额用站点 remaining（今日 + 永久）", () => {
  const out = usageFrom(BOTH_BUCKETS, "u")
  narrowUsage(out, BOTH_BUCKETS, "default")
  assert.deepEqual(out.windows.map((w) => w.name), ["免费按量额度"])
  assert.equal(out.plan, "Lite 免费")
  // remaining 是本 key 真正能用的总量，不是付费+免费相加
  assert.equal(out.balance, "110 token")
})

test("narrowUsage 免费组去掉「付费套餐用完」这类与它无关的错误", () => {
  const data = {
    paid: { group: "paygo", groupName: "按量付费", balance: 0, totalIn: 1000, totalUsed: 1000 },
    permanent: { balance: 50, totalIn: 60, totalUsed: 10 },
    remaining: 50,
  }
  const out = usageFrom(data, "u")
  assert.match(out.error, /付费/)
  narrowUsage(out, data, "default")
  assert.equal(out.error, undefined)
})

test("narrowUsage 分组未知时原样返回，不猜", () => {
  const out = usageFrom(BOTH_BUCKETS, "u")
  const before = out.windows.map((w) => w.name)
  narrowUsage(out, BOTH_BUCKETS, undefined)
  assert.deepEqual(out.windows.map((w) => w.name), before)
})
