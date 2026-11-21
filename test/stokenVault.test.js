import assert from "node:assert/strict"
import { execFile } from "node:child_process"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import test from "node:test"
import { promisify } from "node:util"
import {
  MIHOYO_QR_LOGIN_REGEX,
  classifyBindingReply,
  completeCredentialFlow,
  exchangeCookieAccount,
  exchangeCookieAccountOnce,
  isPrivateMessage,
  parseLoginStokenAccount,
  redactLogError,
  redactLogValue,
} from "../Model/miHoYoAccount.js"
import { StokenVault } from "../Model/stokenVault.js"

const execFileAsync = promisify(execFile)

test("vault encrypts multiple accounts with atomic mode-600 files", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "trss-stoken-vault-"))
  t.after(() => fs.rm(root, { recursive: true, force: true }))
  const vault = new StokenVault(root)

  await vault.save("fixture-owner-a", {
    accountId: "fixture-account-a",
    mid: "fixture-mid-a",
    token: "fixture-token-a-not-real",
    tokenName: "stoken",
  })
  await vault.save("fixture-owner-a", {
    accountId: "fixture-account-b",
    mid: "fixture-mid-b",
    token: "fixture-token-b-not-real",
    tokenName: "stoken_v2",
  })

  const raw = await fs.readFile(path.join(root, "fixture-owner-a.json"), "utf8")
  assert.doesNotMatch(raw, /fixture-token-a-not-real|fixture-token-b-not-real/)
  assert.equal((await fs.stat(path.join(root, "fixture-owner-a.json"))).mode & 0o777, 0o600)
  assert.equal((await fs.stat(path.join(root, ".master-key"))).mode & 0o777, 0o600)
  assert.deepEqual(
    (await vault.readAccounts("fixture-owner-a")).map(item => item.token),
    ["fixture-token-a-not-real", "fixture-token-b-not-real"],
  )
  assert.equal(
    (await fs.readdir(root)).some(file => file.endsWith(".tmp")),
    false,
  )

  assert.equal(await vault.remove("fixture-owner-a", "fixture-account-a"), 1)
  assert.deepEqual(
    (await vault.list("fixture-owner-a")).map(item => item.accountId),
    ["fixture-account-b"],
  )
  assert.equal(await vault.remove("fixture-owner-a"), 1)
  assert.deepEqual(await vault.list("fixture-owner-a"), [])
})

test("vault preserves 12 concurrent account updates and serialized removals", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "trss-stoken-concurrent-"))
  t.after(() => fs.rm(root, { recursive: true, force: true }))
  const vaults = [new StokenVault(root), new StokenVault(root)]
  const accounts = Array.from({ length: 12 }, (_, index) => ({
    accountId: `fixture-account-${index}`,
    mid: `fixture-mid-${index}`,
    token: `fixture-token-${index}-not-real`,
    tokenName: index % 2 ? "stoken_v2" : "stoken",
  }))

  await Promise.all(
    accounts.map((account, index) => vaults[index % 2].save("fixture-owner-b", account)),
  )
  assert.deepEqual(
    (await vaults[0].list("fixture-owner-b")).map(item => item.accountId).sort(),
    accounts.map(item => item.accountId).sort(),
  )
  assert.equal((await vaults[0].readAccounts("fixture-owner-b")).length, 12)

  await Promise.all(
    accounts.slice(0, 6).map(account => vaults[1].remove("fixture-owner-b", account.accountId)),
  )
  assert.deepEqual(
    (await vaults[0].list("fixture-owner-b")).map(item => item.accountId).sort(),
    accounts
      .slice(6)
      .map(item => item.accountId)
      .sort(),
  )
  assert.equal(
    (await fs.readdir(root)).some(file => /\.lock|\.stale\.|\.tmp$/.test(file)),
    false,
  )
})

test("vault file lock preserves 12 updates across three processes", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "trss-stoken-processes-"))
  t.after(() => fs.rm(root, { recursive: true, force: true }))
  const moduleUrl = new URL("../Model/stokenVault.js", import.meta.url).href
  const script = `
    import { StokenVault } from ${JSON.stringify(moduleUrl)}
    const vault = new StokenVault(process.argv[1])
    const start = Number(process.argv[2])
    await Promise.all(Array.from({ length: 4 }, (_, offset) => vault.save("fixture-owner-c", {
      accountId: "fixture-process-account-" + (start + offset),
      mid: "fixture-process-mid-" + (start + offset),
      token: "fixture-process-token-" + (start + offset) + "-not-real",
      tokenName: "stoken",
    })))
  `
  await Promise.all(
    [0, 4, 8].map(start =>
      execFileAsync(process.execPath, ["--input-type=module", "-e", script, root, String(start)]),
    ),
  )

  const vault = new StokenVault(root)
  assert.equal((await vault.list("fixture-owner-c")).length, 12)
  assert.equal((await vault.readAccounts("fixture-owner-c")).length, 12)
  assert.equal(
    (await fs.readdir(root)).some(file => /\.lock|\.stale\./.test(file)),
    false,
  )
})

test("cookie exchange returns only a bindable Cookie", async () => {
  let captured
  const cookie = await exchangeCookieAccount(
    {
      accountId: "fixture-account-a",
      mid: "fixture-mid-a",
      token: "fixture-stoken-not-real",
      tokenName: "stoken",
    },
    async (url, options) => {
      captured = { url, options }
      return {
        ok: true,
        json: async () => ({
          retcode: 0,
          data: { ltoken: "fixture-ltoken-not-real", cookie_token: "fixture-cookie-not-real" },
        }),
      }
    },
  )

  assert.match(captured.options.cookie, /^stoken=fixture-stoken-not-real;/)
  assert.equal(
    cookie,
    "ltoken=fixture-ltoken-not-real;ltuid=fixture-account-a;cookie_token=fixture-cookie-not-real",
  )
  assert.doesNotMatch(cookie, /stoken=/)
})

test("legacy exchange normalizes stoken_v2", async () => {
  let captured
  await exchangeCookieAccount(
    {
      accountId: "fixture-account-b",
      mid: "fixture-mid-b",
      token: "fixture-v2-token-not-real",
      tokenName: "stoken_v2",
    },
    async (url, options) => {
      captured = { url, options }
      return {
        ok: true,
        json: async () => ({
          retcode: 0,
          data: { ltoken: "fixture-ltoken-not-real", cookie_token: "fixture-cookie-not-real" },
        }),
      }
    },
  )
  assert.match(captured.options.cookie, /^stoken=fixture-v2-token-not-real;/)
  assert.doesNotMatch(captured.options.cookie, /^stoken_v2=/)
  assert.equal(classifyBindingReply("绑定Cookie成功\nUID: fixture-uid-not-real"), "success")
  assert.equal(classifyBindingReply("绑定Cookie失败：Cookie错误"), "failed")
})

test("login aliases preserve the upstream Web and App QR split", async () => {
  const pattern = new RegExp(MIHOYO_QR_LOGIN_REGEX)
  for (const command of ["#米游社登录", "#扫码登录", "#米哈游登录"]) {
    assert.equal(pattern.test(command), true, `${command} must match the QR login rule`)
  }

  const source = await fs.readFile(new URL("../Apps/miHoYoLogin.js", import.meta.url), "utf8")
  assert.match(source, /reg: MIHOYO_QR_LOGIN_REGEX,\s+fnc: "miHoYoLoginQRCode"/)
  assert.match(source, /includes\("米游社"\)\) return this\.HyperionLogin\(\)/)
  assert.match(source, /\/web\/createQRLogin/)
  assert.match(source, /\/web\/queryQRLoginStatus/)
  assert.match(source, /\/app\/createQRLogin/)
  assert.match(source, /\/app\/queryQRLoginStatus/)
  assert.doesNotMatch(source, /res\.data\.tokens\[0\]/)
})

test("App QR fixture parses and saves an explicitly named fake Stoken", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "trss-app-qr-stoken-"))
  t.after(() => fs.rm(root, { recursive: true, force: true }))
  const vault = new StokenVault(root)
  const ownerId = "fixture-owner-app-qr-stoken"
  const data = {
    status: "Confirmed",
    tokens: [
      { name: "ltoken", token: "fixture-ltoken-json-not-real" },
      { name: "stoken_v2", token: "fixture-stoken-json-not-real" },
    ],
    user_info: {
      account_id_v2: "fixture-account-app-qr-stoken",
      account_mid_v2: "fixture-mid-app-qr-stoken",
    },
  }
  const account = parseLoginStokenAccount(data)
  assert.deepEqual(account, {
    accountId: "fixture-account-app-qr-stoken",
    mid: "fixture-mid-app-qr-stoken",
    token: "fixture-stoken-json-not-real",
    tokenName: "stoken_v2",
  })

  await completeCredentialFlow(account, {
    exchange: async () =>
      "ltoken=fixture-stoken-json-not-real;ltuid=fixture-account-app-qr-stoken;cookie_token=fixture-cookie-app-qr-not-real",
    bind: async () => "success",
    save: value => vault.save(ownerId, value),
  })

  assert.equal((await vault.readAccounts(ownerId))[0].token, "fixture-stoken-json-not-real")
})

test("credential entry helpers enforce private messages", async () => {
  assert.equal(isPrivateMessage({ isPrivate: true }), true)
  assert.equal(isPrivateMessage({ isPrivate: false }), false)
  const source = await fs.readFile(new URL("../Apps/miHoYoLogin.js", import.meta.url), "utf8")
  for (const method of ["miHoYoLoginDetect", "miHoYoLogin", "miHoYoLoginQRCode", "refreshCookie"]) {
    const start = source.indexOf(`${method}() {`)
    assert.notEqual(start, -1, `${method} must exist`)
    assert.match(source.slice(start, start + 180), /this\.privateOnly\(\)/)
  }
})

test("credential flow validates and binds before replacing an existing vault record", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "trss-stoken-ordering-"))
  t.after(() => fs.rm(root, { recursive: true, force: true }))
  const vault = new StokenVault(root)
  const ownerId = "fixture-owner-ordering"
  const original = {
    accountId: "fixture-account-ordering",
    mid: "fixture-mid-original",
    token: "fixture-token-original-not-real",
    tokenName: "stoken",
  }
  const replacement = {
    ...original,
    mid: "fixture-mid-replacement",
    token: "fixture-token-replacement-not-real",
  }
  await vault.save(ownerId, original)

  await assert.rejects(
    () =>
      completeCredentialFlow(replacement, {
        exchange: async () => {
          throw new Error("fictional exchange failure")
        },
        bind: async () => "success",
        save: value => vault.save(ownerId, value),
      }),
    /fictional exchange failure/,
  )
  assert.equal((await vault.readAccounts(ownerId))[0].token, original.token)

  await assert.rejects(
    () =>
      completeCredentialFlow(replacement, {
        exchange: async () => "fixture-bind-cookie-not-real",
        bind: async () => {
          throw new Error("fictional bind failure")
        },
        save: value => vault.save(ownerId, value),
      }),
    { stage: "bind", kind: "rejected" },
  )
  assert.equal((await vault.readAccounts(ownerId))[0].token, original.token)

  const order = []
  await completeCredentialFlow(replacement, {
    exchange: async () => {
      order.push("exchange")
      return "fixture-bind-cookie-not-real"
    },
    bind: async () => {
      order.push("bind")
      return "success"
    },
    save: async value => {
      order.push("save")
      await vault.save(ownerId, value)
    },
  })
  assert.deepEqual(order, ["exchange", "bind", "save"])
  assert.equal((await vault.readAccounts(ownerId))[0].token, replacement.token)
})

test("concurrent Cookie refreshes share one exchange per owner and account", async () => {
  let requests = 0
  let resolveRequest
  const requester = async () => {
    requests++
    if (requests === 1)
      await new Promise(resolve => {
        resolveRequest = resolve
      })
    return {
      ok: true,
      json: async () => ({
        retcode: 0,
        data: { ltoken: "fixture-ltoken-not-real", cookie_token: "fixture-cookie-not-real" },
      }),
    }
  }
  const account = {
    accountId: "fixture-account-latch",
    mid: "fixture-mid-latch",
    token: "fixture-token-latch-not-real",
    tokenName: "stoken",
  }
  const first = exchangeCookieAccountOnce("fixture-owner-latch", account, requester)
  const second = exchangeCookieAccountOnce("fixture-owner-latch", account, requester)
  assert.strictEqual(first, second)
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(requests, 1)
  resolveRequest()
  assert.equal(await first, await second)
})

test("credential logs contain only field names and status", () => {
  const values = {
    account_id: "fixture-account-log",
    aid: "fixture-aid-log",
    mid: "fixture-mid-log",
    uid: "fixture-uid-log",
    token: "fixture-token-log-not-real",
    login_ticket: "fixture-ticket-log-not-real",
    url: "https://invalid.example/?ticket=fixture-url-ticket-not-real",
    nested: "uid=fixture-inline-uid&cookie_token=fixture-inline-cookie-not-real",
  }
  const output = redactLogValue(values)
  for (const value of Object.values(values)) {
    assert.doesNotMatch(output, new RegExp(String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")))
  }
  const error = redactLogError(
    new Error("https://invalid.example/?uid=fixture-error-uid&stoken=fixture-error-token-not-real"),
  )
  assert.doesNotMatch(error, /fixture-error-uid|fixture-error-token-not-real/)
  assert.match(output, /^status=received fields=/)
  assert.match(error, /^status=failed fields=/)
})

test("App QR token type 1 is parsed as Stoken", () => {
  const account = parseLoginStokenAccount({
    tokens: [{ token_type: 1, token: "app-stoken" }],
    user_info: { aid: "10001", mid: "mid-10001" },
  })

  assert.deepEqual(account, {
    accountId: "10001",
    mid: "mid-10001",
    token: "app-stoken",
    tokenName: "stoken",
  })
})

test("unrelated numeric token types are not treated as Stoken", () => {
  const account = parseLoginStokenAccount({
    tokens: [{ token_type: 2, token: "other-token" }],
    user_info: { aid: "10002", mid: "mid-10002" },
  })

  assert.equal(account, null)
})
