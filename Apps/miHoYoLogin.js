import config from "../Model/config.js"
import QR from "qrcode"
import _ from "lodash"
import crypto from "crypto"
import fetch from "node-fetch"
import {
  MIHOYO_LOGIN_REGEX,
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
import { stokenVault } from "../Model/stokenVault.js"

const regex = MIHOYO_LOGIN_REGEX
const publicKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDvekdPMHN3AYhm/vktJT+YJr7cI5DcsNKqdsx5DZX0gDuWFuIjzdwButrIYPNmRJ1G8ybDIF7oDW2eEpm5sMbL9zs
9ExXCdvqrn51qELbqj0XxtMTIpaCHFSI50PfPpTFV9Xt/hmyVwokoOXFlAEgCn+Q
CgGs52bFoYMtyi+xEQIDAQAB
-----END PUBLIC KEY-----`

function random_string(n) {
  return _.sampleSize("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", n).join("")
}

function encrypt_data(data) {
  return crypto
    .publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PADDING,
      },
      data,
    )
    .toString("base64")
}

function md5(data) {
  return crypto.createHash("md5").update(data).digest("hex")
}

function ds(data) {
  const t = Math.floor(Date.now() / 1000)
  const r = random_string(6)
  const h = md5(`salt=JwYDpKvLj6MrMqqYU6jTKF17KNO2PXoS&t=${t}&r=${r}&b=${data}&q=`)
  return `${t},${r},${h}`
}

function request(url, { data, aigis, cookie } = {}) {
  const opts = {}
  if (data) {
    opts.method = "post"
    opts.body = JSON.stringify(data)
  }
  opts.headers = {
    "x-rpc-app_version": "2.104.0",
    DS: ds(opts.body ?? ""),
    "x-rpc-aigis": aigis,
    "Content-Type": "application/json",
    Accept: "application/json",
    "x-rpc-game_biz": "bbs_cn",
    "x-rpc-sys_version": "12",
    "x-rpc-device_id": random_string(16),
    "x-rpc-device_fp": random_string(13),
    "x-rpc-device_name": random_string(16),
    "x-rpc-device_model": random_string(16),
    "x-rpc-app_id": "bll8iq97cem8",
    "x-rpc-client_type": "2",
    "User-Agent": "Hyperion/550 CFNetwork/3860.500.112 Darwin/25.4.0",
    Cookie: cookie,
  }
  return fetch(url, opts)
}

function app_request(url, { data, device_id }) {
  return fetch(url, {
    method: "post",
    body: data ? JSON.stringify(data) : "{}",
    headers: {
      "User-Agent": "HYPContainer/1.3.3.182",
      "x-rpc-app_id": "ddxf5dufpuyo",
      "x-rpc-client_type": "3",
      "x-rpc-device_id": device_id,
    },
  })
}

const web_headers = {
  "User-Agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
  "x-rpc-app_id": "bll8iq97cem8",
  "x-rpc-device_id": random_string(16),
}

function safeResponse(data) {
  return redactLogValue(data)
}

function safeError(error) {
  return redactLogError(error)
}

function maskId(id) {
  const value = String(id)
  return value.length <= 4 ? "****" : `${"*".repeat(value.length - 4)}${value.slice(-4)}`
}

const errorTips = [
  "登录失败，请检查日志\n请稍后重试【#扫码登录】\nhttps://git.trss.me/TRSS-Plugin",
  segment.button([
    { text: "米哈游登录", callback: "米哈游登录" },
    { text: "米游社登录", callback: "米游社登录" },
  ]),
]
const accounts = {}
const Running = {}
const pendingDeleteAll = new Map()

export class miHoYoLogin extends plugin {
  constructor() {
    super({
      name: "米哈游登录",
      dsc: "米哈游登录",
      event: "message",
      priority: 10,
      rule: [
        {
          reg: MIHOYO_QR_LOGIN_REGEX,
          fnc: "miHoYoLoginQRCode",
        },
        {
          reg: `${regex}.+$`,
          fnc: "miHoYoLoginDetect",
        },
        {
          reg: "^#?(体力|(c|C)(oo)?k(ie)?|(s|S)(to)?k(en)?)(帮助|教程)$",
          fnc: "miHoYoLoginHelp",
        },
        {
          reg: "^#stoken状态$",
          fnc: "stokenStatus",
        },
        {
          reg: "^#删除stoken(?:\\s+(?:all|全部|确认全部|[0-9]+))?$",
          fnc: "deleteStoken",
        },
        {
          reg: "^#刷新(c|C)(k|K)$",
          fnc: "refreshCookie",
        },
      ],
    })
  }

  miHoYoLoginDetect() {
    if (this.privateOnly()) return true
    accounts[this.e.user_id] = this.e
    this.setContext("miHoYoLogin")
    this.reply("请发送密码", true, { recallMsg: 60 })
  }

  async crack_geetest(gt, challenge) {
    let res
    this.reply(
      `请完成验证：https://challenge.minigg.cn/manual/index.html?gt=${gt}&challenge=${challenge}`,
      true,
      { recallMsg: 60 },
    )
    for (let n = 1; n < 60; n++) {
      await Bot.sleep(5000)
      try {
        res = await fetch(`https://challenge.minigg.cn/manual/?callback=${challenge}`)
        res = await res.json()
        if (res.retcode === 200) return res.data
      } catch (err) {
        logger.error("[米哈游登录]", safeError(err))
      }
    }
    this.reply("验证超时", true, { recallMsg: 60 })
    return false
  }

  async miHoYoLogin() {
    if (this.privateOnly()) {
      this.finish("miHoYoLogin")
      return true
    }
    if (!this.e.msg) return false
    this.finish("miHoYoLogin")
    if (Running[this.e.user_id]) {
      this.reply("有正在进行的登录操作，请完成后再试……", true, { recallMsg: 60 })
      return false
    }
    Running[this.e.user_id] = true

    const password = this.e.msg.trim()
    this.e = accounts[this.e.user_id]
    const account = this.e.msg.replace(new RegExp(regex), "").trim()

    const data = {
      account: encrypt_data(account),
      password: encrypt_data(password),
    }

    const url = "https://passport-api.mihoyo.com/account/ma-cn-passport/app/loginByPassword"
    let res = await request(url, { data, aigis: "" })
    const aigis_data = JSON.parse(res.headers.get("x-rpc-aigis"))
    res = await res.json()
    logger.mark(`[米哈游登录] ${logger.blue(safeResponse(res))}`)

    if (res.retcode === -3101) {
      logger.mark("[米哈游登录] 正在验证")
      const aigis_captcha_data = JSON.parse(aigis_data.data)
      const challenge = aigis_captcha_data.challenge
      const validate = await this.crack_geetest(aigis_captcha_data.gt, challenge)
      if (validate.geetest_validate) {
        logger.mark("[米哈游登录] 验证成功")
      } else {
        logger.error("[米哈游登录] 验证失败")
        Running[this.e.user_id] = false
        return false
      }

      const aigis =
        aigis_data.session_id +
        ";" +
        Buffer.from(
          JSON.stringify({
            geetest_challenge: challenge,
            geetest_seccode: validate.geetest_validate + "|jordan",
            geetest_validate: validate.geetest_validate,
          }),
        ).toString("base64")

      res = await request(url, { data, aigis })
      res = await res.json()
      logger.mark(`[米哈游登录] ${logger.blue(safeResponse(res))}`)
    }

    if (res.retcode !== 0) {
      this.reply(`错误：${safeResponse(res)}`, true, { recallMsg: 60 })
      Running[this.e.user_id] = false
      return false
    }
    const stokenAccount = {
      accountId: String(res.data.user_info.aid),
      mid: String(res.data.user_info.mid),
      token: res.data.token.token,
      tokenName: "stoken",
    }
    try {
      await completeCredentialFlow(stokenAccount, {
        exchange: async account => {
          let cookie = await exchangeCookieAccount(account, request)
          if (res.data.login_ticket) cookie += `;login_ticket=${res.data.login_ticket}`
          return cookie
        },
        bind: cookie => this.makeMessage(cookie),
        save: account => stokenVault.save(this.e.user_id, account),
      })
      this.reply("登录完成，Cookie 已自动绑定，Stoken 已加密保存")
    } catch (err) {
      logger.error("[米哈游登录]", safeError(err))
      this.reply(errorTips, true, { recallMsg: 60 })
    } finally {
      Running[this.e.user_id] = false
    }
  }

  async miHoYoLoginQRCode() {
    if (this.privateOnly()) return true
    if (this.e.msg.includes("终止")) {
      Running[this.e.user_id] = false
      return true
    }

    // Preserve the upstream split: 米游社 uses Web QR, other aliases use App QR.
    if (this.e.msg.includes("米游社")) return this.HyperionLogin()

    if (Running[this.e.user_id])
      return this.reply(
        [
          "请使用米游社扫码登录",
          Running[this.e.user_id],
          segment.button([{ text: "终止登录", callback: "米哈游登录终止" }]),
        ],
        true,
        {
          recallMsg: 60,
        },
      )
    Running[this.e.user_id] = true

    const device_id = random_string(16)
    let res, ticket
    try {
      res = await app_request(
        "https://passport-api.mihoyo.com/account/ma-cn-passport/app/createQRLogin",
        { device_id },
      )
      res = await res.json()
      logger.mark(`[米哈游登录] ${logger.blue(safeResponse(res))}`)

      const url = res.data.url
      ticket = res.data.ticket
      const img = segment.image(
        (await QR.toDataURL(url)).replace("data:image/png;base64,", "base64://"),
      )
      Running[this.e.user_id] = img
      this.reply(
        [
          "请使用米游社扫码登录",
          img,
          segment.button([{ text: "终止登录", callback: "米哈游登录终止" }]),
        ],
        true,
        { recallMsg: 60 },
      )
    } catch (err) {
      Running[this.e.user_id] = false
      return logger.error("[米哈游登录]", safeError(err))
    }

    let data, Scanned
    for (let n = 1; n < 60; n++) {
      await Bot.sleep(5000)
      if (Running[this.e.user_id] === false)
        return this.reply(
          [
            "米哈游登录已终止",
            segment.button([
              { text: "米哈游登录", callback: "米哈游登录" },
              { text: "米游社登录", callback: "米游社登录" },
            ]),
          ],
          true,
          { recallMsg: 60 },
        )
      try {
        res = await app_request(
          "https://passport-api.mihoyo.com/account/ma-cn-passport/app/queryQRLoginStatus",
          {
            device_id,
            data: { ticket },
          },
        )
        res = await res.json()

        if (res.retcode !== 0) {
          Running[this.e.user_id] = false
          return this.reply(
            [
              "二维码已过期，请重新登录",
              segment.button([
                { text: "米哈游登录", callback: "米哈游登录" },
                { text: "米游社登录", callback: "米游社登录" },
              ]),
            ],
            true,
            { recallMsg: 60 },
          )
        }

        if (res.data.status === "Scanned" && !Scanned) {
          logger.mark(`[米哈游登录] ${logger.blue(safeResponse(res))}`)
          Scanned = true
          this.reply(
            [
              "二维码已扫描，请确认登录",
              segment.button([{ text: "终止登录", callback: "米哈游登录终止" }]),
            ],
            true,
            { recallMsg: 60 },
          )
        }

        if (res.data.status === "Confirmed") {
          logger.mark(`[米哈游登录] ${logger.blue(safeResponse(res))}`)
          break
        }
      } catch (err) {
        logger.error("[米哈游登录]", safeError(err))
      }
    }
    Running[this.e.user_id] = false

    try {
      if (!(res.data?.tokens && res.data?.user_info))
        return this.reply(errorTips, true, { recallMsg: 60 })

      const account = parseLoginStokenAccount(res.data)
      if (!account) return this.reply(errorTips, true, { recallMsg: 60 })

      await completeCredentialFlow(account, {
        exchange: value => exchangeCookieAccount(value, request),
        bind: cookie => this.makeMessage(cookie),
        save: value => stokenVault.save(this.e.user_id, value),
      })
      this.reply("登录完成，Cookie 已自动绑定，Stoken 已加密保存")
    } catch (err) {
      logger.error("[米哈游登录]", safeError(err))
      return this.reply(errorTips, true, { recallMsg: 60 })
    }
  }

  async HyperionLogin() {
    if (Running[this.e.user_id]) {
      return this.reply(
        [
          "请使用米游社扫码登录",
          Running[this.e.user_id],
          segment.button([{ text: "终止登录", callback: "米游社登录终止" }]),
        ],
        true,
        { recallMsg: 60 },
      )
    }
    Running[this.e.user_id] = true

    let res
    let ticket
    try {
      res = await fetch(
        "https://passport-api.mihoyo.com/account/ma-cn-passport/web/createQRLogin",
        { headers: web_headers, method: "post", body: "{}" },
      )
      res = await res.json()
      logger.mark(`[米游社登录] ${logger.blue(safeResponse(res))}`)

      const img = segment.image(
        (await QR.toDataURL(res.data.url)).replace("data:image/png;base64,", "base64://"),
      )
      ticket = res.data.ticket
      Running[this.e.user_id] = img
      this.reply(
        [
          "请使用米游社扫码登录",
          img,
          segment.button([{ text: "终止登录", callback: "米游社登录终止" }]),
        ],
        true,
        { recallMsg: 60 },
      )
    } catch (err) {
      Running[this.e.user_id] = false
      logger.error("[米游社登录]", safeError(err))
      return this.reply(errorTips, true, { recallMsg: 60 })
    }

    let setCookies
    let scanned = false
    for (let n = 1; n < 60; n++) {
      await Bot.sleep(5000)
      if (Running[this.e.user_id] === false) {
        return this.reply("米游社登录已终止", true, { recallMsg: 60 })
      }
      try {
        const response = await fetch(
          "https://passport-api.mihoyo.com/account/ma-cn-passport/web/queryQRLoginStatus",
          { headers: web_headers, method: "post", body: JSON.stringify({ ticket }) },
        )
        setCookies = response.headers.getSetCookie()
        res = await response.json()

        if (res.retcode !== 0) {
          Running[this.e.user_id] = false
          return this.reply("二维码已过期，请重新登录", true, { recallMsg: 60 })
        }
        if (res.data.status === "Scanned" && !scanned) {
          logger.mark(`[米游社登录] ${logger.blue(safeResponse(res))}`)
          scanned = true
          this.reply("二维码已扫描，请确认登录", true, { recallMsg: 60 })
        }
        if (res.data.status === "Confirmed") {
          logger.mark(`[米游社登录] ${logger.blue(safeResponse(res))}`)
          break
        }
      } catch (err) {
        logger.error("[米游社登录]", safeError(err))
      }
    }
    Running[this.e.user_id] = false

    const cookie = (setCookies || [])
      .map(item => item.split(";", 1)[0])
      .filter(item => item.includes("="))
      .join(";")
    if (!cookie) return this.reply(errorTips, true, { recallMsg: 60 })

    await this.makeMessage(cookie)
    return this.reply("登录完成，Cookie 已送入绑定流程；此登录方式不保存 Stoken")
  }

  privateOnly() {
    if (isPrivateMessage(this.e)) return false
    this.reply("该命令仅支持私聊")
    return true
  }

  async stokenStatus() {
    if (this.privateOnly()) return true
    try {
      const accounts = await stokenVault.list(this.e.user_id)
      if (!accounts.length) return this.reply("尚未保存 Stoken，请先扫码登录")
      const lines = accounts.map(
        (account, index) =>
          `${index + 1}. 通行证 ${maskId(account.accountId)}，更新于 ${account.updatedAt.replace("T", " ").slice(0, 19)}`,
      )
      return this.reply([`已加密保存 ${accounts.length} 个账号的 Stoken`, ...lines].join("\n"))
    } catch (err) {
      logger.error("[米哈游登录]", safeError(err))
      return this.reply("读取 Stoken 状态失败，请检查日志")
    }
  }

  async deleteStoken() {
    if (this.privateOnly()) return true
    const argument = this.e.msg
      .replace(/^#删除stoken/, "")
      .trim()
      .toLowerCase()
    try {
      if (!argument) {
        return this.reply(
          "请先用【#stoken状态】查看序号，再发送【#删除stoken 序号】\n删除全部请发送【#删除stoken all】并按提示确认",
        )
      }
      if (["all", "全部"].includes(argument)) {
        pendingDeleteAll.set(String(this.e.user_id), Date.now() + 60000)
        return this.reply("此操作会删除全部 Stoken，请在 60 秒内发送【#删除stoken 确认全部】")
      }
      if (argument === "确认全部") {
        const expiresAt = pendingDeleteAll.get(String(this.e.user_id)) || 0
        pendingDeleteAll.delete(String(this.e.user_id))
        if (expiresAt < Date.now())
          return this.reply("删除确认已过期，请重新发送【#删除stoken all】")
        const removed = await stokenVault.remove(this.e.user_id)
        if (!removed) return this.reply("没有找到可删除的 Stoken")
        return this.reply(`已删除全部 ${removed} 个账号的 Stoken`)
      }

      const index = Number(argument)
      const accounts = await stokenVault.list(this.e.user_id)
      if (!Number.isInteger(index) || index < 1 || index > accounts.length) {
        return this.reply("序号无效，请先发送【#stoken状态】查看账号序号")
      }
      const removed = await stokenVault.remove(this.e.user_id, accounts[index - 1].accountId)
      if (!removed) return this.reply("没有找到可删除的 Stoken")
      return this.reply(`已删除序号 ${index} 对应账号的 Stoken`)
    } catch (err) {
      logger.error("[米哈游登录]", safeError(err))
      return this.reply("删除 Stoken 失败，请检查日志")
    }
  }

  async refreshCookie() {
    if (this.privateOnly()) return true
    let accounts
    try {
      accounts = await stokenVault.readAccounts(this.e.user_id)
    } catch (err) {
      logger.error("[米哈游登录]", safeError(err))
      return this.reply("读取 Stoken 失败，请检查日志")
    }
    if (!accounts.length) return this.reply("尚未保存 Stoken，请先扫码登录")

    let exchanged = 0
    let bound = 0
    let bindFailed = 0
    let bindTimeout = 0
    for (const account of accounts) {
      try {
        const cookie = await exchangeCookieAccountOnce(this.e.user_id, account, request)
        exchanged++
        const result = await this.makeMessage(cookie, { waitForBinding: true })
        if (result === "success") bound++
        else if (result === "failed") bindFailed++
        else bindTimeout++
      } catch (err) {
        logger.error("[米哈游登录] Cookie 刷新失败", safeError(err))
      }
    }
    if (!exchanged) return this.reply("Cookie 刷新失败，Stoken 可能已失效，请重新扫码登录")
    return this.reply(
      [
        `Cookie 换取成功 ${exchanged}/${accounts.length} 个账号`,
        `绑定成功 ${bound} 个，绑定失败 ${bindFailed} 个，等待结果超时 ${bindTimeout} 个`,
      ].join("\n"),
    )
  }

  makeMessage(msg, { waitForBinding = false } = {}) {
    const emit = reply =>
      Bot.em("message.private.friend", {
        self_id: this.e.self_id,
        message_id: this.e.message_id,
        user_id: this.e.user_id,
        sender: this.e.sender,
        friend: this.e.friend,
        reply,
        post_type: "message",
        message_type: "private",
        sub_type: "friend",
        message: [{ type: "text", text: msg }],
        raw_message: msg,
      })
    if (!waitForBinding) {
      return emit((reply, quote, opts) => this.reply(reply, quote, { ...opts, recallMsg: 60 }))
    }

    return new Promise(resolve => {
      let settled = false
      const finish = result => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        resolve(result)
      }
      const timer = setTimeout(() => finish("timeout"), 60000)
      try {
        emit(async (reply, quote, opts) => {
          await this.reply(reply, quote, { ...opts, recallMsg: 60 })
          const result = classifyBindingReply(reply)
          if (result !== "pending") finish(result)
        })
      } catch (error) {
        logger.error("[米哈游登录]", safeError(error))
        finish("failed")
      }
    })
  }

  miHoYoLoginHelp() {
    if (!config.miHoYoLogin.help) return false
    this.reply(
      [
        "优先发送【米哈游登录】\n如果无法登录发送【米游社登录】",
        segment.button([
          { text: "米哈游登录", callback: "米哈游登录" },
          { text: "米游社登录", callback: "米游社登录" },
        ]),
      ],
      true,
    )
  }
}
