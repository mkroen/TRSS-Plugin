import crypto from "node:crypto"
const refreshExchanges = new Map()

export const MIHOYO_LOGIN_REGEX = "^#?(米哈?游社?登(录|陆|入)|登(录|陆|入)米哈?游社?)"
export const MIHOYO_QR_LOGIN_REGEX = `(${MIHOYO_LOGIN_REGEX}|^#(扫码|二维码|辅助)(登录|绑定|登陆))(终止)?$`

const SAFE_LOGIN_STATUSES = new Set(["Created", "Scanned", "Confirmed", "Expired"])

function fieldNames(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return "none"
  return Object.keys(value).sort().join(",") || "none"
}

export function redactLogValue(data) {
  const rawStatus = data?.data?.status ?? data?.status
  const status = SAFE_LOGIN_STATUSES.has(rawStatus)
    ? rawStatus
    : Object.hasOwn(data || {}, "retcode")
      ? data.retcode === 0
        ? "ok"
        : "error"
      : "received"
  return `status=${status} fields=${fieldNames(data)} data_fields=${fieldNames(data?.data)}`
}

export function redactLogError(error) {
  const stage = stages.has(error?.stage) ? error.stage : "unknown"
  const kind = kinds.has(error?.kind) ? error.kind : "unknown"
  const code =
    typeof error?.retcode === "number" && Number.isFinite(error.retcode) ? error.retcode : "none"
  return "status=failed fields=name,message stage=" + stage + " kind=" + kind + " retcode=" + code
}

export function isPrivateMessage(event) {
  return Boolean(event?.isPrivate)
}

export function stokenCookie(account) {
  // The legacy exchange endpoint expects the v1 Cookie key even when the QR token is named stoken_v2.
  return `stoken=${account.token};stuid=${account.accountId};mid=${account.mid}`
}

export function parseLoginStokenAccount(data) {
  if (!Array.isArray(data?.tokens) || !data?.user_info) return null
  const namedToken = ["stoken_v2", "stoken"]
    .map(name => data.tokens.find(item => item?.name === name && typeof item.token === "string"))
    .find(item => item?.token)
  const token =
    namedToken ??
    data.tokens.find(item => Number(item?.token_type) === 1 && typeof item.token === "string")
  if (!token) return null

  const accountId = String(
    data.user_info.aid ??
      data.user_info.uid ??
      data.user_info.account_id ??
      data.user_info.account_id_v2 ??
      "",
  )
  const mid = String(
    data.user_info.mid ?? data.user_info.account_mid_v2 ?? data.user_info.ltmid_v2 ?? "",
  )
  if (!accountId || !mid) return null
  return {
    accountId,
    mid,
    token: token.token,
    tokenName: token.name ?? "stoken",
  }
}

export function classifyBindingReply(message) {
  const text = typeof message === "string" ? message : JSON.stringify(message)
  if (/绑定Cookie成功/.test(text)) return "success"
  if (/绑定Cookie失败|Cookie不完整|Cookie错误|发送Cookie不完整/.test(text)) return "failed"
  return "pending"
}

const stages = new Set(["ltoken", "cookie", "bind", "save", "exchange"])
const kinds = new Set(["network", "http", "response", "rejected", "timeout", "storage"])
export function credentialError(stage, kind, retcode) {
  const error = new Error("credential operation failed")
  error.stage = stages.has(stage) ? stage : "exchange"
  error.kind = kinds.has(kind) ? kind : "response"
  if (typeof retcode === "number" && Number.isFinite(retcode)) error.retcode = retcode
  return error
}
export function credentialFailureMessage(error) {
  if (error?.stage === "save") return "Cookie 已绑定，但 Stoken 加密保存失败；请检查存储状态。"
  if (error?.stage === "bind")
    return error.kind === "timeout"
      ? "已获取 Stoken 和 Cookie，但未能确认绑定结果（等待超时）；原有 Stoken 未替换。"
      : "已获取 Stoken 和 Cookie，但 Cookie 绑定失败；原有 Stoken 未替换。"
  return "已获取 Stoken，但 Cookie 凭据转换失败；原有 Stoken 未替换，请稍后重新扫码。"
}
export function buildMysCookie(account, ltoken, cookieToken) {
  const { accountId: uid, mid } = account
  const parts = ltoken.startsWith("v2_")
    ? ["ltoken_v2=" + ltoken, "ltuid_v2=" + uid, "ltmid_v2=" + mid]
    : ["ltoken=" + ltoken, "ltuid=" + uid]
  parts.push(
    ...(cookieToken.startsWith("v2_")
      ? ["cookie_token_v2=" + cookieToken, "account_id_v2=" + uid, "account_mid_v2=" + mid]
      : ["cookie_token=" + cookieToken]),
  )
  return parts.join(";")
}
export async function exchangeCookieAccount(account, requester) {
  if (typeof requester !== "function") throw credentialError("exchange", "response")
  const cookie = stokenCookie(account)
  const deviceId = crypto.randomUUID().replaceAll("-", "")
  async function exchange(stage, endpoint, query, clientType, field) {
    let response
    try {
      response = await requester(
        "https://passport-api.mihoyo.com/account/auth/api/" +
          endpoint +
          "?" +
          new URLSearchParams(query),
        { cookie, clientType, deviceId },
      )
    } catch {
      throw credentialError(stage, "network")
    }
    if (!response.ok) throw credentialError(stage, "http", response.status)
    let result
    try {
      result = await response.json()
    } catch {
      throw credentialError(stage, "response")
    }
    if (
      Number(result?.retcode) !== 0 ||
      typeof result?.data?.[field] !== "string" ||
      !result.data[field]
    )
      throw credentialError(
        stage,
        "rejected",
        typeof result?.retcode === "number" ? result.retcode : undefined,
      )
    return result.data[field]
  }
  const ltoken = await exchange(
    "ltoken",
    "getLTokenBySToken",
    { stoken: account.token, stuid: account.accountId },
    5,
    "ltoken",
  )
  const cookieToken = await exchange(
    "cookie",
    "getCookieAccountInfoBySToken",
    { stoken: account.token, uid: account.accountId, mid: account.mid },
    2,
    "cookie_token",
  )
  return buildMysCookie(account, ltoken, cookieToken)
}

export function exchangeCookieAccountOnce(ownerId, account, requester) {
  const key = `${String(ownerId)}:${String(account.accountId)}`
  const pending = refreshExchanges.get(key)
  if (pending) return pending

  const exchange = exchangeCookieAccount(account, requester)
  refreshExchanges.set(key, exchange)
  const cleanup = () => {
    if (refreshExchanges.get(key) === exchange) refreshExchanges.delete(key)
  }
  exchange.then(cleanup, cleanup)
  return exchange
}

export async function completeCredentialFlow(account, { exchange, bind, save }) {
  const cookie = await exchange(account)
  let result
  try {
    result = await bind(cookie)
  } catch {
    throw credentialError("bind", "rejected")
  }
  if (result !== "success")
    throw credentialError("bind", result === "timeout" ? "timeout" : "rejected")
  try {
    await save(account)
  } catch {
    throw credentialError("save", "storage")
  }
  return cookie
}
