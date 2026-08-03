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
  const fields = new Set(["name", "message"])
  if (error && typeof error === "object") {
    for (const key of Object.keys(error)) fields.add(key)
  }
  return `status=failed fields=${[...fields].sort().join(",")}`
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
  const token = ["stoken_v2", "stoken"]
    .map(name => data.tokens.find(item => item?.name === name && typeof item.token === "string"))
    .find(item => item?.token)
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
  return { accountId, mid, token: token.token, tokenName: token.name }
}

export function classifyBindingReply(message) {
  const text = typeof message === "string" ? message : JSON.stringify(message)
  if (/绑定Cookie成功/.test(text)) return "success"
  if (/绑定Cookie失败|Cookie不完整|Cookie错误|发送Cookie不完整/.test(text)) return "failed"
  return "pending"
}

export async function exchangeCookieAccount(
  account,
  requester = (url, { cookie }) => globalThis.fetch(url, { headers: { Cookie: cookie } }),
) {
  const cookie = stokenCookie(account)
  const query = new URLSearchParams({
    stoken: account.token,
    uid: account.accountId,
    mid: account.mid,
  })
  const response = await requester(
    `https://passport-api.mihoyo.com/account/auth/api/getCookieAccountInfoBySToken?${query}`,
    { cookie },
  )
  if (!response.ok) throw new Error("cookie exchange request failed")
  const result = await response.json()
  if (result.retcode !== 0 || !result.data?.cookie_token) {
    throw new Error(result.message || "stoken is invalid")
  }
  return `ltoken=${account.token};ltuid=${account.accountId};cookie_token=${result.data.cookie_token}`
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
  await bind(cookie)
  await save(account)
  return cookie
}
