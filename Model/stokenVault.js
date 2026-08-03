import crypto from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"

export const STOKEN_VAULT_SCHEMA = "trss-stoken-vault"
export const STOKEN_VAULT_VERSION = 1
export const STOKEN_VAULT_ALGORITHM = "aes-256-gcm"
const ownerQueues = new Map()

function safeId(value, name) {
  const id = String(value ?? "")
  if (!/^[A-Za-z0-9_-]+$/.test(id)) throw new Error(`${name} is invalid`)
  return id
}

async function atomicWrite(file, data) {
  const temp = `${file}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`
  try {
    await fs.writeFile(temp, data, { flag: "wx", mode: 0o600 })
    await fs.rename(temp, file)
    await fs.chmod(file, 0o600)
  } finally {
    await fs.rm(temp, { force: true }).catch(() => {})
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

function enqueueOwner(ownerId, operation) {
  const previous = ownerQueues.get(ownerId) || Promise.resolve()
  const current = previous.catch(() => {}).then(operation)
  ownerQueues.set(ownerId, current)
  const cleanup = () => {
    if (ownerQueues.get(ownerId) === current) ownerQueues.delete(ownerId)
  }
  current.then(cleanup, cleanup)
  return current
}

export class StokenVault {
  constructor(rootDir = path.resolve("data/TRSS-Plugin/stoken-vault")) {
    this.rootDir = rootDir
    this.keyFile = path.join(rootDir, ".master-key")
  }

  async ensureRoot() {
    await fs.mkdir(this.rootDir, { recursive: true, mode: 0o700 })
    await fs.chmod(this.rootDir, 0o700)
  }

  async acquireOwnerLock(ownerId, timeoutMs = 10000) {
    await this.ensureRoot()
    const lockFile = path.join(this.rootDir, `.${ownerId}.lock`)
    const startedAt = Date.now()
    const token = `${process.pid}:${crypto.randomBytes(16).toString("hex")}`

    while (Date.now() - startedAt < timeoutMs) {
      try {
        const handle = await fs.open(lockFile, "wx", 0o600)
        await handle.writeFile(`${token}\n`)
        await handle.close()
        return async () => {
          const current = await fs.readFile(lockFile, "utf8").catch(() => "")
          if (current.trim() === token) await fs.rm(lockFile, { force: true })
        }
      } catch (error) {
        if (error.code !== "EEXIST") throw error
        const stat = await fs.stat(lockFile).catch(() => null)
        if (stat && Date.now() - stat.mtimeMs > 30000) {
          const staleFile = `${lockFile}.stale.${crypto.randomBytes(6).toString("hex")}`
          await fs.rename(lockFile, staleFile).catch(() => {})
          await fs.rm(staleFile, { force: true }).catch(() => {})
        }
        await sleep(10 + crypto.randomInt(20))
      }
    }
    throw new Error("stoken vault owner lock timeout")
  }

  fileFor(ownerId) {
    return path.join(this.rootDir, `${safeId(ownerId, "ownerId")}.json`)
  }

  async getKey() {
    await this.ensureRoot()
    try {
      const key = Buffer.from((await fs.readFile(this.keyFile, "utf8")).trim(), "base64")
      if (key.length !== 32) throw new Error("stoken vault master key is invalid")
      return key
    } catch (error) {
      if (error.code !== "ENOENT") throw error
    }

    const key = crypto.randomBytes(32)
    const temp = `${this.keyFile}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`
    try {
      await fs.writeFile(temp, `${key.toString("base64")}\n`, { flag: "wx", mode: 0o600 })
      try {
        await fs.link(temp, this.keyFile)
      } catch (error) {
        if (error.code !== "EEXIST") throw error
      }
    } finally {
      await fs.rm(temp, { force: true }).catch(() => {})
    }

    await fs.chmod(this.keyFile, 0o600)
    const stored = Buffer.from((await fs.readFile(this.keyFile, "utf8")).trim(), "base64")
    if (stored.length !== 32) throw new Error("stoken vault master key is invalid")
    return stored
  }

  async readDocument(ownerId) {
    const owner = safeId(ownerId, "ownerId")
    try {
      const document = JSON.parse(await fs.readFile(this.fileFor(owner), "utf8"))
      if (
        document.schema !== STOKEN_VAULT_SCHEMA ||
        document.version !== STOKEN_VAULT_VERSION ||
        document.ownerId !== owner ||
        !Array.isArray(document.accounts)
      ) {
        throw new Error("unsupported stoken vault format")
      }
      return document
    } catch (error) {
      if (error.code === "ENOENT") {
        return {
          schema: STOKEN_VAULT_SCHEMA,
          version: STOKEN_VAULT_VERSION,
          revision: 0,
          ownerId: owner,
          updatedAt: null,
          accounts: [],
        }
      }
      throw error
    }
  }

  async assertRevision(ownerId, expectedRevision) {
    const latest = await this.readDocument(ownerId)
    if (Number(latest.revision || 0) !== expectedRevision) {
      const error = new Error("stoken vault revision conflict")
      error.code = "VAULT_CONFLICT"
      throw error
    }
  }

  async mutate(ownerId, operation) {
    const owner = safeId(ownerId, "ownerId")
    return enqueueOwner(owner, async () => {
      const release = await this.acquireOwnerLock(owner)
      try {
        for (let attempt = 0; attempt < 3; attempt++) {
          const document = await this.readDocument(owner)
          const expectedRevision = Number(document.revision || 0)
          const mutation = await operation(document)
          if (!mutation?.changed) return mutation?.result
          try {
            await this.assertRevision(owner, expectedRevision)
            if (mutation.deleteDocument) {
              await fs.rm(this.fileFor(owner), { force: true })
            } else {
              document.revision = expectedRevision + 1
              document.updatedAt = new Date().toISOString()
              await atomicWrite(this.fileFor(owner), `${JSON.stringify(document, null, 2)}\n`)
            }
            return mutation.result
          } catch (error) {
            if (error.code !== "VAULT_CONFLICT" || attempt === 2) throw error
          }
        }
      } finally {
        await release()
      }
    })
  }

  encrypt(key, ownerId, accountId, value) {
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv(STOKEN_VAULT_ALGORITHM, key, iv)
    cipher.setAAD(
      Buffer.from(`${STOKEN_VAULT_SCHEMA}:${STOKEN_VAULT_VERSION}:${ownerId}:${accountId}`),
    )
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()])
    return {
      algorithm: STOKEN_VAULT_ALGORITHM,
      iv: iv.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    }
  }

  decrypt(key, ownerId, record) {
    if (record.cipher?.algorithm !== STOKEN_VAULT_ALGORITHM) {
      throw new Error("unsupported stoken cipher")
    }
    const decipher = crypto.createDecipheriv(
      STOKEN_VAULT_ALGORITHM,
      key,
      Buffer.from(record.cipher.iv, "base64"),
    )
    decipher.setAAD(
      Buffer.from(`${STOKEN_VAULT_SCHEMA}:${STOKEN_VAULT_VERSION}:${ownerId}:${record.accountId}`),
    )
    decipher.setAuthTag(Buffer.from(record.cipher.tag, "base64"))
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(record.cipher.ciphertext, "base64")),
      decipher.final(),
    ])
    return JSON.parse(plaintext.toString("utf8"))
  }

  async save(ownerId, account) {
    const owner = safeId(ownerId, "ownerId")
    const accountId = safeId(account.accountId, "accountId")
    if (!account.token || !account.mid) throw new Error("stoken account is incomplete")
    const key = await this.getKey()
    return this.mutate(owner, async document => {
      const now = new Date().toISOString()
      const old = document.accounts.find(item => item.accountId === accountId)
      const record = {
        accountId,
        mid: String(account.mid),
        tokenName: account.tokenName === "stoken_v2" ? "stoken_v2" : "stoken",
        createdAt: old?.createdAt || now,
        updatedAt: now,
        cipher: this.encrypt(key, owner, accountId, {
          accountId,
          mid: String(account.mid),
          token: String(account.token),
          tokenName: account.tokenName === "stoken_v2" ? "stoken_v2" : "stoken",
        }),
      }
      document.accounts = document.accounts.filter(item => item.accountId !== accountId)
      document.accounts.push(record)
      return { changed: true, result: record }
    })
  }

  async list(ownerId) {
    const document = await this.readDocument(ownerId)
    return document.accounts.map(({ accountId, mid, tokenName, createdAt, updatedAt }) => ({
      accountId,
      mid,
      tokenName,
      createdAt,
      updatedAt,
    }))
  }

  async readAccounts(ownerId) {
    const owner = safeId(ownerId, "ownerId")
    const document = await this.readDocument(owner)
    if (!document.accounts.length) return []
    const key = await this.getKey()
    return document.accounts.map(record => this.decrypt(key, owner, record))
  }

  async remove(ownerId, accountId) {
    const owner = safeId(ownerId, "ownerId")
    const target = accountId ? safeId(accountId, "accountId") : ""
    return this.mutate(owner, async document => {
      const before = document.accounts.length
      document.accounts = target ? document.accounts.filter(item => item.accountId !== target) : []
      const removed = before - document.accounts.length
      return {
        changed: removed > 0,
        deleteDocument: removed > 0 && document.accounts.length === 0,
        result: removed,
      }
    })
  }
}

export const stokenVault = new StokenVault()
