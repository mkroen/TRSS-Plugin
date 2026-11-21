import test from "node:test"
import assert from "node:assert/strict"
import {
  exchangeCookieAccount,
  completeCredentialFlow,
  redactLogError,
  buildMysCookie,
} from "../Model/miHoYoAccount.js"
const account = { accountId: "fixture-id", mid: "fixture-mid", token: "fixture-secret" }
test("separate ticket requests use correct client types and shared device", async () => {
  const calls = []
  const result = await exchangeCookieAccount(account, async (url, opts) => {
    calls.push({ url, opts })
    return {
      ok: true,
      json: async () => ({
        retcode: 0,
        data: calls.length === 1 ? { ltoken: "v2_fixture-lt" } : { cookie_token: "v2_fixture-ct" },
      }),
    }
  })
  assert.equal(calls.length, 2)
  assert.match(calls[0].url, /getLTokenBySToken/)
  assert.match(calls[1].url, /getCookieAccountInfoBySToken/)
  assert.deepEqual(
    calls.map(c => c.opts.clientType),
    [5, 2],
  )
  assert.equal(calls[0].opts.deviceId, calls[1].opts.deviceId)
  assert.equal(
    result,
    "ltoken_v2=v2_fixture-lt;ltuid_v2=fixture-id;ltmid_v2=fixture-mid;cookie_token_v2=v2_fixture-ct;account_id_v2=fixture-id;account_mid_v2=fixture-mid",
  )
  assert.doesNotMatch(result, /fixture-secret/)
})
test("mixed ticket versions remain independent", () => {
  assert.equal(
    buildMysCookie(account, "v2_lt", "ct"),
    "ltoken_v2=v2_lt;ltuid_v2=fixture-id;ltmid_v2=fixture-mid;cookie_token=ct",
  )
})
for (const mode of ["network", "http", "json", "rejected", "missing"])
  test("exchange sanitizes " + mode, async () => {
    await assert.rejects(
      exchangeCookieAccount(account, async () => {
        if (mode === "network") throw new Error("fixture-secret")
        return {
          ok: mode !== "http",
          status: 403,
          json: async () => {
            if (mode === "json") throw new Error("fixture-secret")
            return { retcode: mode === "rejected" ? -100 : 0, message: "fixture-secret", data: {} }
          },
        }
      }),
      e => {
        assert.doesNotMatch(redactLogError(e) + e.message, /fixture-secret/)
        assert.equal(e.stage, "ltoken")
        return true
      },
    )
  })
for (const result of ["failed", "timeout", undefined])
  test("unconfirmed binding cannot replace vault: " + result, async () => {
    let saved = false
    await assert.rejects(
      completeCredentialFlow(account, {
        exchange: async () => "cookie",
        bind: async () => result,
        save: async () => {
          saved = true
        },
      }),
      { stage: "bind" },
    )
    assert.equal(saved, false)
  })
test("storage failure is distinct after confirmed binding", async () => {
  await assert.rejects(
    completeCredentialFlow(account, {
      exchange: async () => "cookie",
      bind: async () => "success",
      save: async () => {
        throw new Error("fixture-secret")
      },
    }),
    { stage: "save", kind: "storage" },
  )
})

import fs from 'node:fs/promises'
import vm from 'node:vm'
import crypto from 'node:crypto'
test('actual request helper selects DS salt, device and deadline',async()=>{
 const source=await fs.readFile(new URL('../Apps/miHoYoLogin.js',import.meta.url),'utf8')
 const code=source.slice(source.indexOf('function md5('),source.indexOf('function app_request('))
 const calls=[]
 const context={crypto,random_string:()=> 'fixture-random',AbortSignal,fetch:async(url,opts)=>{calls.push(opts);return {ok:true}}}
 vm.createContext(context);vm.runInContext(code+';this.request=request',context)
 for(const clientType of [5,2]) await context.request('https://invalid.example',{cookie:'fixture',clientType,deviceId:'same-device'})
 for(let i=0;i<2;i++){
  const h=calls[i].headers;const [t,r,digest]=h.DS.split(',')
  const salt=i===0?'xV8v4Qu54lUKrEYFZkJhB8cuOh9Asafs':'JwYDpKvLj6MrMqqYU6jTKF17KNO2PXoS'
  assert.equal(digest,crypto.createHash('md5').update('salt='+salt+'&t='+t+'&r='+r+'&b=&q=').digest('hex'))
  assert.equal(h['x-rpc-device_id'],'same-device');assert.equal(h['x-rpc-client_type'],String([5,2][i]));assert.ok(calls[i].signal)
 }
})
test('actual binding callback waits for success and handles failure',async()=>{
 const source=await fs.readFile(new URL('../Apps/miHoYoLogin.js',import.meta.url),'utf8')
 const method=source.slice(source.indexOf('  makeMessage(msg'),source.indexOf('  miHoYoLoginHelp()'))
 for(const [reply,expected] of [['绑定Cookie成功','success'],['绑定Cookie失败','failed']]){
 const context={setTimeout,clearTimeout,classifyBindingReply:message=>message.includes('成功')?'success':'failed',Bot:{em:(_event,event)=>event.reply(reply)}}
 vm.createContext(context);const obj=vm.runInContext('({'+method+'})',context);obj.e={};obj.reply=async()=>{}
 assert.equal(await obj.makeMessage('fixture-cookie',{waitForBinding:true}),expected)
 }
})
