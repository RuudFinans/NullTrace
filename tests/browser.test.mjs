// Run against the disposable server: python -m tests.browser_server
import assert from "node:assert/strict";
import { chromium } from "playwright";
const base="http://127.0.0.1:5017";
const browser=await chromium.launch({headless:true});
const errors=[], cspErrors=[];
try {
  const contexts=await Promise.all([0,1,2].map(()=>browser.newContext()));
  for(const context of contexts) await context.addInitScript(()=>{
    const RealWebSocket=window.WebSocket;
    window.WebSocket=class extends RealWebSocket {
      constructor(...args){ super(...args); (window.__testSockets ||= []).push(this); }
      send(data){
        const message=JSON.parse(data);
        if(message.t==="gk") window.__testLastEpoch=message.e;
        return super.send(data);
      }
    };
  });
  const pages=await Promise.all(contexts.map(context=>context.newPage()));
  for(const page of pages){
    page.on("pageerror",error=>errors.push(error.message));
    page.on("console",message=>{
      if(message.type()==="error" && /Content Security Policy|Refused/.test(message.text())) cspErrors.push(message.text());
    });
  }
  for(let i=0;i<pages.length;i++){
    const page=pages[i];
    await page.goto(base);
    await page.waitForFunction(()=>window.NullTraceChatReady===true);
    await page.locator("#showSigninBtn").click();
    await page.locator("#signinUserKey").fill("nt_user_browser_"+["host","guest","third"][i]);
    await page.locator("#signinBtn").click();
    await page.waitForFunction(()=>document.body.classList.contains("access-unlocked"));
  }
  const [host,guest,third]=pages;
  // A failed start must return to a usable launch screen with a visible error.
  await host.route("**/api/room-token", route=>route.fulfill({
    status:503,contentType:"application/json",body:"{}"
  }));
  await host.locator("#join").click();
  await host.locator("#roomNotice").filter({hasText:"Couldn't open this room"}).waitFor();
  assert.equal(await host.locator("#join").isVisible(),true);
  assert.equal(await host.locator("#join").isEnabled(),true);
  await host.unroute("**/api/room-token");
  await host.locator("#join").click();
  await host.waitForFunction(()=>!document.getElementById("inviteBtn").disabled);
  async function invite(page) {
    await host.locator("#inviteBtn").click();
    const capsule=await host.locator("#inviteTxt").inputValue();
    await host.locator("#inviteCloseBtn").click();
    await page.locator("#capsuleBtn").click();
    await page.locator("#pasteTxt").fill(capsule);
    await page.locator("#pasteOk").click();
    if(page===guest){
      await page.locator("#confirmJoinBtn").waitFor();
      const cancelledFingerprint=await page.locator("#confirmGuestFP").textContent();
      await page.keyboard.press("Escape");
      await page.waitForFunction(()=>!document.getElementById("confirmDlg").open);
      assert.equal(await page.evaluate(()=>document.activeElement.id),"capsuleBtn");
      await page.locator("#capsuleBtn").click();
      await page.locator("#pasteTxt").fill(capsule);
      await page.locator("#pasteOk").click();
      await page.locator("#confirmJoinBtn").waitFor();
      assert.notEqual(await page.locator("#confirmGuestFP").textContent(),cancelledFingerprint);
    }
    await page.locator("#confirmJoinBtn").click();
    await host.locator("#pendingList button").last().click();
    await page.waitForFunction(()=>!document.getElementById("send").disabled);
  }
  await invite(guest);
  await host.locator("#input").fill("hello guest");
  await host.locator("#send").click();
  await guest.getByText("hello guest",{exact:false}).waitFor();
  await invite(third);
  await guest.locator("#input").fill("hello all three");
  await guest.locator("#send").click();
  await host.getByText("hello all three",{exact:false}).waitFor();
  await third.getByText("hello all three",{exact:false}).waitFor();
  // Observe public ciphertext metadata to verify the real scheduled DH refresh.
  const previousEpoch=await host.evaluate(()=>window.__testLastEpoch);
  assert.ok(Number.isInteger(previousEpoch));
  await host.waitForFunction(epoch=>window.__testLastEpoch>epoch,previousEpoch,{timeout:45000});
  await host.locator("#input").fill("after scheduled ratchet");
  await host.locator("#send").click();
  await guest.getByText("after scheduled ratchet",{exact:false}).waitFor();
  await third.getByText("after scheduled ratchet",{exact:false}).waitFor();
  await guest.evaluate(()=>window.__testSockets.at(-1).close(4005,"test reconnect"));
  await host.locator("#pendingList button").last().click();
  await guest.waitForFunction(()=>!document.getElementById("send").disabled);
  await guest.locator("#input").fill("after reapproval");
  await guest.locator("#send").click();
  await third.getByText("after reapproval",{exact:false}).waitFor();
  await guest.locator("#disconnectBtn").click();
  await host.waitForFunction(()=>document.querySelectorAll("#userList .user-entry").length===2);
  await host.locator("#input").fill("after removal");
  await host.locator("#send").click();
  await third.getByText("after removal",{exact:false}).waitFor();
  assert.equal(await guest.getByText("after removal",{exact:false}).count(),0);
  // A fresh page must initialize with cached static assets and the current code.
  await guest.reload();
  await guest.waitForFunction(()=>window.NullTraceChatReady===true);
  const cachesInfo=await host.evaluate(async()=>Promise.all((await caches.keys()).map(async key=>({
    key,urls:(await (await caches.open(key)).keys()).map(request=>new URL(request.url).pathname)
  }))));
  for(const cache of cachesInfo) assert.ok(cache.urls.every(path=>
    path.startsWith("/static/") && !path.includes("/js/") && !path.includes("/libs/")));
  await host.locator("#disconnectBtn").click();
  await third.getByText("Host disconnected. Request a new invitation.",{exact:false}).waitFor();
  assert.equal(await third.locator("#send").isDisabled(),true);
  await third.locator("#accessLogoutBtn").click();
  await third.waitForFunction(()=>!document.body.classList.contains("access-unlocked"));
  assert.equal(await third.locator("#messages li").count(),0);
  assert.deepEqual(errors,[]);
  assert.deepEqual(cspErrors,[]);
  console.log("PASS: 3 independent browser sessions, login, failed-start retry, cancelled invitation/focus recovery, v3 invites, approval, signed group chat, scheduled ratchet refresh, reconnect/reapproval, membership removal, host departure, logout cleanup, reload, CSP and cache policy.");
} finally {
  for(const context of browser.contexts()) for(const page of context.pages()){
    if(await page.locator("#accessLogoutBtn").isVisible().catch(()=>false)) {
      await page.locator("#accessLogoutBtn").click().catch(()=>{});
    }
  }
  await browser.close();
}
