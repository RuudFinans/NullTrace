// frontend/static/js/app.js – NullTrace Chat v98 (MLS + robust GK + CSP-safe UI)

import sodium from "libsodium-wrappers";
import { createLocalKeys, handshakeWith, b64, u8, createHello, readHello, wipeKeys, wipeBootstrapKeys,
  verifyPacket, fp4, PROTOCOL_VERSION } from "handshake";
import { MlsGroup } from "mls";
import { createCapsule, parseCapsule, CAPSULE_TTL_MS } from "nacp";
await sodium.ready;

// ─── Konfig ─────────────────────────────────────────────────────────
const DEADMAN_TIMEOUT_MS = 2000;
const ENABLE_CHAFF       = true;
const CHAFF_MIN_MS       = 500;
const CHAFF_MAX_MS       = 1500;
const PING_MIN_MS        = 10000;
const PING_MAX_MS        = 20000;
const MIN_PACKET_SIZE    = 3000;
const MAX_PACKET_SIZE    = 5000;
const BURN_BASE_MS       = 30000;
const BURN_JITTER_MS     = 5000;
const BURN_MAX_MS        = BURN_BASE_MS + BURN_JITTER_MS;
const MIN_HUE_DISTANCE   = 60;
const RECONNECT_MIN_MS   = 700;
const RECONNECT_MAX_MS   = 8000;
const HELLO_RETRY_MS     = 1500;
const HELLO_RETRY_TRIES  = 40;

// GK retry (guest ber host om å re-sende GK hvis den ikke dukker opp)
const GK_REQ_DELAY_MS    = 300;
const GK_REQ_TRIES       = 6;

// Host-side rekey-throttle (beskytter mot gk_req-spam)
const REKEY_MIN_MS       = 800;
const REKEY_INTERVAL_MS  = 30000;
// ───────────────────────────────────────────────────────────────────

function genUUID(){
  if (crypto.randomUUID) return crypto.randomUUID();
  return ([1e7]+-1e3+-4e3+-8e3+-1e11)
    .replace(/[018]/g, c =>
      (c ^ crypto.getRandomValues(new Uint8Array(1))[0]
        & (15 >> (c/4))).toString(16)
    );
}

/* DOM refs */
const $ = id => document.getElementById(id);
const J=$("join"), C=$("capsuleBtn"), Ibtn=$("inviteBtn"), R=$("room"),
      S=$("send"), IN=$("input"), ST=$("status"), CH=$("messages"),
      pendingList=$("pendingList"), IDLG=$("inviteDlg"), ITXT=$("inviteTxt"),
      INV_TIMER=$("inviteTimer"), PDL=$("pasteDlg"), PTXT=$("pasteTxt"),
      POK=$("pasteOk"), CONFIRMDLG=$("confirmDlg"), CONF_ROOM=$("confirmRoom"),
      CONF_HOSTFP=$("confirmHostFP"), CONF_GUESTFP=$("confirmGuestFP"),
      CONF_JOIN=$("confirmJoinBtn"), CONF_CANCEL=$("confirmCancelBtn"),
      INV_CLOSE=$("inviteCloseBtn"), INV_COPY=$("inviteCopyBtn"), deadmanToggle=$("deadmanToggle"),
      disconnectBtn=$("disconnectBtn"),
      P_CANCEL=$("pasteCancelBtn");          // ← NEW: no inline onclick

J.disabled = true;
C.disabled = true;
Ibtn.disabled = true;

/* ──────────────────────────────────────────────────────────────────── */


/* State */
let inviteInterval=null, deadmanTimer=null, greeted=false, chaffTimer=null, pingTimer=null;
let reconnectTimer=null, reconnectDelay=RECONNECT_MIN_MS, desiredConnection=false, helloRetryTimer=null, helloRetryCount=0;
let periodicRekeyTimer=null, connectionGeneration=0;
let inviteCopyBusy=false;
const peers=new Map(), pendingRequests=new Map(), usedHues=new Set();

// Buffer GK (gjest), + retry-timere
const pendingGK=new Map(), gkRetryTimers=new Map();

let CID=genUUID();
let localKeys, grp, ws=null;
let role=null;
let capsuleInfo=null;
let capsuleRaw=null;
let nextCid = null; // ← NEW: pre-generert ID som vises i confirm og brukes ved join
let nextKeys = null;

let chatModuleReady = false;

async function writeClipboardText(text){
  if(navigator.clipboard&&window.isSecureContext){
    try{
      await navigator.clipboard.writeText(text);
      return true;
    }catch{}
  }

  const active=document.activeElement;
  const helper=document.createElement("textarea");
  helper.value=text;
  helper.setAttribute("readonly","");
  helper.setAttribute("aria-hidden","true");
  helper.setAttribute("autocomplete","off");
  helper.setAttribute("autocorrect","off");
  helper.setAttribute("autocapitalize","off");
  helper.setAttribute("spellcheck","false");
  helper.setAttribute("inputmode","none");
  Object.assign(helper.style,{
    position:"fixed",
    top:"0",
    left:"0",
    width:"1px",
    height:"1px",
    opacity:"0",
    overflow:"hidden",
    pointerEvents:"none",
    fontSize:"16px"
  });
  const helperRoot=IDLG.open ? IDLG : document.body;
  helperRoot.appendChild(helper);

  let copied=false;
  try{
    helper.focus({preventScroll:true});
    helper.select();
    helper.setSelectionRange(0, text.length);
    copied=document.execCommand("copy");
  }catch{
    copied=false;
  }finally{
    helper.blur();
    helper.remove();
    const selection=window.getSelection?.();
    selection?.removeAllRanges?.();
    if(active&&active!==document.body&&typeof active.focus==="function"){
      try{ active.focus({preventScroll:true}); }catch{}
    }
  }
  return copied;
}

function clearInviteFocus(){
  const selection=window.getSelection?.();
  selection?.removeAllRanges?.();
  ITXT.blur();
  if(document.activeElement&&IDLG.contains(document.activeElement)){
    document.activeElement.blur();
  }
}

function accessIsUnlocked(){
  const shell = $("appShell");
  return document.body.classList.contains("access-unlocked") || (shell && !shell.hidden);
}

function updateLaunchButtons(){
  const enabled = chatModuleReady && accessIsUnlocked();
  J.disabled = !enabled;
  C.disabled = !enabled;
}

window.addEventListener("nulltrace:access-unlocked", updateLaunchButtons);
window.addEventListener("nulltrace:access-locked", ()=>{ wipeSession(); updateLaunchButtons(); });

// Host-side rekey throttle
let lastRekeyAt = 0;
function safeRekey(){
  const now = Date.now();
  if (!grp) return;
  if (now - lastRekeyAt < REKEY_MIN_MS) return;
  lastRekeyAt = now;
  try { grp.rekey(); }
  catch {
    wipeSession();
    addMsg("Key refresh failed. Start a new chat.", "error");
  }
}

function schedulePeriodicRekey(){
  clearTimeout(periodicRekeyTimer);
  periodicRekeyTimer=null;
  if(role!=="init" || !grp?.ready || ws?.readyState!==WebSocket.OPEN) return;
  const group=grp;
  periodicRekeyTimer=setTimeout(()=>{
    if(grp!==group || role!=="init" || ws?.readyState!==WebSocket.OPEN) return;
    safeRekey();
    schedulePeriodicRekey();
  }, REKEY_INTERVAL_MS);
}

/* Helpers */
function randomString(len){
  const arr=new Uint8Array(len); crypto.getRandomValues(arr);
  return Array.from(arr,v=>String.fromCharCode(97+(v%26))).join("");
}
function randomColor(){
  const minDist=MIN_HUE_DISTANCE;
  let hue,attempts=0;
  do{
    hue=Math.floor(Math.random()*360);
    const ok=[...usedHues].every(e=>{
      const d=Math.abs(e-hue),dist=Math.min(d,360-d);
      return dist>=minDist;
    });
    if(ok) break;
    attempts++;
  }while(attempts<50);
  usedHues.add(hue);
  return `hsl(${hue},70%,50%)`;
}
function sendMessage(obj){
  if(!ws || ws.readyState !== WebSocket.OPEN) return false;
  const msg={...obj};
  const overhead=JSON.stringify(msg).length+8;
  const target=MIN_PACKET_SIZE+Math.floor(Math.random()*(MAX_PACKET_SIZE-MIN_PACKET_SIZE+1));
  const pad=target-overhead;
  if(pad>0) msg.pad=randomString(pad);
  const encoded = JSON.stringify(msg);
  if(new TextEncoder().encode(encoded).length > 16384 || ws.bufferedAmount > 262144) {
    throw new Error("Message or send queue is too large");
  }
  ws.send(encoded);
  return true;
}
function sendHello(){
  if(!ws||ws.readyState!==WebSocket.OPEN||!localKeys) return;
  sendMessage(createHello(CID, localKeys, R.value.trim()));
}
function clearHelloRetry(){
  clearTimeout(helloRetryTimer);
  helloRetryTimer=null;
  helloRetryCount=0;
}
function scheduleHelloRetry(){
  if(role!=="resp") return;
  if(grp?.ready){ clearHelloRetry(); return; }
  if(helloRetryCount>=HELLO_RETRY_TRIES) return;
  clearTimeout(helloRetryTimer);
  helloRetryTimer=setTimeout(()=>{
    if(role!=="resp"||!ws||ws.readyState!==WebSocket.OPEN) return;
    if(grp?.ready){ clearHelloRetry(); return; }
    helloRetryCount++;
    sendHello();
    scheduleHelloRetry();
  }, HELLO_RETRY_MS);
}
function scheduleReconnect(delay=RECONNECT_MIN_MS){
  if(!desiredConnection) return;
  if(deadmanToggle?.checked) return;
  if(document.hidden) return;
  if(ws&&(ws.readyState===WebSocket.OPEN||ws.readyState===WebSocket.CONNECTING)) return;
  clearTimeout(reconnectTimer);
  reconnectTimer=setTimeout(()=>{
    reconnectTimer=null;
    startChat({resume:true});
  }, delay);
}
function resetReconnectBackoff(){
  reconnectDelay=RECONNECT_MIN_MS;
  clearTimeout(reconnectTimer);
  reconnectTimer=null;
}
async function getRoomToken(roomId){
  // Krev kode før vi forsøker
  const headers = { "Content-Type": "application/json" };

  const res = await fetch("/api/room-token", {
    method: "POST",
    credentials: "same-origin",
    headers,
    body: JSON.stringify({ room_id: roomId })
  });

  if (!res.ok) {
    // Vis gode feilmeldinger og re-åpne gate ved 401
    if (res.status === 401) {
      addMsg("Sign in to continue.", "error");
    } else if (res.status === 403) {
      addMsg("⛔ Forbidden (bad origin).", "error");
    } else if (res.status === 429) {
      addMsg("⏱️ Too many requests. Please wait a moment.", "error");
    } else {
      const t = await res.text().catch(() => String(res.status));
      addMsg(`🚨 Token error (${res.status}): ${t}`, "error");
    }
    throw new Error(`Token error ${res.status}`);
  }

  const { token } = await res.json();
  if (!token) throw new Error("No token in response");
  return token;
}


/* Chaff/Ping */
function scheduleChaff(){
  if(!ENABLE_CHAFF) return;
  const delay=CHAFF_MIN_MS+Math.random()*(CHAFF_MAX_MS-CHAFF_MIN_MS);
  clearTimeout(chaffTimer);
  chaffTimer=setTimeout(()=>{
    if(!ws||ws.readyState!==WebSocket.OPEN||!grp?.ready) return;
    // Cover traffic has no message/epoch key and cannot retain an erased seed.
    sendMessage({t:"chaff",cid:CID,c:b64(sodium.randombytes_buf(64))});
    scheduleChaff();
  }, delay);
}
function schedulePing(){
  const delay=PING_MIN_MS+Math.random()*(PING_MAX_MS-PING_MIN_MS);
  clearTimeout(pingTimer);
  pingTimer=setTimeout(()=>{
    if(!ws||ws.readyState!==WebSocket.OPEN) return;
    sendMessage({t:"ping"});
    schedulePing();
  }, delay);
}

/* Wipe / Deadman / UI helpers */
function wipeSession(){
  connectionGeneration++;
  desiredConnection=false;
  resetReconnectBackoff();
  clearHelloRetry();
  disableDeadman();
  if(deadmanTimer){clearTimeout(deadmanTimer); deadmanTimer=null;}
  if(inviteInterval){clearInterval(inviteInterval); inviteInterval=null;}

  if(ws){
    try{ sendMessage({t:"leave",cid:CID}); }catch{}
    ws.close(); ws=null;
  }
  clearTimeout(chaffTimer);
  clearTimeout(pingTimer);
  clearTimeout(periodicRekeyTimer);
  chaffTimer=pingTimer=null;
  periodicRekeyTimer=null;
  lastRekeyAt=0;

  for (const {timerId} of gkRetryTimers.values()) clearTimeout(timerId);
  gkRetryTimers.clear();
  pendingGK.clear();

  peers.clear(); pendingRequests.clear(); usedHues.clear();
  grp?.destroy();
  wipeKeys(localKeys);
  wipeKeys(nextKeys); nextKeys=null;
  capsuleRaw=null;
  ITXT.value=""; PTXT.value="";
  grp=null; greeted=false; role=null; capsuleInfo=null;
  localKeys=null; // ← keep CID as-is; ID bestemmes eksplisitt ved ny start/join

  CH.innerHTML=""; pendingList.innerHTML="";
  document.querySelectorAll("#userList .user-entry").forEach(n=>n.remove());

  // Viktig: sett inputs/knapper tilbake til disabled
  S.disabled = true;
  IN.disabled = true;
  disconnectBtn.disabled = true;
  // deadman kan alltid toggles (ikke disable her)

  Ibtn.disabled = true;
  ST.textContent="";
}
function onVisibilityChange(){
  if(document.hidden){
    clearTimeout(deadmanTimer);
    deadmanTimer=setTimeout(wipeSession, DEADMAN_TIMEOUT_MS);
  } else {
    clearTimeout(deadmanTimer);
    deadmanTimer=null;
  }
}
function enableDeadman(){ window.addEventListener("visibilitychange", onVisibilityChange); }
function disableDeadman(){ window.removeEventListener("visibilitychange", onVisibilityChange); }

document.addEventListener("visibilitychange", ()=>{
  if(!document.hidden) scheduleReconnect(120);
});
window.addEventListener("pageshow", ()=>scheduleReconnect(120));
window.addEventListener("online", ()=>scheduleReconnect(120));

function renderPending(){
  pendingList.innerHTML="";
  if(role!=="init") return;
  for(const cid of pendingRequests.keys()){
    const li=document.createElement("li");
    li.textContent=`🔑 Pending: ${cid.slice(0,6)} (${fp4(peers.get(cid).idPub)})`;
    const btn=document.createElement("button");
    btn.textContent="Approve";
    btn.onclick=()=>approvePeer(cid);
    li.appendChild(btn);
    pendingList.appendChild(li);
  }
}
function renderUserList(){
  const c=$("userList");
  c.querySelectorAll(".user-entry").forEach(n=>n.remove());
  if(role==="resp"&&!grp?.ready){
    if(peers.has(CID)){
      const p=peers.get(CID), d=document.createElement("div");
      d.className="user-entry"; d.style.color=p.color;
      setUserLabel(d, CID);
      c.appendChild(d);
    }
    return;
  }
  for(const [id,p] of peers){
    const d=document.createElement("div");
    d.className="user-entry"; d.style.color=p.color;
    if(role==="init"&&pendingRequests.has(id)) d.style.opacity="0.5";
    setUserLabel(d, id);
    c.appendChild(d);
  }
}
function setUserLabel(element, cid){
  const icon=document.createElement("span"), label=document.createElement("span");
  icon.className="user-icon"; label.className="user-id";
  label.textContent=cid.slice(0,6);
  element.replaceChildren(icon, label);
}
function remainingBurnMs(msg){
  if(typeof msg?.rt !== "number") return null;
  return Math.max(0, msg.rt + BURN_MAX_MS - Date.now());
}
function addMsg(txt, cls="in", fromCid=null, ttlMs=null){
  const li=Object.assign(document.createElement("li"),{className:cls});
  if(fromCid&&peers.has(fromCid)) li.style.borderLeftColor=peers.get(fromCid).color;
  li.textContent=txt;
  const burn=Object.assign(document.createElement("button"),{className:"burn",textContent:"💥"});
  burn.onclick=()=>li.remove();
  li.appendChild(burn);
  CH.append(li);
  requestAnimationFrame(()=>{ CH.scrollTop=CH.scrollHeight; });
  const timeout=ttlMs ?? (BURN_BASE_MS+(Math.random()*BURN_JITTER_MS-BURN_JITTER_MS/2));
  setTimeout(()=>li.remove(), timeout);
}

// Abstraksjon så app funker med både Group og MlsGroup
function addToGroup(peerCid, ratchet){
  grp.addMember(peerCid, ratchet, peers.get(peerCid).idPub);
}

/* Host approval */
async function approvePeer(cid){
  const p=peers.get(cid);
  if(!p || p.approving || role!=="init" || !pendingRequests.has(cid)) return;
  p.approving=true;
  const keys=localKeys, group=grp, socket=ws, roomId=R.value.trim();
  let ratchet;
  try {
    ratchet=await handshakeWith(p, keys, "init", roomId, {hostCid:CID,guestCid:cid});
    if(localKeys!==keys || grp!==group || ws!==socket || peers.get(cid)!==p) {
      ratchet.destroy(); return;
    }
    if(!sendMessage({t:"ct", v:PROTOCOL_VERSION, cid:CID, to:cid,
      ct:b64(p.ct), rp:b64(p.rp), sig:b64(p.sig)})) throw new Error("Disconnected");
    addToGroup(cid, ratchet);
    ratchet=null; // Ownership transferred to the group.
    pendingRequests.delete(cid);
    renderPending(); renderUserList();
    addMsg(`✅ SAS for ${cid.slice(0,6)}: ${p.sas}`,"sys");
  } catch {
    ratchet?.destroy();
    if(grp===group && (group?.destroyed || group?.peers.has(cid))) wipeSession();
    addMsg("Peer authentication failed. Request a new invitation.", "error");
  }
  finally { p.approving=false; }
}

/* Ready UI */
function readyUI(){
  if(!greeted){
    addMsg(`🔐 Hybrid encrypted channel established.\nAuthenticated messages • temporary chat`,"sys");
    greeted=true; scheduleChaff();
  }
  S.disabled=false;
  IN.disabled=false;
  disconnectBtn.disabled=false;
  deadmanToggle.disabled=false;

  Ibtn.disabled = role!=="init";
  ST.textContent="🔐 Secured";
  grp.flush(txt=>addMsg(txt,"in"));
  if(role==="resp"){
    for(const {timerId} of gkRetryTimers.values()) clearTimeout(timerId);
    gkRetryTimers.clear();
    for(const id of peers.keys()) if(!grp.identities.has(id)) peers.delete(id);
    for(const [id, idPub] of grp.identities) {
      if(!peers.has(id)) peers.set(id, {idPub, color:randomColor()});
    }
  }
  if(deadmanToggle.checked) enableDeadman();
  renderUserList();
  schedulePeriodicRekey();
}

/* Host start */
J.onclick=()=>{
  if(ws){
    if(!confirm("Leave the current chat and start new?")) return;
    wipeSession();
  }
  CID = genUUID();
  R.value=genUUID();
  role="init";
  startChat();
};


/* Invite */
Ibtn.onclick=()=>{
  ITXT.disabled = false;                 // re-enable i tilfelle tidligere invite utløp
  if(INV_COPY){
    INV_COPY.disabled = false;
    INV_COPY.textContent = "Copy";
  }
  ITXT.value=createCapsule(
    R.value.trim()||genUUID(),
    localKeys.xPub, localKeys.pqPub,
    CID, localKeys.idPriv, localKeys.idPub
  );
  clearInterval(inviteInterval);
  let rem=CAPSULE_TTL_MS;
  INV_TIMER.textContent="02:00";
  inviteInterval=setInterval(()=>{
    rem-=1000;
    if(rem<=0){
      clearInterval(inviteInterval);
      INV_TIMER.textContent="Expired";
      ITXT.disabled=true;
      if(INV_COPY) INV_COPY.disabled=true;
      return;
    }
    const m=String(Math.floor(rem/60000)).padStart(2,"00"),
          s=String(Math.floor((rem%60000)/1000)).padStart(2,"00");
    INV_TIMER.textContent=`${m}:${s}`;
  },1000);
  IDLG.showModal();
  requestAnimationFrame(()=>INV_COPY?.focus({preventScroll:true}));
};
async function copyInviteCapsule(){
  if(inviteCopyBusy) return;
  const capsule=ITXT.value;
  if(!capsule) return;
  inviteCopyBusy=true;
  const copied=await writeClipboardText(capsule);
  INV_COPY.textContent=copied ? "Copied" : "Copy failed";
  setTimeout(()=>{
    inviteCopyBusy=false;
    if(INV_COPY&&!INV_COPY.disabled) INV_COPY.textContent="Copy";
  }, 1200);
}
INV_COPY.addEventListener("click", ev=>{
  ev.preventDefault();
  copyInviteCapsule();
});
function closeInviteDialog(ev){
  ev?.preventDefault();
  inviteCopyBusy=false;
  clearInterval(inviteInterval);
  clearInviteFocus();
  if(IDLG.open) IDLG.close();
}
INV_CLOSE.addEventListener("click", closeInviteDialog);

/* Guest paste & confirm */
C.onclick=()=>PDL.showModal();
POK.onclick=async ()=>{
  const raw=PTXT.value.trim();
  const obj=parseCapsule(raw);
  if(!obj){ alert("❌ Invalid or expired capsule"); return; }
  PDL.close();
  wipeKeys(nextKeys);
  nextKeys=await createLocalKeys();
  capsuleInfo=obj;
  capsuleRaw=raw;
  CONF_ROOM.textContent=obj.room;
  CONF_HOSTFP.textContent=fp4(obj.idPub);
  nextCid = genUUID(); // ← NEW: pre-generer ID som vises og faktisk brukes etter join
  CONF_GUESTFP.textContent = fp4(nextKeys.idPub);
  CONFIRMDLG.showModal();
};
// NEW: no inline onclick in HTML; bind here instead
if (P_CANCEL) P_CANCEL.onclick = () => PDL.close();

CONF_CANCEL.onclick=()=>{ wipeKeys(nextKeys); nextKeys=null; CONFIRMDLG.close(); };

/* Confirm join (guest) */
CONF_JOIN.onclick=async ()=>{
  const info=parseCapsule(capsuleRaw || "");
  if(!info){
    capsuleInfo=null;
    capsuleRaw=null;
    CONFIRMDLG.close();
    alert("❌ Invite capsule expired. Ask the host for a new one.");
    return;
  }
  capsuleInfo=info;
  CONFIRMDLG.close();


  // Lås ID-en som ble vist i dialogen, før ev. wipe
  if (nextCid) { CID = nextCid; nextCid = null; }
  else { CID = genUUID(); }

  const joiningKeys=nextKeys; nextKeys=null;
  if(ws) wipeSession();
  else { grp?.destroy(); wipeKeys(localKeys); grp=null; }

  localKeys=joiningKeys || await createLocalKeys();
  capsuleInfo=info;
  role="resp";
  R.value=info.room;

  peers.clear();
  for(const {timerId} of gkRetryTimers.values()) clearTimeout(timerId);
  gkRetryTimers.clear(); pendingGK.clear();

  peers.set(CID, { xPub:localKeys.xPub, pqPub:localKeys.pqPub, idPub:localKeys.idPub, color:randomColor() });
  peers.set(info.cid, { xPub:info.xPub, pqPub:info.pqPub, idPub:info.idPub, color:randomColor() });

  renderUserList();
  startChat();
};


disconnectBtn.onclick=wipeSession;
// deadman kan alltid toggles; ingen krav om aktiv grp
deadmanToggle.addEventListener("change", ()=>{
  deadmanToggle.checked ? enableDeadman() : disableDeadman();
});

/* GK retry (gjest) */
function scheduleGkRetry(hostCid, attempt=1, delay=GK_REQ_DELAY_MS){
  if(role!=="resp") return;
  if(grp?.ready) return;
  const existing=gkRetryTimers.get(hostCid);
  if(existing) clearTimeout(existing.timerId);

  const timerId=setTimeout(()=>{
    if(grp?.ready || ws?.readyState!==WebSocket.OPEN) return;
    try { grp?.requestKey(); }
    catch {
      wipeSession();
      addMsg("Key synchronization failed. Request a new invitation.", "error");
      return;
    }
    const next=attempt+1;
    if(next<=GK_REQ_TRIES) scheduleGkRetry(hostCid,next, delay*2);
  }, delay);

  gkRetryTimers.set(hostCid,{tries:attempt,timerId});
}

/* WebSocket */
async function startChat({resume=false}={}){
  if(ws&&(ws.readyState===WebSocket.OPEN||ws.readyState===WebSocket.CONNECTING)) return;
  if(ws) ws=null;
  const generation=++connectionGeneration;
  desiredConnection=true;
  if(!R.value.trim()) R.value=genUUID();
  const roomId=R.value.trim();

  let token, keys;
  try{
    if(!localKeys || (resume && role==="resp")){
      const previous=localKeys;
      const fresh=await createLocalKeys();
      if(generation!==connectionGeneration || !desiredConnection){ wipeKeys(fresh); return; }
      if(previous && resume && role==="resp"){
        // Keep the identity fingerprint the user compared, but never reuse the
        // erased bootstrap or old ratchet session when asking for readmission.
        sodium.memzero(fresh.idPriv);
        fresh.idPriv=previous.idPriv;
        fresh.idPub=previous.idPub;
        previous.idPriv=null; // Identity ownership transfers to the new object.
        wipeBootstrapKeys(previous);
        CID=genUUID();
      }
      localKeys=fresh;
    }
    keys=localKeys;
    token=await getRoomToken(roomId);
  }catch(e){
    if(generation!==connectionGeneration || !desiredConnection) return;
    addMsg(`🚨 Failed to get room token: ${e.message||e}`,"error");
    if(resume) scheduleReconnect(Math.min(reconnectDelay*=2, RECONNECT_MAX_MS));
    return;
  }

  if(generation!==connectionGeneration || !desiredConnection || localKeys!==keys) return;
  const proto=(location.protocol==="https:")?"wss":"ws";
  ws=new WebSocket(`${proto}://${location.host}/ws/${roomId}`, token);
  const socket=ws;

  ws.onopen=()=>{
    if(ws!==socket || generation!==connectionGeneration || localKeys!==keys) return;
    resetReconnectBackoff();
    peers.set(CID,{ xPub:localKeys.xPub, pqPub:localKeys.pqPub, idPub:localKeys.idPub, color:randomColor() });
    renderUserList();
    sendHello();
    if(!grp) grp=new MlsGroup(CID, sendMessage, readyUI, role==="init", {
      room:roomId, idPriv:localKeys.idPriv, idPub:localKeys.idPub,
      hostCid:role==="init" ? CID : capsuleInfo.cid,
      hostId:role==="init" ? localKeys.idPub : capsuleInfo.idPub
    });
    else if(grp.ready){ readyUI(); scheduleChaff(); }
    Ibtn.disabled = role!=="init";
    schedulePing();
    if(role==="resp"&&!grp?.ready) scheduleHelloRetry();
  };

  let inbound=Promise.resolve(), queued=0;
  const handleMessage=async ({data})=>{
    if(ws!==socket || typeof data!=="string" || data.length>16384) return;
    let m; try{ m=JSON.parse(data);}catch{return;}
    if(!m || typeof m!=="object" || Array.isArray(m)) return;

    if(m.t==="leave"){
      if(role==="resp" && m.cid===capsuleInfo?.cid){
        wipeSession(); addMsg("Host disconnected. Request a new invitation.", "sys"); return;
      }
      if(role==="init" && grp.peers.has(m.cid)) grp.removeMember(m.cid);
      peers.delete(m.cid);
      pendingRequests.delete(m.cid);
      renderPending(); renderUserList();
      return;
    }
    if(m.t==="hello"){
      if(role==="init"){
        const parsed=readHello(m, roomId);
        if(!parsed || m.cid===CID) return;
        const known=peers.get(m.cid);
        if(known){
          if(!sodium.memcmp(known.idPub,parsed.idPub) || !sodium.memcmp(known.xPub,parsed.xPub) ||
             !sodium.memcmp(known.pqPub,parsed.pqPub)) return;
        } else {
          if(peers.size>=16) return;
          peers.set(m.cid,{...parsed,color:randomColor()});
          pendingRequests.set(m.cid,true);
        }
        renderPending(); renderUserList();
      }
      return;
    }
    if(m.t==="ct" && m.v===PROTOCOL_VERSION && role==="resp" && m.to===CID && m.cid===capsuleInfo?.cid){
      const p=peers.get(m.cid);
      if(!p || grp.peers.has(m.cid)) return;
      p.ct=u8(m.ct);
      p.rp=u8(m.rp);
      p.sig=u8(m.sig);
      const keys=localKeys, group=grp;
      const ratchet=await handshakeWith(p, keys, "resp", roomId, {hostCid:m.cid,guestCid:CID});
      if(ws!==socket || localKeys!==keys || grp!==group) { ratchet.destroy(); return; }
      addMsg(`✅ Verified host ${m.cid.slice(0,6)} (SAS ${p.sas})`,"sys");
      try { addToGroup(m.cid, ratchet); }
      catch {
        ratchet.destroy();
        wipeSession();
        addMsg("Ratchet initialization failed. Request a new invitation.", "error");
        return;
      }
      renderUserList();

      const buf=pendingGK.get(m.cid);
      if(buf){
        grp.loadGK(buf);
        pendingGK.delete(m.cid);
        renderUserList();
      }
      if(!grp.ready) scheduleGkRetry(m.cid);
      clearHelloRetry();
      return;
    }

    if(m.t==="gk" && role==="resp" && m.to===CID && m.cid===capsuleInfo?.cid){
      if(!verifyPacket(m, roomId, capsuleInfo.idPub)) return;
      if(grp.peers.has(m.cid)){
        if(grp.loadGK(m)){
          clearHelloRetry();
          renderUserList();
        }
      } else {
        pendingGK.set(m.cid, m);
      }
      return;
    }

    if((m.t==="gk_req" || m.t==="gk_ack") && role==="init" && m.to===CID && grp.peers.has(m.cid)){
      grp.handleControl(m);
      return;
    }

    if(m.t==="m"){
      const txt=grp.decrypt(m);
      if(txt!==null){
        const ttl=remainingBurnMs(m);
        if(ttl !== 0) addMsg(txt,"in", m.cid, ttl);
      }
      return;
    }

    if(m.t==="rate"){ addMsg("⏱️ Slow down a bit…","sys"); return; }
  };
  socket.onmessage=event=>{
    if(++queued>64){ socket.close(1008); return; }
    inbound=inbound.then(()=>handleMessage(event)).catch(()=>{
      // Invalid unauthenticated packets may be dropped, but a destroyed ratchet
      // (for example a partially sent epoch or failed ACK) must end the room.
      if(ws===socket && grp?.destroyed){
        wipeSession();
        addMsg("Secure session ended after a key synchronization failure.", "error");
      }
    }).finally(()=>queued--);
  };

  ws.onerror=()=>{
    if(!desiredConnection) addMsg("🚨 WebSocket error","error");
  };
  ws.onclose=(ev)=>{
    if(ws!==socket) return;
    connectionGeneration++;
    const recoverable=![4000,4001,4002,4003,4004,1008,1009].includes(ev.code);
    ws=null;
    // Reconnection is a new membership admission, never a resumption with stale group keys.
    grp?.destroy(); grp=null; greeted=false;
    clearHelloRetry();
    peers.clear(); pendingRequests.clear(); pendingGK.clear();
    for(const {timerId} of gkRetryTimers.values()) clearTimeout(timerId);
    gkRetryTimers.clear();
    if(role==="resp" && capsuleInfo){
      peers.set(capsuleInfo.cid, {xPub:capsuleInfo.xPub, pqPub:capsuleInfo.pqPub,
        idPub:capsuleInfo.idPub, color:randomColor()});
    }
    clearTimeout(chaffTimer);
    clearTimeout(pingTimer);
    clearTimeout(periodicRekeyTimer);
    chaffTimer=pingTimer=null;
    periodicRekeyTimer=null;
    S.disabled=true;
    IN.disabled=true;
    disconnectBtn.disabled=!desiredConnection;
    if(!desiredConnection) return;

    if(ev.code===4000) addMsg("🚫 You are sending messages too fast.","error");
    else if(ev.code===4001) addMsg("🚫 You are temporarily banned. Please try again later.","error");
    else if(ev.code===4002) addMsg("⚠️ Too many connection attempts. Slow down!","error");
    else if(ev.code===4003) addMsg("⛔ Policy violation / bad origin / invalid room.","error");
    else if(ev.code===4004) addMsg("🔒 Unauthorized: missing/invalid room token.","error");
    else if(ev.code===1009) addMsg("📦 Message too big.","error");
    else if(desiredConnection&&recoverable&&!deadmanToggle?.checked){
      ST.textContent="Reconnecting";
      scheduleReconnect(reconnectDelay);
      reconnectDelay=Math.min(reconnectDelay*2, RECONNECT_MAX_MS);
    } else {
      wipeSession();
      addMsg("🔌 Disconnected","error");
    }
  };
}

/* Send */
S.onclick=()=>{
  if(!grp?.ready) return;
  const txt=(IN.value||"").trim();
  if(!txt) return;
  try {
    const pkt=grp.encrypt(txt);
    if(!pkt) return;
    if(!sendMessage(pkt)) throw new Error("Disconnected");
  } catch { addMsg("Message is too large or connection is busy.", "error"); return; }
  addMsg(txt,"out",CID);
  IN.value="";
};
IN.addEventListener("keydown", e=> e.key==="Enter" && S.click());
IN.addEventListener("focus", ()=>{
  setTimeout(()=>{ CH.scrollTop=CH.scrollHeight; }, 220);
});

chatModuleReady = true;
window.NullTraceChatReady = true;
updateLaunchButtons();
window.dispatchEvent(new CustomEvent("nulltrace:chat-ready"));
