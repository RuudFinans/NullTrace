// frontend/static/js/app.js – NullTrace Chat v98 (MLS + robust GK + CSP-safe UI)

import sodium from "libsodium-wrappers";
import { createLocalKeys, handshakeWith, b64, u8 } from "handshake";
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

let chatModuleReady = false;

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

// Host-side rekey throttle
let lastRekeyAt = 0;
function safeRekey(){
  const now = Date.now();
  if (!grp) return;
  if (now - lastRekeyAt < REKEY_MIN_MS) return;
  lastRekeyAt = now;
  grp.rekey();
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
  if(!ws) return;
  const msg={...obj};
  const overhead=JSON.stringify(msg).length+8;
  const target=MIN_PACKET_SIZE+Math.floor(Math.random()*(MAX_PACKET_SIZE-MIN_PACKET_SIZE+1));
  const pad=target-overhead;
  if(pad>0) msg.pad=randomString(pad);
  ws.send(JSON.stringify(msg));
}
function sendHello(){
  if(!ws||ws.readyState!==WebSocket.OPEN||!localKeys) return;
  sendMessage({ t:"hello", cid:CID, x:b64(localKeys.xPub), k:b64(localKeys.pqPub), id:b64(localKeys.idPub) });
}
function clearHelloRetry(){
  clearTimeout(helloRetryTimer);
  helloRetryTimer=null;
  helloRetryCount=0;
}
function scheduleHelloRetry(){
  if(role!=="resp") return;
  if(grp&&grp.groupKey){ clearHelloRetry(); return; }
  if(helloRetryCount>=HELLO_RETRY_TRIES) return;
  clearTimeout(helloRetryTimer);
  helloRetryTimer=setTimeout(()=>{
    if(role!=="resp"||!ws||ws.readyState!==WebSocket.OPEN) return;
    if(grp&&grp.groupKey){ clearHelloRetry(); return; }
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
    if(!ws||ws.readyState!==WebSocket.OPEN||!grp||!grp.groupKey) return;
    const n=sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const c=sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(new Uint8Array(),null,null,n,grp.groupKey);
    sendMessage({t:"chaff",cid:CID,n:b64(n),c:b64(c)});
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
  chaffTimer=pingTimer=null;

  for (const {timerId} of gkRetryTimers.values()) clearTimeout(timerId);
  gkRetryTimers.clear();
  pendingGK.clear();

  peers.clear(); pendingRequests.clear(); usedHues.clear();
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
    li.textContent=`🔑 Pending: ${cid.slice(0,6)}`;
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
  if(role==="resp"&&(!grp||!grp.groupKey)){
    if(peers.has(CID)){
      const p=peers.get(CID), d=document.createElement("div");
      d.className="user-entry"; d.style.color=p.color;
      d.innerHTML=`<span class="user-icon"></span><span class="user-id">${CID.slice(0,6)}</span>`;
      c.appendChild(d);
    }
    return;
  }
  for(const [id,p] of peers){
    const d=document.createElement("div");
    d.className="user-entry"; d.style.color=p.color;
    if(role==="init"&&pendingRequests.has(id)) d.style.opacity="0.5";
    d.innerHTML=`<span class="user-icon"></span><span class="user-id">${id.slice(0,6)}</span>`;
    c.appendChild(d);
  }
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
function addToGroup(peerCid, sk){
  if (grp && typeof grp.addMember === "function") grp.addMember(peerCid, sk);
  else if (grp && typeof grp.addPeer === "function") grp.addPeer(peerCid, sk);
}

/* Host approval */
async function approvePeer(cid){
  const p=peers.get(cid);
  if(!p){ addMsg("⚠️ Unknown peer to approve","error"); return; }
  const sk=await handshakeWith(p, localKeys, "init", R.value.trim());
  sendMessage({t:"ct", cid:CID, to:cid, ct:b64(p.ct), sig:b64(p.sig)});
  addToGroup(cid, sk);
  // MLS har debounce, men vi vil ha rask oppstart:
  safeRekey();

  pendingRequests.delete(cid);
  renderPending();

  // announce egen + ny + øvrige
  sendMessage({t:"announce", cid:CID, x:b64(localKeys.xPub), k:b64(localKeys.pqPub), id:b64(localKeys.idPub)});
  sendMessage({t:"announce", cid,      x:b64(p.xPub),         k:b64(p.pqPub),        id:b64(p.idPub)});
  for(const [o,oP] of peers){
    if(o===CID||pendingRequests.has(o)||o===cid) continue;
    sendMessage({t:"announce", cid:o, x:b64(oP.xPub), k:b64(oP.pqPub), id:b64(oP.idPub)});
  }
  renderUserList();
  if(p.sas) addMsg(`✅ SAS for ${cid.slice(0,6)}: ${p.sas}`,"sys");
}

/* Ready UI */
function readyUI(){
  if(!greeted){
    addMsg(`🔐 Secure channel established.\nPost-quantum handshake • forward secrecy • zero logs`,"sys");
    greeted=true; scheduleChaff();
  }
  S.disabled=false;
  IN.disabled=false;
  disconnectBtn.disabled=false;
  deadmanToggle.disabled=false;

  Ibtn.disabled = role!=="init";
  ST.textContent="🔐 Secured";
  grp.flush(txt=>addMsg(txt,"in"));
  if(deadmanToggle.checked) enableDeadman();
  renderUserList();
}

/* Host start */
J.onclick=()=>{
  if(ws){
    if(!confirm("Leave the current chat and start new?")) return;
    wipeSession();
  }
  CID = genUUID();
  R.value=genUUID().slice(0,12);
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
    R.value.trim()||genUUID().slice(0,12),
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
};
async function copyInviteCapsule(){
  if(inviteCopyBusy) return;
  const capsule=ITXT.value;
  if(!capsule) return;
  inviteCopyBusy=true;
  let copied=false;
  try{
    if(navigator.clipboard&&window.isSecureContext){
      await navigator.clipboard.writeText(capsule);
      copied=true;
    } else {
      ITXT.readOnly=true;
      ITXT.focus({preventScroll:true});
      ITXT.select();
      ITXT.setSelectionRange(0, capsule.length);
      copied=document.execCommand("copy");
    }
  }catch{
    try{
      ITXT.readOnly=true;
      ITXT.focus({preventScroll:true});
      ITXT.select();
      ITXT.setSelectionRange(0, capsule.length);
      copied=document.execCommand("copy");
    }catch{}
  }
  INV_COPY.textContent=copied ? "Copied" : "Selected - Copy";
  setTimeout(()=>{
    inviteCopyBusy=false;
    if(INV_COPY&&!INV_COPY.disabled) INV_COPY.textContent="Copy";
  }, 1200);
}
INV_COPY.addEventListener("click", copyInviteCapsule);
function closeInviteDialog(ev){
  ev?.preventDefault();
  inviteCopyBusy=false;
  clearInterval(inviteInterval);
  ITXT.blur();
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
  localKeys=localKeys||await createLocalKeys();
  capsuleInfo=obj;
  capsuleRaw=raw;
  CONF_ROOM.textContent=obj.room;
  CONF_HOSTFP.textContent=obj.cid.slice(0,6);
  nextCid = genUUID(); // ← NEW: pre-generer ID som vises og faktisk brukes etter join
  CONF_GUESTFP.textContent = nextCid.slice(0,6);
  CONFIRMDLG.showModal();
};
// NEW: no inline onclick in HTML; bind here instead
if (P_CANCEL) P_CANCEL.onclick = () => PDL.close();

CONF_CANCEL.onclick=()=>CONFIRMDLG.close();

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

  if(ws) wipeSession();

  localKeys=await createLocalKeys();
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
  if(grp&&grp.groupKey) return;
  const existing=gkRetryTimers.get(hostCid);
  if(existing) clearTimeout(existing.timerId);

  const timerId=setTimeout(()=>{
    if(grp&&grp.groupKey) return;
    sendMessage({t:"gk_req", cid:CID, to:hostCid});
    const next=attempt+1;
    if(next<=GK_REQ_TRIES) scheduleGkRetry(hostCid,next, delay*2);
  }, delay);

  gkRetryTimers.set(hostCid,{tries:attempt,timerId});
}

/* WebSocket */
async function startChat({resume=false}={}){
  if(ws&&(ws.readyState===WebSocket.OPEN||ws.readyState===WebSocket.CONNECTING)) return;
  if(ws) ws=null;
  if(!R.value.trim()) R.value=genUUID().slice(0,12);
  const roomId=R.value.trim();
  localKeys=localKeys||await createLocalKeys();

  let token;
  try{
    token=await getRoomToken(roomId);
  }catch(e){
    addMsg(`🚨 Failed to get room token: ${e.message||e}`,"error");
    if(resume) scheduleReconnect(Math.min(reconnectDelay*=2, RECONNECT_MAX_MS));
    return;
  }

  desiredConnection=true;
  const proto=(location.protocol==="https:")?"wss":"ws";
  ws=new WebSocket(`${proto}://${location.host}/ws/${roomId}`, token);

  ws.onopen=()=>{
    resetReconnectBackoff();
    peers.set(CID,{ xPub:localKeys.xPub, pqPub:localKeys.pqPub, idPub:localKeys.idPub, color:randomColor() });
    renderUserList();
    sendHello();
    if(!grp) grp=new MlsGroup(CID, sendMessage, readyUI, role==="init");
    else if(grp.groupKey){ readyUI(); scheduleChaff(); }
    Ibtn.disabled = role!=="init";
    schedulePing();
    if(role==="resp"&&(!grp||!grp.groupKey)) scheduleHelloRetry();
  };

  ws.onmessage=async ({data})=>{
    let m; try{ m=JSON.parse(data);}catch{return;}

    if(m.t==="leave"){
      peers.delete(m.cid);
      pendingRequests.delete(m.cid);
      renderPending(); renderUserList();
      return;
    }
    if(m.t==="hello"){
      if(role==="init"){
        const knownPeer=peers.has(m.cid)&&!pendingRequests.has(m.cid);
        peers.set(m.cid,{ xPub:u8(m.x), pqPub:u8(m.k), idPub:u8(m.id), color:randomColor() });
        if(!knownPeer) pendingRequests.set(m.cid,true);
        renderPending(); renderUserList();
      }
      return;
    }
    if(m.t==="announce"){
      if(m.cid!==CID && !peers.has(m.cid) && !pendingRequests.has(m.cid)){
        peers.set(m.cid,{ xPub:u8(m.x), pqPub:u8(m.k), idPub:u8(m.id), color:randomColor() });
        renderUserList();
      }
      return;
    }

    if(m.t==="ct" && role==="resp" && m.to===CID){
      const p=peers.get(m.cid);
      if(!p) return;
      p.ct=u8(m.ct);
      if(m.sig) p.sig=u8(m.sig);
      const sk=await handshakeWith(p, localKeys, "resp", R.value.trim());
      if(p.sig){
        if(p.sigOK) addMsg(`✅ Verified host ${m.cid.slice(0,6)} (SAS ${p.sas})`,"sys");
        else addMsg(`⚠️ Could not verify host signature for ${m.cid.slice(0,6)}`,"error");
      }
      addToGroup(m.cid, sk);
      renderUserList();

      const buf=pendingGK.get(m.cid);
      if(buf){
        grp.loadGK(buf, sk);
        pendingGK.delete(m.cid);
        renderUserList();
      } else {
        scheduleGkRetry(m.cid);
      }
      clearHelloRetry();
      return;
    }

    if(m.t==="gk" && role==="resp"){
      const sk=grp.peers.get(m.cid);
      if(sk){
        grp.loadGK(m, sk);
        clearHelloRetry();
        renderUserList();
      } else {
        pendingGK.set(m.cid, m);
      }
      return;
    }

    if(m.t==="gk_req" && role==="init"){ safeRekey(); return; }

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

  ws.onerror=()=>{
    if(!desiredConnection) addMsg("🚨 WebSocket error","error");
  };
  ws.onclose=(ev)=>{
    const recoverable=![4000,4001,4002,4003,4004,1009].includes(ev.code);
    ws=null;
    clearTimeout(chaffTimer);
    clearTimeout(pingTimer);
    chaffTimer=pingTimer=null;
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
    } else addMsg("🔌 Disconnected","error");
  };
}

/* Send */
S.onclick=()=>{
  if(!grp||!grp.groupKey) return;
  const txt=(IN.value||"").trim();
  if(!txt) return;
  const pkt=grp.encrypt(txt);
  if(!pkt) return;
  sendMessage(pkt);
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
