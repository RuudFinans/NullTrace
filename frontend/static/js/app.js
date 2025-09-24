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
const MIN_HUE_DISTANCE   = 60;

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
      INV_CLOSE=$("inviteCloseBtn"), deadmanToggle=$("deadmanToggle"),
      disconnectBtn=$("disconnectBtn"),
      P_CANCEL=$("pasteCancelBtn");          // ← NEW: no inline onclick

Ibtn.disabled = true;

/* State */
let inviteInterval=null, deadmanTimer=null, greeted=false, chaffTimer=null, pingTimer=null;
const peers=new Map(), pendingRequests=new Map(), usedHues=new Set();

// Buffer GK (gjest), + retry-timere
const pendingGK=new Map(), gkRetryTimers=new Map();

let CID=genUUID();
let localKeys, grp, ws=null;
let role=null;
let capsuleInfo=null;
let nextCid = null; // ← NEW: pre-generert ID som vises i confirm og brukes ved join

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
async function getRoomToken(roomId){
  const res=await fetch("/api/room-token",{
    method:"POST", headers:{"Content-Type":"application/json"},
    body:JSON.stringify({room_id:roomId})
  });
  if(!res.ok){
    const t=await res.text().catch(()=>String(res.status));
    throw new Error(`Token error (${res.status}): ${t}`);
  }
  const {token}=await res.json();
  if(!token) throw new Error("No token in response");
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
function addMsg(txt, cls="in", fromCid=null){
  const li=Object.assign(document.createElement("li"),{className:cls});
  if(fromCid&&peers.has(fromCid)) li.style.borderLeftColor=peers.get(fromCid).color;
  li.textContent=txt;
  const burn=Object.assign(document.createElement("button"),{className:"burn",textContent:"💥"});
  burn.onclick=()=>li.remove();
  li.appendChild(burn);
  CH.append(li);
  CH.scrollTop=CH.scrollHeight;
  const timeout=BURN_BASE_MS+(Math.random()*BURN_JITTER_MS-BURN_JITTER_MS/2);
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
  CID = genUUID(); // ← NEW: host får ny ID hver gang
  R.value=genUUID().slice(0,12);
  role="init";
  startChat();
};

/* Invite */
Ibtn.onclick=()=>{
  ITXT.disabled = false;                 // re-enable i tilfelle tidligere invite utløp
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
      return;
    }
    const m=String(Math.floor(rem/60000)).padStart(2,"00"),
          s=String(Math.floor((rem%60000)/1000)).padStart(2,"00");
    INV_TIMER.textContent=`${m}:${s}`;
  },1000);
  IDLG.showModal();
};
INV_CLOSE.onclick=()=>{ clearInterval(inviteInterval); IDLG.close(); };

/* Guest paste & confirm */
C.onclick=()=>PDL.showModal();
POK.onclick=async ()=>{
  const obj=parseCapsule(PTXT.value.trim());
  if(!obj){ alert("❌ Invalid or expired capsule"); return; }
  PDL.close();
  localKeys=localKeys||await createLocalKeys();
  capsuleInfo=obj;
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
  const info=capsuleInfo;
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
async function startChat(){
  if(ws) return;
  if(!R.value.trim()) R.value=genUUID().slice(0,12);
  const roomId=R.value.trim();
  localKeys=localKeys||await createLocalKeys();

  let token;
  try{
    token=await getRoomToken(roomId);
  }catch(e){
    addMsg(`🚨 Failed to get room token: ${e.message||e}`,"error");
    return;
  }

  const proto=(location.protocol==="https:")?"wss":"ws";
  ws=new WebSocket(`${proto}://${location.host}/ws/${roomId}`, token);

  ws.onopen=()=>{
    peers.set(CID,{ xPub:localKeys.xPub, pqPub:localKeys.pqPub, idPub:localKeys.idPub, color:randomColor() });
    renderUserList();
    sendMessage({ t:"hello", cid:CID, x:b64(localKeys.xPub), k:b64(localKeys.pqPub), id:b64(localKeys.idPub) });
    grp=new MlsGroup(CID, sendMessage, readyUI, role==="init");
    Ibtn.disabled = role!=="init";
    schedulePing();
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
        peers.set(m.cid,{ xPub:u8(m.x), pqPub:u8(m.k), idPub:u8(m.id), color:randomColor() });
        pendingRequests.set(m.cid,true);
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
      return;
    }

    if(m.t==="gk" && role==="resp"){
      const sk=grp.peers.get(m.cid);
      if(sk){
        grp.loadGK(m, sk);
        renderUserList();
      } else {
        pendingGK.set(m.cid, m);
      }
      return;
    }

    if(m.t==="gk_req" && role==="init"){ safeRekey(); return; }

    if(m.t==="m"){
      const txt=grp.decrypt(m);
      if(txt!==null) addMsg(txt,"in", m.cid);
      return;
    }

    if(m.t==="rate"){ addMsg("⏱️ Slow down a bit…","sys"); return; }
  };

  ws.onerror=()=>addMsg("🚨 WebSocket error","error");
  ws.onclose=(ev)=>{
    if(ev.code===4000) addMsg("🚫 You are sending messages too fast.","error");
    else if(ev.code===4001) addMsg("🚫 You are temporarily banned. Please try again later.","error");
    else if(ev.code===4002) addMsg("⚠️ Too many connection attempts. Slow down!","error");
    else if(ev.code===4003) addMsg("⛔ Policy violation / bad origin / invalid room.","error");
    else if(ev.code===4004) addMsg("🔒 Unauthorized: missing/invalid room token.","error");
    else if(ev.code===1009) addMsg("📦 Message too big.","error");
    else addMsg("🔌 Disconnected","error");
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
