import { randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import assert from "node:assert/strict";
import { createLocalKeys, handshakeWith, wipeKeys } from "../frontend/static/js/modules/handshake.js";
import { MlsGroup } from "../frontend/static/js/modules/mls.js";

const host=await createLocalKeys(), guest=await createLocalKeys(), room=randomUUID();
const hostCid=randomUUID(), guestCid=randomUUID(), participants={hostCid,guestCid};
const publicKeys=keys=>({idPub:keys.idPub,xPub:keys.xPub,pqPub:keys.pqPub});
let hostRatchet, guestRatchet, groupHost, groupGuest;
try {
  const peer=publicKeys(guest), started=performance.now();
  hostRatchet=await handshakeWith(peer,host,"init",room,participants);
  guestRatchet=await handshakeWith({...publicKeys(host),ct:peer.ct,rp:peer.rp,sig:peer.sig},
    guest,"resp",room,participants);
  const handshakeMs=performance.now()-started, packets=[];
  const send=packet=>{packets.push(packet);return true;};
  groupHost=new MlsGroup(hostCid,send,()=>{},true,
    {room,idPriv:host.idPriv,idPub:host.idPub,hostCid,hostId:host.idPub});
  groupGuest=new MlsGroup(guestCid,send,()=>{},false,
    {room,idPriv:guest.idPriv,idPub:guest.idPub,hostCid,hostId:host.idPub});
  groupGuest.addMember(hostCid,guestRatchet,host.idPub);
  groupHost.addMember(guestCid,hostRatchet,guest.idPub);
  while(packets.length){
    const packet=packets.shift();
    assert.equal(packet.t==="gk" ? groupGuest.loadGK(packet) : groupHost.handleControl(packet),true);
  }
  const text="x".repeat(1024), durations=[];
  for(let i=0;i<1000;i++){
    const now=performance.now();
    assert.equal(groupGuest.decrypt(groupHost.encrypt(text)),text);
    durations.push(performance.now()-now);
  }
  durations.sort((a,b)=>a-b);
  console.log(JSON.stringify({environment:"local Node.js + committed WASM, synthetic 1 KiB messages",
    messages:durations.length,hybridRatchetBootstrapMs:+handshakeMs.toFixed(3),
    encryptSignVerifyDecryptMedianMs:+durations[499].toFixed(3),
    encryptSignVerifyDecryptP95Ms:+durations[949].toFixed(3)},null,2));
} finally {
  groupHost?.destroy();groupGuest?.destroy();
  hostRatchet?.destroy();guestRatchet?.destroy();
  wipeKeys(host);wipeKeys(guest);
}
