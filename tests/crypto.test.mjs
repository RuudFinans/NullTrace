import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import sodium from "libsodium-wrappers";
import {
  createLocalKeys, handshakeWith, createHello, readHello, b64, u8, bytes,
  signPacket, PROTOCOL_VERSION, wipeKeys
} from "../frontend/static/js/modules/handshake.js";
import { createCapsule, parseCapsule } from "../frontend/static/js/modules/nacp.js";
import { MlsGroup } from "../frontend/static/js/modules/mls.js";
await sodium.ready;

const publicKeys = keys => ({xPub:keys.xPub, pqPub:keys.pqPub, idPub:keys.idPub});
const flip = value => { const decoded=u8(value); decoded[0]^=1; return b64(decoded); };
const messageKey = chain => sodium.crypto_auth(bytes("NullTrace v3 sender message key"),chain);
const copyChains = chains => new Map([...chains].map(([cid,chain])=>[cid,{
  key:new Uint8Array(chain.key), next:chain.next,
  skipped:new Map([...chain.skipped].map(([seq,entry])=>[seq,{
    key:new Uint8Array(entry.key), expires:entry.expires
  }]))
}]));

async function handshake(t) {
  const host=await createLocalKeys(), guest=await createLocalKeys(), room=randomUUID();
  const participants={hostCid:randomUUID(),guestCid:randomUUID()};
  const hostPeer=publicKeys(guest);
  const hostRatchet=await handshakeWith(hostPeer,host,"init",room,participants);
  const guestPeer={...publicKeys(host),ct:hostPeer.ct,rp:hostPeer.rp,sig:hostPeer.sig};
  t.after(()=>{hostRatchet.destroy();wipeKeys(host);wipeKeys(guest);});
  return {host,guest,room,participants,hostPeer,hostRatchet,guestPeer};
}

async function network(t,size=2) {
  const room=randomUUID(), keys=[], cids=[], groups=[], packets=[];
  t.after(()=>{groups.forEach(group=>group.destroy());keys.forEach(wipeKeys);});
  for(let i=0;i<size;i++){keys.push(await createLocalKeys());cids.push(randomUUID());}
  const send=packet=>{packets.push(packet);return true;};
  for(let i=0;i<size;i++) groups.push(new MlsGroup(cids[i],send,()=>{},i===0,
    {room,idPriv:keys[i].idPriv,idPub:keys[i].idPub,hostCid:cids[0],hostId:keys[0].idPub}));
  function deliver() {
    const delivered=[];
    while(packets.length){
      assert.ok(delivered.length<128,"Control packets must not trigger an endless rekey loop");
      const packet=packets.shift(), receiver=groups[cids.indexOf(packet.to)];
      delivered.push(packet);
      assert.ok(receiver,"Control packet has a known recipient");
      assert.equal(packet.t==="gk" ? receiver.loadGK(packet) : receiver.handleControl(packet),true);
    }
    return delivered;
  }
  for(let i=1;i<size;i++){
    const peer=publicKeys(keys[i]), participants={hostCid:cids[0],guestCid:cids[i]};
    const hostRatchet=await handshakeWith(peer,keys[0],"init",room,participants);
    const guestRatchet=await handshakeWith({...publicKeys(keys[0]),ct:peer.ct,rp:peer.rp,sig:peer.sig},
      keys[i],"resp",room,participants);
    groups[i].addMember(cids[0],guestRatchet,keys[0].idPub);
    groups[0].addMember(cids[i],hostRatchet,keys[i].idPub);
    deliver();
  }
  return {room,keys,cids,groups,packets,deliver};
}

test("hybrid ratchet bootstrap authenticates participants and fresh DH key before decapsulation",async(t)=>{
  const n=await handshake(t);
  const decap=n.guest.kem.decap.bind(n.guest.kem);
  let decapsulations=0;
  n.guest.kem.decap=async(...args)=>{decapsulations++;return decap(...args);};
  for(const peer of [
    {...n.guestPeer,sig:undefined},
    {...n.guestPeer,sig:new Uint8Array(64)},
    {...n.guestPeer,ct:new Uint8Array(1088)},
    {...n.guestPeer,xPub:sodium.crypto_kx_keypair().publicKey},
    {...n.guestPeer,rp:undefined},
    {...n.guestPeer,rp:sodium.crypto_kx_keypair().publicKey}
  ]) await assert.rejects(handshakeWith(peer,n.guest,"resp",n.room,n.participants));
  await assert.rejects(handshakeWith(n.guestPeer,n.guest,"resp",randomUUID(),n.participants));
  for(const participants of [
    undefined,
    {...n.participants,hostCid:randomUUID()},
    {...n.participants,guestCid:randomUUID()},
    {hostCid:n.participants.guestCid,guestCid:n.participants.hostCid}
  ]) await assert.rejects(handshakeWith(n.guestPeer,n.guest,"resp",n.room,participants));
  assert.equal(decapsulations,0,"Reject unauthenticated transcripts before KEM decapsulation");
  const guestRatchet=await handshakeWith(n.guestPeer,n.guest,"resp",n.room,n.participants);
  t.after(()=>guestRatchet.destroy());
  assert.equal(decapsulations,1);
  const aad=bytes("authenticated test context"), plain=bytes("first epoch");
  assert.deepEqual(guestRatchet.decrypt(n.hostRatchet.encrypt(plain,aad),aad),plain);
  const reply=bytes("acknowledged");
  assert.deepEqual(n.hostRatchet.decrypt(guestRatchet.encrypt(reply,aad),aad),reply);
  assert.equal(n.guestPeer.sigOK,true);
  assert.equal(n.hostPeer.sas,n.guestPeer.sas);
  assert.equal(n.host.pqPub.length,1184);
  assert.equal(n.hostPeer.rp.length,32);
  assert.notDeepEqual(n.hostPeer.rp,n.host.xPub);
  assert.ok(n.guest.xPriv.every(value=>value===0));
  assert.ok(n.guest.pqPriv.every(value=>value===0));
  assert.ok(n.guest.idPriv.some(value=>value!==0),"Identity remains available for signed traffic");
});

test("hello signatures bind identity, key material, client ID and room",async(t)=>{
  const keys=await createLocalKeys(), cid=randomUUID(), room=randomUUID();
  t.after(()=>wipeKeys(keys));
  const hello=createHello(cid,keys,room);
  assert.ok(readHello(hello,room));
  for(const changed of [{...hello,cid:randomUUID()},{...hello,k:flip(hello.k)},
    signPacket({...hello,v:2},room,keys.idPriv),{...hello,sig:""},{...hello,id:flip(hello.id)}]){
    assert.equal(readHello(changed,room),null);
  }
  assert.equal(readHello(hello,randomUUID()),null);
});

test("capsules reject modification, expiration, oversized input and downgrade",async(t)=>{
  const keys=await createLocalKeys();
  t.after(()=>wipeKeys(keys));
  const capsule=createCapsule(randomUUID(),keys.xPub,keys.pqPub,randomUUID(),keys.idPriv,keys.idPub);
  assert.equal(parseCapsule(capsule).ver,"NT-C3");
  for(const change of [
    p=>{p.payload.v="NT-C2";},
    p=>{p.payload.v="NT-C1";},
    p=>{p.payload.room=randomUUID();},
    p=>{p.payload.alg="Ed25519|X25519+ML-KEM-768|HKDF-SHA256|XChaCha20-Poly1305";},
    p=>{p.payload.exp=Date.now()-1;},
    p=>{p.payload.iat=null;},
    p=>{p.sig="";},
    p=>{p.payload.k="A".repeat(1068);}
  ]){
    const data=JSON.parse(sodium.to_string(u8(capsule)));
    change(data);
    assert.equal(parseCapsule(b64(bytes(JSON.stringify(data)))),null);
  }
  assert.equal(parseCapsule("A".repeat(100000)),null);
});

test("three members exchange signed messages in both directions without retaining epoch roots",async(t)=>{
  const n=await network(t,3);
  for(let sender=0;sender<3;sender++){
    assert.equal(n.groups[sender].ready,true);
    assert.equal(n.groups[sender].groupKey,undefined);
    assert.equal(n.groups[sender].recvChains.has(n.cids[sender]),false);
    const packet=n.groups[sender].encrypt("private-"+sender+" 🔐");
    for(let receiver=0;receiver<3;receiver++){
      if(sender!==receiver) assert.equal(n.groups[receiver].decrypt(packet),"private-"+sender+" 🔐");
    }
  }
});

test("tampering does not advance receive state and replay is rejected",async(t)=>{
  const {groups:[host,guest]}=await network(t);
  const packet=host.encrypt("original"), before=new Uint8Array(guest.recvChains.get(host.cid).key);
  t.after(()=>sodium.memzero(before));
  for(const changed of [{...packet,c:flip(packet.c)},{...packet,n:flip(packet.n)},
    {...packet,s:100},{...packet,e:0},{...packet,cid:randomUUID()},
    {...packet,v:2},{...packet,s:-1},{...packet,s:Number.MAX_SAFE_INTEGER+1},
    {...packet,ts:Date.now()+60000}]){
    assert.equal(guest.decrypt(changed),null);
    assert.equal(guest.recvChains.get(host.cid).next,0);
    assert.deepEqual(guest.recvChains.get(host.cid).key,before);
  }
  assert.equal(guest.decrypt(packet),"original");
  assert.equal(guest.decrypt(packet),null);
});

test("a group member cannot impersonate another sender even with its receive chain",async(t)=>{
  const n=await network(t,3), host=n.groups[0];
  const key=messageKey(n.groups[1].recvChains.get(host.cid).key), nonce=sodium.randombytes_buf(24);
  const forged={t:"m",v:PROTOCOL_VERSION,cid:host.cid,s:0,e:host.epoch,ts:Date.now(),n:b64(nonce)};
  forged.c=b64(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    bytes("forged"),host._aad(forged),null,nonce,key));
  sodium.memzero(key);
  assert.equal(n.groups[2].decrypt(signPacket(forged,n.room,n.keys[1].idPriv)),null);
  const otherRoom=new MlsGroup(n.cids[2],()=>true,()=>{},false,
    {room:randomUUID(),idPriv:n.keys[2].idPriv,idPub:n.keys[2].idPub,hostCid:n.cids[0],hostId:n.keys[0].idPub});
  t.after(()=>otherRoom.destroy());
  otherRoom._sendChain=new Uint8Array(n.groups[2]._sendChain);
  otherRoom.recvChains=copyChains(n.groups[2].recvChains);
  otherRoom.epoch=n.groups[2].epoch;
  otherRoom.identities=new Map(n.groups[2].identities);
  assert.equal(otherRoom.decrypt(host.encrypt("cross-room")),null);
});

test("ratchet envelopes bind sender, recipient, roster, room and epoch; no v2 fallback",async(t)=>{
  const n=await network(t);
  n.groups[0].rekey();
  const envelope=n.packets.pop(), guest=n.groups[1];
  for(const changed of [{...envelope,to:randomUUID()},{...envelope,cid:n.cids[1]},
    {...envelope,rh:flip(envelope.rh)},{...envelope,e:envelope.e+1},
    signPacket({...envelope,v:2},n.room,n.keys[0].idPriv),
    {...envelope,sig:""},{...envelope,rk:flip(envelope.rk)}]){
    assert.equal(guest.loadGK(changed),false);
  }
  guest.room=randomUUID();
  assert.equal(guest.loadGK(envelope),false);
  guest.room=n.room;
  assert.equal(guest.loadGK(envelope),true);
  n.deliver();
  guest.encrypt("one");
  assert.equal(guest.loadGK(envelope),false);
  assert.equal(guest.sendSeq,1);
});

test("departed members receive no new epoch and cannot decrypt later messages",async(t)=>{
  const n=await network(t,3), oldChain=new Uint8Array(n.groups[1].recvChains.get(n.cids[0]).key);
  t.after(()=>sodium.memzero(oldChain));
  n.groups[0].removeMember(n.cids[1]);
  assert.equal(n.packets.length,1);
  assert.equal(n.packets[0].to,n.cids[2]);
  n.deliver();
  const packet=n.groups[0].encrypt("after removal");
  assert.equal(n.groups[2].decrypt(packet),"after removal");
  assert.equal(n.groups[1].decrypt(packet),null);
  assert.notDeepEqual(n.groups[0]._sendChain,oldChain);
  const oldMessageKey=messageKey(oldChain);
  try {
    assert.throws(()=>sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,u8(packet.c),n.groups[0]._aad(packet),u8(packet.n),oldMessageKey));
  } finally { sodium.memzero(oldMessageKey); }
});

test("pending queue is bounded and valid messages flush only after authentication",async(t)=>{
  const n=await network(t);
  n.groups[0].rekey();
  const packet=n.groups[0].encrypt("buffered");
  assert.equal(n.groups[1].decrypt(packet),null);
  n.deliver();
  const seen=[];
  n.groups[1].flush(text=>seen.push(text));
  assert.deepEqual(seen,["buffered"]);
  for(let i=0;i<1000;i++) n.groups[1].decrypt({...packet,e:999,s:i});
  assert.equal(n.groups[1].pending.length,32);
});

test("random nonces, bounded sequence gaps, message bounds, and key cleanup",async(t)=>{
  const n=await network(t), host=n.groups[0], guest=n.groups[1];
  const first=host.encrypt("a"), second=host.encrypt("b");
  assert.notEqual(first.n,second.n);
  assert.equal(guest.decrypt(first),"a");
  assert.equal(guest.decrypt(second),"b");
  assert.throws(()=>host.encrypt("🔐".repeat(3000)));
  const before=new Uint8Array(guest.recvChains.get(host.cid).key);
  t.after(()=>sodium.memzero(before));
  host.sendSeq=2**32;
  assert.equal(guest.decrypt(host.encrypt("enormous gap")),null);
  assert.equal(guest.recvChains.get(host.cid).next,2);
  assert.deepEqual(guest.recvChains.get(host.cid).key,before);
  host.sendSeq=Number.MAX_SAFE_INTEGER;
  assert.throws(()=>host.encrypt("exhausted"));
  const chain=host._sendChain, receives=[...host.recvChains.values()].map(value=>value.key);
  const ratchet=host.peers.get(guest.cid), privateKey=n.keys[0].idPriv;
  host.destroy();wipeKeys(n.keys[0]);
  assert.ok(chain.every(value=>value===0));
  assert.ok(receives.every(key=>key.every(value=>value===0)));
  assert.ok(privateKey.every(value=>value===0));
  assert.throws(()=>ratchet.encrypt(bytes("closed"),bytes("test")));
  assert.equal(host.ready,false);
  assert.equal(host.encrypt("closed"),null);
});

test("identity replacement and stale signed messages fail closed",async(t)=>{
  const n=await network(t), host=n.groups[0], guest=n.groups[1], ratchet=host.peers.get(guest.cid);
  assert.throws(()=>host.addMember(guest.cid,ratchet,sodium.crypto_sign_keypair().publicKey));
  assert.equal(host.peers.get(guest.cid),ratchet);
  const stale=host.encrypt("expired");
  stale.ts=Date.now()-60000;
  assert.equal(guest.decrypt(signPacket(stale,n.room,n.keys[0].idPriv)),null);
});
