//! Small in-memory adapter around vodozemac's Double Ratchet.
//! The external handshake authenticates the context and initial ratchet key.
//! No session serialization, secret export, or truncated-MAC mode is exposed.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use vodozemac::{Curve25519PublicKey, Curve25519SecretKey, olm::{OlmMessage, Session, SessionConfig, SessionKeys}};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

const MAX_PLAIN: usize = 8192;
const MAX_CONTEXT: usize = 2048;
const MAX_WIRE: usize = 12_288;
const ENVELOPE: &[u8] = b"NullTrace DR v3\0";
const WIRE_VERSION: u8 = 3;

fn digest(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update((data.len() as u32).to_be_bytes());
    hash.update(data);
    hash.finalize().into()
}

fn root_material(secret: &[u8], context: &[u8]) -> Result<Zeroizing<[u8; 64]>, &'static str> {
    if secret.len() != 32 || context.is_empty() || context.len() > MAX_CONTEXT {
        return Err("Invalid ratchet bootstrap");
    }
    let salt = digest(b"NullTrace v3 Olm bootstrap context\0", context);
    let mut output = Zeroizing::new([0u8; 64]);
    Hkdf::<Sha256>::new(Some(&salt), secret)
        .expand(b"NullTrace v3 Olm root and initial chain", output.as_mut())
        .map_err(|_| "Ratchet key derivation failed")?;
    Ok(output)
}

fn session_keys(context: &[u8], public_key: Curve25519PublicKey) -> SessionKeys {
    // These public fields name the session/pre-key envelope. They are NOT key
    // material in the external-root constructors and perform no DH operation.
    SessionKeys {
        identity_key: Curve25519PublicKey::from_bytes(digest(b"NullTrace v3 session identity\0", context)),
        base_key: public_key,
        one_time_key: Curve25519PublicKey::from_bytes(digest(b"NullTrace v3 session binding\0", context)),
    }
}

struct Ratchet {
    session: Option<Session>,
    initial_public_key: [u8; 32],
}

impl Ratchet {
    fn initiator(secret: &[u8], context: &[u8]) -> Result<Self, &'static str> {
        let material = root_material(secret, context)?;
        let private_key = Curve25519SecretKey::new();
        let public_key = Curve25519PublicKey::from(&private_key);
        let session = Session::from_root_key_material(
            SessionConfig::version_2(), session_keys(context, public_key),
            material[..32].try_into().map_err(|_| "Invalid root")?,
            material[32..].try_into().map_err(|_| "Invalid chain")?,
            *private_key.to_bytes(),
        );
        Ok(Self { session: Some(session), initial_public_key: *public_key.as_bytes() })
    }

    fn responder(secret: &[u8], context: &[u8], public_key: &[u8]) -> Result<Self, &'static str> {
        let material = root_material(secret, context)?;
        let public_bytes: [u8; 32] = public_key.try_into().map_err(|_| "Invalid ratchet public key")?;
        let public_key = Curve25519PublicKey::from_bytes(public_bytes);
        // Reject low-order/non-contributory public keys before holding state.
        if Curve25519SecretKey::new().diffie_hellman(&public_key).is_none() {
            return Err("Invalid ratchet public key");
        }
        let session = Session::from_remote_root_key_material(
            SessionConfig::version_2(), session_keys(context, public_key),
            material[..32].try_into().map_err(|_| "Invalid root")?,
            material[32..].try_into().map_err(|_| "Invalid chain")?, public_key,
        );
        Ok(Self { session: Some(session), initial_public_key: public_bytes })
    }

    fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, &'static str> {
        if plaintext.len() > MAX_PLAIN || aad.len() > MAX_CONTEXT {
            return Err("Ratchet input too large");
        }
        let session = self.session.as_mut().ok_or("Ratchet destroyed")?;
        let mut envelope = Zeroizing::new(Vec::with_capacity(ENVELOPE.len() + 32 + plaintext.len()));
        envelope.extend_from_slice(ENVELOPE);
        envelope.extend_from_slice(&digest(b"NullTrace v3 ratchet AAD\0", aad));
        envelope.extend_from_slice(plaintext);
        let message = session.encrypt(envelope.as_slice()).map_err(|_| "Ratchet encryption failed")?;
        let (kind, body) = message.to_parts();
        let mut wire = Vec::with_capacity(2 + body.len());
        wire.push(WIRE_VERSION);
        wire.push(kind as u8);
        wire.extend_from_slice(&body);
        Ok(wire)
    }

    fn decrypt(&mut self, wire: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        if wire.len() < 3 || wire.len() > MAX_WIRE || aad.len() > MAX_CONTEXT || wire[0] != WIRE_VERSION {
            return None;
        }
        let message = OlmMessage::from_parts(wire[1] as usize, &wire[2..]).ok()?;
        // Official in-memory cloning API, never serialized or exported. The
        // original state survives invalid MACs, context, or inner formatting.
        let mut candidate = Session::from_pickle(self.session.as_ref()?.pickle());
        let envelope = Zeroizing::new(candidate.decrypt(&message).ok()?);
        let prefix_len = ENVELOPE.len() + 32;
        if envelope.len() < prefix_len || envelope.len() > prefix_len + MAX_PLAIN ||
            !bool::from(envelope[..ENVELOPE.len()].ct_eq(ENVELOPE)) ||
            !bool::from(envelope[ENVELOPE.len()..prefix_len].ct_eq(&digest(b"NullTrace v3 ratchet AAD\0", aad))) {
            return None;
        }
        let plaintext = envelope[prefix_len..].to_vec();
        // Group epochs are monotonic: retaining past envelope keys would allow
        // a future state compromise to reopen skipped historical group seeds.
        candidate.discard_receive_history();
        self.session = Some(candidate);
        Some(plaintext)
    }

    fn destroy(&mut self) {
        self.session.take();
    }
}

#[wasm_bindgen]
pub struct NativeRatchet {
    inner: Ratchet,
}

#[wasm_bindgen]
impl NativeRatchet {
    pub fn initiator(secret: Vec<u8>, context: &[u8]) -> Result<Self, JsError> {
        let secret = Zeroizing::new(secret);
        Ok(Self { inner: Ratchet::initiator(&secret, context).map_err(JsError::new)? })
    }

    pub fn responder(secret: Vec<u8>, context: &[u8], public_key: &[u8]) -> Result<Self, JsError> {
        let secret = Zeroizing::new(secret);
        Ok(Self { inner: Ratchet::responder(&secret, context, public_key).map_err(JsError::new)? })
    }

    #[wasm_bindgen(getter, js_name = initialPublicKey)]
    pub fn initial_public_key(&self) -> Vec<u8> {
        self.inner.initial_public_key.to_vec()
    }

    pub fn encrypt(&mut self, plaintext: Vec<u8>, aad: &[u8]) -> Result<Vec<u8>, JsError> {
        let plaintext = Zeroizing::new(plaintext);
        self.inner.encrypt(&plaintext, aad).map_err(JsError::new)
    }

    pub fn decrypt(&mut self, wire: &[u8], aad: &[u8]) -> Option<js_sys::Uint8Array> {
        // Copy directly into a JS typed array before zeroizing the native
        // plaintext; returning Vec<u8> would free an uncleared native buffer.
        self.inner.decrypt(wire, aad).map(|plaintext| {
            let plaintext = Zeroizing::new(plaintext);
            js_sys::Uint8Array::from(plaintext.as_slice())
        })
    }

    pub fn destroy(&mut self) {
        self.inner.destroy();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Ratchet, Ratchet) {
        let alice = Ratchet::initiator(&[7; 32], b"room|host|guest|identities").unwrap();
        let bob = Ratchet::responder(&[7; 32], b"room|host|guest|identities", &alice.initial_public_key).unwrap();
        (alice, bob)
    }

    fn snapshot(value: &Ratchet) -> Ratchet {
        Ratchet { session: value.session.as_ref().map(|s| Session::from_pickle(s.pickle())),
                  initial_public_key: value.initial_public_key }
    }

    #[test]
    fn directions_replay_and_failed_authentication_are_atomic() {
        let (mut alice, mut bob) = pair();
        let packet = alice.encrypt(b"group seed", b"roster epoch 1").unwrap();
        let mut corrupt = packet.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(bob.decrypt(&corrupt, b"roster epoch 1").is_none());
        assert!(bob.decrypt(&packet, b"different epoch").is_none());
        assert_eq!(bob.decrypt(&packet, b"roster epoch 1").unwrap(), b"group seed");
        assert!(bob.decrypt(&packet, b"roster epoch 1").is_none());
        let reply = bob.encrypt(b"ack", b"epoch 1 ack").unwrap();
        assert_eq!(alice.decrypt(&reply, b"epoch 1 ack").unwrap(), b"ack");
        let next = alice.encrypt(b"next seed", b"roster epoch 2").unwrap();
        assert_eq!(bob.decrypt(&next, b"roster epoch 2").unwrap(), b"next seed");
    }

    #[test]
    fn committed_newer_envelope_discards_skipped_and_old_chain_history() {
        let (mut alice, mut bob) = pair();
        let old = alice.encrypt(b"old seed", b"epoch 1").unwrap();
        let new = alice.encrypt(b"new seed", b"epoch 2").unwrap();
        assert_eq!(bob.decrypt(&new, b"epoch 2").unwrap(), b"new seed");
        assert!(bob.decrypt(&old, b"epoch 1").is_none());
        let mut stolen_after = snapshot(&bob);
        assert!(stolen_after.decrypt(&old, b"epoch 1").is_none());
        let later_old_chain = alice.encrypt(b"delayed old chain", b"epoch 3").unwrap();
        let reply = bob.encrypt(b"reply", b"ack").unwrap();
        alice.decrypt(&reply, b"ack").unwrap();
        let fresh_chain = alice.encrypt(b"fresh chain", b"epoch 4").unwrap();
        bob.decrypt(&fresh_chain, b"epoch 4").unwrap();
        assert!(snapshot(&bob).decrypt(&later_old_chain, b"epoch 3").is_none());
    }

    #[test]
    fn post_compromise_snapshot_loses_future_access_after_fresh_dh_exchange() {
        let (mut alice, mut bob) = pair();
        let first = alice.encrypt(b"first", b"epoch1").unwrap();
        bob.decrypt(&first, b"epoch1").unwrap();
        let mut attacker = snapshot(&bob);
        let response = bob.encrypt(b"fresh receiver entropy", b"ack1").unwrap();
        alice.decrypt(&response, b"ack1").unwrap();
        let healed = alice.encrypt(b"fresh sender entropy", b"epoch2").unwrap();
        assert!(attacker.decrypt(&healed, b"epoch2").is_none());
        assert_eq!(bob.decrypt(&healed, b"epoch2").unwrap(), b"fresh sender entropy");
        assert!(snapshot(&bob).decrypt(&first, b"epoch1").is_none());
    }

    #[test]
    fn snapshot_after_ack_tracks_next_envelope_until_another_honest_dh_roundtrip() {
        let (mut alice, mut bob) = pair();
        let first = alice.encrypt(b"epoch one seed", b"epoch1").unwrap();
        bob.decrypt(&first, b"epoch1").unwrap();
        let ack1 = bob.encrypt(b"first acknowledgement", b"ack1").unwrap();

        // Worse compromise timing: Bob's first fresh sending DH private key
        // already exists. A passive attacker can follow Alice's next turn.
        let mut attacker = snapshot(&bob);
        alice.decrypt(&ack1, b"ack1").unwrap();
        let exposed = alice.encrypt(b"still exposed seed", b"epoch2").unwrap();
        assert_eq!(attacker.decrypt(&exposed, b"epoch2").unwrap(), b"still exposed seed");
        assert_eq!(bob.decrypt(&exposed, b"epoch2").unwrap(), b"still exposed seed");

        // A later honest acknowledgement contributes a DH private key absent
        // from the stolen snapshot. Recovery requires these successful turns,
        // not merely elapsed time or a scheduled group-rotation deadline.
        let ack2 = bob.encrypt(b"new uncompromised acknowledgement", b"ack2").unwrap();
        alice.decrypt(&ack2, b"ack2").unwrap();
        let healed = alice.encrypt(b"recovered epoch seed", b"epoch3").unwrap();
        assert!(attacker.decrypt(&healed, b"epoch3").is_none());
        assert_eq!(bob.decrypt(&healed, b"epoch3").unwrap(), b"recovered epoch seed");
    }

    #[test]
    fn bootstrap_binding_bounds_and_destroy() {
        let (mut alice, mut bob) = pair();
        let mut wrong = Ratchet::responder(&[7; 32], b"another room", &alice.initial_public_key).unwrap();
        let packet = alice.encrypt(b"secret", b"aad").unwrap();
        assert!(wrong.decrypt(&packet, b"aad").is_none());
        assert!(Ratchet::responder(&[7; 32], b"context", &[0; 32]).is_err());
        assert!(alice.encrypt(&vec![0; MAX_PLAIN + 1], b"aad").is_err());
        assert!(bob.decrypt(&vec![0; MAX_WIRE + 1], b"aad").is_none());
        bob.destroy();
        assert!(bob.decrypt(&packet, b"aad").is_none());
        assert!(bob.encrypt(b"x", b"aad").is_err());
    }

    #[test]
    fn valid_legacy_truncated_mac_is_rejected_without_consuming_state() {
        let secret = [7; 32];
        let context = b"full mac mandatory";
        let material = root_material(&secret, context).unwrap();
        let private_key = Curve25519SecretKey::new();
        let public_key = Curve25519PublicKey::from(&private_key);
        let make_session = |config| Session::from_root_key_material(
            config, session_keys(context, public_key), material[..32].try_into().unwrap(),
            material[32..].try_into().unwrap(), *private_key.to_bytes());
        let mut legacy = make_session(SessionConfig::version_1());
        let mut current = Ratchet { session: Some(make_session(SessionConfig::version_2())),
                                    initial_public_key: *public_key.as_bytes() };
        let mut bob = Ratchet::responder(&secret, context, public_key.as_bytes()).unwrap();
        let mut inner = ENVELOPE.to_vec();
        inner.extend_from_slice(&digest(b"NullTrace v3 ratchet AAD\0", b"aad"));
        inner.extend_from_slice(b"seed");
        let (kind, body) = legacy.encrypt(inner).unwrap().to_parts();
        let mut wire = vec![WIRE_VERSION, kind as u8];
        wire.extend_from_slice(&body);
        assert!(bob.decrypt(&wire, b"aad").is_none());
        let valid = current.encrypt(b"seed", b"aad").unwrap();
        assert_eq!(bob.decrypt(&valid, b"aad").unwrap(), b"seed");
    }
}
