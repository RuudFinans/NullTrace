# NullTrace browser Double Ratchet engine

The application serves committed WASM and JavaScript from
`frontend/static/libs/ratchet-wasm`. Render needs no Rust, worker, database,
extra process, or new environment setting for this engine. Rebuild these
assets only when modifying the native source or updating a dependency.

## Engine and local changes

The engine is Matrix's maintained **vodozemac 0.11.1**, pinned in Cargo.lock.
The upstream crate is vendored, retaining its Apache-2.0 license and source
notices. Original published crate archive SHA-256:

```
9e322119358132f5fa8e529de9ed9af4cd67ae71ffc6f12c133f75d5c4ec9637
```

Upstream source revision: `3e11ae87d157da6bcac3cbf7825d37c8f5ed60af`.
Provenance: <https://crates.io/crates/vodozemac/0.11.1> and
<https://github.com/matrix-org/vodozemac/tree/0.11.1>.

Upstream has received security auditing. **Our bootstrap, lifecycle patch,
WASM adapter, and application integration have not received that audit.**
The only changes to vendored upstream source are:

1. `olm/session/mod.rs`: expose `from_remote_root_key_material` alongside the
   existing external-root sender constructor. This mirrors the receiver state
   setup after upstream's normal three-DH expansion, accepting an already
   authenticated root/chain and initial peer ratchet public key. The normal
   ratchet, DH, message KDF, cipher, and authentication operations are unchanged.
2. `olm/session/mod.rs`: expose `discard_receive_history`, retaining only the
   newest receive chain and clearing that chain's skipped-message keys.
3. `olm/session/receiver_chain.rs`: the private helper for clearing those keys.

Only `SessionConfig::version_2()` is exposed through the wrapper. Its AES-256
encryption uses a **full 32-byte HMAC-SHA256**, with no truncated 8-byte MAC
fallback. Upstream gates this mode behind `experimental-session-config`;
we pin and test that mode, rather than imply Matrix interoperability.

## Bootstrap and envelope contract

`frontend/static/js/modules/ratchet.js` initializes WASM once with top-level
await, then exposes synchronous `createInitiator(secret, context)` and
`createResponder(secret, context, initialPublicKey)` constructors. Each returns
`initialPublicKey`, `encrypt(plaintext, aad)`, `decrypt(wire, aad)` and
`destroy()`. Plaintext, context and AAD are Uint8Array; wire is canonical
padded base64. Decryption failures return null without committing state.

The existing authenticated hybrid handshake supplies a 32-byte secret. A
domain-separated HKDF-SHA256 binds the canonical protocol, room, participant
CIDs and pinned identities, producing the root and initial chain material.
The initiator generates a **fresh dedicated random X25519 ratchet private
key inside WASM**. It is never the retained handshake key and is never
exported. The handshake signature must authenticate the corresponding
`initialPublicKey` before the responder constructs the session. Constructors
do not authenticate peers themselves. The caller must wipe its copy of the
bootstrap secret promptly.

Olm's upstream envelope has no application AAD parameter. The wrapper encrypts
a domain marker and SHA-256 of length-delimited, domain-separated AAD before
the plaintext. It decrypts into a temporary typed in-memory session clone and
commits only after both engine authentication and constant-time inner AAD
verification pass. This clone uses the public upstream typed pickle API;
there is no serialized JSON state or session export API in the browser.

Bounds: plaintext 8,192 bytes, context/AAD 2,048 bytes, wire 12,288 decoded
bytes (16,384 base64 characters). The existing engine caps ratchet index
skips at 2,000; malformed or over-limit inputs fail closed.

## Deletion and recovery properties

Control envelopes carry monotonic group epochs, so after each authenticated
envelope the wrapper deletes all skipped control-message keys and all obsolete
receive chains. Delayed older control envelopes intentionally become
undecryptable. This prevents a later session-state snapshot from reopening
skipped historical group seeds. Normal group message reordering is handled
separately by the application's bounded sender-chain cache.

The current receive chain remains for future envelopes. Replays are rejected.
Forward secrecy and post-compromise recovery depend on key deletion and on
fresh, authenticated DH exchanges in both directions after the attacker loses
access; continuous endpoint compromise is not repaired by a ratchet. The
group protocol must authenticate acknowledgements and rotate group seeds to
extend that recovery to group messages.

Compromise timing matters: a snapshot taken after an acknowledgement already
contains its sending DH private key and can still decrypt the next host
envelope. A subsequent honest fresh acknowledgement and host DH turn exclude
that snapshot. Recovery requires those successful fresh turns, not a timer
deadline. Native tests cover snapshots taken both before and after the first
acknowledgement, including the temporarily exposed intervening envelope.

This is a **classical** Double Ratchet with an externally supplied hybrid
post-quantum handshake. It is not Signal's Triple Ratchet/SPQR and provides no
ongoing post-quantum ratchet healing. It does not establish superiority over
Signal. Upstream zeroizing key types and explicit wrapper zeroization provide
best-effort memory cleanup; JavaScript, browser/WASM memory, compiler copies,
crash dumps and operating-system snapshots prevent a forensic-erasure
guarantee.

## Build and test

Requirements for local rebuild only: Rust with `wasm32-unknown-unknown`,
and `wasm-bindgen-cli` **0.2.129**. Do not change the compiler's default target.
The committed artifacts were built with **rustc 1.97.1**
(`8bab26f4f68e0e26f0bb7960be334d5b520ea452`, LLVM 22.1.6).

```powershell
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129 --locked --root crypto/ratchet-wasm/.tools
./crypto/ratchet-wasm/build.ps1
cargo test --manifest-path crypto/ratchet-wasm/Cargo.toml --locked
node --test tests/ratchet.test.mjs
```

Equivalent build commands for Linux CI with Rust 1.97.1 selected:

```sh
cargo test --manifest-path crypto/ratchet-wasm/Cargo.toml --locked
cargo build --manifest-path crypto/ratchet-wasm/Cargo.toml --target wasm32-unknown-unknown --release --locked
wasm-bindgen crypto/ratchet-wasm/target/wasm32-unknown-unknown/release/nulltrace_ratchet.wasm --target web --out-dir frontend/static/libs/ratchet-wasm --out-name nulltrace_ratchet --no-typescript
node --test tests/ratchet.test.mjs
```

Verify committed delivery assets before rebuilding with
`cd frontend/static/libs/ratchet-wasm && sha256sum -c SHA256SUMS`.

The build script accepts `-Cargo` and `-WasmBindgen` executable paths if the
tools are not on PATH. Cargo.lock pins the complete runtime dependency tree.
Generated asset SHA-256 values are recorded in `SHA256SUMS` beside the assets.
The native tests include stolen-state snapshots for past-envelope deletion
and classical recovery, invalid-AAD rollback, corruption/replay, and rejection
of otherwise valid legacy truncated-MAC packets. The JavaScript tests run the
actual committed WASM through the public browser adapter.
