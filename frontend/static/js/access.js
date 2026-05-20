const $ = id => document.getElementById(id);

const accessShell = $("accessShell");
const appShell = $("appShell");
const accessNotice = $("accessNotice");
const planList = $("planList");
const paymentPlan = $("paymentPlan");
const paymentAmount = $("paymentAmount");
const depositAddress = $("depositAddress");
const paymentCountdown = $("paymentCountdown");
const paymentStatus = $("paymentStatus");
const devnetFundBtn = $("devnetFundBtn");
const qrCode = $("qrCode");
const restorePanel = $("restorePanel");
const signinStatus = $("signinStatus");
const signinUserKey = $("signinUserKey");
const signinRestoreKey = $("signinRestoreKey");
const shareKeysBtn = $("shareKeysBtn");
const downloadBackupBtn = $("downloadBackupBtn");

let plans = [];
let currentOrder = null;
let statusTimer = null;
let countdownTimer = null;
let heartbeatTimer = null;
let heartbeatSeconds = 60;
let claimedKeys = null;
let devnetPaymentFaucet = false;

function showScreen(name) {
  document.querySelectorAll(".access-screen").forEach(screen => {
    screen.classList.toggle("access-screen-active", screen.id === name);
  });
}

function showGate(screen = "accessLanding", message = "") {
  document.body.classList.remove("access-unlocked");
  accessShell.hidden = false;
  appShell.hidden = true;
  accessShell.style.display = "";
  appShell.style.display = "";
  accessNotice.textContent = message;
  showScreen(screen);
  stopHeartbeat();
}

function showApp() {
  document.body.classList.add("access-unlocked");
  accessShell.hidden = true;
  appShell.hidden = false;
  accessShell.style.display = "none";
  appShell.style.display = "";
  window.dispatchEvent(new CustomEvent("nulltrace:access-unlocked"));
  startHeartbeat();
}

async function postJson(path, body = {}) {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  return { ok: response.ok, status: response.status, data };
}

async function copyText(text, button) {
  let copied = false;
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      copied = true;
    }
  } catch {}
  if (!copied) {
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    copied = document.execCommand("copy");
    area.remove();
  }
  if (button) {
    const original = button.textContent;
    button.textContent = copied ? "Copied" : "Selected";
    window.setTimeout(() => {
      button.textContent = original;
    }, 1100);
  }
}

function stopPaymentTimers() {
  window.clearInterval(statusTimer);
  window.clearInterval(countdownTimer);
  statusTimer = null;
  countdownTimer = null;
}

function stopHeartbeat() {
  window.clearInterval(heartbeatTimer);
  heartbeatTimer = null;
}

async function heartbeat() {
  if (document.visibilityState !== "visible") return;
  const result = await postJson("/api/access/heartbeat");
  if (!result.ok) {
    const detail = result.data.detail ? ` ${result.data.detail}` : "";
    if (result.status === 402) showGate("accessLanding", `Access expired.${detail}`);
    else showGate("signinScreen", `Session ended.${detail}`);
    return;
  }
  heartbeatSeconds = Number(result.data.heartbeatSeconds || heartbeatSeconds || 60);
}

function startHeartbeat() {
  stopHeartbeat();
  heartbeatTimer = window.setInterval(heartbeat, Math.max(10, heartbeatSeconds) * 1000);
}

async function enterAppAfterAuth() {
  const result = await postJson("/api/access/heartbeat");
  if (!result.ok) {
    signinStatus.textContent = result.data.detail || "Signed in, but session cookie was not accepted.";
    showGate("signinScreen", signinStatus.textContent);
    return false;
  }
  heartbeatSeconds = Number(result.data.heartbeatSeconds || heartbeatSeconds || 60);
  showApp();
  return true;
}

document.addEventListener("visibilitychange", () => {
  if (!appShell.hidden && document.visibilityState === "visible") heartbeat();
});

function bestEffortHeartbeat() {
  if (appShell.hidden || !navigator.sendBeacon) return;
  const body = new Blob(["{}"], { type: "application/json" });
  navigator.sendBeacon("/api/access/heartbeat", body);
}

window.addEventListener("pagehide", bestEffortHeartbeat);
window.addEventListener("beforeunload", bestEffortHeartbeat);

async function checkInitialSession() {
  const result = await postJson("/api/access/heartbeat");
  if (result.ok) {
    heartbeatSeconds = Number(result.data.heartbeatSeconds || 60);
    showApp();
  } else {
    showGate("accessLanding");
  }
}

async function loadPlans() {
  const response = await fetch("/api/access/plans", { credentials: "same-origin" });
  if (!response.ok) throw new Error("Could not load plans");
  const data = await response.json();
  plans = data.plans || [];
  devnetPaymentFaucet = data.devnetPaymentFaucet === true;
  planList.innerHTML = "";
  for (const plan of plans) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "plan-option";
    button.innerHTML = `<span>${plan.label}</span><strong>$${plan.usdPrice}</strong>`;
    button.addEventListener("click", () => createPayment(plan.id));
    planList.appendChild(button);
  }
}

async function createPayment(planId) {
  stopPaymentTimers();
  paymentStatus.textContent = "Creating payment order...";
  showScreen("paymentScreen");
  const result = await postJson("/api/access/payment/create", { plan: planId });
  if (!result.ok) {
    paymentStatus.textContent = result.data.detail || "Could not create payment order.";
    return;
  }
  currentOrder = result.data;
  devnetPaymentFaucet = result.data.devnetPaymentFaucet === true;
  const plan = plans.find(item => item.id === planId);
  paymentPlan.textContent = plan ? `${plan.label} / $${currentOrder.usdPrice}` : planId;
  paymentAmount.textContent = currentOrder.solAmount;
  depositAddress.textContent = currentOrder.depositAddress;
  renderQr(currentOrder.depositAddress, qrCode);
  paymentStatus.textContent = "Waiting for payment...";
  devnetFundBtn.hidden = !devnetPaymentFaucet;
  devnetFundBtn.disabled = false;
  startCountdown();
  statusTimer = window.setInterval(checkPaymentStatus, 7000);
  checkPaymentStatus();
}

async function fundDevnetPayment() {
  if (!currentOrder || !devnetPaymentFaucet) return;
  devnetFundBtn.disabled = true;
  paymentStatus.textContent = "Sending devnet SOL...";
  const result = await postJson("/api/access/payment/devnet-fund", {
    orderId: currentOrder.orderId,
    orderSecret: currentOrder.orderSecret,
  });
  if (!result.ok) {
    paymentStatus.textContent = result.data.detail || "Could not send devnet SOL.";
    devnetFundBtn.disabled = false;
    return;
  }
  paymentStatus.textContent = "Devnet SOL sent. Waiting for confirmation...";
  await checkPaymentStatus();
}

function startCountdown() {
  window.clearInterval(countdownTimer);
  const expiresAt = new Date(currentOrder.expiresAt).getTime();
  const tick = () => {
    const remaining = Math.max(0, expiresAt - Date.now());
    const totalSeconds = Math.floor(remaining / 1000);
    const minutes = String(Math.floor(totalSeconds / 60)).padStart(2, "0");
    const seconds = String(totalSeconds % 60).padStart(2, "0");
    paymentCountdown.textContent = remaining > 0 ? `Expires in ${minutes}:${seconds}` : "Expired";
    if (remaining <= 0) {
      window.clearInterval(countdownTimer);
    }
  };
  tick();
  countdownTimer = window.setInterval(tick, 1000);
}

async function checkPaymentStatus() {
  if (!currentOrder) return;
  const result = await postJson("/api/access/payment/status", {
    orderId: currentOrder.orderId,
    orderSecret: currentOrder.orderSecret,
  });
  if (!result.ok) {
    paymentStatus.textContent = result.data.detail || "Payment status unavailable.";
    return;
  }
  if (result.data.status === "pending") {
    paymentStatus.textContent = "Waiting for payment...";
    return;
  }
  if (result.data.status === "expired") {
    stopPaymentTimers();
    paymentStatus.textContent = "Payment expired.";
    return;
  }
  if (result.data.keysAlreadyClaimed) {
    stopPaymentTimers();
    showGate("signinScreen", "Keys were already claimed. Sign in with your saved user key.");
    return;
  }
  if (result.data.status === "confirmed" && result.data.userKey && result.data.restoreKey) {
    stopPaymentTimers();
    claimedKeys = {
      userKey: result.data.userKey,
      restoreKey: result.data.restoreKey,
      paidUntil: result.data.paidUntil,
      signedIn: result.data.signedIn === true,
    };
    showKeys(claimedKeys);
    showScreen("successScreen");
  }
}

function maskKey(value) {
  return "•".repeat(Math.min(32, value.length));
}

function setKeyField(field, value, revealed) {
  field.dataset.value = value;
  field.textContent = revealed ? value : maskKey(value);
  field.classList.toggle("is-hidden", !revealed);
}

function showKeys(keys) {
  setKeyField($("userKeyField"), keys.userKey, false);
  setKeyField($("restoreKeyField"), keys.restoreKey, false);
  $("backupUserKey").textContent = keys.userKey;
  $("backupRestoreKey").textContent = keys.restoreKey;
  if (navigator.share) shareKeysBtn.hidden = false;
  const isIos = /iphone|ipad|ipod/i.test(navigator.userAgent);
  const standalone = window.matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
  downloadBackupBtn.hidden = isIos || standalone;
  updateContinueState();
}

function toggleField(fieldId, buttonId) {
  const field = $(fieldId);
  const button = $(buttonId);
  const next = field.classList.contains("is-hidden");
  setKeyField(field, field.dataset.value || "", next);
  button.textContent = next ? "Hide" : "Reveal";
}

function keysText() {
  if (!claimedKeys) return "";
  return `NullTrace access keys\n\nUser key:\n${claimedKeys.userKey}\n\nRestore key:\n${claimedKeys.restoreKey}\n\nStore these offline. Anyone with these keys can access or reset your NullTrace access.`;
}

function updateContinueState() {
  $("continueToAppBtn").disabled = !(
    $("savedUserKeyCheck").checked &&
    $("savedRestoreKeyCheck").checked &&
    $("understandKeysCheck").checked
  );
}

async function signIn() {
  signinStatus.textContent = "";
  const userKey = signinUserKey.value.trim();
  const restoreKey = signinRestoreKey.value.trim();
  if (!userKey) {
    signinStatus.textContent = "Paste your user key.";
    return;
  }
  if (restoreKey) {
    const restored = await postJson("/api/access/restore", {
      userKey,
      restoreKey,
    });
    if (restored.ok) {
      const entered = await enterAppAfterAuth();
      if (entered) {
        signinRestoreKey.value = "";
        signinUserKey.value = "";
      }
      return;
    }
    signinStatus.textContent = restored.data.detail || "Could not restore access.";
    return;
  }
  const result = await postJson("/api/access/signin", { userKey });
  if (result.ok) {
    const entered = await enterAppAfterAuth();
    if (entered) {
      signinUserKey.value = "";
      signinRestoreKey.value = "";
    }
    return;
  }
  if (result.status === 409 || result.data.restoreRequired) {
    restorePanel.hidden = false;
    signinStatus.textContent = result.data.message || "Enter your restore key to move access here.";
    signinRestoreKey.focus();
    return;
  }
  signinStatus.textContent = result.data.detail || "Invalid or expired access.";
}

async function continueWithClaimedKey() {
  if (!claimedKeys) return;
  if (claimedKeys.signedIn) {
    await enterAppAfterAuth();
    return;
  }
  const result = await postJson("/api/access/signin", { userKey: claimedKeys.userKey });
  if (result.ok) {
    await enterAppAfterAuth();
    return;
  }
  accessNotice.textContent = "Keys were saved, but sign in failed. Paste your user key to continue.";
  signinUserKey.value = claimedKeys.userKey;
  showScreen("signinScreen");
}

function downloadBackupFile() {
  const blob = new Blob([keysText()], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "nulltrace-access-keys.txt";
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function bindAccessEvents() {
  $("payAccessBtn").addEventListener("click", async () => {
    showScreen("planScreen");
    if (!plans.length) {
      try {
        await loadPlans();
      } catch {
        accessNotice.textContent = "Could not load access plans.";
      }
    }
  });
  $("showSigninBtn").addEventListener("click", () => {
    restorePanel.hidden = true;
    signinStatus.textContent = "";
    showScreen("signinScreen");
  });
  document.querySelectorAll("[data-access-back]").forEach(button => {
    button.addEventListener("click", () => {
      if (button.dataset.accessBack === "plans") showScreen("planScreen");
      else showScreen("accessLanding");
    });
  });
  $("copyAmountBtn").addEventListener("click", event => copyText(currentOrder?.solAmount || "", event.currentTarget));
  $("copyAddressBtn").addEventListener("click", event => copyText(currentOrder?.depositAddress || "", event.currentTarget));
  devnetFundBtn.addEventListener("click", fundDevnetPayment);
  $("copyUserKeyBtn").addEventListener("click", event => copyText(claimedKeys?.userKey || "", event.currentTarget));
  $("copyRestoreKeyBtn").addEventListener("click", event => copyText(claimedKeys?.restoreKey || "", event.currentTarget));
  $("copyBothKeysBtn").addEventListener("click", event => copyText(keysText(), event.currentTarget));
  $("toggleUserKeyBtn").addEventListener("click", () => toggleField("userKeyField", "toggleUserKeyBtn"));
  $("toggleRestoreKeyBtn").addEventListener("click", () => toggleField("restoreKeyField", "toggleRestoreKeyBtn"));
  $("showBackupCardBtn").addEventListener("click", () => {
    $("backupCard").hidden = false;
  });
  $("closeBackupCardBtn").addEventListener("click", () => {
    $("backupCard").hidden = true;
  });
  shareKeysBtn.addEventListener("click", async () => {
    if (!navigator.share) return;
    if (!window.confirm("Only share this to a secure place you control.")) return;
    await navigator.share({ title: "NullTrace access keys", text: keysText() }).catch(() => {});
  });
  downloadBackupBtn.addEventListener("click", downloadBackupFile);
  ["savedUserKeyCheck", "savedRestoreKeyCheck", "understandKeysCheck"].forEach(id => {
    $(id).addEventListener("change", updateContinueState);
  });
  $("continueToAppBtn").addEventListener("click", continueWithClaimedKey);
  $("signinBtn").addEventListener("click", signIn);
  [signinUserKey, signinRestoreKey].forEach(field => {
    field.addEventListener("keydown", event => {
      if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
        event.preventDefault();
        signIn();
      }
    });
  });
  $("accessLogoutBtn").addEventListener("click", async () => {
    await postJson("/api/access/logout");
    showGate("accessLanding", "Signed out.");
  });
}

function gfMultiply(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

function gfPow(x, power) {
  let result = 1;
  for (let i = 0; i < power; i++) result = gfMultiply(result, x);
  return result;
}

function rsGenerator(degree) {
  let result = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(result.length + 1).fill(0);
    for (let j = 0; j < result.length; j++) {
      next[j] ^= result[j];
      next[j + 1] ^= gfMultiply(result[j], gfPow(2, i));
    }
    result = next;
  }
  return result;
}

function rsRemainder(data, degree) {
  const generator = rsGenerator(degree);
  const result = new Array(degree).fill(0);
  for (const byte of data) {
    const factor = byte ^ result.shift();
    result.push(0);
    for (let i = 0; i < degree; i++) {
      result[i] ^= gfMultiply(generator[i + 1], factor);
    }
  }
  return result;
}

function appendBits(bits, value, length) {
  for (let i = length - 1; i >= 0; i--) bits.push(((value >>> i) & 1) !== 0);
}

function dataCodewords(text) {
  const bytes = new TextEncoder().encode(text);
  const capacity = 55;
  if (bytes.length > 53) throw new Error("QR payload too long");
  const bits = [];
  appendBits(bits, 0x4, 4);
  appendBits(bits, bytes.length, 8);
  for (const byte of bytes) appendBits(bits, byte, 8);
  const capacityBits = capacity * 8;
  appendBits(bits, 0, Math.min(4, capacityBits - bits.length));
  while (bits.length % 8) bits.push(false);
  const words = [];
  for (let i = 0; i < bits.length; i += 8) {
    let value = 0;
    for (let j = 0; j < 8; j++) value = (value << 1) | (bits[i + j] ? 1 : 0);
    words.push(value);
  }
  for (let pad = 0xec; words.length < capacity; pad ^= 0xfd) words.push(pad);
  return words;
}

function formatBits(mask) {
  const data = (1 << 3) | mask;
  let bits = data << 10;
  for (let i = 14; i >= 10; i--) {
    if (((bits >>> i) & 1) !== 0) bits ^= 0x537 << (i - 10);
  }
  return ((data << 10) | bits) ^ 0x5412;
}

function qrMatrixV3(text) {
  const size = 29;
  const modules = Array.from({ length: size }, () => Array(size).fill(false));
  const reserved = Array.from({ length: size }, () => Array(size).fill(false));
  const set = (x, y, dark, reserve = true) => {
    if (x < 0 || y < 0 || x >= size || y >= size) return;
    modules[y][x] = !!dark;
    if (reserve) reserved[y][x] = true;
  };
  const finder = (x, y) => {
    for (let dy = -1; dy <= 7; dy++) {
      for (let dx = -1; dx <= 7; dx++) {
        const xx = x + dx;
        const yy = y + dy;
        const dark = dx >= 0 && dx <= 6 && dy >= 0 && dy <= 6 &&
          (dx === 0 || dx === 6 || dy === 0 || dy === 6 || (dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4));
        set(xx, yy, dark);
      }
    }
  };
  finder(0, 0);
  finder(size - 7, 0);
  finder(0, size - 7);
  for (let i = 0; i < size; i++) {
    if (!reserved[6][i]) set(i, 6, i % 2 === 0);
    if (!reserved[i][6]) set(6, i, i % 2 === 0);
  }
  for (let dy = -2; dy <= 2; dy++) {
    for (let dx = -2; dx <= 2; dx++) {
      set(22 + dx, 22 + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  }
  for (let i = 0; i <= 8; i++) {
    if (i !== 6) {
      set(8, i, false);
      set(i, 8, false);
    }
  }
  for (let i = 0; i < 8; i++) {
    set(size - 1 - i, 8, false);
    set(8, size - 1 - i, false);
  }
  set(8, size - 8, true);

  const data = dataCodewords(text);
  const allWords = data.concat(rsRemainder(data, 15));
  const bits = [];
  for (const word of allWords) appendBits(bits, word, 8);
  let bitIndex = 0;
  let upward = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right--;
    for (let vert = 0; vert < size; vert++) {
      const y = upward ? size - 1 - vert : vert;
      for (let dx = 0; dx < 2; dx++) {
        const x = right - dx;
        if (reserved[y][x]) continue;
        const bit = bitIndex < bits.length ? bits[bitIndex++] : false;
        const mask = (x + y) % 2 === 0;
        set(x, y, bit !== mask, false);
      }
    }
    upward = !upward;
  }
  const fmt = formatBits(0);
  const getBit = i => ((fmt >>> i) & 1) !== 0;
  for (let i = 0; i <= 5; i++) set(8, i, getBit(i));
  set(8, 7, getBit(6));
  set(8, 8, getBit(7));
  set(7, 8, getBit(8));
  for (let i = 9; i < 15; i++) set(14 - i, 8, getBit(i));
  for (let i = 0; i < 8; i++) set(size - 1 - i, 8, getBit(i));
  for (let i = 8; i < 15; i++) set(8, size - 15 + i, getBit(i));
  set(8, size - 8, true);
  return modules;
}

function renderQr(text, container) {
  try {
    const matrix = qrMatrixV3(text);
    const quiet = 4;
    const size = matrix.length + quiet * 2;
    const rects = [];
    matrix.forEach((row, y) => {
      row.forEach((dark, x) => {
        if (dark) rects.push(`<rect x="${x + quiet}" y="${y + quiet}" width="1" height="1"/>`);
      });
    });
    container.innerHTML = `<svg viewBox="0 0 ${size} ${size}" role="img" aria-label="Deposit address QR"><rect width="${size}" height="${size}" fill="#fff"/>` +
      `<g fill="#05070a">${rects.join("")}</g></svg>`;
  } catch {
    container.textContent = "QR unavailable";
  }
}

bindAccessEvents();
checkInitialSession();
