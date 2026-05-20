(function () {
  const app = document.getElementById("adminApp");
  const apiBase = app.dataset.apiBase;
  const login = document.getElementById("adminLogin");
  const dashboard = document.getElementById("adminDashboard");
  const loginStatus = document.getElementById("adminLoginStatus");
  const password = document.getElementById("adminPassword");
  const generatedKeys = document.getElementById("generatedKeys");

  const fmt = new Intl.NumberFormat("en-US");

  async function request(path, options = {}) {
    const response = await fetch(`${apiBase}${path}`, {
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
      ...options,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || "Request failed");
    return data;
  }

  function text(value) {
    return value === null || value === undefined || value === "" ? "—" : String(value);
  }

  function escapeHtml(value) {
    return text(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function metric(label, value, detail = "") {
    return `<article class="admin-card metric-card"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong><em>${escapeHtml(detail)}</em></article>`;
  }

  function renderCards(data) {
    const totals = data.totals || {};
    const metrics = data.metrics || {};
    const today = data.today || {};
    document.getElementById("overviewCards").innerHTML = [
      metric("Total signups", fmt.format(Number(totals.accounts || 0)), `${fmt.format(Number(totals.admin_free_accounts || 0))} admin generated`),
      metric("Active sessions", fmt.format(Number(totals.active_sessions || 0)), "currently alive"),
      metric("Page views", fmt.format(Number(metrics.page_views || 0)), `${fmt.format(Number(metrics.unique_visitors || 0))} daily uniques total`),
      metric("Messages relayed", fmt.format(Number(metrics.chat_messages || 0)), `${fmt.format(Number(today.chat_messages || 0))} today`),
      metric("Room tokens", fmt.format(Number(metrics.room_tokens || 0)), `${fmt.format(Number(today.room_tokens || 0))} today`),
      metric("WS connections", fmt.format(Number(metrics.ws_connections || 0)), `${fmt.format(Number(today.ws_connections || 0))} today`),
      metric("Paid orders", fmt.format(Number(totals.paid_orders || 0)), `${fmt.format(Number(totals.payment_orders || 0))} total orders`),
      metric("Confirmed SOL", text(totals.confirmed_lamports), "lamports confirmed"),
    ].join("");
  }

  function table(headers, rows) {
    const head = headers.map(item => `<th>${escapeHtml(item)}</th>`).join("");
    const body = rows.map(row => `<tr>${row.map(cell => `<td>${escapeHtml(cell)}</td>`).join("")}</tr>`).join("");
    return `<table><thead><tr>${head}</tr></thead><tbody>${body || `<tr><td colspan="${headers.length}">No data</td></tr>`}</tbody></table>`;
  }

  function renderActivity(data) {
    const rows = (data.recentDays || []).map(day => [
      day.day,
      fmt.format(Number(day.page_views || 0)),
      fmt.format(Number(day.unique_visitors || 0)),
      fmt.format(Number(day.room_tokens || 0)),
      fmt.format(Number(day.ws_connections || 0)),
      fmt.format(Number(day.chat_messages || 0)),
      fmt.format(Number(day.control_messages || 0)),
    ]);
    document.getElementById("activityTable").innerHTML = table(
      ["Day", "Views", "Uniques", "Room tokens", "WS", "Messages", "Control"],
      rows
    );
  }

  function renderGenerated(data) {
    const rows = (data.generatedAccess || []).map(account => {
      let label = "";
      try { label = JSON.parse(account.metadata_json || "{}").label || ""; } catch {}
      return [
        `#${account.id}`,
        label,
        account.paid_until,
        account.created_at,
        fmt.format(Number(account.session_count || 0)),
        account.last_used_at || "Never",
      ];
    });
    document.getElementById("generatedTable").innerHTML = table(
      ["Account", "Label", "Paid until", "Created", "Sessions", "Last used"],
      rows
    );
  }

  function renderWallet(data) {
    const wallet = data.coldWallet || {};
    document.getElementById("walletPanel").innerHTML = `
      <h2>Cold Wallet</h2>
      <div class="admin-table">${table(["Field", "Value"], [
        ["Configured", wallet.configured ? "Yes" : "No"],
        ["Network", wallet.network || "—"],
        ["Address", wallet.address || "—"],
        ["Balance", wallet.error ? wallet.error : `${wallet.sol || "0"} SOL`],
        ["Lamports", wallet.lamports === undefined ? "—" : fmt.format(Number(wallet.lamports || 0))],
      ])}</div>
    `;
  }

  async function loadDashboard() {
    const data = await request("/dashboard");
    login.hidden = true;
    dashboard.hidden = false;
    document.getElementById("adminUpdatedAt").textContent = `Updated ${new Date().toLocaleString()}`;
    renderCards(data);
    renderActivity(data);
    renderGenerated(data);
    renderWallet(data);
  }

  async function signIn() {
    loginStatus.textContent = "";
    try {
      await request("/login", { method: "POST", body: JSON.stringify({ password: password.value }) });
      password.value = "";
      await loadDashboard();
    } catch (error) {
      loginStatus.textContent = error.message;
    }
  }

  async function logout() {
    await request("/logout", { method: "POST", body: "{}" }).catch(() => {});
    dashboard.hidden = true;
    login.hidden = false;
  }

  async function generateAccess() {
    generatedKeys.hidden = true;
    const label = document.getElementById("grantLabel").value;
    const days = Number(document.getElementById("grantDays").value || 3650);
    const data = await request("/generate-access", {
      method: "POST",
      body: JSON.stringify({ label, days }),
    });
    generatedKeys.innerHTML = `
      <strong>Account #${escapeHtml(data.accountId)}</strong>
      <span>User key</span>
      <code>${escapeHtml(data.userKey)}</code>
      <span>Restore key</span>
      <code>${escapeHtml(data.restoreKey)}</code>
      <span>Paid until</span>
      <code>${escapeHtml(data.paidUntil)}</code>
    `;
    generatedKeys.hidden = false;
    await loadDashboard();
  }

  document.getElementById("adminLoginBtn").addEventListener("click", signIn);
  password.addEventListener("keydown", event => {
    if (event.key === "Enter") signIn();
  });
  document.getElementById("adminLogoutBtn").addEventListener("click", logout);
  document.getElementById("generateAccessBtn").addEventListener("click", () => {
    generateAccess().catch(error => {
      generatedKeys.textContent = error.message;
      generatedKeys.hidden = false;
    });
  });
  document.querySelectorAll(".admin-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".admin-tab").forEach(item => item.classList.toggle("is-active", item === tab));
      document.querySelectorAll(".admin-panel").forEach(panel => {
        panel.classList.toggle("is-active", panel.dataset.panel === tab.dataset.tab);
      });
    });
  });

  loadDashboard().catch(() => {
    dashboard.hidden = true;
    login.hidden = false;
  });
})();
