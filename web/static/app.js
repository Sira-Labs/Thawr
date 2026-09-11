// Thawr admin UI: plain JS against /api/v1. No build step by design.
(() => {
  "use strict";
  const $ = (sel) => document.querySelector(sel);
  let csrf = "";
  let me = null;

  async function api(method, path, body) {
    const headers = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (method !== "GET") headers["X-CSRF-Token"] = csrf;
    const resp = await fetch(path, {
      method, headers, credentials: "same-origin", body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (resp.status === 204) return null;
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.error || resp.statusText);
    return data;
  }

  function show(id, visible) { $(id).hidden = !visible; }

  function cell(text) { const td = document.createElement("td"); td.textContent = text ?? ""; return td; }

  function actionCell(label, onClick) {
    const td = document.createElement("td");
    const b = document.createElement("button");
    b.className = "link"; b.textContent = label; b.addEventListener("click", onClick);
    td.appendChild(b);
    return td;
  }

  // detailRow renders what the server knows about a peer under its row:
  // reported paths, candidate addresses and the compiled filter.
  function detailRow(detail) {
    const tr = document.createElement("tr");
    tr.className = "detail";
    const td = document.createElement("td");
    td.colSpan = 8;
    const section = (title, items) => {
      const h = document.createElement("div");
      h.className = "muted";
      h.textContent = title;
      td.append(h);
      if (items.length === 0) {
        const p = document.createElement("div");
        p.textContent = "none";
        td.append(p);
        return;
      }
      const ul = document.createElement("ul");
      for (const text of items) {
        const li = document.createElement("li");
        li.textContent = text;
        ul.append(li);
      }
      td.append(ul);
    };
    const meta = [`version ${detail.version || "-"}`, `os ${detail.os || "-"}`];
    if (detail.last_seen_at) meta.push(`last seen ${detail.last_seen_at}`);
    section("Client", meta);
    section("Paths reported", (detail.paths || []).map((p) => `${p.peer}: ${p.state}${p.endpoint ? " via " + p.endpoint : ""} (${p.updated_at})`));
    section(`Candidates${detail.symmetric ? " (symmetric NAT)" : ""}`, (detail.endpoints || []).map((e) => `${e.addr} (${e.kind})`));
    section("Filter", (detail.filter || []).map((f) => `${f.src} ${f.proto} ${f.port_lo === f.port_hi ? f.port_lo : f.port_lo + "-" + f.port_hi}`));
    tr.append(td);
    return tr;
  }

  // loadLock renders the network-lock line above the peers table; the
  // server only reports it, signing happens on client devices.
  async function loadLock() {
    const el = $("#lock");
    try {
      const lock = await api("GET", "/api/v1/lock");
      if (!lock.enabled) { el.textContent = "Network lock: off. Enable it from a device with `thawr client lock init`."; return; }
      const signers = lock.signers.map((s) => `${s.peer} (${s.fingerprint})`).join(", ");
      const unsigned = lock.unsigned.length ? ` Unsigned: ${lock.unsigned.join(", ")}.` : " Every peer is signed.";
      el.textContent = `Network lock: on (generation ${lock.generation}). Signers: ${signers}.${unsigned}`;
    } catch (e) { el.textContent = ""; }
  }

  function signedCell(p) {
    if (p.signed === undefined) return cell("-");
    return cell(p.signed ? "yes" : "no");
  }

  async function loadPeers() {
    const peers = await api("GET", "/api/v1/peers");
    await loadLock();
    const tbody = $("#peers tbody");
    tbody.replaceChildren();
    for (const p of peers) {
      const tr = document.createElement("tr");
      tr.append(cell(p.name), cell(p.ipv4), cell(p.kind), cell(p.owner || "-"), cell(p.tags.join(", ") || "-"), cell(p.created_at), signedCell(p));
      tr.append(actionCell("Show", async () => {
        const next = tr.nextElementSibling;
        if (next && next.classList.contains("detail")) { next.remove(); return; }
        try {
          const detail = await api("GET", `/api/v1/peers/${encodeURIComponent(p.name)}`);
          tr.after(detailRow(detail));
        } catch (e) { alert(e.message); }
      }));
      if (me.role === "admin") {
        const td = document.createElement("td");
        const rename = document.createElement("button");
        rename.className = "link"; rename.textContent = "Rename";
        rename.addEventListener("click", async () => {
          const name = prompt(`New name for ${p.name}`, p.name);
          if (!name || name === p.name) return;
          try { await api("PATCH", `/api/v1/peers/${encodeURIComponent(p.name)}`, { name }); await loadPeers(); }
          catch (e) { alert(e.message); }
        });
        const del = document.createElement("button");
        del.className = "link"; del.textContent = "Delete";
        del.addEventListener("click", async () => {
          if (!confirm(`Delete peer ${p.name}? Every client drops it within seconds.`)) return;
          try { await api("DELETE", `/api/v1/peers/${encodeURIComponent(p.name)}`); await loadPeers(); }
          catch (e) { alert(e.message); }
        });
        td.append(rename, del);
        tr.append(td);
      } else {
        tr.append(cell(""));
      }
      tbody.append(tr);
    }
  }

  async function loadTokens() {
    const tokens = await api("GET", "/api/v1/tokens");
    const tbody = $("#tokens tbody");
    tbody.replaceChildren();
    for (const t of tokens) {
      const tr = document.createElement("tr");
      tr.append(cell(t.id), cell(t.owner), cell(t.kind), cell(t.tags.join(", ") || "-"), cell(t.expires_at), cell(t.used_at ? "used" : "unused"));
      tr.append(actionCell("Revoke", async () => {
        try { await api("DELETE", `/api/v1/tokens/${encodeURIComponent(t.id)}`); await loadTokens(); }
        catch (e) { alert(e.message); }
      }));
      tbody.append(tr);
    }
  }

  async function loadUsers() {
    if (me.role !== "admin") { show("#users-section", false); return; }
    show("#users-section", true);
    const users = await api("GET", "/api/v1/users");
    const tbody = $("#users tbody");
    tbody.replaceChildren();
    for (const u of users) {
      const tr = document.createElement("tr");
      tr.append(cell(u.name), cell(u.role), cell(u.created_at));
      tbody.append(tr);
    }
  }

  // The audit log pages backwards from the newest entry with before_id.
  const auditPage = 100;
  let auditOldest = 0;

  function auditRow(e) {
    const tr = document.createElement("tr");
    const details = Object.keys(e.details || {}).filter((k) => e.details[k] !== "").sort().map((k) => `${k}=${e.details[k]}`).join(" ");
    tr.append(cell(e.at), cell(e.actor), cell(e.action), cell(e.target || "-"), cell(details || "-"));
    return tr;
  }

  async function loadAudit(older) {
    if (me.role !== "admin") { show("#audit-section", false); return; }
    show("#audit-section", true);
    const params = new URLSearchParams({ limit: String(auditPage) });
    if (older && auditOldest > 0) params.set("before_id", String(auditOldest));
    const entries = await api("GET", `/api/v1/audit?${params}`);
    const tbody = $("#audit tbody");
    if (!older) { tbody.replaceChildren(); auditOldest = 0; }
    for (const e of entries) {
      tbody.append(auditRow(e));
      auditOldest = auditOldest === 0 ? e.id : Math.min(auditOldest, e.id);
    }
    const end = entries.length < auditPage;
    show("#audit-end", end);
    $("#audit-older").hidden = end;
  }

  $("#audit-older").addEventListener("click", async () => {
    try { await loadAudit(true); } catch (e) { alert(e.message); }
  });

  function listItems(ul, items, prefix) {
    ul.replaceChildren();
    for (const text of items || []) {
      const li = document.createElement("li");
      li.textContent = (prefix ? prefix + ": " : "") + text;
      ul.append(li);
    }
  }

  // The policy page is read-only: the file stays the source of truth.
  async function loadPolicy() {
    if (me.role !== "admin") { show("#policy-section", false); return; }
    show("#policy-section", true);
    const p = await api("GET", "/api/v1/policy");
    const s = p.summary || {};
    $("#policy-summary").textContent = `hash ${p.hash || "none (empty default-deny policy)"}: ${s.rules || 0} rules, ${s.peers || 0} peers, ${s.visible_pairs || 0} visible pairs`;
    listItems($("#policy-warnings"), p.warnings, "warning");
    $("#policy-source").textContent = p.source || "(no policy file)";
  }

  $("#policy-reload").addEventListener("click", async () => {
    try {
      const rep = await api("POST", "/api/v1/policy/reload");
      listItems($("#policy-check-result"), rep.warnings, "warning");
      await loadPolicy();
    } catch (e) { alert(e.message); }
  });

  $("#policy-check").addEventListener("click", async () => {
    try {
      const rep = await api("POST", "/api/v1/policy/check", { yaml: $("#policy-input").value });
      const lines = [];
      for (const w of rep.warnings || []) lines.push("warning: " + w);
      for (const err of rep.errors || []) lines.push("error: " + err);
      if (rep.ok) lines.push(`ok: ${rep.summary.rules} rules, ${rep.summary.peers} peers, ${rep.summary.visible_pairs} visible pairs`);
      listItems($("#policy-check-result"), lines);
    } catch (e) { alert(e.message); }
  });

  async function refresh() {
    await Promise.all([loadPeers(), loadTokens(), loadUsers(), loadPolicy(), loadAudit(false)]);
  }

  async function enter(session) {
    me = session; csrf = session.csrf || "";
    $("#who").textContent = `${me.name} (${me.role})`;
    show("#login", false); show("#app", true); show("#logout", true);
    $("#token-form").owner.value = $("#token-form").owner.value || me.name;
    await refresh();
  }

  function leave() {
    me = null; csrf = "";
    $("#who").textContent = "";
    show("#app", false); show("#logout", false); show("#login", true);
  }

  $("#login-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = ev.target;
    $("#login-error").textContent = "";
    try {
      const session = await api("POST", "/api/v1/login", { name: f.name.value, password: f.password.value });
      f.password.value = "";
      await enter(session);
    } catch (e) { $("#login-error").textContent = e.message; }
  });

  $("#logout").addEventListener("click", async () => { try { await api("POST", "/api/v1/logout"); } finally { leave(); } });
  $("#refresh").addEventListener("click", () => refresh().catch((e) => alert(e.message)));

  $("#token-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = ev.target;
    $("#token-error").textContent = "";
    const tags = f.tags.value.split(",").map((s) => s.trim()).filter(Boolean);
    try {
      const t = await api("POST", "/api/v1/tokens", {
        owner: f.owner.value, kind: f.kind.value, tags, peer_name: f.peer_name.value, expires: f.expires.value,
      });
      $("#join-command").textContent = t.join_command;
      show("#token-result", true);
      await loadTokens();
    } catch (e) { $("#token-error").textContent = e.message; }
  });
  $("#copy").addEventListener("click", () => navigator.clipboard?.writeText($("#join-command").textContent));
  $("#dismiss").addEventListener("click", () => { $("#join-command").textContent = ""; show("#token-result", false); });

  // The mobile config is shown once: the dialog holds it only while
  // open, and closing clears every trace of it.
  const mobileDialog = $("#mobile-dialog");
  function discardMobile() {
    $("#mobile-config").textContent = "";
    $("#mobile-qr").replaceChildren();
    $("#mobile-warning").textContent = "";
    if (mobileDialog.open) mobileDialog.close();
  }
  $("#mobile-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = ev.target;
    $("#mobile-error").textContent = "";
    const tags = f.tags.value.split(",").map((s) => s.trim()).filter(Boolean);
    try {
      const m = await api("POST", "/api/v1/peers/mobile", { owner: f.owner.value, name: f.name.value, kind: f.kind.value, tags });
      $("#mobile-warning").textContent = m.warning;
      $("#mobile-config").textContent = m.config;
      const svg = new DOMParser().parseFromString(m.qr_svg, "image/svg+xml").documentElement;
      if (svg && svg.nodeName === "svg") $("#mobile-qr").replaceChildren(document.adoptNode(svg));
      mobileDialog.showModal();
      f.reset();
      await loadPeers();
    } catch (e) { $("#mobile-error").textContent = e.message; }
  });
  $("#mobile-copy").addEventListener("click", () => navigator.clipboard?.writeText($("#mobile-config").textContent));
  $("#mobile-close").addEventListener("click", discardMobile);
  mobileDialog.addEventListener("close", discardMobile);
  mobileDialog.addEventListener("cancel", discardMobile);

  $("#user-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = ev.target;
    $("#user-error").textContent = "";
    try {
      await api("POST", "/api/v1/users", { name: f.name.value, role: f.role.value, password: f.password.value });
      f.reset();
      await loadUsers();
    } catch (e) { $("#user-error").textContent = e.message; }
  });

  // Resume an existing session, else show the login form.
  api("GET", "/api/v1/me").then(enter).catch(leave);
})();
