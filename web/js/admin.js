/* Zoltis Mail – admin console (Community Edition). Uses helpers exported by app.js. */
(() => {
"use strict";
const Z = window.ZoltisMail;
const { api, snack, modal, popover, esc, h, avatar, qs, fmtDate } = Z;
const icon = Z.icon;
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const mb = (v) => (v >= 1024 ? (v / 1024).toFixed(2) + " GB" : v > 0 && v < 10 ? Math.max(0.1, v).toFixed(1) + " MB" : Math.round(v) + " MB");
const ago = (ts) => { if (!ts) return "Never"; const s = Date.now() / 1000 - ts; return s < 90 ? "Just now" : s < 3600 ? `${Math.round(s / 60)} min ago` : s < 86400 ? `${Math.round(s / 3600)} h ago` : fmtDate(new Date(ts * 1000).toISOString()); };
const meter = (pct) => `<div class="meter ${pct >= 95 ? "full" : pct >= 80 ? "warn" : ""}"><span style="width:${Math.max(1, Math.min(100, pct))}%"></span></div>`;
const copyBtn = (text) => `<button class="icon-btn sm copy" data-copy="${esc(text)}" title="Copy">${icon("copy")}</button>`;
const genPassword = () => { const c = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#%*-_"; const a = new Uint32Array(14); crypto.getRandomValues(a); return Array.from(a, (x) => c[x % c.length]).join(""); };

const TABS = [
  ["overview", "Overview"], ["guide", "Setup guide"], ["accounts", "Accounts"], ["domains", "Domains & DNS"], ["aliases", "Aliases"],
  ["import", "Import mail"], ["sessions", "Sessions"], ["activity", "Activity"], ["security", "Security"], ["migrate", "Export & move"], ["license", "License"],
];
let state = { overview: null, accounts: [], domains: [], limits: {}, mode: "bundled", importTimer: null };

function render(root, ctx) {
  const tab = TABS.some(([k]) => k === ctx.sub) || ctx.sub === "upgrade" ? ctx.sub : "overview";
  const ed = ctx.S.me.edition === "enterprise" ? "Enterprise" : "Community Edition";
  root.innerHTML = "";
  const el = h(`<section class="adm">
    <div class="adm-head"><h2>${icon("shield")} Admin console <span class="badge">${esc(ed)}</span></h2>
      <span style="display:flex;gap:8px"><a class="btn outline" href="#/admin/upgrade">${icon("star")} Upgrade to Mail Pro</a>
      <a class="btn text" href="#/inbox">${icon("arrow_back")} Back to mail</a></span></div>
    <div class="tabs">${TABS.filter(([k]) => state.mode === "bundled" || !["guide", "domains", "aliases", "import", "migrate"].includes(k)).map(([k, l]) => `<a class="tab ${k === tab ? "on" : ""}" href="#/admin/${k}">${l}</a>`).join("")}</div>
    <div class="adm-body"><div class="loading-bar"></div></div></section>`);
  root.append(el);
  el.addEventListener("click", (e) => {
    const c = e.target.closest("[data-copy]");
    if (c) { navigator.clipboard?.writeText(c.dataset.copy).then(() => snack("Copied")); }
  });
  const body = $(".adm-body", el);
  clearInterval(state.importTimer); clearInterval(state.migrateTimer);
  ({ overview, guide, accounts, domains, aliases, import: importTab, sessions, activity, security, license, upgrade, migrate })[tab](body, ctx).catch((e) => {
    body.innerHTML = `<div class="empty">${icon("error")}<p>${esc(e.message)}</p></div>`;
  });
}

// ------------------------------------------------------------------ overview
async function overview(body, ctx) {
  const o = await api("/api/admin/overview");
  state.overview = o; state.mode = o.mode; state.limits = o.limits;
  const max = o.limits.max_accounts, pct = max ? (100 * o.accounts / max) : 0;
  const srv = o.server || {};
  const ok = (b) => b ? `<span class="badge ok">${icon("check")} Running</span>` : `<span class="badge off">${icon("error")} Unreachable</span>`;
  const synced = srv.synced ? Object.values(srv.synced).every((x) => x !== false) : true;
  body.innerHTML = `${licenseNote(o.license)}
    ${o.mode === "bundled" && o.accounts <= 1 ? `<div class="limit-note">${icon("help")}<span><b>Finish setting up your mail server.</b>
      The setup guide walks you through Cloudflare DNS (MX, SPF, DKIM, DMARC), reverse DNS and connecting mail apps.
      <a href="#/admin/guide">Open the setup guide</a></span></div>` : ""}
    <div class="cards">
      <div class="card"><h4>${icon("contacts")} Email accounts</h4><div class="big">${o.accounts}<small> / ${max || "∞"}</small></div>
        ${max ? meter(pct) : ""}<div class="sub">${max ? `${max - o.accounts} remaining in this edition` : "Unlimited"}</div></div>
      <div class="card"><h4>${icon("cloud")} Storage allocated</h4><div class="big">${mb(o.allocated_mb)}</div>
        <div class="sub">Up to ${o.limits.max_quota_mb ? mb(o.limits.max_quota_mb) : "custom"} per mailbox, attachments included</div></div>
      <div class="card"><h4>${icon("label")} Domains · aliases</h4><div class="big">${o.domains}<small> · ${o.aliases_counted}${o.limits.max_aliases ? ` / ${o.limits.max_aliases}` : ""} aliases</small></div>
        <div class="sub">${o.admins} administrator${o.admins === 1 ? "" : "s"}${o.disabled ? ` · ${o.disabled} disabled account${o.disabled > 1 ? "s" : ""}` : ""}</div></div>
      <div class="card"><h4>${icon("lock")} Signed in now</h4><div class="big">${o.sessions}</div><div class="sub"><a href="#/admin/sessions">View sessions</a></div></div>
    </div>
    <h3 style="font:500 16px var(--font);margin:8px 0 12px">Mail server</h3>
    <table class="tbl" style="max-width:760px">
      ${o.mode === "bundled" ? `
      <tr><td>Hostname</td><td><b>${esc(o.mail_hostname || "")}</b></td></tr>
      <tr><td>IMAP (Dovecot)</td><td>${ok(srv.imap)}</td></tr>
      <tr><td>SMTP (Postfix)</td><td>${ok(srv.smtp)}</td></tr>
      <tr><td>Configuration</td><td>${synced ? `<span class="badge ok">${icon("check")} Applied</span>` : `<span class="badge warn">${icon("warning")} Waiting for mail containers to reload</span>`}</td></tr>`
      : `<tr><td>Mode</td><td>External mail server: accounts sign in with their existing mail password</td></tr>`}
      <tr><td>Antivirus (ClamAV)</td><td>${!o.antivirus.enabled ? `<span class="badge">Disabled</span>` : ok(o.antivirus.online)}</td></tr>
      <tr><td>Attachment blocker</td><td>${o.attachment_policy.enabled ? `<span class="badge ok">${icon("shield")} Active</span>` : `<span class="badge">Disabled</span>`}</td></tr>
    </table>
    ${upgradeNote(`<b>Community Edition</b> includes up to ${max} accounts and ${o.limits.max_aliases} aliases, with ${o.limits.max_quota_mb} MB per mailbox.`)}`;
}

// ------------------------------------------------------------------ accounts
async function accounts(body, ctx) {
  const r = await api("/api/admin/accounts");
  state.accounts = r.accounts; state.limits = r.limits; state.mode = r.mode;
  if (!state.domains.length && r.mode === "bundled") state.domains = (await api("/api/admin/domains")).domains;
  const max = r.limits.max_accounts, full = max && r.accounts.length >= max;
  const lic = state.overview?.license || (await api("/api/admin/license")), unlicensed = !lic.active;
  body.innerHTML = `${licenseNote(lic)}
    ${r.mode !== "bundled" ? `<div class="limit-note">${icon("help")}<span>Accounts live on your external mail server. People are added here automatically the first time they sign in, up to ${max || "unlimited"} accounts. Disable or delete someone here to free a seat.</span></div>` : ""}
    <div class="adm-tools">
      <input class="txt" type="search" id="acc-q" placeholder="Search accounts">
      ${r.mode === "bundled" ? `<button class="btn primary" id="acc-new" ${full || unlicensed ? "disabled" : ""} title="${unlicensed ? "Activate a license key first" : full ? `Limit of ${max} accounts reached` : ""}">${icon("add")} Create account</button>` : ""}
      <span class="count"><b>${r.accounts.length}</b> of ${max || "∞"} accounts${full ? ` · <span class="st-warn">limit reached</span> · <a href="#/admin/upgrade">Upgrade to Mail Pro</a>` : ""}</span>
    </div>
    <div style="overflow-x:auto"><table class="tbl" id="acc-tbl"><thead><tr><th>Account</th><th>Storage</th><th class="hide-sm">Role</th><th>Status</th><th class="hide-sm">Last sign-in</th><th></th></tr></thead><tbody></tbody></table></div>`;
  const tb = $("#acc-tbl tbody", body);
  const draw = () => {
    const q = $("#acc-q", body).value.toLowerCase();
    tb.innerHTML = "";
    for (const a of state.accounts.filter((a) => !q || a.email.includes(q) || (a.name || "").toLowerCase().includes(q))) {
      const u = a.usage, pct = u ? u.percent : 0;
      const tr = h(`<tr><td><div class="who">${avatar({ name: a.name, email: a.email }, "md")}<div><b>${esc(a.name || a.email.split("@")[0])}</b><span>${esc(a.email)}</span></div></div></td>
        <td class="use">${state.mode === "bundled" ? (u ? `${mb(u.used_mb)} of ${mb(a.quota_mb)}${meter(pct)}` : `<span class="muted">– of ${mb(a.quota_mb)}</span>`) : `<span class="muted">Managed by mail server</span>`}</td>
        <td class="hide-sm">${a.is_admin ? `<span class="badge admin">Admin</span>` : `<span class="muted">User</span>`}</td>
        <td>${a.enabled ? `<span class="badge ok">${a.online ? '<span class="dot"></span> Online' : "Active"}</span>` : `<span class="badge off">Disabled</span>`}</td>
        <td class="hide-sm muted">${esc(ago(a.last_login))}</td>
        <td style="text-align:right"><button class="icon-btn sm" title="Actions">${icon("more_vert")}</button></td></tr>`);
      $("button", tr).onclick = (e) => accountMenu(e.currentTarget, a, ctx);
      tr.querySelector(".who").style.cursor = "pointer";
      tr.querySelector(".who").onclick = () => state.mode === "bundled" && accountForm(a, ctx);
      tb.append(tr);
    }
    if (!tb.children.length) tb.innerHTML = `<tr><td colspan="6" class="muted" style="text-align:center;padding:32px">No accounts found</td></tr>`;
  };
  $("#acc-q", body).oninput = draw;
  const nb = $("#acc-new", body); if (nb) nb.onclick = () => accountForm(null, ctx);
  draw();
}
function reloadTab(ctx) { const v = $("#module-view"); render(v, ctx); }
function accountMenu(btn, a, ctx) {
  const me = ctx.S.me.email.toLowerCase() === a.email;
  const items = [];
  if (state.mode === "bundled") {
    items.push({ label: "Edit account", icon: "edit", onClick: () => accountForm(a, ctx) });
    items.push({ label: "Reset password", icon: "lock", onClick: () => resetPassword(a, ctx) });
    items.push({ label: "Import mail from old server", icon: "download", onClick: () => { location.hash = "#/admin/import"; state.importTarget = a.email; } });
  }
  if (!me) {
    items.push({ label: a.enabled ? "Disable account" : "Enable account", icon: a.enabled ? "error" : "check", onClick: () => update(a.email, { enabled: !a.enabled }, a.enabled ? "Account disabled. The user has been signed out." : "Account enabled", ctx) });
    items.push({ label: a.is_admin ? "Remove admin rights" : "Make administrator", icon: "shield", onClick: () => update(a.email, { is_admin: !a.is_admin }, "Role updated", ctx) });
    items.push({ label: "Sign out everywhere", icon: "logout", onClick: async () => { const r = await api("/api/admin/sessions/revoke", { method: "POST", body: { email: a.email } }); snack(`${r.revoked} session(s) signed out`); } });
    items.push("-", { label: "Delete account", icon: "delete", onClick: () => deleteAccount(a, ctx) });
  }
  popover(btn, items);
}
async function update(email, changes, msg, ctx) {
  try { await api("/api/admin/accounts/update", { method: "POST", body: { email, ...changes } }); snack(msg); reloadTab(ctx); } catch (e) { snack(e.message); }
}
function accountForm(a, ctx) {
  const edit = !!a, maxQ = state.limits.max_quota_mb || 102400;
  const doms = state.domains.map((d) => d.name);
  if (!edit && !doms.length) { snack("Add a domain first"); location.hash = "#/admin/domains"; return; }
  const body = h(`<div class="form-grid">
    <label>Email address</label>
    ${edit ? `<b>${esc(a.email)}</b>` : `<div class="pw-row"><input class="txt" id="f-local" placeholder="firstname" autocomplete="off"><select class="txt" id="f-dom" style="max-width:220px">${doms.map((d) => `<option>@${esc(d)}</option>`).join("")}</select></div>`}
    <label>Full name</label><input class="txt" id="f-name" value="${esc(a ? a.name : "")}" placeholder="Jane Doe">
    ${edit ? "" : `<label>Password</label><div class="pw-row"><input class="txt" id="f-pw" type="text" autocomplete="new-password" placeholder="8+ characters"><button class="btn outline" type="button" id="f-gen">Generate</button></div>`}
    <label>Mailbox size</label><div><div class="pw-row" style="align-items:center"><input type="range" id="f-qr" min="10" max="${maxQ}" step="10" value="${a ? a.quota_mb : maxQ}" style="flex:1"><input class="txt" id="f-q" type="number" min="10" max="${maxQ}" value="${a ? a.quota_mb : maxQ}" style="width:100px"> MB</div>
      <div class="muted" style="font-size:12px;margin-top:4px">Includes all messages and attachments. Maximum ${mb(maxQ)} in this edition.</div></div>
    <label>Administrator</label><label style="display:flex;gap:8px;align-items:center"><input type="checkbox" id="f-admin" ${a && a.is_admin ? "checked" : ""} ${a && ctx.S.me.email.toLowerCase() === a.email ? "disabled" : ""}> Can use this admin console</label>
  </div>`);
  const qr = $("#f-qr", body), qn = $("#f-q", body);
  qr.oninput = () => (qn.value = qr.value); qn.oninput = () => (qr.value = qn.value);
  const gen = $("#f-gen", body); if (gen) gen.onclick = () => { $("#f-pw", body).value = genPassword(); };
  modal({ title: edit ? "Edit account" : "Create account", body, buttons: [{ label: "Cancel" }, { label: edit ? "Save" : "Create account", cls: "primary", onClick: async (m) => {
    const payload = { name: $("#f-name", m).value.trim(), quota_mb: +$("#f-q", m).value, is_admin: $("#f-admin", m).checked };
    try {
      if (edit) { await api("/api/admin/accounts/update", { method: "POST", body: { email: a.email, ...payload } }); snack("Account updated"); }
      else {
        const email = $("#f-local", m).value.trim().toLowerCase() + $("#f-dom", m).value;
        const pw = $("#f-pw", m).value;
        await api("/api/admin/accounts", { method: "POST", body: { email, password: pw, ...payload } });
        modal({ title: "Account created", body: `<p>Share these sign-in details with the user securely:</p>
          <table class="tbl"><tr><td>Email</td><td><b>${esc(email)}</b> ${copyBtn(email)}</td></tr><tr><td>Password</td><td><code>${esc(pw)}</code> ${copyBtn(pw)}</td></tr>
          <tr><td>Webmail</td><td>${esc(location.origin)}</td></tr><tr><td>IMAP / SMTP</td><td>${esc(state.overview?.mail_hostname || "your mail host")} · IMAP 993 (SSL) · SMTP 587 (STARTTLS)</td></tr></table>`,
          buttons: [{ label: "Done", cls: "primary" }] });
      }
      reloadTab(ctx);
    } catch (e) { snack(e.message); return false; }
  } }] });
}
function resetPassword(a, ctx) {
  const pw = genPassword();
  modal({ title: `Reset password for ${a.email}`, body: `<label class="muted">New password</label><div class="pw-row" style="margin-top:6px"><input class="txt" id="rp" value="${esc(pw)}"><button class="btn outline" type="button" id="rp-gen">Generate</button></div><p class="muted" style="font-size:12px">The user will be signed out of all webmail sessions.</p>`,
    buttons: [{ label: "Cancel" }, { label: "Reset password", cls: "primary", onClick: async (m) => {
      const v = $("#rp", m).value;
      try { await api("/api/admin/accounts/update", { method: "POST", body: { email: a.email, password: v } }); snack("Password reset. Share the new password securely."); } catch (e) { snack(e.message); return false; }
    } }] });
  setTimeout(() => { const g = $("#rp-gen"); if (g) g.onclick = () => ($("#rp").value = genPassword()); }, 0);
}
function deleteAccount(a, ctx) {
  modal({ title: "Delete account permanently?", body: `<p style="display:flex;gap:12px">${icon("warning", "st-fail")}<span><b>${esc(a.email)}</b> and <b>all of its email</b> will be deleted. This can't be undone.</span></p><label class="muted">Type the email address to confirm</label><input class="txt" id="del-confirm" style="margin-top:6px" autocomplete="off">`,
    buttons: [{ label: "Cancel" }, { label: "Delete account", cls: "danger", onClick: async (m) => {
      if ($("#del-confirm", m).value.trim().toLowerCase() !== a.email) { snack("The address doesn't match"); return false; }
      try { await api("/api/admin/accounts/delete", { method: "POST", body: { email: a.email, purge: true } }); snack("Account deleted"); reloadTab(ctx); } catch (e) { snack(e.message); return false; }
    } }] });
}

// ------------------------------------------------------------------ domains
async function domains(body, ctx) {
  const r = await api("/api/admin/domains");
  state.domains = r.domains;
  body.innerHTML = `<div class="adm-tools"><button class="btn primary" id="dom-new">${icon("add")} Add domain</button>
    <span class="count">Mail server hostname: <b>${esc(r.mail_hostname || "")}</b></span></div>
    <div class="limit-note">${icon("help")}<span>Publish these records at your DNS provider. They make mail reach you (MX) and keep your messages out of spam (SPF, DKIM, DMARC). Ask your server provider to set the reverse DNS (PTR) of the server's IP to <b>${esc(r.mail_hostname || "")}</b>.
      Using Cloudflare? The <a href="#/admin/guide">setup guide</a> shows each record exactly as Cloudflare asks for it. A records must be <b>DNS only</b> (grey cloud).</span></div>
    <div id="dom-list"></div>`;
  const list = $("#dom-list", body);
  if (!r.domains.length) list.innerHTML = `<div class="empty">${icon("label")}<p>No domains yet. Add the domain your email addresses will use.</p></div>`;
  for (const d of r.domains) {
    const card = h(`<div class="domain-card"><header><b>${esc(d.name)}</b><span class="muted">${d.accounts} account${d.accounts === 1 ? "" : "s"}</span>
      <button class="btn outline" data-check>${icon("shield")} Check DNS</button><button class="icon-btn sm" data-del title="Delete domain">${icon("delete")}</button></header>
      <div class="inner"><table class="tbl dns-tbl"><thead><tr><th>Type</th><th>Name / host</th><th>Value</th><th class="hide-sm">Purpose</th><th></th></tr></thead><tbody>
      ${d.dns.map((x) => `<tr><td><b>${esc(x.type)}</b></td><td>${esc(x.name)}</td><td>${esc(x.value)}</td><td class="hide-sm muted">${esc(x.purpose)}</td><td>${copyBtn(x.value)}</td></tr>`).join("")}
      </tbody></table><div data-out></div></div></div>`);
    $("[data-check]", card).onclick = () => runDnsCheck($("[data-out]", card), d.name);
    $("[data-del]", card).onclick = () => modal({ title: `Delete ${d.name}?`, body: `<p>Mail for ${esc(d.name)} will no longer be accepted. Delete its accounts first.</p>`,
      buttons: [{ label: "Cancel" }, { label: "Delete domain", cls: "danger", onClick: async () => { try { await api("/api/admin/domains/delete", { method: "POST", body: { name: d.name } }); snack("Domain deleted"); reloadTab(ctx); } catch (e) { snack(e.message); return false; } } }] });
    list.append(card);
  }
  $("#dom-new", body).onclick = () => modal({ title: "Add domain", body: `<label class="muted">Domain name</label><input class="txt" id="nd" placeholder="yourcompany.com" style="margin-top:6px"><p class="muted" style="font-size:12px">A DKIM signing key is created automatically.</p>`,
    buttons: [{ label: "Cancel" }, { label: "Add domain", cls: "primary", onClick: async (m) => { try { await api("/api/admin/domains", { method: "POST", body: { name: $("#nd", m).value } }); snack("Domain added. Publish its DNS records."); reloadTab(ctx); } catch (e) { snack(e.message); return false; } } }] });
}

async function runDnsCheck(out, domain) {
  out.innerHTML = `<div class="loading-bar"></div>`;
  try {
    const rep = await api("/api/admin/dns-check?" + qs({ domain }));
    const ic = { pass: "check", warn: "warning", fail: "error" };
    out.innerHTML = `<h4 style="margin:16px 0 4px">DNS check: <span class="${rep.score >= 85 ? "st-pass" : rep.score >= 60 ? "st-warn" : "st-fail"}">${rep.score}/100</span></h4>` +
      rep.results.map((x) => `<div class="report-row"><span class="st-${x.status}">${icon(ic[x.status])}</span><b>${esc(x.check)}</b><div>${esc(x.detail)}${x.fix ? `<div class="fix">${esc(x.fix)}</div>` : ""}</div></div>`).join("") +
      `<p class="muted" style="font-size:12px;margin-top:8px">Just added the records? DNS changes usually show up within 5–30 minutes. Check again later if something is still red.</p>`;
  } catch (e) { out.innerHTML = `<p class="st-fail">${esc(e.message)}</p>`; }
}

// ------------------------------------------------------------------ setup guide (Cloudflare)
function cfTable(recs, zone) {
  const rows = recs.filter((x) => x.type !== "PTR");
  return `<div style="overflow-x:auto"><table class="tbl dns-tbl cf-tbl"><thead><tr><th>Type</th><th>Name</th><th>Content</th><th>Priority</th><th>Proxy status</th><th>TTL</th></tr></thead><tbody>
    ${rows.map((x) => {
      const other = x.zone && x.zone !== zone;
      return `<tr><td><b>${esc(x.type)}</b></td>
        <td><code>${esc(x.host)}</code> ${copyBtn(x.host)}${other ? `<div class="muted" style="font-size:11px">in the Cloudflare site <b>${esc(x.zone)}</b> (add once)</div>` : ""}</td>
        <td class="cf-content"><code>${esc(x.content)}</code> ${copyBtn(x.content)}</td>
        <td>${x.priority ?? "–"}</td>
        <td>${x.proxy ? `<span class="badge warn">${icon("cloud")} DNS only (grey cloud)</span>` : `<span class="muted">–</span>`}</td>
        <td class="muted">Auto</td></tr>`;
    }).join("")}</tbody></table></div>`;
}
async function guide(body, ctx) {
  const r = await api("/api/admin/domains");
  const mailHost = r.mail_hostname || "mail.yourdomain.com", ip = r.public_ip;
  const step = (n, title, html) => `<div class="guide-step"><div class="num">${n}</div><div class="txt"><h3>${title}</h3>${html}</div></div>`;
  body.innerHTML = `<div class="guide">
    <p class="muted" style="margin:0 0 16px;max-width:820px">Follow these steps once per domain. They tell the internet where your mail lives (MX),
      and prove your messages are genuine so they don't land in spam (SPF, DKIM, DMARC). We recommend managing your domain's DNS on
      <b>Cloudflare</b> (the free plan is enough); the steps below use Cloudflare's screens.</p>

    ${step(1, "Connect your domain to Cloudflare", `<ol>
      <li>Sign in at <a href="https://dash.cloudflare.com" target="_blank" rel="noopener">dash.cloudflare.com</a>, click <b>Add a domain</b>, enter your domain and choose the <b>Free</b> plan.</li>
      <li>Cloudflare shows two <b>nameservers</b> (e.g. <code>ada.ns.cloudflare.com</code>). At your registrar, replace the existing nameservers with these two.
        On Namecheap: <i>Domain List → Manage → Nameservers → Custom DNS</i>.</li>
      <li><b>Wait until Cloudflare shows the domain as “Active”</b>, usually about 30 minutes, sometimes up to 24 hours. Cloudflare emails you when it's done.</li>
      <li>In <i>DNS → Records</i>, <b>delete any old MX records</b> and any old <code>v=spf1</code> TXT record Cloudflare imported from your previous provider. A domain may have only one SPF record.</li>
      <li>Make sure <b>Email → Email Routing is turned off</b>. It replaces your MX records with Cloudflare's own.</li></ol>`)}

    ${step(2, "Add the DNS records in Cloudflare", `<p>In Cloudflare open your domain → <b>DNS → Records → Add record</b>, and add each row below exactly as shown.
      Use the copy buttons. Paste the long DKIM value in one piece; Cloudflare handles its length.</p>
      <div class="limit-note">${icon("warning")}<span><b>Proxy status must be “DNS only” (grey cloud) for both A records.</b> Cloudflare turns the orange cloud on by default.
        Its proxy only carries websites, so with the orange cloud on, phones and other mail servers can't reach ports 25, 465, 587 and 993, and mail stops working.</span></div>
      ${!ip ? `<div class="limit-note">${icon("help")}<span>The server's public IP isn't configured, so the A records aren't listed. Set <code>PUBLIC_IP</code> in <code>.env</code> and run <code>docker compose up -d</code>.</span></div>` : ""}
      ${r.domains.length ? r.domains.map((d) => `<div class="domain-card"><header><b>${esc(d.name)}</b><span class="muted">Cloudflare site: ${esc(d.name)}</span>
          <button class="btn outline" data-check="${esc(d.name)}">${icon("shield")} Check DNS</button></header>
          <div class="inner">${cfTable(d.dns, d.name)}<div data-out="${esc(d.name)}"></div></div></div>`).join("")
        : `<div class="empty">${icon("label")}<p>No domains yet. <a href="#/admin/domains">Add your domain</a> first.</p></div>`}`)}

    ${step(3, "Ask your hosting provider for reverse DNS (PTR)", `<p>Reverse DNS isn't set in Cloudflare. It belongs to whoever owns the server's IP address (your VPS provider, e.g. Namecheap).
      Ask their support or use their control panel to set:</p>
      <table class="tbl" style="max-width:620px"><tr><td>IP address</td><td><code>${esc(ip || "your server IP")}</code> ${ip ? copyBtn(ip) : ""}</td></tr>
      <tr><td>Reverse DNS (PTR)</td><td><code>${esc(mailHost)}</code> ${copyBtn(mailHost)}</td></tr></table>
      <p class="muted">Without it, Gmail and Outlook send your mail to spam or reject it.</p>`)}

    ${step(4, "Make sure outgoing port 25 is open", `<p>Many VPS providers block outgoing port 25 until you ask. Without it you can receive mail but can't send to other servers.
      Ask your provider: <i>“Please unblock outbound SMTP port 25 for my server ${esc(ip || "")}; I run my own mail server with SPF, DKIM and DMARC.”</i></p>`)}

    ${step(5, "Check your DNS", `<p>Wait 5–30 minutes after adding the records, then click <b>Check DNS</b> above (or in <a href="#/admin/domains">Domains &amp; DNS</a>).
      Aim for a score of 85 or more. Each problem comes with a suggested fix.</p>`)}

    ${step(6, "Create a postmaster address", `${r.domains.map((d) => `<p>${d.postmaster_ok ? `<span class="badge ok">${icon("check")} Done</span>` : `<span class="badge warn">${icon("warning")} Missing</span>`}
      <code>postmaster@${esc(d.name)}</code> receives DMARC reports and delivery problems.
      ${d.postmaster_ok ? "" : `Create it as an alias in <a href="#/admin/aliases">Aliases</a> that delivers to your own mailbox.`}</p>`).join("") || "<p>Add a domain first.</p>"}`)}

    ${step(7, "Create accounts and connect mail apps", `<p>Create mailboxes in <a href="#/admin/accounts">Accounts</a>. People can use this webmail, or any mail app (iPhone, Android, Outlook, Thunderbird) with:</p>
      <table class="tbl" style="max-width:620px">
        <tr><td>Username</td><td>the full email address</td></tr>
        <tr><td>Incoming (IMAP)</td><td><code>${esc(mailHost)}</code> · port <b>993</b> · SSL/TLS</td></tr>
        <tr><td>Outgoing (SMTP)</td><td><code>${esc(mailHost)}</code> · port <b>587</b> · STARTTLS (or <b>465</b> · SSL/TLS) · authentication on</td></tr></table>`)}

    ${step(8, "Optional: webmail through Cloudflare's proxy", `<p>Keeping the webmail record on “DNS only” is simplest. If you turn the orange cloud on for
      <code>${esc(r.web_hostname || "webmail")}</code> only (never for <code>${esc(mailHost)}</code>), set <i>SSL/TLS → Overview</i> to <b>Full (strict)</b>.
      “Flexible” causes an endless redirect loop.</p>`)}
  </div>`;
  $$("[data-check]", body).forEach((b) => (b.onclick = () => runDnsCheck($(`[data-out="${b.dataset.check}"]`, body), b.dataset.check)));
}

// ------------------------------------------------------------------ aliases
async function aliases(body, ctx) {
  const r = await api("/api/admin/aliases");
  const amax = r.max_aliases, afull = amax && r.counted >= amax;
  body.innerHTML = `<div class="adm-tools"><button class="btn primary" id="al-new" ${afull ? "disabled" : ""} title="${afull ? `Limit of ${amax} aliases reached` : ""}">${icon("add")} Add alias</button>
    <span class="count"><b>${r.counted}</b> of ${amax || "∞"} aliases${afull ? ` · <span class="st-warn">limit reached</span> · <a href="#/admin/upgrade">Upgrade to Mail Pro</a>` : ""} · don't count towards the account limit · <code>postmaster@</code> is free</span></div>
    <table class="tbl"><thead><tr><th>Alias address</th><th>Delivers to</th><th></th></tr></thead><tbody>
    ${r.aliases.map((a) => `<tr><td><b>${esc(a.source)}</b></td><td>${a.destinations.map(esc).join(", ")}</td><td style="text-align:right"><button class="icon-btn sm" data-edit="${esc(a.source)}" title="Edit">${icon("edit")}</button><button class="icon-btn sm" data-del="${esc(a.source)}" title="Delete">${icon("delete")}</button></td></tr>`).join("") || `<tr><td colspan="3" class="muted" style="text-align:center;padding:32px">No aliases. Use them for shared addresses like info@ or sales@.</td></tr>`}
    </tbody></table>`;
  const form = (a) => modal({ title: a ? "Edit alias" : "Add alias", body: `<div class="form-grid"><label>Alias address</label><input class="txt" id="as" value="${esc(a ? a.source : "")}" ${a ? "readonly" : ""} placeholder="info@yourcompany.com">
      <label>Deliver to</label><input class="txt" id="ad" value="${esc(a ? a.destinations.join(", ") : "")}" placeholder="anna@yourcompany.com, raj@yourcompany.com"></div>
      <p class="muted" style="font-size:12px">Accounts listed here can also send mail as the alias address.</p>`,
    buttons: [{ label: "Cancel" }, { label: "Save", cls: "primary", onClick: async (m) => { try { await api("/api/admin/aliases", { method: "POST", body: { source: $("#as", m).value, destinations: $("#ad", m).value } }); snack("Alias saved"); reloadTab(ctx); } catch (e) { snack(e.message); return false; } } }] });
  $("#al-new", body).onclick = () => form(null);
  $$("[data-edit]", body).forEach((b) => (b.onclick = () => form(r.aliases.find((x) => x.source === b.dataset.edit))));
  $$("[data-del]", body).forEach((b) => (b.onclick = async () => { if (!confirm(`Delete alias ${b.dataset.del}?`)) return; await api("/api/admin/aliases/delete", { method: "POST", body: { source: b.dataset.del } }); snack("Alias deleted"); reloadTab(ctx); }));
}

// ------------------------------------------------------------------ import
async function importTab(body, ctx) {
  const [acc, jobs] = await Promise.all([api("/api/admin/accounts?usage=0"), api("/api/admin/import")]);
  body.innerHTML = `<div class="limit-note">${icon("download")}<span>Copy existing mail from your old server (for example your current Postfix + Dovecot + Roundcube setup) into a Zoltis account. All folders are copied. Running it again only copies new messages. Imports stop if the mailbox reaches its size limit.</span></div>
    <div class="form-grid" style="max-width:640px">
      <label>Into account</label><select class="txt" id="im-to">${acc.accounts.map((a) => `<option ${a.email === state.importTarget ? "selected" : ""}>${esc(a.email)}</option>`).join("")}</select>
      <label>Old IMAP server</label><input class="txt" id="im-host" placeholder="mail.oldserver.com">
      <label>Security / port</label><div class="pw-row"><select class="txt" id="im-sec"><option value="ssl">SSL/TLS (993)</option><option value="starttls">STARTTLS (143)</option><option value="plain">None (143)</option></select><input class="txt" id="im-port" type="number" value="993" style="width:110px"></div>
      <label>Old username</label><input class="txt" id="im-user" placeholder="usually the full email address">
      <label>Old password</label><input class="txt" id="im-pw" type="password" autocomplete="off">
      <label></label><div><button class="btn primary" id="im-go">${icon("download")} Start import</button></div>
    </div>
    <h3 style="font:500 16px var(--font);margin:28px 0 12px">Imports</h3><div id="im-jobs"></div>`;
  $("#im-sec", body).onchange = (e) => ($("#im-port", body).value = e.target.value === "ssl" ? 993 : 143);
  $("#im-to", body).onchange = () => { if (!$("#im-user", body).value) $("#im-user", body).placeholder = $("#im-to", body).value; };
  $("#im-go", body).onclick = async () => {
    const b = $("#im-go", body); b.disabled = true;
    try {
      await api("/api/admin/import", { method: "POST", body: { email: $("#im-to", body).value, host: $("#im-host", body).value, port: +$("#im-port", body).value, security: $("#im-sec", body).value, username: $("#im-user", body).value || $("#im-to", body).value, password: $("#im-pw", body).value } });
      $("#im-pw", body).value = ""; snack("Import started"); drawJobs();
    } catch (e) { snack(e.message); } finally { b.disabled = false; }
  };
  const drawJobs = async (data) => {
    const r = data || await api("/api/admin/import");
    const box = $("#im-jobs", body); if (!box) return;
    box.innerHTML = r.jobs.map((j) => {
      const pct = j.total ? Math.min(100, Math.round(100 * (j.copied + j.skipped + j.failed) / j.total)) : 0;
      const badge = { running: "warn", queued: "warn", done: "ok", failed: "off", cancelled: "" }[j.state];
      return `<div class="job"><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><b>${esc(j.source)}</b> → <b>${esc(j.target)}</b><span class="badge ${badge}">${esc(j.state)}</span>
        ${j.state === "running" ? `<button class="btn text" data-cancel="${j.id}">Cancel</button>` : ""}</div>
        <div class="muted" style="font-size:12px;margin-top:4px">${j.copied} copied · ${j.skipped} already there · ${j.failed} failed${j.total ? ` · ${j.total} total` : ""}${j.folder && j.state === "running" ? ` · now: ${esc(j.folder)}` : ""}${j.error ? ` · <span class="st-fail">${esc(j.error)}</span>` : ""}</div>
        ${j.state === "running" ? meter(pct) : ""}</div>`;
    }).join("") || `<p class="muted">No imports yet.</p>`;
    $$("[data-cancel]", box).forEach((b) => (b.onclick = () => api("/api/admin/import/cancel", { method: "POST", body: { id: b.dataset.cancel } })));
  };
  drawJobs(jobs);
  state.importTimer = setInterval(() => { if (!document.contains(body)) return clearInterval(state.importTimer); drawJobs(); }, 2000);
}

// ------------------------------------------------------------------ sessions
const device = (ua) => { if (!ua) return "Unknown"; const b = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "Browser"; const o = /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Windows/.test(ua) ? "Windows" : /Mac OS/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : ""; return `${b}${o ? " on " + o : ""}`; };
async function sessions(body, ctx) {
  const r = await api("/api/admin/sessions");
  body.innerHTML = `<table class="tbl"><thead><tr><th>Account</th><th>Device</th><th class="hide-sm">IP address</th><th>Last active</th><th class="hide-sm">Signed in</th><th></th></tr></thead><tbody>
    ${r.sessions.map((s) => `<tr><td><b>${esc(s.email)}</b>${s.current ? ' <span class="badge">This session</span>' : ""}</td><td>${esc(device(s.user_agent))}</td><td class="hide-sm">${esc(s.ip)}</td><td>${esc(ago(s.last_seen))}</td><td class="hide-sm muted">${esc(ago(s.created))}</td>
      <td style="text-align:right">${s.current ? "" : `<button class="btn text" data-rev="${s.handle}">Sign out</button>`}</td></tr>`).join("")}</tbody></table>`;
  $$("[data-rev]", body).forEach((b) => (b.onclick = async () => { await api("/api/admin/sessions/revoke", { method: "POST", body: { handle: b.dataset.rev } }); snack("Session signed out"); reloadTab(ctx); }));
}

// ------------------------------------------------------------------ activity
const ACTIONS = { "account.create": "Created account", "account.update": "Updated account", "account.delete": "Deleted account", "account.register": "First sign-in", "domain.add": "Added domain", "domain.delete": "Deleted domain", "alias.set": "Saved alias", "alias.delete": "Deleted alias", "import.start": "Started import", "session.revoke": "Signed out a session", "session.revoke_all": "Signed out all sessions of", "license.activate": "Activated license", "account.import": "Imported account", "migration.export": "Exported all data", "migration.import": "Imported export file", "migration.download": "Downloaded export file", "migration.delete": "Deleted export file" };
async function activity(body) {
  const r = await api("/api/admin/audit");
  body.innerHTML = `<table class="tbl"><thead><tr><th>When</th><th>Who</th><th>Action</th><th>Details</th></tr></thead><tbody>
    ${r.events.map((e) => `<tr><td class="muted" style="white-space:nowrap">${esc(new Date(e.ts * 1000).toLocaleString())}</td><td>${esc(e.actor)}</td><td>${esc(ACTIONS[e.action] || e.action)}</td><td>${esc(e.target)}</td></tr>`).join("") || `<tr><td colspan="4" class="muted">No activity yet</td></tr>`}</tbody></table>`;
}

// ------------------------------------------------------------------ security
async function security(body) {
  const o = state.overview || await api("/api/admin/overview");
  const P = o.attachment_policy, av = o.antivirus;
  body.innerHTML = `<table class="tbl" style="max-width:860px">
    <tr><td style="width:220px"><b>Antivirus (ClamAV)</b></td><td>${!av.enabled ? "Disabled" : av.online ? `<span class="badge ok">${icon("shield")} Active</span> <span class="muted">${esc(av.version)}</span><br>Incoming: ${av.scan_incoming ? "scanned" : "off"} · Outgoing: ${av.scan_outgoing ? "scanned" : "off"} · When scanner is down: ${esc(av.fail_mode)}` : `<span class="badge off">Offline</span> ${esc(av.version || "")}`}</td></tr>
    <tr><td><b>Attachment blocker</b></td><td>${P.enabled ? `<span class="badge ok">${icon("shield")} Active</span>` : "Disabled"}<br>Office macros: <b>${esc(P.macro_action)}</b> · Password-protected archives: <b>${esc(P.encrypted_archives)}</b> · Risky received files: <b>${P.incoming_action === "warn" ? "warn" : "blocked"}</b> · Archives checked ${P.archive_max_depth} levels deep
      <details style="margin-top:6px"><summary style="cursor:pointer;color:var(--primary)">${P.blocked_extensions.length} blocked file types</summary><div style="font:12px ui-monospace,monospace;line-height:1.8">${P.blocked_extensions.map((x) => "." + esc(x)).join(" ")}</div></details></td></tr>
    <tr><td><b>Mailbox limits</b></td><td>${o.limits.max_accounts || "Unlimited"} accounts · ${o.limits.max_quota_mb ? o.limits.max_quota_mb + " MB" : "custom"} per mailbox · incoming mail to a full mailbox is refused</td></tr>
    <tr><td><b>Sending rules</b></td><td>Users can only send as their own address or an alias that delivers to them (anti-spoofing). Every message is DKIM-signed.</td></tr>
    <tr><td><b>Sign-in protection</b></td><td>10 failed attempts per 15 minutes per IP and per account, then blocked temporarily.</td></tr>
  </table>
  <p class="muted" style="margin-top:16px;font-size:13px">These settings live in <code>config/zoltis.ini</code> on the server. Edit it, then run <code>docker compose restart web</code>.</p>`;
}

// ------------------------------------------------------------------ export & move (migration)
const fmtBytes = (n) => (n >= 1073741824 ? (n / 1073741824).toFixed(2) + " GB" : n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " KB");
async function migrate(body, ctx) {
  const r = await api("/api/admin/migration");
  const running = r.jobs.find((j) => j.state === "queued" || j.state === "running");
  const jobRow = (j) => {
    const pct = j.total ? Math.min(100, Math.round((100 * (j.messages + j.skipped)) / j.total)) : 0;
    const st = { done: ["ok", "Done"], failed: ["off", "Failed"], cancelled: ["", "Cancelled"], running: ["warn", "Running"], queued: ["", "Queued"] }[j.state] || ["", j.state];
    return `<tr><td><b>${j.kind === "export" ? "Export" : "Import"}</b><div class="muted" style="font-size:12px">${esc(j.file)}</div></td>
      <td><span class="badge ${st[0]}">${st[1]}</span>${j.state === "running" ? `${meter(pct)}<div class="muted" style="font-size:12px">${esc(j.current)}</div>` : ""}
        ${j.error ? `<div class="st-fail" style="font-size:12px">${esc(j.error)}</div>` : ""}</td>
      <td>${j.accounts} accounts · ${j.messages}${j.total ? ` / ${j.total}` : ""} messages${j.skipped ? ` · ${j.skipped} already there` : ""}${j.failed ? ` · <span class="st-warn">${j.failed} failed</span>` : ""}${j.kind === "export" && j.bytes ? ` · ${fmtBytes(j.bytes)}` : ""}
        ${j.warnings.length ? `<details><summary class="st-warn" style="cursor:pointer">${j.warnings.length} warning${j.warnings.length > 1 ? "s" : ""}</summary>${j.warnings.map((w) => `<div style="font-size:12px">${esc(w)}</div>`).join("")}</details>` : ""}</td>
      <td style="text-align:right">${j.state === "running" ? `<button class="btn text" data-cancel="${j.id}">Cancel</button>` : ""}</td></tr>`;
  };
  body.innerHTML = `<div style="max-width:980px">
    <div class="limit-note">${icon("help")}<span><b>Moving to Zoltis Mail Pro, or to another server?</b> Export creates one encrypted file with <b>everything</b>:
      all accounts (people keep their passwords), aliases, domains with their DKIM keys, each person's settings, signature and contacts,
      and every email in every folder (Inbox, Sent, Drafts, Archive and your own folders) with attachments, read/starred status and dates.
      Import it on the new server and everything comes back. Importing twice is safe: nothing is duplicated.</span></div>

    <h3 style="font:500 16px var(--font);margin:20px 0 8px">1. Export this server</h3>
    <p class="muted" style="margin:0 0 10px;font-size:13px">Mail on this server: about <b>${mb(r.mail_mb)}</b>. Free disk: <b>${mb(r.free_mb)}</b>.
      Choose a passphrase and keep it safe. Anyone with the file and the passphrase can read all the mail in it, and without the passphrase the file can't be opened.</p>
    <div class="form-grid" style="max-width:560px"><label>Passphrase</label><input class="txt" type="password" id="mg-p1" autocomplete="new-password" placeholder="at least 10 characters">
      <label>Repeat</label><input class="txt" type="password" id="mg-p2" autocomplete="new-password"></div>
    <div style="margin:10px 0 6px"><button class="btn primary" id="mg-export" ${running ? "disabled" : ""}>${icon("download")} Export everything</button></div>
    ${r.mail_mb * 0.8 + 200 > r.free_mb ? `<div class="limit-note">${icon("warning")}<span>There may not be enough free disk for the export file. Stream it straight to another computer instead:
      <code>ssh you@this-server "cd zoltis-mail && docker compose exec -T -e ZOLTIS_EXPORT_PASSPHRASE='…' web zoltis export create -" &gt; mail.zmexport</code></span></div>` : ""}

    <h3 style="font:500 16px var(--font);margin:24px 0 8px">Progress</h3>
    <table class="tbl"><tbody>${r.jobs.map(jobRow).join("") || `<tr><td class="muted">No exports or imports yet</td></tr>`}</tbody></table>

    <h3 style="font:500 16px var(--font);margin:24px 0 8px">2. Export files on this server</h3>
    <table class="tbl"><thead><tr><th>File</th><th>Size</th><th>Created</th><th></th></tr></thead><tbody>
      ${r.files.map((f) => `<tr><td><code>${esc(f.file)}</code></td><td>${fmtBytes(f.size)}</td><td class="muted">${esc(new Date(f.modified * 1000).toLocaleString())}</td>
        <td style="text-align:right;white-space:nowrap"><a class="btn text" href="/api/admin/migration/download?file=${encodeURIComponent(f.file)}">${icon("download")} Download</a>
          <button class="btn text" data-import="${esc(f.file)}" ${running ? "disabled" : ""}>Import</button>
          <button class="icon-btn sm" data-delfile="${esc(f.file)}" title="Delete">${icon("delete")}</button></td></tr>`).join("") || `<tr><td colspan="4" class="muted">No export files yet</td></tr>`}
    </tbody></table>
    <p class="muted" style="font-size:12px">Download the file and send it to Zoltis (or keep it as a full backup), then delete it here to free the disk space.</p>

    <h3 style="font:500 16px var(--font);margin:24px 0 8px">3. Import on the new server</h3>
    <p style="margin:0 0 8px;font-size:13px">Moving to Zoltis Mail Pro? Zoltis imports the file for you. To import on a server you run yourself, copy the file into it and it appears in the list above:</p>
    <pre class="code">docker compose cp mail.zmexport web:${esc(r.export_dir)}/</pre>
    <p class="muted" style="font-size:12px">Then click <b>Import</b> next to the file. Import follows the new server's limits and license: accounts, aliases or domains it doesn't allow are skipped and listed as warnings.
      After moving, point your domain's MX and A records at the new server. The DKIM record stays the same.</p>
  </div>`;
  $("#mg-export", body).onclick = async () => {
    const p1 = $("#mg-p1", body).value;
    if (p1 !== $("#mg-p2", body).value) return snack("Passphrases don't match");
    try { await api("/api/admin/migration/export", { method: "POST", body: { passphrase: p1 } }); snack("Export started"); reloadTab(ctx); }
    catch (e) { snack(e.message); }
  };
  $$("[data-import]", body).forEach((b) => (b.onclick = () => modal({ title: "Import " + b.dataset.import,
    body: `<p>Adds the domains, accounts, aliases, settings and mail from this file to this server. Existing data is kept, and messages that are already here are skipped.</p>
      <label class="muted">Passphrase used for the export</label><input class="txt" type="password" id="mg-ip" style="margin-top:6px">`,
    buttons: [{ label: "Cancel" }, { label: "Import", cls: "primary", onClick: async (m) => {
      try { await api("/api/admin/migration/import", { method: "POST", body: { file: b.dataset.import, passphrase: $("#mg-ip", m).value } }); snack("Import started"); reloadTab(ctx); }
      catch (e) { snack(e.message); return false; } } }] })));
  $$("[data-delfile]", body).forEach((b) => (b.onclick = async () => {
    if (!confirm(`Delete ${b.dataset.delfile}? Make sure you have a copy if you still need it.`)) return;
    try { await api("/api/admin/migration/delete", { method: "POST", body: { file: b.dataset.delfile } }); snack("Deleted"); reloadTab(ctx); } catch (e) { snack(e.message); }
  }));
  $$("[data-cancel]", body).forEach((b) => (b.onclick = async () => { await api("/api/admin/migration/cancel", { method: "POST", body: { id: b.dataset.cancel } }); reloadTab(ctx); }));
  if (running) state.migrateTimer = setInterval(() => { if (location.hash.startsWith("#/admin/migrate")) reloadTab(ctx); else clearInterval(state.migrateTimer); }, 2000);
}

// ------------------------------------------------------------------ upgrade to Mail Pro
function upgradeNote(lead) {
  return `<div class="limit-note" style="margin-top:24px">${icon("star")}<span>${lead} Need more accounts and aliases, with Zoltis running the server for you?
    <a href="#/admin/upgrade"><b>Upgrade to Zoltis Mail Pro</b></a></span></div>`;
}
async function upgrade(body) {
  const L = await api("/api/admin/license");
  const o = state.overview || await api("/api/admin/overview");
  const lim = o.limits || {};
  body.innerHTML = `<div style="max-width:760px">
    <h3 style="font:500 20px var(--font);margin:0 0 8px">${icon("star")} Upgrade to Zoltis Mail Pro</h3>
    <p style="margin:0 0 12px">This server runs the free Community Edition: <b>${o.accounts} of ${lim.max_accounts}</b> accounts and
      <b>${o.aliases_counted} of ${lim.max_aliases}</b> aliases used, up to ${lim.max_quota_mb} MB per mailbox.</p>
    <p style="margin:0 0 12px">Zoltis also offers paid plans with more accounts and aliases, where Zoltis runs, monitors, updates and backs up
      the mail server for you. See the plans and sign up on the Zoltis website.</p>
    <a class="btn primary" href="${esc(L.upgrade_url)}" target="_blank" rel="noopener">${icon("star")} See plans and sign up</a>
    <p class="muted" style="font-size:12px;margin:8px 0 20px">Opens the Zoltis website in a new tab. Your license${L.license_id ? ` (<code>${esc(L.license_id)}</code>)` : ""}
      and domains are passed along so Zoltis can link your sign-up to this server. Nothing changes here until you've signed up.</p>
    <div class="limit-note">${icon("help")}<span><b>Your mail comes with you.</b> <a href="#/admin/migrate">Export &amp; move</a> creates one encrypted file
      with all accounts, passwords, settings and every email, ready for Zoltis to import into your new server.</span></div>
  </div>`;
}

// ------------------------------------------------------------------ license
const LIC_STATE = {
  active: ["ok", "Active"], disabled: ["ok", "Not required"], missing: ["off", "No license key"],
  invalid: ["off", "Invalid key"], expired: ["off", "Expired"], inactive: ["warn", "Not activated"], lapsed: ["warn", "Activation lapsed"],
};
function licenseNote(lic) {
  if (!lic || lic.active) return "";
  return `<div class="limit-note" style="border:1px solid var(--danger, #d93025)">${icon("warning")}<span><b>No active license.</b>
    Creating email accounts and adding domains is disabled until you activate a license key. Existing mailboxes keep working.
    <a href="#/admin/license">Enter license key</a></span></div>`;
}
async function license(body, ctx) {
  const L = await api("/api/admin/license");
  if (state.overview) state.overview.license = L;
  if (!L.required) {
    body.innerHTML = `<div class="limit-note">${icon("check")}<span><b>No license key needed.</b>
      Licensing is turned off on this server, so you can create accounts and add domains without a key.</span></div>`;
    return;
  }
  const [cls, label] = LIC_STATE[L.state] || ["", L.state];
  const day = (t) => (t ? new Date(t * 1000).toLocaleDateString() : "–");
  body.innerHTML = `<table class="tbl" style="max-width:760px">
      <tr><td style="width:200px">Status</td><td><span class="badge ${cls}">${esc(label)}</span>${L.problem ? `<div class="st-warn" style="margin-top:6px">${esc(L.problem)}</div>` : ""}</td></tr>
      ${L.license_id ? `
      <tr><td>Licensed to</td><td><b>${esc(L.customer || "–")}</b> ${L.email ? `<span class="muted">${esc(L.email)}</span>` : ""}</td></tr>
      <tr><td>Domains covered</td><td>${L.domains.map((d) => `<code>${esc(d)}</code>`).join(" ")}</td></tr>
      <tr><td>License ID</td><td><code>${esc(L.license_id)}</code></td></tr>
      <tr><td>Key expires</td><td>${L.expires ? day(L.expires) : "Never"}</td></tr>
      <tr><td>Activation valid until</td><td>${day(L.activated_until)} <span class="muted">· renewed automatically every day</span></td></tr>
      <tr><td>Last checked</td><td>${L.last_check ? esc(ago(L.last_check)) : "–"} <button class="btn text" id="lic-check">Check now</button></td></tr>` : ""}
      <tr><td>Install ID</td><td><code>${esc(L.install_id || "")}</code> ${copyBtn(L.install_id || "")}</td></tr>
    </table>
    <h3 style="font:500 16px var(--font);margin:24px 0 8px">${L.license_id ? "Replace license key" : "Enter license key"}</h3>
    <p class="muted" style="margin:0 0 12px;font-size:13px">Don't have a key? <a href="${esc(L.register_url)}" target="_blank" rel="noopener">Register for a free Community Edition key</a>.
      The key is activated online once and checked again every day, so this server needs internet access.</p>
    <textarea id="lic-key" class="lic-key" rows="4" spellcheck="false" placeholder="ZM1.…"></textarea>
    <div style="margin-top:12px"><button class="btn primary" id="lic-save">${icon("check")} Activate</button></div>`;
  $("#lic-save", body).onclick = async (e) => {
    const btn = e.currentTarget; btn.disabled = true;
    try { await api("/api/admin/license", { method: "POST", body: { key: $("#lic-key", body).value } }); snack("License activated"); reloadTab(ctx); }
    catch (ex) { snack(ex.message); btn.disabled = false; }
  };
  const chk = $("#lic-check", body);
  if (chk) chk.onclick = async () => {
    chk.disabled = true;
    try { await api("/api/admin/license/refresh", { method: "POST" }); snack("License confirmed"); }
    catch (ex) { snack(ex.message); }
    reloadTab(ctx);
  };
}

window.ZoltisModules = window.ZoltisModules || {};
window.ZoltisModules.admin = async (root, ctx) => {
  if (!ctx.S.me.is_admin) { root.innerHTML = `<div class="empty">${icon("lock")}<p>Administrator access required.</p></div>`; return; }
  if (!state.overview) { try { const o = await api("/api/admin/overview"); state.overview = o; state.mode = o.mode; state.limits = o.limits; } catch (e) {} }
  render(root, ctx);
};
})();
