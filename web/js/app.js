/* Zoltis Mail web client. Vanilla JS, no build step. */
(() => {
"use strict";

// ---------------------------------------------------------------- helpers
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const h = (html) => { const t = document.createElement("template"); t.innerHTML = html.trim(); hydrateIcons(t.content); return t.content.firstElementChild; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const fmtSize = (n) => n < 1024 ? `${n} B` : n < 1048576 ? `${Math.round(n / 1024)} KB` : `${(n / 1048576).toFixed(1)} MB`;
const COLORS = ["#1a73e8", "#d93025", "#188038", "#e37400", "#9334e6", "#c5221f", "#007b83", "#b06000", "#3949ab", "#ad1457", "#00838f", "#5f6368"];
const colorFor = (s) => { let x = 0; for (const c of String(s || "")) x = (x * 31 + c.charCodeAt(0)) >>> 0; return COLORS[x % COLORS.length]; };
const initial = (p) => ((p && (p.name || p.email)) || "?").trim().replace(/^["']/, "").charAt(0).toUpperCase() || "?";
const avatar = (p, cls = "") => `<span class="avatar ${cls}" style="background:${colorFor(p && p.email)}">${esc(initial(p))}</span>`;
const who = (p) => p ? (p.name || p.email) : "";
const fullAddr = (p) => p.name ? `${p.name} <${p.email}>` : p.email;

function fmtDate(iso, long = false) {
  if (!iso) return "";
  const d = new Date(iso), now = new Date();
  if (long) {
    const diff = (now - d) / 36e5;
    const rel = diff < 1 ? `${Math.max(1, Math.round(diff * 60))} minutes ago` : diff < 24 ? `${Math.round(diff)} hours ago` : diff < 24 * 30 ? `${Math.round(diff / 24)} days ago` : "";
    return d.toLocaleString(undefined, { weekday: "short", month: "short", day: "numeric", year: d.getFullYear() !== now.getFullYear() ? "numeric" : undefined, hour: "numeric", minute: "2-digit" }) + (rel ? ` (${rel})` : "");
  }
  if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
  if (d.getFullYear() === now.getFullYear()) return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  return d.toLocaleDateString(undefined, { year: "2-digit", month: "numeric", day: "numeric" });
}

class ApiError extends Error { constructor(msg, status) { super(msg); this.status = status; } }
async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: { "X-Zoltis": "1" }, credentials: "same-origin" };
  if (opts.body !== undefined) { init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(opts.body); }
  let res;
  try { res = await fetch(path, init); } catch (e) { throw new ApiError("Can't reach the server. Check your connection.", 0); }
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && !opts.noAuthRedirect) { showLogin(); throw new ApiError(data.error || "Please sign in", 401); }
  if (!res.ok) throw new ApiError(data.error || `Error ${res.status}`, res.status);
  return data;
}
const qs = (o) => Object.entries(o).filter(([, v]) => v !== undefined && v !== null && v !== "").map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&");

// ---------------------------------------------------------------- state
const S = {
  config: {}, me: null, settings: {}, folders: [],
  folderKey: "inbox", folder: "INBOX", page: 0, q: "", baseQ: "",
  list: [], total: 0, pageSize: 50, selected: new Set(), focus: -1,
  current: null, view: "list", loading: false, lastUnread: null,
};
const ROLE_META = {
  inbox: ["inbox", "Inbox"], starred: ["star_border", "Starred"], sent: ["send", "Sent"],
  drafts: ["draft", "Drafts"], archive: ["archive", "Archive"], junk: ["report", "Spam"],
  trash: ["delete", "Trash"], all: ["mail", "All Mail"],
};

// ---------------------------------------------------------------- snackbar
let snackTimer;
function snack(text, actionLabel, action, ms = 6000) {
  const sb = $("#snackbar");
  $("#snack-text").textContent = text;
  const btn = $("#snack-action");
  btn.textContent = actionLabel || "";
  btn.classList.toggle("hidden", !actionLabel);
  btn.onclick = () => { sb.classList.add("hidden"); action && action(); };
  sb.classList.remove("hidden");
  clearTimeout(snackTimer);
  if (ms) snackTimer = setTimeout(() => sb.classList.add("hidden"), ms);
}
$("#snack-close").onclick = () => $("#snackbar").classList.add("hidden");
const fail = (e) => { console.error(e); if (e.status !== 401) snack(e.message || String(e)); };

// ---------------------------------------------------------------- modal
function modal({ title, body, buttons = [], wide = false, onClose }) {
  const bg = h(`<div class="modal-bg"><div class="modal ${wide ? "wide" : ""}" role="dialog" aria-modal="true"><h3>${esc(title)}</h3><div class="m-body"></div><div class="m-foot"></div></div></div>`);
  const m = bg.firstElementChild;
  if (typeof body === "string") $(".m-body", m).innerHTML = body; else $(".m-body", m).append(body);
  hydrateIcons(m);
  const close = () => { bg.remove(); onClose && onClose(); };
  for (const b of buttons) {
    const el = h(`<button class="btn ${b.cls || "text"}">${esc(b.label)}</button>`);
    el.onclick = async () => { if (b.onClick) { const r = await b.onClick(m); if (r === false) return; } close(); };
    $(".m-foot", m).append(el);
  }
  if (!buttons.length) $(".m-foot", m).remove();
  bg.addEventListener("mousedown", (e) => { if (e.target === bg) close(); });
  bg.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.stopPropagation(); close(); } });
  $("#modal-root").append(bg);
  const f = $("input, textarea, select, [contenteditable]", m); f && f.focus();
  return { el: m, close };
}
function prompt(title, label, value = "") {
  return new Promise((resolve) => {
    let done = false;
    const md = modal({
      title, body: `<label class="muted">${esc(label)}</label><input class="txt" style="margin-top:8px" value="${esc(value)}">`,
      buttons: [{ label: "Cancel" }, { label: "Create", cls: "primary", onClick: (m) => { done = true; resolve($("input", m).value.trim()); } }],
      onClose: () => !done && resolve(null),
    });
    $("input", md.el).addEventListener("keydown", (e) => { if (e.key === "Enter") $(".btn.primary", md.el).click(); });
  });
}

// ---------------------------------------------------------------- popover menus
function popover(anchor, items) {
  const p = $("#popover");
  p.innerHTML = "";
  for (const it of items) {
    if (it === "-") { p.append(h(`<div style="border-top:1px solid var(--border);margin:6px 0"></div>`)); continue; }
    const b = h(`<button class="menu-item">${it.icon ? `<i data-icon="${it.icon}"></i>` : ""}<span>${esc(it.label)}</span></button>`);
    b.onclick = () => { hidePopover(); it.onClick(); };
    p.append(b);
  }
  hydrateIcons(p);
  p.classList.remove("hidden");
  const r = anchor.getBoundingClientRect();
  const w = p.offsetWidth, hh = p.offsetHeight;
  p.style.left = Math.max(8, Math.min(r.left, innerWidth - w - 8)) + "px";
  p.style.top = (r.bottom + hh + 8 > innerHeight ? Math.max(8, r.top - hh) : r.bottom + 4) + "px";
}
function hidePopover() { $("#popover").classList.add("hidden"); }
document.addEventListener("mousedown", (e) => {
  if (!e.target.closest("#popover")) hidePopover();
  if (!e.target.closest("#account-menu") && !e.target.closest("#account-btn")) $("#account-menu").classList.add("hidden");
  if (!e.target.closest(".search")) $("#search-panel").classList.add("hidden");
});
function folderPicker(anchor, cb) {
  const items = S.folders.filter((f) => f.name !== S.folder).map((f) => ({
    label: f.role ? ROLE_META[f.role]?.[1] || f.label : f.name, icon: f.role ? ROLE_META[f.role]?.[0] : "label", onClick: () => cb(f.name),
  }));
  items.push("-", { label: "Create new label", icon: "add", onClick: async () => { const n = await newLabel(); if (n) cb(n); } });
  popover(anchor, items);
}

// ---------------------------------------------------------------- theme / branding
function applyTheme() {
  const t = S.settings.theme || "system";
  const dark = t === "dark" || (t === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  document.documentElement.dataset.density = S.settings.density || "default";
}
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", applyTheme);
function applyBranding() {
  const c = S.config;
  $$(".app-name").forEach((e) => (e.textContent = c.app_name || "Mail"));
  if (c.primary_color && /^#[0-9a-f]{3,8}$/i.test(c.primary_color) && c.primary_color.toLowerCase() !== "#0b57d0")
    document.documentElement.style.setProperty("--primary", c.primary_color);
  $("#login-edition").textContent = `${c.edition === "enterprise" ? "Enterprise" : "Community"} Edition ${c.version || ""}`;
  document.title = c.app_name || "Mail";
}

// ---------------------------------------------------------------- login
function showLogin() {
  stopPolling();
  $("#app").classList.add("hidden");
  $("#login").classList.remove("hidden");
  const dd = S.config.default_domain;
  $("#login-email").placeholder = " ";
  if (dd) $("#login-email").closest(".field").querySelector("span").textContent = `Email or username (@${dd})`;
  setTimeout(() => $("#login-email").focus(), 50);
}
$("#login-showpw").onchange = (e) => ($("#login-password").type = e.target.checked ? "text" : "password");
$("#login-form").onsubmit = async (e) => {
  e.preventDefault();
  const btn = $("#login-btn"), err = $("#login-error");
  err.innerHTML = ""; btn.disabled = true; btn.textContent = "Signing in…";
  try {
    await api("/api/login", { method: "POST", body: { email: $("#login-email").value, password: $("#login-password").value }, noAuthRedirect: true });
    $("#login-password").value = "";
    await startApp();
  } catch (ex) {
    err.innerHTML = icon("error") + esc(ex.message);
  } finally { btn.disabled = false; btn.textContent = "Sign in"; }
};

// ---------------------------------------------------------------- app start
async function boot() {
  hydrateIcons();
  try { S.config = await api("/api/config", { noAuthRedirect: true }); } catch (e) { S.config = {}; }
  applyBranding();
  if (S.config.setup_needed) { showSetup(); return; }
  try { await startApp(); } catch (e) { if (e.status === 401) showLogin(); else fail(e); }
}
function showSetup() {
  $("#login").classList.add("hidden");
  $("#setup").classList.remove("hidden");
  const lic = S.config.license || {};
  $("#setup-register").href = lic.register_url || "#";
  $("#setup-license-box").classList.toggle("hidden", !!lic.active);
  if (lic.active && lic.domains?.length) $("#setup-email").placeholder = "admin@" + lic.domains[0];
  setTimeout(() => $("#setup-token").focus(), 50);
}
$("#setup-form").onsubmit = async (e) => {
  e.preventDefault();
  const err = $("#setup-error"), btn = $("#setup-btn");
  err.innerHTML = "";
  const pw = $("#setup-password").value;
  if (pw !== $("#setup-password2").value) { err.innerHTML = icon("error") + "Passwords don't match"; return; }
  btn.disabled = true; btn.textContent = "Setting up…";
  try {
    const email = $("#setup-email").value.trim();
    await api("/api/setup", { method: "POST", body: { token: $("#setup-token").value, license_key: $("#setup-license").value, name: $("#setup-name").value, email, password: pw }, noAuthRedirect: true });
    await api("/api/login", { method: "POST", body: { email, password: pw }, noAuthRedirect: true });
    S.config.setup_needed = false;
    $("#setup").classList.add("hidden");
    await startApp();
    location.hash = "#/admin/guide";
  } catch (ex) { err.innerHTML = icon("error") + esc(ex.message); }
  finally { btn.disabled = false; btn.textContent = "Create admin & continue"; }
};
async function startApp() {
  S.me = await api("/api/me", { noAuthRedirect: true });
  S.settings = S.me.settings;
  applyTheme();
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  const name = S.settings.display_name || S.me.email.split("@")[0];
  const meP = { name, email: S.me.email };
  for (const id of ["#me-avatar", "#me-avatar2"]) { const a = $(id); a.textContent = initial(meP); a.style.background = colorFor(S.me.email); }
  $("#me-name").textContent = name;
  $("#me-email").textContent = S.me.email;
  $("#me-edition").textContent = `${S.me.edition === "enterprise" ? "Enterprise" : "Community"} Edition` + (S.me.licensed_to ? ` · ${S.me.licensed_to}` : "");
  renderEnterpriseNav();
  $("#admin-link").classList.toggle("hidden", !S.me.is_admin);
  loadQuota();
  await loadFolders();
  route();
  startPolling();
}

// ---------------------------------------------------------------- folders
async function loadFolders() {
  const r = await api("/api/folders");
  S.folders = r.folders;
  renderFolders();
}
const keyFor = (f) => (f.role ? f.role : "f/" + encodeURIComponent(f.name));
function renderFolders() {
  const sys = $("#folders"), lab = $("#labels");
  sys.innerHTML = ""; lab.innerHTML = "";
  const specials = [];
  for (const f of S.folders) if (f.role) specials.push(f);
  const inbox = specials.find((f) => f.role === "inbox");
  const order = ["inbox", "starred", "sent", "drafts", "archive", "junk", "trash", "all"];
  const items = [];
  for (const role of order) {
    if (role === "starred") { if (inbox) items.push({ key: "starred", icon: "star_border", label: "Starred", count: 0 }); continue; }
    const f = specials.find((x) => x.role === role);
    if (!f) continue;
    const cnt = role === "drafts" ? f.total : role === "trash" || role === "sent" || role === "archive" || role === "all" ? 0 : f.unread;
    items.push({ key: role, icon: ROLE_META[role][0], label: ROLE_META[role][1], count: cnt, folder: f });
  }
  for (const it of items) sys.append(folderEl(it));
  for (const f of S.folders.filter((x) => !x.role)) lab.append(folderEl({ key: keyFor(f), icon: "label", label: f.name, count: f.unread, folder: f, custom: true }));
  updateTitle();
}
function folderEl(it) {
  const li = h(`<li><a class="folder ${it.key === S.folderKey ? "active" : ""} ${it.count ? "has-unread" : ""}" href="#/${it.key}" title="${esc(it.label)}">
    <i data-icon="${it.icon}"></i><span class="name">${esc(it.label)}</span><span class="count">${it.count || ""}</span></a></li>`);
  const a = li.firstElementChild;
  a.addEventListener("click", () => document.getElementById("app").classList.remove("drawer"));
  if (it.folder) {
    a.addEventListener("dragover", (e) => { e.preventDefault(); a.classList.add("drop-target"); });
    a.addEventListener("dragleave", () => a.classList.remove("drop-target"));
    a.addEventListener("drop", (e) => {
      e.preventDefault(); a.classList.remove("drop-target");
      const uids = JSON.parse(e.dataTransfer.getData("text/x-zoltis-uids") || "[]");
      if (uids.length) moveMessages(uids, it.folder.name, `Moved to ${it.label}`);
    });
  }
  if (it.custom) a.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    popover(a, [{ label: `Delete label "${it.label}"`, icon: "delete", onClick: async () => {
      if (!confirm(`Delete "${it.label}" and all messages in it?`)) return;
      try { await api("/api/folders?" + qs({ name: it.folder.name }), { method: "DELETE" }); await loadFolders(); if (S.folder === it.folder.name) location.hash = "#/inbox"; snack("Label deleted"); } catch (er) { fail(er); }
    } }]);
  });
  return li;
}
async function newLabel() {
  const n = await prompt("New label", "Please enter a new label name:");
  if (!n) return null;
  try { await api("/api/folders", { method: "POST", body: { name: n } }); await loadFolders(); snack(`Label "${n}" created`); return n; } catch (e) { fail(e); return null; }
}
$("#add-label").onclick = newLabel;
function folderByKey(key) {
  if (key === "starred") return S.folders.find((f) => f.role === "inbox");
  if (key.startsWith("f/")) { const n = decodeURIComponent(key.slice(2)); return S.folders.find((f) => f.name === n) || { name: n, label: n }; }
  return S.folders.find((f) => f.role === key);
}
function updateTitle() {
  const inbox = S.folders.find((f) => f.role === "inbox");
  const u = inbox ? inbox.unread : 0;
  document.title = `${S.folderKey === "inbox" || !S.folderKey ? "Inbox" : (ROLE_META[S.folderKey]?.[1] || folderByKey(S.folderKey)?.label || "Mail")}${u ? ` (${u})` : ""} - ${S.me?.email || ""} - ${S.config.app_name || "Mail"}`;
}

// ---------------------------------------------------------------- routing
// #/inbox  #/inbox/p2  #/f/Name  #/search/<q>  #/<key>/m/<uid>  #/module/<name>
function route() {
  const parts = location.hash.replace(/^#\/?/, "").split("/");
  let key = parts[0] || "inbox", rest = parts.slice(1);
  if (key === "module") return showModule(rest[0]);
  if (key === "admin") { $$(".folder").forEach((a) => a.classList.toggle("active", a.getAttribute("href") === "#/admin")); return showModule("admin", rest[0]); }
  let q = "";
  if (key === "f") { key = "f/" + rest[0]; rest = rest.slice(1); }
  if (key === "search") { q = decodeURIComponent(rest[0] || ""); rest = rest.slice(1); key = S.folderKey && S.folderKey !== "search" ? S.folderKey : "inbox"; S.searchMode = true; } else S.searchMode = false;
  const f = folderByKey(key);
  if (!f) { location.hash = "#/inbox"; return; }
  const changed = key !== S.folderKey || f.name !== S.folder;
  S.folderKey = key; S.folder = f.name;
  S.baseQ = key === "starred" ? "is:starred" : "";
  if (S.searchMode) { S.q = q; $("#search").value = q; } else if (changed || !S.searchMode) { S.q = ""; if (!S.searchMode) $("#search").value = ""; }
  let page = 0, uid = null;
  if (rest[0] && /^p\d+$/.test(rest[0])) page = parseInt(rest[0].slice(1)) - 1;
  if (rest[0] === "m") uid = parseInt(rest[1]);
  $$(".folder").forEach((a) => a.classList.toggle("active", a.getAttribute("href") === `#/${key}`));
  updateTitle();
  if (uid) { if (changed || !S.list.length) { S.page = page; loadList(false); } openMessage(uid); }
  else { if (page !== S.page || changed || S.view !== "list" || S.q !== S.lastQ) { S.page = page; S.selected.clear(); } showList(); loadList(); }
}
window.addEventListener("hashchange", route);
const listHash = () => S.searchMode ? `#/search/${encodeURIComponent(S.q)}` : `#/${S.folderKey}${S.page ? "/p" + (S.page + 1) : ""}`;

// ---------------------------------------------------------------- list
function setView(v) { S.view = v; $("#app").dataset.view = v; }
function showList() {
  setView("list"); S.current = null;
  $("#list-view").classList.remove("hidden");
  $("#msg-view").classList.add("hidden");
  $("#module-view").classList.add("hidden");
}
let listSeq = 0;
async function loadList(render = true) {
  const seq = ++listSeq;
  const query = [S.baseQ, S.q].filter(Boolean).join(" ");
  S.lastQ = S.q;
  const listEl = $("#list");
  if (render && !S.list.length) listEl.innerHTML = `<div class="loading-bar"></div>`;
  else if (render) listEl.insertAdjacentHTML("afterbegin", `<div class="loading-bar" style="position:sticky;top:0"></div>`);
  try {
    const r = await api("/api/messages?" + qs({ folder: S.folder, page: S.page, q: query }));
    if (seq !== listSeq) return;
    S.list = r.messages; S.total = r.total; S.pageSize = r.page_size || S.settings.page_size || 50;
    if (render || S.view === "list") renderList();
  } catch (e) { if (seq === listSeq) { listEl.innerHTML = `<div class="empty">${icon("error")}<p>${esc(e.message)}</p><button class="btn outline" id="retry">Try again</button></div>`; $("#retry") && ($("#retry").onclick = () => loadList()); } fail(e); }
}
function isOutgoing() { const f = folderByKey(S.folderKey); return f && (f.role === "sent" || f.role === "drafts"); }
function renderList() {
  const listEl = $("#list");
  const banner = $("#search-banner");
  if (S.searchMode) { banner.classList.remove("hidden"); banner.innerHTML = `Search results for <b>${esc(S.q)}</b> in ${esc(ROLE_META[S.folderKey]?.[1] || S.folder)} · <a href="#/${S.folderKey}">Clear search</a>`; }
  else banner.classList.add("hidden");
  const start = S.total ? S.page * S.pageSize + 1 : 0, end = Math.min(S.total, (S.page + 1) * S.pageSize);
  $("#pager-text").textContent = S.total ? `${start}–${end} of ${S.total.toLocaleString()}` : "";
  $("#prev-page").disabled = S.page === 0;
  $("#next-page").disabled = end >= S.total;
  if (!S.list.length) {
    const msg = S.searchMode ? "No messages matched your search" : S.folderKey === "inbox" ? "Your inbox is empty. Enjoy your day!" : S.folderKey === "starred" ? "No starred messages. Stars let you give messages a special status to make them easier to find." : "No conversations in this folder";
    listEl.innerHTML = `<div class="empty">${icon(S.folderKey === "inbox" ? "inbox" : "mail")}<p>${esc(msg)}</p></div>`;
    updateBulk(); return;
  }
  const out = isOutgoing(), drafts = S.folderKey === "drafts";
  const frag = document.createDocumentFragment();
  S.list.forEach((m, i) => {
    const people = out ? "To: " + (m.to.map(who).join(", ") || "(no recipients)") : who(m.from[0]) || "(unknown sender)";
    const row = h(`<div class="row ${m.seen ? "" : "unread"} ${S.selected.has(m.uid) ? "selected" : ""} ${i === S.focus ? "focused" : ""}" role="listitem" draggable="true" data-uid="${m.uid}" data-i="${i}">
      <label class="chk-wrap" title="Select"><input type="checkbox" ${S.selected.has(m.uid) ? "checked" : ""} aria-label="Select"></label>
      <button class="icon-btn star ${m.flagged ? "on" : ""}" title="${m.flagged ? "Starred" : "Not starred"}"><i data-icon="${m.flagged ? "star" : "star_border"}"></i></button>
      <div class="from" title="${esc(out ? m.to.map(fullAddr).join(", ") : m.from.map(fullAddr).join(", "))}">${drafts ? '<span class="chip draft">Draft</span> ' : ""}${esc(people)}</div>
      <div class="content"><span class="subject">${esc(m.subject || "(no subject)")}</span><span class="snippet">${m.snippet ? '<span class="dash"> - </span>' + esc(m.snippet) : ""}</span></div>
      ${m.has_attachment ? `<span class="att" title="Has attachment"><i data-icon="attach_file"></i></span>` : ""}
      <div class="date" title="${esc(new Date(m.date).toLocaleString())}">${esc(fmtDate(m.date))}</div>
      <div class="hover-acts">
        <button class="icon-btn" data-a="archive" title="Archive"><i data-icon="archive"></i></button>
        <button class="icon-btn" data-a="delete" title="Delete"><i data-icon="delete"></i></button>
        <button class="icon-btn" data-a="${m.seen ? "unread" : "read"}" title="Mark as ${m.seen ? "unread" : "read"}"><i data-icon="${m.seen ? "mail" : "drafts"}"></i></button>
      </div></div>`);
    frag.append(row);
  });
  listEl.innerHTML = "";
  listEl.append(frag);
  updateBulk();
}
$("#list").addEventListener("click", (e) => {
  const row = e.target.closest(".row"); if (!row) return;
  const uid = +row.dataset.uid, m = S.list.find((x) => x.uid === uid);
  if (e.target.closest(".chk-wrap")) { if (e.target.tagName === "INPUT") toggleSelect(uid, e.target.checked, e.shiftKey ? +row.dataset.i : null); return; }
  if (e.target.closest(".star")) { e.stopPropagation(); toggleStar(m); return; }
  const act = e.target.closest("[data-a]");
  if (act) { e.stopPropagation(); bulkAction(act.dataset.a, [uid]); return; }
  S.focus = +row.dataset.i;
  if (S.folderKey === "drafts") { openDraft(m); return; }
  location.hash = `#/${S.folderKey}/m/${uid}`;
});
$("#list").addEventListener("dragstart", (e) => {
  const row = e.target.closest(".row"); if (!row) return;
  const uid = +row.dataset.uid;
  const uids = S.selected.has(uid) ? [...S.selected] : [uid];
  e.dataTransfer.setData("text/x-zoltis-uids", JSON.stringify(uids));
  e.dataTransfer.effectAllowed = "move";
  const g = h(`<div style="position:fixed;top:-100px;background:var(--primary);color:#fff;padding:8px 16px;border-radius:8px;font:500 14px var(--font)">Move ${uids.length} conversation${uids.length > 1 ? "s" : ""}</div>`);
  document.body.append(g); e.dataTransfer.setDragImage(g, 0, 0); setTimeout(() => g.remove(), 0);
});
let lastSelIdx = null;
function toggleSelect(uid, on, shiftIdx) {
  const idx = S.list.findIndex((m) => m.uid === uid);
  if (shiftIdx !== null && lastSelIdx !== null) {
    const [a, b] = [Math.min(lastSelIdx, idx), Math.max(lastSelIdx, idx)];
    for (let i = a; i <= b; i++) on ? S.selected.add(S.list[i].uid) : S.selected.delete(S.list[i].uid);
  } else on ? S.selected.add(uid) : S.selected.delete(uid);
  lastSelIdx = idx;
  $$("#list .row").forEach((r) => { const s = S.selected.has(+r.dataset.uid); r.classList.toggle("selected", s); $("input", r).checked = s; });
  updateBulk();
}
function updateBulk() {
  const n = S.selected.size;
  $("#bulk-actions").classList.toggle("hidden", n === 0);
  $("#refresh-btn").classList.toggle("hidden", n > 0);
  const all = $("#select-all");
  all.checked = n > 0 && n === S.list.length; all.indeterminate = n > 0 && n < S.list.length;
}
$("#select-all").onchange = (e) => { S.selected = new Set(e.target.checked ? S.list.map((m) => m.uid) : []); renderList(); };
$("#bulk-actions").addEventListener("click", (e) => { const b = e.target.closest("[data-act]"); if (b) bulkAction(b.dataset.act, [...S.selected], b); });
$("#refresh-btn").onclick = () => { loadList(); loadFolders().catch(() => {}); };
$("#prev-page").onclick = () => { if (S.page > 0) { S.page--; location.hash = listHash(); } };
$("#next-page").onclick = () => { S.page++; location.hash = listHash(); };

// ---------------------------------------------------------------- actions
async function toggleStar(m, render = true) {
  m.flagged = !m.flagged;
  if (render) renderList();
  try { await api("/api/messages/flags", { method: "POST", body: { folder: S.folder, uids: [m.uid], flag: "flagged", value: m.flagged } }); }
  catch (e) { m.flagged = !m.flagged; render && renderList(); fail(e); }
}
async function setSeen(uids, value) {
  for (const m of S.list) if (uids.includes(m.uid)) m.seen = value;
  renderList();
  try { await api("/api/messages/flags", { method: "POST", body: { folder: S.folder, uids, flag: "seen", value } }); loadFolders().catch(() => {}); } catch (e) { fail(e); }
}
async function moveMessages(uids, dest, label, undoable = true) {
  const removed = S.list.filter((m) => uids.includes(m.uid));
  S.list = S.list.filter((m) => !uids.includes(m.uid));
  S.total -= removed.length;
  uids.forEach((u) => S.selected.delete(u));
  if (S.view === "list") renderList();
  try {
    const r = await api("/api/messages/move", { method: "POST", body: { folder: S.folder, uids, dest } });
    const n = removed.length;
    snack(`${label || "Moved"}${n > 1 ? ` (${n} conversations)` : ""}`, undoable ? "Undo" : null, undoable ? () => undoMove(removed, r.dest) : null);
    loadFolders().catch(() => {});
    if (S.list.length < 5 && S.total > 0) loadList();
  } catch (e) { fail(e); loadList(); }
}
async function undoMove(msgs, from) {
  try {
    await api("/api/messages/restore", { method: "POST", body: { from, to: S.folder, message_ids: msgs.map((m) => m.message_id).filter(Boolean) } });
    snack("Action undone"); loadList(); loadFolders();
  } catch (e) { fail(e); }
}
async function bulkAction(act, uids, anchor) {
  if (!uids.length) return;
  const f = folderByKey(S.folderKey);
  switch (act) {
    case "archive": {
      if (f && f.role === "archive") return snack("Already archived");
      return moveMessages(uids, "role:archive", "Conversation archived");
    }
    case "spam": return moveMessages(uids, "role:junk", "Conversation marked as spam");
    case "notspam": return moveMessages(uids, "INBOX", "Conversation moved to Inbox");
    case "delete": {
      if (f && (f.role === "trash" || f.role === "junk")) {
        if (!confirm(`Delete ${uids.length} conversation(s) forever?`)) return;
        S.list = S.list.filter((m) => !uids.includes(m.uid)); uids.forEach((u) => S.selected.delete(u)); renderList();
        try { await api("/api/messages/delete", { method: "POST", body: { folder: S.folder, uids } }); snack("Deleted forever"); loadFolders(); loadQuota(); } catch (e) { fail(e); loadList(); }
        return;
      }
      return moveMessages(uids, "role:trash", "Conversation moved to Trash");
    }
    case "read": return setSeen(uids, true);
    case "unread": return setSeen(uids, false);
    case "move": return folderPicker(anchor || $("#bulk-actions"), (dest) => moveMessages(uids, dest, `Moved to ${dest}`));
  }
}

// ---------------------------------------------------------------- message view
let msgSeq = 0;
async function openMessage(uid) {
  const seq = ++msgSeq;
  setView("msg");
  $("#list-view").classList.add("hidden");
  $("#module-view").classList.add("hidden");
  $("#msg-view").classList.remove("hidden");
  const sc = $("#msg-scroll");
  sc.innerHTML = `<div class="loading-bar"></div>`;
  try {
    const m = await api("/api/message?" + qs({ folder: S.folder, uid }));
    if (seq !== msgSeq) return;
    S.current = m;
    const li = S.list.find((x) => x.uid === uid);
    if (li) { if (!li.seen) { li.seen = true; loadFolders().catch(() => {}); } li.message_id = m.message_id; }
    renderMessage(m);
  } catch (e) { if (seq === msgSeq) sc.innerHTML = `<div class="empty">${icon("error")}<p>${esc(e.message)}</p></div>`; fail(e); }
}
function renderMessage(m, images = false) {
  const sc = $("#msg-scroll");
  const f = folderByKey(S.folderKey);
  const fromP = m.from[0] || { name: "", email: "" };
  const toMe = m.to.some((x) => x.email.toLowerCase() === S.me.email.toLowerCase());
  const toLine = (toMe && m.to.length === 1 && !m.cc.length) ? "to me" : "to " + [...m.to, ...m.cc].map((p) => p.email.toLowerCase() === S.me.email.toLowerCase() ? "me" : (p.name || p.email).split(" ")[0]).join(", ");
  const folderChip = f && f.role !== "inbox" ? `<span class="chip">${esc(ROLE_META[f.role]?.[1] || f.label || S.folder)}</span>` : `<span class="chip">Inbox</span>`;
  sc.innerHTML = "";
  const el = h(`<div>
    <div class="msg-subject"><h2>${esc(m.subject || "(no subject)")}${folderChip}</h2></div>
    <div class="msg">
      <div class="msg-head">
        ${avatar(fromP, "md")}
        <div class="who">
          <div><b>${esc(fromP.name || fromP.email)}</b> ${fromP.name ? `<span class="addr">&lt;${esc(fromP.email)}&gt;</span>` : ""}</div>
          <div class="to" data-x="details">${esc(toLine)} <i data-icon="expand_more"></i></div>
          <dl class="msg-details hidden">
            <dt>from:</dt><dd>${esc(m.from.map(fullAddr).join(", "))}</dd>
            ${m.reply_to.length ? `<dt>reply-to:</dt><dd>${esc(m.reply_to.map(fullAddr).join(", "))}</dd>` : ""}
            <dt>to:</dt><dd>${esc(m.to.map(fullAddr).join(", "))}</dd>
            ${m.cc.length ? `<dt>cc:</dt><dd>${esc(m.cc.map(fullAddr).join(", "))}</dd>` : ""}
            <dt>date:</dt><dd>${esc(m.date ? new Date(m.date).toLocaleString() : "")}</dd>
            <dt>subject:</dt><dd>${esc(m.subject)}</dd>
          </dl>
        </div>
        <div class="when">${esc(fmtDate(m.date, true))}</div>
        <div class="msg-actions">
          <button class="icon-btn star-btn ${m.flagged ? "on" : ""}" data-x="star" title="Star (s)" style="${m.flagged ? "color:var(--star)" : ""}"><i data-icon="${m.flagged ? "star" : "star_border"}"></i></button>
          <button class="icon-btn" data-x="reply" title="Reply (r)"><i data-icon="reply"></i></button>
          <button class="icon-btn" data-x="more" title="More"><i data-icon="more_vert"></i></button>
        </div>
      </div>
      ${m.blocked_images && !images ? `<div class="img-banner">${icon("image")} Images in this message are hidden to protect your privacy. <button class="btn text" data-x="images">Display images below</button></div>` : ""}
      <div class="msg-body"><iframe sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox" title="Message body" referrerpolicy="no-referrer"></iframe></div>
      ${m.attachments.length ? `<div class="attachments"><h4>${m.attachments.length} attachment${m.attachments.length > 1 ? "s" : ""}${S.config.antivirus ? ' <span class="muted" style="font-weight:400;font-size:12px">· scanned by antivirus</span>' : ""}</h4><div class="att-grid"></div></div>` : ""}
      <div class="reply-bar">
        <button class="btn outline" data-x="reply"><i data-icon="reply"></i>Reply</button>
        ${m.to.length + m.cc.length > 1 ? `<button class="btn outline" data-x="replyall"><i data-icon="reply_all"></i>Reply all</button>` : ""}
        <button class="btn outline" data-x="forward"><i data-icon="forward"></i>Forward</button>
      </div>
    </div></div>`);
  sc.append(el);
  const frame = $("iframe", el);
  const dark = document.documentElement.dataset.theme === "dark";
  frame.srcdoc = `<!DOCTYPE html><html><head><meta charset="utf-8"><base target="_blank"><style>
    html,body{margin:0;padding:0;background:#fff;color:#222;font:14px/1.5 Arial,Helvetica,sans-serif;word-wrap:break-word;overflow-wrap:anywhere}
    body{padding:4px 2px 8px;height:auto!important;min-height:0!important} img{max-width:100%;height:auto} table{max-width:100%} pre{white-space:pre-wrap}
    blockquote{margin:0 0 0 .8ex;border-left:1px solid #ccc;padding-left:1ex;color:#555} a{color:#0b57d0}
    </style></head><body>${m.html}</body></html>`;
  let lastH = 0;
  const fit = () => { try { const d = frame.contentDocument; if (!d || !d.body) return; const hgt = Math.max(40, Math.ceil(d.body.getBoundingClientRect().height) + 16); if (Math.abs(hgt - lastH) > 2) { lastH = hgt; frame.style.height = hgt + "px"; } } catch (e) {} };
  frame.addEventListener("load", () => {
    fit();
    try {
      const d = frame.contentDocument;
      $$("img", d).forEach((i) => i.addEventListener("load", fit));
      new ResizeObserver(fit).observe(d.body);
    } catch (e) {}
  });
  if (dark) frame.style.borderRadius = "8px";
  // attachments
  const grid = $(".att-grid", el);
  if (grid) for (const a of m.attachments) grid.append(attachmentCard(m, a));
  el.addEventListener("click", (e) => {
    const x = e.target.closest("[data-x]"); if (!x) return;
    const a = x.dataset.x;
    if (a === "details") $(".msg-details", el).classList.toggle("hidden");
    else if (a === "images") loadImages(m);
    else if (a === "star") msgAction("star");
    else if (a === "reply") openComposer({ mode: "reply", msg: m });
    else if (a === "replyall") openComposer({ mode: "replyall", msg: m });
    else if (a === "forward") openComposer({ mode: "forward", msg: m });
    else if (a === "print") printMessage(m, frame);
    else if (a === "more") popover(x, [
      { label: "Reply", icon: "reply", onClick: () => openComposer({ mode: "reply", msg: m }) },
      { label: "Reply all", icon: "reply_all", onClick: () => openComposer({ mode: "replyall", msg: m }) },
      { label: "Forward", icon: "forward", onClick: () => openComposer({ mode: "forward", msg: m }) },
      "-",
      { label: "Mark as unread", icon: "mail", onClick: () => msgAction("unread") },
      { label: "Print", icon: "print", onClick: () => printMessage(m, frame) },
      { label: "Show original", icon: "code", onClick: () => window.open("/api/raw?" + qs({ folder: S.folder, uid: m.uid }), "_blank", "noopener") },
      { label: S.folderKey === "junk" ? "Not spam" : "Report spam", icon: "report", onClick: () => msgAction(S.folderKey === "junk" ? "notspam" : "spam") },
    ]);
  });
}
async function loadImages(m) {
  try { const full = await api("/api/message?" + qs({ folder: S.folder, uid: m.uid, images: 1, peek: 1 })); S.current = full; renderMessage(full, true); } catch (e) { fail(e); }
}
function attachmentCard(m, a) {
  const url = "/api/attachment?" + qs({ folder: S.folder, uid: m.uid, part: a.part });
  const isImg = /^image\/(png|jpe?g|gif|webp)$/.test(a.content_type);
  const card = h(`<a class="att-card" href="${url}" target="_blank" rel="noopener" title="${esc(a.filename)}">
    <div class="att-thumb">${isImg && !S.config.antivirus ? `<img src="${url}" alt="" loading="lazy">` : `<i data-icon="${isImg ? "image" : "draft"}"></i>`}</div>
    <div class="att-meta"><span class="nm">${esc(a.filename)}</span><span class="sz">${fmtSize(a.size)}</span>
      <button class="icon-btn sm" title="Download" data-dl><i data-icon="download"></i></button></div></a>`);
  $("[data-dl]", card).onclick = (e) => { e.preventDefault(); e.stopPropagation(); cautionThen(a, () => (location.href = url + "&download=1")); };
  const pol = a.policy || { verdict: "allow" };
  const P = policy();
  if (pol.verdict === "block" && P.incoming_action !== "warn") {
    card.classList.add("infected"); card.removeAttribute("href"); card.title = `Blocked: ${pol.summary}`;
    $(".att-thumb", card).innerHTML = icon("lock");
    $("[data-dl]", card).remove(); $(".att-meta .sz", card).remove();
    card.append(h(`<span class="av-badge infected">${icon("lock")}Blocked</span>`));
    $(".att-meta", card).insertAdjacentHTML("afterend", `<div class="att-sig" title="${esc(pol.summary)}">${esc(pol.summary)}</div>`);
    return card;
  }
  if (pol.verdict !== "allow") {
    card.classList.add("caution");
    card.append(h(`<span class="av-badge error" title="${esc(pol.summary)}">${icon("warning")}Caution</span>`));
    $(".att-meta", card).insertAdjacentHTML("afterend", `<div class="att-sig warn" title="${esc(pol.summary)}">${esc(pol.summary)}</div>`);
    card.addEventListener("click", (e) => { if (e.target.closest("[data-dl]")) return; e.preventDefault(); cautionThen(a, () => window.open(url, "_blank", "noopener")); });
  }
  if (S.config.antivirus) {
    const badge = h(`<span class="av-badge ${pol.verdict !== "allow" ? "right" : ""}">Scanning…</span>`);
    card.append(badge);
    api("/api/scan?" + qs({ folder: S.folder, uid: m.uid, part: a.part })).then((r) => {
      if (r.status === "clean") {
        badge.className = "av-badge clean"; badge.innerHTML = icon("shield") + "Virus-free";
        if (isImg) $(".att-thumb", card).innerHTML = `<img src="${url}" alt="" loading="lazy">`;
      } else if (r.status === "infected") {
        card.classList.add("infected"); badge.className = "av-badge infected"; badge.innerHTML = icon("warning") + "Virus found";
        card.title = `Blocked: ${r.signature}`; card.removeAttribute("href");
        $("[data-dl]", card).remove();
        $(".att-meta .sz", card).remove();
        $(".att-meta", card).insertAdjacentHTML("afterend", `<div class="att-sig">${esc(r.signature)}</div>`);
      } else if (r.status === "error") {
        badge.className = "av-badge error"; badge.innerHTML = icon("warning") + (r.blocked ? "Not scanned · blocked" : "Not scanned");
      } else badge.remove();
      if (pol.verdict !== "allow" && badge.isConnected) badge.classList.add("right");
    }).catch(() => badge.remove());
  }
  return card;
}
function cautionThen(a, go) {
  const pol = a.policy || { verdict: "allow" };
  if (pol.verdict === "allow") return go();
  modal({ title: "Be careful with this file", body: `<p style="display:flex;gap:12px;align-items:flex-start">${icon("warning", "st-warn")}<span><b>${esc(a.filename)}</b><br>${esc(pol.summary)}</span></p><p class="muted">Only open it if you trust the sender and were expecting this file.</p>`,
    buttons: [{ label: "Cancel" }, { label: "Download anyway", cls: "primary", onClick: () => go() }] });
}
function printMessage(m, frame) {
  const w = window.open("", "_blank");
  if (!w) return;
  w.document.write(`<html><head><title>${esc(m.subject)}</title><style>body{font:14px Arial;margin:24px}h1{font-size:20px}.meta{color:#555;border-bottom:1px solid #ccc;padding-bottom:8px;margin-bottom:16px}</style></head><body>
    <h1>${esc(m.subject)}</h1><div class="meta"><b>From:</b> ${esc(m.from.map(fullAddr).join(", "))}<br><b>To:</b> ${esc(m.to.map(fullAddr).join(", "))}<br><b>Date:</b> ${esc(new Date(m.date).toLocaleString())}</div>${m.html}</body></html>`);
  w.document.close(); w.focus(); setTimeout(() => w.print(), 300);
}
async function msgAction(act, anchor) {
  const m = S.current; if (!m) return;
  if (act === "star") {
    const li = S.list.find((x) => x.uid === m.uid) || { uid: m.uid, flagged: m.flagged };
    li.flagged = m.flagged; await toggleStar(li, false); m.flagged = li.flagged; renderMessage(m); return;
  }
  if (act === "unread") { await setSeen([m.uid], false); back(); return; }
  if (act === "original") { window.open("/api/raw?" + qs({ folder: S.folder, uid: m.uid }), "_blank", "noopener"); return; }
  if (act === "print") { printMessage(m); return; }
  const li = S.list.find((x) => x.uid === m.uid);
  if (li) li.message_id = m.message_id; else S.list.push({ uid: m.uid, message_id: m.message_id });
  if (act === "move") return folderPicker(anchor, (dest) => { back(); moveMessages([m.uid], dest, `Moved to ${dest}`); });
  const next = neighbour(m.uid);
  back();
  await bulkAction(act, [m.uid]);
  if (next && false) location.hash = `#/${S.folderKey}/m/${next}`;
}
function neighbour(uid) { const i = S.list.findIndex((x) => x.uid === uid); return S.list[i + 1]?.uid; }
function back() { location.hash = listHash(); }
$("#back-btn").onclick = back;
$("#msg-view .toolbar").addEventListener("click", (e) => { const b = e.target.closest("[data-mact]"); if (b) msgAction(b.dataset.mact, b); });

// ---------------------------------------------------------------- search
$("#search-form").onsubmit = (e) => { e.preventDefault(); doSearch($("#search").value.trim()); };
function doSearch(q) { $("#search-panel").classList.add("hidden"); if (!q) { location.hash = `#/${S.folderKey}`; return; } S.page = 0; location.hash = `#/search/${encodeURIComponent(q)}`; }
$("#search-clear").onclick = () => { $("#search").value = ""; if (S.searchMode) location.hash = `#/${S.folderKey}`; };
$("#search-opts").onclick = () => $("#search-panel").classList.toggle("hidden");
$("#search-go").onclick = () => {
  const parts = [];
  $$("#search-panel [data-op]").forEach((el) => {
    const op = el.dataset.op;
    if (el.type === "checkbox") { if (el.checked) parts.push(op); return; }
    const v = el.value.trim(); if (!v) return;
    if (op === "text") parts.push(v); else parts.push(`${op}:${/\s/.test(v) ? `"${v}"` : v}`);
  });
  $("#search").value = parts.join(" ");
  doSearch($("#search").value);
};
$("#search-reset").onclick = () => $$("#search-panel [data-op]").forEach((el) => (el.type === "checkbox" ? (el.checked = false) : (el.value = "")));

// ---------------------------------------------------------------- attachment policy (client-side pre-check)
const BIDI = /[‪-‮⁦-⁩‎‏]/;
const DECOY = new Set("pdf doc docx xls xlsx ppt pptx txt jpg jpeg png gif mp3 mp4 zip csv rtf htm html".split(" "));
const OPAQUE = new Set("rar 7z arj lzh lha ace zipx cpio z".split(" "));
const DEEP_CHECK = /\.(zip|jar|tar|tgz|tbz2?|txz|gz|bz2|xz|docx|xlsx|pptx|docm|xlsm|pptm|odt|ods|odp)$/i;
function policy() { return S.config.attachments || { enabled: false, blocked_extensions: [] }; }
function nameVerdict(path) {
  const P = policy();
  if (!P.enabled) return { verdict: "allow" };
  const base = path.split("/").pop();
  if (BIDI.test(base)) return { verdict: "block", reason: "file name uses hidden text-direction characters to disguise its type" };
  const stripped = base.replace(/[ .]+$/, "");
  if (stripped !== base && stripped.includes(".")) return { verdict: "block", reason: "file name ends with dots or spaces to hide its real type" };
  const parts = stripped.toLowerCase().split(".").slice(1).filter(Boolean);
  if (!parts.length) return { verdict: "allow" };
  const ext = parts[parts.length - 1];
  if (P.blocked_extensions.includes(ext)) {
    if (parts.length >= 2 && DECOY.has(parts[parts.length - 2])) return { verdict: "block", reason: `disguised program: looks like .${parts[parts.length - 2]} but is .${ext}` };
    return { verdict: "block", reason: `.${ext} files can run code and are blocked for security` };
  }
  if ((P.macro_extensions || []).includes(ext) && P.macro_action !== "allow") return { verdict: P.macro_action, reason: `Office document with macros (.${ext})` };
  if (OPAQUE.has(ext)) return { verdict: "warn", reason: `.${ext} archives can't be inspected` };
  return { verdict: "allow" };
}
function blockedReport(items, title = "Some files weren't attached") {
  if (!items.length) return;
  const rows = items.slice(0, 200).map((x) => `<div class="report-row" style="grid-template-columns:28px 1fr"><span class="st-${x.verdict === "block" ? "fail" : "warn"}">${icon(x.verdict === "block" ? "error" : "warning")}</span><div><b style="word-break:break-all">${esc(x.path)}</b><div class="muted" style="font-size:12px">${esc(x.reason)}</div></div></div>`).join("");
  modal({ title, wide: true, body: `<p>For your security, these files are blocked by your organization's attachment policy (programs, scripts, installers and disguised files).</p>${rows}${items.length > 200 ? `<p class="muted">…and ${items.length - 200} more</p>` : ""}`, buttons: [{ label: "OK", cls: "primary" }] });
}
// Minimal ZIP writer (STORE, UTF-8 names) used to attach whole folders.
const CRC_T = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
function crc32(u8) { let c = 0xffffffff; for (let i = 0; i < u8.length; i++) c = CRC_T[(c ^ u8[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
function makeZip(entries) { // entries: [{path, data:Uint8Array}]
  const enc = new TextEncoder(), chunks = [], central = [];
  let offset = 0;
  const d = new Date(), dosTime = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1), dosDate = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  for (const e of entries) {
    const name = enc.encode(e.path), crc = crc32(e.data), size = e.data.length;
    const lh = new DataView(new ArrayBuffer(30));
    lh.setUint32(0, 0x04034b50, true); lh.setUint16(4, 20, true); lh.setUint16(6, 0x0800, true); lh.setUint16(8, 0, true);
    lh.setUint16(10, dosTime, true); lh.setUint16(12, dosDate, true); lh.setUint32(14, crc, true); lh.setUint32(18, size, true); lh.setUint32(22, size, true);
    lh.setUint16(26, name.length, true); lh.setUint16(28, 0, true);
    chunks.push(new Uint8Array(lh.buffer), name, e.data);
    const ch = new DataView(new ArrayBuffer(46));
    ch.setUint32(0, 0x02014b50, true); ch.setUint16(4, 20, true); ch.setUint16(6, 20, true); ch.setUint16(8, 0x0800, true); ch.setUint16(10, 0, true);
    ch.setUint16(12, dosTime, true); ch.setUint16(14, dosDate, true); ch.setUint32(16, crc, true); ch.setUint32(20, size, true); ch.setUint32(24, size, true);
    ch.setUint16(28, name.length, true); ch.setUint32(42, offset, true);
    central.push(new Uint8Array(ch.buffer), name);
    offset += 30 + name.length + size;
  }
  const cdSize = central.reduce((a, b) => a + b.length, 0);
  const end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, 0x06054b50, true); end.setUint16(8, entries.length, true); end.setUint16(10, entries.length, true);
  end.setUint32(12, cdSize, true); end.setUint32(16, offset, true);
  return new Blob([...chunks, ...central, new Uint8Array(end.buffer)], { type: "application/zip" });
}
// Walk dropped folders (DataTransferItem.webkitGetAsEntry)
function readEntry(entry, prefix, out) {
  return new Promise((resolve) => {
    if (entry.isFile) entry.file((f) => { out.push({ file: f, path: prefix + f.name }); resolve(); }, () => resolve());
    else if (entry.isDirectory) {
      const rd = entry.createReader(), all = [];
      const next = () => rd.readEntries(async (batch) => {
        if (!batch.length) { for (const e of all) await readEntry(e, prefix + entry.name + "/", out); resolve(); }
        else { all.push(...batch); next(); }
      }, () => resolve());
      next();
    } else resolve();
  });
}
async function addFolder(c, folderName, items) { // items: [{file, path}]
  const limit = (S.config.max_upload_mb || 25) * 1048576;
  const blocked = [], ok = [];
  for (const it of items) {
    const v = nameVerdict(it.path);
    if (v.verdict === "block") blocked.push({ path: it.path, ...v }); else ok.push(it);
  }
  if (!ok.length) { blockedReport(blocked, `Folder "${folderName}" wasn't attached`); return; }
  const total = ok.reduce((s, it) => s + it.file.size, 0) + c.attachments.reduce((s, a) => s + a.size, 0);
  if (total > limit) { snack(`Folder "${folderName}" is too large (${fmtSize(total)}). The limit is ${S.config.max_upload_mb || 25} MB.`); return; }
  const a = { name: folderName + ".zip", type: "application/zip", size: total, data: "", reading: true, note: `${ok.length} file${ok.length > 1 ? "s" : ""} from folder` };
  c.attachments.push(a); c.dirty = true; renderAtts(c);
  try {
    const entries = [];
    for (const it of ok) entries.push({ path: it.path, data: new Uint8Array(await it.file.arrayBuffer()) });
    const blob = makeZip(entries);
    a.size = blob.size;
    a.data = await blobToB64(blob);
    a.reading = false;
    await deepCheck(c, a);
  } catch (e) { c.attachments.splice(c.attachments.indexOf(a), 1); snack(`Couldn't attach folder "${folderName}"`); }
  renderAtts(c);
  if (blocked.length) blockedReport(blocked, `Some files in "${folderName}" were left out`);
}
function blobToB64(blob) {
  return new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(String(r.result).split(",")[1] || ""); r.onerror = rej; r.readAsDataURL(blob); });
}
async function deepCheck(c, a) {
  // Server-side inspection of archives / Office files right after attaching, so users learn immediately.
  if (!policy().enabled || !DEEP_CHECK.test(a.name)) return;
  a.checking = true; renderAtts(c);
  try {
    const r = await api("/api/attachments/check", { method: "POST", body: { files: [{ name: a.name, data: a.data }] } });
    const res = r.results[0];
    if (res.verdict === "block") {
      c.attachments.splice(c.attachments.indexOf(a), 1);
      blockedReport(res.findings.filter((f) => f.level === "block").map((f) => ({ path: f.path, reason: f.reason, verdict: "block" })), `"${a.name}" wasn't attached`);
    } else if (res.verdict === "warn") { a.warn = res.summary; }
  } catch (e) { /* server re-checks on send */ }
  a.checking = false; renderAtts(c);
}

// ---------------------------------------------------------------- composer
const composers = [];
function quoteHeader(m) { return `On ${new Date(m.date).toLocaleString(undefined, { weekday: "short", month: "short", day: "numeric", year: "numeric", hour: "numeric", minute: "2-digit" })}, ${esc(fullAddr(m.from[0] || { email: "" }))} wrote:`; }
function openComposer(opts = {}) {
  const { mode = "new", msg } = opts;
  const sig = S.settings.signature ? `<br><br><div class="zoltis-sig">-- <br>${S.settings.signature}</div>` : "";
  const c = { id: Math.random().toString(36).slice(2), to: [], cc: [], bcc: [], subject: "", html: "", attachments: [], fwdAtts: [], draftUid: opts.draftUid || null, dirty: false, mode };
  const me = S.me.email.toLowerCase();
  if (msg && (mode === "reply" || mode === "replyall")) {
    const rt = msg.reply_to.length ? msg.reply_to : msg.from;
    const sentByMe = (msg.from[0]?.email || "").toLowerCase() === me;
    c.to = sentByMe ? [...msg.to] : [...rt];
    if (mode === "replyall") {
      const seen = new Set([me, ...c.to.map((p) => p.email.toLowerCase())]);
      for (const p of [...msg.to, ...msg.cc]) if (!seen.has(p.email.toLowerCase())) { c.cc.push(p); seen.add(p.email.toLowerCase()); }
    }
    c.subject = /^re:/i.test(msg.subject) ? msg.subject : `Re: ${msg.subject}`;
    c.html = `<br>${sig}<br><div class="zoltis-quote">${quoteHeader(msg)}<blockquote>${msg.html}</blockquote></div>`;
    c.inReplyTo = msg.message_id; c.references = msg.references; c.replyUid = msg.uid; c.replyFolder = S.folder;
  } else if (msg && mode === "forward") {
    c.subject = /^fwd?:/i.test(msg.subject) ? msg.subject : `Fwd: ${msg.subject}`;
    c.html = `<br>${sig}<br><div class="zoltis-quote">---------- Forwarded message ---------<br>From: ${esc(fullAddr(msg.from[0] || { email: "" }))}<br>Date: ${esc(new Date(msg.date).toLocaleString())}<br>Subject: ${esc(msg.subject)}<br>To: ${esc(msg.to.map(fullAddr).join(", "))}<br><br>${msg.html}</div>`;
    c.fwdAtts = msg.attachments.filter((a) => !a.inline).map((a) => ({ folder: S.folder, uid: msg.uid, part: a.part, filename: a.filename, size: a.size }));
  } else if (mode === "draft" && opts.draft) {
    const d = opts.draft;
    c.to = d.to; c.cc = d.cc; c.subject = d.subject; c.html = d.html;
    c.fwdAtts = d.attachments.map((a) => ({ folder: S.folder, uid: d.uid, part: a.part, filename: a.filename, size: a.size }));
  } else {
    c.html = sig ? `<br>${sig}` : "";
    if (opts.to) c.to = [{ name: "", email: opts.to }];
  }
  if (composers.length >= 3) closeComposer(composers[0], true);
  const el = h(`<div class="composer" data-id="${c.id}">
    <div class="c-head"><span class="ttl">${mode === "new" || mode === "draft" ? "New Message" : esc(c.subject)}</span>
      <button class="icon-btn" data-c="min" title="Minimize"><i data-icon="minimize"></i></button>
      <button class="icon-btn" data-c="max" title="Full screen"><i data-icon="open_in_full"></i></button>
      <button class="icon-btn" data-c="close" title="Save & close"><i data-icon="close"></i></button></div>
    <div class="c-body">
      <div class="c-row" data-field="to"><label>To</label><div class="chips"><input class="plain" autocomplete="off" aria-label="To"></div>
        <div class="toggles"><span data-c="showcc">Cc</span><span data-c="showbcc">Bcc</span></div></div>
      <div class="c-row hidden" data-field="cc"><label>Cc</label><div class="chips"><input class="plain" autocomplete="off" aria-label="Cc"></div></div>
      <div class="c-row hidden" data-field="bcc"><label>Bcc</label><div class="chips"><input class="plain" autocomplete="off" aria-label="Bcc"></div></div>
      <div class="c-row"><input class="plain subj" placeholder="Subject" aria-label="Subject" value="${esc(c.subject)}"></div>
      <div class="c-editor" contenteditable="true" data-placeholder="" role="textbox" aria-multiline="true" aria-label="Message body"></div>
      <div class="c-atts"></div>
    </div>
    <div class="fmt-bar hidden">
      <button class="icon-btn" data-cmd="bold" title="Bold (Ctrl+B)"><i data-icon="bold"></i></button>
      <button class="icon-btn" data-cmd="italic" title="Italic (Ctrl+I)"><i data-icon="italic"></i></button>
      <button class="icon-btn" data-cmd="underline" title="Underline (Ctrl+U)"><i data-icon="underline"></i></button>
      <button class="icon-btn" data-cmd="insertOrderedList" title="Numbered list"><i data-icon="list_numbered"></i></button>
      <button class="icon-btn" data-cmd="insertUnorderedList" title="Bulleted list"><i data-icon="list_bulleted"></i></button>
      <button class="icon-btn" data-cmd="formatBlock:blockquote" title="Quote"><i data-icon="quote"></i></button>
      <button class="icon-btn" data-cmd="link" title="Insert link (Ctrl+K)"><i data-icon="link"></i></button>
      <button class="icon-btn" data-cmd="removeFormat" title="Remove formatting"><i data-icon="format_clear"></i></button>
    </div>
    <div class="c-foot">
      <button class="btn primary" data-c="send">Send</button>
      <button class="icon-btn" data-c="fmt" title="Formatting options"><span style="font:700 16px serif;text-decoration:underline">A</span></button>
      <button class="icon-btn" data-c="attach" title="Attach files"><i data-icon="attach_file"></i></button>
      <button class="icon-btn" data-c="link" title="Insert link"><i data-icon="link"></i></button>
      <input type="file" multiple hidden class="in-files"><input type="file" webkitdirectory multiple hidden class="in-folder">
      <div class="spacer"></div>
      <span class="muted c-status" style="font-size:12px;margin-right:8px"></span>
      <button class="icon-btn" data-c="discard" title="Discard draft"><i data-icon="delete"></i></button>
    </div></div>`);
  c.el = el;
  const editor = $(".c-editor", el);
  editor.innerHTML = c.html;
  for (const f of ["to", "cc", "bcc"]) {
    setupRecipients(c, f);
    if (c[f].length && f !== "to") $(`[data-field="${f}"]`, el).classList.remove("hidden");
  }
  renderAtts(c);
  $("#composers").prepend(el);
  composers.push(c);
  const markDirty = () => { c.dirty = true; $(".c-status", el).textContent = ""; };
  editor.addEventListener("input", markDirty);
  $(".subj", el).addEventListener("input", (e) => { c.subject = e.target.value; $(".ttl", el).textContent = c.subject || "New Message"; markDirty(); });
  editor.addEventListener("paste", (e) => {
    const files = [...(e.clipboardData?.files || [])];
    if (files.length) { e.preventDefault(); addFiles(c, files); return; }
    const html = e.clipboardData.getData("text/html");
    if (!html) return; // let plain text paste happen
  });
  el.addEventListener("click", (e) => {
    const b = e.target.closest("[data-c]"); if (!b) return;
    const a = b.dataset.c;
    if (a === "min" || (a === undefined)) toggleMin(c);
    else if (a === "max") toggleMax(c);
    else if (a === "close") closeComposer(c);
    else if (a === "send") sendComposer(c);
    else if (a === "attach") popover(b, [
      { label: "Attach files", icon: "attach_file", onClick: () => $(".in-files", el).click() },
      { label: "Attach a folder (sent as .zip)", icon: "folder", onClick: () => $(".in-folder", el).click() },
    ]);
    else if (a === "discard") discardComposer(c);
    else if (a === "fmt") $(".fmt-bar", el).classList.toggle("hidden");
    else if (a === "link") insertLink(editor);
    else if (a === "showcc" || a === "showbcc") { const f = a === "showcc" ? "cc" : "bcc"; const r = $(`[data-field="${f}"]`, el); r.classList.remove("hidden"); $("input", r).focus(); b.classList.add("hidden"); }
  });
  $(".c-head", el).addEventListener("click", (e) => { if (!e.target.closest("button")) toggleMin(c); });
  $(".fmt-bar", el).addEventListener("mousedown", (e) => {
    const b = e.target.closest("[data-cmd]"); if (!b) return;
    e.preventDefault();
    const [cmd, arg] = b.dataset.cmd.split(":");
    if (cmd === "link") insertLink(editor); else document.execCommand(cmd, false, arg || null);
    markDirty();
  });
  $(".in-files", el).onchange = (e) => { addFiles(c, [...e.target.files]); e.target.value = ""; };
  $(".in-folder", el).onchange = (e) => {
    const files = [...e.target.files];
    if (files.length) {
      const root = (files[0].webkitRelativePath || files[0].name).split("/")[0] || "folder";
      addFolder(c, root, files.map((f) => ({ file: f, path: f.webkitRelativePath || f.name })));
    }
    e.target.value = "";
  };
  el.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); sendComposer(c); }
    else if (e.key === "Escape") { e.preventDefault(); closeComposer(c); }
    else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k" && e.target === editor) { e.preventDefault(); insertLink(editor); }
  });
  // drag & drop files
  let dz;
  el.addEventListener("dragover", (e) => { if ([...e.dataTransfer.types].includes("Files")) { e.preventDefault(); if (!dz) { dz = h(`<div class="drop-zone">Drop files here</div>`); el.append(dz); } } });
  el.addEventListener("dragleave", (e) => { if (dz && !el.contains(e.relatedTarget)) { dz.remove(); dz = null; } });
  el.addEventListener("drop", async (e) => {
    if (dz) { dz.remove(); dz = null; }
    if (!e.dataTransfer.files.length) return;
    e.preventDefault();
    const items = [...(e.dataTransfer.items || [])].map((i) => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
    const plain = [];
    if (!items.length) { addFiles(c, [...e.dataTransfer.files]); return; }
    for (const entry of items) {
      if (entry.isDirectory) { const out = []; await readEntry(entry, "", out); addFolder(c, entry.name, out); }
      else plain.push(entry);
    }
    if (plain.length) { const files = []; for (const p of plain) await new Promise((r) => p.file((f) => { files.push(f); r(); }, r)); addFiles(c, files); }
  });
  c.autosave = setInterval(() => c.dirty && saveDraft(c, true), 15000);
  if (mode === "reply" || mode === "replyall") { editor.focus(); const r = document.createRange(); r.setStart(editor, 0); r.collapse(true); getSelection().removeAllRanges(); getSelection().addRange(r); }
  else if (c.to.length) $(".subj", el).focus(); else $('[data-field="to"] input', el).focus();
  return c;
}
function insertLink(editor) {
  const sel = getSelection(); const range = sel.rangeCount ? sel.getRangeAt(0) : null;
  const url = window.prompt("Link URL", "https://");
  if (!url || !/^(https?:|mailto:)/i.test(url)) return;
  editor.focus();
  if (range) { sel.removeAllRanges(); sel.addRange(range); }
  if (range && !range.collapsed) document.execCommand("createLink", false, url);
  else document.execCommand("insertHTML", false, `<a href="${esc(url)}">${esc(url)}</a>&nbsp;`);
}
function toggleMin(c) { c.el.classList.toggle("min"); c.el.classList.remove("max"); $(".composer-scrim")?.remove(); }
function toggleMax(c) {
  const on = !c.el.classList.contains("max");
  c.el.classList.toggle("max", on); c.el.classList.remove("min");
  $(".composer-scrim")?.remove();
  $('[data-c="max"]', c.el).innerHTML = icon(on ? "close_fullscreen" : "open_in_full");
  if (on) { const s = h(`<div class="composer-scrim"></div>`); s.onclick = () => toggleMax(c); document.body.append(s); }
}
function removeComposer(c) {
  clearInterval(c.autosave);
  c.el.remove(); $(".composer-scrim")?.remove();
  const i = composers.indexOf(c); if (i >= 0) composers.splice(i, 1);
}
function hasContent(c) {
  const text = $(".c-editor", c.el).innerText.replace(/\s|--/g, "");
  const sigText = S.settings.signature ? h(`<div>${S.settings.signature}</div>`).innerText.replace(/\s/g, "") : "";
  return c.to.length || c.cc.length || c.bcc.length || c.subject || c.attachments.length || (text && text !== sigText);
}
async function closeComposer(c, silent) {
  collectComposer(c);
  if (c.dirty && hasContent(c)) { await saveDraft(c); if (!silent) snack("Draft saved", "View drafts", () => (location.hash = "#/drafts")); }
  removeComposer(c);
}
async function discardComposer(c) {
  removeComposer(c);
  if (c.draftUid) { const d = S.folders.find((f) => f.role === "drafts"); if (d) api("/api/messages/delete", { method: "POST", body: { folder: d.name, uids: [c.draftUid] } }).then(() => { loadFolders(); if (S.folderKey === "drafts") loadList(); }).catch(() => {}); }
  snack("Draft discarded");
}
function collectComposer(c) {
  c.html = $(".c-editor", c.el).innerHTML;
  c.subject = $(".subj", c.el).value;
  for (const f of ["to", "cc", "bcc"]) { const inp = $(`[data-field="${f}"] input`, c.el); if (inp.value.trim()) commitRecipient(c, f, inp.value); }
}
function payload(c) {
  return {
    to: c.to.map(fullAddr).join(", "), cc: c.cc.map(fullAddr).join(", "), bcc: c.bcc.map(fullAddr).join(", "),
    subject: c.subject, html: c.html, from_name: S.settings.display_name || "",
    attachments: c.attachments.map((a) => ({ filename: a.name, content_type: a.type, data: a.data })),
    forward_attachments: c.fwdAtts.map((a) => ({ folder: a.folder, uid: a.uid, part: a.part })),
    in_reply_to: c.inReplyTo || "", references: c.references || "",
    reply_folder: c.replyFolder || "", reply_uid: c.replyUid || "", draft_uid: c.draftUid || "",
  };
}
async function saveDraft(c, auto) {
  collectComposer(c);
  if (!hasContent(c)) return;
  if (c.saving) return; c.saving = true;
  const st = $(".c-status", c.el);
  if (st) st.textContent = "Saving…";
  try {
    const r = await api("/api/draft", { method: "POST", body: payload(c) });
    c.draftUid = r.draft_uid; c.dirty = false;
    if (st) st.textContent = "Draft saved";
    if (S.folderKey === "drafts" && S.view === "list") loadList();
    loadFolders().catch(() => {});
  } catch (e) { if (st) st.textContent = "Couldn't save draft"; if (!auto) fail(e); }
  finally { c.saving = false; }
}
async function sendComposer(c) {
  collectComposer(c);
  if (!c.to.length && !c.cc.length && !c.bcc.length) { snack("Please specify at least one recipient."); $('[data-field="to"] input', c.el).focus(); return; }
  const bad = [...c.to, ...c.cc, ...c.bcc].filter((p) => !/^[^@\s<>"]+@[^@\s<>"]+\.[^@\s<>"]+$/.test(p.email));
  if (bad.length) { snack(`The address "${bad[0].email}" is not valid. Please fix it.`); return; }
  if (!c.subject && !confirm("Send this message without a subject?")) return;
  if (c.attachments.some((a) => a.reading || a.checking)) { snack("Please wait, attachments are still being checked…"); return; }
  if (/\battach(ed|ment|ing)\b/i.test(h(`<div>${c.html.split('class="zoltis-quote"')[0]}</div>`)?.innerText || "") && !c.attachments.length && !c.fwdAtts.length && !confirm("You mentioned an attachment but none is attached. Send anyway?")) return;
  const body = payload(c);
  c.el.classList.add("hidden");
  const delay = Math.max(0, +S.settings.undo_send_seconds || 0) * 1000;
  let cancelled = false;
  if (delay) {
    snack("Sending…", "Undo", () => { cancelled = true; c.el.classList.remove("hidden"); snack("Sending undone."); }, delay + 500);
    await sleep(delay);
    if (cancelled) return;
  } else snack("Sending…", null, null, 0);
  try {
    const r = await api("/api/send", { method: "POST", body });
    removeComposer(c);
    snack(r.warnings?.length ? r.warnings[0] : "Message sent", "View message", () => (location.hash = "#/sent"));
    loadFolders().catch(() => {});
    if (["sent", "drafts"].includes(S.folderKey) && S.view === "list") loadList();
  } catch (e) {
    c.el.classList.remove("hidden");
    if (e.status === 422 && !/virus/i.test(e.message)) { modal({ title: "Attachment blocked", body: `<p style="display:flex;gap:12px;align-items:flex-start">${icon("warning", "st-fail")}<span>${esc(e.message)}</span></p><p class="muted">Remove the file and try again. Programs, scripts and disguised files can't be sent.</p>`, buttons: [{ label: "OK", cls: "primary" }] }); markInfected(c, e.message); }
    else if (e.status === 422) { modal({ title: "Virus detected", body: `<p style="display:flex;gap:12px;align-items:flex-start">${icon("warning", "st-fail")}<span>${esc(e.message)}</span></p><p class="muted">Remove the infected file and try again.</p>`, buttons: [{ label: "OK", cls: "primary" }] }); markInfected(c, e.message); }
    else snack("Message not sent: " + e.message, "Retry", () => sendComposer(c), 10000);
  }
}
function markInfected(c, msg) {
  const m = /"([^"]+)"/.exec(msg); if (!m) return;
  c.attachments.forEach((a) => { if (a.name === m[1]) a.bad = true; }); renderAtts(c);
}
function addFiles(c, files) {
  const limit = (S.config.max_upload_mb || 25) * 1048576;
  const blocked = [];
  for (const f of files) {
    const v = nameVerdict(f.name);
    if (v.verdict === "block") { blocked.push({ path: f.name, ...v }); continue; }
    const total = c.attachments.reduce((s, a) => s + a.size, 0) + f.size;
    if (total > limit) { snack(`"${f.name}" is too large. The limit is ${S.config.max_upload_mb || 25} MB in total.`); continue; }
    const a = { name: f.name, type: f.type || "application/octet-stream", size: f.size, data: "", reading: true, warn: v.verdict === "warn" ? v.reason : "" };
    c.attachments.push(a);
    const rd = new FileReader();
    rd.onload = () => { a.data = String(rd.result).split(",")[1] || ""; a.reading = false; renderAtts(c); deepCheck(c, a); };
    rd.onerror = () => { c.attachments.splice(c.attachments.indexOf(a), 1); renderAtts(c); snack(`Couldn't read "${f.name}"`); };
    rd.readAsDataURL(f);
  }
  c.dirty = true; renderAtts(c);
  if (blocked.length) blockedReport(blocked);
}
function renderAtts(c) {
  const box = $(".c-atts", c.el); box.innerHTML = "";
  const all = [...c.fwdAtts.map((a) => ({ ...a, fwd: true, name: a.filename })), ...c.attachments];
  for (const a of all) {
    const st = a.reading ? "uploading…" : a.checking ? "checking…" : fmtSize(a.size) + (a.note ? ` · ${a.note}` : "");
    const chip = h(`<span class="c-att ${a.bad ? "bad" : a.warn ? "warn" : ""}" title="${esc(a.bad ? "Blocked" : a.warn || a.name)}">${a.bad || a.warn ? icon("warning") : a.note ? icon("folder") : ""}<span>${esc(a.name)}</span> <span class="sz">(${esc(st)})</span><button class="icon-btn sm" title="Remove"><i data-icon="close"></i></button></span>`);
    $("button", chip).onclick = () => { if (a.fwd) c.fwdAtts = c.fwdAtts.filter((x) => x.part !== a.part); else c.attachments.splice(c.attachments.indexOf(a), 1); c.dirty = true; renderAtts(c); };
    box.append(chip);
  }
}
// recipients (chips + autocomplete)
function parseAddrList(s) {
  const out = []; const re = /\s*(?:"?([^"<,;]*?)"?\s*<([^>]+)>|([^,;\s]+@[^,;\s]+)|([^,;]+))\s*[,;]?/g; let m;
  while ((m = re.exec(s)) && m[0]) { if (m[2]) out.push({ name: m[1].trim(), email: m[2].trim() }); else if (m[3]) out.push({ name: "", email: m[3].trim() }); else if (m[4] && m[4].trim()) out.push({ name: "", email: m[4].trim() }); }
  return out;
}
function commitRecipient(c, field, text) {
  for (const p of parseAddrList(text)) if (!c[field].some((x) => x.email.toLowerCase() === p.email.toLowerCase())) c[field].push(p);
  $(`[data-field="${field}"] input`, c.el).value = "";
  renderChips(c, field); c.dirty = true;
}
function renderChips(c, field) {
  const wrap = $(`[data-field="${field}"] .chips`, c.el), inp = $("input", wrap);
  $$(".rchip", wrap).forEach((x) => x.remove());
  c[field].forEach((p, i) => {
    const ok = /^[^@\s<>"]+@[^@\s<>"]+\.[^@\s<>"]+$/.test(p.email);
    const chip = h(`<span class="rchip ${ok ? "" : "bad"}" title="${esc(p.email)}"><span>${esc(p.name || p.email)}</span><button title="Remove"><i data-icon="close"></i></button></span>`);
    $("button", chip).onclick = () => { c[field].splice(i, 1); renderChips(c, field); c.dirty = true; };
    wrap.insertBefore(chip, inp);
  });
}
function setupRecipients(c, field) {
  const row = $(`[data-field="${field}"]`, c.el), inp = $("input", row);
  renderChips(c, field);
  let sug = null, items = [], idx = 0, timer;
  const close = () => { sug && sug.remove(); sug = null; };
  const pick = (p) => { c[field].push(p); inp.value = ""; renderChips(c, field); close(); c.dirty = true; inp.focus(); };
  inp.addEventListener("input", () => {
    clearTimeout(timer);
    const v = inp.value;
    if (/[,;]\s*$/.test(v)) { commitRecipient(c, field, v); close(); return; }
    if (!v.trim()) { close(); return; }
    timer = setTimeout(async () => {
      try {
        const r = await api("/api/contacts?" + qs({ q: v.trim() }));
        items = r.contacts.filter((p) => !c[field].some((x) => x.email === p.email)); idx = 0; close();
        if (!items.length || inp.value !== v) return;
        sug = h(`<div class="suggest"></div>`);
        items.forEach((p, i) => { const d = h(`<div class="${i === 0 ? "on" : ""}">${avatar(p)}<span>${esc(p.name || p.email)}<br><small>${esc(p.email)}</small></span></div>`); d.onmousedown = (e) => { e.preventDefault(); pick(p); }; sug.append(d); });
        row.append(sug);
      } catch (e) {}
    }, 150);
  });
  inp.addEventListener("keydown", (e) => {
    if (sug && (e.key === "ArrowDown" || e.key === "ArrowUp")) { e.preventDefault(); idx = (idx + (e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length; $$("div", sug).forEach((d, i) => d.classList.toggle("on", i === idx)); }
    else if ((e.key === "Enter" || e.key === "Tab") && sug && items[idx]) { e.preventDefault(); pick(items[idx]); }
    else if ((e.key === "Enter" || e.key === "Tab" || e.key === ",") && inp.value.trim()) { if (e.key !== "Tab") e.preventDefault(); commitRecipient(c, field, inp.value); close(); }
    else if (e.key === "Backspace" && !inp.value && c[field].length) { c[field].pop(); renderChips(c, field); }
  });
  inp.addEventListener("blur", () => setTimeout(() => { if (inp.value.trim()) commitRecipient(c, field, inp.value); close(); }, 150));
  inp.addEventListener("paste", (e) => { const t = e.clipboardData.getData("text"); if (/[,;\n]/.test(t)) { e.preventDefault(); commitRecipient(c, field, t.replace(/\n/g, ",")); } });
  row.addEventListener("click", (e) => { if (e.target === row || e.target.classList.contains("chips")) inp.focus(); });
}
async function openDraft(m) {
  try {
    const d = await api("/api/message?" + qs({ folder: S.folder, uid: m.uid, images: 1, peek: 1 }));
    openComposer({ mode: "draft", draft: d, draftUid: m.uid });
  } catch (e) { fail(e); }
}
$("#compose-btn").onclick = () => openComposer();
$("#compose-fab").onclick = () => openComposer();
window.addEventListener("beforeunload", (e) => { if (composers.some((c) => c.dirty && hasContent(c))) { e.preventDefault(); e.returnValue = ""; } });

// ---------------------------------------------------------------- settings
function openSettings(tab = "general") {
  const s = { ...S.settings };
  const body = h(`<div>
    <div class="tabs" style="margin:0 0 8px">
      <button class="tab" data-t="general">General</button>
      <button class="tab" data-t="deliver">Deliverability</button>
      <button class="tab" data-t="security">Security</button>
      <button class="tab" data-t="about">About</button>
    </div><div class="t-body"></div></div>`);
  const tb = $(".t-body", body);
  const radios = (name, opts) => `<div class="radio-col">${opts.map(([v, l]) => `<label><input type="radio" name="${name}" value="${v}" ${String(s[name]) === String(v) ? "checked" : ""}> ${l}</label>`).join("")}</div>`;
  const tabs = {
    general: () => {
      tb.innerHTML = `
        <div class="set-row"><b>Your name</b><input class="txt" data-s="display_name" value="${esc(s.display_name)}" placeholder="${esc(S.me.email.split("@")[0])}"></div>
        <div class="set-row"><b>Theme</b>${radios("theme", [["system", "Device default"], ["light", "Light"], ["dark", "Dark"]])}</div>
        <div class="set-row"><b>Density</b>${radios("density", [["default", "Default"], ["comfortable", "Comfortable"], ["compact", "Compact"]])}</div>
        <div class="set-row"><b>Maximum page size</b><div>Show <select data-s="page_size" style="width:auto">${[25, 50, 100].map((n) => `<option ${s.page_size == n ? "selected" : ""}>${n}</option>`).join("")}</select> conversations per page</div></div>
        <div class="set-row"><b>Images</b>${radios("load_images", [["always", "Always display external images"], ["ask", "Ask before displaying external images (protects against tracking)"]])}</div>
        <div class="set-row"><b>Undo send</b><div>Send cancellation period: <select data-s="undo_send_seconds" style="width:auto">${[0, 5, 10, 20, 30].map((n) => `<option value="${n}" ${s.undo_send_seconds == n ? "selected" : ""}>${n}</option>`).join("")}</select> seconds</div></div>
        ${S.me.mail_mode === "bundled" ? `<div class="set-row"><b>Password</b><div><button class="btn outline" type="button" id="chpw">Change password</button></div></div>` : ""}
        <div class="set-row"><b>Signature</b><div><div class="sig-editor" contenteditable="true">${s.signature || ""}</div><div class="muted" style="font-size:12px;margin-top:4px">Appended at the end of all outgoing messages.</div></div></div>`;
      const cp = $("#chpw", tb); if (cp) cp.onclick = changePassword;
    },
    deliver: async () => {
      const dom = S.me.email.split("@")[1];
      tb.innerHTML = `<p>Whether your mail reaches the inbox depends on your domain's DNS records and your mail server's reputation. This check looks at <b>${esc(dom)}</b>.</p>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center"><input class="txt" id="dl-ip" placeholder="Sending IP (optional)" style="max-width:200px"><input class="txt" id="dl-sel" placeholder="DKIM selector (optional)" style="max-width:220px"><button class="btn primary" id="dl-run">${icon("shield")} Run check</button></div><div id="dl-out" style="margin-top:16px"></div>`;
      $("#dl-run", tb).onclick = async () => {
        const out = $("#dl-out", tb); out.innerHTML = `<div class="loading-bar"></div><p class="muted">Checking DNS records…</p>`;
        try {
          const r = await api("/api/deliverability?" + qs({ ip: $("#dl-ip", tb).value.trim(), selector: $("#dl-sel", tb).value.trim() }));
          const ic = { pass: "check", warn: "warning", fail: "error" };
          out.innerHTML = `<div style="display:flex;align-items:baseline;gap:12px"><span class="score ${r.score >= 85 ? "st-pass" : r.score >= 60 ? "st-warn" : "st-fail"}">${r.score}</span><span class="muted">/ 100 · sending IP ${esc(r.ip || "unknown")}</span></div>` +
            r.results.map((x) => `<div class="report-row"><span class="st-${x.status}">${icon(ic[x.status])}</span><b>${esc(x.check)}</b><div>${esc(x.detail)}${x.fix ? `<div class="fix">${esc(x.fix)}</div>` : ""}</div></div>`).join("");
        } catch (e) { out.innerHTML = `<p class="st-fail">${esc(e.message)}</p>`; }
      };
    },
    security: async () => {
      tb.innerHTML = `<div class="loading-bar"></div>`;
      let av = {};
      try { av = await api("/api/antivirus"); } catch (e) {}
      tb.innerHTML = `
        <div class="set-row"><b>Antivirus (ClamAV)</b><div>${!av.enabled ? `<span class="st-warn">${icon("warning")} Disabled by the administrator</span>` :
          av.online ? `<span class="st-pass">${icon("shield")} Active</span><div class="muted" style="font-size:12px;margin-top:4px">${esc(av.version)}</div><div style="margin-top:8px">Incoming attachments: <b>${av.scan_incoming ? "scanned" : "not scanned"}</b><br>Outgoing attachments: <b>${av.scan_outgoing ? "scanned" : "not scanned"}</b><br>If the scanner is unavailable: <b>${av.fail_mode === "block" ? "block files" : "allow files"}</b></div>` :
          `<span class="st-fail">${icon("error")} Scanner offline</span><div class="muted" style="font-size:12px;margin-top:4px">${esc(av.version || "")}</div>`}</div></div>
        <div class="set-row"><b>Attachment blocking</b><div>${(() => { const P = policy(); if (!P.enabled) return `<span class="st-warn">${icon("warning")} Disabled by the administrator</span>`;
          return `<span class="st-pass">${icon("shield")} Active</span>
          <div style="margin-top:8px">Programs, scripts, installers, shortcuts and disguised files are blocked in sent and received mail, including inside zip/tar archives (up to ${esc(String(P.archive_max_depth || 3))} levels) and attached folders.</div>
          <div style="margin-top:6px">Office files with macros: <b>${esc(P.macro_action)}</b> · Password-protected archives: <b>${esc(P.encrypted_archives)}</b> · Risky received files: <b>${P.incoming_action === "warn" ? "warn before download" : "blocked"}</b></div>
          <details style="margin-top:8px"><summary style="cursor:pointer;color:var(--primary)">Blocked file types (${P.blocked_extensions.length})</summary><div style="font:12px ui-monospace,monospace;margin-top:6px;line-height:1.8">${P.blocked_extensions.map((x) => "." + esc(x)).join(" ")}</div></details>`; })()}</div></div>
        <div class="set-row"><b>External images</b><div>Remote images and tracking pixels are blocked until you choose to show them. Links open with no referrer.</div></div>
        <div class="set-row"><b>Message display</b><div>Email HTML is sanitised on the server and shown in an isolated frame where scripts can't run.</div></div>
        <div class="set-row"><b>Session</b><div>Signed in as ${esc(S.me.email)}. <button class="btn text" id="set-logout">Sign out</button></div></div>`;
      $("#set-logout", tb).onclick = logout;
    },
    about: () => {
      const ent = S.me.edition === "enterprise";
      tb.innerHTML = `<div class="set-row"><b>Version</b><div>${esc(S.config.app_name)} ${esc(S.config.version)} · <b>${ent ? "Enterprise" : "Community"} Edition</b>${S.me.licensed_to ? ` · licensed to ${esc(S.me.licensed_to)}` : ""}</div></div>
        <div class="set-row"><b>Mail server</b><div>${S.me.mail_mode === "bundled" ? "Built-in Zoltis mail server (Postfix + Dovecot) running on your own server." : "Connected to your mail server over IMAP (reading) and SMTP (sending)."}</div></div>
        ${S.me.limits ? `<div class="set-row"><b>Edition limits</b><div>${S.me.limits.max_accounts ? `Up to ${S.me.limits.max_accounts} email accounts` : "Unlimited accounts"} · ${S.me.limits.max_quota_mb ? `${S.me.limits.max_quota_mb} MB per mailbox (including attachments)` : "custom mailbox sizes"}${S.me.limits.drive ? "" : " · no Drive storage"}</div></div>` : ""}
        <div class="set-row"><b>Enterprise features</b><div>${[["calendar", "Calendar (CalDAV sync)"], ["drive", "Drive (file storage, share links)"], ["contacts", "Contacts with CardDAV sync"], ["mobile_api", "iOS & Android apps"], ["admin_console", "Admin console & audit log"], ["sso", "Single sign-on (SAML / OIDC)"]].map(([k, l]) => `<div>${S.me.features.includes(k) ? `<span class="st-pass">${icon("check")}</span>` : `<span class="muted">${icon("lock")}</span>`} ${l}</div>`).join("")}</div></div>
        <div class="set-row"><b>Keyboard shortcuts</b><div><button class="btn outline" id="kb">View shortcuts</button></div></div>`;
      $("#kb", tb).onclick = showShortcuts;
    },
  };
  const go = (t) => { collect(); $$(".tab", body).forEach((x) => x.classList.toggle("on", x.dataset.t === t)); body.dataset.tab = t; tabs[t](); };
  const collect = () => {
    if (body.dataset.tab !== "general") return;
    $$("[data-s]", tb).forEach((el) => { const k = el.dataset.s; s[k] = typeof S.settings[k] === "number" ? +el.value : el.value; });
    $$("input[type=radio]:checked", tb).forEach((el) => (s[el.name] = el.value));
    const sig = $(".sig-editor", tb); if (sig) s.signature = sig.innerHTML.trim() === "<br>" ? "" : sig.innerHTML.trim();
  };
  $$(".tab", body).forEach((x) => (x.onclick = () => go(x.dataset.t)));
  const md = modal({ title: "Settings", body, wide: true, buttons: [{ label: "Cancel" }, { label: "Save changes", cls: "primary", onClick: async () => {
    collect();
    try { S.settings = await api("/api/settings", { method: "POST", body: s }); applyTheme(); snack("Settings saved"); if (S.view === "list") loadList(); } catch (e) { fail(e); return false; }
  } }] });
  go(tab);
  return md;
}
$("#settings-btn").onclick = () => openSettings();

function changePassword() {
  const md = modal({ title: "Change password", body: `
    <label class="muted">Current password</label><input class="txt" type="password" id="cp-cur" autocomplete="current-password" style="margin:6px 0 14px">
    <label class="muted">New password (8+ characters)</label><input class="txt" type="password" id="cp-new" autocomplete="new-password" style="margin:6px 0 14px">
    <label class="muted">Confirm new password</label><input class="txt" type="password" id="cp-new2" autocomplete="new-password" style="margin-top:6px">
    <p class="muted" style="font-size:12px">Phones and mail apps signed in with your old password will need the new one.</p>`,
    buttons: [{ label: "Cancel" }, { label: "Change password", cls: "primary", onClick: async (m) => {
      if ($("#cp-new", m).value !== $("#cp-new2", m).value) { snack("New passwords don't match"); return false; }
      try { await api("/api/account/password", { method: "POST", body: { current: $("#cp-cur", m).value, new: $("#cp-new", m).value } }); snack("Password changed"); }
      catch (e) { snack(e.message); return false; }
    } }] });
}
function showShortcuts() {
  const k = [["c", "Compose"], ["/", "Search"], ["j / k", "Older / newer conversation"], ["o / Enter", "Open conversation"], ["u", "Back to list"], ["e", "Archive"], ["#", "Delete"], ["!", "Report spam"], ["s", "Star / unstar"], ["r", "Reply"], ["a", "Reply all"], ["f", "Forward"], ["x", "Select conversation"], ["Shift + i", "Mark as read"], ["Shift + u", "Mark as unread"], ["g then i", "Go to Inbox"], ["g then s", "Go to Starred"], ["g then t", "Go to Sent"], ["g then d", "Go to Drafts"], ["Ctrl + Enter", "Send message"], ["Esc", "Close composer / dialog"], ["?", "Show this help"]];
  modal({ title: "Keyboard shortcuts", wide: true, body: `<div class="kbd-grid">${k.map(([a, b]) => `<div><span>${esc(b)}</span><span>${a.split(" ").map((x) => ["then", "/", "+"].includes(x) && a !== "/" ? ` ${x} ` : `<kbd>${esc(x)}</kbd>`).join("")}</span></div>`).join("")}</div>`, buttons: [{ label: "Close", cls: "primary" }] });
}
$("#help-btn").onclick = showShortcuts;

// ---------------------------------------------------------------- account
$("#account-btn").onclick = () => $("#account-menu").classList.toggle("hidden");
async function logout() {
  for (const c of [...composers]) await closeComposer(c, true);
  try { await api("/api/logout", { method: "POST", noAuthRedirect: true }); } catch (e) {}
  location.hash = ""; location.reload();
}
$("#logout-btn").onclick = logout;
$("#menu-btn").onclick = () => { const a = $("#app"); if (innerWidth <= 900) a.classList.toggle("drawer"); else a.classList.toggle("collapsed"); };
$("#scrim").onclick = () => $("#app").classList.remove("drawer");

// ---------------------------------------------------------------- storage meter
async function loadQuota() {
  try {
    const r = await api("/api/account/quota");
    const q = r.quota, box = $("#storage");
    if (!q || !q.limit_mb) { box.classList.add("hidden"); S.quota = null; return; }
    S.quota = q;
    box.classList.remove("hidden");
    const pct = Math.min(100, q.percent);
    const fill = $("#storage-fill");
    fill.style.width = Math.max(2, pct) + "%";
    box.classList.toggle("warn", pct >= 80 && pct < 95);
    box.classList.toggle("full", pct >= 95);
    const fmt = (mb) => mb >= 1024 ? (mb / 1024).toFixed(2) + " GB" : mb > 0 && mb < 10 ? Math.max(0.1, mb).toFixed(1) + " MB" : Math.round(mb) + " MB";
    $("#storage-text").textContent = `${fmt(q.used_mb)} of ${fmt(q.limit_mb)} used`;
    box.title = pct >= 95 ? "Your mailbox is almost full. New mail may bounce. Empty Trash or delete large messages." : `Mailbox storage: ${q.percent}% used`;
  } catch (e) { /* ignore */ }
}

// ---------------------------------------------------------------- enterprise modules
const MODULES = { calendar: ["calendar", "Calendar"], contacts: ["contacts", "Contacts"], drive: ["cloud", "Drive"] };
function renderEnterpriseNav() {
  const nav = $("#enterprise-nav"); nav.innerHTML = "";
  if (S.me.is_admin) nav.append(folderEl({ key: "admin", icon: "shield", label: "Admin console" }));
  for (const [k, [ic, label]] of Object.entries(MODULES)) if ((S.me.features || []).includes(k)) nav.append(folderEl({ key: "module/" + k, icon: ic, label }));
}
function showModule(name, sub) {
  setView("module");
  $("#list-view").classList.add("hidden"); $("#msg-view").classList.add("hidden");
  const v = $("#module-view"); v.classList.remove("hidden");
  S.folderKey = name;
  if (window.ZoltisModules && window.ZoltisModules[name]) { window.ZoltisModules[name](v, { api, snack, S, sub }); return; }
  v.innerHTML = `<div class="ent-card">${icon(MODULES[name]?.[0] || "lock")}<h3>${esc(MODULES[name]?.[1] || name)}</h3><p>This module is part of the Enterprise Edition.</p></div>`;
}

// ---------------------------------------------------------------- keyboard
let gPrefix = false;
document.addEventListener("keydown", (e) => {
  if ($("#app").classList.contains("hidden")) return;
  const t = e.target;
  if (t.closest && (t.closest("input, textarea, select, [contenteditable=true], .composer") || t.isContentEditable)) return;
  if ($(".modal-bg")) return;
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  const k = e.key;
  if (gPrefix) {
    gPrefix = false;
    const map = { i: "inbox", s: "starred", t: "sent", d: "drafts", a: "archive" };
    if (map[k]) { e.preventDefault(); location.hash = "#/" + map[k]; }
    return;
  }
  const inMsg = S.view === "msg" && S.current;
  const focused = S.list[S.focus];
  const target = inMsg ? [S.current.uid] : S.selected.size ? [...S.selected] : focused ? [focused.uid] : [];
  const setFocus = (i) => { S.focus = Math.max(0, Math.min(S.list.length - 1, i)); $$("#list .row").forEach((r) => r.classList.toggle("focused", +r.dataset.i === S.focus)); $(`#list .row[data-i="${S.focus}"]`)?.scrollIntoView({ block: "nearest" }); };
  switch (k) {
    case "c": e.preventDefault(); openComposer(); break;
    case "/": e.preventDefault(); $("#search").focus(); break;
    case "?": showShortcuts(); break;
    case "g": gPrefix = true; setTimeout(() => (gPrefix = false), 1500); break;
    case "j": case "k": {
      if (inMsg) { const i = S.list.findIndex((m) => m.uid === S.current.uid) + (k === "j" ? 1 : -1); if (S.list[i]) { S.focus = i; location.hash = `#/${S.folderKey}/m/${S.list[i].uid}`; } }
      else setFocus(S.focus + (k === "j" ? 1 : -1));
      break;
    }
    case "o": case "Enter": if (!inMsg && focused) { if (S.folderKey === "drafts") openDraft(focused); else location.hash = `#/${S.folderKey}/m/${focused.uid}`; } break;
    case "u": if (inMsg) back(); break;
    case "e": if (inMsg) msgAction("archive"); else bulkAction("archive", target); break;
    case "#": if (inMsg) msgAction("delete"); else bulkAction("delete", target); break;
    case "!": if (inMsg) msgAction("spam"); else bulkAction("spam", target); break;
    case "s": if (inMsg) msgAction("star"); else if (focused) toggleStar(focused); break;
    case "x": if (!inMsg && focused) toggleSelect(focused.uid, !S.selected.has(focused.uid), null); break;
    case "r": if (inMsg) { e.preventDefault(); openComposer({ mode: "reply", msg: S.current }); } break;
    case "a": if (inMsg) { e.preventDefault(); openComposer({ mode: "replyall", msg: S.current }); } break;
    case "f": if (inMsg) { e.preventDefault(); openComposer({ mode: "forward", msg: S.current }); } break;
    case "I": bulkAction("read", target); break;
    case "U": if (inMsg) msgAction("unread"); else bulkAction("unread", target); break;
  }
});

// ---------------------------------------------------------------- polling & notifications
let pollTimer = null;
function startPolling() {
  stopPolling();
  pollTimer = setInterval(async () => {
    if (document.hidden && Notification?.permission !== "granted") return;
    try {
      const prev = S.folders.find((f) => f.role === "inbox")?.unread ?? 0;
      await loadFolders();
      loadQuota();
      const now = S.folders.find((f) => f.role === "inbox")?.unread ?? 0;
      if (now > prev) {
        if (S.view === "list" && S.page === 0 && !S.selected.size) loadList(false).then(renderList);
        if (document.hidden && window.Notification && Notification.permission === "granted")
          new Notification(`${S.config.app_name || "Mail"}: ${now - prev} new message${now - prev > 1 ? "s" : ""}`, { icon: "/img/logo.svg" });
      }
    } catch (e) {}
  }, 60000);
}
function stopPolling() { if (pollTimer) clearInterval(pollTimer); pollTimer = null; }

window.ZoltisMail = { api, openComposer, snack, state: S, modal, popover, esc, icon: (n, c) => icon(n, c), h, fmtSize, avatar, qs, colorFor, initial, fmtDate, fail };
boot();
})();
