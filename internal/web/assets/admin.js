"use strict";

(() => {
  const { h, icon, clear } = V;
  const app = document.getElementById("app");

  const CATS = {
    ads: ["Ads", "Ad networks in apps and websites."],
    trackers: ["Trackers", "Companies following people around the web."],
    malware: ["Malware and scams", "Known dangerous and phishing sites."],
    adult: ["Adult content", "Adult websites."],
    gambling: ["Gambling", "Betting and casino sites."],
    social: ["Social media", "Facebook, TikTok, Instagram and others."]
  };
  const UPSTREAMS = [
    ["recursive", "Private", "Your server asks directly"],
    ["quad9", "Quad9", "Encrypted, Swiss"],
    ["mullvad", "Mullvad", "Encrypted, Swedish"],
    ["cloudflare", "Cloudflare", "Encrypted, fast"]
  ];
  const REG = {
    invite: ["Invite only", "People need an invite code from you.", "ticket"],
    open: ["Anyone with the app", "Anyone who knows your address can create an account.", "globe"],
    closed: ["Only accounts I create", "You make every account yourself.", "user"]
  };
  const PAGES = [
    ["overview", "Overview", "grid"],
    ["accounts", "Accounts", "users"],
    ["invites", "Invites", "ticket"],
    ["settings", "Settings", "sliders"],
    ["security", "Security", "shieldCheck"],
    ["backup", "Backup", "archive"]
  ];

  let sess = null;
  let page = "overview";
  let pageEl = null;
  let navBtns = {};
  let poll = 0;
  const samples = [];

  async function api(method, url, body, extra) {
    const r = await V.api(method, url, body, extra);
    if (r.status === 401 && !url.endsWith("/login")) {
      sess = null;
      login("You were signed out. Please sign in again.");
    }
    if (r.data && r.data.csrf) V.state.csrf = r.data.csrf;
    return r;
  }

  function dialog(title, body, actions) {
    const d = h("dialog", { "aria-label": title }, h("div", { class: "dlg" }, h("h2", { text: title }), ...body, actions && actions.length ? h("div", { class: "actions" }, ...actions) : null));
    document.body.append(d);
    d.addEventListener("close", () => d.remove());
    d.showModal();
    return d;
  }

  function confirmDlg(title, text, okLabel, danger) {
    return new Promise((resolve) => {
      let ok = false;
      const yes = h("button", { class: "btn " + (danger ? "btn-danger" : "btn-primary"), type: "button" }, h("span", { text: okLabel }));
      const no = h("button", { class: "btn btn-ghost", type: "button", text: "Cancel" });
      const d = dialog(title, [h("p", { class: "muted", text })], [no, yes]);
      yes.addEventListener("click", () => { ok = true; d.close(); });
      no.addEventListener("click", () => d.close());
      d.addEventListener("close", () => resolve(ok));
    });
  }

  function secretDlg(title, value, note, grouped) {
    const close = h("button", { class: "btn btn-primary", type: "button", text: "Done" });
    const d = dialog(title, [
      h("div", { class: "code-box" }, h("div", { class: "val", text: grouped ? V.groupNumber(value) : value }), h("button", { class: "btn btn-ghost btn-small", type: "button", onclick: () => V.copy(value) }, icon("copy"), "Copy")),
      V.callout("warn", "", note)
    ], [close]);
    close.addEventListener("click", () => d.close());
  }

  function errSlot() { return h("div", { "aria-live": "assertive" }); }
  function showErr(slot, msg) { clear(slot).append(V.callout("err", "", msg)); }

  function field(label, input, hint) {
    if (!input.id) input.id = "f" + Math.random().toString(36).slice(2, 8);
    return h("div", { class: "field" }, h("label", { class: "label", for: input.id, text: label }), input, hint ? h("p", { class: "hint", text: hint }) : null);
  }

  function selectEl(options, value) {
    const s = h("select", { class: "select" });
    options.forEach(([v, t]) => s.append(h("option", { value: String(v), text: t, selected: String(v) === String(value) })));
    return s;
  }

  function login(msg) {
    clearInterval(poll);
    const err = errSlot();
    const pw = h("input", { class: "input", id: "pw", type: "password", autocomplete: "current-password", placeholder: "Admin password" });
    const code = h("input", { class: "input mono", id: "code", type: "text", inputmode: "numeric", autocomplete: "one-time-code", maxlength: "7", placeholder: "123 456" });
    const needCode = sess && sess.totp_required;
    const btn = h("button", { class: "btn btn-primary btn-block", type: "submit" }, h("span", { text: "Sign in" }), icon("arrowR"));
    btn.dataset.busy = "Signing in…";
    const form = h("form", { class: "card", novalidate: true },
      field("Password", pw),
      needCode ? field("Code from your authenticator app", code) : null,
      err,
      btn
    );
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      V.busy(btn, async () => {
        if (!pw.value) { pw.focus(); showErr(err, "Enter your admin password."); return; }
        const r = await api("POST", "/v1/admin/login", { password: pw.value, totp: needCode ? code.value.replace(/\s/g, "") : "" });
        if (!r.ok) { showErr(err, r.error); pw.select(); return; }
        await boot();
      });
    });
    const body = [];
    if (sess && !sess.admin_set) {
      body.push(V.callout("warn", "Setup isn't finished", "Finish setup with the link from the installer, then come back here."));
    }
    clear(app).append(h("div", { class: "centered" }, h("div", { class: "login" },
      h("span", { class: "brand" }, V.logo(), h("span", { text: (sess && sess.name) || "Veyl" })),
      h("div", null, h("h1", { text: "Admin sign in" }), h("p", { class: "muted mt-s", text: msg || "Manage accounts, invites and settings." })),
      ...body,
      form,
      h("p", { class: "foot", text: "Forgot your password? Run \"sudo veyl admin reset-password\" on the server." })
    )));
    pw.focus();
  }

  async function logout() {
    await api("POST", "/v1/admin/logout", {});
    sess = null;
    const s = await api("GET", "/v1/admin/session");
    sess = s.data;
    login("Signed out.");
  }

  function shell() {
    navBtns = {};
    const nav = h("nav", { class: "nav", "aria-label": "Sections" });
    PAGES.forEach(([id, label, ic]) => {
      const b = h("button", { type: "button", onclick: () => { location.hash = id; } }, icon(ic), h("span", { text: label }));
      navBtns[id] = b;
      nav.append(b);
    });
    pageEl = h("main", { class: "main", id: "page" });
    const out = h("button", { class: "btn btn-quiet btn-small signout", type: "button", onclick: logout }, icon("logout"), h("span", { text: "Sign out" }));
    const side = h("aside", { class: "side" },
      h("div", { class: "side-head" }, h("span", { class: "brand" }, V.logo(), h("span", { text: sess.name || "Veyl" })), h("span", { class: "who", text: sess.host || "" }), out),
      nav,
      h("div", { class: "side-foot" }, h("button", { class: "btn btn-quiet btn-small", type: "button", onclick: logout }, icon("logout"), h("span", { text: "Sign out" })), h("p", { class: "foot", text: "Veyl " + (sess.version || "") }))
    );
    clear(app).append(h("div", { class: "shell" }, side, pageEl));
    route();
  }

  function route() {
    const want = location.hash.replace(/^#/, "");
    page = PAGES.some((p) => p[0] === want) ? want : "overview";
    Object.keys(navBtns).forEach((k) => {
      if (k === page) navBtns[k].setAttribute("aria-current", "page");
      else navBtns[k].removeAttribute("aria-current");
    });
    if (navBtns[page] && navBtns[page].scrollIntoView) navBtns[page].scrollIntoView({ block: "nearest", inline: "nearest" });
    clearInterval(poll);
    const fn = { overview, accounts, invites, settings, security, backup }[page];
    fn();
  }

  window.addEventListener("hashchange", () => { if (sess && sess.authenticated) route(); });

  function pageShell(title, sub, right) {
    clear(pageEl);
    const p = h("div", { class: "page" }, h("div", { class: "page-head" }, h("div", null, h("h1", { text: title }), sub ? h("p", { text: sub }) : null), right || null));
    pageEl.append(p);
    window.scrollTo(0, 0);
    return p;
  }

  function loading(p) {
    const l = h("div", { class: "empty" }, V.spinner());
    p.append(l);
    return l;
  }

  function uptime(sec) {
    sec = Number(sec) || 0;
    const d = Math.floor(sec / 86400);
    const hh = Math.floor((sec % 86400) / 3600);
    const m = Math.floor((sec % 3600) / 60);
    if (d) return d + "d " + hh + "h";
    if (hh) return hh + "h " + m + "m";
    return m + "m";
  }

  function fmt(n) { return Number(n || 0).toLocaleString(); }

  function graph() {
    const g = h("div", { class: "graph", "aria-hidden": "true" });
    const cols = 32;
    const data = samples.slice(-cols);
    const max = Math.max(4, ...data);
    for (let i = 0; i < cols - data.length; i++) g.append(h("div", { class: "col empty" }, h("i")));
    data.forEach((v) => {
      const n = v === 0 ? 0 : Math.max(1, Math.round((v / max) * 8));
      const col = h("div", { class: "col" + (n === 0 ? " empty" : "") });
      if (n === 0) col.append(h("i"));
      for (let i = 0; i < n; i++) col.append(h("i", { class: i === 0 && n > 1 ? "mid" : "" }));
      g.append(col);
    });
    return g;
  }

  const SYS = [
    ["os", "System"],
    ["public_ip", "Public IP"],
    ["public_ipv6", "Public IPv6"],
    ["openvpn", "OpenVPN"],
    ["openssl", "OpenSSL"],
    ["load", "Load"],
    ["mem", "Memory"],
    ["disk", "Disk"],
    ["uptime", "Server uptime"]
  ];

  function jobBanner(p, kind) {
    const list = V.progressList();
    const bar = h("div", { class: "bar" }, h("i"));
    const title = h("h3", { text: kind === "dns-update" ? "Updating blocklists" : "Applying changes" });
    const card = h("div", { class: "card stack" }, title, bar, list.el);
    p.insertBefore(card, p.children[1] || null);
    V.stream("/v1/admin/apply-progress", (ev) => list.step(ev), (d) => {
      list.settle(!!(d && d.ok));
      bar.className = "bar " + (d && d.ok ? "done" : "fail");
      title.textContent = d && d.ok ? "All done" : "Something didn't finish";
      if (d && !d.ok) card.append(V.callout("err", "", d.error || "Lost contact with the server."));
      V.toast(d && d.ok ? "Done" : "That didn't finish", d && d.ok ? "" : "err");
      setTimeout(() => { if (d && d.ok) card.remove(); }, 4000);
    });
  }

  async function overview() {
    const p = pageShell("Overview", (sess.name || "Veyl") + (sess.host ? " · " + sess.host : ""));
    const l = loading(p);
    const r = await api("GET", "/v1/admin/overview");
    if (!r.ok || page !== "overview") return;
    l.remove();
    const o = r.data;
    samples.push(o.connected);
    if (samples.length > 64) samples.shift();
    const tiles = h("div", { class: "tiles" },
      h("div", { class: "tile hero" }, h("div", { class: "k" }, h("span", { class: "dot on" }), "Connected now"), h("div", { class: "v", text: fmt(o.connected) }), graph(), h("div", { class: "s", text: "Live while this page is open. Nothing is stored." })),
      h("div", { class: "tile" }, h("div", { class: "k", text: "Accounts" }), h("div", { class: "v", text: fmt(o.accounts) })),
      h("div", { class: "tile" }, h("div", { class: "k", text: "Devices" }), h("div", { class: "v", text: fmt(o.devices) })),
      h("div", { class: "tile" }, h("div", { class: "k", text: "Running for" }), h("div", { class: "v", text: uptime(o.uptime) })),
      h("div", { class: "tile" }, h("div", { class: "k", text: "Stealth" }), h("div", { class: "v", text: o.stealth ? "On" : "Off" }))
    );
    const svc = h("div", { class: "card" }, h("h3", { text: "Services" }));
    if (!o.services.length) svc.append(h("p", { class: "hint", text: "The system agent didn't answer. Service status will show when it's running." }));
    o.services.forEach((s) => {
      const good = s.state === "active";
      const off = s.state === "inactive" || s.state === "disabled";
      svc.append(h("div", { class: "svc" }, h("span", { class: "dot " + (good ? "on" : off ? "" : "off") }), h("span", { class: "n", text: s.name }), h("span", { class: "s", text: good ? "Running" : s.state })));
    });
    const sys = h("div", { class: "list" });
    sys.append(h("div", { class: "list-row" }, h("div", { class: "k", text: "Veyl" }), h("div", { class: "v", text: o.version })));
    SYS.forEach(([k, label]) => {
      const v = o.system[k];
      if (!v) return;
      sys.append(h("div", { class: "list-row" }, h("div", { class: "k", text: label }), h("div", { class: "v", text: k === "uptime" ? uptime(v) : v })));
    });
    if (o.cert_expiry) sys.append(h("div", { class: "list-row" }, h("div", { class: "k", text: "Certificate" }), h("div", { class: "v", text: "Renews automatically · expires " + o.cert_expiry })));
    const bl = h("div", { class: "list" });
    o.blocklists.forEach((b) => {
      bl.append(h("div", { class: "list-row" }, h("div", { class: "k", text: (CATS[b.category] || [b.category])[0] }), h("div", { class: "v", text: b.entries ? fmt(b.entries) + " sites" : "Not downloaded yet" }), h("span", { class: "muted small", text: b.updated || "" })));
    });
    const upd = h("button", { class: "btn btn-ghost btn-small", type: "button" }, icon("refresh"), h("span", { text: "Update now" }));
    upd.addEventListener("click", () => V.busy(upd, async () => {
      const x = await api("POST", "/v1/admin/dns/update", {});
      if (!x.ok) { V.toast(x.error, "err"); return; }
      jobBanner(p, "dns-update");
    }));
    p.append(tiles,
      h("div", { class: "grid-2" }, svc, h("div", { class: "stack" }, h("p", { class: "card-title", text: "Server" }), sys)),
      h("div", { class: "stack" }, h("div", { class: "row" }, h("p", { class: "card-title grow", text: "Blocklists" }), upd), bl)
    );
    if (o.job && o.job.running) jobBanner(p, o.job.kind);
    poll = setInterval(async () => {
      if (page !== "overview" || document.hidden) return;
      const x = await api("GET", "/v1/admin/overview");
      if (!x.ok || page !== "overview") return;
      samples.push(x.data.connected);
      if (samples.length > 64) samples.shift();
      const hero = tiles.querySelector(".tile.hero");
      hero.querySelector(".v").textContent = fmt(x.data.connected);
      hero.replaceChild(graph(), hero.querySelector(".graph"));
    }, 15000);
  }

  function avatar(id) {
    const px = h("div", { class: "pixels" });
    let n = parseInt(String(id).slice(0, 6), 16) || 7;
    for (let i = 0; i < 9; i++) {
      px.append(h("i", { class: n & 1 ? "on" : (n & 2 ? "mid" : "") }));
      n = n >> 1 || 5;
    }
    return h("div", { class: "avatar" }, px);
  }

  function statusBadge(s) {
    if (s === "disabled") return h("span", { class: "badge badge-red", text: "Paused" });
    if (s === "expired") return h("span", { class: "badge badge-orange", text: "Expired" });
    return h("span", { class: "badge badge-green", text: "Active" });
  }

  async function accounts() {
    const add = h("button", { class: "btn btn-primary", type: "button", onclick: newAccount }, icon("plus"), h("span", { text: "New account" }));
    const p = pageShell("Accounts", "Everyone who can connect to your VPN.", add);
    const l = loading(p);
    const r = await api("GET", "/v1/admin/accounts");
    if (!r.ok || page !== "accounts") return;
    l.remove();
    const all = r.data.accounts;
    if (!all.length) {
      p.append(h("div", { class: "card empty" }, emptyPixels(), h("p", { text: "No accounts yet." }), h("button", { class: "btn btn-ghost", type: "button", onclick: newAccount }, icon("plus"), "Create the first one")));
      return;
    }
    const q = h("input", { class: "input", type: "search", placeholder: "Search by name", "aria-label": "Search accounts" });
    const list = h("div", { class: "stack" });
    const draw = () => {
      clear(list);
      const term = q.value.trim().toLowerCase();
      const shown = all.filter((a) => !term || (a.label || "").toLowerCase().includes(term) || a.id.includes(term));
      if (!shown.length) list.append(h("p", { class: "muted center", text: "No matches." }));
      shown.forEach((a) => list.append(accountCard(a)));
    };
    q.addEventListener("input", draw);
    if (all.length > 4) p.append(h("div", { class: "search" }, icon("search"), q));
    p.append(list);
    draw();
  }

  function emptyPixels() {
    const px = h("div", { class: "pixels" });
    "on,off,mid,off,on,off,off,mid,off,on,off,mid,mid,off,on,off,mid,off".split(",").forEach((k) => px.append(h("i", { class: k === "off" ? "" : k })));
    return px;
  }

  function accountCard(a) {
    const name = a.label || "Account " + a.id.slice(0, 4).toUpperCase();
    const exp = a.expires ? (a.status === "expired" ? "Expired " : "Expires ") + V.date(a.expires) : "Never expires";
    const devs = h("div", { class: "devs hidden" });
    const devBtn = h("button", { class: "btn btn-ghost btn-small", type: "button", "aria-expanded": "false" }, icon("phone"), h("span", { text: "Devices" }));
    devBtn.addEventListener("click", async () => {
      const open = devs.classList.toggle("hidden") === false;
      devBtn.setAttribute("aria-expanded", open ? "true" : "false");
      if (open) loadDevices(a, devs);
    });
    const pause = h("button", { class: "btn btn-ghost btn-small", type: "button" }, icon(a.disabled ? "play" : "pause"), h("span", { text: a.disabled ? "Resume" : "Pause" }));
    pause.addEventListener("click", () => V.busy(pause, async () => {
      const r = await api("PATCH", "/v1/admin/accounts/" + a.id, { disabled: !a.disabled });
      if (!r.ok) { V.toast(r.error, "err"); return; }
      V.toast(a.disabled ? "Account resumed" : "Account paused. Its devices were disconnected.");
      accounts();
    }));
    const expBtn = h("button", { class: "btn btn-ghost btn-small", type: "button", onclick: () => expiryDlg(a) }, icon("clock"), h("span", { text: "Expiry" }));
    const del = h("button", { class: "btn btn-quiet btn-small", type: "button", "aria-label": "Delete " + name }, icon("trash"), h("span", { text: "Delete" }));
    del.addEventListener("click", async () => {
      if (!(await confirmDlg("Delete " + name + "?", "This removes the account and disconnects all of its devices. It can't be undone.", "Delete account", true))) return;
      const r = await api("DELETE", "/v1/admin/accounts/" + a.id);
      if (!r.ok) { V.toast(r.error, "err"); return; }
      V.toast("Account deleted");
      accounts();
    });
    return h("div", { class: "acct" },
      h("div", { class: "acct-top" }, avatar(a.id), h("div", { class: "grow" }, h("div", { class: "name", text: name }), h("div", { class: "meta", text: a.devices + " of " + a.max_devices + " devices" + (a.online ? " · " + a.online + " online" : "") + " · " + exp })), statusBadge(a.status)),
      h("div", { class: "acct-actions" }, devBtn, pause, expBtn, del),
      devs
    );
  }

  async function loadDevices(a, box) {
    clear(box).append(h("div", { class: "dev" }, V.spinner(), h("span", { class: "muted", text: "Loading devices…" })));
    const r = await api("GET", "/v1/admin/accounts/" + a.id + "/devices");
    clear(box);
    if (!r.ok) { box.append(V.callout("err", "", r.error)); return; }
    if (!r.data.devices.length) { box.append(h("p", { class: "hint", text: "No devices yet. They appear here after signing in with the app." })); return; }
    r.data.devices.forEach((d) => {
      const rm = h("button", { class: "btn btn-quiet btn-small", type: "button", "aria-label": "Remove " + d.name }, icon("x"), h("span", { text: "Remove" }));
      rm.addEventListener("click", async () => {
        if (!(await confirmDlg("Remove " + d.name + "?", "It's disconnected right away and can't connect again until it signs in.", "Remove device", true))) return;
        const x = await api("DELETE", "/v1/admin/accounts/" + a.id + "/devices/" + encodeURIComponent(d.id));
        if (!x.ok) { V.toast(x.error, "err"); return; }
        V.toast("Device removed");
        loadDevices(a, box);
      });
      box.append(h("div", { class: "dev" }, h("span", { class: "dot " + (d.online ? "on" : "") }), h("div", { class: "n" }, h("div", { text: d.name }), h("div", { class: "m", text: (d.online ? "Online now · " : "") + "Added " + V.date(d.created) })), rm));
    });
  }

  const EXPIRY = [[0, "Never"], [30, "In 30 days"], [90, "In 90 days"], [365, "In 1 year"]];

  function expiryDlg(a) {
    const sel = selectEl(EXPIRY, a.expires ? 30 : 0);
    const err = errSlot();
    const save = h("button", { class: "btn btn-primary", type: "button", text: "Save" });
    const cancel = h("button", { class: "btn btn-ghost", type: "button", text: "Cancel" });
    const d = dialog("When should it expire?", [field("Expires", sel, a.expires ? "Currently " + V.date(a.expires) + "." : "Currently never."), err], [cancel, save]);
    cancel.addEventListener("click", () => d.close());
    save.addEventListener("click", () => V.busy(save, async () => {
      const r = await api("PATCH", "/v1/admin/accounts/" + a.id, { expires_days: Number(sel.value) });
      if (!r.ok) { showErr(err, r.error); return; }
      d.close();
      V.toast("Expiry updated");
      accounts();
    }));
  }

  function newAccount() {
    const label = h("input", { class: "input", type: "text", maxlength: "40", placeholder: "e.g. Mum's phone", autocomplete: "off" });
    const exp = selectEl(EXPIRY, 0);
    const lim = selectEl([[0, "Server default"], ...Array.from({ length: 20 }, (_, i) => [i + 1, String(i + 1)])], 0);
    const pw = V.passwordField({ id: "na-pw", label: "Password (optional)", min: 10, hint: "Leave empty to let them choose one in the app." });
    const err = errSlot();
    const create = h("button", { class: "btn btn-primary", type: "button", text: "Create account" });
    const cancel = h("button", { class: "btn btn-ghost", type: "button", text: "Cancel" });
    const d = dialog("New account", [field("Name", label, "Only you see this."), h("div", { class: "grid-2" }, field("Expires", exp), field("Devices", lim)), pw.field, err], [cancel, create]);
    cancel.addEventListener("click", () => d.close());
    create.addEventListener("click", () => V.busy(create, async () => {
      if (pw.input.value && !pw.valid()) { showErr(err, "Passwords need at least 10 characters."); return; }
      const r = await api("POST", "/v1/admin/accounts", { label: label.value.trim(), expires_days: Number(exp.value), limit: Number(lim.value), password: pw.input.value });
      if (!r.ok) { showErr(err, r.error); return; }
      d.close();
      secretDlg("Account created", r.data.number, "Share this account number with them. It's shown only once.", true);
      accounts();
    }));
    label.focus();
  }

  async function invites() {
    const add = h("button", { class: "btn btn-primary", type: "button", onclick: newInvite }, icon("plus"), h("span", { text: "New invite" }));
    const p = pageShell("Invites", "Codes that let someone create their own account.", add);
    const l = loading(p);
    const r = await api("GET", "/v1/admin/invites");
    if (!r.ok || page !== "invites") return;
    l.remove();
    if (r.data.registration === "closed") p.append(V.callout("warn", "Invites are switched off", "\"Who can join\" is set to only accounts you create. Change it in Settings to use invites."));
    const inv = r.data.invites;
    if (!inv.length) {
      p.append(h("div", { class: "card empty" }, emptyPixels(), h("p", { text: "No open invites." }), h("button", { class: "btn btn-ghost", type: "button", onclick: newInvite }, icon("plus"), "Make an invite")));
      return;
    }
    const list = h("div", { class: "list" });
    inv.forEach((i) => {
      const del = h("button", { class: "btn btn-quiet btn-small", type: "button", "aria-label": "Delete invite" }, icon("trash"));
      del.addEventListener("click", async () => {
        if (!(await confirmDlg("Delete this invite?", "The code stops working right away.", "Delete invite", true))) return;
        const x = await api("DELETE", "/v1/admin/invites/" + i.id);
        if (!x.ok) { V.toast(x.error, "err"); return; }
        V.toast("Invite deleted");
        invites();
      });
      const exp = i.expires ? "expires " + V.date(i.expires) : "never expires";
      list.append(h("div", { class: "list-row" },
        h("div", { class: "grow" }, h("div", { class: "v", text: "Invite " + i.id.slice(0, 4).toUpperCase() }), h("div", { class: "muted small", text: "Made " + V.date(i.created) + " · " + exp })),
        h("span", { class: "badge badge-mint", text: i.used + " / " + i.uses + " used" }),
        del
      ));
    });
    p.append(list);
  }

  function newInvite() {
    let uses = 1;
    const out = h("output", { text: "1" });
    const minus = h("button", { type: "button", "aria-label": "Fewer", text: "−" });
    const plus = h("button", { type: "button", "aria-label": "More", text: "+" });
    const sync = () => { out.textContent = String(uses); minus.disabled = uses <= 1; plus.disabled = uses >= 100; };
    minus.addEventListener("click", () => { uses--; sync(); });
    plus.addEventListener("click", () => { uses++; sync(); });
    sync();
    const exp = selectEl([[7, "In 7 days"], [30, "In 30 days"], [0, "Never"]], 7);
    const err = errSlot();
    const create = h("button", { class: "btn btn-primary", type: "button", text: "Create invite" });
    const cancel = h("button", { class: "btn btn-ghost", type: "button", text: "Cancel" });
    const d = dialog("New invite", [
      h("div", { class: "toggle-row" }, h("div", { class: "txt" }, h("div", { class: "t", text: "How many people" }), h("div", { class: "d", text: "Each person uses it once." })), h("div", { class: "stepper" }, minus, out, plus)),
      field("Expires", exp),
      err
    ], [cancel, create]);
    cancel.addEventListener("click", () => d.close());
    create.addEventListener("click", () => V.busy(create, async () => {
      const r = await api("POST", "/v1/admin/invites", { uses, expires_days: Number(exp.value) });
      if (!r.ok) { showErr(err, r.error); return; }
      d.close();
      secretDlg("Invite ready", r.data.code, "Send this code with your server address. It's shown only once.", false);
      invites();
    }));
  }

  async function settings() {
    const p = pageShell("Settings", "Changes that affect the server are applied right away.");
    const l = loading(p);
    const r = await api("GET", "/v1/admin/settings");
    if (!r.ok || page !== "settings") return;
    l.remove();
    const s = r.data.settings;
    const pqOK = r.data.pq_available;
    const err = errSlot();
    const name = h("input", { class: "input", type: "text", maxlength: "40", value: s.name });
    const host = h("input", { class: "input", type: "text", value: s.host, autocapitalize: "off", spellcheck: "false", inputmode: "url" });
    const email = h("input", { class: "input", type: "email", value: s.acme_email, placeholder: "Optional" });
    const appUrl = h("input", { class: "input", type: "url", value: s.app_url, placeholder: "https://" });
    const port = h("input", { class: "input", type: "number", min: "1024", max: "65535", value: String(s.udp_port), inputmode: "numeric" });
    const stealth = V.toggleRow("Stealth mode", "Works on networks that block VPNs. Uses port 443 like normal websites.", s.stealth);
    const v6 = V.toggleRow("IPv6", "Give devices IPv6 addresses too.", s.ipv6);
    const pq = V.toggleRow("Post-quantum protection", pqOK ? "Protects traffic against future quantum computers." : "Needs OpenSSL 3.5 or newer on the server.", pqOK && s.post_quantum, { disabled: !pqOK });
    let limit = s.device_limit;
    const out = h("output", { text: String(limit) });
    const minus = h("button", { type: "button", "aria-label": "Fewer devices", text: "−" });
    const plus = h("button", { type: "button", "aria-label": "More devices", text: "+" });
    const syncLim = () => { out.textContent = String(limit); minus.disabled = limit <= 1; plus.disabled = limit >= 20; };
    minus.addEventListener("click", () => { limit--; syncLim(); dirty(); });
    plus.addEventListener("click", () => { limit++; syncLim(); dirty(); });
    syncLim();
    const on = new Set(s.dns_default);
    const cats = {};
    const catCard = h("div", { class: "card card-tight" });
    r.data.categories.forEach((c) => {
      cats[c] = V.toggleRow((CATS[c] || [c])[0], (CATS[c] || ["", ""])[1], on.has(c));
      catCard.append(cats[c].row);
    });
    let upstream = s.dns_upstream;
    const seg = h("div", { class: "seg" });
    const segBtns = UPSTREAMS.map(([v, t, d]) => h("button", { type: "button", role: "radio", "aria-checked": v === upstream ? "true" : "false", "data-v": v }, h("span", { class: "t", text: t }), h("span", { class: "d", text: d })));
    segBtns.forEach((b) => seg.append(b));
    V.radioGroup(seg, segBtns, (b) => { upstream = b.getAttribute("data-v"); dirty(); });
    const updates = V.toggleRow("Automatic security updates", "Installs security fixes for the system by itself.", s.auto_updates);
    const vpnOnly = V.toggleRow("Admin panel only through the VPN", "Hides this panel from the internet. Connect to the VPN first, or you'll lock yourself out.", s.admin_vpn_only);
    let reg = s.registration;
    const regBtns = ["invite", "open", "closed"].map((k) => {
      const b = V.choice({ icon: REG[k][2], title: REG[k][0], desc: REG[k][1], on: reg === k });
      b.setAttribute("data-v", k);
      return b;
    });
    const regGroup = h("div", { class: "stack" }, ...regBtns);
    V.radioGroup(regGroup, regBtns, (b) => { reg = b.getAttribute("data-v"); dirty(); });

    const saveBtn = h("button", { class: "btn btn-primary btn-small", type: "button" }, h("span", { text: "Save changes" }));
    saveBtn.dataset.busy = "Saving…";
    const bar = h("div", { class: "save-bar hidden" }, h("span", { class: "grow", text: "You have unsaved changes." }), saveBtn);
    function dirty() { bar.classList.remove("hidden"); }
    [name, host, email, appUrl, port].forEach((i) => i.addEventListener("input", dirty));
    [stealth, v6, pq, updates, vpnOnly, ...Object.values(cats)].forEach((t) => t.sw.addEventListener("change", dirty));

    saveBtn.addEventListener("click", () => V.busy(saveBtn, async () => {
      const hv = host.value.trim().toLowerCase();
      const isIP = /^[0-9.]+$/.test(hv) || hv.includes(":");
      const tls = isIP ? "internal" : (hv === s.host ? s.tls : "acme");
      if (vpnOnly.sw.on() && !s.admin_vpn_only) {
        if (!(await confirmDlg("Only allow the admin panel through the VPN?", "After saving, this page only opens while you're connected to this VPN. If you're not connected now, you'll be signed out.", "Yes, hide it"))) return;
      }
      const body = {
        name: name.value.trim(), host: hv, tls, acme_email: email.value.trim(), udp_port: Number(port.value),
        stealth: stealth.sw.on(), ipv6: v6.sw.on(), post_quantum: pq.sw.on(), registration: reg, device_limit: limit,
        dns_default: Object.keys(cats).filter((c) => cats[c].sw.on()), dns_upstream: upstream,
        admin_vpn_only: vpnOnly.sw.on(), auto_updates: updates.sw.on(), app_url: appUrl.value.trim()
      };
      const x = await api("PUT", "/v1/admin/settings", body);
      if (!x.ok) { showErr(err, x.error); return; }
      clear(err);
      Object.assign(s, x.data.settings);
      bar.classList.add("hidden");
      V.toast("Saved");
      if (x.data.applying) jobBanner(p, "apply");
    }));

    p.append(
      h("p", { class: "card-title", text: "General" }),
      h("div", { class: "card stack" }, field("Server name", name, "Shown in the app."), field("Address", host, "Changing it gets a new certificate. Apps need the new address."), field("Certificate email", email), field("App download link", appUrl)),
      h("p", { class: "card-title", text: "VPN" }),
      h("div", { class: "card card-tight" }, stealth.row, v6.row, pq.row,
        h("div", { class: "toggle-row" }, h("div", { class: "txt" }, h("div", { class: "t", text: "Devices per account" }), h("div", { class: "d", text: "Default for everyone." })), h("div", { class: "stepper" }, minus, out, plus))),
      h("div", { class: "card" }, field("VPN port (UDP)", port, "Most people never need to change this.")),
      h("p", { class: "card-title", text: "Block by default" }),
      catCard,
      h("p", { class: "card-title", text: "Name lookups" }),
      seg,
      h("p", { class: "card-title", text: "Who can join" }),
      regGroup,
      h("p", { class: "card-title", text: "Server" }),
      h("div", { class: "card card-tight" }, updates.row, vpnOnly.row),
      err,
      bar
    );
  }

  async function security() {
    const p = pageShell("Security", "Protect the admin panel.");
    const err = errSlot();
    const cur = h("input", { class: "input", type: "password", autocomplete: "current-password" });
    const np = V.passwordField({ id: "np", label: "New password", min: 12, hint: "At least 12 characters." });
    const change = h("button", { class: "btn btn-ghost", type: "button" }, h("span", { text: "Change password" }));
    change.addEventListener("click", () => V.busy(change, async () => {
      if (!np.valid()) { showErr(err, "Use at least 12 characters."); return; }
      const r = await api("POST", "/v1/admin/password", { password: cur.value, new_password: np.input.value });
      if (!r.ok) { showErr(err, r.error); return; }
      clear(err);
      cur.value = "";
      np.input.value = "";
      V.toast("Password changed. Other sessions were signed out.");
    }));
    p.append(h("div", { class: "card stack" }, h("h3", { text: "Admin password" }), field("Current password", cur), np.field, err, h("div", null, change)));

    const tf = h("div", { class: "card stack" });
    p.append(tf);
    const s = await api("GET", "/v1/admin/session");
    if (!s.ok || page !== "security") return;
    sess = s.data;
    drawTOTP(tf);
  }

  function drawTOTP(box) {
    clear(box);
    const on = sess.totp_enabled;
    box.append(h("div", { class: "row" }, h("h3", { class: "grow", text: "Two-step sign in" }), h("span", { class: "badge " + (on ? "badge-green" : ""), text: on ? "On" : "Off" })));
    box.append(h("p", { class: "hint", text: on ? "You need a code from your authenticator app to sign in." : "Ask for a 6-digit code from an app like 1Password, Aegis or Google Authenticator when signing in." }));
    const err = errSlot();
    if (!on) {
      const start = h("button", { class: "btn btn-primary", type: "button" }, icon("shieldCheck"), h("span", { text: "Turn on" }));
      start.addEventListener("click", () => V.busy(start, async () => {
        const r = await api("POST", "/v1/admin/totp/setup", {});
        if (!r.ok) { showErr(err, r.error); return; }
        const code = h("input", { class: "input mono", type: "text", inputmode: "numeric", autocomplete: "one-time-code", maxlength: "7", placeholder: "123 456" });
        const en = h("button", { class: "btn btn-primary", type: "button" }, h("span", { text: "Confirm and turn on" }));
        en.addEventListener("click", () => V.busy(en, async () => {
          const x = await api("POST", "/v1/admin/totp/enable", { code: code.value.replace(/\s/g, "") });
          if (!x.ok) { showErr(err, x.error); return; }
          sess.totp_enabled = true;
          V.toast("Two-step sign in is on");
          drawTOTP(box);
        }));
        clear(box).append(
          h("h3", { text: "Scan with your authenticator app" }),
          h("img", { class: "qr", src: r.data.qr, alt: "QR code for your authenticator app", width: "220", height: "220" }),
          h("p", { class: "hint center", text: "Can't scan? Enter this key instead:" }),
          h("div", { class: "code-box" }, h("div", { class: "val small wrap", text: r.data.secret.replace(/(.{4})/g, "$1 ").trim() }), h("button", { class: "btn btn-ghost btn-small", type: "button", onclick: () => V.copy(r.data.secret) }, icon("copy"), "Copy")),
          field("Enter the 6-digit code it shows", code),
          err,
          h("div", { class: "row-wrap" }, en, h("button", { class: "btn btn-quiet", type: "button", onclick: () => drawTOTP(box), text: "Cancel" }))
        );
        code.focus();
      }));
      box.append(err, h("div", null, start));
    } else {
      const off = h("button", { class: "btn btn-danger", type: "button" }, h("span", { text: "Turn off" }));
      off.addEventListener("click", () => {
        const pw = h("input", { class: "input", type: "password", autocomplete: "current-password" });
        const e2 = errSlot();
        const ok = h("button", { class: "btn btn-danger", type: "button", text: "Turn off" });
        const cancel = h("button", { class: "btn btn-ghost", type: "button", text: "Cancel" });
        const d = dialog("Turn off two-step sign in?", [field("Admin password", pw), e2], [cancel, ok]);
        cancel.addEventListener("click", () => d.close());
        ok.addEventListener("click", () => V.busy(ok, async () => {
          const x = await api("POST", "/v1/admin/totp/disable", { password: pw.value });
          if (!x.ok) { showErr(e2, x.error); return; }
          d.close();
          sess.totp_enabled = false;
          V.toast("Two-step sign in is off");
          drawTOTP(box);
        }));
        pw.focus();
      });
      box.append(err, h("div", null, off));
    }
  }

  function backup() {
    const p = pageShell("Backup", "Keep a copy somewhere safe, like a password manager or USB stick.");
    const pass = V.passwordField({ id: "bk", label: "Passphrase", min: 10, hint: "At least 10 characters. You need it to restore." });
    const err = errSlot();
    const dl = h("button", { class: "btn btn-primary", type: "button" }, icon("download"), h("span", { text: "Download backup" }));
    dl.dataset.busy = "Encrypting…";
    dl.addEventListener("click", () => V.busy(dl, async () => {
      if (!pass.valid()) { pass.input.classList.add("invalid"); showErr(err, "Use at least 10 characters."); return; }
      const r = await api("POST", "/v1/admin/backup", { passphrase: pass.input.value }, { blob: true });
      if (!r.ok) { showErr(err, r.error); return; }
      clear(err);
      V.save(r.blob, r.filename);
      V.toast("Backup downloaded");
    }));
    p.append(
      h("div", { class: "card stack" },
        h("h3", { text: "Download an encrypted backup" }),
        h("p", { class: "hint", text: "Includes settings, accounts, devices, certificates and the admin sign in. It's locked with your passphrase using AES-256." }),
        pass.field, err, h("div", null, dl)
      ),
      h("div", { class: "card stack" },
        h("h3", { text: "Restoring" }),
        h("p", { class: "hint", text: "On a new server, run the installer and choose \"Restore from a backup\" in setup. Everyone keeps their account numbers." }),
        h("div", { class: "code-box" }, h("div", { class: "val small", text: "sudo veyl restore veyl-backup.vbk" }), h("button", { class: "btn btn-ghost btn-small", type: "button", onclick: () => V.copy("sudo veyl restore veyl-backup.vbk") }, icon("copy"), "Copy"))
      )
    );
  }

  async function boot() {
    const s = await V.api("GET", "/v1/admin/session");
    if (!s.ok) {
      clear(app).append(h("div", { class: "centered" }, h("div", { class: "login" }, V.callout("err", "Can't open the admin panel", s.error))));
      return;
    }
    sess = s.data;
    V.state.csrf = sess.csrf || "";
    if (sess.authenticated) shell();
    else login();
  }

  boot();
})();
