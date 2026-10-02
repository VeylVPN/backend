"use strict";

(() => {
  const B = Brand;
  const { h, icon, clear } = B;
  const app = document.getElementById("app");
  const nav = document.getElementById("nav");
  const navActions = document.getElementById("nav-actions");
  const footerVersion = document.getElementById("footer-version");
  B.watchNav(nav);

  const CATS = {
    ads: ["Ads", "Ad networks in apps and websites.", "ban"],
    trackers: ["Trackers", "Companies that follow people around the web.", "eyeOff"],
    malware: ["Malware and scams", "Known dangerous and phishing sites.", "shield"],
    adult: ["Adult content", "Adult websites.", "lock"],
    gambling: ["Gambling", "Betting and casino sites.", "dice"],
    social: ["Social media", "Facebook, TikTok, Instagram and others.", "users"]
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
    ["security", "Security", "shield"],
    ["backup", "Backup", "archive"],
    ["control", "Control Panel", "panel"]
  ];

  let sess = null;
  let page = "overview";
  let content = null;
  let links = [];
  let poll = 0;
  let wave = null;
  let platformKnown = false;
  const samples = [];

  function windows() { return B.state.platform === "windows"; }

  function root(cmd) { return windows() ? cmd : "sudo " + cmd; }

  function shellLabel() { return windows() ? "In an admin PowerShell" : "On your server"; }

  function command(cmd) { return B.codeBlock(root(cmd), shellLabel(), { promptText: windows() ? "PS> " : "$ " }); }

  function learnPlatform(o) {
    if (!o) return;
    const p = B.platformOf(o, o.system);
    B.state.platform = p;
    B.state.stealthPort = B.stealthPortOf(p, o, o.system);
    platformKnown = true;
  }

  async function api(method, url, body, extra) {
    const r = await B.api(method, url, body, extra);
    if (r.status === 401 && !url.endsWith("/login")) {
      sess = null;
      login("You were signed out. Sign in again.");
    }
    if (r.data && r.data.csrf) B.state.csrf = r.data.csrf;
    return r;
  }

  async function ensurePlatform() {
    if (platformKnown) return;
    const r = await api("GET", "/v1/admin/overview");
    if (r.ok) learnPlatform(r.data);
  }

  function title(main, dim) {
    const el = h("h1", { class: "text-title", tabindex: "-1" }, main);
    if (dim) el.append(" ", h("span", { class: "text-dim", text: dim }));
    return el;
  }

  function secretDialog(heading, value, note, grouped) {
    const close = B.button("Done", { async: false, onClick: () => d.close() });
    const d = B.dialog(heading, [
      B.secret(value, grouped ? B.groupNumber(value) : value, { aria: "Copy", toast: "Copied", small: !grouped && value.length > 24 }),
      B.callout("warn", "", note)
    ], [close]);
  }

  function setNavActions(kids) {
    clear(navActions).append(...kids);
  }

  function login(msg) {
    clearInterval(poll);
    stopWave();
    setNavActions([]);
    const err = B.errorSlot();
    const pw = B.input({ id: "pw", type: "password", autocomplete: "current-password", placeholder: "Admin password", class: "input-lg" });
    const code = B.input({ id: "code", inputmode: "numeric", autocomplete: "one-time-code", maxlength: "7", placeholder: "123 456", mono: true, class: "input-lg" });
    const needCode = sess && sess.totp_required;
    const btn = h("button", { class: "btn btn-primary btn-lg btn-block", type: "submit" }, h("span", { text: "Sign in" }), icon("arrowRight", "icon-arrow"));
    btn.dataset.busy = "Signing in";
    const form = h("form", { class: "card surface-card card-glow stack", novalidate: true },
      B.field("Password", pw),
      needCode ? B.field("Code from your authenticator app", code) : null,
      err,
      btn
    );
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      B.busy(btn, async () => {
        if (!pw.value) { pw.focus(); B.showError(err, "Enter your admin password."); return; }
        const r = await api("POST", "/v1/admin/login", { password: pw.value, totp: needCode ? code.value.replace(/\s/g, "") : "" });
        if (!r.ok) { B.showError(err, r.error); pw.select(); return; }
        await boot();
      });
    });
    const name = (sess && sess.name) || "Veyl";
    clear(app).append(h("div", { class: "auth-box rise", id: "login" },
      h("div", { class: "auth-head" },
        h("h1", { class: "text-title", tabindex: "-1" }, "Sign in to ", h("span", { class: "text-gradient", text: name + "." })),
        h("p", { class: "text-lede", text: msg || "Manage accounts, invites and settings for this server." })
      ),
      sess && !sess.admin_set ? B.callout("warn", "Setup isn't finished", "Finish setup with the link from the installer, then come back here.") : null,
      form,
      h("p", { class: "auth-foot", text: "Forgot your password? Run \"" + root("veyl admin reset-password") + "\" on the server." })
    ));
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
    links = [];
    const side = h("nav", { class: "side-nav", "aria-label": "Admin" });
    const tabs = h("nav", { class: "tabs", "aria-label": "Admin sections" });
    PAGES.forEach(([id, label, ic]) => {
      const a = h("a", { class: "side-nav-link", href: "#" + id, "data-page": id }, icon(ic), h("span", { text: label }));
      const t = h("a", { class: "tab", href: "#" + id, "data-page": id }, icon(ic), h("span", { text: label }));
      links.push(a, t);
      side.append(a);
      tabs.append(t);
    });
    content = h("div", { class: "app-content" });
    const aside = h("aside", { class: "app-aside" },
      h("div", { class: "nav-only-desktop stack" },
        h("div", { class: "stack stack-xs" }, h("p", { class: "heading-sm", text: sess.name || "Veyl" }), h("p", { class: "text-sm text-subtle", text: sess.host || "" })),
        side
      ),
      h("div", { class: "nav-only-mobile" }, tabs)
    );
    clear(app).append(h("div", { class: "app-layout" }, aside, content));
    setNavActions([
      h("span", { class: "nav-meta", text: sess.host || "" }),
      B.button("Sign out", { variant: "secondary", size: "sm", icon: "logout", onClick: logout })
    ]);
    if (footerVersion) footerVersion.textContent = "Veyl " + (sess.version || "");
    route();
  }

  function route() {
    const want = location.hash.replace(/^#/, "");
    page = PAGES.some((p) => p[0] === want) ? want : "overview";
    links.forEach((a) => {
      if (a.getAttribute("data-page") === page) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    const tab = links.find((a) => a.classList.contains("tab") && a.getAttribute("data-page") === page);
    if (tab && tab.scrollIntoView && window.innerWidth < 1024) tab.scrollIntoView({ block: "nearest", inline: "center" });
    clearInterval(poll);
    stopWave();
    ({ overview, accounts, invites, settings, security, backup, control })[page]();
  }

  window.addEventListener("hashchange", () => { if (sess && sess.authenticated) route(); });

  function stopWave() {
    if (wave) wave.stop();
    wave = null;
  }

  function pageShell(heading, lead, right) {
    clear(content);
    const head = h("header", { class: "page-header" },
      h("div", { class: "page-header-text" }, Array.isArray(heading) ? title(heading[0], heading[1]) : title(heading), lead ? h("p", { class: "text-lede", text: lead }) : null),
      right ? h("div", { class: "cluster" }, right) : null
    );
    const body = h("div", { class: "page-body" });
    const p = h("div", { class: "rise" }, head, body);
    content.append(p);
    window.scrollTo(0, 0);
    return { el: p, head, body };
  }

  function loading(body) {
    const l = h("div", { class: "loading" }, B.spinner());
    body.append(l);
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

  function stat(label, value, unit) {
    const v = h("div", { class: "stat-value", text: value });
    if (unit) v.append(h("span", { class: "stat-unit", text: unit }));
    return h("div", { class: "stat" }, h("div", { class: "stat-label", text: label }), v);
  }

  const SYS = [
    ["os", "system"],
    ["platform", "platform"],
    ["public_ip", "public-ip"],
    ["public_ipv6", "public-ipv6"],
    ["openvpn", "openvpn"],
    ["openssl", "openssl"],
    ["load", "load"],
    ["mem", "memory"],
    ["disk", "disk"],
    ["uptime", "server-uptime"]
  ];

  function jobCard(p, kind) {
    const list = B.progress();
    const bar = B.progressBar();
    const heading = h("h2", { class: "card-title", text: kind === "dns-update" ? "Updating blocklists" : "Applying changes" });
    const card = h("section", { class: "card surface-card" }, h("div", { class: "stack" }, heading, bar.el, list.el));
    p.body.insertBefore(card, p.body.firstChild);
    B.stream("/v1/admin/apply-progress", (ev) => list.step(ev), (d) => {
      const ok = !!(d && d.ok);
      list.settle(ok);
      if (ok) bar.done(); else bar.fail();
      heading.textContent = ok ? "All done" : "Something didn't finish";
      if (!ok) card.firstChild.append(B.callout("danger", "", (d && d.error) || "Lost contact with the server."));
      B.toast(ok ? "Done" : "That didn't finish", ok ? "" : "err");
      setTimeout(() => { if (ok) card.remove(); }, 4000);
    });
  }

  function serviceState(s) {
    if (s.state === "active") return ["is-ok", "Running", "badge-ok"];
    if (s.state === "inactive" || s.state === "disabled") return ["", s.state === "disabled" ? "Off" : "Stopped", ""];
    if (s.state === "activating" || s.state === "reloading") return ["is-warn", "Starting", "badge-warn"];
    return ["is-danger", s.state === "failed" ? "Failed" : s.state, "badge-danger"];
  }

  function healthy(o) {
    return o.services.length > 0 && o.services.every((s) => s.state === "active" || s.state === "inactive" || s.state === "disabled");
  }

  async function overview() {
    const p = pageShell([sess.name || "Veyl", "at a glance."], "Live while this page is open. Nothing is stored.");
    const l = loading(p.body);
    const r = await api("GET", "/v1/admin/overview");
    if (!r.ok || page !== "overview") return;
    l.remove();
    const o = r.data;
    learnPlatform(o);
    samples.push(o.connected);
    if (samples.length > 64) samples.shift();
    const good = healthy(o);
    clear(p.head.querySelector("h1")).append(o.name || sess.name || "Veyl", " ", h("span", { class: "text-dim", text: good ? "is running." : (o.services.length ? "needs a look." : "at a glance.") }));

    const canvas = h("canvas", { class: "pixel-wave", "aria-hidden": "true" });
    const connected = h("div", { class: "text-headline tabular", text: fmt(o.connected) });
    const status = h("p", { class: "row text-sm text-muted" }, h("span", { class: "dot " + (good ? "is-ok is-live" : o.services.length ? "is-warn" : ""), "aria-hidden": "true" }), h("span", { text: good ? "All services running" : o.services.length ? "A service needs attention" : "Waiting for the system agent" }));
    const stealthValue = o.stealth ? (windows() ? "Port " + B.state.stealthPort : "On") : "Off";
    const hero = h("section", { class: "card surface-card card-glow-bottom", "aria-label": "Live status" },
      h("div", { class: "grid-2" },
        h("div", { class: "stack" },
          h("p", { class: "label text-subtle", text: "Connected now" }),
          connected,
          status
        ),
        canvas
      ),
      h("div", { class: "stat-grid mt-8" },
        stat("Accounts", fmt(o.accounts)),
        stat("Devices", fmt(o.devices)),
        stat("Running for", uptime(o.uptime)),
        stat("Stealth", stealthValue)
      )
    );

    const svc = h("section", { class: "card card-flush surface-panel", "aria-labelledby": "svc-title" }, h("div", { class: "card-head" }, h("h2", { id: "svc-title", text: "Services" })));
    const svcList = h("div", { class: "list" });
    if (!o.services.length) svcList.append(h("p", { class: "list-item text-muted", text: "The system agent didn't answer. Service status shows when it's running." }));
    o.services.forEach((s) => {
      const [dot, label, badge] = serviceState(s);
      svcList.append(h("div", { class: "list-item" }, h("span", { class: "dot " + dot, "aria-hidden": "true" }), h("span", { class: "grow text-mono text-sm", text: s.name }), h("span", { class: "badge " + badge, text: label })));
    });
    svc.append(svcList);

    const sys = h("dl", { class: "kv kv-mono" });
    sys.append(h("div", { class: "kv-row" }, h("dt", { class: "kv-key is-accent", text: "veyl" }), h("dd", { class: "kv-value", text: o.version })));
    SYS.forEach(([k, label]) => {
      const v = k === "platform" ? (o.system[k] || o.platform) : o.system[k];
      if (!v) return;
      sys.append(h("div", { class: "kv-row" }, h("dt", { class: "kv-key" + (k === "public_ip" ? " is-accent" : ""), text: label }), h("dd", { class: "kv-value", text: k === "uptime" ? uptime(v) : v })));
    });
    if (o.cert_expiry) sys.append(h("div", { class: "kv-row" }, h("dt", { class: "kv-key", text: "certificate" }), h("dd", { class: "kv-value", text: "renews automatically, expires " + o.cert_expiry })));
    const server = h("section", { class: "card card-flush surface-panel", "aria-labelledby": "sys-title" }, h("div", { class: "card-head" }, h("h2", { id: "sys-title", text: "Server" })), sys);

    const tbody = h("tbody");
    o.blocklists.forEach((b) => {
      tbody.append(h("tr", null,
        h("td", { class: "is-strong", text: (CATS[b.category] || [b.category])[0] }),
        h("td", { class: "is-num", text: b.entries ? fmt(b.entries) : "Not yet" }),
        h("td", { class: "text-sm", text: b.updated || "" })
      ));
    });
    const upd = B.button("Update now", { variant: "secondary", size: "sm", icon: "refresh", onClick: async () => {
      const x = await api("POST", "/v1/admin/dns/update", {});
      if (!x.ok) { B.toast(x.error, "err"); return; }
      jobCard(p, "dns-update");
    } });
    const lists = h("section", { class: "card card-flush surface-panel", "aria-labelledby": "bl-title" },
      h("div", { class: "card-head" }, h("h2", { id: "bl-title", text: "Blocklists" }), upd),
      h("div", { class: "table-wrap" }, h("table", { class: "table" }, h("thead", null, h("tr", null, h("th", { scope: "col", text: "Category" }), h("th", { scope: "col", class: "is-num", text: "Sites" }), h("th", { scope: "col", text: "Updated" }))), tbody))
    );

    p.body.append(hero, h("div", { class: "grid-2" }, svc, server), lists);
    wave = B.pixelWave(canvas, good);
    if (o.job && o.job.running) jobCard(p, o.job.kind);
    poll = setInterval(async () => {
      if (page !== "overview" || document.hidden) return;
      const x = await api("GET", "/v1/admin/overview");
      if (!x.ok || page !== "overview") return;
      samples.push(x.data.connected);
      if (samples.length > 64) samples.shift();
      connected.textContent = fmt(x.data.connected);
      if (wave) wave.set(healthy(x.data));
    }, 15000);
  }

  function avatar(id) {
    const px = h("span", { class: "avatar", "aria-hidden": "true" });
    let n = parseInt(String(id).slice(0, 6), 16) || 7;
    for (let i = 0; i < 9; i++) {
      px.append(h("i", { class: n & 1 ? "is-on" : (n & 2 ? "is-mid" : "") }));
      n = n >> 1 || 5;
    }
    return px;
  }

  function statusBadge(s) {
    if (s === "disabled") return h("span", { class: "badge badge-danger", text: "Paused" });
    if (s === "expired") return h("span", { class: "badge badge-warn", text: "Expired" });
    return h("span", { class: "badge badge-ok", text: "Active" });
  }

  function emptyState(text, action) {
    return h("div", { class: "card surface-quiet" }, h("div", { class: "empty" }, B.mark(), h("p", { class: "empty-title", text }), action));
  }

  async function accounts() {
    const add = B.button("New account", { icon: "plus", async: false, onClick: newAccount });
    const p = pageShell(["Accounts", "and devices."], "Everyone who can connect to your VPN.", add);
    const l = loading(p.body);
    const r = await api("GET", "/v1/admin/accounts");
    if (!r.ok || page !== "accounts") return;
    l.remove();
    const all = r.data.accounts;
    if (!all.length) {
      p.body.append(emptyState("No accounts yet.", B.button("Create the first one", { variant: "secondary", icon: "plus", async: false, onClick: newAccount })));
      return;
    }
    const q = B.input({ type: "search", placeholder: "Search by name", "aria-label": "Search accounts" });
    const list = h("div", { class: "list" });
    const draw = () => {
      clear(list);
      const term = q.value.trim().toLowerCase();
      const shown = all.filter((a) => !term || (a.label || "").toLowerCase().includes(term) || a.id.includes(term));
      if (!shown.length) list.append(h("p", { class: "list-item text-muted", text: "No matches." }));
      shown.forEach((a) => list.append(accountRow(a)));
    };
    q.addEventListener("input", draw);
    if (all.length > 4) p.body.append(q);
    p.body.append(h("section", { class: "card card-flush surface-panel", "aria-label": "Accounts" }, list));
    draw();
  }

  function accountRow(a) {
    const name = a.label || "Account " + a.id.slice(0, 4).toUpperCase();
    const exp = a.expires ? (a.status === "expired" ? "Expired " : "Expires ") + B.date(a.expires) : "Never expires";
    const devs = h("div", { class: "list-item-sub is-hidden" });
    const devBtn = h("button", { class: "btn btn-quiet", type: "button", "aria-expanded": "false" }, icon("phone"), h("span", { text: "Devices" }));
    devBtn.addEventListener("click", () => {
      const open = devs.classList.toggle("is-hidden") === false;
      devBtn.setAttribute("aria-expanded", open ? "true" : "false");
      if (open) loadDevices(a, devs);
    });
    const pause = h("button", { class: "btn btn-quiet", type: "button" }, icon(a.disabled ? "play" : "pause"), h("span", { text: a.disabled ? "Resume" : "Pause" }));
    pause.addEventListener("click", () => B.busy(pause, async () => {
      const r = await api("PATCH", "/v1/admin/accounts/" + a.id, { disabled: !a.disabled });
      if (!r.ok) { B.toast(r.error, "err"); return; }
      B.toast(a.disabled ? "Account resumed" : "Account paused. Its devices were disconnected.");
      accounts();
    }));
    const expBtn = h("button", { class: "btn btn-quiet", type: "button", onclick: () => expiryDialog(a) }, icon("clock"), h("span", { text: "Expiry" }));
    const del = h("button", { class: "btn btn-quiet", type: "button", "aria-label": "Delete " + name }, icon("trash"), h("span", { text: "Delete" }));
    del.addEventListener("click", async () => {
      if (!(await B.confirm("Delete " + name + "?", "This removes the account and disconnects all of its devices. It can't be undone.", "Delete account", true))) return;
      const r = await api("DELETE", "/v1/admin/accounts/" + a.id);
      if (!r.ok) { B.toast(r.error, "err"); return; }
      B.toast("Account deleted");
      accounts();
    });
    const meta = a.devices + " of " + a.max_devices + " devices" + (a.online ? ", " + a.online + " online" : "") + ". " + exp + ".";
    return h("div", { class: "account list-group" },
      h("div", { class: "list-item is-stacked" },
        avatar(a.id),
        h("div", { class: "grow" }, h("div", { class: "row" }, h("span", { class: "list-item-title", text: name }), statusBadge(a.status)), h("div", { class: "list-item-meta", text: meta })),
        h("div", { class: "list-item-actions" }, devBtn, pause, expBtn, del)
      ),
      devs
    );
  }

  async function loadDevices(a, box) {
    clear(box).append(h("div", { class: "row text-sm text-muted" }, B.spinner(), h("span", { text: "Loading devices" })));
    const r = await api("GET", "/v1/admin/accounts/" + a.id + "/devices");
    clear(box);
    if (!r.ok) { box.append(B.callout("danger", "", r.error)); return; }
    if (!r.data.devices.length) { box.append(h("p", { class: "field-hint", text: "No devices yet. They show up here after signing in with the app." })); return; }
    const list = h("div", { class: "card card-flush surface-quiet card-sm" }, h("div", { class: "list" }));
    r.data.devices.forEach((d) => {
      const rm = h("button", { class: "btn btn-quiet", type: "button", "aria-label": "Remove " + d.name }, icon("x"), h("span", { text: "Remove" }));
      rm.addEventListener("click", async () => {
        if (!(await B.confirm("Remove " + d.name + "?", "It's disconnected right away and can't connect again until it signs in.", "Remove device", true))) return;
        const x = await api("DELETE", "/v1/admin/accounts/" + a.id + "/devices/" + encodeURIComponent(d.id));
        if (!x.ok) { B.toast(x.error, "err"); return; }
        B.toast("Device removed");
        loadDevices(a, box);
      });
      list.firstChild.append(h("div", { class: "list-item" }, h("span", { class: "dot " + (d.online ? "is-ok" : ""), "aria-hidden": "true" }), h("div", { class: "grow" }, h("div", { class: "list-item-title", text: d.name }), h("div", { class: "list-item-meta", text: (d.online ? "Online now. " : "") + "Added " + B.date(d.created) })), rm));
    });
    box.append(list);
  }

  const EXPIRY = [[0, "Never"], [30, "In 30 days"], [90, "In 90 days"], [365, "In 1 year"]];

  function expiryDialog(a) {
    const sel = B.select(EXPIRY, a.expires ? 30 : 0);
    const err = B.errorSlot();
    const cancel = B.button("Cancel", { variant: "secondary", async: false, onClick: () => d.close() });
    const save = B.button("Save", { onClick: async () => {
      const r = await api("PATCH", "/v1/admin/accounts/" + a.id, { expires_days: Number(sel.value) });
      if (!r.ok) { B.showError(err, r.error); return; }
      d.close();
      B.toast("Expiry updated");
      accounts();
    } });
    const d = B.dialog("When should it expire?", [B.field("Expires", sel, a.expires ? "Currently " + B.date(a.expires) + "." : "Currently never."), err], [cancel, save]);
  }

  function newAccount() {
    const label = B.input({ maxlength: "40", placeholder: "Mum's phone", autocomplete: "off" });
    const exp = B.select(EXPIRY, 0);
    const lim = B.select([[0, "Server default"], ...Array.from({ length: 20 }, (_, i) => [i + 1, String(i + 1)])], 0);
    const pw = B.passwordField({ id: "na-pw", label: "Password (optional)", min: 10, hint: "Leave it empty to let them choose one in the app." });
    const err = B.errorSlot();
    const cancel = B.button("Cancel", { variant: "secondary", async: false, onClick: () => d.close() });
    const create = B.button("Create account", { onClick: async () => {
      if (pw.input.value && !pw.valid()) { B.showError(err, "Passwords need at least 10 characters."); return; }
      const r = await api("POST", "/v1/admin/accounts", { label: label.value.trim(), expires_days: Number(exp.value), limit: Number(lim.value), password: pw.input.value });
      if (!r.ok) { B.showError(err, r.error); return; }
      d.close();
      secretDialog("Account created", r.data.number, "Share this account number with them. It's shown only once.", true);
      accounts();
    } });
    const d = B.dialog("New account", [B.field("Name", label, "Only you see this."), h("div", { class: "grid-2" }, B.field("Expires", exp), B.field("Devices", lim)), pw.field, err], [cancel, create]);
    label.focus();
  }

  async function invites() {
    const add = B.button("New invite", { icon: "plus", async: false, onClick: newInvite });
    const p = pageShell(["Invites", "for new people."], "Codes that let someone create their own account.", add);
    const l = loading(p.body);
    const r = await api("GET", "/v1/admin/invites");
    if (!r.ok || page !== "invites") return;
    l.remove();
    if (r.data.registration === "closed") p.body.append(B.callout("warn", "Invites are switched off", "\"Who can join\" is set to only accounts you create. Change it in Settings to use invites."));
    const inv = r.data.invites;
    if (!inv.length) {
      p.body.append(emptyState("No open invites.", B.button("Make an invite", { variant: "secondary", icon: "plus", async: false, onClick: newInvite })));
      return;
    }
    const list = h("div", { class: "list" });
    inv.forEach((i) => {
      const del = h("button", { class: "btn btn-quiet btn-icon", type: "button", "aria-label": "Delete invite" }, icon("trash"));
      del.addEventListener("click", async () => {
        if (!(await B.confirm("Delete this invite?", "The code stops working right away.", "Delete invite", true))) return;
        const x = await api("DELETE", "/v1/admin/invites/" + i.id);
        if (!x.ok) { B.toast(x.error, "err"); return; }
        B.toast("Invite deleted");
        invites();
      });
      const exp = i.expires ? "expires " + B.date(i.expires) : "never expires";
      list.append(h("div", { class: "list-item" },
        h("span", { class: "icon-tile", "aria-hidden": "true" }, icon("ticket")),
        h("div", { class: "grow" }, h("div", { class: "list-item-title text-mono", text: "Invite " + i.id.slice(0, 4).toUpperCase() }), h("div", { class: "list-item-meta", text: "Made " + B.date(i.created) + ", " + exp })),
        h("span", { class: "badge " + (i.used >= i.uses ? "" : "badge-violet"), text: i.used + " of " + i.uses + " used" }),
        del
      ));
    });
    p.body.append(h("section", { class: "card card-flush surface-panel", "aria-label": "Invites" }, list));
  }

  function newInvite() {
    const uses = B.stepper(1, 1, 100, "people");
    const exp = B.select([[7, "In 7 days"], [30, "In 30 days"], [0, "Never"]], 7);
    const err = B.errorSlot();
    const cancel = B.button("Cancel", { variant: "secondary", async: false, onClick: () => d.close() });
    const create = B.button("Create invite", { onClick: async () => {
      const r = await api("POST", "/v1/admin/invites", { uses: uses.value(), expires_days: Number(exp.value) });
      if (!r.ok) { B.showError(err, r.error); return; }
      d.close();
      secretDialog("Invite ready", r.data.code, "Send this code with your server address. It's shown only once.", false);
      invites();
    } });
    const d = B.dialog("New invite", [
      h("div", { class: "setting-list" }, B.settingRow("How many people", "Each person uses it once.", uses.el)),
      B.field("Expires", exp),
      err
    ], [cancel, create]);
  }

  function stealthText() {
    if (windows()) return "Adds a TCP fallback on port " + B.state.stealthPort + " for networks that block VPNs.";
    return "Runs a second VPN on port 443, like normal web traffic. Works on networks that block VPNs.";
  }

  async function settings() {
    const p = pageShell(["Settings", "for this server."], "Changes that affect the server apply right away.");
    const l = loading(p.body);
    await ensurePlatform();
    const r = await api("GET", "/v1/admin/settings");
    if (!r.ok || page !== "settings") return;
    l.remove();
    const s = r.data.settings;
    const pqOK = r.data.pq_available;
    const err = B.errorSlot();
    const name = B.input({ maxlength: "40", value: s.name });
    const host = B.input({ value: s.host, autocapitalize: "off", spellcheck: "false", inputmode: "url", maxlength: "253", mono: true });
    const email = B.input({ type: "email", value: s.acme_email, placeholder: "Optional", maxlength: "254" });
    const appUrl = B.input({ type: "url", value: s.app_url, placeholder: "https://", maxlength: "512" });
    const port = B.input({ type: "number", min: "1024", max: "65535", value: String(s.udp_port), inputmode: "numeric", mono: true });
    const stealth = B.setting("Stealth mode", stealthText(), s.stealth, { icon: "eyeOff" });
    const v6 = B.setting("IPv6", "Give devices IPv6 addresses too.", s.ipv6, { icon: "globe" });
    const pq = B.setting("Post-quantum protection", pqOK ? "Protects traffic against future quantum computers." : "Needs OpenSSL 3.5 or newer on the server.", pqOK && s.post_quantum, { disabled: !pqOK, icon: "key" });
    const limit = B.stepper(s.device_limit, 1, 20, "devices", () => dirty());
    const on = new Set(s.dns_default);
    const cats = {};
    const catList = h("div", { class: "setting-list" });
    r.data.categories.forEach((c) => {
      const m = CATS[c] || [c, "", "ban"];
      cats[c] = B.setting(m[0], m[1], on.has(c), { icon: m[2] });
      catList.append(cats[c].row);
    });
    let upstream = s.dns_upstream;
    const seg = B.segmented(UPSTREAMS, upstream, (v) => { upstream = v; dirty(); }, "Name lookups");
    const updates = B.setting("Automatic security updates", windows() ? "Keeps Veyl's own components patched. Windows Update stays in charge of the system." : "Installs security fixes for the system by itself.", s.auto_updates, { icon: "refresh" });
    const vpnOnly = B.setting("Admin panel only through the VPN", "Hides this panel from the internet. Connect to the VPN first, or you lock yourself out.", s.admin_vpn_only, { icon: "lock" });
    let reg = s.registration;
    const regBtns = ["invite", "open", "closed"].map((k) => B.option({ icon: REG[k][2], title: REG[k][0], desc: REG[k][1], on: reg === k, value: k }));
    const regGroup = h("div", { class: "options" }, ...regBtns);
    B.radioGroup(regGroup, regBtns, (b) => { reg = b.getAttribute("data-value"); dirty(); }, "Who can join");

    const saveBtn = B.button("Save changes", { size: "sm", busy: "Saving", onClick: () => save() });
    const bar = h("div", { class: "save-bar is-hidden", role: "region", "aria-label": "Unsaved changes" }, h("span", { class: "grow", text: "You have unsaved changes." }), saveBtn);
    function dirty() { bar.classList.remove("is-hidden"); }
    [name, host, email, appUrl, port].forEach((i) => i.addEventListener("input", dirty));
    [stealth, v6, pq, updates, vpnOnly, ...Object.values(cats)].forEach((t) => t.toggle.addEventListener("change", dirty));

    async function save() {
      const hv = host.value.trim().toLowerCase();
      const isIP = /^[0-9.]+$/.test(hv) || hv.includes(":");
      const tls = isIP ? "internal" : (hv === s.host ? s.tls : "acme");
      if (vpnOnly.on() && !s.admin_vpn_only) {
        if (!(await B.confirm("Only allow the admin panel through the VPN?", "After saving, this page only opens while you're connected to this VPN. If you're not connected now, you'll be signed out.", "Yes, hide it"))) return;
      }
      const body = {
        name: name.value.trim(), host: hv, tls, acme_email: email.value.trim(), udp_port: Number(port.value),
        stealth: stealth.on(), ipv6: v6.on(), post_quantum: pq.on(), registration: reg, device_limit: limit.value(),
        dns_default: Object.keys(cats).filter((c) => cats[c].on()), dns_upstream: upstream,
        admin_vpn_only: vpnOnly.on(), auto_updates: updates.on(), app_url: appUrl.value.trim()
      };
      const x = await api("PUT", "/v1/admin/settings", body);
      if (!x.ok) { B.showError(err, x.error); return; }
      clear(err);
      Object.assign(s, x.data.settings);
      bar.classList.add("is-hidden");
      B.toast("Saved");
      if (x.data.applying) jobCard(p, "apply");
    }

    const card = (...kids) => h("div", { class: "card surface-card" }, ...kids);
    const sect = (heading, text, ...kids) => h("section", { class: "section" }, h("div", null, h("h2", { class: "section-title", text: heading }), text ? h("p", { class: "section-text mt-1", text }) : null), ...kids);
    p.body.append(
      sect("General", null, card(h("div", { class: "stack" },
        B.field("Server name", name, "Shown in the admin panel and to apps that ask the server for its details."),
        B.field("Address", host, "Changing it gets a new certificate. Apps need the new address."),
        h("div", { class: "grid-2" }, B.field("Certificate email", email), B.field("App download link", appUrl))
      ))),
      sect("VPN", null, card(h("div", { class: "setting-list" }, stealth.row, v6.row, pq.row, B.settingRow("Devices per account", "Default for everyone.", limit.el))), card(B.field("VPN port (UDP)", port, "Most people never need to change this."))),
      sect("Block for everyone", "Blocked names never resolve, on every device that uses this VPN.", card(catList)),
      sect("Name lookups", "Where your server asks when a site isn't blocked.", seg),
      sect("Who can join", null, regGroup),
      sect("Server", null, card(h("div", { class: "setting-list" }, updates.row, vpnOnly.row))),
      err,
      bar
    );
  }

  async function security() {
    const p = pageShell(["Security", "for this panel."], "Protect the admin panel with a strong password and a second step.");
    const err = B.errorSlot();
    const cur = B.input({ type: "password", autocomplete: "current-password" });
    const np = B.passwordField({ id: "np", label: "New password", min: 12, hint: "At least 12 characters." });
    const change = B.button("Change password", { variant: "secondary", onClick: async () => {
      if (!np.valid()) { B.showError(err, "Use at least 12 characters."); return; }
      const r = await api("POST", "/v1/admin/password", { password: cur.value, new_password: np.input.value });
      if (!r.ok) { B.showError(err, r.error); return; }
      clear(err);
      cur.value = "";
      np.input.value = "";
      B.toast("Password changed. Other sessions were signed out.");
    } });
    p.body.append(h("section", { class: "card surface-card" }, h("div", { class: "stack" }, h("h2", { class: "card-title", text: "Admin password" }), B.field("Current password", cur), np.field, err, h("div", null, change))));
    const tf = h("section", { class: "card surface-card" });
    p.body.append(tf);
    const s = await api("GET", "/v1/admin/session");
    if (!s.ok || page !== "security") return;
    sess = s.data;
    drawTOTP(tf);
  }

  function drawTOTP(box) {
    clear(box);
    const on = sess.totp_enabled;
    const inner = h("div", { class: "stack" });
    box.append(inner);
    inner.append(
      h("div", { class: "row" }, h("h2", { class: "card-title grow", text: "Two-step sign in" }), h("span", { class: "badge " + (on ? "badge-ok" : ""), text: on ? "On" : "Off" })),
      h("p", { class: "text-muted", text: on ? "You need a code from your authenticator app to sign in." : "Ask for a 6-digit code from an app like 1Password, Aegis or Google Authenticator when signing in." })
    );
    const err = B.errorSlot();
    if (!on) {
      const start = B.button("Turn on", { icon: "shield", onClick: async () => {
        const r = await api("POST", "/v1/admin/totp/setup", {});
        if (!r.ok) { B.showError(err, r.error); return; }
        const code = B.input({ inputmode: "numeric", autocomplete: "one-time-code", maxlength: "7", placeholder: "123 456", mono: true });
        const en = B.button("Confirm and turn on", { onClick: async () => {
          const x = await api("POST", "/v1/admin/totp/enable", { code: code.value.replace(/\s/g, "") });
          if (!x.ok) { B.showError(err, x.error); return; }
          sess.totp_enabled = true;
          B.toast("Two-step sign in is on");
          drawTOTP(box);
        } });
        clear(inner).append(
          h("h2", { class: "card-title", text: "Scan with your authenticator app" }),
          h("img", { class: "qr", src: r.data.qr, alt: "QR code for your authenticator app", width: "220", height: "220" }),
          h("p", { class: "field-hint center", text: "Can't scan? Enter this key instead." }),
          B.secret(r.data.secret, r.data.secret.replace(/(.{4})/g, "$1 ").trim(), { small: true, aria: "Copy key", toast: "Key copied" }),
          B.field("Enter the 6-digit code it shows", code),
          err,
          h("div", { class: "cluster" }, en, B.button("Cancel", { variant: "ghost", async: false, onClick: () => drawTOTP(box) }))
        );
        code.focus();
      } });
      inner.append(err, h("div", null, start));
    } else {
      const off = B.button("Turn off", { variant: "danger", async: false, onClick: () => {
        const pw = B.input({ type: "password", autocomplete: "current-password" });
        const e2 = B.errorSlot();
        const cancel = B.button("Cancel", { variant: "secondary", async: false, onClick: () => d.close() });
        const ok = B.button("Turn off", { variant: "danger", onClick: async () => {
          const x = await api("POST", "/v1/admin/totp/disable", { password: pw.value });
          if (!x.ok) { B.showError(e2, x.error); return; }
          d.close();
          sess.totp_enabled = false;
          B.toast("Two-step sign in is off");
          drawTOTP(box);
        } });
        const d = B.dialog("Turn off two-step sign in?", [B.field("Admin password", pw), e2], [cancel, ok]);
        pw.focus();
      } });
      inner.append(err, h("div", null, off));
    }
  }

  async function backup() {
    const p = pageShell(["Backup", "and restore."], "Keep a copy somewhere safe, like a password manager or a USB stick.");
    await ensurePlatform();
    if (page !== "backup") return;
    const pass = B.passwordField({ id: "bk", label: "Passphrase", min: 10, hint: "At least 10 characters. You need it to restore." });
    const err = B.errorSlot();
    const dl = B.button("Download backup", { icon: "download", busy: "Encrypting", onClick: async () => {
      if (!pass.valid()) { pass.input.classList.add("is-invalid"); B.showError(err, "Use at least 10 characters."); return; }
      const r = await api("POST", "/v1/admin/backup", { passphrase: pass.input.value }, { blob: true });
      if (!r.ok) { B.showError(err, r.error); return; }
      clear(err);
      B.save(r.blob, r.filename);
      B.toast("Backup downloaded");
    } });
    p.body.append(
      h("section", { class: "card surface-card card-glow" }, h("div", { class: "stack" },
        h("div", null, h("h2", { class: "card-title", text: "Download an encrypted backup" }), h("p", { class: "card-text", text: "Includes settings, accounts, devices, certificates and the admin sign in. It's locked with your passphrase using AES-256." })),
        pass.field, err, h("div", null, dl)
      )),
      h("section", { class: "card surface-quiet" }, h("div", { class: "stack" },
        h("div", null, h("h2", { class: "card-title", text: "Restoring" }), h("p", { class: "card-text", text: "On a new server, run the installer and choose \"Restore from a backup\" in setup. Everyone keeps their account numbers. Or restore from the command line:" })),
        command("veyl restore veyl-backup.vbk")
      ))
    );
  }

  async function control() {
    let scope = "manage";
    const p = pageShell(["Control Panel", "connections."], "Veyl Control watches and manages many nodes from one place. It is optional and runs on its own domain.");
    const l = loading(p.body);
    const r = await api("GET", "/v1/admin/panel/keys");
    if (!r.ok || page !== "control") return;
    l.remove();
    const holder = h("div", { class: "stack" });
    const make = B.button("Create pairing code", { icon: "key", onClick: async () => {
      const x = await api("POST", "/v1/admin/panel/pairing", { scope });
      if (!x.ok) { B.toast(x.error, "err"); return; }
      clear(holder).append(B.secret(x.data.code, x.data.code, { small: true, aria: "Copy pairing code", toast: "Pairing code copied" }), B.callout("warn", "", "Paste it into Veyl Control within 15 minutes. It works once."));
    } });
    const seg = B.segmented([["manage", "Manage", "Accounts, settings, restarts"], ["monitor", "Monitor", "Read only"]], scope, (v) => { scope = v; }, "Access");
    const pair = h("section", { class: "card surface-panel" }, h("div", { class: "card-head" }, h("h2", { text: "Connect a panel" })),
      h("div", { class: "card-body stack" }, B.settingRow("What the panel may do", "", seg), h("div", { class: "cluster" }, make), holder));
    const list = h("div", { class: "list" });
    if (!r.data.keys.length) list.append(h("p", { class: "list-item text-muted", text: "No panel is connected." }));
    r.data.keys.forEach((k) => list.append(h("div", { class: "list-item" }, icon("key"),
      h("div", { class: "grow stack stack-xs" }, h("span", { class: "list-item-title", text: k.name }), h("span", { class: "list-item-meta", text: "Added " + k.created + ", last used " + (k.last_used || "never") })),
      h("span", { class: "badge " + (k.scope === "manage" ? "badge-violet" : ""), text: k.scope === "manage" ? "Manage" : "Monitor" }),
      B.button("Revoke", { variant: "quiet", size: "sm", icon: "trash", onClick: async () => {
        if (!(await B.confirm("Revoke this key?", "That panel loses access to this node right away.", "Revoke", true))) return;
        const x = await api("DELETE", "/v1/admin/panel/keys/" + k.id);
        if (!x.ok) { B.toast(x.error, "err"); return; }
        control();
      } }))));
    const keys = h("section", { class: "card card-flush surface-panel" }, h("div", { class: "card-head" }, h("h2", { text: "Connected panels" })), list);
    const install = h("section", { class: "card surface-panel" }, h("div", { class: "card-head" }, h("h2", { text: "No panel yet?" })),
      h("div", { class: "card-body stack" }, h("p", { class: "card-text", text: "Install Veyl Control on this server or on a separate one. It needs its own domain." }), command("veyl panel install")));
    p.body.append(pair, keys, install);
  }

  async function boot() {
    const s = await B.api("GET", "/v1/admin/session");
    if (!s.ok) {
      clear(app).append(h("div", { class: "auth-box" }, B.callout("danger", "Can't open the admin panel", s.error)));
      return;
    }
    sess = s.data;
    B.state.csrf = sess.csrf || "";
    if (sess.authenticated) shell();
    else login();
  }

  boot();
})();
