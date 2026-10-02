"use strict";

(() => {
  const B = Brand;
  const { h, icon, clear } = B;
  const app = document.getElementById("app");
  const nav = document.getElementById("nav");
  const navActions = document.getElementById("nav-actions");
  const footerVersion = document.getElementById("footer-version");
  B.watchNav(nav);

  const PAGES = [
    ["fleet", "Fleet", "grid", 1],
    ["incidents", "Incidents", "activity", 1],
    ["domains", "Domains", "globe", 1],
    ["alerts", "Alerts", "zap", 2],
    ["team", "Team", "users", 3],
    ["audit", "Audit log", "book", 2],
    ["system", "System", "server", 1],
    ["account", "Your account", "user", 1]
  ];
  const LEVEL = { viewer: 1, admin: 2, owner: 3 };
  const EVENT_KIND = {
    down: "Down",
    service: "Service failed"
  };

  let sess = null;
  let page = "fleet";
  let content = null;
  let links = [];
  let poll = 0;
  const selected = new Set();

  function can(level) { return sess && sess.user && LEVEL[sess.user.role] >= level; }

  async function api(method, url, body, extra) {
    const r = await B.api(method, url, body, extra);
    if (r.status === 401 && sess && sess.authenticated && !url.startsWith("api/login")) {
      sess = null;
      await boot("You were signed out. Sign in again.");
    }
    if (r.data && r.data.csrf) B.state.csrf = r.data.csrf;
    return r;
  }

  function title(main, dim) {
    const el = h("h1", { class: "text-title", tabindex: "-1" }, main);
    if (dim) el.append(" ", h("span", { class: "text-dim", text: dim }));
    return el;
  }

  function fmt(n) { return Number(n || 0).toLocaleString(); }

  function pct(v) {
    if (v === null || v === undefined) return "No data";
    const p = v * 100;
    if (p >= 99.995) return "100%";
    return p.toFixed(p >= 99 ? 2 : 1) + "%";
  }

  function ago(unix) {
    if (!unix) return "never";
    const s = Math.max(0, Math.floor(Date.now() / 1000 - unix));
    if (s < 60) return "just now";
    if (s < 3600) return Math.floor(s / 60) + " min ago";
    if (s < 86400) return Math.floor(s / 3600) + " h ago";
    return Math.floor(s / 86400) + " d ago";
  }

  function when(unix) {
    if (!unix) return "";
    const d = new Date(unix * 1000);
    return d.toISOString().slice(0, 16).replace("T", " ") + " UTC";
  }

  function span(sec) {
    sec = Math.max(0, Math.floor(sec));
    const d = Math.floor(sec / 86400);
    const hh = Math.floor((sec % 86400) / 3600);
    const m = Math.floor((sec % 3600) / 60);
    if (d) return d + "d " + hh + "h";
    if (hh) return hh + "h " + m + "m";
    return m + "m";
  }

  function daysLeft(iso) {
    if (!iso) return null;
    const t = Date.parse(iso);
    if (isNaN(t)) return null;
    return Math.floor((t - Date.now()) / 86400000);
  }

  function setNavActions(kids) { clear(navActions).append(...kids); }

  function card(cls, ...kids) { return h("section", { class: "card " + (cls || "surface-panel") }, ...kids); }

  function head(text, right) { return h("div", { class: "card-head" }, h("h2", { text }), right || null); }

  function loading(body) {
    const l = h("div", { class: "loading" }, B.spinner());
    body.append(l);
    return l;
  }

  function emptyState(text, action) {
    return h("div", { class: "card surface-quiet" }, h("div", { class: "empty" }, B.mark(), h("p", { class: "empty-title", text }), action || null));
  }

  function statusDot(status) {
    const cls = { up: "is-ok is-live", degraded: "is-warn", down: "is-danger" }[status] || "";
    return h("span", { class: "dot " + cls, "aria-hidden": "true" });
  }

  function statusBadge(status) {
    const m = { up: ["badge-ok", "Up"], degraded: ["badge-warn", "Needs a look"], down: ["badge-danger", "Down"], checking: ["", "Checking"], unknown: ["", "Waiting"] };
    const [c, t] = m[status] || m.unknown;
    return h("span", { class: "badge " + c, text: t });
  }

  function strip(cells, days) {
    const s = h("div", { class: "strip" + (days ? " is-days" : ""), role: "img", "aria-label": days ? "Uptime per day" : "Uptime for the last 48 hours" });
    cells.forEach((v) => {
      let c = "";
      if (v >= 999) c = "is-ok";
      else if (v >= 950) c = "is-ok-dim";
      else if (v >= 0 && v >= 500) c = "is-warn";
      else if (v >= 0) c = "is-danger";
      s.append(h("i", { class: c }));
    });
    return s;
  }

  function secretDialog(heading, value, note) {
    const close = B.button("Done", { async: false, onClick: () => d.close() });
    const d = B.dialog(heading, [B.secret(value, value, { aria: "Copy", toast: "Copied", small: value.length > 24 }), note ? B.callout("warn", "", note) : null], [close]);
    return d;
  }

  function codesView(codes) {
    const list = h("ol", { class: "codes" });
    codes.forEach((c) => list.append(h("li", { text: c })));
    const text = codes.join("\n");
    return h("div", { class: "stack" },
      list,
      h("div", { class: "cluster" },
        B.copyButton(text, { class: "btn btn-secondary btn-sm", aria: "Copy recovery codes", toast: "Recovery codes copied" }),
        B.button("Download", { variant: "ghost", size: "sm", icon: "download", async: false, onClick: () => B.save(new Blob([text + "\n"], { type: "text/plain" }), "veyl-control-recovery-codes.txt") })
      ),
      B.callout("warn", "Keep these somewhere safe", "Each code signs you in once if you lose your phone. They are not shown again.")
    );
  }

  async function boot(msg) {
    const r = await api("GET", "api/session");
    if (!r.ok) {
      clear(app).append(B.callout("danger", "Veyl Control is not ready", r.error));
      return;
    }
    sess = r.data;
    B.state.platform = sess.platform || "linux";
    if (!sess.configured && !sess.authenticated && !location.pathname.endsWith("/join")) {
      const st = await B.api("GET", "api/fleet");
      if (st.code === "NOT_SET_UP") {
        clear(app).append(h("div", { class: "auth-box rise" },
          h("div", { class: "auth-head" }, title("Finish setup", "first."), h("p", { class: "text-lede", text: "Open the setup link the installer printed. Lost it? Run this on the server." })),
          B.codeBlock("sudo veyl panel setup-link", "On your server")
        ));
        return;
      }
    }
    if (location.pathname.endsWith("/join")) {
      join();
      return;
    }
    if (!sess.authenticated) {
      login(msg);
      return;
    }
    shell();
  }

  function authBox(heading, dim, lede, ...kids) {
    setNavActions([]);
    clear(app).append(h("div", { class: "auth-box rise" },
      h("div", { class: "auth-head" }, title(heading, dim), lede ? h("p", { class: "text-lede", text: lede }) : null),
      ...kids
    ));
    const h1 = app.querySelector("h1");
    if (h1) h1.focus({ preventScroll: true });
  }

  function login(msg) {
    clearInterval(poll);
    const err = B.errorSlot();
    const user = B.input({ autocomplete: "username", placeholder: "Username", class: "input-lg", autocapitalize: "off", spellcheck: "false" });
    const pw = B.input({ type: "password", autocomplete: "current-password", placeholder: "Password", class: "input-lg" });
    const code = B.input({ inputmode: "numeric", autocomplete: "one-time-code", placeholder: "123 456", mono: true, class: "input-lg" });
    const codeField = B.field("Code from your authenticator app", code, "Lost your phone? Use one of your recovery codes instead.");
    codeField.classList.add("is-hidden");
    const btn = h("button", { class: "btn btn-primary btn-lg btn-block", type: "submit" }, h("span", { text: "Sign in" }), icon("arrowRight", "icon-arrow"));
    btn.dataset.busy = "Signing in";
    const form = h("form", { class: "card surface-card card-glow stack", novalidate: true },
      B.field("Username", user), B.field("Password", pw), codeField, err, btn);
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      B.busy(btn, async () => {
        clear(err);
        if (!user.value || !pw.value) { B.showError(err, "Enter your username and password."); return; }
        const r = await api("POST", "api/login", { username: user.value.trim().toLowerCase(), password: pw.value, code: code.value.replace(/\s/g, "") });
        if (r.ok && r.data.enroll) { enroll(r.data.enroll, "Set up two-step sign in", "Your account needs a fresh authenticator before you continue."); return; }
        if (r.code === "CODE_REQUIRED") { codeField.classList.remove("is-hidden"); code.focus(); return; }
        if (!r.ok) { B.showError(err, r.error); if (r.code === "INVALID_CODE") code.select(); return; }
        if (r.data.recovery_left !== undefined && r.data.recovery_left < 3) B.toast("Only " + r.data.recovery_left + " recovery codes left. Make new ones under Your account.", "err");
        await boot();
      });
    });
    authBox("Sign in to", (sess && sess.name ? sess.name : "Veyl Control") + ".", msg || "Manage every Veyl node from one place.", form,
      h("p", { class: "auth-foot", text: "Locked out? Run \"sudo veyl panel recover <username>\" on the panel server." }));
    user.focus();
  }

  async function enroll(ticket, heading, lede) {
    const r = await api("POST", "api/enroll/info", { ticket });
    if (!r.ok) { login(r.error); return; }
    const err = B.errorSlot();
    const code = B.input({ inputmode: "numeric", autocomplete: "one-time-code", placeholder: "123 456", mono: true, class: "input-lg" });
    const btn = h("button", { class: "btn btn-primary btn-lg btn-block", type: "submit" }, h("span", { text: "Turn on two-step sign in" }));
    const form = h("form", { class: "card surface-card stack", novalidate: true },
      h("p", { class: "text-muted", text: "Scan this with an authenticator app such as Aegis, 2FAS or 1Password, then type the 6 digit code it shows." }),
      h("img", { class: "qr", src: r.data.qr, alt: "QR code for your authenticator app", width: "220", height: "220" }),
      B.secret(r.data.secret, r.data.secret, { small: true, aria: "Copy setup key", toast: "Setup key copied" }),
      B.field("Code", code), err, btn);
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      B.busy(btn, async () => {
        const x = await api("POST", "api/enroll/finish", { ticket, code: code.value.replace(/\s/g, "") });
        if (!x.ok) { B.showError(err, x.error); code.select(); return; }
        const cont = B.button("Continue to Veyl Control", { size: "lg", trailing: "arrowRight", async: false, onClick: () => { location.href = "./"; } });
        authBox("Save your", "recovery codes.", "You are signed in as " + r.data.username + ".", card("surface-card", codesView(x.data.recovery)), cont);
      });
    });
    authBox(heading, null, lede, form);
    code.focus();
  }

  async function join() {
    const token = location.hash.replace(/^#/, "");
    history.replaceState(null, "", location.pathname);
    const info = await api("POST", "api/join/info", { token });
    if (!info.ok) {
      authBox("This invite", "does not work.", info.error);
      return;
    }
    const err = B.errorSlot();
    const user = B.input({ autocomplete: "username", placeholder: "jordan", class: "input-lg", autocapitalize: "off", spellcheck: "false" });
    const pw = B.passwordField({ label: "Password", min: 12, hint: "At least 12 characters." });
    const btn = h("button", { class: "btn btn-primary btn-lg btn-block", type: "submit" }, h("span", { text: "Create my account" }), icon("arrowRight", "icon-arrow"));
    const form = h("form", { class: "card surface-card stack", novalidate: true }, B.field("Username", user, "Lowercase letters, digits, dots and dashes."), pw.field, err, btn);
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      B.busy(btn, async () => {
        if (!pw.valid()) { B.showError(err, "Use at least 12 characters."); return; }
        const r = await api("POST", "api/join/start", { token, username: user.value.trim().toLowerCase(), password: pw.input.value });
        if (!r.ok) { B.showError(err, r.error); return; }
        enroll(r.data.enroll, "Set up two-step sign in", "Every member of the team uses an authenticator app.");
      });
    });
    authBox("Join", info.data.name + ".", info.data.by + " invited you as " + (info.data.role === "admin" ? "an admin" : "a" + (info.data.role === "owner" ? "n owner" : " viewer")) + ".", form);
  }

  async function logout() {
    await api("POST", "api/logout", {});
    sess = null;
    await boot("Signed out.");
  }

  function shell() {
    links = [];
    const side = h("nav", { class: "side-nav", "aria-label": "Veyl Control" });
    const tabs = h("nav", { class: "tabs", "aria-label": "Sections" });
    PAGES.filter((p) => can(p[3])).forEach(([id, label, ic]) => {
      const a = h("a", { class: "side-nav-link", href: "#" + id, "data-page": id }, icon(ic), h("span", { text: label }));
      const t = h("a", { class: "tab", href: "#" + id, "data-page": id }, icon(ic), h("span", { text: label }));
      links.push(a, t);
      side.append(a);
      tabs.append(t);
    });
    content = h("div", { class: "app-content" });
    const aside = h("aside", { class: "app-aside" },
      h("div", { class: "nav-only-desktop stack" },
        h("div", { class: "stack stack-xs" }, h("p", { class: "heading-sm", text: sess.name || "Veyl Control" }), h("p", { class: "text-sm text-subtle", text: sess.user.username + ", " + sess.user.role })),
        side
      ),
      h("div", { class: "nav-only-mobile" }, tabs)
    );
    clear(app).append(h("div", { class: "app-layout" }, aside, content));
    setNavActions([
      h("span", { class: "nav-meta", text: location.host }),
      B.button("Sign out", { variant: "secondary", size: "sm", icon: "logout", onClick: logout })
    ]);
    route();
  }

  function route() {
    const want = location.hash.replace(/^#/, "").split("/");
    clearInterval(poll);
    if (want[0] === "node" && want[1]) {
      page = "node";
      mark("fleet");
      node(want[1], want[2] || "overview");
      return;
    }
    page = PAGES.some((p) => p[0] === want[0] && can(p[3])) ? want[0] : "fleet";
    mark(page);
    ({ fleet, incidents, domains, alerts, team, audit, system, account })[page]();
  }

  function mark(id) {
    links.forEach((a) => {
      if (a.getAttribute("data-page") === id) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    const tab = links.find((a) => a.classList.contains("tab") && a.getAttribute("data-page") === id);
    if (tab && tab.scrollIntoView && window.innerWidth < 1024) tab.scrollIntoView({ block: "nearest", inline: "center" });
  }

  window.addEventListener("hashchange", () => { if (sess && sess.authenticated) route(); });

  function pageShell(heading, lead, right) {
    clear(content);
    const hd = h("header", { class: "page-header" },
      h("div", { class: "page-header-text" }, Array.isArray(heading) ? title(heading[0], heading[1]) : title(heading), lead ? h("p", { class: "text-lede", text: lead }) : null),
      right ? h("div", { class: "cluster" }, right) : null
    );
    const body = h("div", { class: "page-body" });
    const p = h("div", { class: "rise" }, hd, body);
    content.append(p);
    window.scrollTo(0, 0);
    return { el: p, head: hd, body };
  }

  function stat(label, value) {
    return h("div", { class: "stat" }, h("div", { class: "stat-label", text: label }), h("div", { class: "stat-value", text: value }));
  }

  function addNodeDialog() {
    const err = B.errorSlot();
    const code = B.input({ placeholder: "vpp_", mono: true, autocomplete: "off", spellcheck: "false" });
    const name = B.input({ placeholder: "Amsterdam" });
    const pinSlot = h("div");
    let pin = "";
    const go = B.button("Connect node", { icon: "plus", onClick: async () => {
      clear(err);
      const r = await api("POST", "api/nodes", { code: code.value.trim(), name: name.value.trim(), pin });
      if (r.status === 409 && r.data && r.data.code === "UNTRUSTED_CERT") {
        pin = r.data.fingerprint || "";
        clear(pinSlot).append(B.callout("warn", "Check this fingerprint", h("div", { class: "stack stack-sm" },
          h("p", { text: r.data.error }),
          h("p", { class: "mono-wrap", text: pin.replace(/(..)(?=.)/g, "$1:") }),
          h("p", { class: "text-sm text-muted", text: "Press Connect node again to pin it." }))));
        return;
      }
      if (!r.ok) { B.showError(err, r.error); return; }
      d.close();
      B.toast("Connected " + r.data.node.name);
      fleet();
    } });
    const cancel = B.button("Cancel", { variant: "secondary", async: false, onClick: () => d.close() });
    const d = B.dialog("Connect a node", [
      h("p", { class: "text-muted", text: "On the VPN node, open the admin panel under Control Panel, or run this command, then paste the code here. Codes work once and expire after 15 minutes." }),
      B.codeBlock("sudo veyl panel pair", "On the node"),
      B.field("Pairing code", code),
      B.field("Name in Veyl Control", name, "Optional. Defaults to the node's own name."),
      pinSlot, err
    ], [cancel, go]);
    code.focus();
  }

  function nodeCard(n, onSelect) {
    const check = h("input", { type: "checkbox", class: "node-check", "aria-label": "Select " + n.name, checked: selected.has(n.id) });
    check.addEventListener("change", () => { if (check.checked) selected.add(n.id); else selected.delete(n.id); onSelect(); });
    const days = daysLeft(n.cert_expiry);
    const failed = (n.services || []).filter((s) => s.state === "failed").map((s) => s.name);
    const notes = [];
    if (n.status === "down" && n.error) notes.push(B.callout("danger", "", "Not answering: " + n.error + "."));
    if (failed.length) notes.push(B.callout("warn", "", "Failed: " + failed.join(", ") + (n.heal ? ". Auto-heal is on it." : ".")));
    if (n.update) notes.push(h("p", { class: "row text-sm text-violet" }, icon("sparkPixel"), h("span", { text: "Update to " + n.update + " available" })));
    return h("article", { class: "node-card is-" + n.status },
      h("div", { class: "node-card-head" },
        can(2) ? check : null,
        h("div", { class: "grow stack stack-xs" },
          h("a", { class: "node-card-title", href: "#node/" + n.id, text: n.name }),
          h("span", { class: "node-card-host", text: n.host })
        ),
        statusBadge(n.status)
      ),
      h("dl", { class: "node-card-stats" },
        h("div", null, h("dt", { text: "Connected" }), h("dd", { text: n.status === "down" ? "-" : fmt(n.connected) })),
        h("div", null, h("dt", { text: "Accounts" }), h("dd", { text: fmt(n.accounts) })),
        h("div", null, h("dt", { text: "Uptime 30d" }), h("dd", { text: pct(n.uptime_30d) }))
      ),
      h("div", { class: "stack stack-xs" }, strip(n.hours || []), h("div", { class: "strip-legend" }, h("span", { text: "48 hours ago" }), h("span", { text: "now" }))),
      ...notes,
      h("div", { class: "cluster cluster-between text-xs text-subtle" },
        h("span", { text: (n.version ? "Veyl " + n.version : "Version unknown") + " on " + (n.platform === "windows" ? "Windows" : "Linux") }),
        h("span", { text: days === null ? "" : "Certificate " + (days < 0 ? "expired" : days + " days left") })
      )
    );
  }

  async function bulk(action, params) {
    const ids = [...selected];
    const r = await api("POST", "api/bulk", { action, nodes: ids, params });
    if (!r.ok) { B.toast(r.error, "err"); return; }
    const rows = r.data.results.map((x) => h("div", { class: "list-item" },
      h("span", { class: "dot " + (x.ok ? "is-ok" : "is-danger"), "aria-hidden": "true" }),
      h("span", { class: "grow", text: x.name }),
      x.ok && x.data && x.data.code ? B.copyButton(x.data.code, { class: "btn btn-secondary btn-sm", aria: "Copy invite for " + x.name, toast: "Invite copied" }) : null,
      h("span", { class: "text-sm " + (x.ok ? "text-ok" : "text-danger"), text: x.ok ? (x.data && x.data.code ? x.data.code : "Started") : (x.error || "Failed") })
    ));
    const done = B.button("Done", { async: false, onClick: () => d.close() });
    const d = B.dialog("Results", [h("div", { class: "list" }, ...rows)], [done]);
  }

  async function fleet() {
    const add = can(2) ? B.button("Connect a node", { icon: "plus", async: false, onClick: addNodeDialog }) : null;
    const p = pageShell(["Your fleet", "at a glance."], "Every node is checked every 30 seconds. Only health is stored, never who uses the VPN.", add);
    const l = loading(p.body);
    const r = await api("GET", "api/fleet");
    if (!r.ok || page !== "fleet") return;
    l.remove();
    const f = r.data;
    const t = f.totals;
    if (!f.nodes.length) {
      p.body.append(emptyState("No nodes yet. Connect your first VPN server.", add ? B.button("Connect a node", { variant: "secondary", icon: "plus", async: false, onClick: addNodeDialog }) : null));
      return;
    }
    const bad = (t.down || 0) + (t.degraded || 0);
    clear(p.head.querySelector("h1")).append(bad ? (bad === 1 ? "One node" : bad + " nodes") : "Your fleet", " ", h("span", { class: "text-dim", text: bad ? (bad === 1 ? "needs a look." : "need a look.") : "is healthy." }));
    const pixels = h("div", { class: "fleet-pixels", role: "img", "aria-label": (t.up || 0) + " up, " + (t.degraded || 0) + " need a look, " + (t.down || 0) + " down" });
    f.nodes.forEach((n) => pixels.append(h("i", { class: { up: "is-ok", degraded: "is-warn", down: "is-danger" }[n.status] || "", title: n.name })));
    const hero = h("section", { class: "card surface-card card-glow-bottom", "aria-label": "Fleet status" },
      h("div", { class: "grid-2" },
        h("div", { class: "stack" },
          h("p", { class: "label text-subtle", text: "Connected now, all nodes" }),
          h("div", { class: "text-headline tabular", text: fmt(t.connected) }),
          h("p", { class: "row text-sm text-muted" }, h("span", { class: "dot " + (bad ? "is-warn" : "is-ok is-live"), "aria-hidden": "true" }), h("span", { text: bad ? bad + " of " + t.nodes + " nodes need attention" : "All " + t.nodes + " nodes answering" }))
        ),
        pixels
      ),
      h("div", { class: "stat-grid mt-8" },
        stat("Nodes", fmt(t.nodes)),
        stat("Accounts", fmt(t.accounts)),
        stat("Devices", fmt(t.devices)),
        stat("Open incidents", fmt(t.incidents))
      )
    );
    const grid = h("div", { class: "fleet-grid" });
    const bar = h("div", { class: "bulk-bar is-hidden", role: "region", "aria-label": "Bulk actions" });
    const sync = () => {
      clear(bar);
      bar.classList.toggle("is-hidden", selected.size === 0);
      if (!selected.size) return;
      bar.append(
        h("span", { class: "grow text-sm", text: selected.size + " selected" }),
        B.button("Same invite everywhere", { variant: "secondary", size: "sm", icon: "ticket", onClick: () => bulk("invite", { uses: 1, expires_days: 7 }) }),
        B.button("Update blocklists", { variant: "secondary", size: "sm", icon: "refresh", onClick: () => bulk("blocklists") }),
        B.button("Update Veyl", { variant: "secondary", size: "sm", icon: "download", onClick: async () => { if (await B.confirm("Update the selected nodes?", "Each node downloads the latest release and restarts its services. Connected people reconnect on their own.", "Update")) await bulk("update"); } }),
        B.button("Clear", { variant: "ghost", size: "sm", async: false, onClick: () => { selected.clear(); draw(); } })
      );
    };
    const draw = () => {
      clear(grid);
      f.nodes.forEach((n) => grid.append(nodeCard(n, sync)));
      sync();
    };
    draw();
    p.body.append(hero, grid, bar);
    if (f.release) p.body.append(h("p", { class: "text-sm text-subtle", text: "Latest release: " + f.release }));
    poll = setInterval(async () => {
      if (page !== "fleet" || document.hidden) return;
      const x = await api("GET", "api/fleet");
      if (!x.ok || page !== "fleet") return;
      f.nodes = x.data.nodes;
      draw();
    }, 30000);
  }

  function serviceBadge(state) {
    if (state === "active") return h("span", { class: "badge badge-ok", text: "Running" });
    if (state === "failed") return h("span", { class: "badge badge-danger", text: "Failed" });
    if (state === "inactive") return h("span", { class: "badge", text: "Stopped" });
    return h("span", { class: "badge badge-warn", text: state });
  }

  function nodeAPI(id) { return "api/nodes/" + id + "/admin/"; }

  function watchJob(id, list, bar, heading, after) {
    B.stream(nodeAPI(id) + "apply-progress", (ev) => list.step(ev), (d) => {
      const ok = !!(d && d.ok);
      list.settle(ok);
      if (ok) bar.done(); else bar.fail();
      heading.textContent = ok ? "All done" : "Something did not finish";
      if (!ok) B.toast((d && d.error) || "Lost contact with the node.", "err");
      if (after) after(ok);
    });
  }

  function jobCard(container, id, label, after) {
    const list = B.progress();
    const bar = B.progressBar();
    const heading = h("h2", { class: "card-title", text: label });
    const c = h("section", { class: "card surface-card" }, h("div", { class: "stack" }, heading, bar.el, list.el));
    container.insertBefore(c, container.firstChild);
    watchJob(id, list, bar, heading, after);
  }

  async function node(id, tab) {
    const p = pageShell("Node", "");
    const l = loading(p.body);
    const r = await api("GET", "api/nodes/" + id);
    if (page !== "node") return;
    l.remove();
    if (!r.ok) { p.body.append(B.callout("danger", "", r.error)); return; }
    const n = r.data.node;
    clear(p.head.querySelector("h1")).append(n.name, " ", h("span", { class: "text-dim", text: { up: "is up.", degraded: "needs a look.", down: "is down.", checking: "is being checked.", unknown: "is waiting for its first check." }[n.status] }));
    p.head.querySelector(".text-lede") || p.head.firstChild.append(h("p", { class: "text-lede", text: n.host }));
    p.head.querySelector(".text-lede").textContent = n.host + (n.version ? ", Veyl " + n.version : "");
    const tabs = h("nav", { class: "tabs", "aria-label": "Node sections" });
    [["overview", "Overview", "grid"], ["accounts", "Accounts", "users"], ["invites", "Invites", "ticket"], ["settings", "Settings", "sliders"]].forEach(([k, label, ic]) => {
      tabs.append(h("a", { class: "tab", href: "#node/" + id + "/" + k, "aria-current": k === tab ? "page" : null }, icon(ic), h("span", { text: label })));
    });
    p.body.append(h("div", { class: "cluster" }, B.button("All nodes", { variant: "ghost", size: "sm", icon: "arrowLeft", href: "#fleet" }), tabs));
    const body = h("div", { class: "stack stack-lg" });
    p.body.append(body);
    ({ overview: nodeOverview, accounts: nodeAccounts, invites: nodeInvites, settings: nodeSettings }[tab] || nodeOverview)(id, n, r.data, body);
  }

  function nodeOverview(id, n, d, body) {
    const days = d.days || [];
    const hero = h("section", { class: "card surface-card card-glow-bottom" },
      h("div", { class: "stat-grid" },
        stat("Connected now", n.status === "down" ? "-" : fmt(n.connected)),
        stat("Uptime 24h", pct(n.uptime_24h)),
        stat("Uptime 30d", pct(n.uptime_30d)),
        stat("Uptime 90d", pct(n.uptime_90d))
      ),
      h("div", { class: "stack stack-xs mt-8" }, strip(days.slice(-45), true), h("div", { class: "strip-legend" }, h("span", { text: "45 days ago" }), h("span", { text: "today" })))
    );
    const svcList = h("div", { class: "list" });
    if (!n.services.length) svcList.append(h("p", { class: "list-item text-muted", text: "Service states show after the first successful check." }));
    n.services.forEach((s) => {
      const restart = can(2) && n.scope === "manage" ? B.button("Restart", { variant: "quiet", size: "sm", icon: "refresh", onClick: async () => {
        const x = await api("POST", nodeAPI(id) + "services/restart", { service: s.name });
        if (!x.ok) { B.toast(x.error, "err"); return; }
        jobCard(body, id, "Restarting " + s.name);
      } }) : null;
      svcList.append(h("div", { class: "list-item" }, h("span", { class: "dot " + (s.state === "active" ? "is-ok" : s.state === "failed" ? "is-danger" : ""), "aria-hidden": "true" }), h("span", { class: "grow text-mono text-sm", text: s.name }), serviceBadge(s.state), restart));
    });
    const kv = h("dl", { class: "kv kv-mono" });
    const row = (k, v, accent) => { if (v !== undefined && v !== null && v !== "") kv.append(h("div", { class: "kv-row" }, h("dt", { class: "kv-key" + (accent ? " is-accent" : ""), text: k }), h("dd", { class: "kv-value", text: String(v) }))); };
    row("address", d.url, true);
    row("platform", n.platform);
    row("version", n.version);
    row("memory", n.mem);
    row("load", n.load);
    row("disk", n.disk ? Math.round(n.disk * 100) + "% used" : "");
    row("certificate", n.cert_expiry ? "expires " + n.cert_expiry.slice(0, 10) : "");
    row("blocklists", n.blocklist_updated ? "updated " + n.blocklist_updated : "");
    row("last check", n.last_probe ? ago(n.last_probe) : "");
    row("pinned", d.pinned ? "certificate pinned" : "");
    row("key scope", n.scope);
    const actions = h("div", { class: "cluster" });
    if (can(2) && n.scope === "manage") {
      actions.append(
        B.button("Update blocklists", { variant: "secondary", size: "sm", icon: "refresh", onClick: async () => {
          const x = await api("POST", nodeAPI(id) + "dns/update", {});
          if (!x.ok) { B.toast(x.error, "err"); return; }
          jobCard(body, id, "Updating blocklists");
        } }),
        B.button("Restart all services", { variant: "secondary", size: "sm", icon: "refresh", onClick: async () => {
          if (!(await B.confirm("Restart every service?", "Connected people drop for a few seconds and reconnect on their own.", "Restart"))) return;
          const x = await api("POST", nodeAPI(id) + "services/restart", {});
          if (!x.ok) { B.toast(x.error, "err"); return; }
          jobCard(body, id, "Restarting services");
        } }),
        B.button(n.update ? "Update to " + n.update : "Update Veyl", { variant: n.update ? "primary" : "secondary", size: "sm", icon: "download", onClick: async () => {
          if (!(await B.confirm("Update this node?", "The node downloads the latest release and restarts. It is back in about a minute.", "Update"))) return;
          const x = await api("POST", nodeAPI(id) + "update", {});
          if (!x.ok) { B.toast(x.error, "err"); return; }
          B.toast("Update started");
        } })
      );
    }
    const heal = B.setting("Auto-heal", "Restart failed services on their own, at most 3 times an hour, waiting longer each time.", n.heal, { icon: "wand", disabled: !can(2) || n.scope !== "manage", onChange: async (on) => {
      const x = await api("PATCH", "api/nodes/" + id, { heal: on });
      B.toast(x.ok ? (on ? "Auto-heal on" : "Auto-heal off") : x.error, x.ok ? "" : "err");
    } });
    const manage = card("card-flush surface-panel", head("Manage"), h("div", { class: "card-body stack" }, actions, heal.row,
      can(2) ? h("div", { class: "cluster" },
        B.button("Rename", { variant: "ghost", size: "sm", icon: "edit", async: false, onClick: () => renameNode(id, n.name) }),
        B.button("Remove from Veyl Control", { variant: "ghost", size: "sm", icon: "trash", onClick: async () => {
          if (!(await B.confirm("Remove " + n.name + "?", "The node keeps running. Its key for this panel is revoked and its history here is deleted.", "Remove", true))) return;
          const x = await api("DELETE", "api/nodes/" + id);
          if (!x.ok) { B.toast(x.error, "err"); return; }
          B.toast("Removed");
          location.hash = "#fleet";
        } })) : null));
    const inc = card("card-flush surface-panel", head("Incidents"), incidentList(d.incidents || [], false));
    body.append(hero, h("div", { class: "grid-2" }, card("card-flush surface-panel", head("Services"), svcList), card("card-flush surface-panel", head("Server"), kv)), manage, inc);
  }

  function renameNode(id, current) {
    const name = B.input({ value: current });
    const save = B.button("Save", { onClick: async () => {
      const x = await api("PATCH", "api/nodes/" + id, { name: name.value.trim() });
      if (!x.ok) { B.toast(x.error, "err"); return; }
      d.close();
      route();
    } });
    const d = B.dialog("Rename node", [B.field("Name", name)], [B.button("Cancel", { variant: "secondary", async: false, onClick: () => d.close() }), save]);
  }

  async function nodeAccounts(id, n, d, body) {
    const add = can(2) ? B.button("New account", { icon: "plus", async: false, onClick: () => newAccount(id, body) }) : null;
    if (add) body.append(h("div", { class: "cluster" }, add));
    const l = loading(body);
    const r = await api("GET", nodeAPI(id) + "accounts");
    l.remove();
    if (!r.ok) { body.append(B.callout("danger", "", r.error)); return; }
    if (!r.data.accounts.length) { body.append(emptyState("No accounts on this node yet.")); return; }
    const tb = h("tbody");
    r.data.accounts.forEach((a) => {
      const name = a.label || "Account " + a.id.slice(0, 4).toUpperCase();
      const st = a.status === "disabled" ? ["badge-danger", "Paused"] : a.status === "expired" ? ["badge-warn", "Expired"] : ["badge-ok", "Active"];
      const acts = h("div", { class: "cluster cluster-tight" });
      if (can(2)) {
        acts.append(
          B.button("", { variant: "quiet", size: "sm", icon: "phone", aria: "Devices of " + name, async: false, onClick: () => devices(id, a, name) }),
          B.button("", { variant: "quiet", size: "sm", icon: a.disabled ? "play" : "pause", aria: (a.disabled ? "Resume " : "Pause ") + name, onClick: async () => {
            const x = await api("PATCH", nodeAPI(id) + "accounts/" + a.id, { disabled: !a.disabled });
            if (!x.ok) { B.toast(x.error, "err"); return; }
            route();
          } }),
          B.button("", { variant: "quiet", size: "sm", icon: "clock", aria: "Expire " + name + " now", onClick: async () => {
            if (!(await B.confirm("Expire " + name + " today?", "Its devices stop connecting. You can extend it again later.", "Expire"))) return;
            const x = await api("PATCH", nodeAPI(id) + "accounts/" + a.id, { expires_days: 0, disabled: true });
            if (!x.ok) { B.toast(x.error, "err"); return; }
            route();
          } }),
          B.button("", { variant: "quiet", size: "sm", icon: "trash", aria: "Delete " + name, onClick: async () => {
            if (!(await B.confirm("Delete " + name + "?", "All of its devices are revoked right away. This cannot be undone.", "Delete", true))) return;
            const x = await api("DELETE", nodeAPI(id) + "accounts/" + a.id);
            if (!x.ok) { B.toast(x.error, "err"); return; }
            B.toast("Deleted");
            route();
          } })
        );
      }
      tb.append(h("tr", null,
        h("td", { class: "is-strong", text: name }),
        h("td", null, h("span", { class: "badge " + st[0], text: st[1] })),
        h("td", { class: "is-num", text: a.devices + " of " + a.max_devices }),
        h("td", { class: "text-sm", text: a.expires ? B.date(a.expires) : "Never" }),
        h("td", null, acts)
      ));
    });
    body.append(card("card-flush surface-panel", h("div", { class: "table-wrap" }, h("table", { class: "table" },
      h("thead", null, h("tr", null, ...["Account", "Status", "Devices", "Expires", ""].map((x) => h("th", { scope: "col", text: x })))), tb))));
  }

  async function devices(id, a, name) {
    const list = h("div", { class: "list" });
    const close = B.button("Done", { async: false, onClick: () => d.close() });
    const d = B.dialog("Devices of " + name, [list], [close]);
    const r = await api("GET", nodeAPI(id) + "accounts/" + a.id + "/devices");
    if (!r.ok) { list.append(B.callout("danger", "", r.error)); return; }
    if (!r.data.devices.length) list.append(h("p", { class: "list-item text-muted", text: "No devices yet." }));
    r.data.devices.forEach((dv) => {
      const row = h("div", { class: "list-item" }, h("span", { class: "dot " + (dv.online ? "is-ok" : ""), "aria-hidden": "true" }), h("span", { class: "grow", text: dv.name || dv.id }),
        B.button("Revoke", { variant: "quiet", size: "sm", icon: "ban", onClick: async () => {
          const x = await api("DELETE", nodeAPI(id) + "accounts/" + a.id + "/devices/" + encodeURIComponent(dv.id));
          if (!x.ok) { B.toast(x.error, "err"); return; }
          row.remove();
          B.toast("Device revoked");
        } }));
      list.append(row);
    });
  }

  function newAccount(id, body) {
    const err = B.errorSlot();
    const label = B.input({ placeholder: "Family laptop" });
    const days = B.select([[0, "Never"], [30, "30 days"], [90, "90 days"], [365, "1 year"]], 0);
    const go = B.button("Create account", { onClick: async () => {
      const x = await api("POST", nodeAPI(id) + "accounts", { label: label.value.trim(), expires_days: Number(days.value) });
      if (!x.ok) { B.showError(err, x.error); return; }
      d.close();
      secretDialog("Account number", B.groupNumber(x.data.number), "Write this number down. It is stored hashed on the node and never shown again. Veyl Control does not keep it.");
      route();
    } });
    const d = B.dialog("New account", [B.field("Name", label, "Only you see this."), B.field("Expires", days), err], [B.button("Cancel", { variant: "secondary", async: false, onClick: () => d.close() }), go]);
    label.focus();
  }

  async function nodeInvites(id, n, d, body) {
    const add = can(2) ? B.button("New invite", { icon: "plus", onClick: async () => {
      const x = await api("POST", nodeAPI(id) + "invites", { uses: 1, expires_days: 7 });
      if (!x.ok) { B.toast(x.error, "err"); return; }
      secretDialog("Invite code", x.data.code, "Share it with one person. It works once and expires in 7 days.");
      route();
    } }) : null;
    if (add) body.append(h("div", { class: "cluster" }, add));
    const r = await api("GET", nodeAPI(id) + "invites");
    if (!r.ok) { body.append(B.callout("danger", "", r.error)); return; }
    if (!r.data.invites.length) { body.append(emptyState("No open invites on this node.")); return; }
    const list = h("div", { class: "list" });
    r.data.invites.forEach((iv) => list.append(h("div", { class: "list-item" },
      icon("ticket"), h("span", { class: "grow", text: "Used " + iv.used + " of " + iv.uses }), h("span", { class: "text-sm text-subtle", text: iv.expires ? "Until " + B.date(iv.expires) : "No expiry" }),
      can(2) ? B.button("", { variant: "quiet", size: "sm", icon: "trash", aria: "Delete invite", onClick: async () => {
        const x = await api("DELETE", nodeAPI(id) + "invites/" + iv.id);
        if (!x.ok) { B.toast(x.error, "err"); return; }
        route();
      } }) : null)));
    body.append(card("card-flush surface-panel", list));
  }

  async function nodeSettings(id, n, d, body) {
    const r = await api("GET", nodeAPI(id) + "settings");
    if (!r.ok) { body.append(B.callout("danger", "", r.error)); return; }
    const s = r.data.settings;
    const name = B.input({ value: s.name });
    const reg = B.segmented([["invite", "Invite only"], ["open", "Open"], ["closed", "Only mine"]], s.registration, (v) => { s.registration = v; }, "Who can join");
    const limit = B.stepper(s.device_limit, 1, 20, "devices", (v) => { s.device_limit = v; });
    const stealth = B.setting("Stealth mode", "Also listen on TCP 443 for networks that block VPNs.", s.stealth, { icon: "shield", onChange: (v) => { s.stealth = v; } });
    const upd = B.setting("Automatic security updates", "The node installs security fixes on its own.", s.auto_updates, { icon: "download", onChange: (v) => { s.auto_updates = v; } });
    const cats = h("div", { class: "stack stack-sm" });
    (r.data.categories || []).forEach((c) => {
      const on = (s.dns_default || []).includes(c);
      cats.append(B.setting(c.charAt(0).toUpperCase() + c.slice(1), "", on, { onChange: (v) => {
        s.dns_default = (s.dns_default || []).filter((x) => x !== c);
        if (v) s.dns_default.push(c);
      } }).row);
    });
    const err = B.errorSlot();
    const save = can(2) ? B.button("Save and apply", { icon: "check", onClick: async () => {
      clear(err);
      s.name = name.value.trim();
      const x = await api("PUT", nodeAPI(id) + "settings", s);
      if (!x.ok) { B.showError(err, x.error); return; }
      B.toast("Saved");
      if (x.data.applying) jobCard(body, id, "Applying changes");
    } }) : null;
    body.append(
      card("card-flush surface-panel", head("Server"), h("div", { class: "card-body stack" }, B.field("Name", name), B.settingRow("Who can join", "", reg), B.settingRow("Devices per account", "", limit.el), stealth.row, upd.row)),
      card("card-flush surface-panel", head("Blocked by default"), h("div", { class: "card-body" }, cats)),
      err, save ? h("div", { class: "cluster" }, save) : null
    );
  }

  function incidentList(list, withNode) {
    const wrap = h("div", { class: "list" });
    if (!list.length) wrap.append(h("p", { class: "list-item text-muted", text: "No incidents in the last 90 days." }));
    list.forEach((i) => {
      const open = !i.end;
      const dur = (i.end || Date.now() / 1000) - i.start;
      const tl = h("ol", { class: "timeline" });
      (i.notes || []).forEach((nt) => tl.append(h("li", null, h("time", { text: when(nt.time) }), nt.text)));
      wrap.append(h("div", { class: "list-item is-stacked" },
        h("div", { class: "grow stack stack-sm" },
          h("div", { class: "cluster" },
            h("span", { class: "dot " + (open ? "is-danger is-live" : "is-ok"), "aria-hidden": "true" }),
            h("span", { class: "list-item-title", text: (withNode ? i.node_name + ": " : "") + (EVENT_KIND[i.kind] || i.kind) + (i.subject ? ", " + i.subject : "") }),
            h("span", { class: "badge " + (open ? "badge-danger" : ""), text: open ? "Ongoing " + span(dur) : "Lasted " + span(dur) })
          ),
          h("p", { class: "list-item-meta", text: "Started " + when(i.start) + (i.end ? ", ended " + when(i.end) : "") }),
          tl
        )
      ));
    });
    return wrap;
  }

  async function incidents() {
    let openOnly = false;
    const p = pageShell(["Incidents", "and recoveries."], "Downtime and failed services from the last 90 days, with what auto-heal did about them.");
    const seg = B.segmented([["all", "All"], ["open", "Ongoing"]], "all", (v) => { openOnly = v === "open"; load(); }, "Filter");
    const holder = h("div");
    p.body.append(seg, holder);
    async function load() {
      clear(holder);
      const r = await api("GET", "api/incidents" + (openOnly ? "?open=1" : ""));
      if (!r.ok) { holder.append(B.callout("danger", "", r.error)); return; }
      holder.append(card("card-flush surface-panel", incidentList(r.data.incidents, true)));
    }
    load();
  }

  function reportView(rep, role) {
    const ok = rep.status === "ok" || rep.status === "propagating";
    const kind = { ok: "ok", propagating: "info", missing: "warn", wrong: "danger", proxied: role === "node" ? "danger" : "warn", error: "warn" }[rep.status] || "info";
    const parts = [B.callout(kind, rep.summary, "")];
    (rep.findings || []).forEach((f) => parts.push(B.callout(f.level === "error" ? "danger" : f.level === "warn" ? "warn" : "info", "", f.text)));
    if (rep.records && rep.records.length) {
      const tb = h("tbody");
      rep.records.forEach((x) => tb.append(h("tr", null,
        h("td", null, h("span", { class: "badge " + (x.action === "remove" ? "badge-danger" : "badge-violet"), text: x.action === "remove" ? "Remove" : "Add" })),
        h("td", null, h("code", { text: x.host })),
        h("td", { text: x.type }),
        h("td", null, h("code", { text: x.value })),
        h("td", { class: "is-num", text: String(x.ttl) }),
        h("td", null, B.copyButton(x.line, { class: "btn btn-ghost btn-sm", aria: "Copy record", toast: "Record copied" }))
      )));
      parts.push(h("div", { class: "table-wrap" }, h("table", { class: "table record-table" },
        h("thead", null, h("tr", null, ...["", "Name", "Type", "Value", "TTL", ""].map((x) => h("th", { scope: "col", text: x })))), tb)));
    }
    const grid = h("div", { class: "resolver-grid" });
    [...(rep.authoritative || []), ...(rep.public || [])].forEach((v) => {
      const dot = { ok: "is-ok", wrong: "is-danger", proxied: "is-danger", missing: "is-warn", error: "" }[v.status] || "";
      const ans = [...(v.a || []), ...(v.aaaa || [])].join(", ") || (v.error ? v.error : "no records");
      grid.append(h("div", { class: "resolver" },
        h("div", { class: "resolver-name" }, h("span", { class: "dot " + dot, "aria-hidden": "true" }), h("span", { text: v.label }), v.authoritative ? h("span", { class: "badge badge-violet", text: "Nameserver" }) : null),
        h("div", { class: "resolver-answer", text: ans }),
        v.ttl ? h("div", { class: "text-xs text-subtle", text: "TTL " + v.ttl + "s" }) : null));
    });
    parts.push(grid);
    if (rep.caa && rep.caa.records && rep.caa.records.length) parts.push(h("p", { class: "text-sm text-muted", text: "CAA on " + rep.caa.domain + ": " + rep.caa.records.join(", ") }));
    return { ok, el: h("div", { class: "stack" }, ...parts) };
  }

  async function domains() {
    const p = pageShell(["Domains", "and certificates."], "DNS checked against your nameservers and three public resolvers.");
    const l = loading(p.body);
    const r = await api("GET", "api/domains");
    if (!r.ok || page !== "domains") return;
    l.remove();
    const d = r.data;
    if (d.challenge && d.challenge.name) {
      p.body.append(B.callout("warn", "A certificate renewal is waiting for a DNS record", h("div", { class: "stack stack-sm" },
        h("p", { text: "Add this TXT record. Renewal continues by itself once every nameserver shows it." }),
        B.secret(d.challenge.record && d.challenge.record.line ? d.challenge.record.line : d.challenge.name + " TXT " + d.challenge.value, null, { small: true }))));
    }
    d.domains.forEach((dm) => {
      const days = daysLeft(dm.cert_expiry);
      const certText = dm.cert_expiry ? (days < 0 ? "Expired " : "Valid for " + days + " more days, until ") + dm.cert_expiry.slice(0, 10) : "No certificate seen yet";
      const right = h("div", { class: "cluster" }, h("span", { class: "badge " + (days === null ? "" : days < 14 ? "badge-warn" : "badge-ok"), text: days === null ? "Unknown" : days < 14 ? "Expires soon" : "Valid" }));
      const c = card("card-flush surface-panel", head(dm.host, right));
      const inner = h("div", { class: "card-body stack" },
        h("dl", { class: "kv" },
          h("div", { class: "kv-row" }, h("dt", { class: "kv-key", text: "Used by" }), h("dd", { class: "kv-value", text: dm.role === "panel" ? "Veyl Control" : dm.node_name })),
          h("div", { class: "kv-row" }, h("dt", { class: "kv-key", text: "Certificate" }), h("dd", { class: "kv-value", text: certText })),
          h("div", { class: "kv-row" }, h("dt", { class: "kv-key", text: "Issued by" }), h("dd", { class: "kv-value", text: dm.issuer })))
      );
      if (dm.report) inner.append(reportView(dm.report, dm.role).el);
      if (dm.role === "panel" && d.mode !== "caddy" && can(2)) {
        const list = B.progress();
        const holder = h("div", { class: "stack" });
        inner.append(h("div", { class: "cluster" }, B.button("Renew now", { variant: "secondary", size: "sm", icon: "refresh", onClick: async () => {
          if (!(await B.confirm("Renew the panel certificate now?", "certbot renews it on its own before it expires. Renewing by hand counts toward Let's Encrypt's weekly limit.", "Renew"))) return;
          const x = await api("POST", "api/domains/renew", {});
          if (!x.ok) { B.toast(x.error, "err"); return; }
          clear(holder).append(list.el);
          B.stream("api/jobs/renew", (ev) => list.step(ev), (res) => { list.settle(!!(res && res.ok)); B.toast(res && res.ok ? "Certificate renewed" : (res && res.error) || "Renewal failed", res && res.ok ? "" : "err"); });
        } })), holder);
      }
      c.append(inner);
      p.body.append(c);
    });
    if (!d.domains.length) p.body.append(emptyState("No domains yet."));
  }

  async function alerts() {
    const p = pageShell(["Alerts", "that reach you."], "Email, webhooks, Discord, Slack and ntfy. Repeats are held back so you are not flooded.");
    const l = loading(p.body);
    const r = await api("GET", "api/alerts");
    if (!r.ok || page !== "alerts") return;
    l.remove();
    const cfg = r.data;
    const ev = Object.assign({}, cfg.events);
    const evs = h("div", { class: "stack stack-sm" });
    cfg.kinds.forEach((k) => evs.append(B.setting(k.label, "", !!ev[k.kind], { onChange: (v) => { ev[k.kind] = v; } }).row));
    const sm = cfg.smtp;
    const smtpOn = B.setting("Email", "Sent over TLS or STARTTLS only. The password is encrypted on disk.", sm.enabled, { icon: "globe" });
    const host = B.input({ value: sm.host, placeholder: "smtp.example.com" });
    const port = B.input({ value: String(sm.port || 587), inputmode: "numeric" });
    const sec = B.select([["starttls", "STARTTLS"], ["tls", "TLS"]], sm.security || "starttls");
    const user = B.input({ value: sm.username, autocomplete: "off" });
    const pass = B.input({ type: "password", placeholder: sm.password_set ? "Saved. Type to replace." : "", autocomplete: "new-password" });
    const from = B.input({ value: sm.from, placeholder: "alerts@example.com" });
    const to = B.input({ value: (sm.to || []).join(", "), placeholder: "you@example.com" });
    const result = (id) => {
      const st = cfg.status && cfg.status[id];
      if (!st) return null;
      return h("p", { class: "text-sm " + (st.ok ? "text-ok" : "text-danger"), text: (st.ok ? "Last send worked, " : "Last send failed, ") + ago(st.time) + (st.error ? ": " + st.error : "") });
    };
    const test = (id) => B.button("Send a test", { variant: "secondary", size: "sm", icon: "zap", onClick: async () => {
      const x = await api("POST", "api/alerts/test", { channel: id });
      if (!x.ok) { B.toast(x.error, "err"); return; }
      B.toast(x.data.ok ? "Test sent" : "Test failed: " + x.data.error, x.data.ok ? "" : "err");
    } });
    const email = card("card-flush surface-panel", head("Email", test("smtp")), h("div", { class: "card-body stack" }, smtpOn.row,
      h("div", { class: "form-grid" }, B.field("Server", host), B.field("Port", port), B.field("Encryption", sec), B.field("Username", user), B.field("Password", pass), B.field("From", from), B.field("To", to, "Up to 10 addresses, separated by commas.")), result("smtp")));
    const hooks = (cfg.webhooks || []).map((w) => Object.assign({}, w));
    const hookList = h("div", { class: "stack" });
    const drawHooks = () => {
      clear(hookList);
      hooks.forEach((w, i) => {
        const on = B.toggle(w.enabled, "Webhook on");
        on.addEventListener("change", () => { w.enabled = on.on(); });
        const url = B.input({ value: w.url || "", placeholder: "https://hooks.example.com/veyl" });
        url.addEventListener("input", () => { w.url = url.value.trim(); });
        const name = B.input({ value: w.name || "", placeholder: "Ops channel" });
        name.addEventListener("input", () => { w.name = name.value; });
        const fmtSel = B.segmented([["json", "JSON"], ["discord", "Discord"], ["slack", "Slack"]], w.format || "json", (v) => { w.format = v; }, "Format");
        const secret = B.input({ type: "password", placeholder: w.secret_set ? "Saved. Type to replace." : "Optional", autocomplete: "new-password" });
        secret.addEventListener("input", () => { w.secret = secret.value; });
        hookList.append(h("div", { class: "hook-card stack" },
          h("div", { class: "cluster cluster-between" }, h("div", { class: "row" }, on, h("span", { class: "heading-sm", text: w.name || "Webhook " + (i + 1) })),
            h("div", { class: "cluster" }, w.id ? test("webhook:" + w.id) : null, B.button("", { variant: "quiet", size: "sm", icon: "trash", aria: "Remove webhook", async: false, onClick: () => { hooks.splice(i, 1); drawHooks(); } }))),
          h("div", { class: "form-grid" }, B.field("Name", name), B.field("Address", url)),
          B.settingRow("Format", "", fmtSel),
          B.field("Signing secret", secret, "Adds X-Veyl-Signature: sha256=HMAC(secret, timestamp.body) and X-Veyl-Timestamp."),
          w.id ? result("webhook:" + w.id) : null));
      });
    };
    drawHooks();
    const hookCard = card("card-flush surface-panel", head("Webhooks", B.button("Add webhook", { variant: "secondary", size: "sm", icon: "plus", async: false, onClick: () => { if (hooks.length < 8) { hooks.push({ enabled: true, format: "json" }); drawHooks(); } } })), h("div", { class: "card-body" }, hookList));
    const nt = cfg.ntfy;
    const ntOn = B.setting("ntfy", "Push notifications to your phone through an ntfy server.", nt.enabled, { icon: "phone" });
    const ntServer = B.input({ value: nt.server || "https://ntfy.sh" });
    const ntTopic = B.input({ value: nt.topic, placeholder: "veyl-a8f3k2", mono: true });
    const ntToken = B.input({ type: "password", placeholder: nt.token_set ? "Saved. Type to replace." : "Optional", autocomplete: "new-password" });
    const ntCard = card("card-flush surface-panel", head("ntfy", test("ntfy")), h("div", { class: "card-body stack" }, ntOn.row, h("div", { class: "form-grid" }, B.field("Server", ntServer), B.field("Topic", ntTopic, "Pick something hard to guess."), B.field("Access token", ntToken)), result("ntfy")));
    const err = B.errorSlot();
    const save = B.button("Save alerts", { icon: "check", onClick: async () => {
      clear(err);
      const body = {
        events: ev,
        smtp: { enabled: smtpOn.on(), host: host.value.trim(), port: Number(port.value) || 0, security: sec.value, username: user.value.trim(), password: pass.value, from: from.value.trim(), to: to.value.split(",").map((x) => x.trim()).filter(Boolean) },
        webhooks: hooks.map((w) => ({ id: w.id || "", enabled: !!w.enabled, name: w.name || "", url: w.url || "", format: w.format || "json", secret: w.secret || "" })),
        ntfy: { enabled: ntOn.on(), server: ntServer.value.trim(), topic: ntTopic.value.trim(), token: ntToken.value }
      };
      const x = await api("PUT", "api/alerts", body);
      if (!x.ok) { B.showError(err, x.error); return; }
      B.toast("Alerts saved");
      alerts();
    } });
    p.body.append(card("card-flush surface-panel", head("When to alert"), h("div", { class: "card-body" }, evs)), email, hookCard, ntCard, err, h("div", { class: "cluster" }, save),
      cfg.dropped ? h("p", { class: "text-sm text-subtle", text: cfg.dropped + " alerts were held back by the hourly limit." }) : null);
  }

  async function team() {
    const p = pageShell(["Team", "and roles."], "Owners manage everything. Admins manage nodes and alerts. Viewers can only look. Everyone uses two-step sign in.", B.button("Invite someone", { icon: "plus", async: false, onClick: invite }));
    const r = await api("GET", "api/team");
    if (!r.ok || page !== "team") return;
    const tb = h("tbody");
    r.data.users.forEach((u) => {
      const role = B.select([["owner", "Owner"], ["admin", "Admin"], ["viewer", "Viewer"]], u.role);
      role.setAttribute("aria-label", "Role of " + u.username);
      role.addEventListener("change", async () => {
        const x = await api("PATCH", "api/team/users/" + u.id, { role: role.value });
        B.toast(x.ok ? "Role changed" : x.error, x.ok ? "" : "err");
        if (!x.ok) role.value = u.role;
      });
      tb.append(h("tr", null,
        h("td", { class: "is-strong", text: u.username + (u.id === sess.user.id ? " (you)" : "") }),
        h("td", null, role),
        h("td", null, h("span", { class: "badge " + (u.two_factor ? "badge-ok" : "badge-warn"), text: u.two_factor ? "On" : "Pending" })),
        h("td", { class: "text-sm", text: u.last_login ? ago(u.last_login) : "Never" }),
        h("td", null, u.id === sess.user.id ? null : h("div", { class: "cluster cluster-tight" },
          B.button("", { variant: "quiet", size: "sm", icon: "key", aria: "Reset two-step sign in for " + u.username, onClick: async () => {
            if (!(await B.confirm("Reset two-step sign in?", u.username + " sets up a new authenticator at the next sign in.", "Reset"))) return;
            const x = await api("POST", "api/team/users/" + u.id + "/reset-2fa", {});
            B.toast(x.ok ? "Reset" : x.error, x.ok ? "" : "err");
          } }),
          B.button("", { variant: "quiet", size: "sm", icon: "trash", aria: "Remove " + u.username, onClick: async () => {
            if (!(await B.confirm("Remove " + u.username + "?", "They are signed out everywhere right away.", "Remove", true))) return;
            const x = await api("DELETE", "api/team/users/" + u.id);
            if (!x.ok) { B.toast(x.error, "err"); return; }
            team();
          } })))
      ));
    });
    p.body.append(card("card-flush surface-panel", h("div", { class: "table-wrap" }, h("table", { class: "table" }, h("thead", null, h("tr", null, ...["Person", "Role", "Two-step", "Last sign in", ""].map((x) => h("th", { scope: "col", text: x })))), tb))));
    if (r.data.invites.length) {
      const list = h("div", { class: "list" });
      r.data.invites.forEach((iv) => list.append(h("div", { class: "list-item" }, icon("ticket"), h("span", { class: "grow", text: (iv.note || "Invite") + ", " + iv.role }), h("span", { class: "text-sm text-subtle", text: "Until " + when(iv.expires) }),
        B.button("", { variant: "quiet", size: "sm", icon: "trash", aria: "Delete invite", onClick: async () => { await api("DELETE", "api/team/invites/" + iv.id); team(); } }))));
      p.body.append(card("card-flush surface-panel", head("Open invites"), list));
    }
  }

  function invite() {
    let role = "admin";
    const note = B.input({ placeholder: "Sam from support" });
    const seg = B.segmented([["viewer", "Viewer", "Looks only"], ["admin", "Admin", "Runs nodes"], ["owner", "Owner", "Everything"]], role, (v) => { role = v; }, "Role");
    const go = B.button("Create link", { onClick: async () => {
      const x = await api("POST", "api/team/invites", { role, note: note.value.trim() });
      if (!x.ok) { B.toast(x.error, "err"); return; }
      d.close();
      const base = location.href.split("#")[0].replace(/[^/]*$/, "");
      secretDialog("Invite link", base + x.data.path, "Send it privately. It works once and expires in 48 hours.");
      team();
    } });
    const d = B.dialog("Invite someone", [B.field("Note", note, "Only shown to owners."), seg], [B.button("Cancel", { variant: "secondary", async: false, onClick: () => d.close() }), go]);
  }

  async function audit() {
    const exp = B.button("Export CSV", { variant: "secondary", icon: "download", onClick: async () => {
      const x = await api("GET", "api/audit/export", undefined, { blob: true });
      if (!x.ok) { B.toast(x.error || "Export failed", "err"); return; }
      B.save(x.blob, x.filename);
    } });
    const p = pageShell(["Audit log", "of every change."], "Who changed what, kept for 90 days. It never holds account numbers or anything about VPN users.", exp);
    const r = await api("GET", "api/audit?limit=300");
    if (!r.ok || page !== "audit") return;
    if (!r.data.entries.length) { p.body.append(emptyState("Nothing has changed yet.")); return; }
    const tb = h("tbody");
    r.data.entries.forEach((e) => tb.append(h("tr", null, h("td", { text: when(e.time) }), h("td", { class: "is-strong", text: e.user }), h("td", { class: "text-mono text-sm", text: e.action }), h("td", { class: "text-sm", text: e.target || "" }), h("td", { class: "text-sm text-muted", text: e.detail || "" }))));
    p.body.append(card("card-flush surface-panel", h("div", { class: "table-wrap" }, h("table", { class: "table audit-table" }, h("thead", null, h("tr", null, ...["Time", "Who", "Action", "Target", "Details"].map((x) => h("th", { scope: "col", text: x })))), tb))));
  }

  async function system() {
    const p = pageShell(["Veyl Control", "itself."], "The panel's own health, updates and backups.");
    const r = await api("GET", "api/system");
    if (!r.ok || page !== "system") return;
    const s = r.data;
    if (footerVersion) footerVersion.textContent = "Veyl Control " + s.version;
    const kv = h("dl", { class: "kv kv-mono" });
    const row = (k, v) => { if (v) kv.append(h("div", { class: "kv-row" }, h("dt", { class: "kv-key", text: k }), h("dd", { class: "kv-value", text: String(v) }))); };
    row("version", s.version);
    row("latest", s.release || "not checked");
    row("domain", s.domain);
    row("certificates", s.mode === "dns" ? "certbot with DNS TXT records" : s.mode === "caddy" ? "Caddy" : "certbot with the web check");
    row("platform", s.platform);
    row("running for", span(s.uptime));
    Object.keys(s.agent || {}).filter((k) => k.startsWith("svc.")).sort().forEach((k) => row(k.slice(4), s.agent[k]));
    row("certbot", s.agent && s.agent.certbot);
    const health = card("card-flush surface-panel", head("Health"), kv);
    const upd = card("card-flush surface-panel", head("Updates"), h("div", { class: "card-body stack" },
      h("p", { class: "text-muted", text: s.update ? "Version " + s.release + " is available." : "You run the latest version we know about." }),
      can(3) ? h("div", { class: "cluster" }, B.button("Update Veyl Control", { variant: s.update ? "primary" : "secondary", icon: "download", onClick: async () => {
        if (!(await B.confirm("Update Veyl Control?", "The panel restarts when the update finishes. Your nodes keep running.", "Update"))) return;
        const x = await api("POST", "api/system/update", {});
        B.toast(x.ok ? "Update started" : x.error, x.ok ? "" : "err");
      } })) : null));
    p.body.append(health, upd);
    if (can(3)) {
      const name = B.input({ value: s.settings.name });
      const heal = B.setting("Auto-heal", "Restart failed services on nodes that allow it.", s.settings.auto_heal, { icon: "wand" });
      const chk = B.setting("Check for updates", "Ask GitHub for the latest release every 6 hours.", s.settings.check_updates, { icon: "refresh" });
      const save = B.button("Save", { icon: "check", onClick: async () => {
        const x = await api("PUT", "api/system/settings", { name: name.value.trim(), auto_heal: heal.on(), check_updates: chk.on() });
        B.toast(x.ok ? "Saved" : x.error, x.ok ? "" : "err");
      } });
      const pass = B.passwordField({ label: "Backup passphrase", min: 10, hint: "At least 10 characters. You need it to restore.", generate: true });
      const bk = B.button("Download encrypted backup", { variant: "secondary", icon: "archive", onClick: async () => {
        if (!pass.valid()) { B.toast("Use at least 10 characters.", "err"); return; }
        const x = await api("POST", "api/system/backup", { passphrase: pass.input.value }, { blob: true });
        if (!x.ok) { B.toast(x.error || "Backup failed", "err"); return; }
        B.save(x.blob, x.filename);
      } });
      p.body.append(
        card("card-flush surface-panel", head("Settings"), h("div", { class: "card-body stack" }, B.field("Panel name", name), heal.row, chk.row, h("div", { class: "cluster" }, save))),
        card("card-flush surface-panel", head("Backup"), h("div", { class: "card-body stack" }, h("p", { class: "text-muted", text: "Holds the team, node keys, alert settings, history and the encryption key, all sealed with your passphrase." }), pass.field, h("div", { class: "cluster" }, bk), B.codeBlock("sudo veyl panel restore veyl-control.vbk", "Restore on a server")))
      );
    }
  }

  async function account() {
    const p = pageShell([sess.user.username, "and your sign in."], "Your password, recovery codes and where you are signed in.");
    const me = await api("GET", "api/me");
    const cur = B.input({ type: "password", autocomplete: "current-password" });
    const next = B.passwordField({ label: "New password", min: 12, hint: "At least 12 characters." });
    const code = B.input({ inputmode: "numeric", autocomplete: "one-time-code", mono: true, placeholder: "123 456" });
    const err = B.errorSlot();
    const save = B.button("Change password", { icon: "key", onClick: async () => {
      const x = await api("POST", "api/me/password", { password: cur.value, new_password: next.input.value, code: code.value.replace(/\s/g, "") });
      if (!x.ok) { B.showError(err, x.error); return; }
      B.toast("Password changed. Other sessions were signed out.");
      account();
    } });
    const pw = card("card-flush surface-panel", head("Password"), h("div", { class: "card-body stack" }, B.field("Current password", cur), next.field, B.field("Code from your authenticator app", code), err, h("div", { class: "cluster" }, save)));
    const rcur = B.input({ type: "password", autocomplete: "current-password" });
    const rcode = B.input({ inputmode: "numeric", mono: true, placeholder: "123 456" });
    const rerr = B.errorSlot();
    const rec = card("card-flush surface-panel", head("Recovery codes", h("span", { class: "badge " + (me.ok && me.data.recovery_left < 3 ? "badge-warn" : ""), text: (me.ok ? me.data.recovery_left : 0) + " left" })),
      h("div", { class: "card-body stack" },
        h("p", { class: "text-muted", text: "New codes replace all the old ones." }),
        h("div", { class: "form-grid" }, B.field("Password", rcur), B.field("Code", rcode)), rerr,
        h("div", { class: "cluster" }, B.button("Make new codes", { variant: "secondary", icon: "refresh", onClick: async () => {
          const x = await api("POST", "api/me/recovery", { password: rcur.value, code: rcode.value.replace(/\s/g, "") });
          if (!x.ok) { B.showError(rerr, x.error); return; }
          B.dialog("New recovery codes", [codesView(x.data.recovery)], [B.button("Done", { async: false, onClick: (b) => b.closest("dialog").close() })]);
        } }))));
    const s = await api("GET", "api/me/sessions");
    const list = h("div", { class: "list" });
    if (s.ok) s.data.sessions.forEach((x) => list.append(h("div", { class: "list-item" }, icon("laptop"), h("span", { class: "grow", text: x.agent + (x.current ? " (this one)" : "") }), h("span", { class: "text-sm text-subtle", text: "Active " + ago(x.last) }),
      x.current ? null : B.button("Sign out", { variant: "quiet", size: "sm", onClick: async () => { await api("DELETE", "api/me/sessions/" + x.id); account(); } }))));
    const sessions = card("card-flush surface-panel", head("Where you are signed in", B.button("Sign out everywhere else", { variant: "secondary", size: "sm", onClick: async () => { await api("DELETE", "api/me/sessions/others"); account(); } })), list);
    p.body.append(pw, rec, sessions);
  }

  boot();
})();
