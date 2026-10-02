"use strict";

(() => {
  const B = Brand;
  const { h, icon, clear, api } = B;
  const app = document.getElementById("app");
  const nav = document.getElementById("nav");
  const navMeta = document.getElementById("nav-meta");
  B.watchNav(nav);

  const FLOW = ["welcome", "address", "secure", "admin", "vpn", "privacy", "accounts", "review", "done"];
  const RESTORE_FLOW = ["welcome", "address", "secure", "restore", "review", "done"];
  const NAMES = {
    welcome: "Welcome",
    address: "Address",
    secure: "Secure link",
    admin: "Admin password",
    vpn: "Your VPN",
    privacy: "Privacy and blocking",
    accounts: "Who can join",
    restore: "Restore",
    review: "Install",
    done: "Done"
  };

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
    closed: ["Only accounts I create", "You make every account yourself in the admin panel.", "user"]
  };

  let token = "";
  let st = null;
  let mode = "normal";
  let current = "welcome";
  const draft = { addressMode: "", host: "", email: "" };

  function flow() { return mode === "restore" ? RESTORE_FLOW : FLOW; }

  function platform() { return B.state.platform; }

  function windows() { return platform() === "windows"; }

  function root(cmd) { return windows() ? cmd : "sudo " + cmd; }

  function shellLabel() { return windows() ? "In an admin PowerShell" : "On your server"; }

  function command(cmd) { return B.codeBlock(root(cmd), shellLabel(), { promptText: windows() ? "PS> " : "$ " }); }

  function syncPlatform() {
    if (!st) return;
    const p = B.platformOf(st, st.facts, st.settings);
    B.state.platform = p;
    B.state.stealthPort = B.stealthPortOf(p, st, st.facts, st.settings);
  }

  function readToken() {
    const hash = location.hash.replace(/^#/, "");
    if (hash) {
      token = decodeURIComponent(hash);
      history.replaceState(null, "", location.pathname + location.search);
      try { sessionStorage.setItem("veyl.setup", token); } catch (e) { }
    } else {
      try { token = sessionStorage.getItem("veyl.setup") || ""; } catch (e) { token = ""; }
    }
  }

  async function refresh() {
    const r = await api("GET", "/v1/setup/state");
    if (!r.ok) return r;
    st = r.data;
    B.state.csrf = st.csrf || B.state.csrf;
    if (st.restore) mode = "restore";
    syncPlatform();
    return r;
  }

  function setMeta(text) {
    if (navMeta) navMeta.textContent = text || "";
  }

  function title(parts) {
    const el = h("h1", { class: "text-title", tabindex: "-1" });
    if (Array.isArray(parts)) {
      el.append(parts[0]);
      if (parts[1]) el.append(" ", h("span", { class: parts[2] || "text-dim", text: parts[1] }));
    } else {
      el.textContent = parts;
    }
    return el;
  }

  function rail() {
    const f = flow().filter((s) => s !== "done");
    const idx = f.indexOf(current);
    const r = h("div", { class: "rail flow-rail", role: "progressbar", "aria-label": "Setup progress", "aria-valuemin": "1", "aria-valuemax": String(f.length), "aria-valuenow": String(Math.max(1, idx + 1)), "aria-valuetext": NAMES[current] });
    f.forEach((_, i) => r.append(h("i", { class: i < idx ? "is-done" : i === idx ? "is-current" : "" })));
    return r;
  }

  function steps() {
    const f = flow().filter((s) => s !== "done");
    const idx = f.indexOf(current);
    const list = h("ol", { class: "steps", "aria-label": "Setup steps" });
    f.forEach((s, i) => {
      const done = i < idx;
      list.append(h("li", { class: "steps-item" + (done ? " is-done" : ""), "aria-current": i === idx ? "step" : null },
        h("span", { class: "steps-marker", "aria-hidden": "true" }, done ? icon("check") : String(i + 1)),
        h("span", { text: NAMES[s] }),
        done ? h("span", { class: "sr-only", text: "(done)" }) : null
      ));
    });
    return list;
  }

  function screen(o) {
    const head = h("header", { class: "page-header" },
      h("div", { class: "page-header-text" }, title(o.title), o.lead ? h("p", { class: "text-lede", text: o.lead }) : null)
    );
    const body = h("div", { class: "page-body" }, ...(o.body || []));
    const acts = (o.actions || []).filter(Boolean);
    const main = h("div", { class: "flow-main rise" }, rail(), head, body, acts.length ? h("div", { class: "flow-actions" }, ...acts) : null);
    const wrap = h("div", { class: "flow" }, h("aside", { class: "flow-aside", "aria-label": "Progress" }, steps()), main);
    clear(app).append(wrap);
    setMeta((st && st.settings && st.settings.host) || "");
    window.scrollTo(0, 0);
    const h1 = main.querySelector("h1");
    if (h1 && o.focus !== false) h1.focus({ preventScroll: true });
    return { main, head, body, h1 };
  }

  function backBtn() {
    const f = flow();
    const i = f.indexOf(current);
    let prev = f[i - 1];
    if (prev === "secure") prev = f[i - 2];
    if ((prev === "address" || prev === "welcome") && st && st.secure && st.on_host && current !== "secure") return null;
    if (!prev) return null;
    return B.button("Back", { variant: "secondary", size: "lg", icon: "arrowLeft", class: "btn-back", aria: "Back", async: false, onClick: () => go(prev) });
  }

  function nextBtn(label, fn, ic) {
    const b = B.button(label || "Continue", { size: "lg", trailing: ic || "arrowRight", onClick: fn });
    return b;
  }

  function go(name) {
    current = name;
    STEPS[name]();
  }

  function card(...kids) {
    return h("div", { class: "card surface-card" }, ...kids);
  }

  function quiet(...kids) {
    return h("div", { class: "card surface-quiet" }, ...kids);
  }

  function section(heading, text, ...kids) {
    return h("section", { class: "section" },
      h("div", null, h("h2", { class: "section-title", text: heading }), text ? h("p", { class: "section-text mt-1", text }) : null),
      ...kids
    );
  }

  function wordmark() {
    return h("div", { class: "wordmark-band", "aria-hidden": "true" },
      h("div", { class: "grid-lines mask-fade-y" }),
      h("img", { class: "brand-wordmark", src: "/setup/wordmark.svg", alt: "", width: "1100", height: "262" })
    );
  }

  const STEPS = {};

  STEPS.link = (msg) => {
    current = "welcome";
    clear(app).append(h("div", { class: "auth-box rise" },
      h("div", { class: "auth-head" },
        h("h1", { class: "text-title", tabindex: "-1" }, "Open your ", h("span", { class: "text-gradient", text: "setup link." })),
        h("p", { class: "text-lede", text: msg || "For your safety, setup only opens from the private link the installer printed." })
      ),
      quiet(
        h("h2", { class: "card-title", text: "Lost the link?" }),
        h("p", { class: "card-text", text: "Run this on your server to print a fresh one." }),
        h("div", { class: "mt-6" }, command("veyl setup-link"))
      )
    ));
    app.querySelector("h1").focus({ preventScroll: true });
    setMeta("");
  };

  function ramText(mb) {
    if (!mb) return "";
    const n = Number(mb);
    return n >= 1024 ? (n / 1024).toFixed(1).replace(/\.0$/, "") + " GB" : n + " MB";
  }

  STEPS.welcome = () => {
    const f = (st && st.facts) || {};
    const rows = [
      ["Public IP", f.public_ip, true],
      ["System", f.os, false],
      ["Platform", windows() ? "Windows" : "Linux", false],
      ["Memory", ramText(f.ram_mb), false],
      ["OpenVPN", f.openvpn, false],
      ["OpenSSL", f.openssl, false],
      ["Post-quantum", f.pq_available ? "Available" : (f.openssl ? "Needs OpenSSL 3.5" : ""), false]
    ];
    const kv = h("dl", { class: "kv kv-mono" });
    rows.forEach(([k, v, accent]) => kv.append(h("div", { class: "kv-row" }, h("dt", { class: "kv-key" + (accent ? " is-accent" : ""), text: k.toLowerCase().replace(/ /g, "-") }), h("dd", { class: "kv-value", text: v || "-" }))));
    const start = nextBtn("Start setup", async () => { mode = "normal"; go("address"); });
    const restore = B.button("Restore from a backup", { variant: "secondary", size: "lg", icon: "upload", async: false, onClick: () => { mode = "restore"; go("address"); } });
    const features = [
      ["clock", "About five minutes", "Pick an address, set a password, press install. Every step is checked."],
      ["shield", "Safe defaults", "Everything good is already on. You can change any of it later."],
      ["lock", "Locks itself", "When you finish, this page closes for good. The admin panel takes over."]
    ];
    clear(app).append(
      h("div", { class: "stack stack-xl" },
        h("header", { class: "stack rise" },
          h("h1", { class: "text-headline", tabindex: "-1" }, h("span", { text: "Your server is here." }), h("br"), h("span", { class: "text-gradient", text: "Let's make it yours." })),
          h("p", { class: "text-lede measure", text: "Answer a few questions and Veyl sets up a private VPN on this machine. No account with us, no subscription, no traffic logs." }),
          h("div", { class: "cluster mt-4" }, start, restore)
        ),
        h("div", { class: "grid-2 rise delay-2" },
          h("section", { class: "card card-flush surface-panel", "aria-labelledby": "facts-title" },
            h("div", { class: "card-head" }, h("h2", { id: "facts-title", text: "What we found on this server" }), h("span", { class: "dot is-ok is-live", "aria-hidden": "true" })),
            kv,
            h("p", { class: "card-foot", text: "Read from the system agent on this machine. Nothing here leaves your server." })
          ),
          h("div", { class: "stack" }, ...features.map(([ic, t, d]) => h("div", { class: "card card-sm surface-quiet row" }, h("span", { class: "icon-tile" }, icon(ic)), h("div", { class: "grow" }, h("h2", { class: "feature-title", text: t }), h("p", { class: "feature-text", text: d })))))
        ),
        wordmark()
      )
    );
    app.querySelector("h1").focus({ preventScroll: true });
    setMeta(f.public_ip || "");
  };

  function dnsRecord(host, ip) {
    const parts = host.split(".");
    const name = parts.length > 2 ? parts.slice(0, parts.length - 2).join(".") : "@";
    return h("section", { class: "card card-flush surface-panel" },
      h("div", { class: "card-head" }, h("h3", { text: "Add this record at your domain provider" })),
      h("dl", { class: "kv kv-mono" },
        h("div", { class: "kv-row" }, h("dt", { class: "kv-key", text: "type" }), h("dd", { class: "kv-value", text: "A" })),
        h("div", { class: "kv-row" }, h("dt", { class: "kv-key", text: "name" }), h("dd", { class: "kv-value", text: name })),
        h("div", { class: "kv-row" }, h("dt", { class: "kv-key is-accent", text: "value" }), h("dd", { class: "kv-value", text: ip || "this server's IP" }), ip ? h("div", { class: "kv-action" }, B.copyButton(ip, { aria: "Copy IP address" })) : null)
      )
    );
  }

  STEPS.address = () => {
    const f = (st && st.facts) || {};
    const ip = f.public_ip || "";
    const free = ip ? ip.replace(/\./g, "-") + ".sslip.io" : "";
    if (!draft.addressMode) draft.addressMode = free ? "free" : "domain";
    if (!draft.host && st && st.settings.host && !/\.sslip\.io$/.test(st.settings.host) && !/^[0-9.:]+$/.test(st.settings.host)) {
      draft.host = st.settings.host;
      draft.addressMode = "domain";
    }
    const err = B.errorSlot();
    const detail = h("div", { class: "stack" });
    const status = h("div", { class: "stack", "aria-live": "polite" });
    let lastCheck = null;
    let timer = 0;

    const freeBtn = B.option({ icon: "sparkPixel", title: "Use a free address", badge: free ? "Easiest" : null, desc: free ? "We use " + free + ", a free name from sslip.io that points to this server. Nothing to set up." : "Not available, because we couldn't find this server's public IPv4 address.", on: draft.addressMode === "free", disabled: !free });
    const domBtn = B.option({ icon: "globe", title: "Use my own domain", desc: "Like vpn.example.com. You point it at this server.", on: draft.addressMode === "domain" });
    const ipBtn = B.option({ icon: "server", title: "Use the IP address only", desc: "Browsers will warn, because the certificate is self-signed.", on: draft.addressMode === "ip" });
    const group = h("div", { class: "options" }, freeBtn, domBtn);
    const more = h("details", { class: "disclosure", open: draft.addressMode === "ip" },
      h("summary", null, h("span", { text: "More options" }), h("span", { class: "disclosure-icon", "aria-hidden": "true" }, icon("plus"))),
      h("div", { class: "disclosure-body" }, ipBtn)
    );

    const hostInput = B.input({ id: "host", inputmode: "url", autocomplete: "off", autocapitalize: "off", spellcheck: "false", placeholder: "vpn.example.com", value: draft.host, maxlength: "253", mono: true });
    const emailInput = B.input({ id: "email", type: "email", autocomplete: "email", placeholder: "you@example.com", value: draft.email, maxlength: "254" });
    const emailBox = h("details", { class: "disclosure", open: !!draft.email },
      h("summary", null, h("span", { text: "Email for certificate notices" }), h("span", { class: "disclosure-icon", "aria-hidden": "true" }, icon("plus"))),
      h("div", { class: "disclosure-body" }, B.field("Email (optional)", emailInput, "Only Let's Encrypt uses it, to warn you about expiring certificates."))
    );

    const TITLES = { ok: "Points to this server", missing: "Not found yet", wrong: "Points somewhere else", mixed: "Extra addresses found", proxied: "Behind Cloudflare's proxy", error: "Couldn't check" };

    async function check() {
      const host = hostInput.value.trim().toLowerCase().replace(/\.$/, "");
      draft.host = host;
      if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(host)) {
        lastCheck = null;
        clear(status);
        if (host.length > 3) status.append(B.callout("neutral", "", "Enter the full name, like vpn.example.com."));
        nextLabel();
        return;
      }
      clear(status).append(h("div", { class: "callout callout-neutral" }, B.spinner(), h("p", { class: "grow", text: "Checking " + host })));
      const r = await api("GET", "/v1/setup/dns-check?host=" + encodeURIComponent(host));
      if (hostInput.value.trim().toLowerCase().replace(/\.$/, "") !== host) return;
      if (!r.ok) { lastCheck = null; clear(status).append(B.callout("danger", "", r.error)); return; }
      lastCheck = r.data;
      const c = r.data;
      const kind = c.status === "ok" ? "ok" : c.status === "error" ? "neutral" : "warn";
      clear(status).append(B.callout(kind, TITLES[c.status] || "", c.message + (c.note ? " " + c.note : "")));
      if (c.status !== "ok") {
        status.append(dnsRecord(host, ip), h("div", null, B.button("Check again", { variant: "secondary", icon: "refresh", onClick: check })));
      }
      nextLabel();
    }

    hostInput.addEventListener("input", () => {
      clearTimeout(timer);
      lastCheck = null;
      nextLabel();
      timer = setTimeout(check, 700);
    });

    function renderDetail() {
      clear(detail);
      if (draft.addressMode === "domain") {
        detail.append(card(h("div", { class: "stack" }, B.field("Your domain", hostInput, "Its A record must point to " + (ip || "this server") + "."), status, emailBox)));
        if (draft.host && !lastCheck) check();
      } else if (draft.addressMode === "ip") {
        detail.append(B.callout("warn", "Not recommended", "Browsers and some apps show a security warning, because a trusted certificate needs a name. Use this only if the other options don't work."));
      } else if (draft.addressMode === "free") {
        detail.append(B.callout("info", "", "sslip.io is a free public service that turns an IP address into a name. If you get a domain later, switch to it in the admin panel."));
      }
      nextLabel();
    }

    B.radioGroup(group, [freeBtn, domBtn, ipBtn], (b) => {
      draft.addressMode = b === freeBtn ? "free" : b === domBtn ? "domain" : "ip";
      renderDetail();
      if (draft.addressMode === "domain") setTimeout(() => hostInput.focus(), 50);
    }, "Address");

    const next = nextBtn("Continue", async () => {
      const body = { mode: draft.addressMode, restore: mode === "restore" };
      if (draft.addressMode === "domain") {
        body.host = hostInput.value.trim().toLowerCase().replace(/\.$/, "");
        body.email = emailInput.value.trim();
        draft.email = body.email;
        if (!body.host) { hostInput.classList.add("is-invalid"); hostInput.focus(); B.showError(err, "Enter your domain first."); return; }
      }
      const r = await api("POST", "/v1/setup/address", body);
      if (!r.ok) { B.showError(err, r.error); return; }
      st.settings.host = r.data.host;
      st.settings.tls = r.data.tls;
      go("secure");
    });

    function nextLabel() {
      const span = next.querySelector("span");
      if (!span || next.disabled) return;
      span.textContent = draft.addressMode === "domain" && lastCheck && lastCheck.status !== "ok" ? "Continue anyway" : "Continue";
    }

    screen({
      title: ["How will apps find", "your server?"],
      lead: "Pick an address. It gets a free certificate too, so everything after this step is encrypted.",
      body: [group, detail, more, err],
      actions: [backBtn(), next]
    });
    renderDetail();
  };

  STEPS.secure = (resume) => {
    const list = B.progress();
    const bar = B.progressBar();
    const out = h("div", { class: "stack", "aria-live": "polite" });
    const host = (st && st.settings.host) || "";
    const actions = h("div", { class: "cluster" });
    const ports = windows() ? "ports 80 and 443 are blocked by your hosting firewall or Windows Defender Firewall" : "ports 80 and 443 are blocked by your hosting firewall";
    screen({
      title: ["Securing", "your connection."],
      lead: "Getting a certificate for " + host + ". This usually takes under a minute.",
      body: [card(h("div", { class: "stack" }, bar.el, list.el)), out, actions]
    });

    function failed(msg) {
      bar.fail();
      list.settle(false);
      clear(out).append(B.callout("danger", "We couldn't get a certificate", msg || "The certificate service didn't respond."), h("p", { class: "field-hint", text: "Common causes: the domain doesn't point here yet, or " + ports + "." }));
      const retry = B.button("Try again", { size: "lg", icon: "refresh", async: false, onClick: () => STEPS.secure() });
      const self = B.button("Use a self-signed certificate", { variant: "secondary", size: "lg", onClick: async () => {
        const body = { mode: draft.addressMode || "domain", self_signed: true, restore: mode === "restore" };
        if (body.mode === "domain") body.host = host;
        const r = await api("POST", "/v1/setup/address", body);
        if (!r.ok) { B.toast(r.error, "err"); return; }
        STEPS.secure();
      } });
      const change = B.button("Change address", { variant: "ghost", size: "lg", icon: "arrowLeft", async: false, onClick: () => go("address") });
      clear(actions).append(retry, self, change);
    }

    function succeeded(res) {
      bar.done();
      list.settle(true);
      const url = res && res.result && res.result.redirect;
      if (!url) { failed("No secure address was returned."); return; }
      if (!token) {
        clear(out).append(B.callout("warn", "Secured", "Open " + url + " with your setup link to continue. Run \"" + root("veyl setup-link") + "\" on the server to get it."));
        return;
      }
      clear(out).append(B.callout("ok", "Secured", "Taking you to the secure page."));
      setTimeout(() => location.replace(url + "#" + encodeURIComponent(token)), 900);
    }

    async function run() {
      if (!resume) {
        const r = await api("POST", "/v1/setup/secure", {});
        if (!r.ok && r.status !== 409) { failed(r.error); return; }
      }
      B.stream("/v1/setup/progress", (ev) => list.step(ev), (d) => {
        if (d && d.ok) succeeded(d);
        else failed(d ? d.error : "Lost contact with the server.");
      });
    }
    run();
  };

  STEPS.admin = () => {
    const err = B.errorSlot();
    const pw = B.passwordField({ id: "admin-pw", label: "Admin password", min: 12, hint: "At least 12 characters." });
    const already = st && st.admin_set;
    screen({
      title: ["Create your", "admin password."],
      lead: "You use it to sign in to the admin panel. Only you need it.",
      body: [
        card(pw.field),
        already ? B.callout("ok", "Password saved", "Enter a new one to change it, or just continue.") : null,
        B.callout("info", "", "Keep it in a password manager. Forgot it later? Run \"" + root("veyl admin reset-password") + "\" on the server.", "key"),
        err
      ],
      actions: [backBtn(), nextBtn("Continue", async () => {
        if (!pw.input.value && already) { go("vpn"); return; }
        if (!pw.valid()) { pw.input.classList.add("is-invalid"); pw.input.focus(); B.showError(err, "Use at least 12 characters."); return; }
        const r = await api("POST", "/v1/setup/admin", { password: pw.input.value });
        if (!r.ok) { B.showError(err, r.error); return; }
        st.admin_set = true;
        go("vpn");
      })]
    });
  };

  function stealthText() {
    if (windows()) return "Adds a TCP fallback on port " + B.state.stealthPort + " for networks that block VPNs, like some offices, schools and hotels.";
    return "Runs a second VPN on port 443, so it looks like normal web traffic. Works on networks that block VPNs, like some offices, schools and hotels.";
  }

  STEPS.vpn = () => {
    const s = st.settings;
    const f = st.facts || {};
    const err = B.errorSlot();
    const name = B.input({ id: "name", maxlength: "40", value: s.name || "Veyl", autocomplete: "off" });
    const stealth = B.setting("Stealth mode", stealthText(), s.stealth, { icon: "eyeOff" });
    const v6 = B.setting("IPv6", f.has_ipv6 ? "Give devices IPv6 too, so every site works." : "This server has no public IPv6 address, so this stays off.", f.has_ipv6 ? s.ipv6 : false, { disabled: !f.has_ipv6, icon: "globe" });
    const pq = B.setting("Post-quantum protection", f.pq_available ? "Protects today's traffic against future quantum computers." : "Needs OpenSSL 3.5 or newer on the server" + (f.openssl ? " (this one has " + f.openssl + ")" : "") + ".", f.pq_available ? s.post_quantum : false, { disabled: !f.pq_available, icon: "key" });
    const limit = B.stepper(s.device_limit || 5, 1, 20, "devices");
    screen({
      title: ["Your VPN.", "Good defaults are on."],
      lead: "Change what you like. Everything here can be changed later in the admin panel.",
      body: [
        card(B.field("Server name", name, "Shown in the admin panel and to apps that ask the server for its details.")),
        card(h("div", { class: "setting-list" }, stealth.row, v6.row, pq.row, B.settingRow("Devices per account", "How many phones and computers each person can connect.", limit.el))),
        err
      ],
      actions: [backBtn(), nextBtn("Continue", async () => {
        const body = { name: name.value.trim(), stealth: stealth.on(), ipv6: v6.on(), post_quantum: pq.on(), device_limit: limit.value() };
        const r = await api("PUT", "/v1/setup/settings", body);
        if (!r.ok) { B.showError(err, r.error); return; }
        st.settings = r.data.settings;
        go("privacy");
      })]
    });
  };

  STEPS.privacy = () => {
    const s = st.settings;
    const err = B.errorSlot();
    const on = new Set(s.dns_default || []);
    const rows = {};
    const cats = h("div", { class: "setting-list" });
    (st.categories || Object.keys(CATS)).forEach((c) => {
      const m = CATS[c] || [c, "", "ban"];
      rows[c] = B.setting(m[0], m[1], on.has(c), { icon: m[2] });
      cats.append(rows[c].row);
    });
    let upstream = s.dns_upstream || "recursive";
    const seg = B.segmented(UPSTREAMS, upstream, (v) => { upstream = v; }, "Name lookups");
    const updates = B.setting("Automatic security updates", windows() ? "Keeps Veyl's own components patched. Windows Update stays in charge of the system." : "Installs security fixes for the system by itself.", s.auto_updates, { icon: "refresh" });
    const vpnOnly = B.setting("Admin panel only through the VPN", "Hides the admin panel from the internet. You need to be connected to open it.", s.admin_vpn_only, { icon: "lock" });
    screen({
      title: ["Privacy", "and blocking."],
      lead: "Veyl never logs what anyone does. Pick what to block for everyone. You can change it for any account later.",
      body: [
        section("Block for everyone", "Blocked names never resolve, on every device that uses this VPN.", card(cats)),
        section("Name lookups", "Where your server asks when a site isn't blocked.", seg),
        section("Server", null, card(h("div", { class: "setting-list" }, updates.row, vpnOnly.row))),
        err
      ],
      actions: [backBtn(), nextBtn("Continue", async () => {
        const dns = Object.keys(rows).filter((c) => rows[c].on());
        const r = await api("PUT", "/v1/setup/settings", { dns_default: dns, dns_upstream: upstream, auto_updates: updates.on(), admin_vpn_only: vpnOnly.on() });
        if (!r.ok) { B.showError(err, r.error); return; }
        st.settings = r.data.settings;
        go("accounts");
      })]
    });
  };

  STEPS.accounts = () => {
    const s = st.settings;
    const err = B.errorSlot();
    let reg = s.registration || "invite";
    const btns = ["invite", "open", "closed"].map((k) => B.option({ icon: REG[k][2], title: REG[k][0], desc: REG[k][1], badge: k === "invite" ? "Recommended" : null, on: reg === k, value: k }));
    const group = h("div", { class: "options" }, ...btns);
    B.radioGroup(group, btns, (b) => { reg = b.getAttribute("data-value"); }, "Who can join");
    const pw = B.passwordField({ id: "acct-pw", label: "Password for your account", min: 10, hint: "At least 10 characters. You get an account number at the end." });
    const made = st.account_created;
    const skip = h("button", { class: "link", type: "button", onclick: () => B.busy(skip, () => submit(true)) }, made ? "Remove my account" : "Skip, I'll do this later");
    const own = card(h("div", { class: "stack" },
      h("div", null, h("h2", { class: "card-title", text: "Your own account" }), h("p", { class: "card-text", text: made ? "Your account is ready. Type a new password to replace it, or just continue." : "Create an account for yourself now, so you can connect right away." })),
      pw.field,
      h("div", null, skip)
    ));
    async function submit(skipping) {
      const r = await api("PUT", "/v1/setup/settings", { registration: reg });
      if (!r.ok) { B.showError(err, r.error); return; }
      st.settings = r.data.settings;
      if (skipping) {
        const a = await api("POST", "/v1/setup/account", { skip: true });
        if (!a.ok) { B.showError(err, a.error); return; }
        st.account_created = false;
      } else if (pw.input.value) {
        if (!pw.valid()) { pw.input.classList.add("is-invalid"); pw.input.focus(); B.showError(err, "Use at least 10 characters."); return; }
        const a = await api("POST", "/v1/setup/account", { password: pw.input.value });
        if (!a.ok) { B.showError(err, a.error); return; }
        st.account_created = true;
      } else if (!made) {
        pw.input.classList.add("is-invalid");
        pw.input.focus();
        B.showError(err, "Add a password, or choose \"Skip\".");
        return;
      }
      go("review");
    }
    screen({
      title: ["Who can join?"],
      lead: "People sign in to the app with an account number and a password. No email, no recovery questions.",
      body: [group, own, err],
      actions: [backBtn(), nextBtn("Continue", () => submit(false))]
    });
  };

  STEPS.restore = () => {
    const err = B.errorSlot();
    let file = null;
    const input = h("input", { type: "file", accept: ".vbk,application/octet-stream", class: "sr-only", id: "file" });
    const hint = h("span", { class: "drop-hint", text: "Tap to choose, or drop it here." });
    const name = h("span", { class: "drop-title", text: "Choose your backup file (.vbk)" });
    const drop = h("label", { class: "drop", for: "file" }, h("span", { class: "icon-tile icon-tile-lg" }, icon("upload")), name, hint, input);
    const pick = (f) => {
      if (!f) return;
      file = f;
      name.textContent = f.name;
      hint.textContent = Math.max(1, Math.round(f.size / 1024)) + " KB. Tap to choose another.";
    };
    input.addEventListener("change", () => pick(input.files[0]));
    drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("is-over"); });
    drop.addEventListener("dragleave", () => drop.classList.remove("is-over"));
    drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("is-over"); pick(e.dataTransfer.files[0]); });
    const pass = B.passwordField({ id: "bk-pass", label: "Backup passphrase", min: 1, generate: false, meter: false, autocomplete: "off", hint: "The passphrase you chose when you made the backup." });
    screen({
      title: ["Restore", "from a backup."],
      lead: "Accounts, devices, your admin password and settings all come back. This server keeps its new address.",
      body: [drop, card(pass.field), err],
      actions: [backBtn(), nextBtn("Restore", async () => {
        if (!file) { B.showError(err, "Choose your backup file first."); return; }
        if (!pass.input.value) { pass.input.focus(); B.showError(err, "Enter the backup passphrase."); return; }
        const enc = btoa(String.fromCharCode(...new TextEncoder().encode(pass.input.value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
        const r = await api("POST", "/v1/setup/restore", file, { headers: { "X-Backup-Passphrase": enc } });
        if (!r.ok) { B.showError(err, r.error); return; }
        await refresh();
        B.toast("Backup restored");
        go("review");
      }, "check")]
    });
  };

  function onOff(v) { return v ? "On" : "Off"; }

  STEPS.review = (resume) => {
    const s = st.settings;
    const err = B.errorSlot();
    const restore = mode === "restore";
    const catNames = (s.dns_default || []).map((c) => (CATS[c] || [c])[0]);
    const up = (UPSTREAMS.find((u) => u[0] === s.dns_upstream) || ["", s.dns_upstream])[1];
    const row = (k, v, to) => h("div", { class: "kv-row" }, h("dt", { class: "kv-key", text: k }), h("dd", { class: "kv-value", text: v }), to && !restore ? h("div", { class: "kv-action" }, h("button", { class: "btn btn-quiet", type: "button", "aria-label": "Edit " + k, onclick: () => go(to) }, icon("edit"), h("span", { text: "Edit" }))) : null);
    const stealthValue = s.stealth ? (windows() ? "On, TCP fallback on port " + B.state.stealthPort : "On, port 443") : "Off";
    const summary = h("section", { class: "card card-flush surface-panel", "aria-label": "Your setup" },
      h("dl", { class: "kv" },
        row("Address", s.host + (s.tls === "internal" ? " (self-signed)" : ""), null),
        row("Name", s.name, "vpn"),
        row("Stealth mode", stealthValue, "vpn"),
        row("IPv6", onOff(s.ipv6), "vpn"),
        row("Post-quantum", onOff(s.post_quantum), "vpn"),
        row("Devices", s.device_limit + " per account", "vpn"),
        row("Blocking", catNames.length ? catNames.join(", ") : "Nothing", "privacy"),
        row("Lookups", up, "privacy"),
        row("Updates", s.auto_updates ? "Automatic" : "Manual", "privacy"),
        row("Admin panel", s.admin_vpn_only ? "Only through the VPN" : "From anywhere", "privacy"),
        row("Who can join", (REG[s.registration] || [s.registration])[0], "accounts"),
        restore ? row("Accounts", "Restored from backup", null) : row("Your account", st.account_created ? "Ready" : "Skipped", "accounts")
      )
    );
    const list = B.progress();
    const bar = B.progressBar();
    const prog = card(h("div", { class: "stack" }, bar.el, list.el));
    prog.classList.add("is-hidden");
    const install = nextBtn(restore ? "Install restored server" : "Install", () => start(false), "zap");
    install.dataset.busy = "Starting";
    const view = screen({
      title: ["Ready", "to install."],
      lead: "Here's your setup. Press Install and Veyl configures everything. It takes a few minutes.",
      body: [summary, prog, err],
      actions: [backBtn(), install]
    });

    function running() {
      summary.classList.add("is-hidden");
      prog.classList.remove("is-hidden");
      clear(err);
      clear(view.h1).append("Installing", " ", h("span", { class: "text-dim", text: "your VPN." }));
      const lead = view.head.querySelector(".text-lede");
      lead.textContent = "Hang tight. You can keep this page open. It picks up where it left off if your connection drops.";
      const acts = view.main.querySelector(".flow-actions");
      if (acts) acts.classList.add("is-hidden");
    }

    function failed(msg) {
      bar.fail();
      list.settle(false);
      const retry = B.button("Try again", { size: "lg", icon: "refresh", onClick: () => start(false) });
      const back = B.button("Review settings", { variant: "secondary", size: "lg", async: false, onClick: () => STEPS.review() });
      clear(err).append(B.callout("danger", "Something didn't finish", msg || "Lost contact with the server."), h("div", { class: "cluster" }, retry, back));
    }

    async function start(attach) {
      if (!attach) {
        const r = await api("POST", "/v1/setup/apply", {});
        if (!r.ok && r.status !== 409) { B.showError(err, r.error); return; }
      }
      running();
      list.reset();
      bar.reset();
      B.stream("/v1/setup/progress", (ev) => list.step(ev), (d) => {
        if (d && d.ok && d.result && d.result.host) {
          bar.done();
          list.settle(true);
          setTimeout(() => STEPS.done(d.result), 700);
        } else {
          failed(d ? d.error : null);
        }
      });
    }
    if (resume) start(true);
  };

  function panelCard() {
    return h("section", { class: "card surface-quiet", "aria-labelledby": "panel-title" },
      h("div", { class: "stack" },
        h("div", { class: "row" },
          h("span", { class: "icon-tile" }, icon("panel")),
          h("div", { class: "grow" }, h("h2", { class: "card-title", id: "panel-title" }, "Add the Control Panel ", h("span", { class: "badge", text: "Optional" })))
        ),
        h("p", { class: "text-muted", text: "Manage one or many Veyl servers from one place, with uptime checks, alerts and automatic restarts. It runs on its own domain with its own sign in. Skip it if one server is all you need." }),
        command("veyl panel install"),
        h("p", { class: "field-hint" }, windows() ? "Or rerun the installer with -Panel. " : "Or rerun the installer with --panel. ", h("a", { class: "link-quiet", href: "https://github.com/VeylVPN/backend", target: "_blank", rel: "noopener noreferrer" }, "Read how it works", h("span", { class: "sr-only", text: " (opens in a new tab)" })))
      )
    );
  }

  STEPS.done = (res) => {
    current = "done";
    const r = res || {};
    const body = [];
    if (r.account) {
      body.push(h("section", { class: "card surface-card card-glow", "aria-labelledby": "acct-title" },
        h("div", { class: "stack" },
          h("div", null, h("h2", { class: "card-title", id: "acct-title", text: "Your account number" }), h("p", { class: "card-text", text: "It's how you sign in to the app. Write it down: it can't be shown again." })),
          B.secret(r.account, B.groupNumber(r.account), { aria: "Copy account number", toast: "Account number copied" })
        )
      ));
    } else if (r.restored) {
      body.push(B.callout("ok", "Everything was restored", "Everyone can keep using their existing account numbers."));
    }
    body.push(h("section", { class: "card surface-card", "aria-labelledby": "addr-title" },
      h("div", { class: "stack" },
        h("div", null, h("h2", { class: "card-title", id: "addr-title", text: "Server address" }), h("p", { class: "card-text", text: "Type this into the Veyl app. Phones and other computers get an OpenVPN profile from it." })),
        B.command(r.host || "", { icon: "globe", prompt: false, aria: "Copy server address", toast: "Address copied" }),
        h("div", { class: "cluster" },
          r.app_url ? B.button("Get the app", { size: "lg", icon: "download", href: r.app_url, external: true }) : null,
          B.button("Open the admin panel", { variant: r.app_url ? "secondary" : "primary", size: "lg", trailing: "arrowRight", href: r.admin_url || "/admin" })
        )
      )
    ));
    const pass = B.passwordField({ id: "bk", label: "Backup passphrase", min: 10, hint: "At least 10 characters. You need it to restore." });
    const err = B.errorSlot();
    const dl = B.button("Download backup", { variant: "secondary", icon: "download", busy: "Encrypting", onClick: async () => {
      if (!pass.valid()) { pass.input.classList.add("is-invalid"); B.showError(err, "Use at least 10 characters."); return; }
      const x = await api("POST", "/v1/setup/backup", { passphrase: pass.input.value }, { blob: true });
      if (!x.ok) { B.showError(err, x.error); return; }
      clear(err);
      B.save(x.blob, x.filename);
      B.toast("Backup downloaded");
    } });
    body.push(h("section", { class: "card surface-quiet", "aria-labelledby": "bk-title" },
      h("div", { class: "stack" },
        h("div", null, h("h2", { class: "card-title", id: "bk-title", text: "Download an encrypted backup" }), h("p", { class: "card-text", text: "Keeps your accounts, certificates and settings safe if you ever move servers." })),
        pass.field, err, h("div", null, dl)
      )
    ));
    body.push(panelCard());
    clear(app).append(
      h("div", { class: "stack stack-xl" },
        h("header", { class: "stack rise" },
          h("span", { class: "icon-tile icon-tile-lg is-ok", "aria-hidden": "true" }, icon("check")),
          h("h1", { class: "text-headline", tabindex: "-1" }, h("span", { text: "You're all set." }), h("br"), h("span", { class: "text-gradient", text: "Your VPN is live." })),
          h("p", { class: "text-lede measure", text: (r.name ? r.name + " is up and running. " : "Your VPN is up and running. ") + "Setup is now locked. Manage everything from the admin panel." })
        ),
        h("div", { class: "grid-2 grid-start rise delay-2" }, ...body),
        wordmark()
      )
    );
    app.querySelector("h1").focus({ preventScroll: true });
    setMeta(r.host || "");
    try { sessionStorage.removeItem("veyl.setup"); } catch (e) { }
  };

  async function boot() {
    readToken();
    clear(app).append(h("div", { class: "loading" }, B.spinner()));
    if (token) {
      const r = await api("POST", "/v1/setup/session", undefined, { headers: { "X-Setup-Token": token } });
      if (r.ok) {
        B.state.csrf = r.data.csrf;
      } else if (r.status === 429) {
        const s = await refresh();
        if (!s.ok) { STEPS.link("Too many tries. Wait a minute, then open your setup link again."); return; }
      } else {
        const s = await refresh();
        if (!s.ok) {
          try { sessionStorage.removeItem("veyl.setup"); } catch (e) { }
          STEPS.link(r.status === 404 ? "Setup is already finished. Sign in to the admin panel instead." : r.error);
          return;
        }
      }
    }
    const s = await refresh();
    if (!s.ok) {
      STEPS.link(s.status === 404 ? "Setup is already finished. Sign in to the admin panel instead." : null);
      return;
    }
    const job = st.job || {};
    if (st.configured || (job.kind === "apply" && (job.running || job.ok))) {
      current = "review";
      STEPS.review(true);
      return;
    }
    if (job.kind === "tls" && job.running) {
      current = "secure";
      STEPS.secure(true);
      return;
    }
    if (st.secure && st.on_host) {
      if (mode === "restore") { go(st.restored ? "review" : "restore"); return; }
      go(st.admin_set ? "vpn" : "admin");
      return;
    }
    go("welcome");
  }

  window.addEventListener("hashchange", () => { if (location.hash.length > 1) boot(); });

  boot();
})();
