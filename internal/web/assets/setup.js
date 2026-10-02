"use strict";

(() => {
  const { h, icon, clear, api } = V;
  const app = document.getElementById("app");
  const dots = document.getElementById("dots");
  const brand = document.getElementById("brand");
  clear(brand).append(V.logo(), h("span", { text: "Veyl" }));

  const FLOW = ["welcome", "address", "secure", "admin", "vpn", "privacy", "accounts", "review", "done"];
  const RESTORE_FLOW = ["welcome", "address", "secure", "restore", "review", "done"];

  const CATS = {
    ads: ["Ads", "Blocks ad networks in apps and websites.", "ban"],
    trackers: ["Trackers", "Stops companies following people around the web.", "eyeOff"],
    malware: ["Malware and scams", "Blocks known dangerous and phishing sites.", "shield"],
    adult: ["Adult content", "Blocks adult websites.", "lock"],
    gambling: ["Gambling", "Blocks betting and casino sites.", "dice"],
    social: ["Social media", "Blocks Facebook, TikTok, Instagram and others.", "users"]
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
  const draft = { addressMode: "", host: "", email: "", accountSkip: false };

  function flow() { return mode === "restore" ? RESTORE_FLOW : FLOW; }

  function renderDots() {
    clear(dots);
    const f = flow();
    const idx = f.indexOf(current);
    f.forEach((_, i) => dots.append(h("i", { class: i < idx ? "done" : i === idx ? "cur" : "" })));
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
    V.state.csrf = st.csrf || V.state.csrf;
    if (st.restore) mode = "restore";
    return r;
  }

  function screen(o) {
    const head = h("div", { class: "head" },
      o.mark || null,
      o.eyebrow ? h("p", { class: "eyebrow", text: o.eyebrow }) : null,
      h("h1", { text: o.title, tabindex: "-1" }),
      o.lead ? h("p", { class: "lead", text: o.lead }) : null
    );
    const sec = h("section", { class: "step" }, head, ...(o.body || []));
    const bar = h("div", { class: "actions-bar" }, h("div", { class: "in" }, ...(o.actions || [])));
    clear(app).append(sec);
    if (o.actions && o.actions.some(Boolean)) app.append(bar);
    renderDots();
    window.scrollTo(0, 0);
    const h1 = sec.querySelector("h1");
    if (h1 && o.focus !== false) h1.focus({ preventScroll: true });
    return sec;
  }

  function stepLabel() {
    const f = flow();
    const i = f.indexOf(current);
    return "Step " + (i + 1) + " of " + (f.length - 1);
  }

  function backBtn() {
    const f = flow();
    const i = f.indexOf(current);
    let prev = f[i - 1];
    if (prev === "secure") prev = f[i - 2];
    if ((prev === "address" || prev === "welcome") && st && st.secure && st.on_host && current !== "secure") return null;
    if (!prev) return null;
    return h("button", { class: "btn btn-ghost", type: "button", onclick: () => go(prev) }, icon("arrowL"), h("span", { text: "Back" }));
  }

  function nextBtn(label, fn, ic) {
    const b = h("button", { class: "btn btn-primary", type: "button" }, h("span", { text: label || "Continue" }), icon(ic || "arrowR"));
    b.addEventListener("click", () => V.busy(b, fn));
    return b;
  }

  function errorBox() {
    return h("div", { class: "err-slot", "aria-live": "assertive" });
  }

  function showErr(slot, msg, title) {
    clear(slot).append(V.callout("err", title || "", msg));
  }

  function go(name) {
    current = name;
    const fn = STEPS[name];
    fn();
  }

  function fact(k, v, good) {
    return h("div", null, h("div", { class: "k", text: k }), h("div", { class: "v" + (good ? " good" : ""), text: v || "—", title: v || "" }));
  }

  function heroMark() {
    const m = h("div", { class: "hero-mark", "aria-hidden": "true" });
    const pat = "on,off,on,mid,on,mid,on,off,mid,off,on,mid,off,on,on".split(",");
    pat.forEach((k) => m.append(h("i", { class: k === "off" ? "" : k })));
    return m;
  }

  const STEPS = {};

  STEPS.link = (msg) => {
    current = "welcome";
    screen({
      mark: heroMark(),
      eyebrow: "Setup link needed",
      title: "Open your setup link",
      lead: msg || "For your safety, setup only opens from the private link the installer printed.",
      body: [
        h("div", { class: "card stack" },
          h("p", { text: "Lost the link? Run this on your server to get a fresh one:" }),
          h("div", { class: "code-box" }, h("div", { class: "val small", text: "sudo veyl setup-link" }), h("button", { class: "btn btn-ghost btn-small", type: "button", onclick: () => V.copy("sudo veyl setup-link") }, icon("copy"), "Copy"))
        )
      ]
    });
    clear(dots);
  };

  STEPS.welcome = () => {
    const f = (st && st.facts) || {};
    const ram = f.ram_mb ? (Number(f.ram_mb) >= 1024 ? (Number(f.ram_mb) / 1024).toFixed(1).replace(/\.0$/, "") + " GB" : f.ram_mb + " MB") : "";
    screen({
      mark: heroMark(),
      eyebrow: "Welcome",
      title: "Let's set up your private VPN",
      lead: "It takes about five minutes. We've picked safe defaults, and you can change anything later.",
      body: [
        h("div", { class: "kv" },
          fact("Public IP", f.public_ip),
          fact("System", f.os),
          fact("Memory", ram),
          fact("OpenVPN", f.openvpn),
          fact("OpenSSL", f.openssl),
          fact("Post-quantum", f.pq_available ? "Available" : (f.openssl ? "Not available" : ""), f.pq_available)
        ),
        h("div", { class: "row-wrap" },
          h("button", { class: "link-btn", type: "button", onclick: () => { mode = "restore"; go("address"); } }, "Moving from another server? Restore from a backup")
        )
      ],
      actions: [nextBtn("Start setup", async () => { mode = "normal"; go("address"); })]
    });
  };

  function dnsHelp(host, ip) {
    const parts = host.split(".");
    const name = parts.length > 2 ? parts.slice(0, parts.length - 2).join(".") : "@";
    return h("div", { class: "list" },
      h("div", { class: "list-row" }, h("div", { class: "k", text: "Type" }), h("div", { class: "v mono", text: "A" })),
      h("div", { class: "list-row" }, h("div", { class: "k", text: "Name" }), h("div", { class: "v mono", text: name })),
      h("div", { class: "list-row" }, h("div", { class: "k", text: "Value" }), h("div", { class: "v mono", text: ip || "this server's IP" }), ip ? h("button", { class: "btn btn-quiet btn-small", type: "button", "aria-label": "Copy IP address", onclick: () => V.copy(ip) }, icon("copy")) : null)
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
    const err = errorBox();
    const detail = h("div", { class: "stack" });
    const status = h("div", { "aria-live": "polite" });
    let lastCheck = null;
    let timer = 0;

    const freeBtn = V.choice({ icon: "sparkle", title: "Use a free address", badge: free ? "Easiest" : null, desc: free ? "We'll use " + free + ", a free name from sslip.io that points to this server. Nothing to set up." : "Not available because we couldn't find this server's public IPv4 address.", on: draft.addressMode === "free" });
    const domBtn = V.choice({ icon: "globe", title: "I have my own domain", desc: "Like vpn.example.com. You'll point it at this server.", on: draft.addressMode === "domain" });
    const ipBtn = V.choice({ icon: "server", title: "Use the IP address only", desc: "Advanced. Browsers will warn because the certificate is self-signed.", on: draft.addressMode === "ip" });
    if (!free) freeBtn.disabled = true;
    const group = h("div", { class: "stack" }, freeBtn, domBtn);
    const advanced = h("div", { class: "stack" + (draft.addressMode === "ip" ? "" : " hidden") }, ipBtn);
    const advLink = h("button", { class: "link-btn" + (draft.addressMode === "ip" ? " hidden" : ""), type: "button", onclick: () => { advanced.classList.remove("hidden"); advLink.classList.add("hidden"); } }, "More options");

    const hostInput = h("input", { class: "input", id: "host", type: "text", inputmode: "url", autocomplete: "off", autocapitalize: "off", spellcheck: "false", placeholder: "vpn.example.com", value: draft.host });
    const emailInput = h("input", { class: "input", id: "email", type: "email", autocomplete: "email", placeholder: "you@example.com", value: draft.email });
    const emailField = h("div", { class: "field hidden" }, h("label", { class: "label", for: "email", text: "Email for certificate notices (optional)" }), emailInput, h("p", { class: "hint", text: "Only used by Let's Encrypt to warn about expiring certificates." }));
    const emailLink = h("button", { class: "link-btn", type: "button", onclick: () => { emailField.classList.remove("hidden"); emailLink.classList.add("hidden"); emailInput.focus(); } }, "Add an email for certificate notices (optional)");
    if (draft.email) { emailField.classList.remove("hidden"); emailLink.classList.add("hidden"); }

    async function check() {
      const host = hostInput.value.trim().toLowerCase().replace(/\.$/, "");
      draft.host = host;
      if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(host)) {
        lastCheck = null;
        clear(status);
        if (host.length > 3) status.append(V.callout("", "", "Enter the full name, like vpn.example.com."));
        return;
      }
      clear(status).append(h("div", { class: "callout" }, V.spinner(), h("div", { class: "grow", text: "Checking " + host + "…" })));
      const r = await api("GET", "/v1/setup/dns-check?host=" + encodeURIComponent(host));
      if (hostInput.value.trim().toLowerCase().replace(/\.$/, "") !== host) return;
      if (!r.ok) { lastCheck = null; clear(status).append(V.callout("err", "", r.error)); return; }
      lastCheck = r.data;
      const c = r.data;
      const kind = c.status === "ok" ? "ok" : c.status === "error" ? "" : "warn";
      const title = { ok: "Points to this server", missing: "Not found yet", wrong: "Points somewhere else", mixed: "Extra addresses found", proxied: "Behind Cloudflare's proxy", error: "Couldn't check" }[c.status] || "";
      clear(status).append(V.callout(kind, title, c.message + (c.note ? " " + c.note : "")));
      if (c.status !== "ok") status.append(h("div", { class: "stack mt-s" }, h("p", { class: "hint", text: "At your domain provider, add this record:" }), dnsHelp(host, ip), h("div", { class: "row-wrap" }, h("button", { class: "btn btn-ghost btn-small", type: "button", onclick: check }, icon("refresh"), "Check again"))));
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
        detail.append(h("div", { class: "card stack" },
          h("div", { class: "field" }, h("label", { class: "label", for: "host", text: "Your domain" }), hostInput),
          status,
          emailLink,
          emailField
        ));
        if (draft.host && !lastCheck) check();
      } else if (draft.addressMode === "ip") {
        detail.append(V.callout("warn", "Not recommended", "Browsers and some apps will show a security warning, because a free trusted certificate needs a name. Use this only if the other options don't work."));
      } else if (draft.addressMode === "free") {
        detail.append(V.callout("", "", "sslip.io is a free public service that turns an IP address into a name. If you get a domain later, you can switch in the admin panel."));
      }
      nextLabel();
    }

    V.radioGroup(group, [freeBtn, domBtn, ipBtn], (b) => {
      draft.addressMode = b === freeBtn ? "free" : b === domBtn ? "domain" : "ip";
      renderDetail();
      if (draft.addressMode === "domain") setTimeout(() => hostInput.focus(), 50);
    });

    const next = nextBtn("Continue", async () => {
      const body = { mode: draft.addressMode, restore: mode === "restore" };
      if (draft.addressMode === "domain") {
        body.host = hostInput.value.trim().toLowerCase().replace(/\.$/, "");
        body.email = emailInput.value.trim();
        draft.email = body.email;
        if (!body.host) { hostInput.classList.add("invalid"); hostInput.focus(); showErr(err, "Enter your domain first."); return; }
      }
      const r = await api("POST", "/v1/setup/address", body);
      if (!r.ok) { showErr(err, r.error); return; }
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
      eyebrow: stepLabel(),
      title: "How will apps find your server?",
      lead: "Pick an address. It also gets a free certificate, so everything after this step is encrypted.",
      body: [group, detail, advLink, advanced, err],
      actions: [backBtn(), next]
    });
    renderDetail();
  };

  STEPS.secure = (resume) => {
    const list = V.progressList();
    const bar = h("div", { class: "bar" }, h("i"));
    const out = h("div", { "aria-live": "polite" });
    const host = (st && st.settings.host) || "";
    const actions = h("div", { class: "row-wrap" });
    screen({
      eyebrow: stepLabel(),
      title: "Securing your connection",
      lead: "Getting a certificate for " + host + ". This usually takes under a minute.",
      body: [h("div", { class: "card stack" }, bar, list.el), out, actions]
    });

    function failed(msg) {
      bar.className = "bar fail";
      list.settle(false);
      clear(out).append(V.callout("err", "We couldn't get a certificate", msg || "The certificate service didn't respond."));
      const retry = h("button", { class: "btn btn-primary", type: "button" }, icon("refresh"), h("span", { text: "Try again" }));
      retry.addEventListener("click", () => STEPS.secure());
      const self = h("button", { class: "btn btn-ghost", type: "button" }, h("span", { text: "Use a self-signed certificate" }));
      self.addEventListener("click", () => V.busy(self, async () => {
        const body = { mode: draft.addressMode || "domain", self_signed: true, restore: mode === "restore" };
        if (body.mode === "domain") body.host = host;
        const r = await api("POST", "/v1/setup/address", body);
        if (!r.ok) { V.toast(r.error, "err"); return; }
        STEPS.secure();
      }));
      const change = h("button", { class: "btn btn-quiet", type: "button", onclick: () => go("address") }, icon("arrowL"), h("span", { text: "Change address" }));
      clear(actions).append(retry, self, change);
      out.append(h("p", { class: "hint mt-s", text: "Common causes: the domain doesn't point here yet, or ports 80 and 443 are blocked by your hosting firewall." }));
    }

    function succeeded(res) {
      bar.className = "bar done";
      list.settle(true);
      const url = res && res.result && res.result.redirect;
      if (!url) { failed("No secure address was returned."); return; }
      if (!token) {
        clear(out).append(V.callout("warn", "Secured", "Open " + url + " with your setup link to continue. Run \"sudo veyl setup-link\" on the server to get it."));
        return;
      }
      clear(out).append(V.callout("ok", "Secured", "Taking you to the secure page…"));
      setTimeout(() => location.replace(url + "#" + encodeURIComponent(token)), 900);
    }

    async function run() {
      if (!resume) {
        const r = await api("POST", "/v1/setup/secure", {});
        if (!r.ok && r.status !== 409) { failed(r.error); return; }
      }
      V.stream("/v1/setup/progress", (ev) => list.step(ev), (d) => {
        if (d && d.ok) succeeded(d);
        else failed(d ? d.error : "Lost contact with the server.");
      });
    }
    run();
  };

  STEPS.admin = () => {
    const err = errorBox();
    const pw = V.passwordField({ id: "admin-pw", label: "Admin password", min: 12, hint: "At least 12 characters." });
    const already = st && st.admin_set;
    screen({
      eyebrow: stepLabel(),
      title: "Create your admin password",
      lead: "You'll use it to sign in to the admin panel. Only you need it.",
      body: [
        h("div", { class: "card stack" }, pw.field),
        already ? V.callout("ok", "Password saved", "Enter a new one to change it, or just continue.") : null,
        V.callout("", "", "Keep it in a password manager. Forgot it later? Run \"sudo veyl admin reset-password\" on the server.", "key"),
        err
      ],
      actions: [backBtn(), nextBtn("Continue", async () => {
        if (!pw.input.value && already) { go("vpn"); return; }
        if (!pw.valid()) { pw.input.classList.add("invalid"); pw.input.focus(); showErr(err, "Use at least 12 characters."); return; }
        const r = await api("POST", "/v1/setup/admin", { password: pw.input.value });
        if (!r.ok) { showErr(err, r.error); return; }
        st.admin_set = true;
        go("vpn");
      })]
    });
  };

  STEPS.vpn = () => {
    const s = st.settings;
    const f = st.facts || {};
    const err = errorBox();
    const name = h("input", { class: "input", id: "name", type: "text", maxlength: "40", value: s.name || "Veyl", autocomplete: "off" });
    const stealth = V.toggleRow("Stealth mode", "Works on networks that block VPNs, like some offices, schools and hotels. Looks like normal web traffic.", s.stealth);
    const v6 = V.toggleRow("IPv6", f.has_ipv6 ? "Give devices IPv6 too, so every site works." : "This server has no public IPv6 address, so this stays off.", f.has_ipv6 ? s.ipv6 : false, { disabled: !f.has_ipv6 });
    const pq = V.toggleRow("Post-quantum protection", f.pq_available ? "Protects today's traffic against future quantum computers." : "Needs OpenSSL 3.5 or newer on the server" + (f.openssl ? " (this one has " + f.openssl + ")" : "") + ".", f.pq_available ? s.post_quantum : false, { disabled: !f.pq_available });
    let limit = s.device_limit || 5;
    const out = h("output", { text: String(limit) });
    const minus = h("button", { type: "button", "aria-label": "Fewer devices", text: "−" });
    const plus = h("button", { type: "button", "aria-label": "More devices", text: "+" });
    const sync = () => { out.textContent = String(limit); minus.disabled = limit <= 1; plus.disabled = limit >= 20; };
    minus.addEventListener("click", () => { limit = Math.max(1, limit - 1); sync(); });
    plus.addEventListener("click", () => { limit = Math.min(20, limit + 1); sync(); });
    sync();
    screen({
      eyebrow: stepLabel(),
      title: "Your VPN",
      lead: "Good defaults are already on. Change what you like.",
      body: [
        h("div", { class: "card" }, h("div", { class: "field" }, h("label", { class: "label", for: "name", text: "Server name" }), name, h("p", { class: "hint", text: "Shown in the app." }))),
        h("div", { class: "card card-tight" }, stealth.row, v6.row, pq.row,
          h("div", { class: "toggle-row" }, h("div", { class: "txt" }, h("div", { class: "t", text: "Devices per account" }), h("div", { class: "d", text: "How many phones and computers each person can connect." })), h("div", { class: "stepper" }, minus, out, plus))
        ),
        err
      ],
      actions: [backBtn(), nextBtn("Continue", async () => {
        const body = { name: name.value.trim(), stealth: stealth.sw.on(), ipv6: v6.sw.on(), post_quantum: pq.sw.on(), device_limit: limit };
        const r = await api("PUT", "/v1/setup/settings", body);
        if (!r.ok) { showErr(err, r.error); return; }
        st.settings = r.data.settings;
        go("privacy");
      })]
    });
  };

  STEPS.privacy = () => {
    const s = st.settings;
    const err = errorBox();
    const on = new Set(s.dns_default || []);
    const rows = {};
    const cats = h("div", { class: "card card-tight" });
    (st.categories || Object.keys(CATS)).forEach((c) => {
      const m = CATS[c] || [c, "", "ban"];
      rows[c] = V.toggleRow(m[0], m[1], on.has(c));
      cats.append(rows[c].row);
    });
    let upstream = s.dns_upstream || "recursive";
    const seg = h("div", { class: "seg" });
    const segBtns = UPSTREAMS.map(([v, t, d]) => h("button", { type: "button", role: "radio", "aria-checked": v === upstream ? "true" : "false", "data-v": v }, h("span", { class: "t", text: t }), h("span", { class: "d", text: d })));
    segBtns.forEach((b) => seg.append(b));
    V.radioGroup(seg, segBtns, (b) => { upstream = b.getAttribute("data-v"); });
    const updates = V.toggleRow("Automatic security updates", "Installs security fixes for the system by itself.", s.auto_updates);
    const vpnOnly = V.toggleRow("Admin panel only through the VPN", "Hides the admin panel from the internet. You'll need to be connected to open it.", s.admin_vpn_only);
    screen({
      eyebrow: stepLabel(),
      title: "Privacy and blocking",
      lead: "Veyl never logs what anyone does. Pick what to block for everyone. Each person can change it in the app.",
      body: [
        h("p", { class: "card-title", text: "Block by default" }),
        cats,
        h("p", { class: "card-title", text: "Name lookups" }),
        seg,
        h("p", { class: "card-title", text: "Server" }),
        h("div", { class: "card card-tight" }, updates.row, vpnOnly.row),
        err
      ],
      actions: [backBtn(), nextBtn("Continue", async () => {
        const dns = Object.keys(rows).filter((c) => rows[c].sw.on());
        const r = await api("PUT", "/v1/setup/settings", { dns_default: dns, dns_upstream: upstream, auto_updates: updates.sw.on(), admin_vpn_only: vpnOnly.sw.on() });
        if (!r.ok) { showErr(err, r.error); return; }
        st.settings = r.data.settings;
        go("accounts");
      })]
    });
  };

  STEPS.accounts = () => {
    const s = st.settings;
    const err = errorBox();
    let reg = s.registration || "invite";
    const btns = ["invite", "open", "closed"].map((k) => {
      const b = V.choice({ icon: REG[k][2], title: REG[k][0], desc: REG[k][1], badge: k === "invite" ? "Recommended" : null, on: reg === k });
      b.setAttribute("data-v", k);
      return b;
    });
    const group = h("div", { class: "stack" }, ...btns);
    V.radioGroup(group, btns, (b) => { reg = b.getAttribute("data-v"); });
    const pw = V.passwordField({ id: "acct-pw", label: "Password for your account", min: 10, hint: "At least 10 characters. You'll get an account number at the end." });
    const made = st.account_created;
    const accountCard = h("div", { class: "card stack" },
      h("h3", { text: "Your own account" }),
      h("p", { class: "hint", text: made ? "Your account is ready. Type a new password to replace it, or just continue." : "Create an account for yourself now, so you can connect right away." }),
      pw.field,
      h("div", { class: "row-wrap" }, h("button", { class: "link-btn", type: "button", onclick: () => { draft.accountSkip = true; submit(true); } }, made ? "Remove my account" : "Skip, I'll do this later"))
    );
    async function submit(skip) {
      const r = await api("PUT", "/v1/setup/settings", { registration: reg });
      if (!r.ok) { showErr(err, r.error); return; }
      st.settings = r.data.settings;
      if (skip) {
        const a = await api("POST", "/v1/setup/account", { skip: true });
        if (!a.ok) { showErr(err, a.error); return; }
        st.account_created = false;
      } else if (pw.input.value) {
        if (!pw.valid()) { pw.input.classList.add("invalid"); pw.input.focus(); showErr(err, "Use at least 10 characters."); return; }
        const a = await api("POST", "/v1/setup/account", { password: pw.input.value });
        if (!a.ok) { showErr(err, a.error); return; }
        st.account_created = true;
      } else if (!made) {
        pw.input.classList.add("invalid");
        pw.input.focus();
        showErr(err, "Add a password, or choose \"Skip\".");
        return;
      }
      go("review");
    }
    screen({
      eyebrow: stepLabel(),
      title: "Who can join?",
      lead: "People sign in to the app with an account number and a password.",
      body: [group, accountCard, err],
      actions: [backBtn(), nextBtn("Continue", () => submit(false))]
    });
  };

  STEPS.restore = () => {
    const err = errorBox();
    let file = null;
    const input = h("input", { type: "file", accept: ".vbk,application/octet-stream", class: "sr", id: "file" });
    const dt = h("div", { class: "d", text: "Tap to choose, or drop it here." });
    const tt = h("div", { class: "t", text: "Choose your backup file (.vbk)" });
    const drop = h("label", { class: "drop", for: "file" }, icon("upload"), tt, dt, input);
    const pick = (f) => {
      if (!f) return;
      file = f;
      tt.textContent = f.name;
      dt.textContent = Math.max(1, Math.round(f.size / 1024)) + " KB · tap to choose another";
    };
    input.addEventListener("change", () => pick(input.files[0]));
    drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
    drop.addEventListener("dragleave", () => drop.classList.remove("over"));
    drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); pick(e.dataTransfer.files[0]); });
    const pass = V.passwordField({ id: "bk-pass", label: "Backup passphrase", min: 1, generate: false, meter: false, autocomplete: "off", hint: "The passphrase you chose when you made the backup." });
    screen({
      eyebrow: stepLabel(),
      title: "Restore from a backup",
      lead: "Accounts, devices, your admin password and settings all come back. This server keeps its new address.",
      body: [drop, h("div", { class: "card" }, pass.field), err],
      actions: [backBtn(), nextBtn("Restore", async () => {
        if (!file) { showErr(err, "Choose your backup file first."); return; }
        if (!pass.input.value) { pass.input.focus(); showErr(err, "Enter the backup passphrase."); return; }
        const enc = btoa(String.fromCharCode(...new TextEncoder().encode(pass.input.value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
        const r = await api("POST", "/v1/setup/restore", file, { headers: { "X-Backup-Passphrase": enc } });
        if (!r.ok) { showErr(err, r.error); return; }
        await refresh();
        V.toast("Backup restored");
        go("review");
      }, "check")]
    });
  };

  function onOff(v) { return v ? "On" : "Off"; }

  STEPS.review = (resume) => {
    const s = st.settings;
    const err = errorBox();
    const restore = mode === "restore";
    const catNames = (s.dns_default || []).map((c) => (CATS[c] || [c])[0]);
    const up = (UPSTREAMS.find((u) => u[0] === s.dns_upstream) || ["", s.dns_upstream])[1];
    const row = (k, v, to) => h("div", { class: "list-row" }, h("div", { class: "k", text: k }), h("div", { class: "v", text: v }), to && !restore ? h("button", { class: "btn btn-quiet btn-small", type: "button", "aria-label": "Edit " + k, onclick: () => go(to) }, icon("edit")) : null);
    const summary = h("div", { class: "list" },
      row("Address", s.host + (s.tls === "internal" ? " (self-signed)" : ""), null),
      row("Name", s.name, "vpn"),
      row("Stealth mode", onOff(s.stealth), "vpn"),
      row("IPv6", onOff(s.ipv6), "vpn"),
      row("Post-quantum", onOff(s.post_quantum), "vpn"),
      row("Devices", s.device_limit + " per account", "vpn"),
      row("Blocking", catNames.length ? catNames.join(", ") : "Nothing", "privacy"),
      row("Lookups", up, "privacy"),
      row("Updates", s.auto_updates ? "Automatic" : "Manual", "privacy"),
      row("Admin panel", s.admin_vpn_only ? "Only through the VPN" : "From anywhere", "privacy"),
      row("Who can join", (REG[s.registration] || [s.registration])[0], "accounts"),
      restore ? row("Accounts", "Restored from backup", null) : row("Your account", st.account_created ? "Ready" : "Skipped", "accounts")
    );
    const prog = h("div", { class: "stack hidden" });
    const list = V.progressList();
    const bar = h("div", { class: "bar" }, h("i"));
    prog.append(h("div", { class: "card stack" }, bar, list.el));
    const install = nextBtn(restore ? "Install restored server" : "Install", () => start(false), "zap");
    install.dataset.busy = "Starting…";
    const sec = screen({
      eyebrow: restore ? "Almost there" : stepLabel(),
      title: "Ready to install",
      lead: "Here's your setup. Tap Install and we'll configure everything. It takes a few minutes.",
      body: [summary, prog, err],
      actions: [backBtn(), install]
    });
    const bar2 = document.querySelector(".actions-bar");

    function running() {
      summary.classList.add("hidden");
      prog.classList.remove("hidden");
      clear(err);
      const t = sec.querySelector("h1");
      t.textContent = "Installing";
      const lead = sec.querySelector(".lead");
      lead.textContent = "Hang tight. You can keep this page open; it picks up where it left off if your connection drops.";
      if (bar2) bar2.classList.add("hidden");
    }

    function failed(msg) {
      bar.className = "bar fail";
      list.settle(false);
      const retry = h("button", { class: "btn btn-primary", type: "button" }, icon("refresh"), h("span", { text: "Try again" }));
      retry.addEventListener("click", () => V.busy(retry, () => start(false)));
      const back = h("button", { class: "btn btn-ghost", type: "button", onclick: () => STEPS.review() }, h("span", { text: "Review settings" }));
      clear(err).append(V.callout("err", "Something didn't finish", msg || "Lost contact with the server."), h("div", { class: "row-wrap mt-s" }, retry, back));
    }

    async function start(attach) {
      if (!attach) {
        const r = await api("POST", "/v1/setup/apply", {});
        if (!r.ok && r.status !== 409) { showErr(err, r.error); return; }
      }
      running();
      list.reset();
      bar.className = "bar";
      V.stream("/v1/setup/progress", (ev) => list.step(ev), (d) => {
        if (d && d.ok && d.result && d.result.host) {
          bar.className = "bar done";
          list.settle(true);
          setTimeout(() => STEPS.done(d.result), 700);
        } else {
          failed(d ? d.error : null);
        }
      });
    }
    if (resume) start(true);
  };

  STEPS.done = (res) => {
    current = "done";
    const r = res || {};
    const body = [];
    if (r.account) {
      body.push(h("div", { class: "card stack" },
        h("h3", { text: "Your account number" }),
        h("div", { class: "code-box big" }, h("div", { class: "val", text: V.groupNumber(r.account) }), h("button", { class: "btn btn-ghost btn-small", type: "button", onclick: () => V.copy(r.account, "Account number copied") }, icon("copy"), "Copy")),
        V.callout("warn", "Write it down", "It's how you sign in to the app, and it can't be shown again.")
      ));
    } else if (r.restored) {
      body.push(V.callout("ok", "Everything was restored", "Everyone can keep using their existing account numbers."));
    }
    body.push(h("div", { class: "card stack" },
      h("h3", { text: "Server address" }),
      h("p", { class: "hint", text: "Type this into the Veyl app." }),
      h("div", { class: "code-box" }, h("div", { class: "val small", text: r.host || "" }), h("button", { class: "btn btn-ghost btn-small", type: "button", onclick: () => V.copy(r.host || "", "Address copied") }, icon("copy"), "Copy"))
    ));
    body.push(h("div", { class: "cta" },
      r.app_url ? h("a", { class: "btn btn-primary", href: r.app_url, target: "_blank", rel: "noopener noreferrer" }, icon("phone"), h("span", { text: "Get the app" })) : null,
      h("a", { class: "btn btn-ghost", href: r.admin_url || "/admin" }, icon("grid"), h("span", { text: "Open admin panel" }))
    ));
    const pass = V.passwordField({ id: "bk", label: "Backup passphrase", min: 10, hint: "At least 10 characters. You'll need it to restore." });
    const err = errorBox();
    const dl = h("button", { class: "btn btn-ghost", type: "button" }, icon("download"), h("span", { text: "Download backup" }));
    dl.dataset.busy = "Encrypting…";
    dl.addEventListener("click", () => V.busy(dl, async () => {
      if (!pass.valid()) { pass.input.classList.add("invalid"); showErr(err, "Use at least 10 characters."); return; }
      const x = await api("POST", "/v1/setup/backup", { passphrase: pass.input.value }, { blob: true });
      if (!x.ok) { showErr(err, x.error); return; }
      clear(err);
      V.save(x.blob, x.filename);
      V.toast("Backup downloaded");
    }));
    body.push(h("div", { class: "card stack" },
      h("h3", { text: "Download an encrypted backup" }),
      h("p", { class: "hint", text: "Keeps your accounts, certificates and settings safe if you ever move servers." }),
      pass.field, dl, err
    ));
    body.push(h("p", { class: "foot" }, "Setup is now locked. Manage everything from the admin panel."));
    screen({
      mark: h("div", { class: "done-mark", "aria-hidden": "true" }, icon("check")),
      eyebrow: "Done",
      title: "You're all set",
      lead: "Your VPN is up and running.",
      body
    });
    clear(dots);
    try { sessionStorage.removeItem("veyl.setup"); } catch (e) { }
  };

  async function boot() {
    readToken();
    clear(app).append(h("div", { class: "empty" }, V.spinner()));
    if (token) {
      const r = await api("POST", "/v1/setup/session", undefined, { headers: { "X-Setup-Token": token } });
      if (r.ok) {
        V.state.csrf = r.data.csrf;
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
