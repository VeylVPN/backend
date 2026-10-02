"use strict";

(() => {
  const B = Brand;
  const { h, icon, clear } = B;
  const app = document.getElementById("app");
  const meta = document.getElementById("nav-meta");
  B.watchNav(document.getElementById("nav"));

  const FLOW = ["domain", "records", "certificate", "owner", "nodes", "done"];
  const NAMES = { domain: "Domain", records: "DNS records", certificate: "Certificate", owner: "Owner account", nodes: "Nodes", done: "Done" };

  let token = "";
  let csrf = "";
  let st = null;
  let current = "domain";
  let nodeHosts = [];
  let timer = 0;

  async function api(method, url, body, extra) {
    B.state.csrf = csrf;
    return B.api(method, url, body, extra);
  }

  function title(parts) {
    const el = h("h1", { class: "text-title", tabindex: "-1" });
    el.append(parts[0]);
    if (parts[1]) el.append(" ", h("span", { class: "text-dim", text: parts[1] }));
    return el;
  }

  function rail() {
    const f = FLOW.filter((s) => s !== "done");
    const idx = f.indexOf(current);
    const r = h("div", { class: "rail flow-rail", role: "progressbar", "aria-label": "Setup progress", "aria-valuemin": "1", "aria-valuemax": String(f.length), "aria-valuenow": String(Math.max(1, idx + 1)), "aria-valuetext": NAMES[current] });
    f.forEach((_, i) => r.append(h("i", { class: i < idx || current === "done" ? "is-done" : i === idx ? "is-current" : "" })));
    return r;
  }

  function steps() {
    const f = FLOW.filter((s) => s !== "done");
    const idx = current === "done" ? f.length : f.indexOf(current);
    const list = h("ol", { class: "steps", "aria-label": "Setup steps" });
    f.forEach((s, i) => {
      const done = i < idx;
      list.append(h("li", { class: "steps-item" + (done ? " is-done" : ""), "aria-current": i === idx ? "step" : null },
        h("span", { class: "steps-marker", "aria-hidden": "true" }, done ? icon("check") : String(i + 1)),
        h("span", { text: NAMES[s] })));
    });
    return list;
  }

  function screen(o) {
    clearInterval(timer);
    const head = h("header", { class: "page-header" }, h("div", { class: "page-header-text" }, title(o.title), o.lead ? h("p", { class: "text-lede", text: o.lead }) : null));
    const body = h("div", { class: "page-body" }, ...(o.body || []).filter(Boolean));
    const acts = (o.actions || []).filter(Boolean);
    const main = h("div", { class: "flow-main rise" }, rail(), head, body, acts.length ? h("div", { class: "flow-actions" }, ...acts) : null);
    clear(app).append(h("div", { class: "flow" }, h("aside", { class: "flow-aside", "aria-label": "Progress" }, steps()), main));
    meta.textContent = (st && st.site && st.site.domain) || location.host;
    window.scrollTo(0, 0);
    const h1 = main.querySelector("h1");
    if (h1) h1.focus({ preventScroll: true });
    return { main, body };
  }

  function back(to) {
    return B.button("Back", { variant: "secondary", size: "lg", icon: "arrowLeft", class: "btn-back", aria: "Back", async: false, onClick: () => go(to) });
  }

  function go(name) {
    current = name;
    ({ domain, records, certificate, owner, nodes, done })[name]();
  }

  async function refresh() {
    const r = await api("GET", "api/setup/state");
    if (r.ok) st = r.data;
    return r;
  }

  function linkProblem(msg) {
    clear(app).append(h("div", { class: "auth-box rise" },
      h("div", { class: "auth-head" }, title(["Open your", "setup link."]), h("p", { class: "text-lede", text: msg || "This page needs the link the installer printed. Lost it? Run this on the server." })),
      B.codeBlock("sudo veyl panel setup-link", "On your server")));
  }

  function domain() {
    const err = B.errorSlot();
    const input = B.input({ value: (st.site && st.site.domain) || "", placeholder: "control.example.com", class: "input-lg", autocapitalize: "off", spellcheck: "false", inputmode: "url" });
    const nodes = h("textarea", { class: "textarea input-mono", rows: "3", placeholder: "vpn1.example.com", spellcheck: "false" });
    nodes.value = (nodeHosts.length ? nodeHosts : (st.node_host ? [st.node_host] : [])).join("\n");
    const next = B.button("Check DNS", { size: "lg", trailing: "arrowRight", onClick: async () => {
      clear(err);
      nodeHosts = nodes.value.split(/\s+/).map((x) => x.trim().toLowerCase()).filter(Boolean).slice(0, 32);
      const r = await api("POST", "api/setup/domain", { domain: input.value.trim(), node_hosts: nodeHosts });
      if (!r.ok) { B.showError(err, r.error); input.focus(); return; }
      await refresh();
      go("records");
    } });
    screen({
      title: ["Give the panel", "its own domain."],
      lead: "Veyl Control lives on a separate name, like control.example.com. It must not be the address of any VPN node.",
      body: [
        h("div", { class: "card surface-card stack" },
          B.field("Panel domain", input, "Point an A record for this name at this server. We show the exact records next."),
          B.field("Node domains to check too", nodes, "Optional. One per line. We check them for the Cloudflare proxy and wrong addresses."),
          err),
        st.ipv4 && st.ipv4.length ? B.callout("info", "This server", "Public address " + st.ipv4.join(", ") + (st.ipv6 && st.ipv6.length ? " and " + st.ipv6.join(", ") : "") + ".") : null
      ],
      actions: [next]
    });
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") next.click(); });
  }

  function reportView(rep, role) {
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
        h("td", null, B.copyButton(x.line, { class: "btn btn-ghost btn-sm", aria: "Copy record", toast: "Record copied" })))));
      parts.push(h("div", { class: "card card-flush surface-panel" }, h("div", { class: "table-wrap" }, h("table", { class: "table record-table" },
        h("thead", null, h("tr", null, ...["", "Name", "Type", "Value", "TTL", ""].map((x) => h("th", { scope: "col", text: x })))), tb))));
    }
    const grid = h("div", { class: "resolver-grid" });
    [...(rep.authoritative || []), ...(rep.public || [])].forEach((v) => {
      const dot = { ok: "is-ok", wrong: "is-danger", proxied: "is-danger", missing: "is-warn" }[v.status] || "";
      const ans = [...(v.a || []), ...(v.aaaa || [])].join(", ") || (v.error ? v.error : "no records yet");
      grid.append(h("div", { class: "resolver" },
        h("div", { class: "resolver-name" }, h("span", { class: "dot " + dot, "aria-hidden": "true" }), h("span", { text: v.label }), v.authoritative ? h("span", { class: "badge badge-violet", text: "Nameserver" }) : null),
        h("div", { class: "resolver-answer", text: ans })));
    });
    parts.push(grid);
    return h("div", { class: "stack" }, ...parts);
  }

  function records() {
    const host = st.site.domain;
    const holder = h("div", { class: "stack" }, h("div", { class: "loading" }, B.spinner()));
    const nodeHolder = h("div", { class: "stack" });
    const live = h("p", { class: "row text-sm text-muted" }, h("span", { class: "dot is-ok is-live", "aria-hidden": "true" }), h("span", { text: "Checking again every 5 seconds" }));
    const next = B.button("Continue", { size: "lg", trailing: "arrowRight", async: false, onClick: () => go("certificate") });
    next.disabled = true;
    const anyway = B.button("Continue anyway", { variant: "ghost", size: "lg", async: false, onClick: () => go("certificate") });
    anyway.classList.add("is-hidden");
    screen({
      title: [host, "in DNS."],
      lead: "We ask your nameservers directly and compare with Cloudflare, Google and Quad9. Fix what is red, the page updates by itself.",
      body: [live, holder, nodeHosts.length ? h("h2", { class: "heading-md mt-8", text: "Node domains" }) : null, nodeHolder],
      actions: [back("domain"), anyway, next]
    });
    let busy = false;
    const check = async () => {
      if (busy || current !== "records") return;
      busy = true;
      const r = await api("GET", "api/setup/records?host=" + encodeURIComponent(host));
      busy = false;
      if (current !== "records") return;
      if (!r.ok) { clear(holder).append(B.callout("danger", "", r.error)); return; }
      clear(holder).append(reportView(r.data, "panel"));
      const ok = r.data.status === "ok" || r.data.status === "propagating";
      next.disabled = !ok;
      anyway.classList.toggle("is-hidden", ok);
    };
    const checkNodes = async () => {
      clear(nodeHolder);
      for (const n of nodeHosts) {
        const r = await api("GET", "api/setup/records?role=node&host=" + encodeURIComponent(n));
        if (current !== "records") return;
        nodeHolder.append(h("section", { class: "card surface-panel stack" }, h("h3", { class: "heading-sm", text: n }), r.ok ? reportView(r.data, "node") : B.callout("danger", "", r.error)));
      }
    };
    check();
    checkNodes();
    timer = setInterval(check, 5000);
  }

  function certificate() {
    const windows = st.platform === "windows";
    let mode = windows ? "caddy" : (st.site.mode === "dns" ? "dns" : "http");
    const err = B.errorSlot();
    const email = B.input({ type: "email", value: st.site.email || "", placeholder: "you@example.com", class: "input-lg", autocomplete: "email" });
    const agree = h("input", { type: "checkbox", id: "agree" });
    const agreeRow = h("label", { class: "check-row", for: "agree" }, agree, h("span", null, "I agree to the ", h("a", { href: "https://letsencrypt.org/repository/", target: "_blank", rel: "noopener noreferrer", text: "Let's Encrypt subscriber agreement" }), "."));
    const modes = windows
      ? B.callout("info", "Caddy gets the certificate on Windows", "certbot is no longer made for Windows, so Caddy requests and renews the certificate with your email. Ports 80 and 443 need to be open.")
      : B.segmented([["http", "Web check", "Port 80 must be open"], ["dns", "DNS TXT record", "For when port 80 is blocked"]], mode, (v) => { mode = v; }, "How to prove the domain is yours");
    const progress = B.progress();
    const bar = B.progressBar();
    const challenge = h("div", { class: "stack" });
    const result = h("div", { class: "stack" });
    const https = "https://" + st.site.domain + "/setup#" + token;
    const cont = B.button("Continue on https", { size: "lg", trailing: "arrowRight", async: false, onClick: () => { location.href = https; } });
    const start = B.button(st.cert ? "Get a new certificate" : "Get the certificate", { size: "lg", icon: "lock", onClick: async () => {
      clear(err);
      if (!email.value.trim()) { B.showError(err, "Enter the email for expiry notices."); email.focus(); return; }
      if (!agree.checked) { B.showError(err, "Agree to the Let's Encrypt terms to continue."); return; }
      const r = await api("POST", "api/setup/cert", { email: email.value.trim(), agree: true, mode });
      if (!r.ok) { B.showError(err, r.error); return; }
      watch(true);
    } });
    const form = h("div", { class: "card surface-card stack" }, B.field("Email for Let's Encrypt", email, "Only used by Let's Encrypt for expiry notices."), windows ? modes : B.settingRow("How to prove it is yours", "", modes), agreeRow, err);
    const s = screen({
      title: ["Lock it down", "with HTTPS."],
      lead: "A free Let's Encrypt certificate for " + st.site.domain + ". It renews on its own.",
      body: [st.https ? B.callout("ok", "This page is already on https", "") : null, form, h("div", { class: "card surface-panel stack is-hidden", id: "cert-progress" }, bar.el, progress.el), challenge, result],
      actions: [back("records"), st.cert && !st.https ? cont : null, start]
    });
    const box = s.body.querySelector("#cert-progress");
    let poller = 0;
    function drawChallenge(c) {
      clear(challenge);
      if (!c || !c.active) return;
      const ch = c.challenge;
      const rows = h("div", { class: "resolver-grid" });
      (ch.report && ch.report.servers || []).forEach((sv) => rows.append(h("div", { class: "resolver" },
        h("div", { class: "resolver-name" }, h("span", { class: "dot " + (sv.visible ? "is-ok" : "is-warn"), "aria-hidden": "true" }), h("span", { text: sv.label })),
        h("div", { class: "resolver-answer", text: sv.visible ? "Sees the record" : (sv.error || "Not yet") }))));
      challenge.append(h("section", { class: "card surface-card stack" },
        h("h2", { class: "heading-md", text: "Add this TXT record" }),
        h("p", { class: "text-muted", text: "Create it at your DNS provider. We continue as soon as every nameserver shows it." }),
        B.secret(ch.value, ch.value, { small: true, aria: "Copy TXT value", toast: "Value copied" }),
        h("dl", { class: "kv" },
          h("div", { class: "kv-row" }, h("dt", { class: "kv-key", text: "Name" }), h("dd", { class: "kv-value text-mono", text: ch.name })),
          h("div", { class: "kv-row" }, h("dt", { class: "kv-key", text: "Type" }), h("dd", { class: "kv-value", text: "TXT" })),
          h("div", { class: "kv-row" }, h("dt", { class: "kv-key", text: "TTL" }), h("dd", { class: "kv-value", text: "300" }))),
        rows,
        h("div", { class: "cluster" }, B.copyButton(ch.record && ch.record.line ? ch.record.line : ch.name, { class: "btn btn-secondary btn-sm", aria: "Copy zone file line", toast: "Record copied" }),
          B.button("Cancel", { variant: "ghost", size: "sm", onClick: async () => { await api("POST", "api/setup/challenge/cancel", {}); } }))));
    }
    function watch(fresh) {
      box.classList.remove("is-hidden");
      start.disabled = true;
      if (fresh) { progress.reset(); bar.reset(); }
      if (mode === "dns") {
        poller = setInterval(async () => {
          const c = await api("GET", "api/setup/challenge");
          if (c.ok) drawChallenge(c.data);
        }, 3000);
      }
      B.stream("api/setup/cert/progress", (ev) => progress.step(ev), async (d) => {
        clearInterval(poller);
        clear(challenge);
        start.disabled = false;
        const ok = !!(d && d.ok);
        progress.settle(ok);
        if (ok) bar.done(); else bar.fail();
        clear(result);
        if (ok) {
          result.append(B.callout("ok", "Certificate ready", "Continue on https to create the owner account. Your setup link comes along."), h("div", { class: "cluster" }, B.button("Continue on https", { size: "lg", trailing: "arrowRight", async: false, onClick: () => { location.href = https; } })));
        } else {
          result.append(B.callout("danger", "No certificate yet", (d && d.error) || "Lost contact with the server."));
        }
      });
    }
    if (st.cert_job && st.cert_job.running) watch(false);
  }

  function owner() {
    const err = B.errorSlot();
    if (!st.https) {
      screen({
        title: ["Switch to", "https first."],
        lead: "The owner password is only sent over an encrypted link.",
        body: [B.callout("warn", "", "Open https://" + st.site.domain + "/setup with your setup link.")],
        actions: [back("certificate"), B.button("Continue on https", { size: "lg", trailing: "arrowRight", async: false, onClick: () => { location.href = "https://" + st.site.domain + "/setup#" + token; } })]
      });
      return;
    }
    const user = B.input({ placeholder: "you", class: "input-lg", autocomplete: "username", autocapitalize: "off", spellcheck: "false" });
    const pw = B.passwordField({ label: "Password", min: 12, hint: "At least 12 characters. A password manager helps." });
    const next = B.button("Create the owner", { size: "lg", trailing: "arrowRight", onClick: async () => {
      clear(err);
      if (!pw.valid()) { B.showError(err, "Use at least 12 characters."); return; }
      const r = await api("POST", "api/setup/owner", { username: user.value.trim().toLowerCase(), password: pw.input.value });
      if (!r.ok) { B.showError(err, r.error); return; }
      enroll(r.data.enroll, user.value.trim().toLowerCase());
    } });
    screen({
      title: ["Create the", "owner account."],
      lead: "The owner can do everything, including inviting the rest of the team. Two-step sign in is required.",
      body: [h("div", { class: "card surface-card stack" }, B.field("Username", user, "Lowercase letters, digits, dots and dashes."), pw.field, err)],
      actions: [next]
    });
  }

  async function enroll(ticket, name) {
    const info = await api("POST", "api/enroll/info", { ticket });
    if (!info.ok) { owner(); return; }
    const err = B.errorSlot();
    const code = B.input({ inputmode: "numeric", autocomplete: "one-time-code", placeholder: "123 456", mono: true, class: "input-lg" });
    const next = B.button("Turn on two-step sign in", { size: "lg", trailing: "arrowRight", onClick: async () => {
      const r = await api("POST", "api/enroll/finish", { ticket, code: code.value.replace(/\s/g, "") });
      if (!r.ok) { B.showError(err, r.error); code.select(); return; }
      const list = h("ol", { class: "codes" });
      r.data.recovery.forEach((c) => list.append(h("li", { text: c })));
      const text = r.data.recovery.join("\n");
      screen({
        title: ["Save your", "recovery codes."],
        lead: "Each code signs you in once if you lose your phone. They are not shown again.",
        body: [h("div", { class: "card surface-card stack" }, list, h("div", { class: "cluster" },
          B.copyButton(text, { class: "btn btn-secondary btn-sm", aria: "Copy recovery codes", toast: "Recovery codes copied" }),
          B.button("Download", { variant: "ghost", size: "sm", icon: "download", async: false, onClick: () => B.save(new Blob([text + "\n"], { type: "text/plain" }), "veyl-control-recovery-codes.txt") })))],
        actions: [B.button("I saved them", { size: "lg", trailing: "arrowRight", onClick: async () => { await refresh(); go("nodes"); } })]
      });
    } });
    screen({
      title: ["Scan with your", "authenticator."],
      lead: "Signed in as " + name + " from now on. Use an app like Aegis, 2FAS or 1Password.",
      body: [h("div", { class: "card surface-card stack" },
        h("img", { class: "qr", src: info.data.qr, alt: "QR code for your authenticator app", width: "220", height: "220" }),
        B.secret(info.data.secret, info.data.secret, { small: true, aria: "Copy setup key", toast: "Setup key copied" }),
        B.field("6 digit code", code), err)],
      actions: [next]
    });
    code.focus();
  }

  function nodes() {
    const err = B.errorSlot();
    const list = h("div", { class: "list" });
    const draw = () => {
      clear(list);
      if (!st.nodes.length) list.append(h("p", { class: "list-item text-muted", text: "No nodes connected yet. You can add them later too." }));
      st.nodes.forEach((n) => list.append(h("div", { class: "list-item" }, h("span", { class: "dot is-ok", "aria-hidden": "true" }), h("span", { class: "grow", text: n.name }), h("span", { class: "text-sm text-subtle text-mono", text: n.host }))));
    };
    draw();
    const code = B.input({ placeholder: "vpp_", mono: true, spellcheck: "false", autocomplete: "off" });
    let pin = "";
    const pinSlot = h("div");
    const pair = async (body) => {
      clear(err);
      const r = await api("POST", "api/setup/pair", Object.assign({ pin }, body));
      if (r.status === 409 && r.data && r.data.code === "UNTRUSTED_CERT") {
        pin = r.data.fingerprint || "";
        clear(pinSlot).append(B.callout("warn", "Check this fingerprint", h("div", { class: "stack stack-sm" }, h("p", { text: r.data.error }), h("p", { class: "mono-wrap", text: pin.replace(/(..)(?=.)/g, "$1:") }), h("p", { class: "text-sm text-muted", text: "Press Connect again to pin it." }))));
        return;
      }
      if (!r.ok) { B.showError(err, r.error); return; }
      pin = "";
      clear(pinSlot);
      code.value = "";
      await refresh();
      draw();
      B.toast("Connected " + r.data.node.name);
      if (local) local.remove();
    };
    const local = st.local_node ? h("div", { class: "card surface-card card-glow stack" },
      h("h2", { class: "heading-md", text: "This server runs a VPN node" }),
      h("p", { class: "text-muted", text: "Connect it with one click. A pairing code was made when the panel was installed." }),
      h("div", { class: "cluster" }, B.button("Connect this node", { icon: "plus", onClick: () => pair({ local: true }) }))) : null;
    screen({
      title: ["Connect your", "VPN nodes."],
      lead: "Each node gives the panel a key that only works for its admin tools. Nodes stay in control and can revoke it.",
      body: [local,
        h("div", { class: "card surface-card stack" },
          h("p", { class: "text-muted", text: "On a node, run this command or open Control Panel in its admin page, then paste the code." }),
          B.codeBlock("sudo veyl panel pair", "On the node"),
          B.field("Pairing code", code), pinSlot, err,
          h("div", { class: "cluster" }, B.button("Connect", { variant: "secondary", icon: "plus", onClick: () => pair({ code: code.value.trim() }) }))),
        h("section", { class: "card card-flush surface-panel" }, h("div", { class: "card-head" }, h("h2", { text: "Connected" })), list)],
      actions: [B.button("Finish setup", { size: "lg", trailing: "arrowRight", onClick: async () => {
        const r = await api("POST", "api/setup/finish", {});
        if (!r.ok) { B.showError(err, r.error); return; }
        doneURL = r.data.url;
        go("done");
      } })]
    });
  }

  let doneURL = "./";

  function done() {
    screen({
      title: ["Veyl Control", "is ready."],
      lead: "Setup is locked now. Sign in with your username, password and authenticator code.",
      body: [h("div", { class: "card surface-card card-glow-bottom stack" },
        h("div", { class: "empty" }, B.mark(), h("p", { class: "empty-title", text: "Your fleet is watched every 30 seconds." })),
        B.callout("info", "Next", "Set up alerts so you hear about problems first, and invite your team."))],
      actions: [B.button("Open Veyl Control", { size: "lg", trailing: "arrowRight", href: doneURL })]
    });
  }

  async function start() {
    token = location.hash.replace(/^#/, "");
    if (token) history.replaceState(null, "", location.pathname);
    if (!token) { linkProblem(); return; }
    const s = await B.api("POST", "api/setup/session", undefined, { headers: { "X-Setup-Token": token } });
    if (!s.ok) { linkProblem(s.status === 404 ? "Setup is already finished. Sign in instead." : s.error); return; }
    csrf = s.data.csrf;
    const r = await refresh();
    if (!r.ok) { linkProblem(r.error); return; }
    if (st.owner) go("nodes");
    else if (st.https && st.cert) go("owner");
    else if (st.site.domain && st.cert) go("certificate");
    else go("domain");
  }

  start();
})();
