"use strict";

const V = (() => {
  const NS = "http://www.w3.org/2000/svg";

  const PATHS = {
    check: "M20 6 9 17l-5-5",
    x: "M18 6 6 18M6 6l12 12",
    arrowR: "M5 12h14M13 6l6 6-6 6",
    arrowL: "M19 12H5M11 18l-6-6 6-6",
    copy: "M9 9h11v11H9zM5 15V5a2 2 0 0 1 2-2h10",
    eye: "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z",
    eyeOff: "M3 3l18 18M10.6 5.1A9.7 9.7 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4M6.6 6.6C3.8 8.3 2 12 2 12s3.5 7 10 7c1.8 0 3.4-.5 4.8-1.3M9.9 9.9a3 3 0 0 0 4.2 4.2",
    refresh: "M21 12a9 9 0 1 1-3-6.7L21 8M21 3v5h-5",
    globe: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM3 12h18M12 3c2.5 2.7 3.8 5.7 3.8 9s-1.3 6.3-3.8 9c-2.5-2.7-3.8-5.7-3.8-9S9.5 5.7 12 3z",
    sparkle: "M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8zM19 16l.8 2.2L22 19l-2.2.8L19 22l-.8-2.2L16 19l2.2-.8z",
    shield: "M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z",
    shieldCheck: "M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6zM8.5 12l2.5 2.5 4.5-5",
    lock: "M6 11h12v10H6zM8 11V7a4 4 0 0 1 8 0v4",
    upload: "M12 16V4M7 9l5-5 5 5M4 20h16",
    download: "M12 4v12M7 11l5 5 5-5M4 20h16",
    user: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0",
    users: "M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM2 21a7 7 0 0 1 14 0M16 3.5a4 4 0 0 1 0 7.5M22 21a7 7 0 0 0-4-6.3",
    key: "M10.8 12.2 21 2M17 6l3 3M14 9l2 2M8 21a4 4 0 1 0 0-8 4 4 0 0 0 0 8z",
    ticket: "M3 8a2 2 0 0 0 2-2h14a2 2 0 0 0 2 2v8a2 2 0 0 0-2 2H5a2 2 0 0 0-2-2zM14 6v2M14 11v2M14 16v2",
    sliders: "M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1M15 4v4M9 10v4M17 16v4",
    grid: "M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z",
    server: "M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01",
    alert: "M12 3 2 20h20zM12 10v4M12 17h.01",
    info: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 11v6M12 7.5h.01",
    trash: "M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3",
    plus: "M12 5v14M5 12h14",
    logout: "M15 4h4v16h-4M10 8l-4 4 4 4M6 12h11",
    wand: "M4 20 15 9M14 4v2M19 9h2M17.5 5.5l1.5-1.5M18 13l1 1M10 5 9 4",
    phone: "M7 2h10v20H7zM11 18h2",
    archive: "M3 4h18v5H3zM5 9v11h14V9M10 13h4",
    ban: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM5.6 5.6l12.8 12.8",
    dice: "M4 4h16v16H4zM8.5 8.5h.01M15.5 8.5h.01M12 12h.01M8.5 15.5h.01M15.5 15.5h.01",
    search: "M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3",
    pause: "M8 5v14M16 5v14",
    play: "M7 4l13 8-13 8z",
    clock: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 7v5l3 2",
    cpu: "M7 7h10v10H7zM10 2v3M14 2v3M10 19v3M14 19v3M2 10h3M2 14h3M19 10h3M19 14h3",
    zap: "M13 2 4 14h7l-1 8 9-12h-7z",
    edit: "M4 20h4L19 9l-4-4L4 16zM13.5 6.5l4 4"
  };

  function icon(name) {
    const s = document.createElementNS(NS, "svg");
    s.setAttribute("viewBox", "0 0 24 24");
    s.setAttribute("fill", "none");
    s.setAttribute("stroke", "currentColor");
    s.setAttribute("stroke-width", "2");
    s.setAttribute("stroke-linecap", "round");
    s.setAttribute("stroke-linejoin", "round");
    s.setAttribute("aria-hidden", "true");
    const p = document.createElementNS(NS, "path");
    p.setAttribute("d", PATHS[name] || PATHS.info);
    s.append(p);
    return s;
  }

  function logo() {
    const s = document.createElementNS(NS, "svg");
    s.setAttribute("viewBox", "0 0 26 26");
    s.setAttribute("aria-hidden", "true");
    const cells = [[0, 0, "on"], [1, 0, "off"], [2, 0, "on"], [0, 1, "mid"], [1, 1, "off"], [2, 1, "mid"], [0, 2, "off"], [1, 2, "on"], [2, 2, "off"]];
    for (const [x, y, k] of cells) {
      const r = document.createElementNS(NS, "rect");
      r.setAttribute("x", String(x * 9));
      r.setAttribute("y", String(y * 9));
      r.setAttribute("width", "8");
      r.setAttribute("height", "8");
      r.setAttribute("rx", "1.6");
      r.setAttribute("class", "logo-" + k);
      s.append(r);
    }
    return s;
  }

  const PROPS = new Set(["value", "checked", "disabled", "selected", "hidden", "readOnly", "multiple"]);

  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const k of Object.keys(attrs)) {
        const v = attrs[k];
        if (v === undefined || v === null || v === false) continue;
        if (k === "class") el.className = v;
        else if (k === "text") el.textContent = v;
        else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
        else if (PROPS.has(k)) el[k] = v;
        else if (k !== "style") el.setAttribute(k, v === true ? "" : String(v));
      }
    }
    for (const c of kids.flat(3)) {
      if (c === undefined || c === null || c === false) continue;
      el.append(c instanceof Node ? c : String(c));
    }
    return el;
  }

  function clear(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
    return el;
  }

  const state = { csrf: "" };

  function friendly(status) {
    if (status === 0) return "Can't reach the server. Check your connection and try again.";
    if (status === 401) return "Please sign in again.";
    if (status === 403) return "That isn't allowed right now. Reload the page and try again.";
    if (status === 404) return "Not found.";
    if (status === 409) return "Something else is running. Try again in a moment.";
    if (status === 413) return "That was too large.";
    if (status === 429) return "Too many tries. Wait a minute and try again.";
    if (status >= 500) return "Something went wrong on the server.";
    return "That didn't work. Please try again.";
  }

  async function api(method, url, body, extra) {
    const headers = {};
    if (state.csrf) headers["X-CSRF-Token"] = state.csrf;
    let payload;
    if (body instanceof Blob) {
      payload = body;
      headers["Content-Type"] = "application/octet-stream";
    } else if (body !== undefined) {
      payload = JSON.stringify(body);
      headers["Content-Type"] = "application/json";
    }
    if (extra && extra.headers) Object.assign(headers, extra.headers);
    let res;
    try {
      res = await fetch(url, { method, headers, body: payload, credentials: "same-origin", cache: "no-store", redirect: "error" });
    } catch (e) {
      return { ok: false, status: 0, data: null, error: friendly(0) };
    }
    if (extra && extra.blob && res.ok) {
      const blob = await res.blob();
      const cd = res.headers.get("Content-Disposition") || "";
      const m = /filename="([^"]+)"/.exec(cd);
      return { ok: true, status: res.status, blob, filename: m ? m[1] : "download" };
    }
    let data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    return { ok: res.ok, status: res.status, data, error: (data && data.error) || friendly(res.status), code: data && data.code };
  }

  function stream(url, onStep, onDone) {
    let finished = false;
    const es = new EventSource(url, { withCredentials: true });
    es.addEventListener("step", (e) => {
      try { onStep(JSON.parse(e.data)); } catch (err) { }
    });
    es.addEventListener("done", (e) => {
      finished = true;
      es.close();
      let d = null;
      try { d = JSON.parse(e.data); } catch (err) { d = { ok: false, error: "Unexpected reply." }; }
      onDone(d);
    });
    es.onerror = () => {
      if (!finished && es.readyState === EventSource.CLOSED) {
        finished = true;
        onDone(null);
      }
    };
    return es;
  }

  let toastWrap;
  function toast(msg, kind) {
    if (!toastWrap) {
      toastWrap = h("div", { class: "toast-wrap", role: "status", "aria-live": "polite" });
      document.body.append(toastWrap);
    }
    const t = h("div", { class: "toast" + (kind === "err" ? " err" : "") }, icon(kind === "err" ? "alert" : "check"), h("span", { text: msg }));
    toastWrap.append(t);
    setTimeout(() => t.remove(), 3200);
  }

  async function copy(text, label) {
    let ok = false;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        ok = true;
      }
    } catch (e) { ok = false; }
    if (!ok) {
      const ta = h("textarea", { class: "sr", "aria-hidden": "true" });
      ta.value = text;
      document.body.append(ta);
      ta.select();
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      ta.remove();
    }
    toast(ok ? (label || "Copied") : "Couldn't copy. Select the text and copy it yourself.", ok ? "" : "err");
  }

  const ALPHA = "abcdefghjkmnpqrstuvwxyz23456789";
  function genPassword(groups) {
    const n = groups || 4;
    const out = [];
    const buf = new Uint32Array(n * 4);
    crypto.getRandomValues(buf);
    for (let g = 0; g < n; g++) {
      let s = "";
      for (let i = 0; i < 4; i++) s += ALPHA[buf[g * 4 + i] % ALPHA.length];
      out.push(s);
    }
    return out.join("-");
  }

  function strength(pw, min) {
    if (!pw) return { level: 0, text: "" };
    const len = [...pw].length;
    if (len < min) return { level: 1, text: "Too short. Use at least " + min + " characters." };
    let classes = 0;
    if (/[a-z]/.test(pw)) classes++;
    if (/[A-Z]/.test(pw)) classes++;
    if (/[0-9]/.test(pw)) classes++;
    if (/[^A-Za-z0-9]/.test(pw)) classes++;
    let level = 2;
    if (len >= 14 || classes >= 3) level = 3;
    if ((len >= 16 && classes >= 2) || (len >= 14 && classes >= 3) || len >= 22) level = 4;
    const text = ["", "", "Okay. Longer is stronger.", "Good.", "Strong."][level];
    return { level, text };
  }

  function passwordField(opts) {
    const input = h("input", { class: "input mono", type: "password", id: opts.id, autocomplete: opts.autocomplete || "new-password", spellcheck: "false", autocapitalize: "off", placeholder: opts.placeholder || "", minlength: String(opts.min) });
    const meter = h("div", { class: "meter", "data-level": "0", "aria-hidden": "true" }, h("i"), h("i"), h("i"), h("i"));
    const hint = h("p", { class: "hint", text: opts.hint || "" });
    const eyeBtn = h("button", { class: "inline-btn", type: "button", "aria-label": "Show password", text: "Show" });
    eyeBtn.addEventListener("click", () => {
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      eyeBtn.textContent = show ? "Hide" : "Show";
    });
    const update = () => {
      const s = strength(input.value, opts.min);
      meter.setAttribute("data-level", String(s.level));
      hint.textContent = input.value ? s.text : (opts.hint || "");
      input.classList.remove("invalid");
      if (opts.onInput) opts.onInput(input.value);
    };
    input.addEventListener("input", update);
    const gen = h("button", { class: "btn btn-ghost btn-small", type: "button" }, icon("wand"), "Suggest a strong one");
    const cp = h("button", { class: "btn btn-quiet btn-small hidden", type: "button" }, icon("copy"), "Copy");
    cp.addEventListener("click", () => copy(input.value, "Password copied"));
    gen.addEventListener("click", () => {
      input.value = genPassword(4);
      input.type = "text";
      eyeBtn.textContent = "Hide";
      cp.classList.remove("hidden");
      update();
      input.focus();
    });
    const field = h("div", { class: "field" },
      h("label", { class: "label", for: opts.id, text: opts.label }),
      h("div", { class: "input-row" }, input, eyeBtn),
      opts.meter === false ? null : meter,
      hint,
      opts.generate === false ? null : h("div", { class: "row-wrap mt-s" }, gen, cp)
    );
    return { field, input, valid: () => [...input.value].length >= opts.min };
  }

  function sw(on, label, disabled) {
    const b = h("button", { class: "switch", type: "button", role: "switch", "aria-checked": on ? "true" : "false", "aria-label": label, disabled: !!disabled });
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      if (b.disabled) return;
      b.setAttribute("aria-checked", b.getAttribute("aria-checked") === "true" ? "false" : "true");
      b.dispatchEvent(new Event("change"));
    });
    b.on = () => b.getAttribute("aria-checked") === "true";
    b.set = (v) => b.setAttribute("aria-checked", v ? "true" : "false");
    return b;
  }

  function toggleRow(title, desc, on, opts) {
    const o = opts || {};
    const s = sw(on, title, o.disabled);
    const row = h("div", { class: "toggle-row" + (o.disabled ? " disabled" : "") },
      o.icon ? h("div", { class: "ic-s" }, icon(o.icon)) : null,
      h("div", { class: "txt" }, h("div", { class: "t", text: title }), desc ? h("div", { class: "d", text: desc }) : null),
      s
    );
    row.addEventListener("click", () => { if (!s.disabled) s.click(); });
    if (o.onChange) s.addEventListener("change", () => o.onChange(s.on()));
    return { row, sw: s };
  }

  function choice(opts) {
    const b = h("button", { class: "choice", type: "button", role: "radio", "aria-checked": opts.on ? "true" : "false" },
      opts.icon ? h("div", { class: "ic" }, icon(opts.icon)) : null,
      h("div", { class: "grow" }, h("div", { class: "t" }, opts.title, opts.badge ? h("span", { class: "badge badge-green", text: opts.badge }) : null), h("div", { class: "d", text: opts.desc || "" })),
      h("span", { class: "radio", "aria-hidden": "true" })
    );
    if (opts.onClick) b.addEventListener("click", opts.onClick);
    return b;
  }

  function radioGroup(container, buttons, onPick) {
    container.setAttribute("role", "radiogroup");
    buttons.forEach((b) => {
      b.addEventListener("click", () => {
        buttons.forEach((x) => x.setAttribute("aria-checked", x === b ? "true" : "false"));
        onPick(b);
      });
    });
  }

  function callout(kind, title, text, ic) {
    const name = ic || (kind === "ok" ? "check" : kind === "warn" ? "alert" : kind === "err" ? "alert" : "info");
    return h("div", { class: "callout " + (kind || ""), role: kind === "err" ? "alert" : null }, icon(name), h("div", { class: "grow" }, title ? h("b", { text: title }) : null, text ? h("span", { text }) : null));
  }

  function spinner() {
    return h("span", { class: "spinner", "aria-hidden": "true" });
  }

  async function busy(btn, fn) {
    if (btn.disabled) return;
    const kids = Array.from(btn.childNodes);
    btn.disabled = true;
    btn.setAttribute("aria-busy", "true");
    clear(btn).append(spinner(), h("span", { text: btn.dataset.busy || "Working…" }));
    try {
      return await fn();
    } finally {
      clear(btn).append(...kids);
      btn.disabled = false;
      btn.removeAttribute("aria-busy");
    }
  }

  const STEP_NAMES = {
    users: "Creating service users",
    dirs: "Preparing folders",
    pki: "Securing certificates",
    sysctl: "Tuning the network",
    privacy: "Switching off system logs",
    nftables: "Setting up the firewall",
    firewall: "Setting up the firewall",
    dnsif: "Preparing private DNS",
    unbound: "Starting the private DNS resolver",
    blocklists: "Downloading blocklists",
    openvpn: "Starting the VPN",
    "openvpn-udp": "Starting the VPN",
    "openvpn-tcp": "Starting stealth mode",
    caddy: "Setting up HTTPS",
    tls: "Getting a certificate",
    certificate: "Getting a certificate",
    "unattended-upgrades": "Turning on security updates",
    updates: "Turning on security updates",
    "veyl-dns": "Starting content blocking",
    verify: "Checking everything works",
    ports: "Checking the VPN is reachable",
    health: "Checking the secure link",
    restart: "Restarting services",
    "dns-update": "Updating blocklists"
  };

  function stepName(s) {
    if (STEP_NAMES[s]) return STEP_NAMES[s];
    const t = String(s || "Working").replace(/[-_.]+/g, " ").trim();
    return t.charAt(0).toUpperCase() + t.slice(1);
  }

  function progressList() {
    const root = h("div", { class: "progress", "aria-live": "polite" });
    const rows = new Map();
    function mark(st, status) {
      clear(st);
      if (status === "ok") st.append(icon("check"));
      else if (status === "fail") st.append(icon("x"));
      else if (status === "skip") st.append(icon("arrowR"));
      else st.append(spinner());
    }
    return {
      el: root,
      step(ev) {
        const key = ev.step || "step";
        let r = rows.get(key);
        if (!r) {
          const st = h("div", { class: "st" });
          const d = h("div", { class: "d" });
          const el = h("div", { class: "pstep" }, st, h("div", { class: "grow" }, h("div", { class: "t", text: stepName(key) }), d));
          r = { el, st, d };
          rows.set(key, r);
          root.append(el);
        }
        r.el.className = "pstep " + (ev.status || "run");
        mark(r.st, ev.status);
        r.d.textContent = ev.detail || "";
      },
      settle(ok) {
        rows.forEach((r) => {
          if (r.el.classList.contains("run")) {
            r.el.className = "pstep " + (ok ? "ok" : "fail");
            mark(r.st, ok ? "ok" : "fail");
          }
        });
      },
      reset() { rows.clear(); clear(root); }
    };
  }

  function groupNumber(n) {
    return String(n || "").replace(/(\d{4})(?=\d)/g, "$1 ");
  }

  function date(unix) {
    if (!unix) return "";
    const d = new Date(unix * 1000);
    return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" });
  }

  function save(blob, name) {
    const url = URL.createObjectURL(blob);
    const a = h("a", { href: url, download: name, class: "sr" });
    document.body.append(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
  }

  return { h, icon, logo, clear, api, stream, toast, copy, genPassword, strength, passwordField, sw, toggleRow, choice, radioGroup, callout, spinner, busy, progressList, stepName, groupNumber, date, save, state };
})();
