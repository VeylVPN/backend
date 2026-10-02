"use strict";

const Brand = (() => {
  const NS = "http://www.w3.org/2000/svg";

  const STROKE = {
    alert: ["M12 3.5 2.5 20h19L12 3.5Z", "M12 10v4.5", "M12 17.5h.01"],
    arrowRight: ["M5 12h14", "m13 6 6 6-6 6"],
    arrowLeft: ["M19 12H5", "m11 18-6-6 6-6"],
    arrowUpRight: ["M7 17 17 7", "M8 7h9v9"],
    book: ["M4 5.5A2.5 2.5 0 0 1 6.5 3H20v15H6.5A2.5 2.5 0 0 0 4 20.5v-15Z", "M4 20.5A2.5 2.5 0 0 0 6.5 23H20v-5"],
    check: ["m5 12.5 4.5 4.5L19 7.5"],
    chevronDown: ["m6 9 6 6 6-6"],
    chevronLeft: ["m15 6-6 6 6 6"],
    chevronRight: ["m9 6 6 6-6 6"],
    copy: ["M10.5 8h7A2.5 2.5 0 0 1 20 10.5v7a2.5 2.5 0 0 1-2.5 2.5h-7A2.5 2.5 0 0 1 8 17.5v-7A2.5 2.5 0 0 1 10.5 8Z", "M16 8V6.5A2.5 2.5 0 0 0 13.5 4h-7A2.5 2.5 0 0 0 4 6.5v7A2.5 2.5 0 0 0 6.5 16H8"],
    download: ["M12 4v11", "m7 10 5 5 5-5", "M5 20h14"],
    upload: ["M12 20V9", "m7 14 5-5 5 5", "M5 4h14"],
    eye: ["M3 12s3.5-7 9-7 9 7 9 7-3.5 7-9 7-9-7-9-7Z", "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z"],
    eyeOff: ["M3 3l18 18", "M10.6 5.1A10.5 10.5 0 0 1 12 5c5.5 0 9 7 9 7a16.6 16.6 0 0 1-3 3.9", "M6.6 6.6C4.2 8.2 3 12 3 12s3.5 7 9 7a9.6 9.6 0 0 0 4.4-1.1", "M9.9 9.9a3 3 0 0 0 4.2 4.2"],
    key: ["M8 19a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z", "m10.8 12.2 8.7-8.7", "m16 7 2.5 2.5", "m18.5 4.5 2 2"],
    laptop: ["M6 5h12a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2Z", "M2 19h20"],
    lock: ["M7 10.5h10a2.5 2.5 0 0 1 2.5 2.5v5a2.5 2.5 0 0 1-2.5 2.5H7A2.5 2.5 0 0 1 4.5 18v-5A2.5 2.5 0 0 1 7 10.5Z", "M8 10.5V7.5a4 4 0 0 1 8 0v3", "M12 14.5v2"],
    menu: ["M4 8h16", "M4 16h16"],
    phone: ["M9.5 2.5h5A2.5 2.5 0 0 1 17 5v14a2.5 2.5 0 0 1-2.5 2.5h-5A2.5 2.5 0 0 1 7 19V5a2.5 2.5 0 0 1 2.5-2.5Z", "M11 18.5h2"],
    plus: ["M12 5v14", "M5 12h14"],
    refresh: ["M20 11a8 8 0 0 0-14.8-4", "M4 4v4h4", "M4 13a8 8 0 0 0 14.8 4", "M20 20v-4h-4"],
    server: ["M5 4h14a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2Z", "M5 13h14a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2Z", "M7 7.5h.01", "M7 16.5h.01", "M11 7.5h6", "M11 16.5h6"],
    shield: ["M12 3 4.5 6v5.5c0 4.6 3.1 8.3 7.5 9.5 4.4-1.2 7.5-4.9 7.5-9.5V6L12 3Z", "m9 12 2 2 4-4"],
    shieldPlain: ["M12 3 4.5 6v5.5c0 4.6 3.1 8.3 7.5 9.5 4.4-1.2 7.5-4.9 7.5-9.5V6L12 3Z"],
    sparkPixel: ["M5 4h2a1 1 0 0 1 1 1v2a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1Z", "M11 10h2a1 1 0 0 1 1 1v2a1 1 0 0 1-1 1h-2a1 1 0 0 1-1-1v-2a1 1 0 0 1 1-1Z", "M17 4h2a1 1 0 0 1 1 1v2a1 1 0 0 1-1 1h-2a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1Z", "M17 16h2a1 1 0 0 1 1 1v2a1 1 0 0 1-1 1h-2a1 1 0 0 1-1-1v-2a1 1 0 0 1 1-1Z", "M5 16h2a1 1 0 0 1 1 1v2a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-2a1 1 0 0 1 1-1Z"],
    terminal: ["M6 4h12a3 3 0 0 1 3 3v10a3 3 0 0 1-3 3H6a3 3 0 0 1-3-3V7a3 3 0 0 1 3-3Z", "m7 9 3 3-3 3", "M13 15h4"],
    x: ["M6 6l12 12", "M18 6 6 18"],
    globe: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z", "M3.5 9h17", "M3.5 15h17", "M12 3c2.3 2.5 3.5 5.5 3.5 9s-1.2 6.5-3.5 9c-2.3-2.5-3.5-5.5-3.5-9S9.7 5.5 12 3Z"],
    user: ["M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z", "M4.5 20.5a7.5 7.5 0 0 1 15 0"],
    users: ["M9 11a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z", "M2.5 20a6.5 6.5 0 0 1 13 0", "M15.5 4.3a3.5 3.5 0 0 1 0 6.4", "M21.5 20a6.5 6.5 0 0 0-3.5-5.8"],
    ticket: ["M4 6.5h16v3a2.5 2.5 0 0 0 0 5v3H4v-3a2.5 2.5 0 0 0 0-5v-3Z", "M14 6.5v2", "M14 11v2", "M14 15.5v2"],
    sliders: ["M4 7h9", "M17 7h3", "M4 17h3", "M11 17h9", "M15 5v4", "M9 15v4"],
    grid: ["M5 4h4a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1Z", "M15 4h4a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1h-4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1Z", "M5 14h4a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-4a1 1 0 0 1 1-1Z", "M15 14h4a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1h-4a1 1 0 0 1-1-1v-4a1 1 0 0 1 1-1Z"],
    archive: ["M4 4.5h16v4.5H4z", "M5.5 9v9.5A1.5 1.5 0 0 0 7 20h10a1.5 1.5 0 0 0 1.5-1.5V9", "M10 13h4"],
    trash: ["M4 7h16", "M10 11v6", "M14 11v6", "M6 7l1 12a1.5 1.5 0 0 0 1.5 1.4h7a1.5 1.5 0 0 0 1.5-1.4L18 7", "M9 7V4.5h6V7"],
    pause: ["M8.5 5v14", "M15.5 5v14"],
    play: ["M7 4.8v14.4a.8.8 0 0 0 1.2.7l11.3-7.2a.8.8 0 0 0 0-1.4L8.2 4.1a.8.8 0 0 0-1.2.7Z"],
    clock: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z", "M12 7v5l3 2"],
    logout: ["M15 4h3.5A1.5 1.5 0 0 1 20 5.5v13a1.5 1.5 0 0 1-1.5 1.5H15", "m10 8-4 4 4 4", "M6 12h11"],
    edit: ["M4 20h4L19 9a2.8 2.8 0 0 0-4-4L4 16v4Z", "m13.5 6.5 4 4"],
    search: ["M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14Z", "m20 20-4-4"],
    info: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z", "M12 11v5.5", "M12 7.5h.01"],
    wand: ["m4 20 11-11", "M14 4v2", "M19 9h2", "m17.5 5.5 1.5-1.5", "m18 13 1 1", "m10 5-1-1"],
    ban: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z", "m5.6 5.6 12.8 12.8"],
    dice: ["M6.5 4h11A2.5 2.5 0 0 1 20 6.5v11a2.5 2.5 0 0 1-2.5 2.5h-11A2.5 2.5 0 0 1 4 17.5v-11A2.5 2.5 0 0 1 6.5 4Z", "M8.5 8.5h.01", "M15.5 8.5h.01", "M12 12h.01", "M8.5 15.5h.01", "M15.5 15.5h.01"],
    zap: ["M13 2.5 4.5 13.5h7l-1 8 8.5-11h-7l1-8Z"],
    panel: ["M5 4h14a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2Z", "M9 4v16", "M13 9h4", "M13 13h4"],
    activity: ["M3 12h4l2.5-6 5 12 2.5-6h4"]
  };

  const FILL = {
    github: "M12 1.8a10.2 10.2 0 0 0-3.2 19.9c.5.1.7-.2.7-.5v-1.8c-2.9.6-3.5-1.2-3.5-1.2-.5-1.2-1.1-1.5-1.1-1.5-.9-.6.1-.6.1-.6 1 .1 1.6 1 1.6 1 .9 1.6 2.4 1.1 3 .9.1-.7.4-1.1.6-1.4-2.3-.3-4.7-1.1-4.7-5 0-1.1.4-2 1-2.7-.1-.3-.4-1.3.1-2.7 0 0 .9-.3 2.8 1a9.6 9.6 0 0 1 5.1 0c1.9-1.3 2.8-1 2.8-1 .6 1.4.2 2.4.1 2.7.6.7 1 1.6 1 2.7 0 3.9-2.4 4.7-4.7 5 .4.3.7.9.7 1.9v2.8c0 .3.2.6.7.5A10.2 10.2 0 0 0 12 1.8Z",
    windows: "M3 5.4 10.4 4.4v7H3V5.4Zm0 13.2 7.4 1v-7H3v6Zm8.4 1.1L21 21v-8.4h-9.6v7.1Zm0-15.4v7.1H21V3l-9.6 1.3Z",
    linux: "M12 2c-2.1 0-3.6 1.7-3.6 4.4 0 1.4.2 2.4-.6 3.7-.9 1.5-2.6 3.6-2.6 6.2 0 .7.1 1.3.4 1.8-.6.3-1.3.7-1.3 1.4 0 1 1.6 1.2 3 1.6 1.2.3 1.8.9 2.9.9 1 0 1.5-.6 2.1-.8h1.4c.6.2 1.1.8 2.1.8 1.1 0 1.7-.6 2.9-.9 1.4-.4 3-.6 3-1.6 0-.7-.7-1.1-1.3-1.4.3-.5.4-1.1.4-1.8 0-2.6-1.7-4.7-2.6-6.2-.8-1.3-.6-2.3-.6-3.7C15.6 3.7 14.1 2 12 2Zm-1.6 4.2c.5 0 .8.6.8 1.2s-.3 1.1-.8 1.1-.8-.5-.8-1.1.3-1.2.8-1.2Zm3.2 0c.5 0 .8.6.8 1.2s-.3 1.1-.8 1.1-.8-.5-.8-1.1.3-1.2.8-1.2ZM12 9.6c.9 0 2.2.6 2.2 1s-1.3 1.2-2.2 1.2-2.2-.8-2.2-1.2 1.3-1 2.2-1Z"
  };

  function svg(tag, attrs) {
    const el = document.createElementNS(NS, tag);
    for (const k of Object.keys(attrs || {})) el.setAttribute(k, String(attrs[k]));
    return el;
  }

  function icon(name, extra) {
    const s = svg("svg", { viewBox: "0 0 24 24", class: "icon" + (extra ? " " + extra : ""), "aria-hidden": "true", focusable: "false" });
    if (FILL[name]) {
      s.setAttribute("fill", "currentColor");
      s.append(svg("path", { d: FILL[name] }));
      return s;
    }
    s.setAttribute("fill", "none");
    s.setAttribute("stroke", "currentColor");
    s.setAttribute("stroke-width", "1.75");
    s.setAttribute("stroke-linecap", "round");
    s.setAttribute("stroke-linejoin", "round");
    for (const d of STROKE[name] || STROKE.info) s.append(svg("path", { d }));
    return s;
  }

  let gradients = 0;
  function mark(tone, extra) {
    const id = "brand-mark-" + (++gradients);
    const s = svg("svg", { viewBox: "0 0 7 4", fill: "none", class: "brand-mark" + (extra ? " " + extra : ""), "aria-hidden": "true", focusable: "false" });
    const defs = svg("defs");
    const g = svg("linearGradient", { id, x1: "0", y1: "0", x2: "7", y2: "4", gradientUnits: "userSpaceOnUse" });
    [["0", "#d4ceff"], ["0.55", "#8f7fff"], ["1", "#526bff"]].forEach(([o, c]) => g.append(svg("stop", { offset: o, "stop-color": c })));
    defs.append(g);
    s.append(defs);
    [0, 1, 2, 3, 2, 1, 0].forEach((row, col) => s.append(svg("rect", { x: col + 0.11, y: row + 0.11, width: "0.78", height: "0.78", rx: "0.2", fill: tone === "white" ? "#ffffff" : "url(#" + id + ")" })));
    return s;
  }

  const PROPS = new Set(["value", "checked", "disabled", "selected", "hidden", "readOnly", "multiple", "open"]);

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

  function logo(name) {
    const label = h("span", { class: "brand-logo-name" });
    if (name) label.textContent = name;
    else label.append("Veyl", h("span", { text: "VPN" }));
    return h("span", { class: "brand-logo" }, h("span", { class: "brand-logo-tile" }, mark()), label);
  }

  function watchNav(nav) {
    const sync = () => nav.classList.toggle("is-scrolled", window.scrollY > 8);
    sync();
    window.addEventListener("scroll", sync, { passive: true });
  }

  const state = { csrf: "", platform: "linux", stealthPort: 443 };

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
      toastWrap = h("div", { class: "toasts", role: "status", "aria-live": "polite" });
      document.body.append(toastWrap);
    }
    const err = kind === "err" || kind === "error";
    const t = h("div", { class: "toast" + (err ? " is-error" : "") }, icon(err ? "alert" : "check"), h("span", { text: msg }));
    toastWrap.append(t);
    setTimeout(() => t.remove(), 3200);
  }

  async function writeClipboard(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (e) { }
    const ta = h("textarea", { class: "sr-only", "aria-hidden": "true" });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    ta.remove();
    return ok;
  }

  async function copy(text, label) {
    const ok = await writeClipboard(text);
    toast(ok ? (label || "Copied") : "Couldn't copy. Select the text and copy it yourself.", ok ? "" : "err");
    return ok;
  }

  function copyButton(text, opts) {
    const o = opts || {};
    const label = h("span", { class: o.labelClass || "", text: "Copy", "aria-live": "polite" });
    const ic = h("span", { class: "row" }, icon("copy"));
    const b = h("button", { type: "button", class: o.class || "copy-btn", "aria-label": o.aria || "Copy" }, ic, label);
    let timer = 0;
    b.addEventListener("click", async () => {
      const value = typeof text === "function" ? text() : text;
      const ok = await writeClipboard(value);
      clear(ic).append(icon(ok ? "check" : "alert"));
      label.textContent = ok ? "Copied" : "Copy failed";
      b.classList.toggle("is-copied", ok);
      if (o.toast) toast(ok ? o.toast : "Couldn't copy. Select the text and copy it yourself.", ok ? "" : "err");
      clearTimeout(timer);
      timer = setTimeout(() => {
        clear(ic).append(icon("copy"));
        label.textContent = "Copy";
        b.classList.remove("is-copied");
      }, 1800);
    });
    return b;
  }

  function codeBlock(code, label, opts) {
    const o = opts || {};
    const prompt = o.prompt !== false;
    const c = h("code");
    const lines = String(code).split("\n");
    lines.forEach((line, i) => {
      if (prompt && line && !line.startsWith("#")) c.append(h("span", { class: "code-prompt", "aria-hidden": "true", text: o.promptText || "$ " }));
      c.append(h("span", { class: line.startsWith("#") ? "code-comment" : "", text: line }));
      if (i < lines.length - 1) c.append("\n");
    });
    return h("figure", { class: "code-block" },
      h("figcaption", { class: "code-block-head" }, h("span", { class: "code-block-label", text: label || "Shell" }), copyButton(code, { aria: "Copy " + (label || "shell") + " code" })),
      h("pre", null, c)
    );
  }

  function command(text, opts) {
    const o = opts || {};
    return h("div", { class: "command" },
      h("span", { class: "command-icon", "aria-hidden": "true" }, icon(o.icon || "server")),
      h("code", { class: "command-text" }, o.prompt === false ? null : h("span", { class: "code-prompt", "aria-hidden": "true", text: "$ " }), text),
      copyButton(text, { class: "command-copy", labelClass: "command-copy-label", aria: o.aria || "Copy", toast: o.toast })
    );
  }

  function secret(value, display, opts) {
    const o = opts || {};
    return h("div", { class: "secret" },
      h("div", { class: "secret-value" + (o.small ? " is-small" : ""), text: display || value }),
      copyButton(value, { class: "btn btn-secondary btn-sm", aria: o.aria || "Copy", toast: o.toast })
    );
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

  let ids = 0;
  function uid(prefix) {
    ids += 1;
    return (prefix || "f") + "-" + ids;
  }

  function field(label, input, hint) {
    if (!input.id) input.id = uid("field");
    const hintEl = hint ? h("p", { class: "field-hint", id: input.id + "-hint", text: hint }) : null;
    if (hintEl) input.setAttribute("aria-describedby", hintEl.id);
    return h("div", { class: "field" }, h("label", { class: "field-label", for: input.id, text: label }), input, hintEl);
  }

  function input(attrs) {
    const a = Object.assign({ type: "text" }, attrs || {});
    a.class = "input" + (a.mono ? " input-mono" : "") + (a.class ? " " + a.class : "");
    delete a.mono;
    return h("input", a);
  }

  function select(options, value) {
    const s = h("select", { class: "select" });
    options.forEach(([v, t]) => s.append(h("option", { value: String(v), text: t, selected: String(v) === String(value) })));
    return s;
  }

  function passwordField(opts) {
    const id = opts.id || uid("pw");
    const el = h("input", { class: "input input-mono", type: "password", id, autocomplete: opts.autocomplete || "new-password", spellcheck: "false", autocapitalize: "off", placeholder: opts.placeholder || "", minlength: String(opts.min) });
    const meter = h("div", { class: "meter", "data-level": "0", "aria-hidden": "true" }, h("i"), h("i"), h("i"), h("i"));
    const hint = h("p", { class: "field-hint", id: id + "-hint", text: opts.hint || "" });
    el.setAttribute("aria-describedby", hint.id);
    const eye = h("button", { class: "input-group-action", type: "button", "aria-label": "Show password", "aria-pressed": "false", text: "Show" });
    eye.addEventListener("click", () => {
      const show = el.type === "password";
      el.type = show ? "text" : "password";
      eye.textContent = show ? "Hide" : "Show";
      eye.setAttribute("aria-pressed", show ? "true" : "false");
      eye.setAttribute("aria-label", show ? "Hide password" : "Show password");
    });
    const update = () => {
      const s = strength(el.value, opts.min);
      meter.setAttribute("data-level", String(s.level));
      hint.textContent = el.value ? s.text : (opts.hint || "");
      el.classList.remove("is-invalid");
      if (opts.onInput) opts.onInput(el.value);
    };
    el.addEventListener("input", update);
    const gen = h("button", { class: "btn btn-secondary btn-sm", type: "button" }, icon("wand"), "Suggest a strong one");
    const cp = copyButton(() => el.value, { class: "btn btn-ghost btn-sm", aria: "Copy password", toast: "Password copied" });
    cp.classList.add("is-hidden");
    gen.addEventListener("click", () => {
      el.value = genPassword(4);
      el.type = "text";
      eye.textContent = "Hide";
      eye.setAttribute("aria-pressed", "true");
      cp.classList.remove("is-hidden");
      update();
      el.focus();
    });
    const fieldEl = h("div", { class: "field" },
      h("label", { class: "field-label", for: id, text: opts.label }),
      h("div", { class: "input-group" }, el, eye),
      opts.meter === false ? null : meter,
      hint,
      opts.generate === false ? null : h("div", { class: "cluster cluster-tight" }, gen, cp)
    );
    return { field: fieldEl, input: el, valid: () => [...el.value].length >= opts.min };
  }

  function toggle(on, label, disabled) {
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

  function setting(title, desc, on, opts) {
    const o = opts || {};
    const s = toggle(on, title, o.disabled);
    const row = h("div", { class: "setting is-clickable" + (o.disabled ? " is-disabled" : "") },
      o.icon ? h("span", { class: "icon-tile" }, icon(o.icon)) : null,
      h("div", { class: "setting-text" }, h("div", { class: "setting-title", text: title }), desc ? h("div", { class: "setting-desc", text: desc }) : null),
      s
    );
    row.addEventListener("click", () => { if (!s.disabled) s.click(); });
    if (o.onChange) s.addEventListener("change", () => o.onChange(s.on()));
    return { row, toggle: s, on: () => s.on() };
  }

  function settingRow(title, desc, control) {
    return h("div", { class: "setting" }, h("div", { class: "setting-text" }, h("div", { class: "setting-title", text: title }), desc ? h("div", { class: "setting-desc", text: desc }) : null), control);
  }

  function option(opts) {
    const b = h("button", { class: "option", type: "button", role: "radio", "aria-checked": opts.on ? "true" : "false", disabled: !!opts.disabled },
      opts.icon ? h("span", { class: "icon-tile" }, icon(opts.icon)) : null,
      h("span", { class: "option-body" },
        h("span", { class: "option-title" }, h("span", { text: opts.title }), opts.badge ? h("span", { class: "badge badge-violet", text: opts.badge }) : null),
        h("span", { class: "option-desc", text: opts.desc || "" })
      ),
      h("span", { class: "option-radio", "aria-hidden": "true" })
    );
    if (opts.value !== undefined) b.setAttribute("data-value", opts.value);
    if (opts.onClick) b.addEventListener("click", opts.onClick);
    return b;
  }

  function radioGroup(container, buttons, onPick, label) {
    container.setAttribute("role", "radiogroup");
    if (label) container.setAttribute("aria-label", label);
    buttons.forEach((b) => {
      b.addEventListener("click", () => {
        buttons.forEach((x) => x.setAttribute("aria-checked", x === b ? "true" : "false"));
        onPick(b);
      });
    });
    container.addEventListener("keydown", (e) => {
      const keys = ["ArrowDown", "ArrowRight", "ArrowUp", "ArrowLeft"];
      if (!keys.includes(e.key)) return;
      const live = buttons.filter((b) => !b.disabled);
      const i = live.indexOf(document.activeElement);
      if (i < 0) return;
      e.preventDefault();
      const n = live[(i + (e.key === "ArrowDown" || e.key === "ArrowRight" ? 1 : live.length - 1)) % live.length];
      n.focus();
      n.click();
    });
  }

  function segmented(items, value, onPick, label) {
    const wrap = h("div", { class: "segmented" });
    const btns = items.map(([v, t, d]) => h("button", { class: "segment", type: "button", role: "radio", "aria-checked": v === value ? "true" : "false", "data-value": v }, h("span", { class: "segment-title", text: t }), d ? h("span", { class: "segment-desc", text: d }) : null));
    btns.forEach((b) => wrap.append(b));
    radioGroup(wrap, btns, (b) => onPick(b.getAttribute("data-value")), label);
    return wrap;
  }

  function stepper(value, min, max, label, onChange) {
    let v = value;
    const out = h("output", { text: String(v), "aria-live": "polite" });
    const minus = h("button", { type: "button", "aria-label": "Fewer " + label, text: "−" });
    const plus = h("button", { type: "button", "aria-label": "More " + label, text: "+" });
    const sync = () => { out.textContent = String(v); minus.disabled = v <= min; plus.disabled = v >= max; };
    minus.addEventListener("click", () => { v = Math.max(min, v - 1); sync(); if (onChange) onChange(v); });
    plus.addEventListener("click", () => { v = Math.min(max, v + 1); sync(); if (onChange) onChange(v); });
    sync();
    return { el: h("div", { class: "stepper" }, minus, out, plus), value: () => v };
  }

  const CALLOUT_ICON = { ok: "check", warn: "alert", danger: "alert", err: "alert", neutral: "info", info: "shieldPlain" };

  function callout(kind, title, text, ic) {
    const k = kind === "err" ? "danger" : (kind || "info");
    const cls = k === "info" ? "callout" : "callout callout-" + k;
    return h("div", { class: cls, role: k === "danger" ? "alert" : null },
      ic === false ? null : icon(ic || CALLOUT_ICON[k] || "info"),
      h("div", { class: "grow" }, title ? h("p", { class: "callout-title", text: title }) : null, text ? (text instanceof Node ? text : h("p", { text })) : null)
    );
  }

  function spinner() {
    return h("span", { class: "spinner", "aria-hidden": "true" });
  }

  async function busy(btn, fn) {
    if (btn.disabled) return;
    const kids = Array.from(btn.childNodes);
    btn.disabled = true;
    btn.setAttribute("aria-busy", "true");
    clear(btn).append(spinner(), h("span", { text: btn.dataset.busy || "Working" }));
    try {
      return await fn();
    } finally {
      clear(btn).append(...kids);
      btn.disabled = false;
      btn.removeAttribute("aria-busy");
    }
  }

  function button(label, opts) {
    const o = opts || {};
    const cls = "btn btn-" + (o.variant || "primary") + (o.size ? " btn-" + o.size : "") + (o.class ? " " + o.class : "");
    const b = h(o.href ? "a" : "button", { class: cls, type: o.href ? null : (o.type || "button"), href: o.href, target: o.external ? "_blank" : null, rel: o.external ? "noopener noreferrer" : null, "aria-label": o.aria },
      o.icon ? icon(o.icon) : null,
      label ? h("span", { text: label }) : null,
      o.trailing ? icon(o.trailing, o.trailing === "arrowRight" ? "icon-arrow" : "") : null,
      o.external ? h("span", { class: "sr-only", text: "(opens in a new tab)" }) : null
    );
    if (o.busy) b.dataset.busy = o.busy;
    if (o.onClick) b.addEventListener("click", () => (o.async === false ? o.onClick(b) : busy(b, () => o.onClick(b))));
    return b;
  }

  const STEP_NAMES = {
    settings: "Reading your settings",
    system: "Checking the system",
    users: "Creating service users",
    directories: "Preparing folders",
    dirs: "Preparing folders",
    fonts: "Fetching the interface font",
    certificates: "Creating keys and certificates",
    pki: "Creating keys and certificates",
    units: "Installing services",
    kernel: "Tuning the network",
    sysctl: "Tuning the network",
    privacy: "Switching off system logs",
    firewall: "Setting up the firewall",
    nftables: "Setting up the firewall",
    "dns-addresses": "Preparing private DNS",
    dnsif: "Preparing private DNS",
    resolver: "Starting the private DNS resolver",
    unbound: "Starting the private DNS resolver",
    blocklists: "Downloading blocklists",
    "stealth-off": "Turning stealth mode off",
    web: "Setting up HTTPS",
    caddy: "Setting up HTTPS",
    "vpn-udp": "Starting the VPN",
    "openvpn-udp": "Starting the VPN",
    openvpn: "Starting the VPN",
    "vpn-tcp": "Starting stealth mode",
    "openvpn-tcp": "Starting stealth mode",
    tls: "Getting a certificate",
    certificate: "Getting a certificate",
    https: "Getting a certificate",
    updates: "Turning on security updates",
    "unattended-upgrades": "Turning on security updates",
    "dns-filter": "Starting content blocking",
    "veyl-dns": "Starting content blocking",
    services: "Starting services",
    "verify-ports": "Checking the VPN is reachable",
    ports: "Checking the VPN is reachable",
    "verify-dns": "Checking private DNS",
    "verify-https": "Checking the secure link",
    verify: "Checking everything works",
    health: "Checking the secure link",
    restart: "Restarting services",
    "dns-update": "Updating blocklists",
    queue: "Waiting for the last task to finish",
    veyl: "Restarting Veyl"
  };

  function stepName(s) {
    if (state.platform === "windows" && (s === "vpn-tcp" || s === "openvpn-tcp")) return "Starting the TCP fallback";
    if (STEP_NAMES[s]) return STEP_NAMES[s];
    const t = String(s || "Working").replace(/[-_.]+/g, " ").trim();
    return t.charAt(0).toUpperCase() + t.slice(1);
  }

  function progress() {
    const root = h("div", { class: "progress", "aria-live": "polite" });
    const rows = new Map();
    function mark(st, status) {
      clear(st);
      if (status === "ok") st.append(icon("check"));
      else if (status === "fail") st.append(icon("x"));
      else if (status === "skip") st.append(icon("arrowRight"));
      else st.append(spinner());
    }
    return {
      el: root,
      step(ev) {
        const key = ev.step || "step";
        let r = rows.get(key);
        if (!r) {
          const st = h("span", { class: "progress-mark" });
          const d = h("div", { class: "progress-detail" });
          const el = h("div", { class: "progress-step" }, st, h("div", { class: "grow" }, h("div", { class: "progress-name", text: stepName(key) }), d));
          r = { el, st, d };
          rows.set(key, r);
          root.append(el);
        }
        const status = ev.status || "run";
        r.el.className = "progress-step is-" + status;
        mark(r.st, status);
        r.d.textContent = ev.detail || "";
      },
      settle(ok) {
        rows.forEach((r) => {
          if (r.el.classList.contains("is-run")) {
            r.el.className = "progress-step " + (ok ? "is-ok" : "is-fail");
            mark(r.st, ok ? "ok" : "fail");
          }
        });
      },
      reset() { rows.clear(); clear(root); }
    };
  }

  function progressBar() {
    const el = h("div", { class: "progress-bar", role: "presentation" }, h("i"));
    return { el, done: () => { el.className = "progress-bar is-done"; }, fail: () => { el.className = "progress-bar is-fail"; }, reset: () => { el.className = "progress-bar"; } };
  }

  function dialog(title, body, actions) {
    const d = h("dialog", { class: "dialog", "aria-label": title },
      h("h2", { class: "dialog-title", text: title }),
      h("div", { class: "dialog-body" }, ...body),
      actions && actions.length ? h("div", { class: "dialog-actions" }, ...actions) : null
    );
    document.body.append(d);
    d.addEventListener("close", () => d.remove());
    d.showModal();
    return d;
  }

  function confirm(title, text, okLabel, danger) {
    return new Promise((resolve) => {
      let ok = false;
      const yes = h("button", { class: "btn " + (danger ? "btn-danger" : "btn-primary"), type: "button" }, h("span", { text: okLabel }));
      const no = h("button", { class: "btn btn-secondary", type: "button", text: "Cancel" });
      const d = dialog(title, [h("p", { class: "text-muted", text })], [no, yes]);
      yes.addEventListener("click", () => { ok = true; d.close(); });
      no.addEventListener("click", () => d.close());
      d.addEventListener("close", () => resolve(ok));
      no.focus();
    });
  }

  function errorSlot() {
    return h("div", { class: "error-slot", "aria-live": "assertive" });
  }

  function showError(slot, msg, title) {
    clear(slot).append(callout("danger", title || "", msg));
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
    const a = h("a", { href: url, download: name, class: "sr-only" });
    document.body.append(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
  }

  function reducedMotion() {
    return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }

  function pixelWave(canvas, on) {
    const COLS = 26;
    const ROWS = 9;
    const OFF = [232, 115, 74];
    const ON = [84, 232, 112];
    let target = on ? 1 : 0;
    let k = target;
    let t = 0;
    let last = 0;
    let frame = 0;
    let visible = true;
    const mix = (a, b, x) => a.map((v, i) => Math.round(v + (b[i] - v) * x));
    function paint() {
      const ctx = canvas.getContext("2d");
      if (!ctx) return;
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      const w = canvas.clientWidth;
      const hh = canvas.clientHeight;
      if (canvas.width !== Math.round(w * dpr)) {
        canvas.width = Math.round(w * dpr);
        canvas.height = Math.round(hh * dpr);
      }
      if (!w) return;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, hh);
      const cell = Math.min(w / COLS, hh / ROWS);
      const left = (w - cell * COLS) / 2;
      const top = (hh - cell * ROWS) / 2;
      const gap = Math.max(1.5, cell * 0.12);
      const [r, g, b] = mix(OFF, ON, k);
      for (let c = 0; c < COLS; c++) {
        const down = 1.5 + (c / COLS) * (ROWS - 4);
        const live = ROWS / 2 - 0.5 + Math.sin(c * 0.42 + t * 1.6) * 1.1;
        const centre = down + (live - down) * k;
        const thick = 2.2 + (Math.sin(c * 0.55 - t * 1.1) * 0.9 + 0.9) * k;
        for (let row = 0; row < ROWS; row++) {
          const d = Math.abs(row + 0.5 - centre) - thick / 2;
          if (d > 0.6) continue;
          const a = d <= 0 ? 1 : 1 - d / 0.6;
          const shade = d > -0.5 ? 0.55 : 1;
          ctx.fillStyle = "rgba(" + r + "," + g + "," + b + "," + (a * shade).toFixed(3) + ")";
          const x = left + c * cell + gap / 2;
          const y = top + row * cell + gap / 2;
          ctx.beginPath();
          if (ctx.roundRect) ctx.roundRect(x, y, cell - gap, cell - gap, cell * 0.18);
          else ctx.rect(x, y, cell - gap, cell - gap);
          ctx.fill();
        }
      }
    }
    function tick(now) {
      frame = 0;
      if (!canvas.isConnected) return;
      const dt = last ? Math.min(0.05, (now - last) / 1000) : 0;
      last = now;
      t += dt;
      k += (target - k) * Math.min(1, dt * 3);
      paint();
      if (visible && !document.hidden) frame = requestAnimationFrame(tick);
    }
    function start() {
      if (reducedMotion()) {
        k = target;
        paint();
        return;
      }
      if (!frame) {
        last = 0;
        frame = requestAnimationFrame(tick);
      }
    }
    if ("IntersectionObserver" in window) {
      new IntersectionObserver((entries) => {
        visible = entries.some((e) => e.isIntersecting);
        if (visible) start();
      }).observe(canvas);
    }
    document.addEventListener("visibilitychange", () => { if (!document.hidden) start(); });
    requestAnimationFrame(() => { paint(); start(); });
    return {
      set(v) { target = v ? 1 : 0; start(); },
      stop() { cancelAnimationFrame(frame); frame = 0; }
    };
  }

  function platformOf(...sources) {
    for (const s of sources) {
      if (s && typeof s.platform === "string" && s.platform) return s.platform === "windows" ? "windows" : "linux";
    }
    return "linux";
  }

  function stealthPortOf(platform, ...sources) {
    for (const s of sources) {
      const n = s && Number(s.stealth_port);
      if (n && n > 0 && n < 65536) return n;
    }
    return platform === "windows" ? 993 : 443;
  }

  return {
    h, svg, icon, mark, logo, clear, watchNav, state, api, stream, toast, copy, copyButton, codeBlock, command, secret,
    genPassword, strength, field, input, select, passwordField, toggle, setting, settingRow, option, radioGroup, segmented, stepper,
    callout, spinner, busy, button, stepName, progress, progressBar, dialog, confirm, errorSlot, showError,
    groupNumber, date, save, reducedMotion, pixelWave, platformOf, stealthPortOf, uid
  };
})();
