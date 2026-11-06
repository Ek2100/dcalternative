// Verification page. Nothing is read from the device until the visitor presses
// "I agree". Raw values never leave the browser for the heavy signals: canvas,
// WebGL, audio and fonts are SHA-256'd here, and the server re-hashes
// everything with a per-server secret key before storing it.
(function () {
  "use strict";
  const app = document.getElementById("app");
  const cfg = {
    siteKey: app.dataset.siteKey,
    cdata: app.dataset.cdata,
    submitUrl: app.dataset.submitUrl,
    statusUrl: app.dataset.statusUrl,
  };
  const $ = (id) => document.getElementById(id);
  const show = (id) => {
    for (const s of ["step-consent", "step-check", "step-result"]) $(s).hidden = s !== id;
  };
  const result = (title, body) => {
    show("step-result");
    $("result-title").textContent = title;
    $("result-body").textContent = body;
  };

  // ── signals ────────────────────────────────────────────────────────────────
  async function sha256hex(str) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
  }

  function withTimeout(promise, ms, fallback) {
    return Promise.race([promise, new Promise((r) => setTimeout(() => r(fallback), ms))]);
  }

  function deviceToken() {
    // A random ID kept only on this site. It lets us recognise the same browser
    // without reading anything identifying.
    try {
      let t = localStorage.getItem("vdt");
      if (!t || !/^[A-Za-z0-9_-]{43}$/.test(t)) {
        const a = new Uint8Array(32);
        crypto.getRandomValues(a);
        t = btoa(String.fromCharCode.apply(null, a)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
        localStorage.setItem("vdt", t);
      }
      return t;
    } catch (e) {
      return "";
    }
  }

  function drawCanvas() {
    const c = document.createElement("canvas");
    c.width = 280;
    c.height = 60;
    const x = c.getContext("2d");
    if (!x) return "";
    x.textBaseline = "top";
    x.font = "16px Arial";
    x.fillStyle = "#f60";
    x.fillRect(100, 1, 62, 20);
    x.fillStyle = "#069";
    x.fillText("Verify \u{1F60A} 0.1234 ÆØ", 2, 15);
    x.fillStyle = "rgba(102,204,0,0.7)";
    x.fillText("Verify \u{1F60A} 0.1234 ÆØ", 4, 17);
    x.beginPath();
    x.arc(240, 30, 20, 0, Math.PI * 2);
    x.stroke();
    return c.toDataURL();
  }

  async function canvasSig() {
    try {
      const a = drawCanvas();
      const b = drawCanvas();
      if (!a) return { value: "", noisy: false };
      // Browsers that add random noise (e.g. Brave) give two different images.
      // We just skip the signal: privacy browsers are never punished.
      if (a !== b) return { value: "", noisy: true };
      return { value: await sha256hex(a), noisy: false };
    } catch (e) {
      return { value: "", noisy: false };
    }
  }

  async function webglSig() {
    try {
      const c = document.createElement("canvas");
      const gl = c.getContext("webgl") || c.getContext("experimental-webgl");
      if (!gl) return "";
      const parts = [gl.getParameter(gl.VENDOR), gl.getParameter(gl.RENDERER)];
      const dbg = gl.getExtension("WEBGL_debug_renderer_info");
      if (dbg) parts.push(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL), gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL));
      for (const p of [gl.MAX_TEXTURE_SIZE, gl.MAX_RENDERBUFFER_SIZE, gl.MAX_VERTEX_ATTRIBS,
                       gl.MAX_VERTEX_UNIFORM_VECTORS, gl.MAX_FRAGMENT_UNIFORM_VECTORS, gl.MAX_VARYING_VECTORS]) {
        parts.push(String(gl.getParameter(p)));
      }
      parts.push(String(gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE)));
      parts.push((gl.getSupportedExtensions() || []).join(","));
      return await sha256hex(parts.join("|"));
    } catch (e) {
      return "";
    }
  }

  async function audioSig() {
    try {
      const Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!Ctx) return "";
      const ctx = new Ctx(1, 5000, 44100);
      const osc = ctx.createOscillator();
      osc.type = "triangle";
      osc.frequency.value = 10000;
      const comp = ctx.createDynamicsCompressor();
      comp.threshold.value = -50;
      comp.knee.value = 40;
      comp.ratio.value = 12;
      comp.attack.value = 0;
      comp.release.value = 0.25;
      osc.connect(comp);
      comp.connect(ctx.destination);
      osc.start(0);
      const buf = await withTimeout(ctx.startRendering(), 1500, null);
      if (!buf) return "";
      const d = buf.getChannelData(0);
      let s = 0;
      for (let i = 4500; i < 5000; i++) s += Math.abs(d[i]);
      return await sha256hex(s.toFixed(6));
    } catch (e) {
      return "";
    }
  }

  const FONTS = ["Arial", "Arial Black", "Calibri", "Cambria", "Comic Sans MS", "Consolas", "Courier New",
    "Georgia", "Helvetica", "Helvetica Neue", "Impact", "Lucida Console", "Lucida Grande", "Menlo", "Monaco",
    "Palatino", "Segoe UI", "Tahoma", "Times New Roman", "Trebuchet MS", "Verdana", "Roboto", "Ubuntu",
    "DejaVu Sans", "Noto Sans", "Liberation Sans", "Cantarell", "Fira Sans", "Gill Sans", "Futura", "Optima",
    "Avenir", "Baskerville", "Didot", "Franklin Gothic Medium", "Garamond", "Book Antiqua", "Century Gothic",
    "MS Gothic", "SimSun", "Yu Gothic", "Malgun Gothic", "Microsoft YaHei", "PingFang SC", "Hiragino Sans"];

  async function fontsSig() {
    try {
      const x = document.createElement("canvas").getContext("2d");
      if (!x) return "";
      const text = "mmmmmmmmmmlli10OQ@#";
      const bases = ["monospace", "serif", "sans-serif"];
      const base = {};
      for (const b of bases) {
        x.font = "72px " + b;
        base[b] = x.measureText(text).width;
      }
      const found = [];
      for (const f of FONTS) {
        for (const b of bases) {
          x.font = '72px "' + f + '", ' + b;
          if (x.measureText(text).width !== base[b]) {
            found.push(f);
            break;
          }
        }
      }
      return await sha256hex(found.join(","));
    } catch (e) {
      return "";
    }
  }

  function screenSig() {
    const w = screen.width | 0;
    const h = screen.height | 0;
    const dpr = Math.round((window.devicePixelRatio || 1) * 100) / 100;
    // Larger side first, so rotating a phone doesn't change it.
    return Math.max(w, h) + "x" + Math.min(w, h) + "x" + (screen.colorDepth | 0) + "@" + dpr;
  }

  async function collect() {
    const [canvas, webgl, audio, fonts] = await Promise.all([canvasSig(), webglSig(), audioSig(), fontsSig()]);
    let tz = "";
    try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch (e) { /* ignore */ }
    return {
      device: deviceToken(),
      canvas: canvas.value,
      noisy: canvas.noisy,
      webgl: webgl,
      audio: audio,
      fonts: fonts,
      screen: screenSig(),
      tz: tz,
      lang: (navigator.languages || [navigator.language || ""]).join(",").slice(0, 64),
      platform: String(navigator.platform || "").slice(0, 32),
      hw: (navigator.hardwareConcurrency || 0) + "|" + (navigator.deviceMemory || 0),
    };
  }

  // ── flow ───────────────────────────────────────────────────────────────────
  const MESSAGES = {
    verified: ["You're verified! ✅", "Go back to Discord. You should have access now. You can close this tab."],
    review: ["Almost there", "A moderator will check your verification shortly. You can close this tab."],
    blocked: ["Please turn off your VPN",
      "This server doesn't allow VPNs or proxies while verifying. Turn yours off, then press Verify in Discord again for a new link."],
    error: ["Something went wrong", "Go back to Discord and press Verify again, or ask a moderator."],
    expired: ["This link has expired", "Go back to Discord and press Verify for a new link."],
  };

  async function pollStatus() {
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 1500));
      try {
        const r = await fetch(cfg.statusUrl, { cache: "no-store", credentials: "omit" });
        const { status } = await r.json();
        if (MESSAGES[status]) return result(...MESSAGES[status]);
      } catch (e) { /* keep trying */ }
    }
    result("Still working…", "Check Discord in a minute. If nothing happens, press Verify again.");
  }

  async function onToken(token) {
    result("Working…", "Checking your browser. This takes a few seconds.");
    let signals = {};
    try { signals = await collect(); } catch (e) { /* send what we have */ }
    try {
      const r = await fetch(cfg.submitUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "omit",
        body: JSON.stringify({ turnstile: token, signals: signals }),
      });
      if (r.status === 202) return pollStatus();
      if (r.status === 403) return result("Check failed", "The human check didn't pass. Go back to Discord and press Verify for a new link.");
      if (r.status === 410) return result(...MESSAGES.expired);
      return result(...MESSAGES.error);
    } catch (e) {
      return result(...MESSAGES.error);
    }
  }

  window.onTurnstileLoad = function () {
    window.turnstile.render("#turnstile", {
      sitekey: cfg.siteKey,
      action: "verify",
      cData: cfg.cdata,
      callback: onToken,
      "error-callback": () => result("Check failed", "The human check couldn't load. Refresh the page or ask a moderator."),
      "refresh-expired": "auto",
    });
  };

  $("agree").addEventListener("click", () => {
    $("agree").disabled = true;
    show("step-check");
    // Turnstile is only loaded after consent.
    const s = document.createElement("script");
    s.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=onTurnstileLoad";
    s.async = true;
    document.head.appendChild(s);
  });

  $("decline").addEventListener("click", () => {
    result("No problem", "Nothing was collected. Go back to Discord and press “Ask a moderator” on the verify message to be verified by hand.");
  });
})();
