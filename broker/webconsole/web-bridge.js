// Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
/* Vertirite web console — browser bridge.
 *
 * The desktop renderer (app.js) talks to the broker exclusively through
 * `window.surgeDesktop`, which under Electron is injected by preload.js. In a
 * browser there is no preload, so this script provides the SAME surface backed
 * by same-origin fetch + a bearer token the operator enters once.
 *
 * Design:
 *  - No-op under Electron (preload already defined window.surgeDesktop), so ONE
 *    renderer codebase serves both the desktop app and the served web console.
 *  - Same-origin only: the console is served BY the broker, so every /v1/... call
 *    is same-origin. We never point the browser at a foreign broker URL (avoids
 *    CORS + keeps Vertirite an internal-LAN tool).
 *  - Token lives in localStorage['vr.token'] — the same key the onboarding wizard
 *    uses — so desktop and web share the convention. Read per-request so a
 *    re-login takes effect without a reload of the bridge.
 *  - Electron-only IPC features (local exec, workspace files, Theatre) are not
 *    available in a browser; they resolve to a clear "desktop-only" error and
 *    their nav is hidden by web.css.
 */
(function () {
  "use strict";

  // Electron already provided the real bridge — do nothing.
  if (window.surgeDesktop) return;

  var TOKEN_KEY = "vr.token";

  function getToken() {
    try { return localStorage.getItem(TOKEN_KEY) || ""; } catch (_) { return ""; }
  }
  function setToken(t) {
    try { localStorage.setItem(TOKEN_KEY, t); } catch (_) {}
  }
  function clearToken() {
    try { localStorage.removeItem(TOKEN_KEY); } catch (_) {}
  }

  // ── core transport (same-origin) ─────────────────────────────────────────
  async function bfetch(path) {
    var headers = {};
    if (path !== "/health") headers["Authorization"] = "Bearer " + getToken();
    var res = await fetch(path, { headers: headers });
    if (res.status === 401 || res.status === 403) {
      showLogin(true);
      throw new Error("Unauthorized — enter a valid access token");
    }
    if (!res.ok) throw new Error("Broker responded " + res.status);
    var ct = res.headers.get("content-type") || "";
    return ct.indexOf("application/json") >= 0 ? res.json() : res.text();
  }

  async function bpost(path, payload) {
    var controller = new AbortController();
    var timeoutId = setTimeout(function () { controller.abort(); }, 60000);
    try {
      var res = await fetch(path, {
        method: "POST",
        headers: {
          Authorization: "Bearer " + getToken(),
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload || {}),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      if (res.status === 401 || res.status === 403) {
        showLogin(true);
        throw new Error("Unauthorized — enter a valid access token");
      }
      if (!res.ok) throw new Error("Broker responded " + res.status);
      var ct = res.headers.get("content-type") || "";
      return ct.indexOf("application/json") >= 0 ? res.json() : res.text();
    } catch (err) {
      clearTimeout(timeoutId);
      if (err && err.name === "AbortError") {
        throw new Error("Request timed out — broker may be unreachable");
      }
      throw err;
    }
  }

  // authed file download — a plain <a href> can't carry the bearer header, so
  // fetch the file as a blob with auth and hand the browser a save via an object URL.
  async function bdownload(path, filename) {
    var res = await fetch(path, { headers: { Authorization: "Bearer " + getToken() } });
    if (res.status === 401 || res.status === 403) {
      showLogin(true);
      throw new Error("Unauthorized — enter a valid access token");
    }
    if (!res.ok) throw new Error("Broker responded " + res.status);
    var blob = await res.blob();
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = filename || "download";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
  }

  function desktopOnly(label) {
    return async function () {
      throw new Error(label + " is a desktop-app feature and isn't available in the browser console");
    };
  }

  // ── the bridge — mirrors preload.js method-for-method ────────────────────
  window.surgeDesktop = {
    version: "web-0.1.0",
    web: true,
    brokerBaseUrl: window.location.origin,

    getBrokerHealth: function () { return bfetch("/health"); },
    getProjects: function () { return bfetch("/v1/projects"); },
    getApprovals: function () { return bfetch("/v1/approvals"); },
    createProject: function (name, localPath) {
      return bpost("/v1/projects", { name: name, local_path: localPath });
    },
    approveApproval: function (id, notes) {
      return bpost("/v1/approvals/" + id + "/approve", { decision_notes: notes });
    },
    denyApproval: function (id, notes) {
      return bpost("/v1/approvals/" + id + "/deny", { decision_notes: notes });
    },

    // control-plane reads
    getSurgePendingApprovals: function () { return bfetch("/v1/approvals"); },
    getCoverage: function () { return bfetch("/v1/discovery/coverage"); },
    getExposure: function () { return bfetch("/v1/discovery/exposure.json"); },
    downloadExposurePdf: function () { return bdownload("/v1/discovery/exposure.pdf", "vertirite-exposure-report.pdf"); },
    governFinding: function (id) { return bpost("/v1/discovery/findings/" + id + "/govern", {}); },
    getGoverned: function () { return bfetch("/v1/discovery/governed"); },
    getSources: function () { return bfetch("/v1/discovery/sources"); },
    getLicense: function () { return bfetch("/v1/license"); },
    getProtection: function () { return bfetch("/v1/protection/identity"); },
    getRemediation: function (id) { return bfetch("/v1/discovery/findings/" + id + "/remediation"); },
    dismissFinding: function (id, reason) {
      return bpost("/v1/admin/witnessed/" + id + "/dismiss", { reason: reason || "" });
    },
    approveSurgeApproval: function (id, notes) {
      return bpost("/v1/approvals/" + id + "/approve", { decision_notes: notes || "" });
    },
    denySurgeApproval: function (id, notes) {
      return bpost("/v1/approvals/" + id + "/deny", { decision_notes: notes || "" });
    },
    getAuditEvents: function () { return bfetch("/v1/audit/me"); },
    getAdminTenants: function () { return bfetch("/v1/admin/tenants"); },
    getMe: function () { return bfetch("/v1/me"); },
    getModels: function () { return bfetch("/v1/models"); },
    getSlashCommands: function (query) {
      var url = query ? "/v1/slash-commands?q=" + encodeURIComponent(query) : "/v1/slash-commands";
      return bfetch(url);
    },
    getKeys: function () { return bfetch("/v1/keys"); },
    saveKey: function (provider, apiKey, label) {
      return bpost("/v1/keys", { provider: provider, api_key: apiKey, label: label || provider });
    },
    testKey: function (provider) { return bpost("/v1/keys/" + provider + "/test", {}); },

    // Electron-only — not available in a browser
    localExec: desktopOnly("Local command execution"),
    initWorkspace: desktopOnly("Workspace"),
    listProjects: desktopOnly("Workspace"),
    createLocalProject: desktopOnly("Workspace"),
    openProject: desktopOnly("Workspace"),
    saveNote: desktopOnly("Workspace"),
    logChat: desktopOnly("Workspace"),
    readFile: desktopOnly("Workspace"),
    setWorkspacePath: desktopOnly("Workspace"),
    transcribeAudio: desktopOnly("Voice"),
    speakText: desktopOnly("Voice"),
    voiceChat: desktopOnly("Voice"),
    startVoiceSession: desktopOnly("Voice"),
    stopVoiceSession: desktopOnly("Voice"),
    listVoiceSessions: desktopOnly("Voice"),
    deleteKey: desktopOnly("Key delete"),
    demo: {
      listScenarios: desktopOnly("Theatre"),
      startScenario: desktopOnly("Theatre"),
      stopScenario: desktopOnly("Theatre"),
      readReport: desktopOnly("Theatre"),
      listRecordings: desktopOnly("Theatre"),
      startRecording: desktopOnly("Theatre"),
    },

    // web-only helper the console can call to sign out
    webLogout: function () { clearToken(); showLogin(false); },
  };

  // Web mode never runs the desktop onboarding wizard (it asks for a broker URL
  // that is meaningless same-origin). Mark onboarded + seed the origin so app.js
  // skips it; this bridge owns auth via the login overlay below.
  try {
    localStorage.setItem("vr.tenantUrl", window.location.origin);
    if (!localStorage.getItem("vr.onboarded")) localStorage.setItem("vr.onboarded", "1");
    if (!localStorage.getItem("vr.operatorName")) localStorage.setItem("vr.operatorName", "Operator");
  } catch (_) {}

  // ── login overlay ────────────────────────────────────────────────────────
  function showLogin(invalid) {
    if (document.getElementById("vrt-login")) {
      if (invalid) { var ex = document.getElementById("vrt-login-err"); if (ex) ex.style.display = "block"; }
      return;
    }
    var ov = document.createElement("div");
    ov.id = "vrt-login";
    ov.innerHTML =
      '<div class="vrt-login-card">' +
      '  <div class="vrt-login-mark">VERTI<span>RITE</span></div>' +
      '  <p class="vrt-login-tag">Sign in to your control plane</p>' +
      '  <div id="vrt-pw-mode">' +
      '    <label class="vrt-login-label">Email</label>' +
      '    <input id="vrt-login-email" type="email" autocomplete="username" spellcheck="false" placeholder="you@company.com" />' +
      '    <label class="vrt-login-label">Password</label>' +
      '    <input id="vrt-login-pw" type="password" autocomplete="current-password" placeholder="your password" />' +
      '    <p id="vrt-login-err" class="vrt-login-err" style="display:none">Email or password was rejected. Check them and try again.</p>' +
      '    <button id="vrt-login-go" class="vrt-login-btn">Sign in</button>' +
      '    <p class="vrt-login-hint">Stored only in this browser. <a href="#" id="vrt-tok-toggle">Use an access token instead</a></p>' +
      '  </div>' +
      '  <div id="vrt-tok-mode" style="display:none">' +
      '    <label class="vrt-login-label">Access token</label>' +
      '    <input id="vrt-login-token" type="password" autocomplete="off" spellcheck="false" placeholder="paste the access token your operator gave you" />' +
      '    <p id="vrt-tok-err" class="vrt-login-err" style="display:none">That token was rejected. Check it and try again.</p>' +
      '    <button id="vrt-tok-go" class="vrt-login-btn">Open Vertirite</button>' +
      '    <p class="vrt-login-hint"><a href="#" id="vrt-pw-toggle">Back to email sign-in</a></p>' +
      '  </div>' +
      "</div>";
    document.body.appendChild(ov);
    function _show(id){var e=document.getElementById(id);if(e)e.style.display="block";}
    function _hide(id){var e=document.getElementById(id);if(e)e.style.display="none";}

    document.getElementById("vrt-tok-toggle").addEventListener("click", function(e){e.preventDefault();_hide("vrt-pw-mode");_show("vrt-tok-mode");document.getElementById("vrt-login-token").focus();});
    document.getElementById("vrt-pw-toggle").addEventListener("click", function(e){e.preventDefault();_hide("vrt-tok-mode");_show("vrt-pw-mode");document.getElementById("vrt-login-email").focus();});

    var emailEl = document.getElementById("vrt-login-email");
    var pwEl = document.getElementById("vrt-login-pw");
    var goBtn = document.getElementById("vrt-login-go");
    emailEl.focus();
    async function pwSubmit() {
      var email = (emailEl.value || "").trim(); var pw = pwEl.value || "";
      if (!email || !pw) return;
      goBtn.disabled = true; goBtn.textContent = "Signing in…";
      try {
        var res = await fetch("/v1/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: email, password: pw }) });
        if (!res.ok) throw new Error("rejected");
        var data = await res.json();
        if (data.session_token) setToken(data.session_token);
        if (data.user && data.user.must_change_password) {
          showChange(data.user.id, email, pw, ov);
        } else {
          ov.parentNode.removeChild(ov); window.location.reload();
        }
      } catch (e) {
        goBtn.disabled = false; goBtn.textContent = "Sign in"; _show("vrt-login-err"); pwEl.focus();
      }
    }
    goBtn.addEventListener("click", pwSubmit);
    pwEl.addEventListener("keydown", function(e){ if (e.key === "Enter") pwSubmit(); });

    var tokEl = document.getElementById("vrt-login-token");
    var tokBtn = document.getElementById("vrt-tok-go");
    async function tokSubmit() {
      var t = (tokEl.value || "").trim(); if (!t) return;
      setToken(t); tokBtn.disabled = true; tokBtn.textContent = "Verifying…";
      try {
        var res = await fetch("/v1/license", { headers: { Authorization: "Bearer " + t } });
        if (res.status === 401 || res.status === 403) throw new Error("rejected");
        ov.parentNode.removeChild(ov); window.location.reload();
      } catch (e) {
        clearToken(); tokBtn.disabled = false; tokBtn.textContent = "Open Vertirite"; _show("vrt-tok-err"); tokEl.focus();
      }
    }
    tokBtn.addEventListener("click", tokSubmit);
    tokEl.addEventListener("keydown", function(e){ if (e.key === "Enter") tokSubmit(); });

    if (invalid) _show("vrt-login-err");
  }

  // Forced password change on first login (must_change_password). The user
  // cannot reach the console until the temporary password is replaced.
  function showChange(userId, email, currentPw, ov) {
    var card = ov.querySelector(".vrt-login-card");
    card.innerHTML =
      '<div class="vrt-login-mark">VERTI<span>RITE</span></div>' +
      '<p class="vrt-login-tag">Set a new password to continue</p>' +
      '<label class="vrt-login-label">New password</label>' +
      '<input id="vrt-ch-new" type="password" autocomplete="new-password" placeholder="at least 8 characters" />' +
      '<label class="vrt-login-label">Confirm new password</label>' +
      '<input id="vrt-ch-confirm" type="password" autocomplete="new-password" placeholder="re-enter it" />' +
      '<p id="vrt-ch-err" class="vrt-login-err" style="display:none"></p>' +
      '<button id="vrt-ch-go" class="vrt-login-btn">Set password &amp; continue</button>' +
      '<p class="vrt-login-hint">This is required on your first sign-in.</p>';
    var nw = document.getElementById("vrt-ch-new");
    var cf = document.getElementById("vrt-ch-confirm");
    var b = document.getElementById("vrt-ch-go");
    var er = document.getElementById("vrt-ch-err");
    nw.focus();
    function fail(m){ er.textContent = m; er.style.display = "block"; b.disabled = false; b.textContent = "Set password & continue"; }
    async function chSubmit() {
      var a = nw.value || ""; var c = cf.value || "";
      if (a.length < 8) return fail("New password must be at least 8 characters.");
      if (a !== c) return fail("The two passwords do not match.");
      if (a === currentPw) return fail("Choose a password different from the temporary one.");
      b.disabled = true; b.textContent = "Saving…";
      try {
        var res = await fetch("/v1/auth/change-password", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ user_id: userId, current_password: currentPw, new_password: a }) });
        if (!res.ok) { var d = {}; try { d = await res.json(); } catch (_) {} return fail((d && d.detail) || "Could not set the password."); }
        // Changing the password invalidates the temp session — sign back in with the new one.
        var lr = await fetch("/v1/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: email, password: a }) });
        if (lr.ok) { var ld = await lr.json(); if (ld.session_token) setToken(ld.session_token); }
        else { clearToken(); }
        ov.parentNode.removeChild(ov); window.location.reload();
      } catch (e) { fail("Network error — try again."); }
    }
    b.addEventListener("click", chSubmit);
    cf.addEventListener("keydown", function(e){ if (e.key === "Enter") chSubmit(); });
  }

  function boot() {
    // Frictionless entry: accept a token from the URL fragment (never sent to the
    // server, not logged) so the hosted demo's "Try live" link lands straight in
    // the console. Harmless generally — an invalid token still hits the login wall.
    try {
      var m = (location.hash || "").match(/[#&]k=([^&]+)/);
      if (m && m[1]) { setToken(decodeURIComponent(m[1])); history.replaceState(null, "", location.pathname + location.search); }
    } catch (_) {}
    if (!getToken()) showLogin(false);
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
