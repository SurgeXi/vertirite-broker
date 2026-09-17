// Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
/* Vertirite Desktop — standalone shell renderer.
 *
 * Replaces the inherited Maestro chat-shell app.js (1227 lines) with a
 * focused single-page view router. No chat console. No voice overlay.
 * No BYOK panel. The desktop's job is the control plane + Theatre.
 *
 * What this file owns:
 *   1. View routing (sidebar item ↔ #hash ↔ active <section>)
 *   2. Live broker status probe (top-right pill on Home)
 *   3. Mode-authority click handler (UI-only for now; broker IPC TBD)
 *   4. Counter / value updates from broker polls
 *
 * What this file deliberately does NOT do:
 *   - Open IPC chat sessions (Vertirite has no chat surface)
 *   - Manage voice / TTS sessions
 *   - Manage workspaces or local projects
 *   - Render LLM streaming responses
 * Those Maestro-era handlers are still exposed in preload.js for
 * backwards compat but are simply unused here.
 */

(function () {
  'use strict';

  const $  = (id) => document.getElementById(id);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  // Theatre is a separate page (theatre.html), not a routed view, because
  // Electron preload scripts don't propagate into iframes.
  const VIEWS = ['home', 'approvals', 'audit', 'mode', 'capabilities', 'tenants', 'discovery', 'exposure', 'governed', 'protection'];
  const POLL_INTERVAL_MS = 12_000;
  const BROKER_TIMEOUT_MS = 4000;

  // ─── View routing ───────────────────────────────────────────
  function showView(name) {
    if (!VIEWS.includes(name)) name = 'home';

    for (const v of VIEWS) {
      const el = document.getElementById(`vr-view-${v}`);
      if (el) el.classList.toggle('vr-view-active', v === name);
    }
    for (const navItem of $$('.vr-nav-item')) {
      const isActive = navItem.dataset.view === name;
      navItem.classList.toggle('vr-nav-active', isActive);
      if (isActive) navItem.scrollIntoView({ block: 'nearest' });
    }
    if (window.location.hash !== `#${name}`) {
      history.replaceState(null, '', `#${name}`);
    }
    document.title = name === 'home'
      ? 'Vertirite'
      : `Vertirite — ${name.charAt(0).toUpperCase() + name.slice(1)}`;

    // Each view fetches its own data on activation. Errors fall through
    // to the empty-state already rendered in the HTML; we only replace
    // the empty state on success.
    const renderers = {
      approvals: renderApprovals,
      audit: renderAudit,
      capabilities: renderCapabilities,
      tenants: renderTenants,
      discovery: renderCoverage,
      exposure: renderExposure,
      governed: renderGoverned,
      protection: renderProtection,
    };
    const fn = renderers[name];
    if (fn) fn().catch(err => console.warn(`[${name}] render failed:`, err));
  }

  function bindNav() {
    document.body.addEventListener('click', (e) => {
      const copyb = e.target.closest('.vr-snip-copy');
      if (copyb) { e.preventDefault(); _copySnippet(copyb); return; }
      const howto = e.target.closest('.vr-coverage-howto');
      if (howto) { e.preventDefault(); _howtoFinding(howto); return; }
      const dis = e.target.closest('.vr-coverage-dismiss');
      if (dis) { e.preventDefault(); _dismissFinding(dis); return; }
      const gov = e.target.closest('.vr-coverage-govern');
      if (gov) { e.preventDefault(); _governFinding(gov); return; }
      const target = e.target.closest('[data-view]');
      if (!target) return;
      e.preventDefault();
      showView(target.dataset.view);
    });
    window.addEventListener('hashchange', () => {
      const name = (window.location.hash || '#home').slice(1);
      showView(name);
    });
  }

  // ─── Broker status probe ────────────────────────────────────
  // Polls /health every 12s. Updates the top-right status pill on Home
  // and the mode badge in the sidebar. If the broker is unreachable,
  // the pill flips to red with a clear "broker offline" message —
  // operators see this before they wonder why nothing's loading.
  async function probeBroker() {
    const dot  = $('vr-broker-status')?.querySelector('.vr-status-dot');
    const text = $('vr-broker-status')?.querySelector('.vr-status-text');
    if (!dot || !text) return;

    if (!window.surgeDesktop || !window.surgeDesktop.getBrokerHealth) {
      dot.className = 'vr-status-dot';
      text.textContent = 'Standalone (no broker IPC)';
      return;
    }

    dot.className = 'vr-status-dot vr-status-dot-pending';
    text.textContent = 'Connecting to broker…';

    const timeout = new Promise((_, rej) =>
      setTimeout(() => rej(new Error('timeout')), BROKER_TIMEOUT_MS));

    try {
      const health = await Promise.race([
        window.surgeDesktop.getBrokerHealth(),
        timeout,
      ]);
      dot.className = 'vr-status-dot vr-status-dot-ok';
      const v = (health && (health.version || health.status)) || 'reachable';
      text.textContent = `Broker · ${v}`;
    } catch (err) {
      dot.className = 'vr-status-dot vr-status-dot-fail';
      text.textContent = 'Broker offline · running standalone';
    }
  }

  // ─── Pending approvals counter ─────────────────────────────
  async function pollApprovals() {
    const counterEl = $('vr-counter-approvals');
    const homeEl    = $('vr-home-pending');
    if (!counterEl || !homeEl) return;

    if (!window.surgeDesktop || !window.surgeDesktop.getApprovals) {
      counterEl.textContent = '0';
      counterEl.classList.add('is-zero');
      homeEl.textContent = '0';
      return;
    }

    try {
      const list = await Promise.race([
        window.surgeDesktop.getApprovals(),
        new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), BROKER_TIMEOUT_MS)),
      ]);
      const n = Array.isArray(list) ? list.length : (list?.items?.length ?? 0);
      counterEl.textContent = String(n);
      counterEl.classList.toggle('is-zero', n === 0);
      homeEl.textContent = String(n);
    } catch (_) {
      counterEl.textContent = '—';
      counterEl.classList.add('is-zero');
      homeEl.textContent = '—';
    }
  }

  // ─── Mode authority (UI-only stub) ─────────────────────────
  function bindModeAuthority() {
    let lockdownArmed = false;
    let lockdownTimer = null;

    for (const card of $$('.vr-mode-card')) {
      card.addEventListener('click', () => {
        const requested = card.dataset.mode;
        if (!requested) return;

        // Lockdown requires a confirm-click within 3s
        if (requested === 'LOCKDOWN' && !lockdownArmed) {
          lockdownArmed = true;
          card.style.borderTopColor = 'var(--vr-blocked)';
          card.querySelector('.vr-mode-card-key').textContent = '!';
          if (lockdownTimer) clearTimeout(lockdownTimer);
          lockdownTimer = setTimeout(() => {
            lockdownArmed = false;
            card.style.borderTopColor = '';
            card.querySelector('.vr-mode-card-key').textContent = 'L';
          }, 3000);
          return;
        }

        // Optimistic UI update — broker IPC plumbing comes Day 4-5.
        $$('.vr-mode-card').forEach(c => c.classList.remove('vr-mode-active'));
        card.classList.add('vr-mode-active');
        const cur = card.querySelector('.vr-mode-current');
        $$('.vr-mode-current').forEach(el => el.remove());
        if (!cur) {
          const span = document.createElement('span');
          span.className = 'vr-mode-current';
          span.textContent = 'current';
          card.querySelector('h3')?.appendChild(span);
        }

        // Reflect in sidebar badge + sidebar version line + home card
        const display = requested.toLowerCase().replace('_', ' ');
        const modeBadge = $('vr-mode-badge');
        const versionMode = $('vr-version-mode');
        const homeMode = $('vr-home-mode');
        if (modeBadge)   modeBadge.textContent = display;
        if (versionMode) versionMode.textContent = requested;
        if (homeMode)    homeMode.textContent = requested;

        lockdownArmed = false;
        if (lockdownTimer) clearTimeout(lockdownTimer);
      });
    }
  }

  // ─── Helpers ───────────────────────────────────────────────
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtTime = (t) => {
    if (!t) return '';
    try {
      const d = typeof t === 'number' ? new Date(t * 1000) : new Date(t);
      return d.toLocaleString();
    } catch { return String(t); }
  };
  const truncate = (s, n) => (s = String(s || ''), s.length <= n ? s : s.slice(0, n - 1) + '…');

  function withTimeout(p, ms = BROKER_TIMEOUT_MS) {
    return Promise.race([
      p,
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), ms)),
    ]);
  }

  function classChip(cls) {
    const m = {
      'high_stakes': { bg: '#FBEBEB', fg: '#B82929', border: '#B82929', label: 'high stakes' },
      'gated':       { bg: '#FAF3DD', fg: '#8C6F2A', border: '#C8A24A', label: 'gated' },
      'scoped':      { bg: '#E5EEF8', fg: '#1A4D8C', border: '#1A4D8C', label: 'scoped' },
      'safe':        { bg: '#E8F5EE', fg: '#1F8A4C', border: '#1F8A4C', label: 'safe' },
    }[cls] || { bg: 'transparent', fg: '#6B6B73', border: '#E8E2D0', label: cls || '?' };
    return `<span style="background:${m.bg};color:${m.fg};border:1px solid ${m.border};padding:2px 9px;border-radius:999px;font-size:0.68rem;font-weight:800;letter-spacing:0.06em;text-transform:uppercase">${esc(m.label)}</span>`;
  }

  function emptyOrError(viewId, msg, ctaHref, ctaLabel) {
    const el = $(viewId);
    if (!el) return;
    el.innerHTML = `
      <p>${esc(msg)}</p>
      ${ctaHref ? `<a class="vr-btn vr-btn-secondary" href="${esc(ctaHref)}">${esc(ctaLabel || 'Open')}</a>` : ''}
    `;
    el.className = 'vr-empty';
  }

  // ─── View renderers ────────────────────────────────────────
  function _coverageIsAi(f) {
    const s = ((f.target_hostname || '') + ' ' + (f.pattern_name || '') + ' ' + (f.signal_type || '')).toLowerCase();
    return ['openai','anthropic','claude','gpt','gemini','bedrock','cohere','mistral','llm','perplexity','huggingface','langchain','llamaindex','transformers'].some(m => s.includes(m));
  }

  function _friendly(f) {
    // Wave A #4 — the human name the sensor attached to a finding
    // (evidence.friendly_name = {name, vendor, service}). Console shows this
    // over the raw hostname: 'Claude' beats 'api.anthropic.com'.
    try {
      var ev = (typeof f.evidence === 'string') ? JSON.parse(f.evidence) : (f.evidence || {});
      var fn = ev.friendly_name || f.friendly_name;
      return (fn && fn.name) ? fn : null;
    } catch (_) { return null; }
  }


  function _planeChips(covered) {
    const map = { 'north-south': 'egress', 'east-west': 'internal (east-west)', 'host-local': 'host-local' };
    return Object.keys(map).map(p => {
      const on = covered && covered[p];
      return `<span class="vr-plane-chip ${on ? 'vr-plane-on' : 'vr-plane-off'}">${on ? '&#10003;' : '&#9675;'} ${map[p]}</span>`;
    }).join('');
  }

  function _renderSourcesPanel(s) {
    if (!s) return '';
    const banner = s.partial_view ? `
      <div class="vr-sources-banner">
        <strong>&#9888; Partial view.</strong> Vertirite is only seeing part of this environment.
        Point it at more sources below for a true evaluation &mdash; a host-only install is one keyhole.
      </div>` : `
      <div class="vr-sources-banner vr-sources-ok">
        <strong>&#10003; Full-plane coverage.</strong> Egress, east-west, and host signals are all feeding in.
      </div>`;
    const recs = (s.recommendations || []).map(r => `<li>${esc(r)}</li>`).join('');
    const tiers = (s.tiers || []).map(t => `
      <div class="vr-source-tier ${t.active ? 'vr-source-active' : ''}">
        <div class="vr-source-tier-head">
          <span class="vr-source-dot ${t.active ? 'on' : 'off'}"></span>
          <strong>${esc(t.title)}</strong>
          <span class="vr-source-status">${t.active ? 'active' : esc(t.status)}</span>
        </div>
        <div class="vr-source-tier-meta">${esc(t.catches)}</div>
        <div class="vr-source-tier-place"><em>Place:</em> ${esc(t.placement)}</div>
      </div>`).join('');
    return `
      <details class="vr-sources" ${s.partial_view ? 'open' : ''}>
        <summary>
          ${banner}
          <div class="vr-sources-planes">Planes covered: ${_planeChips(s.planes_covered)}</div>
        </summary>
        ${recs ? `<div class="vr-sources-recs"><div class="vr-sources-recs-h">Where to point me next:</div><ul>${recs}</ul></div>` : ''}
        <div class="vr-sources-tiers">${tiers}</div>
      </details>`;
  }

  async function renderCoverage() {
    const body = $('vr-coverage-body');
    if (!body) return;
    const refresh = $('vr-coverage-refresh');
    if (refresh) refresh.onclick = renderCoverage;
    body.className = 'vr-empty';
    body.innerHTML = `<div class="vr-empty"><p>Scanning for ungoverned activity…</p></div>`;
    if (!window.surgeDesktop || !window.surgeDesktop.getCoverage) {
      emptyOrError('vr-coverage-body', 'IPC bridge unavailable.');
      return;
    }
    let d;
    try {
      d = await withTimeout(window.surgeDesktop.getCoverage());
    } catch (e) {
      emptyOrError('vr-coverage-body', `Couldn't reach broker for coverage (${e.message || 'unknown'}). Confirm the broker is up and your token has platform_admin scope.`);
      return;
    }
    const c = d.counts || {};
    const ungoverned = d.ungoverned || [];
    const pct = (d.coverage_pct != null) ? d.coverage_pct : 100;
    // Sensor registry — drives the partial-view banner + "where do I point you?"
    // panel. Best-effort: if it fails, the coverage map still renders.
    let sources = null;
    try { sources = await withTimeout(window.surgeDesktop.getSources()); } catch (e) { sources = null; }
    body.className = '';
    body.innerHTML = `
      ${_renderSourcesPanel(sources)}
      <div class="vr-coverage-head">
        <div class="vr-coverage-pct ${pct < 80 ? 'vr-coverage-pct-warn' : ''}">${pct}%</div>
        <div class="vr-coverage-stat">
          <div><strong>${c.governed || 0}</strong> governed &middot; <strong>${c.ungoverned || 0}</strong> ungoverned</div>
          <div class="vr-coverage-aicount">${c.ungoverned_ai_services || 0} ungoverned AI service${(c.ungoverned_ai_services === 1) ? '' : 's'} detected</div>
          ${c.ungoverned_suspicious ? `<div class="vr-coverage-threatcount">&#9888; ${c.ungoverned_suspicious} suspicious / malicious destination${c.ungoverned_suspicious === 1 ? '' : 's'} found</div>` : ''}
          ${c.ungoverned_unknown ? `<div class="vr-coverage-unknowncount">? ${c.ungoverned_unknown} unrecognized artifact${c.ungoverned_unknown === 1 ? '' : 's'} &mdash; needs investigation</div>` : ''}
          ${(c.east_west || c.host_local) ? `<div class="vr-coverage-planecount">&harr; ${c.east_west || 0} east-west (internal) &middot; ${c.north_south || 0} egress${c.host_local ? ` &middot; ${c.host_local} host-local` : ''}</div>` : ''}
        </div>
      </div>
      ${ungoverned.length ? `
        <div class="vr-coverage-lead">Movement we see that is <strong>not</strong> under governance &mdash; highest-signal first:</div>
        <div class="vr-coverage-list">
          ${ungoverned.map(f => `
            <div class="vr-coverage-row ${f.suspicious ? 'vr-coverage-row-threat' : (_coverageIsAi(f) ? 'vr-coverage-row-ai' : (f.unclassified ? 'vr-coverage-row-unknown' : ''))}">
              <div class="vr-coverage-target">${_friendly(f) ? `<strong class="vr-coverage-name">${esc(_friendly(f).name)}</strong> ` : ''}<code>${esc(f.target_hostname || f.destination || '?')}</code>${f.suspicious ? ' <span class="vr-coverage-threat">&#9888; SUSPICIOUS</span>' : (_coverageIsAi(f) ? ' <span class="vr-coverage-tag">AI</span>' : (f.unclassified ? ' <span class="vr-coverage-unknown">? UNKNOWN &mdash; investigate</span>' : ''))}</div>
              <div class="vr-coverage-meta">${f.plane && f.plane !== 'north-south' ? `<span class="vr-coverage-plane">${f.plane === 'east-west' ? '&harr; internal' : '&#8675; host-local'}</span> ` : ''}${esc(f.pattern_name || f.signal_type || 'observed')} &middot; confidence ${esc(f.confidence || '?')} &middot; seen ${esc(String(f.occurrence_count || 1))}&times;</div>
              ${f.remediation ? `<div class="vr-coverage-rem">&#9656; ${esc(f.remediation)}</div>` : ''}
              <div class="vr-coverage-actions">
                <button class="vr-btn vr-btn-secondary vr-coverage-howto" data-finding="${esc(f.id || '')}">How to govern &#9662;</button>
                <button class="vr-btn vr-btn-primary vr-coverage-govern" data-finding="${esc(f.id || '')}">Mark governed</button>
                <button class="vr-btn vr-btn-ghost vr-coverage-dismiss" data-finding="${esc(f.id || '')}">Dismiss</button>
              </div>
              <div class="vr-coverage-guide" data-guide="${esc(f.id || '')}" hidden></div>
            </div>`).join('')}
        </div>` : `<div class="vr-empty"><p>Full coverage &mdash; every AI/automation we can see is already governed.</p></div>`}
    `;
  }

  // ─── Exposure report (free-tier deliverable, §8.1) ──────────
  // Governed vs ungoverned coverage + the ranked ungoverned exposure, plus a
  // forwardable PDF a CISO/board/auditor can read. Reads /v1/discovery/exposure.json;
  // the PDF is an authed blob download (a plain <a href> can't carry the bearer).
  function _planeLabel(p) {
    return { 'north-south': 'egress', 'east-west': 'east-west (internal)', 'host-local': 'host-local' }[p] || (p || 'egress');
  }
  function _exposureRowClass(cls) {
    return { 'threat': 'vr-coverage-row-threat', 'AI service': 'vr-coverage-row-ai', 'unknown': 'vr-coverage-row-unknown' }[cls] || '';
  }
  function _exposureClassChip(cls) {
    const m = {
      'threat':     { cls: 'vr-coverage-threat', label: '&#9888; threat' },
      'AI service': { cls: 'vr-coverage-tag', label: 'AI service' },
      'unknown':    { cls: 'vr-coverage-unknown', label: '? unknown' },
    }[cls];
    return m ? `<span class="${m.cls}">${m.label}</span>` : esc(cls || 'other');
  }

  async function _downloadExposurePdf(ev) {
    const btn = ev && ev.currentTarget;
    if (!window.surgeDesktop || !window.surgeDesktop.downloadExposurePdf) return;
    const orig = btn ? btn.innerHTML : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Preparing PDF…'; }
    try {
      await window.surgeDesktop.downloadExposurePdf();
      if (btn) btn.innerHTML = orig;
    } catch (e) {
      console.warn('[exposure] pdf download failed:', e);
      if (btn) btn.textContent = 'Download failed — retry';
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function renderExposure() {
    const body = $('vr-exposure-body');
    if (!body) return;
    const refresh = $('vr-exposure-refresh');
    if (refresh) refresh.onclick = renderExposure;
    const dl = $('vr-exposure-download');
    if (dl) dl.onclick = _downloadExposurePdf;
    body.className = 'vr-empty';
    body.innerHTML = `<div class="vr-empty"><p>Building your exposure report…</p></div>`;
    if (!window.surgeDesktop || !window.surgeDesktop.getExposure) {
      emptyOrError('vr-exposure-body', 'IPC bridge unavailable.');
      return;
    }
    let d;
    try {
      d = await withTimeout(window.surgeDesktop.getExposure());
    } catch (e) {
      emptyOrError('vr-exposure-body', `Couldn't reach broker for the exposure report (${e.message || 'unknown'}). Confirm the broker is up and your token has platform_admin scope.`);
      return;
    }
    const c = d.counts || {};
    const ranked = d.ranked_exposure || [];
    const pct = (d.coverage_pct != null) ? d.coverage_pct : 100;
    body.className = '';
    body.innerHTML = `
      <div class="vr-coverage-head">
        <div class="vr-coverage-pct ${pct < 80 ? 'vr-coverage-pct-warn' : ''}">${pct}%</div>
        <div class="vr-coverage-stat">
          <div><strong>${c.governed || 0}</strong> governed &middot; <strong>${c.ungoverned || 0}</strong> ungoverned</div>
          <div class="vr-coverage-aicount">${c.ungoverned_ai_services || 0} ungoverned AI service${c.ungoverned_ai_services === 1 ? '' : 's'}${c.witnessed != null ? ` &middot; ${c.witnessed} witnessed` : ''}</div>
          ${(c.east_west || c.host_local) ? `<div class="vr-coverage-planecount">&harr; ${c.east_west || 0} east-west (internal) &middot; ${c.north_south || 0} egress${c.host_local ? ` &middot; ${c.host_local} host-local` : ''}</div>` : ''}
        </div>
      </div>
      <div class="vr-exposure-forward">
        <button class="vr-btn vr-btn-primary vr-btn-lg" id="vr-exposure-download-cta">&#8681; Download PDF report</button>
        <span class="vr-exposure-forward-note">A forwardable summary a CISO, board, or auditor can read &mdash; free to export.</span>
      </div>
      ${ranked.length ? `
        <div class="vr-coverage-lead">Ranked ungoverned exposure &mdash; highest-signal first${d.truncated ? ` (top ${ranked.length} of ${d.ungoverned_total})` : ''}:</div>
        <div class="vr-exposure-table-wrap">
          <table class="vr-exposure-table">
            <thead><tr><th>Target</th><th>Pattern</th><th>Plane</th><th>Class</th><th>Confidence</th><th>Seen</th></tr></thead>
            <tbody>
              ${ranked.map(f => `
                <tr class="${_exposureRowClass(f.classification)}">
                  <td><code>${esc(f.target_hostname || '—')}</code></td>
                  <td>${esc(f.pattern_name || f.signal_type || 'observed')}</td>
                  <td>${esc(_planeLabel(f.plane))}</td>
                  <td>${_exposureClassChip(f.classification)}</td>
                  <td>${esc(f.confidence || '—')}</td>
                  <td>${esc(String(f.occurrence_count || 1))}&times;</td>
                </tr>`).join('')}
            </tbody>
          </table>
        </div>` : `<div class="vr-empty"><p>No ungoverned exposure found yet &mdash; every AI/automation we can see is already governed. Point more sensors at your network from the Coverage map to widen the view.</p></div>`}
    `;
    const cta = $('vr-exposure-download-cta');
    if (cta) cta.onclick = _downloadExposurePdf;
  }

  async function _governFinding(btn) {
    const fid = btn.dataset.finding;
    if (!fid || !window.surgeDesktop || !window.surgeDesktop.governFinding) return;
    btn.disabled = true; const orig = btn.textContent; btn.textContent = 'Bringing under watch…';
    try {
      await withTimeout(window.surgeDesktop.governFinding(fid));
      renderCoverage();  // the artifact leaves the gap; coverage % rises
    } catch (e) {
      btn.disabled = false; btn.textContent = orig;
    }
  }

  // "Show me how" — render the BLOCK + ROUTE copy-paste guidance for a finding.
  function _renderGuide(g) {
    const prim = (title, p) => {
      if (!p) return '';
      const snips = (p.snippets || []).map(s => `
        <div class="vr-snip">
          <div class="vr-snip-head"><span>${esc(s.target)}</span><button class="vr-snip-copy">copy</button></div>
          <pre class="vr-snip-code">${esc(s.code)}</pre>
        </div>`).join('');
      return `<div class="vr-guide-prim ${p.applicable === false ? 'vr-guide-na' : ''}">
        <div class="vr-guide-prim-h">${title}</div>
        <div class="vr-guide-what">${esc(p.what)}</div>
        ${snips}
        ${p.note ? `<div class="vr-guide-note">${esc(p.note)}</div>` : ''}
      </div>`;
    };
    return `
      <div class="vr-guide-summary">${esc(g.summary || '')}</div>
      ${prim('BLOCK &mdash; cut the direct path', g.block)}
      ${prim('ROUTE &mdash; govern through the broker', g.route)}`;
  }

  async function _howtoFinding(btn) {
    const fid = btn.dataset.finding;
    const guide = document.querySelector(`[data-guide="${fid}"]`);
    if (!guide) return;
    if (!guide.hidden) { guide.hidden = true; btn.innerHTML = 'How to govern &#9662;'; return; }
    guide.hidden = false; btn.innerHTML = 'Hide &#9652;';
    if (guide.dataset.loaded) return;
    guide.innerHTML = '<div class="vr-guide-loading">Generating the exact change&hellip;</div>';
    try {
      const g = await withTimeout(window.surgeDesktop.getRemediation(fid));
      guide.innerHTML = _renderGuide(g);
      guide.dataset.loaded = '1';
    } catch (e) {
      guide.innerHTML = '<div class="vr-guide-loading">Couldn\'t load guidance.</div>';
    }
  }

  function _copySnippet(btn) {
    const snip = btn.closest('.vr-snip'); if (!snip) return;
    const code = snip.querySelector('.vr-snip-code'); if (!code) return;
    navigator.clipboard.writeText(code.textContent).then(() => {
      const o = btn.textContent; btn.textContent = 'copied'; setTimeout(() => { btn.textContent = o; }, 1200);
    }).catch(() => {});
  }

  async function _dismissFinding(btn) {
    const fid = btn.dataset.finding;
    if (!fid || !window.surgeDesktop || !window.surgeDesktop.dismissFinding) return;
    const reason = window.prompt('Dismiss as baseline / known-good — reason:', 'Known-good baseline traffic');
    if (reason == null || !reason.trim()) return;
    btn.disabled = true; btn.textContent = 'Dismissing…';
    try {
      await withTimeout(window.surgeDesktop.dismissFinding(fid, reason.trim()));
      renderCoverage();  // leaves the gap as baseline (not a governance win)
    } catch (e) {
      btn.disabled = false; btn.textContent = 'Dismiss';
    }
  }

  async function renderGoverned() {
    const body = $('vr-governed-body');
    if (!body) return;
    body.className = 'vr-empty';
    body.innerHTML = `<div class="vr-empty"><p>Loading governed artifacts…</p></div>`;
    if (!window.surgeDesktop || !window.surgeDesktop.getGoverned) { emptyOrError('vr-governed-body', 'IPC bridge unavailable.'); return; }
    let d;
    try { d = await withTimeout(window.surgeDesktop.getGoverned()); }
    catch (e) { emptyOrError('vr-governed-body', `Couldn't reach broker (${e.message || 'unknown'}).`); return; }
    const items = d.governed || [];
    if (!items.length) { emptyOrError('vr-governed-body', 'Nothing under governance yet. Bring discovered artifacts under watch from the Coverage map.'); return; }
    body.className = '';
    body.innerHTML = `
      <div class="vr-coverage-lead"><strong>${items.length}</strong> artifact${items.length === 1 ? '' : 's'} under Vertirite&rsquo;s watch:</div>
      <div class="vr-coverage-list">
        ${items.map(f => `
          <div class="vr-coverage-row vr-governed-row">
            <div class="vr-coverage-target"><code>${esc(f.target_hostname || '?')}</code> <span class="vr-governed-tag">&#10003; governed</span></div>
            <div class="vr-coverage-meta">${esc(f.pattern_name || f.signal_type || 'observed')} &middot; on ${esc(f.source_host_id || '?')} &middot; since ${esc((f.acknowledged_at || f.created_at || '').slice(0, 10))}</div>
          </div>`).join('')}
      </div>`;
  }

  async function renderProtection() {
    const body = $('vr-protection-body');
    if (!body) return;
    const refresh = $('vr-protection-refresh');
    if (refresh) refresh.onclick = renderProtection;
    body.className = 'vr-empty';
    body.innerHTML = `<div class="vr-empty"><p>Loading protection status…</p></div>`;
    if (!window.surgeDesktop || !window.surgeDesktop.getLicense) {
      emptyOrError('vr-protection-body', 'IPC bridge unavailable.'); return;
    }
    let lic = null, prot = null, src = null;
    try { lic = await withTimeout(window.surgeDesktop.getLicense()); } catch (e) {}
    try { prot = await withTimeout(window.surgeDesktop.getProtection()); } catch (e) {}
    try { src = await withTimeout(window.surgeDesktop.getSources()); } catch (e) {}
    if (!lic && !prot) {
      emptyOrError('vr-protection-body', "Couldn't reach broker for protection status. Confirm the broker is up and your token has platform_admin scope.");
      return;
    }
    const intel = (src && src.intelligence) || {};
    const beacon = (prot && prot.beacon) || {};
    const binding = (prot && prot.binding) || {};
    const pill = (v) => `vr-pill vr-pill-${v}`;
    const licState = lic ? lic.state : 'unknown';
    const licP = { valid: 'ok', none: 'mut', expired: 'crit', tampered: 'crit' }[licState] || 'mut';
    const intelState = intel.state || 'baseline-only';
    const intelP = { fresh: 'ok', stale: 'warn', expired: 'crit', tampered: 'crit', foreign: 'crit', unlicensed: 'crit' }[intelState] || 'mut';
    body.className = '';
    body.innerHTML = `
      <div class="vr-prot-grid">
        <div class="vr-prot-card">
          <div class="vr-prot-card-h">License</div>
          <div class="vr-prot-big"><span class="${pill(licP)}">${esc(licState)}</span></div>
          <div class="vr-prot-meta">
            ${lic && lic.sku ? `<div>SKU: <strong>${esc(lic.sku)}</strong></div>` : ''}
            ${lic && lic.customer ? `<div>${esc(lic.customer)}</div>` : ''}
            ${lic && lic.features && lic.features.length ? `<div>Features: ${lic.features.map(f => `<span class="vr-tag">${esc(f)}</span>`).join(' ')}</div>` : ''}
            ${lic && lic.days_left != null ? `<div class="vr-prot-mut">${lic.days_left} days left</div>` : ''}
            ${licState === 'none' ? `<div class="vr-prot-mut">Free baseline tier — no premium features.</div>` : ''}
          </div>
        </div>
        <div class="vr-prot-card">
          <div class="vr-prot-card-h">Intelligence freshness</div>
          <div class="vr-prot-big"><span class="${pill(intelP)}">${esc(intelState)}</span></div>
          <div class="vr-prot-meta">
            <div>Catalog v${intel.catalog_version || 0}</div>
            ${intel.age_days != null ? `<div class="vr-prot-mut">${intel.age_days} days old</div>` : ''}
            <div>${intel.premium_pattern_count || 0} premium + ${intel.baseline_pattern_count || 0} baseline patterns</div>
            ${intel.baseline_only ? `<div class="vr-prot-mut">Running on baseline only.</div>` : ''}
          </div>
        </div>
        <div class="vr-prot-card">
          <div class="vr-prot-card-h">Governance channel (self-watch)</div>
          <div class="vr-prot-big"><span class="${pill(beacon.suppressed ? 'crit' : 'ok')}">${beacon.suppressed ? 'suppressed' : 'healthy'}</span></div>
          <div class="vr-prot-meta">
            <div class="vr-prot-mut">consecutive failures: ${beacon.consecutive_failures || 0}</div>
            ${beacon.suppressed ? `<div>&#9888; Vertirite's phone-home is being blocked — a sign someone is hiding this deployment.</div>` : `<div class="vr-prot-mut">Phone-home reachable.</div>`}
          </div>
        </div>
        <div class="vr-prot-card">
          <div class="vr-prot-card-h">Behavioral binding</div>
          <div class="vr-prot-big"><span class="${pill(binding.foreign ? 'crit' : 'ok')}">${binding.foreign ? 'foreign env' : 'bound'}</span></div>
          <div class="vr-prot-meta">
            <div class="vr-prot-mut">enforced: ${binding.enforced ? 'yes' : 'detection-only'}</div>
            ${binding.foreign ? `<div>&#9888; Environment fingerprint changed — this install may be a copy. Re-bind after a legitimate move.</div>` : `<div class="vr-prot-mut">Running in its bound environment.</div>`}
          </div>
        </div>
      </div>
      ${prot && prot.instance_id ? `<div class="vr-prot-id">instance <code>${esc(prot.instance_id.slice(0, 8))}…</code> &middot; canary ${esc(prot.canary_masked || '')}</div>` : ''}`;
  }

  async function renderApprovals() {
    const list = $('vr-approvals-list');
    if (!list) return;
    list.innerHTML = `<div class="vr-empty"><p>Loading approvals…</p></div>`;

    if (!window.surgeDesktop || !window.surgeDesktop.getSurgePendingApprovals) {
      emptyOrError('vr-approvals-list', 'IPC bridge unavailable.');
      return;
    }
    let data;
    try {
      data = await withTimeout(window.surgeDesktop.getSurgePendingApprovals());
    } catch (e) {
      emptyOrError('vr-approvals-list',
        `Couldn't reach broker for approvals (${e.message || 'unknown'}). Confirm the broker is up and your token has /v1/surge/approvals scope.`,
        './theatre.html', '▶ Try Theatre instead');
      return;
    }
    const items = Array.isArray(data) ? data : (data?.items || data?.approvals || []);
    if (!items.length) {
      emptyOrError('vr-approvals-list',
        'Queue is empty — no pending approvals. Either everything is auto-approved (mode=AUTONOMOUS), nothing has been queued recently, or the broker has gated requests but your filter excludes them.',
        './theatre.html', '▶ Open Theatre');
      return;
    }

    list.className = 'vr-approval-list';
    list.innerHTML = items.map(a => `
      <div class="vr-approval-card" data-approval-id="${esc(a.id || a.approval_id)}">
        <div class="vr-approval-row">
          <div class="vr-approval-cap"><code>${esc(a.capability || a.action || '?')}</code></div>
          ${classChip(a.classification || a.approval_class || a.class)}
          ${(a.chokepoints && a.chokepoints.length) ? `<span class="vr-contained" title="Contained — crosses a chokepoint the AI cannot route around">&#9939; contained: ${a.chokepoints.join(' &middot; ')}</span>` : ''}
        </div>
        <div class="vr-approval-meta">
          <span><strong>${esc(a.actor_id || a.requester || '?')}</strong></span>
          <span>·</span>
          <span>tenant ${esc(a.tenant_id || '?')}</span>
          <span>·</span>
          <span>${esc(fmtTime(a.created_at || a.requested_at))}</span>
        </div>
        ${a.summary ? `<div class="vr-approval-summary">${esc(truncate(a.summary, 240))}</div>` : ''}
        ${a.params ? `<details class="vr-approval-params"><summary>Params</summary><pre>${esc(JSON.stringify(a.params, null, 2))}</pre></details>` : ''}
        <div class="vr-approval-actions">
          <button class="vr-btn vr-btn-primary" data-act="approve" data-id="${esc(a.id || a.approval_id)}">✓ Approve</button>
          <button class="vr-btn vr-btn-secondary" data-act="deny" data-id="${esc(a.id || a.approval_id)}">✗ Deny</button>
          <input class="vr-input vr-approval-notes" placeholder="Decision notes (required for deny)" data-id="${esc(a.id || a.approval_id)}" />
        </div>
      </div>
    `).join('');

    // Wire approve/deny buttons
    list.querySelectorAll('button[data-act]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.id;
        const act = btn.dataset.act;
        const noteEl = list.querySelector(`input.vr-approval-notes[data-id="${id}"]`);
        const notes = noteEl ? noteEl.value : '';
        if (act === 'deny' && !notes.trim()) {
          alert('Decision notes required when denying an approval.');
          noteEl.focus();
          return;
        }
        btn.disabled = true;
        btn.textContent = act === 'approve' ? '...' : '...';
        try {
          const fn = act === 'approve'
            ? window.surgeDesktop.approveSurgeApproval
            : window.surgeDesktop.denySurgeApproval;
          await fn(id, notes);
          // Optimistic: remove the card; renderApprovals re-fetch will re-sync
          const card = btn.closest('.vr-approval-card');
          if (card) card.style.opacity = '0.4';
          setTimeout(renderApprovals, 600);
        } catch (e) {
          alert(`${act} failed: ${e.message || 'unknown'}`);
          btn.disabled = false;
          btn.textContent = act === 'approve' ? '✓ Approve' : '✗ Deny';
        }
      });
    });
  }

  async function renderAudit() {
    const list = $('vr-audit-list');
    if (!list) return;
    list.innerHTML = `<div class="vr-empty"><p>Loading audit log…</p></div>`;

    if (!window.surgeDesktop || !window.surgeDesktop.getAuditEvents) {
      emptyOrError('vr-audit-list', 'IPC bridge unavailable.');
      return;
    }
    let data;
    try {
      data = await withTimeout(window.surgeDesktop.getAuditEvents());
    } catch (e) {
      emptyOrError('vr-audit-list',
        `Couldn't reach broker for audit log (${e.message || 'unknown'}). Confirm the broker is up and your token has /v1/audit/me scope.`);
      return;
    }
    const events = Array.isArray(data) ? data : (data?.events || data?.items || []);
    if (!events.length) {
      emptyOrError('vr-audit-list',
        'Audit log is empty for this tenant + actor combination. Run a Theatre demo or fire an action through the broker to populate it.');
      return;
    }

    _auditEvents = events;
    const _filterEl = $('vr-audit-filter');
    if (_filterEl && !_filterEl._vrWired) {
      _filterEl._vrWired = true;
      _filterEl.addEventListener('input', () => _renderAuditRows(_filterEl.value));
    }
    _renderAuditRows(_filterEl ? _filterEl.value : '');
  }

  // Client-side audit filter (matches tenant / actor / type / summary — any field).
  let _auditEvents = [];
  function _renderAuditRows(q) {
    const list = $('vr-audit-list');
    if (!list) return;
    const query = (q || '').trim().toLowerCase();
    const rows = query
      ? _auditEvents.filter(e => JSON.stringify(e).toLowerCase().includes(query))
      : _auditEvents;
    list.className = 'vr-audit-list';
    if (!rows.length) {
      list.innerHTML = `<div class="vr-empty"><p>No audit rows match \u201c${esc(q)}\u201d.</p></div>`;
      return;
    }
    list.innerHTML = rows.map(e => `
      <div class="vr-audit-row">
        <span class="vr-audit-time">${esc(fmtTime(e.created_at || e.timestamp || e.ts))}</span>
        <span class="vr-audit-type">${esc(e.event_type || e.type || '?')}</span>
        <span class="vr-audit-actor">${esc(e.actor_id || e.actor || '?')}</span>
        <span class="vr-audit-summary">${esc(truncate(e.summary || e.description || JSON.stringify(e).slice(0, 120), 200))}</span>
      </div>
    `).join('');
  }

  async function renderCapabilities() {
    const list = $('vr-capabilities-list');
    if (!list) return;
    list.innerHTML = `<div class="vr-empty"><p>Loading capability registry…</p></div>`;

    if (!window.surgeDesktop || !window.surgeDesktop.getSurgeCapabilities) {
      emptyOrError('vr-capabilities-list', 'IPC bridge unavailable.');
      return;
    }
    let data;
    try {
      data = await withTimeout(window.surgeDesktop.getSurgeCapabilities());
    } catch (e) {
      emptyOrError('vr-capabilities-list',
        `Couldn't reach broker for capabilities (${e.message || 'unknown'}). Confirm the broker is up.`);
      return;
    }
    const caps = Array.isArray(data) ? data : (data?.capabilities || data?.items || []);
    if (!caps.length) {
      emptyOrError('vr-capabilities-list',
        'No capabilities registered. The broker needs at least propose_new_tool to be operational; check broker startup logs.');
      return;
    }

    // Update home dashboard counter while we're here
    const homeCount = $('vr-home-cap-count');
    if (homeCount) homeCount.textContent = String(caps.length);

    list.className = 'vr-capability-list';
    list.innerHTML = caps.map(c => {
      const name = c.name || c;
      const cls = c.approval_class || c.class || 'safe';
      const desc = c.description || c.summary || '';
      return `
        <div class="vr-capability-row">
          <div class="vr-capability-head">
            <code class="vr-capability-name">${esc(name)}</code>
            ${classChip(cls)}
          </div>
          ${desc ? `<div class="vr-capability-desc">${esc(truncate(desc, 220))}</div>` : ''}
        </div>
      `;
    }).join('');
  }

  async function renderTenants() {
    const list = $('vr-tenants-list');
    if (!list) return;
    list.innerHTML = `<div class="vr-empty"><p>Loading tenants…</p></div>`;

    if (!window.surgeDesktop || !window.surgeDesktop.getAdminTenants) {
      emptyOrError('vr-tenants-list', 'IPC bridge unavailable.');
      return;
    }
    let data;
    try {
      data = await withTimeout(window.surgeDesktop.getAdminTenants());
    } catch (e) {
      const msg = (e.message || '').includes('403')
        ? 'Your operator role is not platform_admin — only admins can list tenants. Switch to an admin token to view.'
        : `Couldn't reach broker for tenants (${e.message || 'unknown'}).`;
      emptyOrError('vr-tenants-list', msg);
      return;
    }
    const tenants = Array.isArray(data) ? data : (data?.tenants || data?.items || []);
    if (!tenants.length) {
      emptyOrError('vr-tenants-list', 'No tenants registered. The broker has at least the creator-loopback tenant by default.');
      return;
    }

    list.className = 'vr-tenant-list';
    list.innerHTML = tenants.map(t => `
      <div class="vr-tenant-row">
        <div class="vr-tenant-name"><strong>${esc(t.tenant_id || t.id)}</strong> ${t.display_name ? `· ${esc(t.display_name)}` : ''}</div>
        <div class="vr-tenant-meta">
          ${t.created_at ? `created ${esc(fmtTime(t.created_at))}` : ''}
          ${t.user_count != null ? ` · ${t.user_count} users` : ''}
        </div>
      </div>
    `).join('');
  }

  // ─── First-run onboarding wizard ──────────────────────────
  function bindWizard() {
    const overlay = $('vr-wizard-overlay');
    if (!overlay) return;
    let currentStep = 1;

    function showStep(n) {
      overlay.querySelectorAll('.vr-wizard-step-pane').forEach(p => {
        p.style.display = String(n) === p.dataset.step ? '' : 'none';
      });
      currentStep = n;
    }

    overlay.addEventListener('click', (e) => {
      const action = e.target?.dataset?.wizAction;
      if (!action) return;
      if (action === 'next') {
        // Validate the current step's required field
        if (currentStep === 1) {
          const v = $('vr-wiz-tenant-url').value.trim();
          if (!v || !/^https?:\/\//.test(v)) {
            $('vr-wiz-tenant-url').focus();
            return;
          }
        } else if (currentStep === 2) {
          const v = $('vr-wiz-token').value.trim();
          if (!v) { $('vr-wiz-token').focus(); return; }
        }
        showStep(currentStep + 1);
      } else if (action === 'back') {
        showStep(currentStep - 1);
      } else if (action === 'finish') {
        const name = $('vr-wiz-name').value.trim() || 'Operator';
        const tenantUrl = $('vr-wiz-tenant-url').value.trim();
        const token = $('vr-wiz-token').value.trim();
        try {
          localStorage.setItem('vr.tenantUrl', tenantUrl);
          localStorage.setItem('vr.token', token);
          localStorage.setItem('vr.operatorName', name);
          localStorage.setItem('vr.onboarded', '1');
        } catch (_) {}
        // Reflect in the sidebar footer
        const userName = document.querySelector('.vr-user-name');
        if (userName) userName.textContent = name;
        const userAvatar = document.querySelector('.vr-user-avatar');
        if (userAvatar) {
          const initials = name.split(/\s+/).slice(0, 2).map(w => w[0]?.toUpperCase()).join('');
          userAvatar.textContent = initials || 'OP';
        }
        overlay.style.display = 'none';
        // Re-probe broker now that we have a token (preload bridge uses
        // env-var fallback, but a future enhancement will read from localStorage)
        probeBroker();
      }
    });

    // Show only on first run
    let onboarded = false;
    try { onboarded = localStorage.getItem('vr.onboarded') === '1'; } catch (_) {}
    if (!onboarded) {
      overlay.style.display = 'flex';
      // Default the tenant URL field if env hint is available
      const url = window.surgeDesktop?.brokerBaseUrl;
      if (url && $('vr-wiz-tenant-url')) $('vr-wiz-tenant-url').value = url;
      showStep(1);
    } else {
      // Apply saved name to sidebar
      try {
        const name = localStorage.getItem('vr.operatorName');
        if (name) {
          const userName = document.querySelector('.vr-user-name');
          if (userName) userName.textContent = name;
          const userAvatar = document.querySelector('.vr-user-avatar');
          if (userAvatar) {
            const initials = name.split(/\s+/).slice(0, 2).map(w => w[0]?.toUpperCase()).join('');
            userAvatar.textContent = initials || 'OP';
          }
        }
      } catch (_) {}
    }
  }

  // ─── Bootstrap ─────────────────────────────────────────────
  function bootstrap() {
    bindNav();
    bindModeAuthority();
    bindWizard();

    // Initial view from URL hash
    const initial = (window.location.hash || '#home').slice(1);
    showView(initial);

    // First broker probe + recurring poll
    probeBroker();
    pollApprovals();
    setInterval(probeBroker, POLL_INTERVAL_MS);
    setInterval(pollApprovals, POLL_INTERVAL_MS);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootstrap);
  } else {
    bootstrap();
  }
})();
