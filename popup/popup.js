const api = typeof browser !== "undefined" ? browser : chrome;

const SEV = { crit: 3, warn: 2, info: 1, good: 0 };
const SEV_LABEL = { crit: "critical", warn: "warning", info: "info", good: "pass" };
const SEV_COLOR = { crit: "var(--crit)", warn: "var(--warn)", info: "var(--info)", good: "var(--good)" };
const SEV_DEDUCT = { crit: 14, warn: 6, info: 1, good: 0 };

function iconFor(sev) {
  return { crit: "✕", warn: "!", info: "i", good: "✓" }[sev];
}

async function getActiveTab() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function promiseMessage(payload) {
  return new Promise((resolve) => {
    api.runtime.sendMessage(payload, (resp) => resolve(resp));
  });
}

function promiseTabMessage(tabId, payload) {
  return new Promise((resolve) => {
    api.tabs.sendMessage(tabId, payload, (resp) => resolve(resp || null));
  });
}

// ---------- individual check builders ----------

function buildHeaderChecks(headers, isHttps) {
  headers = headers || {};
  const checks = [];

  checks.push(
    headers["content-security-policy"]
      ? { sev: "good", title: "Content-Security-Policy set", detail: headers["content-security-policy"].slice(0, 140) }
      : { sev: "warn", title: "No Content-Security-Policy header", detail: "Without CSP, injected scripts run with no restriction — primary XSS mitigation is missing." }
  );

  if (isHttps) {
    checks.push(
      headers["strict-transport-security"]
        ? { sev: "good", title: "HSTS enabled", detail: headers["strict-transport-security"] }
        : { sev: "warn", title: "No Strict-Transport-Security header", detail: "Browser won't force HTTPS on future visits — vulnerable to SSL-stripping on the first request." }
    );
  }

  checks.push(
    headers["x-content-type-options"] === "nosniff"
      ? { sev: "good", title: "X-Content-Type-Options: nosniff", detail: null }
      : { sev: "warn", title: "Missing X-Content-Type-Options", detail: "Browser may MIME-sniff responses, enabling content-type confusion attacks." }
  );

  const hasFrameProtection =
    headers["x-frame-options"] || (headers["content-security-policy"] || "").includes("frame-ancestors");
  checks.push(
    hasFrameProtection
      ? { sev: "good", title: "Clickjacking protection present", detail: headers["x-frame-options"] || "via CSP frame-ancestors" }
      : { sev: "warn", title: "No clickjacking protection", detail: "Missing X-Frame-Options / frame-ancestors — page can be framed by any site." }
  );

  checks.push(
    headers["referrer-policy"]
      ? { sev: "good", title: "Referrer-Policy set", detail: headers["referrer-policy"] }
      : { sev: "info", title: "No Referrer-Policy header", detail: "Defaults vary by browser; full URLs (incl. query strings) may leak to third parties via Referer." }
  );

  checks.push(
    headers["permissions-policy"]
      ? { sev: "good", title: "Permissions-Policy set", detail: headers["permissions-policy"].slice(0, 140) }
      : { sev: "info", title: "No Permissions-Policy header", detail: "Browser features (camera, geolocation, etc.) aren't explicitly restricted." }
  );

  const leaky = ["server", "x-powered-by"].filter((h) => headers[h]);
  if (leaky.length) {
    checks.push({
      sev: "info",
      title: "Server fingerprinting headers present",
      detail: leaky.map((h) => `${h}: ${headers[h]}`).join(" · ")
    });
  }

  return checks;
}

// ---------- Rate limiting: passive only ----------
// This reads rate-limit headers off the single response the browser already
// fetched. It never sends extra/repeat requests to test enforcement —
// deliberately, since automatically hammering every site you visit to see
// if it blocks you is active reconnaissance against a third party, not
// passive auditing, and isn't something this extension does without your
// explicit say-so on a specific target.
function buildRateLimitChecks(headers) {
  headers = headers || {};
  const checks = [];

  const ietf = ["ratelimit-limit", "ratelimit-remaining", "ratelimit-reset"].filter((h) => headers[h]);
  const legacy = ["x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"].filter((h) => headers[h]);
  const retryAfter = headers["retry-after"];

  if (ietf.length) {
    checks.push({
      sev: "good",
      title: "Rate-limit headers present (IETF draft standard)",
      detail: ietf.map((h) => `${h}: ${headers[h]}`).join(" · ")
    });
  } else if (legacy.length) {
    checks.push({
      sev: "good",
      title: "Rate-limit headers present (X-RateLimit-* convention)",
      detail: legacy.map((h) => `${h}: ${headers[h]}`).join(" · ")
    });
  } else {
    checks.push({
      sev: "info",
      title: "No rate-limit headers observed on this response",
      detail: "Doesn't confirm the absence of rate limiting — many services (especially behind Cloudflare/Akamai/AWS WAF) enforce it at the edge without disclosing headers until you're actually blocked. This check is passive-only and never sends extra requests to test enforcement."
    });
  }

  if (retryAfter) {
    checks.push({ sev: "info", title: "Retry-After header present", detail: `Value: ${retryAfter} — normally only sent alongside a 429/503 response.` });
  }

  return checks;
}

// ---------- Access control (CORS): passive only ----------
// Reads Access-Control-* headers off the same response — no crafted Origin
// header, no probing of other endpoints on the site. A full CORS
// misconfiguration scan (reflecting arbitrary Origins, enumerating API
// routes) is active testing against endpoints you didn't ask this tool to
// touch, so it's out of scope here for the same reason as active
// rate-limit testing above.
function buildAccessControlChecks(headers) {
  headers = headers || {};
  const checks = [];
  const acao = headers["access-control-allow-origin"];
  const acac = headers["access-control-allow-credentials"];

  if (!acao) {
    checks.push({ sev: "info", title: "No Access-Control-Allow-Origin on this response", detail: "Normal for a top-level page load — most sites only send CORS headers on their API responses, which this passive check doesn't probe for." });
    return checks;
  }

  if (acao === "*" && acac === "true") {
    checks.push({
      sev: "crit",
      title: "Invalid CORS combination: wildcard origin with credentials allowed",
      detail: "Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true is disallowed by the CORS spec — browsers should reject it, but a server sending both indicates a real misconfiguration worth fixing at the source."
    });
  } else if (acao === "*") {
    checks.push({ sev: "info", title: "Wildcard CORS origin (Access-Control-Allow-Origin: *)", detail: "Only a real risk if this response also carries sensitive, credentialed data — which a wildcard origin can't legally pair with under the CORS spec." });
  } else {
    checks.push({ sev: "info", title: "Access-Control-Allow-Origin set", detail: acao });
    if (acac === "true") {
      checks.push({ sev: "info", title: "Credentials allowed for this origin", detail: "Confirm this specific origin is actually meant to receive cookies/auth headers cross-site." });
    }
  }

  return checks;
}

function buildCookieChecks(cookies, isHttps) {
  if (!cookies || cookies.length === 0) {
    return [{ sev: "good", title: "No cookies set by this origin", detail: null }];
  }
  const checks = [];
  for (const c of cookies) {
    const flags = [];
    if (isHttps && !c.secure) {
      checks.push({ sev: "crit", title: `Cookie "${c.name}" missing Secure flag`, detail: "Can be sent over an unencrypted connection if one is ever made." });
    }
    if (!c.httpOnly) {
      checks.push({ sev: "warn", title: `Cookie "${c.name}" missing HttpOnly`, detail: "Readable by page JavaScript — exposed to theft via any XSS on this site." });
    }
    if (c.sameSite === "no_restriction" && !c.secure) {
      checks.push({ sev: "crit", title: `Cookie "${c.name}" is SameSite=None without Secure`, detail: "Browsers reject this combination or treat it as a CSRF exposure." });
    } else if (c.sameSite === "no_restriction") {
      checks.push({ sev: "info", title: `Cookie "${c.name}" is SameSite=None`, detail: "Sent on cross-site requests — confirm that's intentional (e.g. embedded widget)." });
    }
  }
  if (checks.length === 0) {
    checks.push({ sev: "good", title: `${cookies.length} cookie(s) checked — flags look correct`, detail: null });
  }
  return checks;
}

function buildTlsChecks(url, security, isFirefox) {
  const isHttps = url.startsWith("https://");
  const checks = [];
  checks.push(
    isHttps
      ? { sev: "good", title: "Connection uses HTTPS", detail: null }
      : { sev: "crit", title: "Page loaded over plain HTTP", detail: "All traffic, including any form data, is unencrypted and interceptable." }
  );

  if (!isHttps) return checks;

  if (isFirefox && security) {
    if (security.state !== "secure") {
      checks.push({ sev: "crit", title: `TLS state: ${security.state}`, detail: "Browser did not fully validate this connection." });
    }
    if (security.isUntrusted) {
      checks.push({ sev: "crit", title: "Certificate is untrusted", detail: security.issuer || "" });
    }
    if (security.isDomainMismatch) {
      checks.push({ sev: "crit", title: "Certificate domain mismatch", detail: null });
    }
    if (security.isNotValidAtThisTime) {
      checks.push({ sev: "crit", title: "Certificate expired or not yet valid", detail: `${security.validFrom} → ${security.validTo}` });
    }
    if (security.protocolVersion) {
      const weak = /TLSv1$|TLSv1\.0|TLSv1\.1|SSL/i.test(security.protocolVersion);
      checks.push({
        sev: weak ? "warn" : "good",
        title: `Protocol: ${security.protocolVersion}`,
        detail: weak ? "Outdated protocol version — TLS 1.2+ recommended." : null
      });
    }
    if (security.issuer) {
      checks.push({ sev: "info", title: "Certificate issuer", detail: security.issuer });
    }
  } else {
    checks.push({
      sev: "info",
      title: "Certificate detail unavailable in this browser",
      detail: "Chrome's extension APIs don't expose TLS certificate data — check the padlock icon in the address bar for chain/expiry detail."
    });
  }

  return checks;
}

function daysUntil(dateStr) {
  if (!dateStr) return null;
  const ms = new Date(dateStr).getTime() - Date.now();
  return Math.floor(ms / (1000 * 60 * 60 * 24));
}

function certExpiryCheck(notAfter, source) {
  const days = daysUntil(notAfter);
  if (days === null) return { sev: "info", title: "Certificate expiry unknown", detail: `Could not determine expiry (${source}).` };
  const detail = `Expires ${new Date(notAfter).toLocaleDateString()} (${source})`;
  if (days < 0) return { sev: "crit", title: "Certificate has expired", detail };
  if (days <= 7) return { sev: "crit", title: `Certificate expires in ${days} day(s)`, detail };
  if (days <= 30) return { sev: "warn", title: `Certificate expires in ${days} day(s)`, detail };
  return { sev: "good", title: `Certificate valid for ${days} more day(s)`, detail };
}

// Adds a cert-expiry finding to an existing TLS checks array, mutating in place.
// Firefox: expiry already came free with getSecurityInfo(). Chrome: falls
// back to a crt.sh lookup, gated behind consent.
async function addCertExpiryCheck(checks, { isHttps, isFirefox, security, hostname, consentGiven }) {
  if (!isHttps) return;

  if (isFirefox && security && security.validTo) {
    checks.push(certExpiryCheck(security.validTo, "from browser TLS info"));
    return;
  }

  if (!consentGiven) {
    checks.push({ sev: "info", title: "Certificate expiry not checked", detail: "Requires an external lookup (crt.sh) — external checks are off." });
    return;
  }

  const ct = await NET.fetchCertExpiryFromCT(hostname);
  if (ct.ok) {
    checks.push(certExpiryCheck(ct.notAfter, "via crt.sh, certificate transparency log"));
  } else {
    checks.push({ sev: "info", title: "Certificate expiry lookup failed", detail: ct.error });
  }
}

function buildOwnerChecks(owner, consentGiven) {
  if (!consentGiven) {
    return [{ sev: "info", title: "Ownership lookup skipped", detail: "External checks are off — enable them to see registrant/registrar info." }];
  }
  if (!owner || !owner.ok) {
    return [{ sev: "info", title: "Ownership lookup failed", detail: owner ? owner.error : "Unknown error" }];
  }
  const checks = [{ sev: "info", title: `Registered organization: ${owner.organization}`, detail: `Domain: ${owner.domain}` }];
  const registered = owner.events.find((e) => e.action === "registration");
  const expiration = owner.events.find((e) => e.action === "expiration");
  if (registered) checks.push({ sev: "info", title: "Domain registered", detail: new Date(registered.date).toLocaleDateString() });
  if (expiration) {
    const days = daysUntil(expiration.date);
    checks.push({
      sev: days !== null && days < 30 ? "warn" : "info",
      title: "Domain registration expires",
      detail: `${new Date(expiration.date).toLocaleDateString()}${days !== null ? ` (${days} days)` : ""}`
    });
  }
  return checks;
}

function buildVulnChecks(vuln, consentGiven) {
  if (!consentGiven) {
    return [{ sev: "info", title: "Known-vulnerability lookup skipped", detail: "External checks are off — enable them to cross-reference the detected stack against NVD." }];
  }
  if (!vuln || !vuln.ok) {
    return [{ sev: "info", title: "Vulnerability lookup failed", detail: vuln ? vuln.error : "Unknown error" }];
  }
  if (vuln.stack.length === 0) {
    return [{ sev: "info", title: "No server technology fingerprinted", detail: "Server / X-Powered-By headers weren't present or didn't match a known pattern." }];
  }
  const checks = [];
  for (const r of vuln.results) {
    if (r.error) {
      checks.push({ sev: "info", title: `${r.product}${r.version ? " " + r.version : ""} — lookup failed`, detail: r.error });
      continue;
    }
    if (!r.cves || r.cves.length === 0) {
      checks.push({ sev: "good", title: `${r.product}${r.version ? " " + r.version : ""} — no matching CVEs found`, detail: "Keyword match against NVD; not a guarantee of no vulnerabilities." });
      continue;
    }
    for (const cve of r.cves) {
      const high = /CRITICAL|HIGH/i.test(cve.severity);
      checks.push({
        sev: high ? "crit" : "warn",
        title: `${r.product}${r.version ? " " + r.version : ""} — ${cve.id} (${cve.severity})`,
        detail: cve.summary.slice(0, 180)
      });
    }
  }
  return checks;
}

function buildLocationChecks(geo, consentGiven) {
  if (!consentGiven) {
    return [{ sev: "info", title: "Server location lookup skipped", detail: "External checks are off — enable them to see hosting location and network." }];
  }
  if (!geo || !geo.ok) {
    return [{ sev: "info", title: "Server location lookup failed", detail: geo ? geo.error : "No resolved IP available — reload the page once, then re-scan." }];
  }
  return [
    { sev: "info", title: `Server located in ${geo.city ? geo.city + ", " : ""}${geo.region ? geo.region + ", " : ""}${geo.country}`, detail: `IP: ${geo.ip}` },
    { sev: "info", title: `Hosted by ${geo.isp || geo.org || "unknown network"}`, detail: geo.asn || null }
  ];
}

function buildMixedContentChecks(mixedContent) {
  if (!mixedContent || !mixedContent.applicable) {
    return [{ sev: "info", title: "Not applicable — page isn't served over HTTPS", detail: null }];
  }
  if (mixedContent.items.length === 0) {
    return [{ sev: "good", title: "No mixed content detected", detail: null }];
  }
  const activeKinds = new Set(["script", "iframe", "stylesheet"]);
  return mixedContent.items.slice(0, 12).map((item) => ({
    sev: activeKinds.has(item.kind) ? "crit" : "warn",
    title: `Insecure ${item.kind} loaded over HTTP`,
    detail: item.url
  }));
}

function buildLibraryChecks(libraries) {
  if (!libraries || libraries.length === 0) {
    return [{ sev: "info", title: "No fingerprinted libraries detected", detail: "Detection covers jQuery, AngularJS, Lodash, Moment, Bootstrap, Handlebars only." }];
  }
  const checks = [];
  for (const lib of libraries) {
    if (lib.vulnerabilities.length === 0) {
      checks.push({ sev: "good", title: `${lib.label} ${lib.version}`, detail: "No known issues in the bundled database." });
    } else {
      for (const v of lib.vulnerabilities) {
        checks.push({
          sev: v.severity === "high" ? "crit" : "warn",
          title: `${lib.label} ${lib.version} — ${v.id}`,
          detail: v.summary
        });
      }
    }
  }
  return checks;
}

function buildFormChecks(formIssues) {
  if (!formIssues || formIssues.length === 0) {
    return [{ sev: "good", title: "No form hygiene issues found", detail: null }];
  }
  return formIssues.map((f) =>
    f.type === "password-over-http"
      ? { sev: "crit", title: "Password field submits over HTTP", detail: f.detail }
      : { sev: "info", title: "Password field missing autocomplete hint", detail: f.detail }
  );
}

// ---------- rendering ----------

function sectionSeverity(checks) {
  return checks.reduce((worst, c) => (SEV[c.sev] > SEV[worst] ? c.sev : worst), "good");
}

function renderSection(id, label, checks, openByDefault) {
  const worst = sectionSeverity(checks);
  const section = document.createElement("div");
  section.className = "section" + (openByDefault ? " open" : "");

  const badgeClass = worst === "crit" ? "crit" : worst === "warn" ? "warn" : "good";
  const badgeText = worst === "good" ? "clear" : `${checks.filter((c) => c.sev === worst).length} ${SEV_LABEL[worst]}`;

  section.innerHTML = `
    <button class="section__head" aria-expanded="${openByDefault}">
      <span>${label}</span>
      <span class="section__badge ${badgeClass}">${badgeText}</span>
      <span class="chev">▶</span>
    </button>
    <div class="section__body"></div>
  `;

  const body = section.querySelector(".section__body");
  if (checks.length === 0) {
    body.innerHTML = `<div class="empty">Nothing to report.</div>`;
  } else {
    for (const c of checks) {
      const row = document.createElement("div");
      row.className = "check";
      row.innerHTML = `
        <span class="check__icon ${c.sev}">${iconFor(c.sev)}</span>
        <div class="check__body">
          <strong>${escapeHtml(c.title)}</strong>
          ${c.detail ? `<div class="detail">${escapeHtml(c.detail)}</div>` : ""}
        </div>
      `;
      body.appendChild(row);
    }
  }

  section.querySelector(".section__head").addEventListener("click", () => {
    section.classList.toggle("open");
  });

  return section;
}

function escapeHtml(str) {
  const d = document.createElement("div");
  d.textContent = str;
  return d.innerHTML;
}

function getScoreBand(score) {
  if (score >= 90) return { label: "Excellent", desc: "Strong baseline — few or no issues found.", color: "var(--good)" };
  if (score >= 70) return { label: "Good", desc: "Solid overall, some gaps worth closing.", color: "var(--good)" };
  if (score >= 50) return { label: "Fair", desc: "Several issues that add real risk.", color: "var(--warn)" };
  if (score >= 30) return { label: "Poor", desc: "Significant exposure — worth prioritizing.", color: "var(--warn)" };
  return { label: "Critical", desc: "Seriously vulnerable as configured.", color: "var(--crit)" };
}

function renderScore(allChecks) {
  let score = 100;
  const tally = { crit: 0, warn: 0, info: 0 };
  for (const c of allChecks) {
    if (c.sev === "crit") tally.crit++;
    if (c.sev === "warn") tally.warn++;
    if (c.sev === "info") tally.info++;
    score -= SEV_DEDUCT[c.sev];
  }
  score = Math.max(0, Math.min(100, score));

  const ring = document.getElementById("scoreRing");
  const circumference = 170; // matches stroke-dasharray in CSS
  const offset = circumference - (circumference * score) / 100;
  ring.style.strokeDashoffset = String(offset);
  ring.style.stroke = score >= 80 ? "var(--good)" : score >= 50 ? "var(--warn)" : "var(--crit)";

  document.getElementById("scoreNum").textContent = score;

  const band = getScoreBand(score);
  const bandEl = document.getElementById("scoreBand");
  bandEl.textContent = band.label;
  bandEl.title = band.desc;
  bandEl.style.display = "inline-block";
  bandEl.style.color = band.color;
  bandEl.style.border = `1px solid ${band.color}`;

  const tallyEl = document.getElementById("scoreTally");
  tallyEl.innerHTML = `
    <li><span class="dot" style="background:var(--crit)"></span>${tally.crit} critical</li>
    <li><span class="dot" style="background:var(--warn)"></span>${tally.warn} warning</li>
    <li><span class="dot" style="background:var(--info)"></span>${tally.info} info</li>
  `;
}

// ---------- main flow ----------

// Generation guard: if a second runAudit() starts before a slower first one
// finishes (e.g. a stray double-trigger, or clicking rescan while the
// external lookups are still in flight), the first run's late-arriving
// results must not be allowed to touch the DOM — that's what caused
// duplicated sections and a score that didn't match what was on screen.
let currentAuditId = 0;

async function runAudit() {
  const auditId = ++currentAuditId;
  const tab = await getActiveTab();
  const container = document.getElementById("sections");
  container.innerHTML = "";

  if (!tab || !tab.url || !/^https?:\/\//.test(tab.url)) {
    document.getElementById("targetUrl").textContent = "Open a regular http(s) page to scan it.";
    document.getElementById("scoreNum").textContent = "--";
    document.getElementById("scoreBand").style.display = "none";
    return;
  }

  document.getElementById("targetUrl").textContent = tab.url;
  const isHttps = tab.url.startsWith("https://");
  const isFirefox = typeof browser !== "undefined";

  const [cachedHeaderAudit, cookies, pageAudit] = await Promise.all([
    promiseMessage({ type: "GET_HEADER_AUDIT", tabId: tab.id }),
    promiseMessage({ type: "GET_COOKIES", url: tab.url }),
    promiseTabMessage(tab.id, { type: "GET_PAGE_AUDIT" })
  ]);

  const cacheUsable = cachedHeaderAudit && cachedHeaderAudit.url === tab.url && !cachedHeaderAudit.stale;
  let headerAudit = cacheUsable ? cachedHeaderAudit : null;
  let usedFallback = false;

  // Cache is missing/stale — most commonly because this tab is a single-page
  // app and the URL changed via history.pushState with no real network
  // request for the background script to observe. Fetch headers directly
  // instead of reporting everything as absent.
  if (!headerAudit) {
    try {
      const res = await fetch(tab.url, { credentials: "include", cache: "no-store" });
      const headers = {};
      res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
      headerAudit = { url: tab.url, headers, ip: null, security: null, statusCode: res.status };
      usedFallback = true;
    } catch (_) {
      headerAudit = null;
    }
  }

  const headerChecks = buildHeaderChecks(headerAudit && headerAudit.headers, isHttps);
  const rateLimitChecks = buildRateLimitChecks(headerAudit && headerAudit.headers);
  const accessControlChecks = buildAccessControlChecks(headerAudit && headerAudit.headers);
  const cookieChecks = buildCookieChecks(cookies, isHttps);
  const tlsChecks = buildTlsChecks(tab.url, headerAudit && headerAudit.security, isFirefox);
  const mixedChecks = buildMixedContentChecks(pageAudit && pageAudit.mixedContent);
  const libChecks = buildLibraryChecks(pageAudit && pageAudit.libraries);
  const formChecks = buildFormChecks(pageAudit && pageAudit.formIssues);

  const consentGiven = await CONSENT.ensureConsent();
  const hostname = new URL(tab.url).hostname;
  const ip = headerAudit && headerAudit.ip;

  await addCertExpiryCheck(tlsChecks, {
    isHttps,
    isFirefox,
    security: headerAudit && headerAudit.security,
    hostname,
    consentGiven
  });

  const [ownerInfo, vulnInfo, geoInfo] = consentGiven
    ? await Promise.all([
        NET.fetchOwnerInfo(hostname),
        NET.fetchCveInfo(headerAudit && headerAudit.headers ? headerAudit.headers : {}),
        NET.fetchGeolocation(ip)
      ])
    : [null, null, null];

  const ownerChecks = buildOwnerChecks(ownerInfo, consentGiven);
  const vulnChecks = buildVulnChecks(vulnInfo, consentGiven);
  const locationChecks = buildLocationChecks(geoInfo, consentGiven);

  // A newer run started while this one was still waiting on network calls
  // (RDAP/NVD/geolocation/crt.sh) — discard these results instead of
  // appending stale/duplicate sections on top of the current run's.
  if (auditId !== currentAuditId) return;

  // Re-clear in case a run that started after us already rendered and this
  // stale run is still somehow reaching this point — belt and suspenders
  // alongside the auditId check above.
  container.innerHTML = "";

  const all = [
    ...headerChecks, ...rateLimitChecks, ...accessControlChecks, ...cookieChecks, ...tlsChecks,
    ...mixedChecks, ...libChecks, ...formChecks,
    ...vulnChecks // only externally-sourced section that affects the risk score — ownership/location are informational only
  ];
  renderScore(all);

  container.appendChild(renderSection("headers", "Security Headers", headerChecks, true));
  container.appendChild(renderSection("ratelimit", "Rate Limiting", rateLimitChecks, false));
  container.appendChild(renderSection("acl", "Access Control (CORS)", accessControlChecks, false));
  container.appendChild(renderSection("tls", "TLS / Connection", tlsChecks, false));
  container.appendChild(renderSection("cookies", "Cookies", cookieChecks, false));
  container.appendChild(renderSection("mixed", "Mixed Content", mixedChecks, false));
  container.appendChild(renderSection("libs", "JS Library Vulnerabilities", libChecks, false));
  container.appendChild(renderSection("vulns", "Known Vulnerabilities (stack CVEs)", vulnChecks, false));
  container.appendChild(renderSection("forms", "Form Hygiene", formChecks, false));
  container.appendChild(renderSection("owner", "Domain & Organization", ownerChecks, false));
  container.appendChild(renderSection("location", "Server Location", locationChecks, false));

  if (!headerAudit) {
    const note = document.createElement("div");
    note.className = "empty";
    note.style.padding = "8px 16px";
    note.textContent = "Header data not yet captured for this tab — reload the page once, then re-scan.";
    container.prepend(note);
  } else if (usedFallback) {
    const note = document.createElement("div");
    note.className = "empty";
    note.style.padding = "8px 16px";
    note.textContent = "Fetched headers directly (this looks like a single-page app route change) — TLS certificate detail wasn't available for this pass.";
    container.prepend(note);
  }
}

document.getElementById("rescan").addEventListener("click", async (e) => {
  e.currentTarget.classList.add("spinning");
  await runAudit();
  setTimeout(() => e.currentTarget.classList.remove("spinning"), 400);
});

// ---------- theme ----------
async function initTheme() {
  const stored = await api.storage.local.get("theme");
  const theme = stored.theme || "dark";
  document.documentElement.dataset.theme = theme;
}

document.getElementById("themeToggle").addEventListener("click", async () => {
  const current = document.documentElement.dataset.theme === "light" ? "light" : "dark";
  const next = current === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = next;
  await api.storage.local.set({ theme: next });
});

initTheme();
runAudit();
