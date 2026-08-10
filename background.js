// background.js
// Captures response headers for the main-frame request of each tab, and
// (on Firefox) pulls certificate/TLS detail via webRequest.getSecurityInfo.
// Chrome's webRequest API does not expose certificate data to extensions —
// that gap is documented in the popup rather than silently ignored.

const tabAudits = new Map(); // tabId -> { url, headers, security, timestamp }
const isFirefox = typeof browser !== "undefined";
const api = isFirefox ? browser : chrome;

function headersToMap(headersArray) {
  const map = {};
  for (const h of headersArray || []) {
    map[h.name.toLowerCase()] = h.value;
  }
  return map;
}

api.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type !== "main_frame") return;

    const entry = {
      url: details.url,
      statusCode: details.statusCode,
      headers: headersToMap(details.responseHeaders),
      ip: details.ip || null, // resolved server IP — free from webRequest, no external call
      timestamp: Date.now(),
      security: null
    };

    tabAudits.set(details.tabId, entry);

    // Firefox-only: real TLS/certificate detail for this exact request.
    if (isFirefox && details.url.startsWith("https://")) {
      browser.webRequest
        .getSecurityInfo(details.requestId, { certificateChain: true })
        .then((info) => {
          const cur = tabAudits.get(details.tabId);
          if (!cur || cur.url !== details.url) return;
          const cert = info.certificates && info.certificates[0];
          cur.security = {
            state: info.state, // "secure" | "broken" | "insecure"
            protocolVersion: info.protocolVersion,
            cipherSuite: info.cipherSuite,
            issuer: cert ? cert.issuer : null,
            subject: cert ? cert.subject : null,
            validFrom: cert ? cert.validity.start : null,
            validTo: cert ? cert.validity.end : null,
            isDomainMismatch: info.isDomainMismatch,
            isExtendedValidation: info.isExtendedValidation,
            isNotValidAtThisTime: info.isNotValidAtThisTime,
            isUntrusted: info.isUntrusted
          };
          tabAudits.set(details.tabId, cur);
        })
        .catch(() => {
          /* getSecurityInfo unsupported for this request type — ignore */
        });
    }

    return {};
  },
  { urls: ["http://*/*", "https://*/*"], types: ["main_frame"] },
  ["responseHeaders"]
);

// Clean up when a tab navigates away or closes, so stale audits aren't served.
api.tabs.onRemoved.addListener((tabId) => {
  tabAudits.delete(tabId);
  for (const key of notifiedNav.keys()) {
    if (key.startsWith(`${tabId}::`)) notifiedNav.delete(key);
  }
});
api.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId === 0) tabAudits.delete(details.tabId);
});

// SPAs (React/Vue/etc, including this exact page) change the URL via
// history.pushState with no real network request — onHeadersReceived never
// fires again, so the cached entry is left pointing at the old URL. This is
// what caused the "false missing headers" bug: onHistoryStateUpdated is the
// dedicated event for that case. We can't re-fetch headers here (no new
// request happens), so we mark the entry stale and let the popup fall back
// to a direct fetch() for the current URL instead of trusting a cached
// snapshot that no longer matches what's on screen.
api.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId !== 0) return;
  const cur = tabAudits.get(details.tabId);
  if (cur && cur.url !== details.url) {
    cur.stale = true;
    updateBadge(details.tabId, details.url);
  }
});

// ---------- badge: lightweight auto-check on every navigation ----------
// Extensions cannot programmatically open their own toolbar popup on page
// load — Chrome and Firefox both restrict action.openPopup() to direct user
// gestures (a real click, or a keyboard command), specifically so a
// misbehaving extension can't spam a popup open on every page you visit.
// The supported way to surface "something changed, worth a look" without a
// click is the toolbar badge, so that's what runs automatically here — the
// full popup audit still needs you to click the icon.
function quickBadgeScore(headers, cookies, isHttps) {
  let critical = 0, warning = 0;
  headers = headers || {};
  if (!headers["content-security-policy"]) warning++;
  if (isHttps && !headers["strict-transport-security"]) warning++;
  if (headers["x-content-type-options"] !== "nosniff") warning++;
  if (!headers["x-frame-options"] && !(headers["content-security-policy"] || "").includes("frame-ancestors")) warning++;
  for (const c of cookies || []) {
    if (isHttps && !c.secure) critical++;
    if (!c.httpOnly) warning++;
  }
  return { critical, warning };
}

async function updateBadge(tabId, url) {
  if (!url || !/^https?:\/\//.test(url)) {
    api.action.setBadgeText({ tabId, text: "" });
    return;
  }
  const isHttps = url.startsWith("https://");
  const entry = tabAudits.get(tabId);
  const headers = entry && entry.url === url ? entry.headers : null;
  let cookies = [];
  try {
    cookies = await api.cookies.getAll({ url });
  } catch (_) { /* ignore */ }

  const { critical, warning } = quickBadgeScore(headers, cookies, isHttps);
  const total = critical + warning;

  api.action.setBadgeText({ tabId, text: total > 0 ? String(total) : "" });
  api.action.setBadgeBackgroundColor({
    tabId,
    color: critical > 0 ? "#e0473f" : warning > 0 ? "#d98c1f" : "#6ea666"
  });

  maybeNotify(tabId, url, critical);
}

// ---------- desktop notification: the genuine "auto alert" ----------
// Unlike the badge, this fires without the user looking at the toolbar at
// all — it's the actual equivalent of "pop something up when a new page
// loads." Scoped to critical findings only (by explicit choice) so it
// doesn't fire on every single page, which would make it noise you'd
// start ignoring. Deduped per tab+URL so re-focusing the same tab or a
// SPA re-render on the same URL doesn't refire it.
const notifiedNav = new Map(); // `${tabId}::${url}` -> true

function maybeNotify(tabId, url, criticalCount) {
  if (criticalCount <= 0) return;
  const key = `${tabId}::${url}`;
  if (notifiedNav.has(key)) return;
  notifiedNav.set(key, true);

  let hostname = url;
  try { hostname = new URL(url).hostname; } catch (_) { /* keep raw url */ }

  api.notifications.create(`sentry-check-${tabId}-${Date.now()}`, {
    type: "basic",
    iconUrl: api.runtime.getURL("icons/icon48.png"),
    title: "Sentry Check — critical finding",
    message: `${hostname} has ${criticalCount} critical issue${criticalCount > 1 ? "s" : ""}. Click the toolbar icon for details.`,
    priority: 2
  });
}

api.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) updateBadge(tabId, tab.url);
});
api.tabs.onActivated.addListener(({ tabId }) => {
  api.tabs.get(tabId).then((tab) => tab.url && updateBadge(tabId, tab.url));
});

api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_HEADER_AUDIT") {
    const tabId = message.tabId;
    sendResponse(tabAudits.get(tabId) || null);
    return true;
  }

  if (message.type === "GET_COOKIES") {
    api.cookies
      .getAll({ url: message.url })
      .then((cookies) => sendResponse(cookies))
      .catch(() => sendResponse([]));
    return true; // async
  }
});
