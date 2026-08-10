// content.js
// Runs in the page context (isolated world). Scans the live DOM on request
// from the popup rather than caching at load time, so results reflect the
// page as it currently stands (post-lazy-load, post-SPA-navigation, etc).

function detectMixedContent() {
  if (location.protocol !== "https:") return { applicable: false, items: [] };

  const items = [];
  const selectors = [
    ["img[src]", "src", "image"],
    ["script[src]", "src", "script"],
    ["link[rel=stylesheet][href]", "href", "stylesheet"],
    ["iframe[src]", "src", "iframe"],
    ["audio[src]", "src", "audio"],
    ["video[src]", "src", "video"],
    ["source[src]", "src", "media source"]
  ];

  for (const [sel, attr, kind] of selectors) {
    document.querySelectorAll(sel).forEach((el) => {
      const raw = el.getAttribute(attr);
      if (raw && raw.trim().toLowerCase().startsWith("http://")) {
        items.push({ kind, url: raw });
      }
    });
  }
  return { applicable: true, items: items.slice(0, 50) };
}

function detectLibraries() {
  const found = [];
  const w = window;

  // jQuery
  if (w.jQuery && w.jQuery.fn && w.jQuery.fn.jquery) {
    found.push({ name: "jquery", label: "jQuery", version: w.jQuery.fn.jquery });
  }
  // AngularJS (1.x)
  if (w.angular && w.angular.version && w.angular.version.full) {
    found.push({ name: "angularjs", label: "AngularJS", version: w.angular.version.full });
  }
  // Lodash / Underscore
  if (w._ && w._.VERSION) {
    found.push({ name: "lodash", label: w._.templateSettings ? "Lodash/Underscore" : "Lodash", version: w._.VERSION });
  }
  // Moment
  if (w.moment && w.moment.version) {
    found.push({ name: "moment", label: "Moment.js", version: w.moment.version });
  }
  // Bootstrap (v4/v5 expose on jQuery.fn.tooltip.Constructor.VERSION, or bootstrap global in v5)
  try {
    if (w.bootstrap && w.bootstrap.Tooltip && w.bootstrap.Tooltip.VERSION) {
      found.push({ name: "bootstrap", label: "Bootstrap", version: w.bootstrap.Tooltip.VERSION });
    } else if (w.jQuery && w.jQuery.fn.tooltip && w.jQuery.fn.tooltip.Constructor && w.jQuery.fn.tooltip.Constructor.VERSION) {
      found.push({ name: "bootstrap", label: "Bootstrap", version: w.jQuery.fn.tooltip.Constructor.VERSION });
    }
  } catch { /* defensive - some Bootstrap builds don't expose this path */ }
  // Handlebars
  if (w.Handlebars && w.Handlebars.VERSION) {
    found.push({ name: "handlebars", label: "Handlebars", version: w.Handlebars.VERSION });
  }

  // Fallback: sniff version numbers out of script src filenames for libs
  // that don't expose a global (best-effort, lower confidence).
  const srcPattern = /(jquery|bootstrap|lodash|moment|handlebars|angular)[.\-]?(?:min\.)?js.*?(\d+\.\d+\.\d+)/i;
  document.querySelectorAll("script[src]").forEach((el) => {
    const m = el.src.match(srcPattern);
    if (m) {
      const key = m[1].toLowerCase() === "angular" ? "angularjs" : m[1].toLowerCase();
      if (!found.some((f) => f.name === key)) {
        found.push({ name: key, label: m[1], version: m[2], source: "filename-guess" });
      }
    }
  });

  const withVulns = found.map((lib) => ({
    ...lib,
    vulnerabilities: (self.SentryVulnDB ? self.SentryVulnDB.checkLibrary(lib.name, lib.version) : [])
  }));

  return withVulns;
}

function auditForms() {
  const issues = [];
  document.querySelectorAll("form").forEach((form) => {
    const action = form.getAttribute("action") || location.href;
    let resolvedHttp = false;
    try {
      resolvedHttp = new URL(action, location.href).protocol === "http:";
    } catch { /* relative/invalid action, skip protocol check */ }

    const hasPassword = !!form.querySelector('input[type="password"]');

    if (hasPassword && resolvedHttp) {
      issues.push({ type: "password-over-http", detail: `Form posts to ${action}` });
    }
    if (hasPassword && form.querySelector('input[type="password"]:not([autocomplete="new-password"]):not([autocomplete="current-password"])')) {
      issues.push({ type: "password-autocomplete", detail: "Password field has no explicit autocomplete attribute" });
    }
  });
  return issues;
}

if (typeof browser !== "undefined" ? true : typeof chrome !== "undefined") {
  const api = typeof browser !== "undefined" ? browser : chrome;
  api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "GET_PAGE_AUDIT") {
      sendResponse({
        mixedContent: detectMixedContent(),
        libraries: detectLibraries(),
        formIssues: auditForms()
      });
      return true;
    }
  });
}
