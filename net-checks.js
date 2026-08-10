// net-checks.js
// Everything in this file makes an outbound call to a third-party service.
// It is only ever invoked after the user has granted consent (see
// consent.js) — nothing here fires on page load or without an explicit
// audit run.

const NET = (() => {
  const TIMEOUT_MS = 6000;

  async function fetchJson(url, opts = {}) {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      const res = await fetch(url, { ...opts, signal: controller.signal });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } finally {
      clearTimeout(t);
    }
  }

  // ---------- Ownership: RDAP (modern WHOIS successor, JSON-over-HTTPS) ----------
  // rdap.org bootstraps to the correct registry automatically.
  async function fetchOwnerInfo(hostname) {
    const registrableDomain = hostname.split(".").slice(-2).join(".");
    try {
      const data = await fetchJson(`https://rdap.org/domain/${registrableDomain}`);
      const registrant = (data.entities || []).find((e) =>
        (e.roles || []).includes("registrant")
      ) || (data.entities || []).find((e) => (e.roles || []).includes("registrar"));

      let orgName = null;
      if (registrant && Array.isArray(registrant.vcardArray)) {
        const vcard = registrant.vcardArray[1] || [];
        const fnEntry = vcard.find((f) => f[0] === "fn" || f[0] === "org");
        orgName = fnEntry ? fnEntry[3] : null;
      }

      return {
        ok: true,
        domain: registrableDomain,
        organization: orgName || "Redacted / not disclosed by registry",
        registrar: (data.entities || []).find((e) => (e.roles || []).includes("registrar"))?.handle || null,
        events: (data.events || []).map((e) => ({ action: e.eventAction, date: e.eventDate }))
      };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  // ---------- Known vulnerabilities: fingerprint stack from headers, query NVD ----------
  function fingerprintStack(headers) {
    const products = [];
    const serverHeader = headers["server"];
    const poweredBy = headers["x-powered-by"];

    // e.g. "nginx/1.18.0 (Ubuntu)", "Apache/2.4.41"
    const serverMatch = serverHeader && serverHeader.match(/^([A-Za-z\-]+)\/([\d.]+)/);
    if (serverMatch) products.push({ product: serverMatch[1], version: serverMatch[2] });

    const poweredMatch = poweredBy && poweredBy.match(/^([A-Za-z.\-]+)\/?([\d.]+)?/);
    if (poweredMatch) products.push({ product: poweredMatch[1], version: poweredMatch[2] || null });

    return products;
  }

  // NVD's public API works keyless at a low rate limit (~5 req/30s) — fine
  // for a single popup audit, not for bulk scanning.
  async function fetchCveInfo(headers) {
    const stack = fingerprintStack(headers);
    if (stack.length === 0) {
      return { ok: true, stack: [], results: [] };
    }

    const results = [];
    for (const { product, version } of stack.slice(0, 2)) {
      const keyword = version ? `${product} ${version}` : product;
      try {
        const data = await fetchJson(
          `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=5`
        );
        const cves = (data.vulnerabilities || []).map((v) => ({
          id: v.cve.id,
          summary: (v.cve.descriptions.find((d) => d.lang === "en") || {}).value || "",
          severity:
            v.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ||
            v.cve.metrics?.cvssMetricV2?.[0]?.baseSeverity ||
            "UNKNOWN"
        }));
        results.push({ product, version, cves });
      } catch (err) {
        results.push({ product, version, error: err.message });
      }
    }
    return { ok: true, stack, results };
  }

  // ---------- Cert expiry fallback for Chrome: certificate transparency logs ----------
  async function fetchCertExpiryFromCT(hostname) {
    try {
      const data = await fetchJson(`https://crt.sh/?q=${encodeURIComponent(hostname)}&output=json`);
      if (!Array.isArray(data) || data.length === 0) {
        return { ok: false, error: "No certificate transparency records found" };
      }
      // crt.sh returns many entries (reissues, SANs); take the one with the
      // latest not_before, i.e. the most recently issued cert for this name.
      const newest = data.reduce((a, b) => (new Date(a.entry_timestamp) > new Date(b.entry_timestamp) ? a : b));
      return { ok: true, notBefore: newest.not_before, notAfter: newest.not_after, issuer: newest.issuer_name };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  // ---------- Server location: free IP -> geolocation, IP itself is already local (webRequest) ----------
  // ipwho.is (not ip-api.com) — free tier only serves plain HTTP, which
  // extension pages will block as a mixed-content/insecure request; ipwho.is
  // is HTTPS on the free tier with no key.
  async function fetchGeolocation(ip) {
    if (!ip) return { ok: false, error: "No resolved IP available for this request" };
    try {
      const data = await fetchJson(`https://ipwho.is/${ip}`);
      if (!data.success) return { ok: false, error: data.message || "Lookup failed" };
      return {
        ok: true,
        ip,
        country: data.country,
        region: data.region,
        city: data.city,
        isp: data.connection?.isp || null,
        org: data.connection?.org || null,
        asn: data.connection?.asn || null
      };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  return { fetchOwnerInfo, fetchCveInfo, fetchCertExpiryFromCT, fetchGeolocation, fingerprintStack };
})();
