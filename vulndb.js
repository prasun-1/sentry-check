// vulndb.js
// A small, hand-curated subset of publicly documented CVEs for widely used
// front-end libraries. This is NOT a replacement for retire.js/Snyk — it's
// enough to demonstrate the detection technique: fingerprint a library +
// version from the page, compare against known-bad ranges.
//
// Each entry: { test(version) -> bool, id, summary, severity }

const VULN_DB = {
  jquery: [
    {
      test: (v) => cmpVersion(v, "3.5.0") < 0,
      id: "CVE-2020-11022 / CVE-2020-11023",
      summary: "jQuery <3.5.0: passing untrusted HTML to .html()/.append() etc. can execute injected <script>/<option> content (XSS).",
      severity: "high"
    },
    {
      test: (v) => cmpVersion(v, "3.0.0") < 0,
      id: "CVE-2015-9251",
      summary: "jQuery <3.0.0: cross-domain Ajax requests via jQuery.ajax() can execute attacker JS (XSS).",
      severity: "high"
    }
  ],
  angularjs: [
    {
      test: (v) => cmpVersion(v, "1.8.0") < 0,
      id: "CVE-2020-7676",
      summary: "AngularJS <1.8.0: sandbox bypass in bindings can lead to XSS. Note: AngularJS (1.x) is end-of-life.",
      severity: "high"
    }
  ],
  lodash: [
    {
      test: (v) => cmpVersion(v, "4.17.21") < 0,
      id: "CVE-2020-8203 / CVE-2021-23337",
      summary: "Lodash <4.17.21: prototype pollution in zipObjectDeep and command injection in template().",
      severity: "high"
    }
  ],
  moment: [
    {
      test: (v) => cmpVersion(v, "2.29.4") < 0,
      id: "CVE-2022-31129",
      summary: "Moment.js <2.29.4: inefficient parsing regex enables ReDoS on crafted date strings.",
      severity: "medium"
    }
  ],
  bootstrap: [
    {
      test: (v) => cmpVersion(v, "4.3.1") < 0,
      id: "CVE-2019-8331",
      summary: "Bootstrap <4.3.1: data-target/href attributes in tooltip/popover/carousel not sanitized (XSS).",
      severity: "medium"
    }
  ],
  handlebars: [
    {
      test: (v) => cmpVersion(v, "4.7.7") < 0,
      id: "CVE-2021-23383",
      summary: "Handlebars <4.7.7: crafted templates can lead to prototype pollution / remote code execution.",
      severity: "high"
    }
  ]
};

// Minimal dotted-version comparator: returns -1, 0, 1.
function cmpVersion(a, b) {
  const pa = String(a).split(/[.\-+]/).map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split(/[.\-+]/).map((n) => parseInt(n, 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

function checkLibrary(name, version) {
  const rules = VULN_DB[name];
  if (!rules || !version) return [];
  return rules.filter((r) => {
    try {
      return r.test(version);
    } catch {
      return false;
    }
  });
}

// Exposed for content.js (classic script, shared global scope in MV3 content scripts)
self.SentryVulnDB = { checkLibrary, cmpVersion };
