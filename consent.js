// consent.js
// Gates the four checks that call third-party services (owner lookup,
// known-vulnerability lookup, Chrome cert-expiry fallback, geolocation).
// Asked once; the choice is remembered in extension storage.

const CONSENT = (() => {
  const api = typeof browser !== "undefined" ? browser : chrome;
  const KEY = "externalChecksConsent"; // undefined = not yet asked, true/false = decided

  async function getStored() {
    const res = await api.storage.local.get(KEY);
    return res[KEY]; // undefined | true | false
  }

  async function setStored(value) {
    await api.storage.local.set({ [KEY]: value });
  }

  // Resolves to true/false. Shows the modal and waits for a click if the
  // user hasn't decided yet; otherwise resolves immediately from storage.
  async function ensureConsent() {
    const existing = await getStored();
    if (existing !== undefined) return existing;

    return new Promise((resolve) => {
      const modal = document.getElementById("consentModal");
      modal.classList.add("open");

      const finish = async (value) => {
        modal.classList.remove("open");
        await setStored(value);
        resolve(value);
      };

      document.getElementById("consentAllow").onclick = () => finish(true);
      document.getElementById("consentSkip").onclick = () => finish(false);
    });
  }

  return { ensureConsent, getStored, setStored };
})();
