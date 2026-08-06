const emailInput = document.getElementById("emailInput");
const scanBtn = document.getElementById("scanBtn");
const sampleBtn = document.getElementById("sampleBtn");
const resultPanel = document.getElementById("resultPanel");
const errorMsg = document.getElementById("errorMsg");

const SAMPLE_PHISH = `Dear Customer,

Unusual sign-in activity detected on your Apple ID account. Your account will be permanently closed within 24 hours unless you verify your identity.

Click here to verify: http://secure-appleid-verify.info/confirm

Please act now to prevent unauthorized access to your account. This is an automated security message from the Apple ID team.

If you do not respond within 24 hours your account access will be revoked.`;

sampleBtn.addEventListener("click", () => {
  emailInput.value = SAMPLE_PHISH;
});

scanBtn.addEventListener("click", async () => {
  const text = emailInput.value.trim();
  errorMsg.textContent = "";
  if (!text) {
    errorMsg.textContent = "Paste an email body first.";
    return;
  }

  scanBtn.disabled = true;
  const originalLabel = scanBtn.querySelector(".btn-label").textContent;
  scanBtn.querySelector(".btn-label").textContent = "Scanning...";

  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email_text: text }),
    });
    const data = await res.json();

    if (!res.ok) {
      errorMsg.textContent = data.error || "Something went wrong.";
      return;
    }
    renderResult(data);
  } catch (err) {
    errorMsg.textContent = "Could not reach the analysis server.";
  } finally {
    scanBtn.disabled = false;
    scanBtn.querySelector(".btn-label").textContent = originalLabel;
  }
});

function renderResult(data) {
  const isPhish = data.verdict === "Phishing";
  const b = data.breakdown;

  resultPanel.innerHTML = `
    <div class="verdict-card">
      <div class="verdict-top">
        <div>
          <div class="verdict-label">VERDICT</div>
          <div class="verdict-title ${isPhish ? "phishing" : "safe"}">${data.verdict}</div>
        </div>
        <div class="confidence-ring" style="color: ${isPhish ? "var(--danger)" : "var(--safe)"}">
          ${data.confidence}%
        </div>
      </div>

      <div class="bar-row">
        <span>Phishing</span>
        <div class="bar-track"><div class="bar-fill phish" style="width:${data.phishing_probability}%"></div></div>
        <span>${data.phishing_probability}%</span>
      </div>
      <div class="bar-row">
        <span>Safe</span>
        <div class="bar-track"><div class="bar-fill safe" style="width:${data.safe_probability}%"></div></div>
        <span>${data.safe_probability}%</span>
      </div>

      <div class="breakdown">
        <div class="breakdown-item"><span>URLs found</span><span class="${b.n_urls > 0 ? "" : ""}">${b.n_urls}</span></div>
        <div class="breakdown-item"><span>Raw-IP link</span><span class="${b.has_ip_url ? "flag-yes" : ""}">${b.has_ip_url ? "Yes" : "No"}</span></div>
        <div class="breakdown-item"><span>Suspicious TLD</span><span class="${b.has_suspicious_tld ? "flag-yes" : ""}">${b.has_suspicious_tld ? "Yes" : "No"}</span></div>
        <div class="breakdown-item"><span>Urgency score</span><span class="${b.urgency_score > 2 ? "flag-yes" : ""}">${b.urgency_score}</span></div>
      </div>
    </div>
  `;
}
