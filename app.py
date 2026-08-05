import re
import json
import joblib
import numpy as np
from flask import Flask, request, jsonify, render_template
from scipy.sparse import hstack, csr_matrix

app = Flask(__name__)

MODEL_DIR = "model"
model = joblib.load(f"{MODEL_DIR}/model.joblib")
vectorizer = joblib.load(f"{MODEL_DIR}/vectorizer.joblib")
max_vals = joblib.load(f"{MODEL_DIR}/feature_maxvals.joblib")
with open(f"{MODEL_DIR}/metrics.json") as f:
    METRICS = json.load(f)

URL_RE = re.compile(r"https?://[^\s]+")
IP_URL_RE = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
SUSPICIOUS_TLDS = (".ru", ".info", ".xyz", ".top", ".click")
URGENT_WORDS = [
    "verify", "suspend", "urgent", "immediately", "confirm", "click here",
    "password", "account", "expire", "act now", "locked", "security alert",
    "unauthorized", "update your", "won", "prize", "limited time",
]


def extract_features(text):
    low = text.lower()
    urls = URL_RE.findall(text)
    n_urls = len(urls)
    has_ip_url = 1 if IP_URL_RE.search(text) else 0
    has_susp_tld = 1 if any(tld in low for tld in SUSPICIOUS_TLDS) else 0
    urgent_count = sum(low.count(w) for w in URGENT_WORDS)
    exclaim_count = text.count("!")
    length = len(text)
    return np.array([[n_urls, has_ip_url, has_susp_tld, urgent_count, exclaim_count, length]], dtype=float), {
        "urls_found": urls,
        "n_urls": n_urls,
        "has_ip_url": bool(has_ip_url),
        "has_suspicious_tld": bool(has_susp_tld),
        "urgency_score": urgent_count,
        "exclamations": exclaim_count,
    }


@app.route("/")
def index():
    return render_template("index.html", metrics=METRICS)


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(force=True)
    text = (data.get("email_text") or "").strip()
    if not text:
        return jsonify({"error": "Paste an email body first."}), 400

    tfidf_vec = vectorizer.transform([text])
    extra_vec, breakdown = extract_features(text)
    extra_vec_n = extra_vec / max_vals
    X = hstack([tfidf_vec, csr_matrix(extra_vec_n)])

    pred = model.predict(X)[0]
    proba = model.predict_proba(X)[0]
    confidence = round(float(max(proba)) * 100, 2)
    verdict = "Phishing" if pred == 1 else "Safe"

    return jsonify({
        "verdict": verdict,
        "confidence": confidence,
        "phishing_probability": round(float(proba[1]) * 100, 2),
        "safe_probability": round(float(proba[0]) * 100, 2),
        "breakdown": breakdown,
    })


@app.route("/api/metrics")
def metrics():
    return jsonify(METRICS)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
