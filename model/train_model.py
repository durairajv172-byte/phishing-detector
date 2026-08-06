"""
Trains a phishing email detection model.
- TF-IDF text features + hand-engineered features (URL count, IP-based URLs,
  urgency keyword count, exclamation count, suspicious TLDs).
- Logistic Regression classifier.
- Saves model.joblib, vectorizer.joblib, metrics.json, confusion_matrix.png
"""
import re
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

DATA_PATH = "/home/claude/phishing-detector/data/emails.csv"
MODEL_DIR = "/home/claude/phishing-detector/model"

URL_RE = re.compile(r"https?://[^\s]+")
IP_URL_RE = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
SUSPICIOUS_TLDS = (".ru", ".info", ".xyz", ".top", ".click", ".click.com")
URGENT_WORDS = [
    "verify", "suspend", "urgent", "immediately", "confirm", "click here",
    "password", "account", "expire", "act now", "locked", "security alert",
    "unauthorized", "update your", "won", "prize", "limited time",
]


def extract_features(texts):
    """Hand-engineered numeric features per email."""
    feats = []
    for t in texts:
        low = t.lower()
        urls = URL_RE.findall(t)
        n_urls = len(urls)
        has_ip_url = 1 if IP_URL_RE.search(t) else 0
        has_susp_tld = 1 if any(tld in low for tld in SUSPICIOUS_TLDS) else 0
        urgent_count = sum(low.count(w) for w in URGENT_WORDS)
        exclaim_count = t.count("!")
        length = len(t)
        feats.append([n_urls, has_ip_url, has_susp_tld, urgent_count, exclaim_count, length])
    return np.array(feats, dtype=float)


def main():
    df = pd.read_csv(DATA_PATH)
    X_text = df["text"].values
    y = df["label"].values

    X_train_text, X_test_text, y_train, y_test = train_test_split(
        X_text, y, test_size=0.2, random_state=42, stratify=y
    )

    vectorizer = TfidfVectorizer(max_features=3000, stop_words="english", ngram_range=(1, 2))
    X_train_tfidf = vectorizer.fit_transform(X_train_text)
    X_test_tfidf = vectorizer.transform(X_test_text)

    X_train_extra = extract_features(X_train_text)
    X_test_extra = extract_features(X_test_text)

    # normalize extra features by max on train set to keep scale reasonable
    max_vals = X_train_extra.max(axis=0)
    max_vals[max_vals == 0] = 1
    X_train_extra_n = X_train_extra / max_vals
    X_test_extra_n = X_test_extra / max_vals

    X_train = hstack([X_train_tfidf, csr_matrix(X_train_extra_n)])
    X_test = hstack([X_test_tfidf, csr_matrix(X_test_extra_n)])

    clf = LogisticRegression(max_iter=1000, C=5.0)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=["Safe", "Phishing"], output_dict=True)

    print(f"Accuracy: {acc:.4f}")
    print(cm)

    # Save confusion matrix plot
    fig, ax = plt.subplots(figsize=(4.5, 4))
    im = ax.imshow(cm, cmap="Greens")
    ax.set_xticks([0, 1]); ax.set_xticklabels(["Safe", "Phishing"])
    ax.set_yticks([0, 1]); ax.set_yticklabels(["Safe", "Phishing"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
    ax.set_title(f"Confusion Matrix (Accuracy: {acc*100:.1f}%)")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(cm[i, j]), ha="center", va="center",
                     color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=14, fontweight="bold")
    fig.colorbar(im, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(f"{MODEL_DIR}/confusion_matrix.png", dpi=150)

    joblib.dump(clf, f"{MODEL_DIR}/model.joblib")
    joblib.dump(vectorizer, f"{MODEL_DIR}/vectorizer.joblib")
    joblib.dump(max_vals, f"{MODEL_DIR}/feature_maxvals.joblib")

    metrics = {
        "accuracy": round(acc * 100, 2),
        "confusion_matrix": cm.tolist(),
        "labels": ["Safe", "Phishing"],
        "precision_phishing": round(report["Phishing"]["precision"] * 100, 2),
        "recall_phishing": round(report["Phishing"]["recall"] * 100, 2),
        "f1_phishing": round(report["Phishing"]["f1-score"] * 100, 2),
        "train_size": len(X_train_text),
        "test_size": len(X_test_text),
    }
    with open(f"{MODEL_DIR}/metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    print("Saved model, vectorizer, metrics.json, confusion_matrix.png")


if __name__ == "__main__":
    main()
