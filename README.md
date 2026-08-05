# Wardline — Phishing Email Detection Model

A web app (Flask + Scikit-learn) that classifies pasted email text as **Phishing** or **Safe**.

## What it does
- Trains a Logistic Regression classifier on TF-IDF text features (unigrams + bigrams)
  combined with hand-engineered features: URL count, raw-IP links, suspicious TLDs,
  an urgency-keyword score, exclamation count, and message length.
- Web UI lets you paste any email body and get an instant verdict with confidence
  scores and a feature breakdown.
- Displays model accuracy, precision/recall/F1, and a confusion matrix computed on
  a held-out 20% test split.

## Project structure
```
phishing-detector/
├── app.py                 # Flask app (routes: / , /api/analyze , /api/metrics)
├── data/
│   ├── generate_dataset.py  # builds the synthetic labeled dataset
│   └── emails.csv           # 360 emails (180 phishing / 180 legit)
├── model/
│   ├── train_model.py     # trains + evaluates + saves the model
│   ├── model.joblib
│   ├── vectorizer.joblib
│   ├── feature_maxvals.joblib
│   ├── metrics.json
│   └── confusion_matrix.png
├── templates/index.html
├── static/style.css, app.js, confusion_matrix.png
└── requirements.txt
```

## Run it locally
```bash
pip install -r requirements.txt

# (optional) regenerate the dataset and retrain
python3 data/generate_dataset.py
python3 model/train_model.py

# start the web app
python3 app.py
```
Then open **http://localhost:5000** in your browser.

## Swapping in a real dataset
Replace `data/emails.csv` with any CSV that has `text` and `label` columns
(`label`: 1 = phishing, 0 = safe) — e.g. the Kaggle "Phishing Email Dataset" or the
Nazario phishing corpus — then rerun `train_model.py`. No other code changes needed.

## Notes for the assignment writeup
- **Key features implemented**: dataset training, URL/keyword feature extraction,
  Phishing/Safe classification, accuracy + confusion matrix display — all present.
- The bundled dataset is synthetic (template-generated) so the demo works out of the
  box; swap in a real-world dataset before drawing conclusions from the accuracy number.
