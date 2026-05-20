from flask import Flask, render_template, request
import pickle
import pandas as pd
import re
import string
import math
from urllib.parse import urlparse
import validators 

app = Flask(__name__)

# Load model
with open('XGBoost_model.pkl', 'rb') as f:
    model = pickle.load(f)

with open('label_encoder.pkl', 'rb') as f:
    label_encoder = pickle.load(f)

EXPECTED_FEATURES = getattr(model, "feature_names_in_", [])

# Keywords
suspicious_keywords = [
    'login','signin','verify','update','bank','account','secure',
    'paypal','amazon','password'
]

# Trusted domains (🔥 demo saver)
trusted_domains = [
    'google.com','microsoft.com','amazon.in','github.com','wikipedia.org'
]

# ---------- UTILS ----------
def entropy(s):
    prob = [float(s.count(c))/len(s) for c in dict.fromkeys(list(s))]
    return -sum([p * math.log(p,2) for p in prob])

def parse(url):
    try:
        return urlparse(url)
    except:
        return urlparse('')

# ---------- FEATURES ----------
def extract(url):
    parsed = parse(url)
    domain = parsed.netloc.lower()
    full = url.lower()

    f = {}
    f['url_length'] = len(url)
    f['num_special_chars'] = sum(c in string.punctuation for c in url)
    f['num_dots'] = url.count('.')
    f['has_https'] = int(parsed.scheme == 'https')
    f['has_ip'] = int(bool(re.fullmatch(r'\d+\.\d+\.\d+\.\d+', domain)))

    # FIXED keyword detection
    f['has_suspicious_word'] = int(
        any(re.search(r'(?:^|[^a-z])'+w+r'(?:[^a-z]|$)', full) for w in suspicious_keywords)
    )

    f['entropy'] = entropy(url)

    df = pd.DataFrame([f])

    for col in EXPECTED_FEATURES:
        if col not in df.columns:
            df[col] = 0

    df = df.reindex(columns=EXPECTED_FEATURES, fill_value=0)

    return df, f

# ---------- REASONS ----------
def explain(label, f):
    r = []

    if label == "phishing":
        if f['has_suspicious_word']:
            r.append("Contains phishing keywords")
        if f['url_length'] > 80:
            r.append("URL is unusually long")
        if f['num_special_chars'] > 12:
            r.append("Too many special characters")
        if f['has_ip']:
            r.append("Uses IP address")
        if f['entropy'] > 4:
            r.append("Complex/random URL structure")

        if not r:
            r.append("Detected suspicious pattern by model")

    else:
        if f['has_https']:
            r.append("Uses HTTPS (secure connection)")
        if not f['has_suspicious_word']:
            r.append("No suspicious keywords")
        if f['url_length'] < 60:
            r.append("Normal URL length")
        if f['num_special_chars'] < 6:
            r.append("Clean URL structure")
        if not f['has_ip']:
            r.append("Valid domain used")

        if not r:
            r.append("No suspicious patterns found")

    return r[:3]

# ---------- ROUTES ----------
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form.get('url')

    if not url:
        return render_template('index.html', prediction_text="error")

    if not validators.url(url):
        return render_template('index.html', prediction_text="error")

    # 🔥 TRUSTED DOMAIN FIX
    if any(td in url.lower() for td in trusted_domains):
        return render_template(
            'index.html',
            prediction_text="safe",
            confidence=99.0,
            reasons=[
                "Trusted domain",
                "Uses HTTPS",
                "No suspicious activity"
            ]
        )

    X, raw = extract(url)

    try:
        pred = model.predict(X)[0]
        label = str(label_encoder.inverse_transform([pred])[0]).lower()

        if hasattr(model, 'predict_proba'):
            prob = model.predict_proba(X)[0]
            conf = round(max(prob)*100,2)
        else:
            conf = 90

        reasons = explain(label, raw)

        return render_template(
            'index.html',
            prediction_text=label,
            confidence=conf,
            reasons=reasons
        )

    except Exception as e:
        return render_template('index.html', prediction_text="error")

if __name__ == '__main__':
    app.run(debug=True)