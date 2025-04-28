import re
import ipaddress
import tldextract
import whois          # pip install python-whois
from datetime import datetime
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
import argparse
import pickle

def has_ip(url: str) -> int:
    try:
        host = re.findall(r'://([^/]+)', url)[0]
        ipaddress.ip_address(host)
        return 1
    except Exception:
        return 0

def url_length(url: str) -> int:
    return len(url)

def count_special_chars(url: str) -> int:
    return sum(url.count(c) for c in ['-', '@', '?', '%', '.', '=', '&', '_'])

def subdomain_count(url: str) -> int:
    ext = tldextract.extract(url)
    return 0 if ext.subdomain == '' else ext.subdomain.count('.') + 1

def has_at_symbol(url: str) -> int:
    return 1 if '@' in url else 0

def count_double_slashes(url: str) -> int:
    path = re.sub(r'^[a-zA-Z]+://', '', url)
    return max(0, path.count('//') - 1)

def is_https(url: str) -> int:
    return 1 if url.lower().startswith('https://') else 0

def domain_age_days(url: str) -> float:
    ext = tldextract.extract(url)
    domain = ext.registered_domain
    try:
        w = whois.whois(domain)
        cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        return (datetime.now() - cd).days
    except Exception:
        return -1

def extract_features(url: str) -> list:
    return [
        has_ip(url),
        url_length(url),
        count_special_chars(url),
        subdomain_count(url),
        has_at_symbol(url),
        count_double_slashes(url),
        is_https(url),
        domain_age_days(url),
    ]

def train_model(dataset_path: str, model_path: str, test_size: float = 0.2):
    df = pd.read_csv(dataset_path)
    feature_dicts = [dict(zip(
        ['has_ip', 'length', 'special_chars', 'subdomains',
         'has_at', 'double_slashes', 'is_https', 'domain_age'],
        extract_features(u)
    )) for u in df['url']]
    X = pd.DataFrame(feature_dicts)
    y = df['label']
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y
    )
    model = LogisticRegression(max_iter=2000)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    print(f"Model saved to {model_path}")


def load_model(model_path: str):
    with open(model_path, 'rb') as f:
        return pickle.load(f)

def predict_urls(urls: list, model):
    for url in urls:
        feat = extract_features(url)
        pred = model.predict([feat])[0]
        label = 'PHISH' if pred == 1 else 'LEGIT'
        print(f"{url} -> {label}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phishing URL Detector CLI")
    parser.add_argument('-d', '--dataset', help='Path to CSV dataset (url,label)')
    parser.add_argument('-m', '--model', default='phish_model.pkl', help='Path to save/load model')
    parser.add_argument('-t', '--test-size', type=float, default=0.2, help='Test size for training split')
    parser.add_argument('-u', '--urls', nargs='+', help='One or more URLs to predict')
    args = parser.parse_args()

    if args.dataset:
        train_model(args.dataset, args.model, args.test_size)

    if args.urls:
        model = load_model(args.model)
        predict_urls(args.urls, model)
