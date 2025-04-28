# detectphish

A Python-based command-line tool for detecting phishing URLs using feature extraction and machine learning.

## Features

- Detects URLs hosting an IP address
- Measures URL length
- Counts special characters (e.g., `-`, `@`, `?`, `%`, `=`, `&`, `_`)
- Counts number of subdomains
- Checks for `@` symbol in URL
- Counts extra `//` occurrences in path
- Flags HTTPS vs HTTP
- Calculates domain age (in days) via WHOIS lookup
- Trains a logistic regression classifier and saves the model
- Provides a CLI for both training and prediction

## Requirements

- Python 3.8+
- Dependencies listed in `requirements.txt`:
  ```txt
  pandas
  scikit-learn
  tldextract
  python-whois
  ```

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/detectphish.git
   cd detectphish
   ```
2. Create a virtual environment and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

## Usage

### Train a model

```bash
python detectphish.py --dataset path/to/phishing_dataset.csv --model phish_model.pkl
```

- `--dataset`: CSV file containing two columns: `url` and `label` (1 for phishing, 0 for legitimate)
- `--model`: Path to save the trained model (default: `phish_model.pkl`)

The script will output accuracy and classification report, then save the model.

### Predict URLs

```bash
python detectphish.py --model phish_model.pkl --urls <url1> <url2> ...
```

Example:

```bash
python detectphish.py --model phish_model.pkl \
  --urls http://192.168.0.1/login.php https://www.google.com http://bit.ly@malicious//pay
```

Sample output:

http://192.168.0.1/login.php -> PHISH
https://www.google.com      -> LEGIT
http://bit.ly@malicious//pay -> PHISH


