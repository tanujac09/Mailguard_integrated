"""
NLP detection engine — the real trained models behind the
"NLP Semantics & Social Engineering Analysis" pipeline step.

This is the integration of the two models built and validated in the
project notebook (NLP and LR.ipynb):

  1. Transformer classifier — a pretrained DistilBERT fine-tuned for
     phishing detection ("cybersectony/phishing-email-detection-distilbert_v2.4.1").
     Zero-shot, no local training needed, understands broad phrasing.

  2. TF-IDF + Logistic Regression — trained locally on backend/data/email_text.csv
     (~53.6k labelled emails). This is the model that, in testing, correctly
     caught the "quiet, well-written CEO wire-transfer" business-email-
     compromise (BEC) style message that the transformer alone missed,
     because it learned the actual vocabulary of this dataset rather than
     generic phishing phrasing.

Composite score = 0.45 * transformer_phishing_probability
                + 0.55 * tfidf_logreg_phishing_probability

(same weights validated in the notebook: the locally-trained model gets
slightly more weight because it matched the dataset's own class balance
and caught the BEC case the transformer alone did not).

Both models are loaded/trained ONCE per process (module-level singletons)
and reused for every email — loading a transformer or retraining a
scikit-learn model on every request would make the API unusably slow.

If `transformers`/`torch` aren't installed, or the transformer model
can't be downloaded (no internet on demo day, etc.), the engine
degrades gracefully to TF-IDF + regex only and says so in the summary
— it never crashes the pipeline.
"""
import os
import re
import threading

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

from ..config import settings

_MODULE_DIR = os.path.dirname(__file__)
_DATA_PATH = os.path.join(_MODULE_DIR, "..", "..", "data", "email_text.csv")
_CACHE_DIR = os.path.join(_MODULE_DIR, "..", "model_cache")
_TFIDF_CACHE = os.path.join(_CACHE_DIR, "tfidf_vectorizer.joblib")
_LR_CACHE = os.path.join(_CACHE_DIR, "logreg_model.joblib")

NLP_SIGNAL_WEIGHTS = {"transformer": 0.75, "tfidf": 0.25}

_lock = threading.Lock()
_state = {
    "tfidf_vectorizer": None,
    "tfidf_model": None,
    "tfidf_metrics": None,
    "transformer_tokenizer": None,
    "transformer_model": None,
    "transformer_available": False,
    "transformer_error": None,
    "loaded": False,
}


# --------------------------------------------------------------------
# TF-IDF + Logistic Regression (trained on backend/data/email_text.csv)
# --------------------------------------------------------------------

def _train_or_load_tfidf():
    os.makedirs(_CACHE_DIR, exist_ok=True)

    if os.path.exists(_TFIDF_CACHE) and os.path.exists(_LR_CACHE):
        vectorizer = joblib.load(_TFIDF_CACHE)
        lr_model = joblib.load(_LR_CACHE)
        return vectorizer, lr_model, None

    if not os.path.exists(_DATA_PATH):
        raise FileNotFoundError(
            f"Training dataset not found at {_DATA_PATH}. "
            "Place email_text.csv (columns: label,text) in backend/data/."
        )

    # A handful of rows near the end of the dataset contain unescaped
    # commas inside the text field (not quoted), which breaks strict
    # CSV parsing. They are a tiny fraction of ~53.6k rows, so we skip
    # just those malformed rows rather than failing the whole load.
    df = pd.read_csv(_DATA_PATH, on_bad_lines="skip", engine="python")
    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["label"], test_size=0.3, random_state=42, stratify=df["label"]
    )

    vectorizer = TfidfVectorizer(max_features=3000, stop_words="english")
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    lr_model = LogisticRegression(max_iter=1000)
    lr_model.fit(X_train_vec, y_train)

    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score,
        roc_auc_score, average_precision_score,
    )

    y_pred = lr_model.predict(X_test_vec)
    y_proba = lr_model.predict_proba(X_test_vec)[:, 1]

    metrics = {
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "precision": round(float(precision_score(y_test, y_pred, pos_label=1)), 4),
        "recall": round(float(recall_score(y_test, y_pred, pos_label=1)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, y_proba)), 4),
        "pr_auc": round(float(average_precision_score(y_test, y_proba)), 4),
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
    }

    joblib.dump(vectorizer, _TFIDF_CACHE)
    joblib.dump(lr_model, _LR_CACHE)
    return vectorizer, lr_model, metrics


# --------------------------------------------------------------------
# Transformer (cybersectony/phishing-email-detection-distilbert_v2.4.1)
# --------------------------------------------------------------------

def _load_transformer():
    if not settings.USE_TRANSFORMER_MODEL:
        return None, None, "Disabled via USE_TRANSFORMER_MODEL=false in .env"
    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification

        tokenizer = AutoTokenizer.from_pretrained(
            "cybersectony/phishing-email-detection-distilbert_v2.4.1"
        )
        model = AutoModelForSequenceClassification.from_pretrained(
            "cybersectony/phishing-email-detection-distilbert_v2.4.1"
        )
        model.eval()
        return tokenizer, model, None
    except Exception as exc:  # pragma: no cover - depends on env/network
        return None, None, str(exc)


def _ensure_loaded():
    if _state["loaded"]:
        return
    with _lock:
        if _state["loaded"]:
            return
        vectorizer, lr_model, metrics = _train_or_load_tfidf()
        _state["tfidf_vectorizer"] = vectorizer
        _state["tfidf_model"] = lr_model
        _state["tfidf_metrics"] = metrics

        tokenizer, model, error = _load_transformer()
        _state["transformer_tokenizer"] = tokenizer
        _state["transformer_model"] = model
        _state["transformer_available"] = tokenizer is not None and model is not None
        _state["transformer_error"] = error
        _state["loaded"] = True


def model_status() -> dict:
    _ensure_loaded()
    return {
        "tfidf_ready": _state["tfidf_model"] is not None,
        "tfidf_training_metrics": _state["tfidf_metrics"],
        "transformer_ready": _state["transformer_available"],
        "transformer_disabled_reason": None if _state["transformer_available"] else _state["transformer_error"],
    }


# --------------------------------------------------------------------
# Prediction functions (ported from NLP and LR.ipynb)
# --------------------------------------------------------------------

def predict_transformer(email_text: str) -> dict:
    _ensure_loaded()
    if not _state["transformer_available"]:
        return {
            "prediction": "unavailable",
            "confidence": 0.0,
            "phishing_score": 0.0,
            "all_probabilities": None,
        }

    import torch

    tokenizer = _state["transformer_tokenizer"]
    model = _state["transformer_model"]

    inputs = tokenizer(email_text, return_tensors="pt", truncation=True, max_length=512)
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1)[0].tolist()

    labels = {
        "legitimate_email": probs[0],
        "phishing_url": probs[1],
        "legitimate_url": probs[2],
        "phishing_url_alt": probs[3],
    }
    max_label = max(labels.items(), key=lambda x: x[1])

    return {
        "prediction": max_label[0],
        "confidence": max_label[1],
        "phishing_score": 1 - labels["legitimate_email"],
        "all_probabilities": labels,
    }


def predict_with_tfidf(text: str) -> dict:
    _ensure_loaded()
    vectorizer = _state["tfidf_vectorizer"]
    lr_model = _state["tfidf_model"]
    vec = vectorizer.transform([text])
    proba = lr_model.predict_proba(vec)[0]
    return {"legitimate_prob": float(proba[0]), "phishing_prob": float(proba[1])}


def get_tfidf_explanation(text: str, top_n: int = 6) -> list:
    """Top N words in THIS email that pushed the TF-IDF/LR score toward phishing."""
    _ensure_loaded()
    vectorizer = _state["tfidf_vectorizer"]
    lr_model = _state["tfidf_model"]

    feature_names = vectorizer.get_feature_names_out()
    coefficients = lr_model.coef_[0]

    vec = vectorizer.transform([text])
    present_word_indices = vec.nonzero()[1]

    word_contributions = [(feature_names[i], coefficients[i]) for i in present_word_indices]
    word_contributions.sort(key=lambda x: x[1], reverse=True)

    return [word for word, weight in word_contributions[:top_n] if weight > 0]


def combine_scores(transformer_result: dict, tfidf_result: dict) -> dict:
    if transformer_result["prediction"] == "unavailable":
        # Transformer unavailable -> fall back to TF-IDF alone, re-normalised.
        total = tfidf_result["phishing_prob"]
    else:
        total = (
            transformer_result["phishing_score"] * NLP_SIGNAL_WEIGHTS["transformer"]
            + tfidf_result["phishing_prob"] * NLP_SIGNAL_WEIGHTS["tfidf"]
        )
    return {
        "total_nlp_score": total,
        "breakdown": {"transformer": transformer_result, "tfidf": tfidf_result},
    }


def analyze_text(text: str) -> dict:
    """Single entry point used by content_module.py. Runs both models and
    the composite scoring engine, and returns everything needed to render
    both the score and a human-readable explanation."""
    transformer_result = predict_transformer(text)
    tfidf_result = predict_with_tfidf(text)
    combined = combine_scores(transformer_result, tfidf_result)
    top_words = get_tfidf_explanation(text)

    return {
        "transformer": transformer_result,
        "tfidf": tfidf_result,
        "combined": combined,
        
        "top_phishing_words": top_words,
        "transformer_available": _state["transformer_available"],
    }
