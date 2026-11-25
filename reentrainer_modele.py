"""Réentraîne le modèle final de notebooks/02_tfidf.ipynb (mêmes hyperparamètres)
avec la version de scikit-learn de l'environnement, puis l'exporte pour le WAF.

Usage : uv run python reentrainer_modele.py
"""
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import confusion_matrix, f1_score, roc_curve
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

ROOT = Path(__file__).parent
BEST_C, NGRAM = 10, (2, 4)  # meilleurs paramètres du GridSearchCV (notebook 02)
CIBLE_FPR = 0.01


def make_final():
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=NGRAM,
                                  max_features=100_000, sublinear_tf=True)),
        ("clf", CalibratedClassifierCV(LinearSVC(C=BEST_C, class_weight="balanced"), cv=3)),
    ])


train = pd.read_parquet(ROOT / "data/train.parquet")
test = pd.read_parquet(ROOT / "data/test.parquet")
X_train, y_train = train["text"], train["label"].astype(int)
X_test, y_test = test["text"], test["label"].astype(int)

X_fit, X_val, y_fit, y_val = train_test_split(X_train, y_train, test_size=0.2,
                                              stratify=y_train, random_state=42)
proba_val = make_final().fit(X_fit, y_fit).predict_proba(X_val)[:, 1]
fprs, tprs, seuils = roc_curve(y_val, proba_val)
j = np.where(fprs <= CIBLE_FPR)[0][-1]
SEUIL = float(seuils[j])
print(f"Seuil = {SEUIL:.4f} (FPR val {fprs[j]:.4f}, détection {tprs[j]:.4f})")

final = make_final().fit(X_train, y_train)
y_pred = (final.predict_proba(X_test)[:, 1] >= SEUIL).astype(int)
tn, fp, _, _ = confusion_matrix(y_test, y_pred).ravel()
print(f"Test : F1 = {f1_score(y_test, y_pred):.4f}, FPR = {fp / (fp + tn):.4f}")

joblib.dump(final, ROOT / "models/waf_tfidf.joblib")
(ROOT / "models/seuil.txt").write_text(str(SEUIL))
print("Exporté.")
