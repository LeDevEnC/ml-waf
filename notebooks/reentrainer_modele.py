"""Réentraîne le modèle final (TF-IDF caractères + LinearSVC calibré) avec la version de
scikit-learn de l'environnement, puis l'exporte pour le WAF (models/waf_tfidf.joblib, models/seuil.txt).

Différences avec notebooks/02_tfidf.ipynb, pour que le modèle détecte le contenu des attaques et non
les habitudes d'en-têtes du dataset (voir trafic_synthetique.py et preprocessing.MODEL_COLS) :
  - la méthode HTTP est retirée du texte (87 % des POST du dataset sont des attaques) ;
  - les labels sont corrigés : 21 % des requêtes "légitimes" du dataset sont des injections placées dans
    le chemin de l'URL (cat /etc/passwd, sleep(15), <script>...), reclassées en attaques ;
  - le dataset est complété par du trafic synthétique du site protégé (légitime + attaques), qui partage
    les mêmes profils de navigateurs dans les deux classes ;
  - C = 3 au lieu de 10 : C = 10 maximise le F1 du dataset mais bloque 47 % du trafic légitime dès que les
    en-têtes changent (profil Chrome) ;
  - le seuil est calibré sur la validation du dataset seul (FPR <= 1 %), pas sur le trafic synthétique,
    plus facile, qui le tirerait vers le bas.

Usage (depuis la racine) : uv run python notebooks/reentrainer_modele.py
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

from preprocessing import masque_identifiants_seuls, nettoyer_labels, restrict_text
from trafic_synthetique import generer

ROOT = Path(__file__).parent.parent
BEST_C, NGRAM = 3, (2, 4)
CIBLE_FPR = 0.01
N_SYNTH = 80_000  # par classe


def make_final():
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=NGRAM,
                                  max_features=100_000, sublinear_tf=True)),
        ("clf", CalibratedClassifierCV(LinearSVC(C=BEST_C, class_weight="balanced"), cv=3)),
    ])


train = pd.read_parquet(ROOT / "data/train.parquet", columns=["text", "label"])
test = pd.read_parquet(ROOT / "data/test.parquet", columns=["text", "label"])
synth = generer(N_SYNTH, N_SYNTH, seed=1, ensemble="train")
synth_test = generer(5_000, 5_000, seed=99, ensemble="test")  # payloads et pages jamais vus à l'entraînement

X_ds, X_test = restrict_text(train["text"]), restrict_text(test["text"])
y_ds, n_ds = nettoyer_labels(X_ds, train["label"])
y_test, n_test = nettoyer_labels(X_test, test["label"])
y_test_brut = test["label"].astype(int).to_numpy()
# Logins "identifiants seuls" étiquetés attaque : non détectables par le contenu (force brute), retirés
garde_ds = ~(masque_identifiants_seuls(X_ds).to_numpy() & (y_ds == 1))
garde_te = ~(masque_identifiants_seuls(X_test).to_numpy() & (y_test == 1))
print(f"Logins sans payload retirés (force brute, hors périmètre du modèle) : train {(~garde_ds).sum()}, test {(~garde_te).sum()}", flush=True)
X_ds, y_ds = X_ds[garde_ds].reset_index(drop=True), np.asarray(y_ds)[garde_ds]
X_test, y_test, y_test_brut = X_test[garde_te].reset_index(drop=True), np.asarray(y_test)[garde_te], y_test_brut[garde_te]
print(f"Dataset : {len(X_ds)} lignes ({n_ds} labels corrigés légitime -> attaque; test : {n_test}) | "
      f"synthétique : {len(synth)} lignes", flush=True)

X_train = pd.concat([X_ds, synth["text"]], ignore_index=True)
y_train = np.concatenate([y_ds, synth["label"].to_numpy()])
est_dataset = np.arange(len(y_train)) < len(y_ds)

i_fit, i_val = train_test_split(np.arange(len(y_train)), test_size=0.2, stratify=y_train, random_state=42)
proba_val = make_final().fit(X_train.iloc[i_fit], y_train[i_fit]).predict_proba(X_train.iloc[i_val])[:, 1]
val_ds = est_dataset[i_val]
fprs, tprs, seuils = roc_curve(y_train[i_val][val_ds], proba_val[val_ds])
j = np.where(fprs <= CIBLE_FPR)[0][-1]
SEUIL = float(seuils[j])
print(f"Seuil = {SEUIL:.4f} (FPR val dataset {fprs[j]:.4f}, détection {tprs[j]:.4f})", flush=True)

final = make_final().fit(X_train, y_train)


def evaluer(nom, X, y):
    y_pred = (final.predict_proba(X)[:, 1] >= SEUIL).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, y_pred).ravel()
    print(f"{nom} : F1 = {f1_score(y, y_pred):.4f}, FPR = {fp / (fp + tn):.4f}, détection = {tp / (tp + fn):.4f}")


evaluer("Test dataset (labels corrigés)", X_test, y_test)
evaluer("Test dataset (labels d'origine, FPR gonflé par les injections dans le chemin)", X_test, y_test_brut)
evaluer("Test synthétique (payloads inédits)", synth_test["text"], synth_test["label"].to_numpy())

joblib.dump(final, ROOT / "models/waf_tfidf.joblib")
(ROOT / "models/seuil.txt").write_text(str(SEUIL))
print("Exporté.")
