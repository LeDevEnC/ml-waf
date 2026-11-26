# WAF IA : TODO général

Rendu : **vendredi 27/11 à 18h** sur Moodle (zip) + présentation de 20 min en amphi.
**Tout doit être terminé mercredi 25 au soir** (personne n'est disponible jeudi).

## Équipe

| Rôle | Qui |
|---|---|
| Données (exploration, prétraitement, split) | Augustin |
| Modèle TF-IDF (classifiers, tuning, évaluation, export) | Mathéo |
| Modèle marqueurs (marqueurs, mix, Referer, bonus type) | Célian |
| Tests + rapport (tests du modèle, rapport PDF, slides) | Nolhan |
| Déploiement (Docker, NGINX, proxy FastAPI, WordPress) | Malki |

## Organisation du dépôt

```
ml-waf/
├── TODO.md
├── docs/                    # un guide par membre
├── preprocessing.py         # fonctions PARTAGÉES notebook + API (ne pas dupliquer ailleurs)
├── dataset_check.py         # exploration rapide en ligne de commande
├── data/                    # NON versionné (.gitignore)
│   ├── data_capec_multilabel.csv
│   ├── train.parquet        # produit par Augustin
│   ├── test.parquet         # produit par Augustin
│   └── sample.parquet       # 50 000 lignes du train, pour développer vite
├── notebooks/
│   ├── 01_donnees.ipynb     # Augustin
│   ├── 02_tfidf.ipynb       # Mathéo
│   ├── 03_marqueurs.ipynb   # Célian
│   ├── 04_tests.ipynb       # Nolhan
│   └── waf.ipynb            # notebook FINAL assemblé
├── models/
│   └── waf.joblib           # pipeline final exporté par Mathéo
├── deploiement/             # Malki
└── rapport/                 # Nolhan
```

**Pourquoi un notebook par personne** : git gère très mal les conflits dans les `.ipynb`. Chacun travaille dans le sien, et Mathéo assemble le notebook final mercredi après-midi.

**Pour importer `preprocessing.py` depuis `notebooks/`**, première cellule de chaque notebook :

```python
import sys
sys.path.append("..")
```

## Contrat d'interface (à ne pas changer sans prévenir tout le monde)

- **Label** : `label = 1` malveillante, `label = 0` légitime.
- **Entrée du modèle** : la colonne `text`, produite par `preprocessing.build_text` (ou `build_text_df`). Personne ne réécrit sa propre version.
- **Split** : fait UNE fois par Augustin (`train.parquet` / `test.parquet`, stratifié 80/20, `random_state=42`). Tout le monde utilise ces fichiers.
- **Cross-validation** : `StratifiedKFold(n_splits=5, shuffle=True, random_state=42)`, uniquement sur le train.
- **Métriques communes** : F1, précision, rappel, taux de faux positifs (FPR), latence par requête.
- **Modèle exporté** : `models/waf.joblib` = pipeline complet (texte en entrée, `predict_proba` disponible).
- **Seuil** : 0.5 par défaut, ajusté par Mathéo après évaluation.
- **Logs du WAF** : `horodatage | ALLOW/BLOCK | proba | méthode | URL`.
- **Versions** : même version de scikit-learn partout (notebook et Docker). Lancer `pip freeze > requirements.txt` dans le venv et la recopier dans `deploiement/`.

## Planning

### Lundi 23
- [x] Choix du dataset (SR-BH 2020) et exploration rapide (`dataset_check.py`)
- [x] `preprocessing.py` (build_text, normalisation Host/Referer, marqueurs)
- [X] Répartition des rôles et lecture de son guide (tous)
- [X] État de l'art : une référence chacun, 2 idées à retenir (PeerJ 2025, ModSec-Learn, open-appsec, WAMM)
- [X] Restitution de fin de séance (problématique, dataset, méthodologie, déploiement)
- [x] Augustin : `sample.parquet` disponible **ce soir** pour débloquer Mathéo et Célian

### Mardi 24 : chaîne complète de bout en bout + premiers résultats
- [x] Augustin : `train.parquet` et `test.parquet` produits **mardi matin**, puis `01_donnees.ipynb` finalisé (Markdown + 3 graphiques)
- [X] Mathéo : première LogReg TF-IDF exportée en `models/waf.joblib` **avant midi**, puis comparaison des 5 classifiers l'après-midi
- [X] Célian : marqueurs analysés et améliorés, pipelines marqueurs en cross-validation, pipeline mix
- [X] Malki : stack Docker avec modèle factice le matin, premier `waf.joblib` branché l'après-midi, logs
- [X] Nolhan : `04_tests.ipynb` (requêtes de test), squelette du rapport, sections Introduction et État de l'art rédigées
- [X] Augustin : 1/2 page « Dataset et prétraitement » + figures envoyées à Nolhan **mardi soir**

### Mercredi 25 : tout finir
**Matin**
- [X] Mathéo : GridSearchCV sur le meilleur modèle, choix du seuil, évaluation finale sur le test, export du modèle final
- [X] Célian : expérience avec / sans Referer, importance des marqueurs, bonus type d'attaque seulement s'il reste du temps
- [X] Malki : démo d'attaques bloquées (curl, sqlmap), README de déploiement
- [X] Nolhan : tests sur la stack Docker, mesure des faux positifs sur une vraie navigation
- [X] Augustin : slides de la partie dataset, relecture du rapport

**Après-midi**
- [X] Mathéo + Célian : `waf.ipynb` assemblé et exécuté de bout en bout (Restart & Run All)
- [X] Mathéo + Célian : 1/2 page chacun + figures envoyées à Nolhan **avant 15h**
- [] Malki : modèle final branché, 1/2 page « Architecture et déploiement » envoyée à Nolhan
- [] Nolhan : rapport PDF finalisé, slides assemblées
- [] Augustin : préparation du zip (voir Livrable), vérifié depuis une copie propre

**Soir**
- [ ] Tous : répétition complète de la présentation (20 min chrono)
- [ ] Vidéo de secours de la démo enregistrée
- [ ] Zip final prêt

### Vendredi 27
- [ ] Dernière répétition rapide
- [ ] Zip déposé **avant 18h** (il est prêt depuis mercredi, ne pas attendre la dernière minute)

## Livrable (zip)

- [ ] Le dataset (`data_capec_multilabel.csv`)
- [ ] Le notebook `waf.ipynb` (exécuté, avec les sorties visibles)
- [ ] Le dossier de déploiement (`deploiement/` + `preprocessing.py` + `models/waf.joblib`)
- [ ] Le rapport technique PDF (quelques pages)

## Présentation (20 min)

| Durée | Contenu | Qui |
|---|---|---|
| 5 min | Sujet, problématique, dataset, marqueurs retenus | Augustin + Célian |
| 5 min | Méthodologie, choix, performances | Mathéo + Célian |
| 10 min | Déploiement et démo | Malki + Nolhan |

## Décisions déjà prises (à citer dans le rapport)

- Classification **binaire** (le type d'attaque est un bonus).
- Colonnes supprimées : `timestamp`, IP, ports (identifiants), `response_*` (fuite : une règle « 200 = légitime » fait ~82 % sans lire la requête), `request_do_not_track` et `request_origin` (vides à 100 %).
- Host et Referer normalisés (`test-site.com` → `self`) pour que le modèle n'apprenne pas le domaine du dataset.
- Dédoublonnage sur le texte final + retrait des 284 requêtes contradictoires : ~543 000 requêtes uniques, ~68 % malveillantes / 32 % légitimes.
- Déséquilibre ~2 contre 1 : pas de rééchantillonnage, mais `stratify`, `class_weight="balanced"` et suivi du F1 et du FPR plutôt que de l'accuracy.
