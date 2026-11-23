# ml-waf

Projet de WAF (Web Application Firewall) basé sur le machine learning - ENSIBS 3A, IA pour la cybersécurité.

L'objectif est de classer des requêtes HTTP comme légitimes ou malveillantes, avec une classification **multi-label** selon les catégories d'attaque CAPEC.

## État actuel

Pour l'instant, le dépôt contient uniquement le script d'exploration du dataset.

### `dataset_check.py`

Analyse `data_capec_multilabel.csv` et affiche dans le terminal :

0. vue d'ensemble (dimensions, colonnes, répartition Normal / malveillant, doublons)
1. nombre de requêtes par type d'attaque
2. requêtes avec plusieurs attaques (multi-label)
3. proportion de valeurs manquantes par colonne
4. code HTTP de réponse par classe
5. doublons sur les colonnes `request_*`
6. conflits de labels et dédoublonnage
7. header `Host`
8. header `Referer`

## Prérequis

- Python 3
- `pandas`
- `dotenv`

```bash
python -m venv venv
source venv/bin/activate
pip install pandas
pip install dotenv
```

## Utilisation

Le chemin du CSV est codé en dur au début de `dataset_check.py` (`pd.read_csv(...)`). Adaptez-le à votre machine, puis lancez :

```bash
python dataset_check.py
```

## Données

Le dataset (`*.csv`) n'est pas versionné (voir `.gitignore`). Il faut le télécharger séparément et le placer à l'emplacement attendu par le script.

Téléchargement (Harvard Dataverse, *SR-BH 2020 multi-label dataset*) : <https://doi.org/10.7910/DVN/OGOIXX>

Les 14 dernières colonnes sont les labels : `000 - Normal` et 13 catégories d'attaque. Les colonnes `request_*` décrivent la requête HTTP.

## Rôles

Malki : Déploiement / Documentation du déploiement
Augustin : Partie exploration et pré-traitement du dataset
Mathéo : Modèle TD-IDF
Célian : Modèle marqueurs
Nolhan : Tests d'attaque, mesure de faux positifs + documentation de notebook