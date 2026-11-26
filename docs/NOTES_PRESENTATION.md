# Notes pour la présentation : ce qui a changé dans le WAF et pourquoi

> À lire avant de présenter. Le modèle déployé n'est plus celui des notebooks 01 à 04 : le dataset avait des biais
> qui rendaient le WAF inutilisable sur un vrai site. Ce document explique lesquels, comment on les a corrigés,
> et ce qu'on peut affirmer (ou pas) devant le jury.

## 1. En deux phrases

- Notre WAF est un **reverse proxy** : chaque requête passe par un modèle (TF-IDF + SVM linéaire) qui la note de 0 à 1.
  Au-dessus du **seuil**, la requête est bloquée (403).
- Sur le dataset, le modèle d'origine faisait ~99 %, mais il **bloquait un simple login DVWA** : il avait appris des
  raccourcis du dataset (méthode POST, en-têtes d'outils, site WordPress) au lieu de reconnaître les attaques.
  On a corrigé ces biais, et on a vérifié le résultat sur 3 vrais sites (DVWA, WordPress, Juice Shop).

## 2. Architecture

```
navigateur / curl ──► nginx (8080 / 8082 / 8083) ──► WAF (FastAPI + modèle) ──► site protégé
                                                          │                    DVWA / WordPress / Juice Shop
                                                          └── score ≥ seuil ? 403 : on transmet
```

- Un WAF par site (même image, même modèle), un port nginx par site : DVWA 8080, WordPress 8082, Juice Shop 8083.
- Les sites sont aussi joignables **sans WAF** (DVWA 8081, Juice Shop 8084) pour comparer.
- Le WAF écrit un log par requête : `deploiement/logs/waf*.log` (ALLOW/BLOCK, score, chemin).

## 3. Le modèle en bref

- **Entrée** : un texte construit à partir de 7 champs de la requête : URL, protocole, user-agent, referer, host,
  cookie, corps. (`notebooks/preprocessing.py`, `build_text`)
- **Pipeline** : `TfidfVectorizer` sur des **n-grammes de caractères (2 à 4)**, puis un **LinearSVC** calibré
  (`CalibratedClassifierCV`) pour obtenir une probabilité. `C=3`, `class_weight="balanced"`.
- **Seuil** (0.59) : choisi avec la **courbe ROC** sur des données de validation, pour avoir au plus **1 % de faux positifs**.
  Un seuil plus bas détecte plus d'attaques mais bloque plus de monde légitime.
- **C** : force de régularisation du SVM. `C` grand = le modèle colle aux données (y compris leur bruit) ; `C` plus petit = il
  généralise mieux. On est passé de 10 à 3.

## 4. Les biais du dataset et leurs corrections

| # | Problème constaté | Preuve | Correction |
|---|---|---|---|
| 1 | **Biais POST** : 87 % des POST du dataset sont des attaques (contre 67 % des GET). Le modèle traite donc tout formulaire comme suspect. | Login DVWA légitime bloqué (score 0.43 > seuil) | La méthode HTTP est retirée de l'entrée du modèle. `Content-Type` aussi (il n'est renseigné que pour les POST, donc il rejouait le même biais). |
| 2 | **Raccourcis d'en-têtes** : `Accept*`, `Connection`… sont des habitudes d'outils d'attaque, pas du contenu. | Avec les en-têtes de Chrome, 47 % du trafic légitime était bloqué (`C=10`) | En-têtes de négociation retirés ; `C=3` ; le trafic synthétique donne les mêmes profils de navigateurs aux deux classes. |
| 3 | **Étiquettes fausses** : 21 % des requêtes « légitimes » (29 427 en train) sont des injections placées dans le chemin d'URL (`/blog/..;cat+/etc/passwd`, `sleep(15)`…). | Relues à la main : ce sont des attaques | Relabellisées en attaque par des signatures strictes (`nettoyer_labels`). |
| 4 | **Un seul site légitime** : tout le légitime vient de WordPress. DVWA ou toute autre appli ressemble à de l'inconnu, donc à une attaque. | Pages DVWA et sites génériques bloqués | **Trafic synthétique** (section 5). |
| 5 | **JSON = attaque** : presque tous les corps JSON du dataset sont des attaques. | Un login JSON anodin noté 0.96 ; le même en formulaire noté 0.02 | Le corps JSON est converti en `clé=valeur&…` avant le modèle (entraînement **et** production). |
| 6 | **Force brute étiquetée « attaque »** : sur `wp-login.php`, 5 230 attaques contre 3 949 légitimes, presque toutes de la force brute ou de l'énumération d'utilisateurs, **sans aucun payload**. | Tout login WordPress bloqué | Ces requêtes d'authentification sans payload (2 685 en train, 644 en test) sont retirées. Une requête de login isolée ne se juge pas par son contenu : c'est un comportement, à traiter par **limitation de débit**. |

Fichiers : `notebooks/preprocessing.py` (colonnes du modèle, JSON, filtres de labels), `notebooks/trafic_synthetique.py`,
`notebooks/reentrainer_modele.py` (entraînement complet, ~35 min).

## 5. Le trafic synthétique (à présenter honnêtement)

- **Quoi** : 80 000 requêtes légitimes + 80 000 attaques générées par `trafic_synthetique.py`, ajoutées au dataset.
- **Légitime** : pages et formulaires DVWA, formulaires WordPress (login, commentaire, installation), sites génériques
  (catalogue, panier, recherche), API JSON, clients scriptés. 65 % de générique.
- **Attaques** : SQLi, XSS, LFI, injection de commande, scans, JSON, injections dans des formulaires, avec obfuscations
  (casse, double encodage, commentaires `/**/`…).
- **Règle clé** : légitime et attaque partagent les **mêmes** navigateurs, cookies et formes de requêtes. Seul le **contenu**
  distingue les classes, donc le modèle ne peut plus tricher avec un raccourci.
- **Limite à dire** : c'est de la simulation écrite par nous. Elle comble un manque du dataset, elle ne remplace pas un
  vrai trafic. Une partie des cas de test (login, installation WordPress) a fini dans l'entraînement : ils ne comptent
  plus comme tests d'inédit.

## 6. Résultats

**Sur le dataset (test, labels corrigés)** : F1 **0.994**, détection **99.3 %**, faux positifs **1.6 %**.
Avec les **labels d'origine**, on voit ~22 % de « faux positifs » : ce sont les injections dans le chemin que le dataset
croit légitimes (point 3). Ce n'est pas une régression, c'est la preuve du bruit de labels.

**Sur des payloads jamais vus (synthétique, jeu B)** : détection **83 %**, faux positifs 0.1 %.

**Tests en conditions réelles** (`deploiement/tests/trafic_reel.sh`, 3 sites) :

| | curl | navigateur |
|---|---|---|
| Requêtes légitimes (11 types : login, inscription, recherche, commentaire, API JSON…) | 11 / 11 passent | 11 / 11 passent |
| Attaques (SQLi, XSS, commande, LFI, scan, JSON) | 12 / 12 bloquées | |

`deploiement/tests/attaques.sh` : 15 / 15 attaques bloquées.

## 7. Limites (à dire avant que le jury les trouve)

- **Pas de protection contre la force brute** : on a retiré ces cas du modèle. Solution : `limit_req` dans nginx (à citer comme piste).
- **Le trafic légitime de test est écrit par nous** : les chiffres sont encourageants, pas une preuve. Un vrai test
  demanderait du trafic réel d'un autre site.
- **83 % de détection sur payloads inédits** : le modèle repère les motifs qu'il a vus ; une attaque très originale peut passer.
- **Chemins de scan très spécifiques** (ex. fichiers de config rares) peuvent passer. Piste : couche de règles simples
  (regex) en complément du modèle.
- **Marges minces** sur certains POST WordPress (scores de 0.3 à 0.7 pour un seuil de 0.59).
- **Le seuil dépend du modèle** : à chaque réentraînement, mettre à jour `WAF_SEUIL` (`.env`, `.env.example`, `docker-compose.yml`).

## 8. Questions probables

- *Pourquoi pas 100 % ?* Bruit de labels dans le dataset, et compromis détection / faux positifs fixé par le seuil.
- *Pourquoi un SVM linéaire et pas du deep learning ?* Rapide (3 ms par requête), interprétable (on peut voir quels
  n-grammes pèsent), robuste sur du texte court.
- *Pourquoi des n-grammes de caractères ?* Les attaques sont obfusquées (`UnIoN/**/SeLeCt`) : les mots entiers ne suffisent pas.
- *Pourquoi retirer la méthode HTTP ?* Dans le dataset elle prédit l'attaque presque à elle seule ; sur un vrai site, c'est faux.
- *Comment sait-on que ça généralise ?* Trois sites différents, deux types de clients, et des payloads de test séparés de ceux d'entraînement. Avec les limites du point 7.

## 9. Reproduire

```bash
uv sync
uv run python notebooks/reentrainer_modele.py        # ~35 min : modèle + seuil dans models/
cd deploiement && docker compose up -d --build       # 3 sites + 3 WAF + nginx
bash tests/trafic_reel.sh                            # test complet (curl + navigateur)
bash tests/attaques.sh                               # 15 attaques (port 8080)
```

- DVWA : `http://localhost:8080`, `admin` / `password` (à la première fois : `/setup.php` puis « Create / Reset Database »).
- WordPress : `http://localhost:8082` (assistant d'installation au premier lancement).
- Juice Shop : `http://localhost:8083`.
