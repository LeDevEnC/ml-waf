import pandas as pd
import os
from dotenv import load_dotenv

load_dotenv()

def titre(t):
    """Affiche un titre de section pour aérer la sortie du terminal."""
    print("\n" + "=" * 70)
    print(t)
    print("=" * 70)


df = pd.read_csv(os.getenv('CSV_PATH'), dtype=str)

titre("0. VUE D'ENSEMBLE")
print("Dimensions (lignes, colonnes) :", df.shape) # Affiche le nombre de lignes et de colonnes
print("\nColonnes :", df.columns.tolist()) # Affiche la liste des noms des colonnes
print("\nPremière ligne :")
print(df.iloc[0]) # Affiche la première ligne
print("\nRépartition de 000 - Normal (1 = légitime, 0 = malveillante) :")
print(df["000 - Normal"].value_counts()) # Compte combien de fois chaque valeur (0 ou 1) apparaît dans la colonne Normal.
print("\nLignes strictement identiques :", df.duplicated().sum()) # Lignes strictement identiques sur toutes les colonnes

# La liste des 14 colonnes de labels, puis les 13 sans Normal
label_cols  = df.columns[24:].tolist()
attack_cols = label_cols[1:]

df[label_cols] = df[label_cols].astype(int) # Convertit les labels du texte en entier
req_cols = [c for c in df.columns if c.startswith("request_")] # La liste des colonnes qui commencent par request_.

# 1. Fait la somme de chaque colonne d'attaque (donc le nombre de requêtes par type) et trie du plus grand au plus petit.
titre("1. NOMBRE DE REQUÊTES PAR TYPE D'ATTAQUE")
print(df[attack_cols].sum().sort_values(ascending=False))

# 2. Requêtes avec plusieurs attaques à la fois (multi-label)
titre("2. REQUÊTES AVEC PLUSIEURS ATTAQUES (MULTI-LABEL)")
print((df[attack_cols].sum(axis=1) > 1).sum(), "requêtes")

# 3. Taux de valeurs manquantes par colonne (isna() donne True si la case est vide, .mean() fait la proportion par colonne, ensuite tri et arrondi)
titre("3. PROPORTION DE VALEURS MANQUANTES PAR COLONNE (0 à 1)")
print(df[req_cols].isna().mean().sort_values(ascending=False).round(2))

# 4. Tableau croisé code HTTP / classe (0 = malveillante, 1 = légitime).
# Le code de réponse est très lié à la classe (200 surtout légitime, 404 surtout malveillant) :
# une règle "200 = légitime" ferait ~82 % sans lire la requête. Or un WAF décide AVANT la réponse
# du serveur, cette info n'existe pas en production => on supprime les colonnes response_* (fuite de données).
titre("4. CODE HTTP DE RÉPONSE PAR CLASSE (0 = malveillante, 1 = légitime)")
print(pd.crosstab(df["response_http_status_code"], df["000 - Normal"]))

# 5. Doublons sur la requête seule (sans horodatage, IP, port). Permet de ne pas se retrouver avec une même requête dans l'entrainement et le test.
titre("5. DOUBLONS SUR LES COLONNES request_* SEULES")
print(df.duplicated(subset=req_cols).sum(), "doublons")


# 6. Dédoublonnage
df["label"] = 1 - df["000 - Normal"] # Crée le label binaire (1 = malveillante, 0 = légitime)
d = df[req_cols + ["label"]].fillna("") # Un sous tableau (requêtes + label 1/0) avec les cases vides remplacées par du texte vide.
conflits = d.groupby(req_cols)["label"].nunique() # Pour chaque requête identique, nombre de labels différents (1 ou 2)
titre("6. CONFLITS ET DÉDOUBLONNAGE")
print((conflits > 1).sum(), "requêtes contradictoires") # Requêtes étiquetées à la fois 0 et 1

# Supprime les doublons (les 284 conflits restent présents en 0 et en 1, retirés dans le notebook)
dd = d.drop_duplicates()
print(len(dd), "requêtes uniques")
print("\nProportion par label après dédoublonnage (1 = malveillante, 0 = légitime) :")
print(dd["label"].value_counts(normalize=True).round(3)) # Proportion de 0 et de 1 après dédoublonnage (~68 % malveillantes, 32 % légitimes)


# 7. Header Host : domaine que le client dit vouloir joindre.
# 99,5 % des requêtes visent test-site.com. Les autres Hosts (IP directe, www.google.com:80 = test de proxy ouvert, ...)
# sont presque tous des attaques : c'est un vrai signal. Mais le modèle ne doit pas apprendre le nom "test-site.com",
# sinon en démo (Host = localhost) il bloquerait tout => on normalise : Host du site -> "self", le reste tel quel.
titre("7. HEADER HOST")
print("Hosts les plus fréquents :")
print(df["request_host"].value_counts().head())
print("\nHost par classe (0 = légitime, 1 = malveillante) :")
print(pd.crosstab(df["request_host"], df["label"]).sort_values(0, ascending=False).head(10))

# 8. Header Referer : page d'où vient le client (ajouté automatiquement par le navigateur, mais contrôlable par l'attaquant).
# Résultat sur SR-BH 2020 :
#   - Referer absent ou externe        : 447 325 légitimes / 172 212 malveillantes -> ~28 % d'attaques
#   - Referer contenant test-site.com  :  77 870 légitimes / 210 408 malveillantes -> ~73 % d'attaques
# => Le Referer sépare bien les classes, et un payload peut y être injecté : on le garde.
# MAIS c'est probablement un artefact du dataset (les scanners crawlent le site et envoient un Referer interne,
# le trafic légitime du dataset en a peu), alors qu'en vrai un navigateur envoie un Referer à presque chaque requête.
# Risque : faux positifs sur la navigation normale pendant la démo.
# Décision : normaliser le domaine (http(s)://test-site.com -> self), puis comparer en cross-validation
# le modèle AVEC et SANS Referer, et mesurer les faux positifs sur une vraie navigation.
ref = df["request_referer"].fillna("")
titre("8. HEADER REFERER")
print("Referers les plus fréquents :")
print(ref.value_counts().head(10))
print("\nReferer contenant test-site.com, par classe (0 = légitime, 1 = malveillante) :")
ct_ref = pd.crosstab(ref.str.contains("test-site.com", regex=False), df["label"])
ct_ref["% malveillantes"] = (100 * ct_ref[1] / ct_ref.sum(axis=1)).round(1)
print(ct_ref)