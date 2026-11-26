"""
Prétraitement commun du projet ml-waf.

REQ_COLS : colonnes de la requête HTTP qui servent à construire le texte
build_text_df(df) : transforme chaque requête en une chaîne normalisée
marqueurs(texts) : marqueurs manuels (DataFrame numérique) calculés sur ces chaînes
MARQUEURS_RETENUS : les marqueurs gardés après sélection (voir 03_marqueurs.ipynb)
"""
import json
import os
import math
import re
from collections import Counter
from urllib.parse import unquote

import numpy as np
import pandas as pd

# Les 13 colonnes request_* conservées (après suppression de request_origin et request_do_not_track)
REQ_COLS = [
    "request_http_method",
    "request_http_request",
    "request_http_protocol",
    "request_user_agent",
    "request_referer",
    "request_host",
    "request_cookie",
    "request_content_type",
    "request_accept",
    "request_accept_language",
    "request_accept_encoding",
    "request_connection",
    "request_body",
]

# Colonnes réellement vues par le modèle déployé : la méthode HTTP est exclue car, dans le dataset,
# 87 % des POST sont des attaques (contre 67 % des GET) : le modèle bloquait tout formulaire légitime.
# Les en-têtes de négociation (accept*, connection) sont aussi exclus : ce sont des habitudes d'outils
# (le dataset les associe à des attaquants) et non du contenu ; ils poussaient les scores des vrais navigateurs.
_COLS_EXCLUES = {"request_http_method", "request_content_type", "request_accept", "request_accept_language", "request_accept_encoding", "request_connection"}
MODEL_COLS = [c for c in REQ_COLS if c not in _COLS_EXCLUES]

SITE_HOST = os.environ.get("WAF_SITE_HOST","test-site.com")


def _normalize_host(value: str) -> str:
    # Le site de test devient "self" : le modèle ne doit pas apprendre le nom du site
    return "self" if value == SITE_HOST else value


def _normalize_referer(value: str) -> str:
    # http(s)://test-site.com/blog/ -> self/blog/
    return re.sub(r"^https?://" + re.escape(SITE_HOST), "self", value)


def _clean_value(col: str, value: str) -> str:
    if col == "request_host":
        value = _normalize_host(value)
    elif col == "request_referer":
        value = _normalize_referer(value)
    # Décodage URL deux fois : %2527 -> %27 -> '
    value = unquote(unquote(value))
    return value.lower()


def build_text_df(df: pd.DataFrame) -> pd.Series:
    """Retourne une Series de textes, un par ligne de df, alignée sur son index."""
    cols = [c for c in REQ_COLS if c in df.columns]
    missing = [c for c in REQ_COLS if c not in df.columns]
    if missing:
        raise KeyError(f"Colonnes absentes : {missing}")

    filled = df[cols].fillna("").astype(str)

    texts = []
    for row in filled.itertuples(index=False, name=None):
        parts = [f"{col} {_clean_value(col, val)}" for col, val in zip(cols, row)]
        texts.append(" ".join(parts))

    return pd.Series(texts, index=df.index)


def _aplatir_json(corps: str) -> str:
    """
    Normalisation du corps JSON : {"email":"a@b.fr","password":"x"} -> email=a@b.fr&password=x.
    Le dataset associe la syntaxe JSON à des attaques (presque tous ses corps JSON en sont) : sans cette
    normalisation, toute API JSON légitime est bloquée. Seul le contenu (clés, valeurs) compte pour le modèle.
    Un corps qui n'est pas du JSON valide est laissé tel quel. Appliqué à l'entraînement ET en production.
    """
    s = corps.strip()
    if not s or s[0] not in "{[":
        return corps
    try:
        obj = json.loads(s)
    except ValueError:
        return corps
    paires = []

    def parcourir(x, cle=""):
        if isinstance(x, dict):
            for k, v in x.items():
                parcourir(v, str(k))
        elif isinstance(x, list):
            for v in x:
                parcourir(v, cle)
        else:
            paires.append(f"{cle}={'' if x is None else x}")
    parcourir(obj)
    return "&".join(paires).lower()


def build_text(champs: dict) -> str:
    """
    Texte d'UNE seule requête, restreint aux MODEL_COLS (utilisé par l'API).
    Identique à restrict_text(build_text_df(...)) utilisé à l'entraînement.
    champs : {nom_de_colonne: valeur}, ex. le résultat de champs_from_http.
    """
    parts = []
    for col in MODEL_COLS:
        val = champs.get(col)
        if val is None or (isinstance(val, float) and val != val):   # None ou NaN -> "" (comme fillna(""))
            val = ""
        val = _clean_value(col, str(val))
        if col == "request_body":
            val = _aplatir_json(val)
        parts.append(f"{col} {val}")
    return " ".join(parts)


# Correspondance header HTTP -> colonne du dataset
HEADER_TO_COL = {
    "user-agent": "request_user_agent",
    "referer": "request_referer",
    "host": "request_host",
    "cookie": "request_cookie",
    "content-type": "request_content_type",
    "accept": "request_accept",
    "accept-language": "request_accept_language",
    "accept-encoding": "request_accept_encoding",
    "connection": "request_connection",
}


def champs_from_http(method: str, target: str, protocol: str, headers, body) -> dict:
    """
    Transforme une vraie requête HTTP (reçue par l'API) en dict au même format qu'une ligne du CSV.
    target : chemin + query string, ex. "/vulnerabilities/sqli/?id=1&Submit=Submit"
    headers : dict-like (insensible à la casse côté FastAPI)
    """
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="ignore")
    champs = {
        "request_http_method": method,
        "request_http_request": target,
        "request_http_protocol": protocol,
        "request_body": body,
    }
    for header, col in HEADER_TO_COL.items():
        champs[col] = headers.get(header, "")
    return champs

# ---------------------------------------------------------------------------
# Marqueurs manuels
# ---------------------------------------------------------------------------
# marqueurs(texts) : une ligne par requête, une colonne par « question » posée
# sur la requête. Aucun apprentissage (pas de fit) : peut être précalculée
# avant la cross-validation et utilisée dans un FunctionTransformer.

# Une regex qui découpe le texte de build_text_df en ses 13 champs (ordre de REQ_COLS)
_FIELD_RE = re.compile(
    "^" + " ".join(f"{col} (?P<{col[8:]}>.*?)" for col in REQ_COLS[:-1])
    + f" {REQ_COLS[-1]} (?P<{REQ_COLS[-1][8:]}>.*)$",
    re.DOTALL,
)


def restrict_text(texts: pd.Series) -> pd.Series:
    """Texte à 13 champs (sortie de build_text_df, colonne `text` des parquet) -> texte MODEL_COLS."""
    f = texts.str.extract(_FIELD_RE)
    if f.isna().all(axis=1).any():
        raise ValueError("Texte au mauvais format (attendu : sortie de build_text_df)")
    f = f.fillna("")
    f["body"] = f["body"].map(_aplatir_json)
    out = None
    for col in MODEL_COLS:
        part = f"{col} " + f[col[8:]]
        out = part if out is None else out + " " + part
    return out


# Signatures d'attaque strictes, utilisées uniquement pour corriger les labels du dataset :
# 21 % de ses requêtes "légitimes" sont des injections placées dans le CHEMIN de l'URL
# (ex. /blog/index.php&&cat+/etc/passwd/2020/04, /blog/...+sleep(15)+...). Pour un WAF, ce sont des attaques.
SIGNATURES_ATTAQUE = re.compile("|".join([
    r"etc/passwd|etc/shadow|win\.ini|boot\.ini|/proc/self",
    r"<\s*script|javascript:|on(?:error|load|mouseover|focus)\s*=|<\s*(?:img|svg|iframe)\b[^>]*\bon\w+\s*=|alert\s*\(",
    r"(?:;|\|\||&&|\||`)\s*(?:ls|cat|id|whoami|uname|wget|curl|nc|bash|sh|ping)(?![\w=])",
    r"union[\s+/*]+(?:all[\s+/*]+)?select|(?:'|\"|\b)\s*(?:or|and)[\s+]+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|sleep\s*\(\s*\d",
]))


_CARACTERES_PAYLOAD = re.compile(r"['\"<>;`|]|--|\.\./")
_URL_AUTH = re.compile(r"login|signin|auth")
_CHEMIN_AUTH = re.compile(r"(?:/[\w.\-]+)*/[\w.\-]*(?:login|signin|auth)[\w.\-]*/?")
# Champs d'un formulaire d'authentification (WordPress et génériques) : sans autre champ ni payload, la requête
# ne contient rien d'« attaque » dans son contenu.
_CLES_AUTH = {"log", "pwd", "rememberme", "wp-submit", "redirect_to", "testcookie", "user_login", "user_email", "user_pass",
              "username", "password", "user", "pass", "login", "email", "remember", "submit", "action", "redirect", "reauth",
              "loggedout", "interim-login", "key", "checkemail", "wp_lang", "_wpnonce", "redirect_url", "next"}


def _cles(chaine: str) -> set:
    return {kv.split("=", 1)[0] for kv in chaine.split("&") if kv}


def masque_identifiants_seuls(texts: pd.Series) -> pd.Series:
    """
    True pour les requêtes d'authentification SANS payload : page de login, formulaire de login, mot de passe oublié,
    force brute / énumération d'utilisateurs (noms aléatoires). Le dataset en étiquette des milliers comme attaques
    (wp-login.php : ~2 400 attaques POST/GET de ce type) contre quasi aucune légitime : une requête de login isolée
    ne se distingue pas par son contenu, c'est un comportement (trop d'essais) à traiter par limitation de débit.
    Les garder apprend au modèle que tout login est une attaque.
    """
    url = texts.str.extract(r"request_http_request (\S*)")[0].fillna("")
    corps = texts.str.extract(r" request_body (.*)$")[0].fillna("")
    res = pd.Series(False, index=texts.index)
    for i in url.index[url.str.contains(_URL_AUTH)]:
        u, c = url[i], corps[i]
        chemin, _, q = u.partition("?")
        if (_CARACTERES_PAYLOAD.search(u) or _CARACTERES_PAYLOAD.search(c) or SIGNATURES_ATTAQUE.search(u + " " + c)
                or not _CHEMIN_AUTH.fullmatch(chemin)):
            continue
        res[i] = _cles(q) <= _CLES_AUTH and _cles(c) <= _CLES_AUTH
    return res


def nettoyer_labels(texts: pd.Series, labels) -> tuple:
    """Passe à 1 les requêtes étiquetées 0 qui portent une signature d'attaque. Retourne (labels, nb_corriges)."""
    y = np.asarray(labels).astype(int).copy()
    bruit = (y == 0) & texts.str.contains(SIGNATURES_ATTAQUE).to_numpy()
    y[bruit] = 1
    return y, int(bruit.sum())


_SQL_KEYWORDS = [
    "union", "select", "insert", "update", "delete", "drop", "from", "where",
    "sleep", "benchmark", "waitfor", "information_schema", "concat", "char(",
    "order by", "group by", "having", "null", "@@version", "xp_cmdshell",
]
_SQL_KW_RE = re.compile("|".join(re.escape(k) for k in _SQL_KEYWORDS))

_PATTERNS = {
    "contient_union_select": r"union[\s+/*]+(?:all[\s+/*]+)?select",
    "contient_sql_tautologie": r"(?:'|\"|\b)\s*(?:or|and)[\s+]+['\"]?\w+['\"]?\s*=\s*['\"]?\w+",
    "contient_commentaire_sql": r"--|/\*|\*/|#\s*$",
    "contient_traversal": r"\.\.[/\\]",
    "contient_fichier_sensible": r"etc/passwd|etc/shadow|win\.ini|boot\.ini|\.htaccess|proc/self|web\.config|\.env\b",
    "contient_xss": r"<\s*script|javascript:|on(?:error|load|mouseover|focus)\s*=|alert\s*\(|<\s*(?:img|svg|iframe)\b|document\.cookie",
    "contient_cmd": r"[;|`]\s*(?:ls|cat|id|whoami|uname|wget|curl|nc|bash|sh|ping)\b|\$\(|&&\s*\w",
    "contient_crlf": r"[\r\n]",
    "contient_null_byte": r"\x00",
}
_PATTERNS_RE = {k: re.compile(v) for k, v in _PATTERNS.items()}

_SCANNER_RE = re.compile(
    r"sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|wpscan|acunetix|nessus|"
    r"openvas|burp|zap|w3af|curl|wget|python-requests|python-urllib|go-http-client|libwww"
)
_WP_RE = re.compile(r"wp-login|xmlrpc\.php|wp-admin|wp-config")
_SPECIAUX_RE = re.compile(r"[<>'\";(){}|`$\\]")
_METHODES_STD = {"get", "post", "head"}

# Marqueurs gardés après sélection (03_marqueurs.ipynb, étape 2 bis) :
# AUC seule >= 0.51, plus nb_parametres et methode_inhabituelle (utiles en combinaison).
# Les 10 autres candidats sont exclus : constants, sans apport, ou inversés par le bruit
# de labels du dataset (contient_cmd, contient_fichier_sensible...).
MARQUEURS_RETENUS = [
    "longueur_url", "longueur_body", "nb_parametres", "nb_guillemets", "nb_speciaux",
    "ratio_speciaux", "entropie_url", "nb_mots_sql", "contient_union_select",
    "contient_sql_tautologie", "contient_commentaire_sql", "contient_traversal",
    "contient_crlf", "methode_inhabituelle",
]
_PROTOCOLES_STD = {"http/1.1", "http/1.0"}


def _entropie(s: str) -> float:
    """Entropie de Shannon (bits par caractère)."""
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _as_series(texts) -> pd.Series:
    """Accepte une Series, une liste ou un array (1D ou 2D à une colonne)."""
    if isinstance(texts, pd.DataFrame):
        texts = texts.iloc[:, 0]
    if isinstance(texts, pd.Series):
        return texts.fillna("").astype(str)
    arr = np.asarray(texts, dtype=object).ravel()
    return pd.Series(arr).fillna("").astype(str)


def marqueurs(texts, tous: bool = False) -> pd.DataFrame:
    """Calcule les marqueurs manuels à partir de la colonne `text` (sortie de build_text_df).

    Retourne un DataFrame numérique (une ligne par requête), aligné sur l'index d'entrée,
    avec les colonnes de MARQUEURS_RETENUS. tous=True renvoie les 24 marqueurs candidats
    (pour l'analyse et la sélection).
    """
    s = _as_series(texts)
    f = s.str.extract(_FIELD_RE)
    if f.isna().all(axis=1).any():
        bad = f.index[f.isna().all(axis=1)][:3].tolist()
        raise ValueError(f"Texte au mauvais format (attendu : sortie de build_text_df), lignes {bad}")

    url, body = f["http_request"], f["body"]
    payload = url + " " + body + " " + f["cookie"]   # là où se trouvent les attaques

    M = pd.DataFrame(index=s.index)

    # Taille et forme de la requête
    M["longueur_url"] = url.str.len()
    M["longueur_body"] = body.str.len()
    M["nb_parametres"] = url.str.count(r"[?&][^=&]*=")
    M["nb_guillemets"] = payload.str.count(r"['\"]")
    M["nb_speciaux"] = payload.str.count(_SPECIAUX_RE)
    M["ratio_speciaux"] = M["nb_speciaux"] / payload.str.len().clip(lower=1)
    M["entropie_url"] = url.map(_entropie)

    # Signatures d'attaque
    M["nb_mots_sql"] = payload.map(lambda x: len(set(_SQL_KW_RE.findall(x))))
    for nom, rx in _PATTERNS_RE.items():
        M[nom] = payload.str.contains(rx).astype(int)

    # En-têtes et contexte
    M["methode_inhabituelle"] = (~f["http_method"].isin(_METHODES_STD)).astype(int)
    M["protocole_inhabituel"] = (~f["http_protocol"].isin(_PROTOCOLES_STD)).astype(int)
    M["host_etranger"] = (f["host"] != "self").astype(int)
    M["user_agent_vide"] = (f["user_agent"].str.strip() == "").astype(int)
    M["user_agent_outil"] = f["user_agent"].str.contains(_SCANNER_RE).astype(int)
    M["cible_wordpress"] = url.str.contains(_WP_RE).astype(int)
    M["referer_externe"] = ((f["referer"] != "") & ~f["referer"].str.startswith("self")).astype(int)

    M = M.astype(float)
    return M if tous else M[MARQUEURS_RETENUS]
