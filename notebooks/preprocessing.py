"""
Prétraitement commun du projet ml-waf.

REQ_COLS : colonnes de la requête HTTP qui servent à construire le texte
build_text_df(df) : transforme chaque requête en une chaîne normalisée
marqueurs(texts) : marqueurs manuels (DataFrame numérique) calculés sur ces chaînes
"""
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


def build_text(champs: dict) -> str:
    """
    Même texte que build_text_df, mais pour UNE seule requête (utilisé par l'API).
    champs : {nom_de_colonne: valeur}, ex. le résultat de champs_from_http.
    """
    parts = []
    for col in REQ_COLS:
        val = champs.get(col)
        if val is None or (isinstance(val, float) and val != val):   # None ou NaN -> "" (comme fillna(""))
            val = ""
        val = str(val)
        parts.append(f"{col} {_clean_value(col, val)}")
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
_SPECIAUX = set("<>'\";(){}|`$\\")
_METHODES_STD = {"get", "post", "head"}
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


def marqueurs(texts) -> pd.DataFrame:
    """Calcule les marqueurs manuels à partir de la colonne `text` (sortie de build_text_df).

    Retourne un DataFrame numérique (une ligne par requête), aligné sur l'index d'entrée.
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
    M["nb_speciaux"] = payload.map(lambda x: sum(c in _SPECIAUX for c in x))
    M["ratio_speciaux"] = M["nb_speciaux"] / payload.str.len().clip(lower=1)
    M["entropie_url"] = url.map(_entropie)

    # Signatures d'attaque
    M["nb_mots_sql"] = payload.map(lambda x: len(set(_SQL_KW_RE.findall(x))))
    for nom, rx in _PATTERNS_RE.items():
        M[nom] = payload.map(lambda x, rx=rx: int(rx.search(x) is not None))

    # En-têtes et contexte
    M["methode_inhabituelle"] = (~f["http_method"].isin(_METHODES_STD)).astype(int)
    M["protocole_inhabituel"] = (~f["http_protocol"].isin(_PROTOCOLES_STD)).astype(int)
    M["host_etranger"] = (f["host"] != "self").astype(int)
    M["user_agent_vide"] = (f["user_agent"].str.strip() == "").astype(int)
    M["user_agent_outil"] = f["user_agent"].str.contains(_SCANNER_RE).astype(int)
    M["cible_wordpress"] = url.str.contains(_WP_RE).astype(int)
    M["referer_externe"] = ((f["referer"] != "") & ~f["referer"].str.startswith("self")).astype(int)

    return M.astype(float)
