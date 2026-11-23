"""
Prétraitement commun du projet ml-waf.

REQ_COLS : colonnes de la requête HTTP qui servent à construire le texte
build_text_df(df) : transforme chaque requête en une chaîne normalisée
"""
import re
from urllib.parse import unquote

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

SITE_HOST = "test-site.com"


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
