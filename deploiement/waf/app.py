import os
import time
from datetime import datetime
from pathlib import Path

import httpx
import joblib
from fastapi import FastAPI, Request, Response

from preprocessing import build_text, champs_from_http

# Configuration (lue dans les variables d'environnement du docker-compose)
BACKEND = os.environ.get("WAF_BACKEND", "http://dvwa:80")
MODEL_PATH = Path(os.environ.get("WAF_MODEL_PATH", "/app/models/waf_tfidf.joblib"))
SEUIL = float(os.environ.get("WAF_SEUIL", "0.5"))
LOG_PATH = Path(os.environ.get("WAF_LOG_PATH", "/app/logs/waf.log"))

REQ_EXCLUS = {"connection", "keep-alive", "transfer-encoding", "content-length", "accept-encoding"}
REP_EXCLUS = {"connection", "keep-alive", "transfer-encoding", "content-length", "content-encoding"}

# Chargement du modèle au démarrage. S'il n'existe pas encore : mode FACTICE (tout passe).
model = joblib.load(MODEL_PATH) if MODEL_PATH.exists() else None
MODE = "MODELE" if model is not None else "FACTICE"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
print(f"[WAF] mode={MODE} modele={MODEL_PATH} seuil={SEUIL} backend={BACKEND}", flush=True)

app = FastAPI()
client = httpx.AsyncClient(base_url=BACKEND, follow_redirects=False, timeout=30.0)


def log(decision, proba, method, target, latence_ms):
    """horodatage | ALLOW/BLOCK | proba | méthode | URL | latence"""
    ligne = (f"{datetime.now().isoformat(timespec='seconds')} | {decision:<5} | {proba:.3f} | "
             f"{method:<6} | {target} | {latence_ms:.1f} ms")
    print(ligne, flush=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(ligne + "\n")


@app.get("/_waf/health")
async def health():
    """Vérifier que le WAF tourne et quel modèle est chargé."""
    return {"mode": MODE, "modele": str(MODEL_PATH), "seuil": SEUIL, "backend": BACKEND}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def waf(request: Request, path: str):
    t0 = time.perf_counter()

    # 1. Reconstituer la requête brute
    target = request.scope["raw_path"].decode("latin-1")
    if request.scope["query_string"]:
        target += "?" + request.scope["query_string"].decode("latin-1")
    body = await request.body()
    protocole = "HTTP/" + request.scope.get("http_version", "1.1")

    # 2. Score du modèle (même traitement qu'à l'entraînement grâce à preprocessing.py)
    if model is not None:
        champs = champs_from_http(request.method, target, protocole, request.headers, body)
        texte = build_text(champs)
        proba = float(model.predict_proba([texte])[0, 1])
    else:
        proba = 0.0
    latence = (time.perf_counter() - t0) * 1000

    # 3. Décision : bloquer
    if proba >= SEUIL:
        log("BLOCK", proba, request.method, target, latence)
        return Response(
            content=f"<h1>403 : requête bloquée par le WAF IA</h1><p>Score : {proba:.3f}</p>",
            status_code=403,
            media_type="text/html; charset=utf-8",
            headers={"X-WAF-Score": f"{proba:.3f}", "X-WAF-Decision": "BLOCK"},
        )

    # 4. Décision : laisser passer vers DVWA
    log("ALLOW", proba, request.method, target, latence)
    headers = [(k, v) for k, v in request.headers.items() if k.lower() not in REQ_EXCLUS]
    r = await client.request(request.method, target, headers=headers, content=body)

    reponse = Response(content=r.content, status_code=r.status_code)
    for k, v in r.headers.multi_items():
        if k.lower() not in REP_EXCLUS:
            reponse.headers.append(k, v)
    reponse.headers["X-WAF-Score"] = f"{proba:.3f}"
    reponse.headers["X-WAF-Decision"] = "ALLOW"
    return reponse
