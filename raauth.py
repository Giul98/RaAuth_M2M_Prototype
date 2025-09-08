# raauth.py
from flask import Flask, request, jsonify
import jwt
from jwt import PyJWKClient
from pymongo import MongoClient
import requests
import logging
from requests.exceptions import RequestException

app = Flask(__name__)

# === Config ===
JWKS_URL = "http://127.0.0.1:5000/jwks.json"   # JWKS dell'Authorization Server
RESOURCE_SERVER_URL = "http://127.0.0.1:6000/data"
ALLOWED_ISSUERS = ["adfs", "spid", "cie"]      # issuer fidati

# === JWKS client ===
jwk_client = PyJWKClient(JWKS_URL)

# === Mongo ===
mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client["raauth"]              # come in Compass
services_collection = db["serviceRole"]  # censimento servizi (appCode, codServizio, utenti...)
clients_collection  = db["clients"]      # profilo dei client M2M (permessi, appCode, issuer)

# === Logging ===
logging.basicConfig(
    filename="raauth.log",
    level=logging.INFO,
    format="%(asctime)s - RAAuth - %(message)s"
)

# === Safelist parametri per action ===
ALLOWED_PARAM_KEYS = {
    "read": ["page","size","q","sort"],
    "search": ["page","size","q","sort"],
    "get_user": ["cf"],
    "disable_user": ["cf"],
    "enable_user": ["cf"],              # <-- aggiunta
    "assign_role": ["cf","role_code","role_desc"],
    "remove_role": ["cf","role_code","role_desc"],
    "export_users": ["q","sort"],
}

@app.route("/gateway", methods=["POST"])
def gateway():
    """
    Richiesta dal client:
      - Header: Authorization: Bearer <JWT>
      - Body:   { "service": "<codServizio>", "action": "<read|search|get_user|...>", ...params }

    Flusso:
      1) Verifica firma token via JWKS + audience == service
      2) Verifica issuer (iss)
      3) Carica profilo client (sub) da 'clients' e verifica scope & action
      4) Verifica censimento su 'serviceRole' (appCode + codServizio) e utenti abilitati
      5) Safelist dei parametri per l'azione e forward al Resource Server
    """
    # --- input ---
    auth_header = request.headers.get("Authorization", "")
    body = request.get_json(silent=True) or {}
    target_service = str(body.get("service", "")).strip()
    action = str(body.get("action", "")).strip()

    if not auth_header or not target_service or not action:
        logging.warning(f"Richiesta rifiutata: dati mancanti (service={target_service}, action={action})")
        return jsonify({"error": "Dati mancanti"}), 400
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Formato Authorization non valido"}), 400

    token = auth_header.split(" ", 1)[1]

    try:
        # 1) Verifica firma/audience tramite JWKS
        signing_key = jwk_client.get_signing_key_from_jwt(token).key
        decoded = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=target_service
        )
        logging.info(f"Token valido: sub={decoded.get('sub')} iss={decoded.get('iss')} aud={decoded.get('aud')} scope={decoded.get('scope')}")

        # 2) Issuer ammesso?
        if decoded.get("iss") not in ALLOWED_ISSUERS:
            logging.warning(f"Issuer non autorizzato: {decoded.get('iss')}")
            return jsonify({"error": "issuer non autorizzato"}), 403

        # 3) Profilo client (sub = client_id)
        client_id = decoded.get("sub")
        client_doc = clients_collection.find_one({"client_id": client_id, "enabled": True})
        if not client_doc:
            logging.warning(f"Client non censito o disabilitato: {client_id}")
            return jsonify({"error": "client non censito o disabilitato"}), 403

        # issuer previsto dal profilo client (opzionale)
        expected_issuer = client_doc.get("issuer")
        if expected_issuer and decoded.get("iss") != expected_issuer:
            logging.warning(f"Issuer non coerente per client={client_id}: got={decoded.get('iss')} expected={expected_issuer}")
            return jsonify({"error": "issuer non coerente per il client"}), 403

        # scope/svc autorizzato per il client?
        if target_service not in client_doc.get("allowed_scopes", []):
            logging.warning(f"Scope non consentito per client={client_id}: {target_service}")
            return jsonify({"error": "scope non consentito per questo client"}), 403

        # action autorizzata su quello scope?
        allowed_actions = client_doc.get("allowed_actions", {}).get(target_service, [])
        if action not in allowed_actions:
            logging.warning(f"Azione non consentita per client={client_id} su service={target_service}: {action}")
            return jsonify({"error": "azione non consentita per questo client su questo servizio"}), 403

        # 4) Verifica censimento su serviceRole (appCode + codServizio) e utenti abilitati
        app_code = client_doc.get("appCode")
        if not app_code:
            logging.warning(f"Profilo client privo di appCode: client={client_id}")
            return jsonify({"error": "profilo client non valido (appCode mancante)"}), 500

        app_doc = services_collection.find_one({
            "appCode": app_code,
            "codServizio": target_service
        })
        if not app_doc:
            logging.warning(f"Censimento mancante: appCode={app_code} service={target_service}")
            return jsonify({"error": "App non censita o servizio non trovato"}), 403

        utenti_validi = [
            u for u in app_doc.get("utenti", [])
            if u.get("abilitato") and any(r.get("isChecked") for r in u.get("ruoli", []))
        ]
        if not utenti_validi:
            logging.warning(f"Nessun utente abilitato per appCode={app_code} service={target_service}")
            return jsonify({"error": "Nessun utente abilitato per questo servizio"}), 403

        logging.info(f"Accesso autorizzato: client={client_id} appCode={app_code} service={target_service} action={action} utenti_validi={len(utenti_validi)}")

        # 5) Safelist parametri per action + forward al Resource Server
        params = {}
        for k in ALLOWED_PARAM_KEYS.get(action, []):
            if k in body:
                params[k] = body[k]

        forward_payload = {
            "claims": decoded,
            "action": action,
            "appCode": app_code,
            "params": params
        }
        logging.info(f"Forward RS: action={action} appCode={app_code} service={target_service} params={list(params.keys())}")

        try:
            forward_resp = requests.post(RESOURCE_SERVER_URL, json=forward_payload, timeout=8)
            # Prova a restituire JSON; fallback a testo grezzo
            try:
                resp_json = forward_resp.json()
            except ValueError:
                resp_json = {"raw": forward_resp.text}

            return jsonify({
                "gateway": "RAAuth",
                "validated_claims": decoded,
                "resource_response": resp_json
            }), forward_resp.status_code

        except RequestException as re:
            logging.error(f"Errore contattando il Resource Server: {re}")
            return jsonify({"error": "Resource Server non raggiungibile"}), 502

    except jwt.ExpiredSignatureError:
        logging.warning(f"Token scaduto per service={target_service}")
        return jsonify({"error": "Token scaduto"}), 401
    except Exception as e:
        logging.error(f"Errore durante validazione: {str(e)}")
        return jsonify({"error": str(e)}), 403

if __name__ == "__main__":
    app.run(port=7000)
