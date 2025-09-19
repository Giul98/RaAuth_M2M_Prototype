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
db = mongo_client["raauth"]             # come in Compass
services_collection = db["serviceRole"] # servizi censiti (codServizio, appCode, utenti, ruoli...)
clients_collection  = db["clients"]     # profilo dei client M2M (permessi)

# === Logging ===
logging.basicConfig(
    filename="raauth.log",
    level=logging.INFO,
    format="%(asctime)s - RAAuth - %(message)s"
)

@app.route("/gateway", methods=["POST"])
def gateway():
    """
    Headers:
      - Authorization: Bearer <JWT>
      - (opz.) AppId: <appCode>  [solo per debug/cross-check]
    Body:
      - { "service": "<codServizio>", "action": "<read|write|...>" }
    """
    # --- input ---
    auth_header = request.headers.get("Authorization", "")
    header_appid = request.headers.get("AppId")  # opzionale (debug)
    body = request.get_json(silent=True) or {}
    target_service = str(body.get("service", "")).strip()
    action = str(body.get("action", "")).strip()

    if not auth_header or not target_service or not action:
        logging.warning(f"Richiesta rifiutata: dati mancanti (AppId={header_appid}, service={target_service}, action={action})")
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

        # (Opz.) cross-check AppId header con appCode censito per il client
        if header_appid and header_appid != client_doc.get("appCode"):
            logging.warning(f"AppId non coerente (header={header_appid} != clients.appCode={client_doc.get('appCode')})")
            return jsonify({"error": "AppId non coerente con il client"}), 403

        # 4) Autorizzazione service/scope & action
        if target_service not in client_doc.get("allowed_scopes", []):
            logging.warning(f"Scope non consentito per client={client_id}: {target_service}")
            return jsonify({"error": "scope non consentito per questo client"}), 403

        allowed_actions = client_doc.get("allowed_actions", {}).get(target_service, [])
        if action not in allowed_actions:
            logging.warning(f"Azione non consentita per client={client_id} su service={target_service}: {action}")
            return jsonify({"error": "azione non consentita per questo client su questo servizio"}), 403

        # 5) Verifica censimento su serviceRole (appCode + codServizio) e utenti abilitati
        app_code = client_doc.get("appCode")                          # NEW: ricava appCode dal profilo client
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

        # 6) Forward al Resource Server (claims + action + appCode)
        try:
            forward_payload = {
                "claims": decoded,
                "action": action,
                "appCode": app_code,
                "data": body.get("data"),
                "field": body.get("field"),
                "array": body.get("array")
            }

            logging.info(f"Forward RS: {forward_payload['action']} appCode={app_code} service={target_service}")
            forward_resp = requests.post(RESOURCE_SERVER_URL, json=forward_payload, timeout=5)

            return jsonify({
                "gateway": "RAAuth",
                "validated_claims": decoded,
                "resource_response": forward_resp.json()
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
