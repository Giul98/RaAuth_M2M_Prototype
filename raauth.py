from flask import Flask, request, jsonify
import jwt
from jwt import PyJWKClient
from pymongo import MongoClient
import requests
import logging

app = Flask(__name__)

# JWKS endpoint dell’Authorization Server
JWKS_URL = "http://127.0.0.1:5000/jwks.json"
jwk_client = PyJWKClient(JWKS_URL)

# Connessione a MongoDB locale
mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client["raauth"]                # nome DB su cui hai importato
services_collection = db["serviceRole"]

# URL del Resource Server
RESOURCE_SERVER_URL = "http://127.0.0.1:6000/data"

# Configurazione logging
logging.basicConfig(
    filename="raauth.log",
    level=logging.INFO,
    format="%(asctime)s - RAAuth - %(message)s"
)

@app.route("/gateway", methods=["POST"])
def gateway():
    auth_header = request.headers.get("Authorization")
    appid = request.headers.get("AppId")
    target_service = request.json.get("service")

    if not auth_header or not appid or not target_service:
        logging.warning(f"Richiesta rifiutata: dati mancanti (AppId={appid}, service={target_service})")
        return jsonify({"error": "Dati mancanti"}), 400

    token = auth_header.split(" ")[1]

    try:
        # 1. Validazione token
        signing_key = jwk_client.get_signing_key_from_jwt(token).key
        decoded = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=target_service
        )
        logging.info(f"Token valido per sub={decoded.get('sub')} aud={decoded.get('aud')} scope={decoded.get('scope')}")

        appid_str = str(appid).strip()
        service_str = str(target_service).strip()

        count = services_collection.count_documents({})
        print(f"DEBUG - Totale documenti nella collection: {count}")

        # cerca per appCode solo
        test1 = services_collection.find_one({"appCode": appid_str})
        print("DEBUG - Ricerca solo appCode:", test1)

        # cerca per codServizio solo
        test2 = services_collection.find_one({"codServizio": service_str})
        print("DEBUG - Ricerca solo codServizio:", test2)

        app_doc = services_collection.find_one({
            "appCode": appid_str,
            "codServizio": service_str
        })

        if not app_doc:
            logging.warning(f"App non censita o servizio non trovato (AppId={appid}, service={target_service})")
            return jsonify({"error": "App non censita o servizio non trovato"}), 403

        utenti_validi = [
            u for u in app_doc.get("utenti", [])
            if u.get("abilitato") and any(r.get("isChecked") for r in u.get("ruoli", []))
        ]
        if not utenti_validi:
            logging.warning(f"Nessun utente abilitato per AppId={appid}, service={target_service}")
            return jsonify({"error": "Nessun utente abilitato per questo servizio"}), 403

        logging.info(f"Accesso autorizzato: AppId={appid}, service={target_service}, utenti={len(utenti_validi)}")

        # 3. Inoltro al Resource Server
        forward_resp = requests.post(RESOURCE_SERVER_URL, json={"claims": decoded})
        return jsonify({
            "gateway": "RAAuth",
            "validated_claims": decoded,
            "resource_response": forward_resp.json()
        })

    except jwt.ExpiredSignatureError:
        logging.warning(f"Token scaduto (AppId={appid}, service={target_service})")
        return jsonify({"error": "Token scaduto"}), 401
    except Exception as e:
        logging.error(f"Errore durante validazione: {str(e)}")
        return jsonify({"error": str(e)}), 403

if __name__ == "__main__":
    app.run(port=7000)
