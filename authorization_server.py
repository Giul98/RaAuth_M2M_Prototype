from flask import Flask, request, jsonify
import jwt, datetime
from pymongo import MongoClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# === Caricamento chiavi ===
with open("private.pem", "r") as f:
    PRIVATE_KEY = f.read()

with open("public.pem", "rb") as f:
    pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    numbers = pub_key.public_numbers()
    n = numbers.n
    e = numbers.e

def int_to_base64url(n):
    """Converte un intero in base64url (per JWKS)."""
    return jwt.utils.base64url_encode(
        n.to_bytes((n.bit_length() + 7) // 8, "big")
    ).decode()

# === Connessione a MongoDB ===
mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client["raauth"]              # nome del DB
services_collection = db["serviceRole"]  # collection dei servizi censiti

@app.route("/token", methods=["POST"])
def token():
    """
    Endpoint per ottenere un token.
    Il client deve passare: client_id, client_secret, scope (codServizio).
    """
    data = request.json

    # ✅ autenticazione client (fittizia per la demo)
    if data and data.get("client_id") == "microA" and data.get("client_secret") == "12345":
        requested_scope = data.get("scope")  # es. "125455"

        if not requested_scope:
            return jsonify({"error": "scope mancante"}), 400

        # ✅ controllo in Mongo se il codServizio esiste
        service_doc = services_collection.find_one({"codServizio": str(requested_scope).strip()})
        if not service_doc:
            return jsonify({"error": "scope non autorizzato"}), 403

        # ✅ se censito → creo il token
        payload = {
            "iss": "adfs",                 # issuer = ADFS o altro server reale
            "sub": "microA",
            "aud": requested_scope,        # audience = codServizio richiesto
            "scope": requested_scope,      # manteniamo anche il claim scope
            "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=5)
        }

        token = jwt.encode(
            payload,
            PRIVATE_KEY,
            algorithm="RS256",
            headers={"kid": "raauth-key-1"}
        )
        return jsonify({"access_token": token})

    return jsonify({"error": "invalid_client"}), 401

@app.route("/jwks.json")
def jwks():
    """JWKS endpoint che espone la chiave pubblica."""
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "n": int_to_base64url(n),
        "e": int_to_base64url(e),
        "kid": "raauth-key-1"
    }
    return jsonify({"keys": [jwk]})

if __name__ == "__main__":
    app.run(port=5000)
