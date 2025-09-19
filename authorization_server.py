from flask import Flask, request, jsonify
import jwt, datetime
from pymongo import MongoClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# === Chiavi ===
with open("private.pem", "r") as f:
    PRIVATE_KEY = f.read()

with open("public.pem", "rb") as f:
    pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    numbers = pub_key.public_numbers()
    n = numbers.n
    e = numbers.e

def int_to_base64url(n_int: int) -> str:
    return jwt.utils.base64url_encode(
        n_int.to_bytes((n_int.bit_length() + 7) // 8, "big")
    ).decode()

# === Mongo: verifica che lo scope richiesto (codServizio) esista ===
mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client["raauth"]
services_collection = db["serviceRole"]
clients_collection = db["clients"]   # 👈 nuova collection

@app.route("/token", methods=["POST"])
def token():
    data = request.json or {}
    client_doc = clients_collection.find_one({
        "client_id": data.get("client_id"),
        "client_secret": data.get("client_secret"),
        "enabled": True
    })
    if not client_doc:
        return jsonify({"error": "invalid_client"}), 401

    requested_scope = str(data.get("scope", "")).strip()
    if not requested_scope:
        return jsonify({"error": "scope mancante"}), 400

    # 1) esiste davvero il servizio?
    if not services_collection.find_one({"codServizio": requested_scope}):
        return jsonify({"error": "scope non autorizzato"}), 403

    # 2) il client è autorizzato a chiedere quello scope?
    client_doc = clients_collection.find_one({"client_id": data.get("client_id")})
    if not client_doc or not client_doc.get("enabled", False):
        return jsonify({"error": "client disabilitato o non censito"}), 403

    if requested_scope not in client_doc.get("allowed_scopes", []):
        return jsonify({"error": "scope non consentito per questo client"}), 403

    # (opz.) prendo issuer configurato per quel client
    issuer = client_doc.get("issuer", "adfs")

    payload = {
        "iss": issuer,
        "sub": data.get("client_id"),
        "aud": requested_scope,
        "scope": requested_scope,
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
    }

    token = jwt.encode(
        payload,
        PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": "raauth-key-1"}
    )
    return jsonify({"access_token": token})

@app.route("/jwks.json")
def jwks():
    """Espone la chiave pubblica in formato JWKS."""
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "n": int_to_base64url(n),
        "e": int_to_base64url(e),
        "kid": "raauth-key-1",
    }
    return jsonify({"keys": [jwk]})

if __name__ == "__main__":
    app.run(port=5000)
