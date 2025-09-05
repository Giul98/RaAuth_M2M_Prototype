from flask import Flask, request, jsonify
import jwt, datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Carica chiave privata per firmare i token
with open("private.pem", "r") as f:
    PRIVATE_KEY = f.read()

# Carica chiave pubblica per JWKS
with open("public.pem", "rb") as f:
    pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    numbers = pub_key.public_numbers()
    n = numbers.n
    e = numbers.e

def int_to_base64url(n):
    """Converte un intero in stringa base64url, come richiesto da JWKS"""
    return jwt.utils.base64url_encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).decode()

@app.route("/token", methods=["POST"])
def token():
    """
    Endpoint per ottenere un token.
    Il client deve passare: client_id, client_secret, scope (codServizio).
    """
    data = request.json
    if data and data.get("client_id") == "microA" and data.get("client_secret") == "12345":
        requested_scope = data.get("scope")  # es. "125455"

        if not requested_scope:
            return jsonify({"error": "scope mancante"}), 400

        # 🔎 Qui potresti validare lo scope contro MongoDB o una lista statica
        scope_validi = ["125455", "125456"]  # esempio
        if requested_scope not in scope_validi:
            return jsonify({"error": "scope non autorizzato"}), 403

        payload = {
            "iss": "RAAuth",
            "sub": "microA",
            "aud": requested_scope,    # audience = scope richiesto
            "scope": requested_scope,  # claim scope
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
    """JWKS endpoint che espone la chiave pubblica"""
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
