from flask import Flask, request, jsonify
import jwt, datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Chiave privata
with open("private.pem", "r") as f:
    PRIVATE_KEY = f.read()

# Chiave pubblica per JWKS
with open("public.pem", "rb") as f:
    pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    numbers = pub_key.public_numbers()
    n = numbers.n
    e = numbers.e

def int_to_base64url(n):
    return jwt.utils.base64url_encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).decode()

@app.route("/token", methods=["POST"])
def token():
    """
    Endpoint per ottenere un token.
    Il client deve passare: client_id, client_secret, service (codServizio).
    """
    data = request.json
    if data and data.get("client_id") == "microA" and data.get("client_secret") == "12345":
        target_service = data.get("service")  # es. "125455"

        if not target_service:
            return jsonify({"error": "service (codServizio) mancante"}), 400

        payload = {
            "iss": "RAAuth",
            "sub": "microA",
            "aud": target_service,   # 👈 audience = codice servizio
            "scope": "read:data",
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
