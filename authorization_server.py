from flask import Flask, request, jsonify
import jwt, datetime
from pymongo import MongoClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)


# Key material: the Authorization Server uses its private key to sign
# issued tokens and exposes the corresponding public key via JWKS.

with open("private.pem", "r") as f:
    PRIVATE_KEY = f.read()

with open("public.pem", "rb") as f:
    pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    numbers = pub_key.public_numbers()
    n = numbers.n
    e = numbers.e

def int_to_base64url(n_int: int) -> str:
    """Encodes an integer as base64url (used for JWKS 'n' and 'e' values)."""
    return jwt.utils.base64url_encode(
        n_int.to_bytes((n_int.bit_length() + 7) // 8, "big")
    ).decode()



# MongoDB connection: the database stores both registered clients and
# available services. Clients are identified by their credentials and
# the scope associated with their registration at the IdP.

mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client["raauth"]
services_collection = db["serviceRole"]
clients_collection = db["clients"]



# TOKEN ENDPOINT (OAuth 2.0 Client Credentials Grant)
# The client authenticates by presenting:
#   - client_id
#   - client_secret
#   - scope (here used as an additional authentication credential)
#
# If the credentials are valid, the server issues a signed JWT where
# 'aud' = scope. The scope field is not returned in the payload.

@app.route("/token", methods=["POST"])
def token():
    data = request.json or {}

    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    requested_scope = str(data.get("scope", "")).strip()

    # Step 1: basic parameter validation
    if not client_id or not client_secret or not requested_scope:
        return jsonify({"error": "missing parameters"}), 400

    # Step 2: lookup client in MongoDB
    client_doc = clients_collection.find_one({
        "client_id": client_id,
        "client_secret": client_secret,
        "enabled": True
    })
    if not client_doc:
        return jsonify({"error": "invalid_client"}), 401

    # Step 3: verify that the provided scope matches the one registered for this client
    registered_scope = client_doc.get("scope")
    if requested_scope != registered_scope:
        return jsonify({"error": "invalid_scope"}), 403

    # Step 4: verify that the client has at least one allowed service
    allowed_services = client_doc.get("allowed_services", [])
    if not allowed_services:
        return jsonify({"error": "no allowed services configured"}), 403

    # Step 5: set the issuer (default: 'adfs')
    issuer = client_doc.get("issuer", "adfs")

    # Step 6: build the JWT payload
    # The 'aud' (audience) is derived directly from the registered scope.
    # This means the token is uniquely bound to the requesting client.
    payload = {
        "iss": issuer,
        "sub": client_id,
        "aud": requested_scope,  # scope becomes the audience
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
    }

    # Step 7: sign and issue the JWT access token
    token = jwt.encode(
        payload,
        PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": "raauth-key-1"}
    )

    # Step 8: return the access token to the client
    return jsonify({"access_token": token})



# JWKS ENDPOINT
# Exposes the public key used to verify signatures on JWTs.
# Resource servers and RAAuth can use this endpoint to retrieve the
# current signing key of the Authorization Server.

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
