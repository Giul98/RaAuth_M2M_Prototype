from flask import Flask, request, jsonify
import jwt
from jwt import PyJWKClient

app = Flask(__name__)
jwk_client = PyJWKClient("http://127.0.0.1:5000/jwks.json")

@app.route("/data", methods=["GET"])
def protected_data():
    auth_header = request.headers.get("Authorization") or ""
    token = auth_header.replace("Bearer ", "")

    print("\n=== TOKEN GREZZO ===")
    print(token)

    print("\n=== HEADER (non verificato) ===")
    header = jwt.get_unverified_header(token)
    print(header)

    print("\n=== PAYLOAD (non verificato) ===")
    payload_unverified = jwt.decode(token, options={"verify_signature": False})
    print(payload_unverified)

    try:
        signing_key = jwk_client.get_signing_key_from_jwt(token).key
        decoded = jwt.decode(token, signing_key, algorithms=["RS256"], audience="microB")

        print("\n=== PAYLOAD VERIFICATO ===")
        print(decoded)

        return jsonify({"message": "Accesso consentito!", "claims": decoded})
    except Exception as e:
        return jsonify({"error": str(e)}), 403

if __name__ == "__main__":
    app.run(port=6000)

##v2
##"Version 2: L'Authorization server adesso pubblica le chiavi su un endpoin esposto da lui stesso e il resource server non legge più la chiave pubblica da public.pem ma la scarica da questo endpoint (JWKS Endpoint)"