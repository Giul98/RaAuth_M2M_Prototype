from flask import Flask, request, jsonify
import jwt
from jwt import PyJWKClient
from pymongo import MongoClient
import requests
import logging
from requests.exceptions import RequestException

app = Flask(__name__)


# Configuration
# RAAuth acts as a gateway between the clients and the Resource Server.
# It validates the integrity and authenticity of the token (via JWKS),
# verifies that the client is authorized for a specific service and action,
# and then forwards the request to the Resource Server.

JWKS_URL = "http://127.0.0.1:5000/jwks.json"
RESOURCE_SERVER_URL = "http://127.0.0.1:6000/data"
ALLOWED_ISSUERS = ["adfs"]

# JWKS client for dynamic retrieval of the public signing key
jwk_client = PyJWKClient(JWKS_URL)


# MongoDB setup:
# - serviceRole: contains the definition of applications and related users
# - clients: stores the list of authorized M2M clients and their permissions

mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client["raauth"]
services_collection = db["serviceRole"]
clients_collection = db["clients"]

# Logging for audit and traceability
logging.basicConfig(
    filename="raauth.log",
    level=logging.INFO,
    format="%(asctime)s - RAAuth - %(message)s"
)


@app.route("/gateway", methods=["POST"])
def gateway():
    """
    RAAuth Gateway Endpoint
    -----------------------
    Expected:
      Headers:
        - Authorization: Bearer <JWT access token>
        - AppId: <appCode> (optional, used for consistency checks)
      Body:
        {
          "service": "<codServizio>",
          "action": "<read|update|add>",
          "data": {...},
          "field": "...",
          "array": "..."
        }

    Processing steps:
      1. Token verification via JWKS (signature and issuer)
      2. Client authorization (allowed_services and allowed_actions)
      3. Forwarding of authorized operations to the Resource Server
    """
    #  Input parsing
    auth_header = request.headers.get("Authorization", "")
    header_appid = request.headers.get("AppId")
    body = request.get_json(silent=True) or {}
    target_service = str(body.get("service", "")).strip()
    action = str(body.get("action", "")).strip()

    #  Basic request validation
    if not auth_header or not target_service or not action:
        logging.warning(f"Rejected request: missing data (AppId={header_appid}, service={target_service}, action={action})")
        return jsonify({"error": "Missing data"}), 400

    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Invalid Authorization format"}), 400

    token = auth_header.split(" ", 1)[1]

    try:

        # 1. Token validation
        # Verify the signature and extract the payload.

        signing_key = jwk_client.get_signing_key_from_jwt(token).key
        decoded = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            options={"verify_aud": False}
        )

        client_id = decoded.get("sub")
        issuer = decoded.get("iss")
        audience = decoded.get("aud")

        logging.info(f"Token validated: sub={client_id} iss={issuer} aud={audience}")

        # Check that the issuer is trusted
        if issuer not in ALLOWED_ISSUERS:
            logging.warning(f"Unauthorized issuer: {issuer}")
            return jsonify({"error": "Unauthorized issuer"}), 403


        # 2. Retrieve and verify client authorization

        client_doc = clients_collection.find_one({"client_id": client_id, "enabled": True})
        if not client_doc:
            logging.warning(f"Client not registered or disabled: {client_id}")
            return jsonify({"error": "Client not registered or disabled"}), 403

        # Optional consistency check between AppId header and registered appCode
        if header_appid and header_appid != client_doc.get("appCode"):
            logging.warning(f"AppId mismatch (header={header_appid} != appCode={client_doc.get('appCode')})")
            return jsonify({"error": "AppId does not match registered client"}), 403

        # Check that the client is authorized to access this service
        allowed_services = client_doc.get("allowed_services", [])
        if target_service not in allowed_services:
            logging.warning(f"Service not authorized for client={client_id}: {target_service}")
            return jsonify({"error": "Service not authorized for this client"}), 403

        # Check that the client is authorized to perform the requested action
        allowed_actions = client_doc.get("allowed_actions", {}).get(target_service, [])
        if action not in allowed_actions:
            logging.warning(f"Action not authorized for client={client_id} on service={target_service}: {action}")
            return jsonify({"error": "Action not authorized for this client on this service"}), 403


        # 3. Validate that the requested service exists in the registry

        app_code = client_doc.get("appCode")
        app_doc = services_collection.find_one({
            "appCode": app_code,
            "codServizio": target_service
        })
        if not app_doc:
            logging.warning(f"Service not found or not registered: appCode={app_code}, service={target_service}")
            return jsonify({"error": "Service not registered"}), 403

        # Optional check: ensure that at least one user is active
        valid_users = [
            u for u in app_doc.get("utenti", [])
            if u.get("abilitato") and any(r.get("isChecked") for r in u.get("ruoli", []))
        ]
        if not valid_users:
            logging.warning(f"No enabled users for appCode={app_code}, service={target_service}")
            return jsonify({"error": "No enabled users for this service"}), 403

        logging.info(f"Authorized access: client={client_id}, service={target_service}, action={action}")


        # 4. Forward authorized operation to the Resource Server

        try:
            forward_payload = {
                "claims": decoded,
                "action": action,
                "appCode": app_code,
                "service": target_service,
                "data": body.get("data"),
                "field": body.get("field"),
                "array": body.get("array")
            }

            forward_resp = requests.post(RESOURCE_SERVER_URL, json=forward_payload, timeout=5)

            return jsonify({
                "gateway": "RAAuth",
                "validated_claims": decoded,
                "resource_response": forward_resp.json()
            }), forward_resp.status_code

        except RequestException as re:
            logging.error(f"Resource Server not reachable: {re}")
            return jsonify({"error": "Resource Server unreachable"}), 502

    except jwt.ExpiredSignatureError:
        logging.warning(f"Expired token for service={target_service}")
        return jsonify({"error": "Token expired"}), 401

    except Exception as e:
        logging.error(f"Error during validation: {str(e)}")
        return jsonify({"error": str(e)}), 403


if __name__ == "__main__":
    app.run(port=7000)
