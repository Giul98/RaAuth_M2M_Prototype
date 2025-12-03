from flask import Flask, request, jsonify
from pymongo import MongoClient
from bson import ObjectId

app = Flask(__name__)

# ----------------------------------------------------------------------
# Database Connection
# The Resource Server interacts directly with the application's data.
# It executes read, update, and add operations on the registered services.
# ----------------------------------------------------------------------
mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client["raauth"]
services_collection = db["serviceRole"]


# ----------------------------------------------------------------------
# Utility Functions
# ----------------------------------------------------------------------
def clean_mongo_doc(doc):
    """Converts ObjectId fields into strings for JSON serialization."""
    if not doc:
        return doc
    doc = dict(doc)
    if "_id" in doc and isinstance(doc["_id"], ObjectId):
        doc["_id"] = str(doc["_id"])
    return doc


def get_nested_value(doc, path):
    """
    Retrieves a nested field from a dictionary or list using a dotted path.
    Example: "utenti.0.nome" retrieves the name of the first user.
    """
    keys = path.split(".")
    current = doc
    for key in keys:
        if isinstance(current, list):
            try:
                key = int(key)
            except ValueError:
                return None
        if isinstance(current, (dict, list)):
            try:
                current = current[key]
            except (KeyError, IndexError, TypeError):
                return None
        else:
            return None
    return current


# ----------------------------------------------------------------------
# Protected Endpoint: /data
# ----------------------------------------------------------------------
@app.route("/data", methods=["POST"])
def protected_data():
    """
    Resource Server Endpoint
    ------------------------
    This endpoint is invoked exclusively by RAAuth, which has already:
      - validated the token (via JWKS)
      - checked client permissions and actions

    Request body:
        {
          "claims": { ... },     # validated JWT payload
          "action": "read|update|add",
          "appCode": "000019",
          "data": {...},         # payload for update or add
          "field": "path.to.field",
          "array": "services"    # array name for add operations
        }
    """
    body = request.get_json(silent=True) or {}
    claims = body.get("claims", {})
    action = body.get("action")
    app_code = str(body.get("appCode", "")).strip()
    service_code = str(body.get("service", "")).strip()
    data = body.get("data") or {}
    field = body.get("field")
    array = body.get("array")

    # --- Input validation ---
    if not action or not app_code or not service_code:
        return jsonify({"error": "Missing required parameters"}), 400

    service_doc = services_collection.find_one({
        "appCode": app_code,
        "codServizio": service_code
    })

    if not service_doc:
        return jsonify({"error": f"Service {service_code} for appCode {app_code} not found"}), 404

    # ------------------------------------------------------------------
    # ACTIONS IMPLEMENTATION
    # ------------------------------------------------------------------
    if action == "read":
        # Return a specific field or the full service document
        if field:
            value = get_nested_value(service_doc, field)
            return jsonify({
                "action": "read",
                "path": field,
                "value": value if value is not None else "Field not found"
            })
        return jsonify({
            "action": "read",
            "service": clean_mongo_doc(service_doc)
        })

    elif action == "update":
        # Perform a partial update on the document
        if not data:
            return jsonify({"error": "Missing payload 'data'"}), 400
        services_collection.update_one(
            {"appCode": app_code, "codServizio": service_code},
            {"$set": data}
        )
        return jsonify({
            "action": "update",
            "msg": "Service successfully updated",
            "updated_fields": data
        })

    elif action == "add":
        # Add an element to a specified array within the document
        if not array or not data:
            return jsonify({"error": "Both 'array' and 'data' are required"}), 400
        services_collection.update_one(
            {"appCode": app_code, "codServizio": service_code},
            {"$push": {array: data}}
        )
        return jsonify({
            "action": "add",
            "msg": f"Element added to array '{array}'",
            "added_item": data
        })

    # Any unsupported action triggers an explicit error response
    else:
        return jsonify({"error": f"Action '{action}' not supported"}), 400


if __name__ == "__main__":
    app.run(port=6000)
