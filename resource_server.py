from flask import Flask, request, jsonify
from pymongo import MongoClient
from bson import ObjectId

app = Flask(__name__)

mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client["raauth"]
services_collection = db["serviceRole"]

def clean_mongo_doc(doc):
    """Converte ObjectId in stringhe per renderlo JSON serializzabile"""
    if not doc:
        return doc
    doc = dict(doc)
    if "_id" in doc and isinstance(doc["_id"], ObjectId):
        doc["_id"] = str(doc["_id"])
    return doc

def get_nested_value(doc, path):

    #Recupera un valore annidato dato un path tipo "utenti.0.nome"
    keys = path.split(".")
    current = doc
    for key in keys:
        if isinstance(current, list):
            try:
                key = int(key)  # se è un indice array
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


@app.route("/data", methods=["POST"])
def protected_data():
    body = request.get_json(silent=True) or {}
    claims = body.get("claims", {})
    action = body.get("action")
    app_code = str(body.get("appCode", "")).strip()
    service_code = str(claims.get("aud", "")).strip()
    data = body.get("data") or {}
    field = body.get("field")
    array = body.get("array")

    if not action or not app_code or not service_code:
        return jsonify({"error": "Parametri mancanti"}), 400

    service_doc = services_collection.find_one({
        "appCode": app_code,
        "codServizio": service_code
    })
    if not service_doc:
        return jsonify({"error": f"Servizio {service_code} per appCode {app_code} non trovato"}), 404

    # === ACTIONS ===
    if action == "read":
        if field:
            value = get_nested_value(service_doc, field)
            return jsonify({field: value if value is not None else "Campo non trovato"})
        return jsonify(service_doc)

    elif action == "update":
        if not data:
            return jsonify({"error": "Manca il payload 'data'"}), 400
        services_collection.update_one(
            {"appCode": app_code, "codServizio": service_code},
            {"$set": data}
        )
        return jsonify({"msg": "Servizio aggiornato", "updated_fields": data})

    elif action == "add":
        if not array or not data:
            return jsonify({"error": "Servono 'array' e 'data'"}), 400
        services_collection.update_one(
            {"appCode": app_code, "codServizio": service_code},
            {"$push": {array: data}}
        )
        return jsonify({"msg": f"Elemento aggiunto a {array}", "item": data})

    else:
        return jsonify({"error": f"Azione {action} non gestita"}), 400


if __name__ == "__main__":
    app.run(port=6000)
